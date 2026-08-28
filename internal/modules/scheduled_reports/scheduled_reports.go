// Package scheduledreports implements the CrowdStrike Falcon scheduled reports
// and scheduled searches tools over two gofalcon sub-clients: scheduled_reports
// (query/get/execute of report entities) and report_executions (query/get/
// download of execution history).
//
// It registers four tools:
//   - falcon_search_scheduled_reports   — two-step FQL search of report entities
//   - falcon_launch_scheduled_report    — launch a report on demand (mutating)
//   - falcon_search_report_executions   — two-step FQL search of execution history
//   - falcon_download_report_execution  — download a completed execution's results
//
// The two search tools follow the two-step query→detail pattern (query for IDs,
// then bulk-fetch full records via base.FetchDetails). Both detail endpoints
// (QueryByID, ReportExecutionsGet) take the IDs as GET query params rather than
// a POST body — the gofalcon *Params expose an `Ids` field, mirroring the Python
// module's use_params=True.
//
// download_report_execution passes a buffer to the generated download client to
// capture the raw 200 body, then branches on the response Content-Type the OK
// type reports to distinguish CSV, JSON, and rejected PDF results. It matches
// the Python module, returning the CSV text or JSON records verbatim.
package scheduledreports

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strconv"
	"strings"

	"github.com/crowdstrike/gofalcon/falcon/client/report_executions"
	"github.com/crowdstrike/gofalcon/falcon/client/scheduled_reports"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/crowdstrike/falcon-mcp/internal/modules/base"
	"github.com/crowdstrike/falcon-mcp/internal/modules/registry"
)

// defaultLimit is the search page size applied when the caller omits limit,
// mirroring the Python falcon-mcp scheduled_reports module's default of 10.
const defaultLimit = 10

// detailBatchSize is the maximum number of IDs fetched per detail call. It bounds
// each QueryByID / ReportExecutionsGet request; base.FetchDetails chunks larger
// ID sets and fetches the chunks concurrently.
const detailBatchSize = 100

// MCP resource URIs for the two FQL guides, matching falcon-mcp's
// falcon://scheduled-reports/search/fql-guide and
// falcon://scheduled-reports/executions/search/fql-guide resources.
const (
	reportsFQLGuideURI    = "falcon://scheduled-reports/search/fql-guide"
	executionsFQLGuideURI = "falcon://scheduled-reports/executions/search/fql-guide"
)

// scopeScheduledReports is the CrowdStrike API scope required by every operation
// in this module (read for search/get, and — per the Falcon docs — read for the
// launch and download endpoints too). Surfaced on a 403 via base.APIError.
var scopeScheduledReports = base.Scope{Name: "Scheduled Reports", Read: true}

// errUnsupportedFormat classifies a download whose content type cannot be
// returned to an LLM (currently PDF), matching the Python module's graceful
// "configure CSV or JSON instead" message.
var errUnsupportedFormat = errors.New("scheduledreports: unsupported report format")

// Factory builds the scheduled_reports module from shared deps. It consumes two
// gofalcon sub-clients directly; the download handler recovers the raw body by
// passing a buffer to the report_executions download client. The generated
// aggregator (internal/mcpserver) collects the Factory, so the module needs no
// init side effect.
var Factory registry.Factory = func(d registry.Deps) base.Module {
	return &Module{
		Reports:     d.API.ScheduledReports,
		Executions:  d.API.ReportExecutions,
		Concurrency: d.Concurrency,
		Logger:      d.Logger,
	}
}

// reportsAPI is the minimal slice of the gofalcon scheduled_reports client this
// module consumes, declared next to its consumer so handlers can be tested with
// a small fake.
type reportsAPI interface {
	Query(params *scheduled_reports.QueryParams, opts ...scheduled_reports.ClientOption) (*scheduled_reports.QueryOK, error)
	QueryByID(params *scheduled_reports.QueryByIDParams, opts ...scheduled_reports.ClientOption) (*scheduled_reports.QueryByIDOK, error)
	Execute(params *scheduled_reports.ExecuteParams, opts ...scheduled_reports.ClientOption) (*scheduled_reports.ExecuteOK, error)
}

// executionsAPI is the minimal slice of the gofalcon report_executions client
// this module consumes, satisfied directly by the gofalcon ClientService.
// ReportExecutionsDownloadGet writes the raw 200 body to the supplied writer and
// reports its Content-Type on the returned OK; downloadReportExecution passes a
// buffer and branches on that Content-Type to distinguish CSV, JSON, and
// rejected PDF results.
type executionsAPI interface {
	ReportExecutionsQuery(params *report_executions.ReportExecutionsQueryParams, opts ...report_executions.ClientOption) (*report_executions.ReportExecutionsQueryOK, error)
	ReportExecutionsGet(params *report_executions.ReportExecutionsGetParams, opts ...report_executions.ClientOption) (*report_executions.ReportExecutionsGetOK, error)
	ReportExecutionsDownloadGet(params *report_executions.ReportExecutionsDownloadGetParams, writer io.Writer, opts ...report_executions.ClientOption) (*report_executions.ReportExecutionsDownloadGetOK, error)
}

// Module registers the scheduled_reports tools. It holds only the shared,
// concurrency-safe Falcon clients and configuration; handlers are stateless and
// reentrant. Logger must be non-nil.
type Module struct {
	Reports     reportsAPI
	Executions  executionsAPI
	Concurrency int // bounds concurrent detail fetches
	Logger      *slog.Logger
}

// Name reports the module name.
func (m *Module) Name() string { return "scheduledreports" }

// Description reports a one-line summary of the module.
func (m *Module) Description() string {
	return "Access and manage CrowdStrike Falcon scheduled reports and scheduled searches"
}

// Tool and parameter descriptions, kept 1:1 with the Python falcon-mcp
// scheduled_reports module. The filter descriptions carry backticks that cannot
// live in a jsonschema struct tag, so they are consts applied to each schema by
// its mutate func below.
const (
	searchScheduledReportsDescription = `Search for scheduled reports and searches in your CrowdStrike environment.

Use this to find reports by status, type, creator, or creation date. Consult
falcon://scheduled-reports/search/fql-guide before constructing filter expressions.
Returns full report/search entity details including schedule configuration.
Responses include ` + "`pagination.total`" + ` (the total number of records matching the filter, or null when the API does not report a count) — use it to answer "how many" questions.`

	launchScheduledReportDescription = `Launch a scheduled report or search on demand.

Executes the report immediately outside its recurring schedule. Returns
execution records containing an execution ID that can be tracked with
falcon_search_report_executions and downloaded with
falcon_download_report_execution when complete.`

	searchReportExecutionsDescription = `Search for report/search execution history.

Use this to find executions by status, report ID, or completion date. Consult
falcon://scheduled-reports/executions/search/fql-guide before constructing filter
expressions. Returns full execution details including status and timestamps.
Responses include ` + "`pagination.total`" + ` (the total number of records matching the filter, or null when the API does not report a count) — use it to answer "how many" questions.`

	downloadReportExecutionDescription = `Download the results of a completed report execution.

Only works for executions with status='DONE'. Check status first using
falcon_search_report_executions. Returns CSV string or JSON records depending
on the report's configured format. PDF format is not supported.`

	reportsFilterDescription    = "FQL filter expression. See `falcon://scheduled-reports/search/fql-guide` for syntax."
	executionsFilterDescription = "FQL filter expression. See `falcon://scheduled-reports/executions/search/fql-guide` for syntax."

	reportsSortDescription    = "Property to sort by. Ex: created_on.asc, last_updated_on.desc, next_execution_on.desc"
	executionsSortDescription = "Property to sort by. Ex: created_on.asc, last_updated_on.desc"

	reportsQDescription = "Free-text search for terms in id, name, description, type, status fields"

	limitDescription  = "Maximum number of records to return. (Max: 5000)"
	offsetDescription = "Starting index of overall result set from which to return IDs."
)

// searchReportsSchema is the input schema for falcon_search_scheduled_reports.
var searchReportsSchema = base.SchemaFor[SearchReportsInput](func(s *jsonschema.Schema) {
	s.Properties["filter"].Description = reportsFilterDescription
	s.Properties["sort"].Description = reportsSortDescription
	s.Properties["q"].Description = reportsQDescription
	s.Properties["limit"].Description = limitDescription
	s.Properties["offset"].Description = offsetDescription
	s.Properties["limit"].Minimum = jsonschema.Ptr(1.0)
	s.Properties["limit"].Maximum = jsonschema.Ptr(5000.0)
	s.Properties["limit"].Default = json.RawMessage(`10`)
	s.Properties["offset"].Minimum = jsonschema.Ptr(0.0)
})

// searchExecutionsSchema is the input schema for falcon_search_report_executions.
var searchExecutionsSchema = base.SchemaFor[SearchExecutionsInput](func(s *jsonschema.Schema) {
	s.Properties["filter"].Description = executionsFilterDescription
	s.Properties["sort"].Description = executionsSortDescription
	s.Properties["limit"].Description = limitDescription
	s.Properties["offset"].Description = offsetDescription
	s.Properties["limit"].Minimum = jsonschema.Ptr(1.0)
	s.Properties["limit"].Maximum = jsonschema.Ptr(5000.0)
	s.Properties["limit"].Default = json.RawMessage(`10`)
	s.Properties["offset"].Minimum = jsonschema.Ptr(0.0)
})

// RegisterTools registers the scheduled_reports tools into r.
func (m *Module) RegisterTools(r base.Registrar) {
	base.AddTool(r, &mcp.Tool{
		Name:        "search_scheduled_reports",
		Description: searchScheduledReportsDescription,
		InputSchema: searchReportsSchema,
	}, m.searchScheduledReports)

	base.AddTool(r, &mcp.Tool{
		Name:        "launch_scheduled_report",
		Description: launchScheduledReportDescription,
		Annotations: base.MutatingAnnotations(false),
	}, m.launchScheduledReport)

	base.AddTool(r, &mcp.Tool{
		Name:        "search_report_executions",
		Description: searchReportExecutionsDescription,
		InputSchema: searchExecutionsSchema,
	}, m.searchReportExecutions)

	base.AddTool(r, &mcp.Tool{
		Name:        "download_report_execution",
		Description: downloadReportExecutionDescription,
	}, m.downloadReportExecution)
}

// RegisterResources publishes the two scheduled_reports FQL guides as MCP
// resources, mirroring falcon-mcp's scheduled_reports FQL guide resources.
func (m *Module) RegisterResources(s *mcp.Server) {
	base.TextResource(s, reportsFQLGuideURI,
		"search_scheduled_reports_fql_guide",
		"Contains the guide for the `filter` param of the `falcon_search_scheduled_reports` tool.",
		"text/markdown", reportsFQLGuide)

	base.TextResource(s, executionsFQLGuideURI,
		"search_report_executions_fql_guide",
		"Contains the guide for the `filter` param of the `falcon_search_report_executions` tool.",
		"text/markdown", executionsFQLGuide)
}

// RegisterPrompts is a no-op: the scheduled_reports module exposes no prompts.
func (m *Module) RegisterPrompts(_ *mcp.Server) {}

// SearchReportsInput is the input for falcon_search_scheduled_reports.
type SearchReportsInput struct {
	Filter string `json:"filter,omitempty" jsonschema:"FQL filter (e.g. status:'ACTIVE'+type:'event_search')"`
	Limit  int    `json:"limit,omitempty" jsonschema:"maximum records to return"`
	Offset int    `json:"offset,omitempty" jsonschema:"pagination offset"`
	Sort   string `json:"sort,omitempty" jsonschema:"FQL sort (e.g. created_on.desc)"`
	Q      string `json:"q,omitempty" jsonschema:"free-text search across id, name, description, type, status"`
}

func (m *Module) searchScheduledReports(ctx context.Context, req *mcp.CallToolRequest, in SearchReportsInput) (*mcp.CallToolResult, base.SearchResult[*models.DomainScheduledReportV1], error) {
	var zero base.SearchResult[*models.DomainScheduledReportV1]
	limit := int64(in.Limit)
	if limit == 0 {
		limit = defaultLimit
	}
	m.Logger.Debug("search_scheduled_reports", "filter", in.Filter, "q", in.Q, "limit", limit, "offset", in.Offset, "sort", in.Sort)

	params := scheduled_reports.NewQueryParamsWithContext(ctx)
	params.Limit = &limit
	if in.Filter != "" {
		params.Filter = &in.Filter
	}
	if in.Q != "" {
		params.Q = &in.Q
	}
	if in.Offset != 0 {
		params.Offset = new(strconv.Itoa(in.Offset))
	}
	if in.Sort != "" {
		params.Sort = &in.Sort
	}

	queryResp, err := m.Reports.Query(params)
	if err != nil {
		if details, ok := reportsQueryFQLBadRequest(err); ok {
			return nil, base.FQLError[*models.DomainScheduledReportV1](details, in.Filter, reportsFQLGuide), nil
		}
	}
	if e := base.APIError(err, queryResp, scopeScheduledReports); e != nil {
		return nil, zero, e
	}

	ids := queryResp.Payload.Resources
	m.Logger.Debug("search_scheduled_reports query complete", "matched_ids", len(ids))
	if len(ids) == 0 {
		return nil, base.Found([]*models.DomainScheduledReportV1{}, in.Filter).WithMeta(queryResp.Payload.Meta), nil
	}
	details, err := m.fetchReports(ctx, req, ids)
	if err != nil {
		return nil, zero, err
	}
	return nil, base.Found(details, in.Filter).WithMeta(queryResp.Payload.Meta), nil
}

// LaunchInput is the input for falcon_launch_scheduled_report.
type LaunchInput struct {
	ID string `json:"id" jsonschema:"scheduled report/search entity ID to execute"`
}

func (m *Module) launchScheduledReport(ctx context.Context, _ *mcp.CallToolRequest, in LaunchInput) (*mcp.CallToolResult, base.EntitiesResult[*models.DomainReportExecutionV1], error) {
	var zero base.EntitiesResult[*models.DomainReportExecutionV1]
	id := strings.TrimSpace(in.ID)
	if id == "" {
		return nil, zero, fmt.Errorf("%w: id is required", base.ErrInvalidInput)
	}
	m.Logger.Debug("launch_scheduled_report", "id", id)

	params := scheduled_reports.NewExecuteParamsWithContext(ctx)
	params.Body = []*models.DomainReportExecutionLaunchRequestV1{{ID: &id}}

	resp, err := m.Reports.Execute(params)
	if e := base.APIError(err, resp, scopeScheduledReports); e != nil {
		return nil, zero, e
	}
	return nil, base.Entities(resp.Payload.Resources).WithMeta(resp.Payload.Meta), nil
}

// SearchExecutionsInput is the input for falcon_search_report_executions.
type SearchExecutionsInput struct {
	Filter string `json:"filter,omitempty" jsonschema:"FQL filter (e.g. status:'DONE'+scheduled_report_id:'abc123')"`
	Limit  int    `json:"limit,omitempty" jsonschema:"maximum records to return"`
	Offset int    `json:"offset,omitempty" jsonschema:"pagination offset"`
	Sort   string `json:"sort,omitempty" jsonschema:"FQL sort (e.g. created_on.desc)"`
}

func (m *Module) searchReportExecutions(ctx context.Context, req *mcp.CallToolRequest, in SearchExecutionsInput) (*mcp.CallToolResult, base.SearchResult[*models.DomainReportExecutionV1], error) {
	var zero base.SearchResult[*models.DomainReportExecutionV1]
	limit := int64(in.Limit)
	if limit == 0 {
		limit = defaultLimit
	}
	m.Logger.Debug("search_report_executions", "filter", in.Filter, "limit", limit, "offset", in.Offset, "sort", in.Sort)

	params := report_executions.NewReportExecutionsQueryParamsWithContext(ctx)
	params.Limit = &limit
	if in.Filter != "" {
		params.Filter = &in.Filter
	}
	if in.Offset != 0 {
		params.Offset = new(strconv.Itoa(in.Offset))
	}
	if in.Sort != "" {
		params.Sort = &in.Sort
	}

	queryResp, err := m.Executions.ReportExecutionsQuery(params)
	if err != nil {
		if details, ok := executionsQueryFQLBadRequest(err); ok {
			return nil, base.FQLError[*models.DomainReportExecutionV1](details, in.Filter, executionsFQLGuide), nil
		}
	}
	if e := base.APIError(err, queryResp, scopeScheduledReports); e != nil {
		return nil, zero, e
	}

	ids := queryResp.Payload.Resources
	m.Logger.Debug("search_report_executions query complete", "matched_ids", len(ids))
	if len(ids) == 0 {
		return nil, base.Found([]*models.DomainReportExecutionV1{}, in.Filter).WithMeta(queryResp.Payload.Meta), nil
	}
	details, err := m.fetchExecutions(ctx, req, ids)
	if err != nil {
		return nil, zero, err
	}
	return nil, base.Found(details, in.Filter).WithMeta(queryResp.Payload.Meta), nil
}

// DownloadInput is the input for falcon_download_report_execution.
type DownloadInput struct {
	ID string `json:"id" jsonschema:"report execution ID to download"`
}

// DownloadResult is the structured output envelope for
// falcon_download_report_execution. A CSV-format execution populates Raw with
// the report text verbatim; a JSON-format execution populates Resources with the
// records array from the response body. Format echoes which path was taken.
type DownloadResult struct {
	Format    string          `json:"format"`
	Raw       string          `json:"raw,omitempty"`
	Resources json.RawMessage `json:"resources,omitempty"`
}

func (m *Module) downloadReportExecution(ctx context.Context, _ *mcp.CallToolRequest, in DownloadInput) (*mcp.CallToolResult, DownloadResult, error) {
	var zero DownloadResult
	id := strings.TrimSpace(in.ID)
	if id == "" {
		return nil, zero, fmt.Errorf("%w: id is required", base.ErrInvalidInput)
	}
	m.Logger.Debug("download_report_execution", "id", id)

	params := report_executions.NewReportExecutionsDownloadGetParamsWithContext(ctx)
	params.Ids = id

	var buf bytes.Buffer
	ok, err := m.Executions.ReportExecutionsDownloadGet(params, &buf)
	if e := base.APIError(err, nil, scopeScheduledReports); e != nil {
		return nil, zero, e
	}
	body := buf.Bytes()

	contentType := ""
	if ok != nil {
		contentType = ok.ContentType
	}

	// PDF is a binary format that cannot be handed to an LLM; reject it — whether
	// the Content-Type declares it or the body carries the %PDF magic bytes —
	// with the same guidance the Python module returns rather than dumping bytes.
	if strings.Contains(contentType, "application/pdf") || (len(body) >= 4 && string(body[:4]) == "%PDF") {
		return nil, zero, fmt.Errorf("%w: PDF format not supported for LLM consumption. "+
			"Please configure the scheduled report to use CSV or JSON format instead", errUnsupportedFormat)
	}

	// A JSON-format execution is served as application/json, mirroring the Python
	// module's bytes-vs-dict split on content type. Its rows arrive as a bare
	// top-level array (`[{...},{...}]`, or `[]` when empty) — not a
	// {"resources": [...]} envelope — so that array is returned verbatim as
	// Resources. An empty body maps to an empty array, and an object body is
	// unwrapped defensively in case a version wraps the rows in an envelope.
	if strings.Contains(contentType, "application/json") {
		trimmed := bytes.TrimSpace(body)
		switch {
		case len(trimmed) == 0:
			return nil, DownloadResult{Format: "json", Resources: json.RawMessage(`[]`)}, nil
		case trimmed[0] == '{':
			var envelope struct {
				Resources json.RawMessage `json:"resources"`
			}
			if err := json.Unmarshal(trimmed, &envelope); err != nil {
				return nil, zero, fmt.Errorf("%w: report execution download was not valid JSON", base.ErrInvalidInput)
			}
			result := DownloadResult{Format: "json", Resources: envelope.Resources}
			if len(result.Resources) == 0 {
				result.Resources = json.RawMessage(`[]`)
			}
			return nil, result, nil
		default:
			var rows json.RawMessage
			if err := json.Unmarshal(trimmed, &rows); err != nil {
				return nil, zero, fmt.Errorf("%w: report execution download was not valid JSON", base.ErrInvalidInput)
			}
			return nil, DownloadResult{Format: "json", Resources: rows}, nil
		}
	}

	// Any other content type (text/csv, application/octet-stream, an absent
	// header, …) is returned verbatim as CSV/text.
	return nil, DownloadResult{Format: "csv", Raw: string(body)}, nil
}

// fetchReports fetches full scheduled report/search records for the given IDs.
// QueryByID takes the IDs as GET query params (params.Ids) and may reorder
// results, so records are reordered back to the query step's sort by their id.
func (m *Module) fetchReports(ctx context.Context, req *mcp.CallToolRequest, ids []string) ([]*models.DomainScheduledReportV1, error) {
	return base.FetchDetails(ctx, base.FetchDetailsParams[*models.DomainScheduledReportV1]{
		IDs:         ids,
		ChunkSize:   detailBatchSize,
		Concurrency: m.Concurrency,
		Progress:    base.ProgressFunc(ctx, req),
		Fetch: func(ctx context.Context, chunk []string) ([]*models.DomainScheduledReportV1, error) {
			params := scheduled_reports.NewQueryByIDParamsWithContext(ctx)
			params.Ids = chunk
			resp, err := m.Reports.QueryByID(params)
			if e := base.APIError(err, resp, scopeScheduledReports); e != nil {
				return nil, e
			}
			return resp.Payload.Resources, nil
		},
		KeyFn: func(r *models.DomainScheduledReportV1) string { return base.Deref(r.ID) },
	})
}

// fetchExecutions fetches full execution records for the given IDs.
// ReportExecutionsGet takes the IDs as GET query params (params.Ids) and may
// reorder results, so records are reordered back to the query step's sort by
// their id.
func (m *Module) fetchExecutions(ctx context.Context, req *mcp.CallToolRequest, ids []string) ([]*models.DomainReportExecutionV1, error) {
	return base.FetchDetails(ctx, base.FetchDetailsParams[*models.DomainReportExecutionV1]{
		IDs:         ids,
		ChunkSize:   detailBatchSize,
		Concurrency: m.Concurrency,
		Progress:    base.ProgressFunc(ctx, req),
		Fetch: func(ctx context.Context, chunk []string) ([]*models.DomainReportExecutionV1, error) {
			params := report_executions.NewReportExecutionsGetParamsWithContext(ctx)
			params.Ids = chunk
			resp, err := m.Executions.ReportExecutionsGet(params)
			if e := base.APIError(err, resp, scopeScheduledReports); e != nil {
				return nil, e
			}
			return resp.Payload.Resources, nil
		},
		KeyFn: func(r *models.DomainReportExecutionV1) string { return base.Deref(r.ID) },
	})
}

// reportsQueryFQLBadRequest reports whether err is a 400-class scheduled-reports
// query error and, if so, extracts the API error details for an FQL-error
// response. gofalcon surfaces the 400 as a typed *scheduled_reports.QueryBadRequest
// whose payload carries the errors as []*models.MsaAPIError.
func reportsQueryFQLBadRequest(err error) ([]base.FQLErrorDetail, bool) {
	var badReq *scheduled_reports.QueryBadRequest
	if !errors.As(err, &badReq) || badReq.Payload == nil {
		return nil, false
	}
	return base.FQLErrorDetails(badReq.Payload.Errors), true
}

// executionsQueryFQLBadRequest reports whether err is a 400-class
// report-executions query error and, if so, extracts the API error details.
func executionsQueryFQLBadRequest(err error) ([]base.FQLErrorDetail, bool) {
	var badReq *report_executions.ReportExecutionsQueryBadRequest
	if !errors.As(err, &badReq) || badReq.Payload == nil {
		return nil, false
	}
	return base.FQLErrorDetails(badReq.Payload.Errors), true
}
