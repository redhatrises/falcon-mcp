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
// download_report_execution needs a custom response reader: the gofalcon
// generated reader for the download endpoint discards the 200 body (its OK type
// carries only headers), so executionsClient wraps the client to recover the raw
// bytes and Content-Type, matching the Python module which returns the CSV text
// or JSON records verbatim.
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
	"github.com/go-openapi/runtime"
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

// errInvalidInput classifies client-side validation failures (e.g. a missing
// required id) so the handler can distinguish them from API errors.
var errInvalidInput = errors.New("scheduledreports: invalid input")

// errUnsupportedFormat classifies a download whose content type cannot be
// returned to an LLM (currently PDF), matching the Python module's graceful
// "configure CSV or JSON instead" message.
var errUnsupportedFormat = errors.New("scheduledreports: unsupported report format")

// Factory builds the scheduled_reports module from shared deps. It consumes two
// gofalcon sub-clients; the report_executions client is wrapped by
// executionsClient so the download handler can recover the raw body the
// generated reader discards. The generated aggregator (internal/mcpserver)
// collects the Factory, so the module needs no init side effect.
var Factory registry.Factory = func(d registry.Deps) base.Module {
	return &Module{
		Reports:     d.API.ScheduledReports,
		Executions:  executionsClient{ClientService: d.API.ReportExecutions},
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
// this module consumes. ReportExecutionsDownloadGet returns a downloadPayload
// (raw body + Content-Type) rather than the gofalcon typed OK, because the
// generated reader discards the download body (see executionsClient).
type executionsAPI interface {
	ReportExecutionsQuery(params *report_executions.ReportExecutionsQueryParams, opts ...report_executions.ClientOption) (*report_executions.ReportExecutionsQueryOK, error)
	ReportExecutionsGet(params *report_executions.ReportExecutionsGetParams, opts ...report_executions.ClientOption) (*report_executions.ReportExecutionsGetOK, error)
	ReportExecutionsDownloadGet(params *report_executions.ReportExecutionsDownloadGetParams, opts ...report_executions.ClientOption) (*downloadPayload, error)
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
func (m *Module) Name() string { return "scheduled_reports" }

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
		Annotations: base.MutatingAnnotations(),
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
		return nil, zero, fmt.Errorf("%w: id is required", errInvalidInput)
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
		return nil, zero, fmt.Errorf("%w: id is required", errInvalidInput)
	}
	m.Logger.Debug("download_report_execution", "id", id)

	params := report_executions.NewReportExecutionsDownloadGetParamsWithContext(ctx)
	params.Ids = id

	payload, err := m.Executions.ReportExecutionsDownloadGet(params)
	if e := base.APIError(err, nil, scopeScheduledReports); e != nil {
		return nil, zero, e
	}
	if payload == nil {
		return nil, zero, fmt.Errorf("%w: empty download response", errInvalidInput)
	}

	// PDF is a binary format that cannot be handed to an LLM; surface the same
	// guidance the Python module returns rather than dumping raw bytes.
	if len(payload.Body) >= 4 && string(payload.Body[:4]) == "%PDF" {
		return nil, zero, fmt.Errorf("%w: PDF format not supported for LLM consumption. "+
			"Please configure the scheduled report to use CSV or JSON format instead", errUnsupportedFormat)
	}

	// JSON format: the download endpoint returns the report rows as a bare
	// top-level JSON array (e.g. `[{...},{...}]`, or `[]` when empty) — not a
	// {"resources": [...]} envelope. Return that array verbatim as Resources.
	// Some endpoints/versions may wrap the rows in an object envelope, so an
	// object body is unwrapped defensively.
	if isJSONContentType(payload.ContentType) {
		trimmed := bytes.TrimSpace(payload.Body)
		switch {
		case len(trimmed) == 0:
			return nil, DownloadResult{Format: "json", Resources: json.RawMessage(`[]`)}, nil
		case trimmed[0] == '[':
			var rows json.RawMessage
			if err := json.Unmarshal(trimmed, &rows); err != nil {
				return nil, zero, fmt.Errorf("%w: report execution download was not valid JSON", errInvalidInput)
			}
			return nil, DownloadResult{Format: "json", Resources: rows}, nil
		default:
			var envelope struct {
				Resources json.RawMessage `json:"resources"`
			}
			if err := json.Unmarshal(trimmed, &envelope); err != nil {
				return nil, zero, fmt.Errorf("%w: report execution download was not valid JSON", errInvalidInput)
			}
			result := DownloadResult{Format: "json", Resources: envelope.Resources}
			if len(result.Resources) == 0 {
				result.Resources = json.RawMessage(`[]`)
			}
			return nil, result, nil
		}
	}

	// Otherwise treat the body as CSV/text and return it verbatim.
	return nil, DownloadResult{Format: "csv", Raw: string(payload.Body)}, nil
}

// isJSONContentType reports whether a Content-Type header denotes a JSON body.
func isJSONContentType(contentType string) bool {
	return strings.Contains(strings.ToLower(contentType), "application/json")
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
		KeyFn: func(r *models.DomainScheduledReportV1) string {
			if r == nil || r.ID == nil {
				return ""
			}
			return *r.ID
		},
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
		KeyFn: func(r *models.DomainReportExecutionV1) string {
			if r == nil || r.ID == nil {
				return ""
			}
			return *r.ID
		},
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

// downloadPayload carries the raw download body and its Content-Type, recovered
// by executionsClient from a response the gofalcon generated reader would
// otherwise discard.
type downloadPayload struct {
	Body        []byte
	ContentType string
}

// executionsClient adapts the gofalcon report_executions.ClientService,
// overriding ReportExecutionsDownloadGet to recover the raw 200 body. The
// generated download reader consumes only response headers (its OK type carries
// no payload), and the generated method panics if the transport returns any
// non-*ReportExecutionsDownloadGetOK value, so a Reader override cannot simply
// return the raw bytes in its place. Instead the override captures the body and
// Content-Type into a field on a custom reader while still returning a valid
// *ReportExecutionsDownloadGetOK to satisfy the method's type assertion; this
// adapter then hands the captured bytes back as a downloadPayload. Non-200
// responses fall through to the generated typed errors. The other two methods
// (Query, Get) are served by the embedded ClientService unchanged.
type executionsClient struct {
	report_executions.ClientService
}

// ReportExecutionsDownloadGet fetches the download body, recovering the 200 body
// the generated reader discards. It returns the raw body and Content-Type on
// success, or the generated typed error on a non-200 response.
func (c executionsClient) ReportExecutionsDownloadGet(params *report_executions.ReportExecutionsDownloadGetParams, opts ...report_executions.ClientOption) (*downloadPayload, error) {
	capture := &downloadReader{}
	override := func(op *runtime.ClientOperation) {
		capture.orig = op.Reader
		op.Reader = capture
	}
	_, err := c.ClientService.ReportExecutionsDownloadGet(params, append([]report_executions.ClientOption{override}, opts...)...)
	if err != nil {
		return nil, err
	}
	return &downloadPayload{Body: capture.body, ContentType: capture.contentType}, nil
}

// downloadReader wraps the generated reader to capture the 200 response body and
// Content-Type, which the generated reader leaves unconsumed (see
// executionsClient). On non-200 responses it delegates to the original reader so
// 400/403/429/500 still surface as gofalcon's typed errors.
type downloadReader struct {
	orig        runtime.ClientResponseReader
	body        []byte
	contentType string
}

// ReadResponse captures the 200 body and Content-Type into r and returns a valid
// *ReportExecutionsDownloadGetOK so the generated method's type assertion
// succeeds; other status codes delegate to the wrapped reader.
func (r *downloadReader) ReadResponse(resp runtime.ClientResponse, c runtime.Consumer) (any, error) {
	if resp.Code() == 200 {
		b, err := io.ReadAll(resp.Body())
		if err != nil {
			return nil, fmt.Errorf("read report execution download body: %w", err)
		}
		r.body = b
		r.contentType = resp.GetHeader("Content-Type")
		return report_executions.NewReportExecutionsDownloadGetOK(), nil
	}
	return r.orig.ReadResponse(resp, c)
}
