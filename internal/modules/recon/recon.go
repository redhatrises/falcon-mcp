// Package recon implements the CrowdStrike Falcon Intelligence Recon tools over
// the gofalcon recon client: searching Recon notifications (recon alerts),
// monitoring rules, and exposed-data records. It registers three FQL guide
// resources, one per search tool.
//
// Each tool is a two-step typed gofalcon call — a query for matching IDs
// followed by a bulk detail fetch (base.FetchDetails) — so the module bounds
// its fan-out with Deps.Concurrency. All three tools are read-only.
package recon

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"

	"github.com/crowdstrike/gofalcon/falcon/client/recon"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/crowdstrike/falcon-mcp/internal/modules/base"
	"github.com/crowdstrike/falcon-mcp/internal/modules/registry"
)

// defaultLimit is the search page size applied when the caller omits limit.
const defaultLimit = 10

// recordBatchSize is the maximum number of IDs fetched per detail call. The
// query operations cap limit at 500, so a single query never returns more IDs
// than one detail call accepts; the chunking in base.FetchDetails is a safety
// net for callers that pass many IDs, not the common path.
const recordBatchSize = 500

// MCP resource URIs for the three recon FQL guides, matching falcon-mcp's
// falcon://recon/{notifications,rules,exposed-data-records}/search/fql-guide
// resources.
const (
	notificationsFQLGuideURI      = "falcon://recon/notifications/search/fql-guide"
	rulesFQLGuideURI              = "falcon://recon/rules/search/fql-guide"
	exposedDataRecordsFQLGuideURI = "falcon://recon/exposed-data-records/search/fql-guide"
)

// scopeMonitoringRules is the CrowdStrike API scope required by every recon
// operation. Surfaced on a 403 via base.APIError.
var scopeMonitoringRules = base.Scope{Name: "Monitoring rules (Falcon Intelligence Recon)", Read: true}

// Factory builds the recon module from shared deps. The generated aggregator
// (internal/mcpserver) collects it, so the module needs no init side effect.
var Factory registry.Factory = func(d registry.Deps) base.Module {
	return &Module{API: d.API.Recon, Concurrency: d.Concurrency, Logger: d.Logger}
}

// reconAPI is the minimal slice of the gofalcon recon client this module
// consumes, declared next to its consumer so handlers can be tested against a
// small fake rather than all of gofalcon.
type reconAPI interface {
	QueryNotificationsV1(params *recon.QueryNotificationsV1Params, opts ...recon.ClientOption) (*recon.QueryNotificationsV1OK, error)
	GetNotificationsDetailedV1(params *recon.GetNotificationsDetailedV1Params, opts ...recon.ClientOption) (*recon.GetNotificationsDetailedV1OK, error)
	QueryRulesV1(params *recon.QueryRulesV1Params, opts ...recon.ClientOption) (*recon.QueryRulesV1OK, error)
	GetRulesV1(params *recon.GetRulesV1Params, opts ...recon.ClientOption) (*recon.GetRulesV1OK, error)
	QueryNotificationsExposedDataRecordsV1(params *recon.QueryNotificationsExposedDataRecordsV1Params, opts ...recon.ClientOption) (*recon.QueryNotificationsExposedDataRecordsV1OK, error)
	GetNotificationsExposedDataRecordsV1(params *recon.GetNotificationsExposedDataRecordsV1Params, opts ...recon.ClientOption) (*recon.GetNotificationsExposedDataRecordsV1OK, error)
}

// Module registers the recon tools. It holds only the shared, concurrency-safe
// Falcon client and configuration; handlers are stateless and reentrant.
// Logger must be non-nil.
type Module struct {
	API         reconAPI
	Concurrency int // bounds concurrent detail fetches
	Logger      *slog.Logger
}

// Name reports the module name.
func (m *Module) Name() string { return "recon" }

// Description reports a one-line summary of the module.
func (m *Module) Description() string {
	return "Search Falcon Intelligence Recon notifications, monitoring rules, and exposed-data records"
}

// Tool and parameter descriptions, kept 1:1 with the Python falcon-mcp recon
// module. The filter descriptions carry backticks and the sort/q descriptions
// carry multi-line content that cannot live in a jsonschema struct tag, so they
// are consts applied to each schema by its mutate func below.
const (
	searchNotificationsDescription = `Search Falcon Intelligence Recon notifications (also called recon alerts) and return their full details.

Use this for dark web matches, leaked credentials, typosquatting matches, and breach
summaries triggered by your monitoring rules. Consult
` + "`falcon://recon/notifications/search/fql-guide`" + ` before constructing filter expressions.
This serves the external cyber risk monitoring capability of CrowdStrike Counter Adversary
Operations (CAO). For endpoint, XDR, or NG-SIEM alerts, use ` + "`falcon_search_detections`" + `
instead. Returns full notification records with a nested ` + "`notification`" + ` object
containing status, rule metadata, breach_summary, and item details.
Responses include ` + "`pagination.total`" + ` (the total number of records matching the filter, or null when the API does not report a count) — use it to answer "how many" questions.`

	searchRulesDescription = `Search Falcon Intelligence Recon monitoring rules and return their full details.

Use this to list the rules that generate your recon notifications — find rules by
topic (domain, email, typosquatting, brand), priority, status, or whether breach
monitoring is enabled. Consult ` + "`falcon://recon/rules/search/fql-guide`" + ` before
constructing filter expressions. These monitoring rules power the external cyber risk
monitoring capability of CrowdStrike Counter Adversary Operations (CAO). Returns full
rule definitions including topic, priority, filter expressions, and notification settings.
Responses include ` + "`pagination.total`" + ` (the total number of records matching the filter, or null when the API does not report a count) — use it to answer "how many" questions.`

	searchExposedDataRecordsDescription = `Search Falcon Intelligence Recon exposed-data records and return their full details.

Use this to find leaked credential and PII rows associated with recon notifications —
emails, login IDs, password hashes, domains, and breach metadata. Consult
` + "`falcon://recon/exposed-data-records/search/fql-guide`" + ` before constructing filter
expressions. These records are part of the external cyber risk monitoring capability of
CrowdStrike Counter Adversary Operations (CAO). Returns full records including credential
fields, location data, and associated notification context.
Responses include ` + "`pagination.total`" + ` (the total number of records matching the filter, or null when the API does not report a count) — use it to answer "how many" questions.`

	notificationsFilterDescription      = "FQL filter expression. See `falcon://recon/notifications/search/fql-guide` for syntax."
	rulesFilterDescription              = "FQL filter expression. See `falcon://recon/rules/search/fql-guide` for syntax."
	exposedDataRecordsFilterDescription = "FQL filter expression. See `falcon://recon/exposed-data-records/search/fql-guide` for syntax."

	notificationsSortDescription = `Sort notifications using these options:
created_date: When the notification was created
updated_date: When the notification was last updated

Append |asc or |desc for direction (default desc).
Examples: 'created_date|desc', 'updated_date|asc'`

	rulesSortDescription = `Sort rules using these options:
created_timestamp: When the rule was created
last_updated_timestamp: When the rule was last modified
priority: Rule priority level
topic: Rule topic category

Append |asc or |desc for direction (default desc).
Examples: 'created_timestamp|desc', 'priority|asc'`

	exposedDataRecordsSortDescription = `Sort records using these options:
created_date: When the record was created
exposure_date: When the data was exposed/breached

Append |asc or |desc for direction (default desc).
Examples: 'created_date|desc', 'exposure_date|desc'`

	notificationsQDescription      = "Free text search across all notification metadata."
	rulesQDescription              = "Free text search across all rule metadata."
	exposedDataRecordsQDescription = "Free text search across all exposed-data record fields."

	limitDescription  = "Maximum number of results to return (default: 10; max: 500). offset + limit must not exceed 10,000."
	offsetDescription = "Starting index for pagination. offset + limit must not exceed 10,000."
)

// searchSchema builds a search input schema, applying the shared limit bounds
// (min 1, max 500, default 10) and offset minimum the tag syntax cannot
// express, then the multi-line sort/q and backtick-bearing filter descriptions
// that cannot live in a struct tag.
func searchSchema[In any](filterDesc, sortDesc, qDesc string) *jsonschema.Schema {
	return base.SchemaFor[In](func(s *jsonschema.Schema) {
		s.Properties["filter"].Description = filterDesc
		s.Properties["sort"].Description = sortDesc
		s.Properties["q"].Description = qDesc
		s.Properties["limit"].Description = limitDescription
		s.Properties["offset"].Description = offsetDescription
		s.Properties["limit"].Minimum = jsonschema.Ptr(1.0)
		s.Properties["limit"].Maximum = jsonschema.Ptr(500.0)
		s.Properties["limit"].Default = json.RawMessage(`10`)
		s.Properties["offset"].Minimum = jsonschema.Ptr(0.0)
	})
}

var (
	searchNotificationsSchema      = searchSchema[NotificationsInput](notificationsFilterDescription, notificationsSortDescription, notificationsQDescription)
	searchRulesSchema              = searchSchema[RulesInput](rulesFilterDescription, rulesSortDescription, rulesQDescription)
	searchExposedDataRecordsSchema = searchSchema[ExposedDataRecordsInput](exposedDataRecordsFilterDescription, exposedDataRecordsSortDescription, exposedDataRecordsQDescription)
)

// RegisterTools registers the recon tools into r.
func (m *Module) RegisterTools(r base.Registrar) {
	base.AddTool(r, &mcp.Tool{
		Name:        "search_recon_notifications",
		Description: searchNotificationsDescription,
		InputSchema: searchNotificationsSchema,
	}, m.searchReconNotifications)

	base.AddTool(r, &mcp.Tool{
		Name:        "search_recon_rules",
		Description: searchRulesDescription,
		InputSchema: searchRulesSchema,
	}, m.searchReconRules)

	base.AddTool(r, &mcp.Tool{
		Name:        "search_recon_exposed_data_records",
		Description: searchExposedDataRecordsDescription,
		InputSchema: searchExposedDataRecordsSchema,
	}, m.searchReconExposedDataRecords)
}

// RegisterResources publishes the three recon FQL guides as MCP resources,
// mirroring falcon-mcp's recon FQL guide resources.
func (m *Module) RegisterResources(s *mcp.Server) {
	base.TextResource(s, notificationsFQLGuideURI,
		"search_recon_notifications_fql_guide",
		"Contains the guide for the `filter` param of the `falcon_search_recon_notifications` tool.",
		"text/markdown", notificationsFQLGuide)

	base.TextResource(s, rulesFQLGuideURI,
		"search_recon_rules_fql_guide",
		"Contains the guide for the `filter` param of the `falcon_search_recon_rules` tool.",
		"text/markdown", rulesFQLGuide)

	base.TextResource(s, exposedDataRecordsFQLGuideURI,
		"search_recon_exposed_data_records_fql_guide",
		"Contains the guide for the `filter` param of the `falcon_search_recon_exposed_data_records` tool.",
		"text/markdown", exposedDataRecordsFQLGuide)
}

// RegisterPrompts is a no-op: the recon module exposes no prompts.
func (m *Module) RegisterPrompts(_ *mcp.Server) {}

// NotificationsInput is the input for falcon_search_recon_notifications. The
// json tags drive the SDK's unmarshal into this struct; the served schema
// (searchNotificationsSchema) is inferred from these jsonschema tags, then
// augmented with the limit/offset bounds and the backtick-bearing filter and
// multi-line sort/q descriptions.
type NotificationsInput struct {
	Filter string `json:"filter,omitempty" jsonschema:"FQL filter (e.g. status:'new'+rule_priority:'high')"`
	Q      string `json:"q,omitempty" jsonschema:"free-text search across all notification metadata"`
	Limit  int    `json:"limit,omitempty" jsonschema:"maximum records to return"`
	Offset int    `json:"offset,omitempty" jsonschema:"pagination offset"`
	Sort   string `json:"sort,omitempty" jsonschema:"FQL sort (e.g. created_date|desc)"`
}

func (m *Module) searchReconNotifications(ctx context.Context, req *mcp.CallToolRequest, in NotificationsInput) (*mcp.CallToolResult, base.SearchResult[*models.DomainDetailedNotificationV1], error) {
	var zero base.SearchResult[*models.DomainDetailedNotificationV1]
	limit := int64(in.Limit)
	if limit == 0 {
		limit = defaultLimit
	}
	m.Logger.Debug("search_recon_notifications", "filter", in.Filter, "q", in.Q, "limit", limit, "offset", in.Offset, "sort", in.Sort)

	params := recon.NewQueryNotificationsV1ParamsWithContext(ctx)
	params.Limit = &limit
	if in.Filter != "" {
		params.Filter = &in.Filter
	}
	if in.Q != "" {
		params.Q = &in.Q
	}
	if in.Offset != 0 {
		offset := int64(in.Offset)
		params.Offset = &offset
	}
	if in.Sort != "" {
		params.Sort = &in.Sort
	}

	queryResp, err := m.API.QueryNotificationsV1(params)
	if err != nil {
		if details, ok := notificationsFQLBadRequest(err); ok {
			return nil, base.FQLError[*models.DomainDetailedNotificationV1](details, in.Filter, notificationsFQLGuide), nil
		}
	}
	if e := base.APIError(err, queryResp, scopeMonitoringRules); e != nil {
		return nil, zero, e
	}

	ids := queryResp.Payload.Resources
	m.Logger.Debug("search_recon_notifications query complete", "matched_ids", len(ids))
	if len(ids) == 0 {
		return nil, base.Found([]*models.DomainDetailedNotificationV1{}, in.Filter).WithMeta(queryResp.Payload.Meta), nil
	}
	details, err := m.fetchNotifications(ctx, req, ids)
	if err != nil {
		return nil, zero, err
	}
	return nil, base.Found(details, in.Filter).WithMeta(queryResp.Payload.Meta), nil
}

// RulesInput is the input for falcon_search_recon_rules.
type RulesInput struct {
	Filter string `json:"filter,omitempty" jsonschema:"FQL filter (e.g. status:'active'+priority:'high')"`
	Q      string `json:"q,omitempty" jsonschema:"free-text search across all rule metadata"`
	Limit  int    `json:"limit,omitempty" jsonschema:"maximum records to return"`
	Offset int    `json:"offset,omitempty" jsonschema:"pagination offset"`
	Sort   string `json:"sort,omitempty" jsonschema:"FQL sort (e.g. created_timestamp|desc)"`
}

func (m *Module) searchReconRules(ctx context.Context, req *mcp.CallToolRequest, in RulesInput) (*mcp.CallToolResult, base.SearchResult[*models.SadomainRule], error) {
	var zero base.SearchResult[*models.SadomainRule]
	limit := int64(in.Limit)
	if limit == 0 {
		limit = defaultLimit
	}
	m.Logger.Debug("search_recon_rules", "filter", in.Filter, "q", in.Q, "limit", limit, "offset", in.Offset, "sort", in.Sort)

	params := recon.NewQueryRulesV1ParamsWithContext(ctx)
	params.Limit = &limit
	if in.Filter != "" {
		params.Filter = &in.Filter
	}
	if in.Q != "" {
		params.Q = &in.Q
	}
	if in.Offset != 0 {
		offset := int64(in.Offset)
		params.Offset = &offset
	}
	if in.Sort != "" {
		params.Sort = &in.Sort
	}

	queryResp, err := m.API.QueryRulesV1(params)
	if err != nil {
		if details, ok := rulesFQLBadRequest(err); ok {
			return nil, base.FQLError[*models.SadomainRule](details, in.Filter, rulesFQLGuide), nil
		}
	}
	if e := base.APIError(err, queryResp, scopeMonitoringRules); e != nil {
		return nil, zero, e
	}

	ids := queryResp.Payload.Resources
	m.Logger.Debug("search_recon_rules query complete", "matched_ids", len(ids))
	if len(ids) == 0 {
		return nil, base.Found([]*models.SadomainRule{}, in.Filter).WithMeta(queryResp.Payload.Meta), nil
	}
	details, err := m.fetchRules(ctx, req, ids)
	if err != nil {
		return nil, zero, err
	}
	return nil, base.Found(details, in.Filter).WithMeta(queryResp.Payload.Meta), nil
}

// ExposedDataRecordsInput is the input for
// falcon_search_recon_exposed_data_records.
type ExposedDataRecordsInput struct {
	Filter string `json:"filter,omitempty" jsonschema:"FQL filter (e.g. domain:'example.com'+credential_status:'confirmed_active')"`
	Q      string `json:"q,omitempty" jsonschema:"free-text search across all exposed-data record fields"`
	Limit  int    `json:"limit,omitempty" jsonschema:"maximum records to return"`
	Offset int    `json:"offset,omitempty" jsonschema:"pagination offset"`
	Sort   string `json:"sort,omitempty" jsonschema:"FQL sort (e.g. created_date|desc)"`
}

func (m *Module) searchReconExposedDataRecords(ctx context.Context, req *mcp.CallToolRequest, in ExposedDataRecordsInput) (*mcp.CallToolResult, base.SearchResult[*models.APINotificationExposedDataRecordV1], error) {
	var zero base.SearchResult[*models.APINotificationExposedDataRecordV1]
	limit := int64(in.Limit)
	if limit == 0 {
		limit = defaultLimit
	}
	m.Logger.Debug("search_recon_exposed_data_records", "filter", in.Filter, "q", in.Q, "limit", limit, "offset", in.Offset, "sort", in.Sort)

	params := recon.NewQueryNotificationsExposedDataRecordsV1ParamsWithContext(ctx)
	params.Limit = &limit
	if in.Filter != "" {
		params.Filter = &in.Filter
	}
	if in.Q != "" {
		params.Q = &in.Q
	}
	if in.Offset != 0 {
		offset := int64(in.Offset)
		params.Offset = &offset
	}
	if in.Sort != "" {
		params.Sort = &in.Sort
	}

	queryResp, err := m.API.QueryNotificationsExposedDataRecordsV1(params)
	if err != nil {
		if details, ok := exposedDataRecordsFQLBadRequest(err); ok {
			return nil, base.FQLError[*models.APINotificationExposedDataRecordV1](details, in.Filter, exposedDataRecordsFQLGuide), nil
		}
	}
	if e := base.APIError(err, queryResp, scopeMonitoringRules); e != nil {
		return nil, zero, e
	}

	ids := queryResp.Payload.Resources
	m.Logger.Debug("search_recon_exposed_data_records query complete", "matched_ids", len(ids))
	if len(ids) == 0 {
		return nil, base.Found([]*models.APINotificationExposedDataRecordV1{}, in.Filter).WithMeta(queryResp.Payload.Meta), nil
	}
	details, err := m.fetchExposedDataRecords(ctx, req, ids)
	if err != nil {
		return nil, zero, err
	}
	return nil, base.Found(details, in.Filter).WithMeta(queryResp.Payload.Meta), nil
}

// fetchNotifications fetches full notification records for the given IDs,
// chunking and fetching concurrently when the set exceeds a single detail
// call's capacity. GetNotificationsDetailedV1 may reorder results, so the
// records are reordered back to the query step's sort by their id field.
func (m *Module) fetchNotifications(ctx context.Context, req *mcp.CallToolRequest, ids []string) ([]*models.DomainDetailedNotificationV1, error) {
	return base.FetchDetails(ctx, base.FetchDetailsParams[*models.DomainDetailedNotificationV1]{
		IDs:         ids,
		ChunkSize:   recordBatchSize,
		Concurrency: m.Concurrency,
		Progress:    base.ProgressFunc(ctx, req),
		Fetch: func(ctx context.Context, chunk []string) ([]*models.DomainDetailedNotificationV1, error) {
			params := recon.NewGetNotificationsDetailedV1ParamsWithContext(ctx)
			params.Ids = chunk
			resp, err := m.API.GetNotificationsDetailedV1(params)
			if e := base.APIError(err, resp, scopeMonitoringRules); e != nil {
				return nil, e
			}
			return resp.Payload.Resources, nil
		},
		KeyFn: func(n *models.DomainDetailedNotificationV1) string {
			if n == nil || n.ID == nil {
				return ""
			}
			return *n.ID
		},
	})
}

// fetchRules fetches full rule definitions for the given IDs. GetRulesV1 may
// reorder results, so the rules are reordered back to the query step's sort by
// their id field.
func (m *Module) fetchRules(ctx context.Context, req *mcp.CallToolRequest, ids []string) ([]*models.SadomainRule, error) {
	return base.FetchDetails(ctx, base.FetchDetailsParams[*models.SadomainRule]{
		IDs:         ids,
		ChunkSize:   recordBatchSize,
		Concurrency: m.Concurrency,
		Progress:    base.ProgressFunc(ctx, req),
		Fetch: func(ctx context.Context, chunk []string) ([]*models.SadomainRule, error) {
			params := recon.NewGetRulesV1ParamsWithContext(ctx)
			params.Ids = chunk
			resp, err := m.API.GetRulesV1(params)
			if e := base.APIError(err, resp, scopeMonitoringRules); e != nil {
				return nil, e
			}
			return resp.Payload.Resources, nil
		},
		KeyFn: func(r *models.SadomainRule) string {
			if r == nil || r.ID == nil {
				return ""
			}
			return *r.ID
		},
	})
}

// fetchExposedDataRecords fetches full exposed-data records for the given IDs.
// GetNotificationsExposedDataRecordsV1 may reorder results, so the records are
// reordered back to the query step's sort by their id field.
func (m *Module) fetchExposedDataRecords(ctx context.Context, req *mcp.CallToolRequest, ids []string) ([]*models.APINotificationExposedDataRecordV1, error) {
	return base.FetchDetails(ctx, base.FetchDetailsParams[*models.APINotificationExposedDataRecordV1]{
		IDs:         ids,
		ChunkSize:   recordBatchSize,
		Concurrency: m.Concurrency,
		Progress:    base.ProgressFunc(ctx, req),
		Fetch: func(ctx context.Context, chunk []string) ([]*models.APINotificationExposedDataRecordV1, error) {
			params := recon.NewGetNotificationsExposedDataRecordsV1ParamsWithContext(ctx)
			params.Ids = chunk
			resp, err := m.API.GetNotificationsExposedDataRecordsV1(params)
			if e := base.APIError(err, resp, scopeMonitoringRules); e != nil {
				return nil, e
			}
			return resp.Payload.Resources, nil
		},
		KeyFn: func(r *models.APINotificationExposedDataRecordV1) string {
			if r == nil || r.ID == nil {
				return ""
			}
			return *r.ID
		},
	})
}

// notificationsFQLBadRequest reports whether err is a 400-class notification
// query error and, if so, extracts the API error details for an FQL-error
// response. gofalcon surfaces 400s as a typed *recon.QueryNotificationsV1BadRequest
// whose payload carries the errors as []*models.DomainReconAPIError; classify
// with errors.As rather than string matching.
func notificationsFQLBadRequest(err error) ([]base.FQLErrorDetail, bool) {
	var badReq *recon.QueryNotificationsV1BadRequest
	if !errors.As(err, &badReq) || badReq.Payload == nil {
		return nil, false
	}
	return reconErrorDetails(badReq.Payload.Errors), true
}

// rulesFQLBadRequest reports whether err is a 400-class rule query error and,
// if so, extracts the API error details.
func rulesFQLBadRequest(err error) ([]base.FQLErrorDetail, bool) {
	var badReq *recon.QueryRulesV1BadRequest
	if !errors.As(err, &badReq) || badReq.Payload == nil {
		return nil, false
	}
	return reconErrorDetails(badReq.Payload.Errors), true
}

// exposedDataRecordsFQLBadRequest reports whether err is a 400-class
// exposed-data-record query error and, if so, extracts the API error details.
func exposedDataRecordsFQLBadRequest(err error) ([]base.FQLErrorDetail, bool) {
	var badReq *recon.QueryNotificationsExposedDataRecordsV1BadRequest
	if !errors.As(err, &badReq) || badReq.Payload == nil {
		return nil, false
	}
	return reconErrorDetails(badReq.Payload.Errors), true
}

// reconErrorDetails flattens gofalcon DomainReconAPIError values into
// base.FQLErrorDetail, skipping nil entries and dereferencing the optional
// Code/Message pointers. The recon query endpoints carry their 400 errors as
// []*models.DomainReconAPIError rather than the []*models.MsaAPIError that
// base.FQLErrorDetails consumes, so this module converts them locally.
func reconErrorDetails(errs []*models.DomainReconAPIError) []base.FQLErrorDetail {
	details := make([]base.FQLErrorDetail, 0, len(errs))
	for _, e := range errs {
		if e == nil {
			continue
		}
		var code int32
		if e.Code != nil {
			code = *e.Code
		}
		var msg string
		if e.Message != nil {
			msg = *e.Message
		}
		details = append(details, base.FQLErrorDetail{Code: code, Message: msg})
	}
	return details
}
