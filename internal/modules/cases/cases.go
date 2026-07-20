// Package cases implements the CrowdStrike Falcon case-management tools over two
// gofalcon sub-clients: cases (search/get/create/update cases, evidence, and
// tags) and case_management (listing case templates).
//
// It registers eight tools:
//   - falcon_search_cases            — two-step FQL search of case entities
//   - falcon_get_cases               — fetch full case records by ID
//   - falcon_create_case             — create a case (mutating)
//   - falcon_update_case             — update a case's fields (mutating)
//   - falcon_add_case_alert_evidence — attach alert evidence (mutating)
//   - falcon_add_case_event_evidence — attach LogScale event evidence (mutating)
//   - falcon_manage_case_tags        — add or remove tags (mutating)
//   - falcon_list_case_templates     — two-step list of case templates
//
// The read tools follow the two-step query→detail pattern (query for IDs, then
// bulk-fetch full records via base.FetchDetails). Case details come from
// EntitiesCasesPostV2 (POST body Ids); template details come from
// EntitiesTemplatesGetV1 (GET query params Ids). Both detail endpoints may
// reorder results, so records are reordered back to the query step's sort by id.
package cases

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"

	"github.com/crowdstrike/gofalcon/falcon/client/case_management"
	"github.com/crowdstrike/gofalcon/falcon/client/cases"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/crowdstrike/falcon-mcp/internal/modules/base"
	"github.com/crowdstrike/falcon-mcp/internal/modules/registry"
)

// Factory builds the cases module from shared deps. It consumes two gofalcon
// sub-clients: Cases for case CRUD, evidence, and tags, and CaseManagement for
// case templates. The generated aggregator (internal/mcpserver) collects the
// Factory, so the module needs no init side effect.
var Factory registry.Factory = func(d registry.Deps) base.Module {
	return &Module{
		Cases:       d.API.Cases,
		Templates:   d.API.CaseManagement,
		Concurrency: d.Concurrency,
		Logger:      d.Logger,
	}
}

// defaultCaseLimit is the search page size applied when search_cases omits
// limit, mirroring the Python falcon-mcp cases module's default of 10.
const defaultCaseLimit = 10

// defaultTemplateLimit is the page size applied when list_case_templates omits
// limit, mirroring the Python module's default of 50.
const defaultTemplateLimit = 50

// detailBatchSize is the maximum number of IDs fetched per detail call. It
// bounds each EntitiesCasesPostV2 / EntitiesTemplatesGetV1 request;
// base.FetchDetails chunks larger ID sets and fetches the chunks concurrently.
const detailBatchSize = 100

// fqlGuideURI is the MCP resource URI for the case-search FQL guide, matching
// falcon-mcp's falcon://cases/search/fql-guide.
const fqlGuideURI = "falcon://cases/search/fql-guide"

// errInvalidInput classifies client-side validation failures in the mutating
// tools so handlers can distinguish them from API errors.
var errInvalidInput = errors.New("cases: invalid input")

// CrowdStrike API scopes required by this module's operations. Surfaced on a
// 403 via base.APIError, referenced directly at each call site.
var (
	scopeCasesRead         = base.Scope{Name: "Cases", Read: true}
	scopeCasesWrite        = base.Scope{Name: "Cases", Write: true}
	scopeCaseTemplatesRead = base.Scope{Name: "Case Templates", Read: true}
)

// casesAPI is the minimal slice of the gofalcon cases client this module
// consumes, declared next to its consumer so handlers can be tested against a
// small fake rather than all of gofalcon.
type casesAPI interface {
	QueriesCasesGetV1(params *cases.QueriesCasesGetV1Params, opts ...cases.ClientOption) (*cases.QueriesCasesGetV1OK, error)
	EntitiesCasesPostV2(params *cases.EntitiesCasesPostV2Params, opts ...cases.ClientOption) (*cases.EntitiesCasesPostV2OK, error)
	EntitiesCasesPutV2(params *cases.EntitiesCasesPutV2Params, opts ...cases.ClientOption) (*cases.EntitiesCasesPutV2Created, error)
	EntitiesCasesPatchV2(params *cases.EntitiesCasesPatchV2Params, opts ...cases.ClientOption) (*cases.EntitiesCasesPatchV2OK, error)
	EntitiesAlertEvidencePostV1(params *cases.EntitiesAlertEvidencePostV1Params, opts ...cases.ClientOption) (*cases.EntitiesAlertEvidencePostV1OK, error)
	EntitiesEventEvidencePostV1(params *cases.EntitiesEventEvidencePostV1Params, opts ...cases.ClientOption) (*cases.EntitiesEventEvidencePostV1OK, error)
	EntitiesCaseTagsPostV1(params *cases.EntitiesCaseTagsPostV1Params, opts ...cases.ClientOption) (*cases.EntitiesCaseTagsPostV1OK, error)
	EntitiesCaseTagsDeleteV1(params *cases.EntitiesCaseTagsDeleteV1Params, opts ...cases.ClientOption) (*cases.EntitiesCaseTagsDeleteV1OK, error)
}

// templatesAPI is the minimal slice of the gofalcon case_management client this
// module consumes, for listing case templates.
type templatesAPI interface {
	QueriesTemplatesGetV1(params *case_management.QueriesTemplatesGetV1Params, opts ...case_management.ClientOption) (*case_management.QueriesTemplatesGetV1OK, error)
	EntitiesTemplatesGetV1(params *case_management.EntitiesTemplatesGetV1Params, opts ...case_management.ClientOption) (*case_management.EntitiesTemplatesGetV1OK, error)
}

// Module registers the cases tools. It holds only the shared, concurrency-safe
// Falcon clients and configuration; handlers are stateless and reentrant.
// Logger must be non-nil.
type Module struct {
	Cases       casesAPI
	Templates   templatesAPI
	Concurrency int // bounds concurrent detail fetches
	Logger      *slog.Logger
}

// Name reports the module name.
func (m *Module) Name() string { return "cases" }

// Description reports a one-line summary of the module.
func (m *Module) Description() string {
	return "Search, retrieve, create, update, and manage CrowdStrike Falcon cases, evidence, tags, and templates"
}

// searchCasesSchema is the input schema for falcon_search_cases. It is inferred
// from SearchInput's tags, then a mutate func adds the limit bounds/default and
// offset minimum the tag syntax cannot express.
var searchCasesSchema = base.SchemaFor[SearchInput](func(s *jsonschema.Schema) {
	s.Properties["limit"].Minimum = jsonschema.Ptr(1.0)
	s.Properties["limit"].Maximum = jsonschema.Ptr(500.0)
	s.Properties["limit"].Default = json.RawMessage(`10`)
	s.Properties["offset"].Minimum = jsonschema.Ptr(0.0)
})

// listTemplatesSchema is the input schema for falcon_list_case_templates.
var listTemplatesSchema = base.SchemaFor[TemplatesInput](func(s *jsonschema.Schema) {
	s.Properties["limit"].Minimum = jsonschema.Ptr(1.0)
	s.Properties["limit"].Maximum = jsonschema.Ptr(200.0)
	s.Properties["limit"].Default = json.RawMessage(`50`)
	s.Properties["offset"].Minimum = jsonschema.Ptr(0.0)
})

// createCaseSchema is the input schema for falcon_create_case.
var createCaseSchema = base.SchemaFor[CreateInput](func(s *jsonschema.Schema) {
	s.Properties["severity"].Minimum = jsonschema.Ptr(1.0)
	s.Properties["severity"].Maximum = jsonschema.Ptr(100.0)
})

// updateCaseSchema is the input schema for falcon_update_case.
var updateCaseSchema = base.SchemaFor[UpdateInput](func(s *jsonschema.Schema) {
	s.Properties["severity"].Minimum = jsonschema.Ptr(1.0)
	s.Properties["severity"].Maximum = jsonschema.Ptr(100.0)
})

// RegisterTools registers the eight case-management tools into r.
func (m *Module) RegisterTools(r base.Registrar) {
	base.AddTool(r, &mcp.Tool{
		Name: "search_cases",
		Description: "Find cases by criteria and return their complete details. Use this to " +
			"discover cases by status, severity, assignee, time range, or evidence attributes. " +
			"Consult falcon://cases/search/fql-guide before constructing filter expressions. " +
			"Returns full case records including status, severity, evidence, assigned user, and analysis results.",
		InputSchema: searchCasesSchema,
	}, m.searchCases)

	base.AddTool(r, &mcp.Tool{
		Name: "get_cases",
		Description: "Retrieve details for case IDs you already have. Use when you have specific " +
			"case IDs from search results or external references. For discovering cases by criteria, " +
			"use falcon_search_cases instead. Returns full case records.",
	}, m.getCases)

	base.AddTool(r, &mcp.Tool{
		Name: "create_case",
		Description: "Create a new case in CrowdStrike. Provide a name and severity at minimum. " +
			"Optionally attach alert or event evidence, assign a user, apply a template, and set tags. " +
			"Returns the created case record.",
		InputSchema: createCaseSchema,
		Annotations: base.MutatingAnnotations(),
	}, m.createCase)

	base.AddTool(r, &mcp.Tool{
		Name: "update_case",
		Description: "Update an existing case's fields. Provide the case ID and any fields to change. " +
			"Use expected_version for optimistic concurrency control to prevent conflicting updates. " +
			"Returns the updated case record with incremented version.",
		InputSchema: updateCaseSchema,
		Annotations: base.MutatingAnnotations(),
	}, m.updateCase)

	base.AddTool(r, &mcp.Tool{
		Name: "add_case_alert_evidence",
		Description: "Attach alert evidence to an existing case. Provide alert composite_id values " +
			"from the Alerts v2 API (e.g. from falcon_search_detections). Each case supports a maximum " +
			"of 100 combined evidence items. Returns the updated case record.",
		Annotations: base.MutatingAnnotations(),
	}, m.addCaseAlertEvidence)

	base.AddTool(r, &mcp.Tool{
		Name: "add_case_event_evidence",
		Description: "Attach LogScale event evidence to an existing case. Provide event IDs obtained " +
			"from falcon_search_ngsiem or the Falcon console. Each case supports a maximum of 100 " +
			"combined evidence items. Returns the updated case record.",
		Annotations: base.MutatingAnnotations(),
	}, m.addCaseEventEvidence)

	base.AddTool(r, &mcp.Tool{
		Name: "manage_case_tags",
		Description: "Add or remove tags on a case. Set action to 'add' to attach new tags, or " +
			"'remove' to delete existing tags. Returns the updated case record.",
		Annotations: base.MutatingAnnotations(),
	}, m.manageCaseTags)

	base.AddTool(r, &mcp.Tool{
		Name: "list_case_templates",
		Description: "List available case templates. Use to discover templates that can be applied " +
			"when creating or updating cases. Returns template details including name, custom fields, " +
			"and SLA configuration.",
		InputSchema: listTemplatesSchema,
	}, m.listCaseTemplates)
}

// RegisterResources publishes the case-search FQL guide as an MCP resource,
// mirroring falcon-mcp's falcon://cases/search/fql-guide resource.
func (m *Module) RegisterResources(s *mcp.Server) {
	base.TextResource(s,
		fqlGuideURI,
		"search_cases_fql_guide",
		"Contains the guide for the `filter` param of the `falcon_search_cases` tool.",
		"text/markdown",
		fqlGuide,
	)
}

// RegisterPrompts is a no-op: the cases module exposes no prompts.
func (m *Module) RegisterPrompts(_ *mcp.Server) {}

// SearchInput is the input for falcon_search_cases.
type SearchInput struct {
	Filter string `json:"filter,omitempty" jsonschema:"FQL filter expression. See falcon://cases/search/fql-guide for syntax (e.g. status:'new'+severity:>70)"`
	Limit  int    `json:"limit,omitempty" jsonschema:"maximum number of cases to return (default 10, max 500)"`
	Offset int    `json:"offset,omitempty" jsonschema:"starting index for pagination"`
	Q      string `json:"q,omitempty" jsonschema:"free-text search across all case metadata"`
	Sort   string `json:"sort,omitempty" jsonschema:"sort order. Fields: created_timestamp, updated_timestamp, severity, status, name, reference_id. Formats: 'field.desc', 'field|asc' (e.g. created_timestamp.desc)"`
}

func (m *Module) searchCases(ctx context.Context, req *mcp.CallToolRequest, in SearchInput) (*mcp.CallToolResult, base.SearchResult[*models.SdkCaseVM], error) {
	var zero base.SearchResult[*models.SdkCaseVM]
	limit := int64(in.Limit)
	if limit == 0 {
		limit = defaultCaseLimit
	}
	m.Logger.Debug("search_cases", "filter", in.Filter, "q", in.Q, "limit", limit, "offset", in.Offset, "sort", in.Sort)

	params := cases.NewQueriesCasesGetV1ParamsWithContext(ctx)
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

	queryResp, err := m.Cases.QueriesCasesGetV1(params)
	if err != nil {
		if details, ok := casesQueryFQLBadRequest(err); ok {
			return nil, base.FQLError[*models.SdkCaseVM](details, in.Filter, fqlGuide), nil
		}
	}
	if e := base.APIError(err, queryResp, scopeCasesRead); e != nil {
		return nil, zero, e
	}

	ids := queryResp.Payload.Resources
	m.Logger.Debug("search_cases query complete", "matched_ids", len(ids))
	if len(ids) == 0 {
		return nil, base.Found([]*models.SdkCaseVM{}, in.Filter).WithMeta(queryResp.Payload.Meta), nil
	}
	details, err := m.fetchCases(ctx, req, ids)
	if err != nil {
		return nil, zero, err
	}
	return nil, base.Found(details, in.Filter).WithMeta(queryResp.Payload.Meta), nil
}

// GetInput is the input for falcon_get_cases.
type GetInput struct {
	IDs []string `json:"ids" jsonschema:"case ID(s) to retrieve. These are opaque system IDs, not the human-readable reference_id (required, non-empty)"`
}

func (m *Module) getCases(ctx context.Context, req *mcp.CallToolRequest, in GetInput) (*mcp.CallToolResult, base.EntitiesResult[*models.SdkCaseVM], error) {
	var zero base.EntitiesResult[*models.SdkCaseVM]
	if len(in.IDs) == 0 {
		return nil, zero, wrapInvalid("get cases", "ids must not be empty")
	}
	m.Logger.Debug("get_cases", "ids", len(in.IDs))

	details, err := m.fetchCases(ctx, req, in.IDs)
	if err != nil {
		return nil, zero, err
	}
	return nil, base.Entities(details), nil
}

// TemplatesInput is the input for falcon_list_case_templates.
type TemplatesInput struct {
	Limit  int `json:"limit,omitempty" jsonschema:"maximum number of templates to return (default 50, max 200)"`
	Offset int `json:"offset,omitempty" jsonschema:"starting index for pagination"`
}

func (m *Module) listCaseTemplates(ctx context.Context, req *mcp.CallToolRequest, in TemplatesInput) (*mcp.CallToolResult, base.EntitiesResult[*models.APITemplateV1], error) {
	var zero base.EntitiesResult[*models.APITemplateV1]
	limit := int64(in.Limit)
	if limit == 0 {
		limit = defaultTemplateLimit
	}
	m.Logger.Debug("list_case_templates", "limit", limit, "offset", in.Offset)

	params := case_management.NewQueriesTemplatesGetV1ParamsWithContext(ctx)
	params.Limit = &limit
	if in.Offset != 0 {
		offset := int64(in.Offset)
		params.Offset = &offset
	}

	queryResp, err := m.Templates.QueriesTemplatesGetV1(params)
	if e := base.APIError(err, queryResp, scopeCaseTemplatesRead); e != nil {
		return nil, zero, e
	}

	ids := queryResp.Payload.Resources
	m.Logger.Debug("list_case_templates query complete", "matched_ids", len(ids))
	if len(ids) == 0 {
		return nil, base.Entities([]*models.APITemplateV1{}).WithMeta(queryResp.Payload.Meta), nil
	}
	details, err := m.fetchTemplates(ctx, req, ids)
	if err != nil {
		return nil, zero, err
	}
	return nil, base.Entities(details).WithMeta(queryResp.Payload.Meta), nil
}

// fetchCases fetches full case records for the given IDs. EntitiesCasesPostV2
// takes the IDs in a POST body and may reorder results, so records are reordered
// back to the query step's sort by their id.
func (m *Module) fetchCases(ctx context.Context, req *mcp.CallToolRequest, ids []string) ([]*models.SdkCaseVM, error) {
	return base.FetchDetails(ctx, base.FetchDetailsParams[*models.SdkCaseVM]{
		IDs:         ids,
		ChunkSize:   detailBatchSize,
		Concurrency: m.Concurrency,
		Progress:    base.ProgressFunc(ctx, req),
		Fetch: func(ctx context.Context, chunk []string) ([]*models.SdkCaseVM, error) {
			params := cases.NewEntitiesCasesPostV2ParamsWithContext(ctx)
			params.Body = &models.OperationsGetCasesByIDsRequest{Ids: chunk}
			resp, err := m.Cases.EntitiesCasesPostV2(params)
			if e := base.APIError(err, resp, scopeCasesRead); e != nil {
				return nil, e
			}
			return resp.Payload.Resources, nil
		},
		KeyFn: func(c *models.SdkCaseVM) string {
			if c == nil || c.ID == nil {
				return ""
			}
			return *c.ID
		},
	})
}

// fetchTemplates fetches full template records for the given IDs.
// EntitiesTemplatesGetV1 takes the IDs as GET query params (params.Ids) and may
// reorder results, so records are reordered back to the query step's sort by id.
func (m *Module) fetchTemplates(ctx context.Context, req *mcp.CallToolRequest, ids []string) ([]*models.APITemplateV1, error) {
	return base.FetchDetails(ctx, base.FetchDetailsParams[*models.APITemplateV1]{
		IDs:         ids,
		ChunkSize:   detailBatchSize,
		Concurrency: m.Concurrency,
		Progress:    base.ProgressFunc(ctx, req),
		Fetch: func(ctx context.Context, chunk []string) ([]*models.APITemplateV1, error) {
			params := case_management.NewEntitiesTemplatesGetV1ParamsWithContext(ctx)
			params.Ids = chunk
			resp, err := m.Templates.EntitiesTemplatesGetV1(params)
			if e := base.APIError(err, resp, scopeCaseTemplatesRead); e != nil {
				return nil, e
			}
			return resp.Payload.Resources, nil
		},
		KeyFn: func(t *models.APITemplateV1) string {
			if t == nil || t.ID == nil {
				return ""
			}
			return *t.ID
		},
	})
}

// casesQueryFQLBadRequest reports whether err is a 400-class cases query error
// and, if so, extracts the API error details for an FQL-error response. gofalcon
// surfaces the 400 as a typed *cases.QueriesCasesGetV1BadRequest whose payload
// carries the errors as []*models.MsaAPIError; classify with errors.As rather
// than string matching.
func casesQueryFQLBadRequest(err error) ([]base.FQLErrorDetail, bool) {
	var badReq *cases.QueriesCasesGetV1BadRequest
	if !errors.As(err, &badReq) || badReq.Payload == nil {
		return nil, false
	}
	return base.FQLErrorDetails(badReq.Payload.Errors), true
}
