// Package intel implements the CrowdStrike Falcon threat-intelligence tools over
// the gofalcon intel client: searching threat actors, indicators, and reports,
// plus generating a MITRE ATT&CK report for a given actor. It registers three
// FQL guide resources, one per search tool.
//
// The three search tools are single-step typed gofalcon calls that return full
// entities directly. get_mitre_report (see mitre.go) streams the report body
// into a buffer via the gofalcon client's io.Writer payload. All four tools are
// read-only; this module does no bulk detail fetch and ignores Deps.Concurrency.
package intel

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"

	"github.com/crowdstrike/gofalcon/falcon/client/intel"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/crowdstrike/falcon-mcp/internal/modules/base"
	"github.com/crowdstrike/falcon-mcp/internal/modules/registry"
)

// Factory builds the intel module from shared deps. The generated aggregator
// (internal/mcpserver) collects it, so the module needs no init side effect.
// All tools are single-call, so the module ignores Deps.Concurrency.
var Factory registry.Factory = func(d registry.Deps) base.Module {
	return &Module{API: d.API.Intel, Logger: d.Logger}
}

// defaultLimit is the search page size applied when the caller omits limit.
const defaultLimit = 10

// CrowdStrike API scopes required by this module's operations. Surfaced on a
// 403 via base.APIError, referenced directly at each call site.
var (
	scopeActors     = base.Scope{Name: "Actors (Falcon Intelligence)", Read: true}
	scopeIndicators = base.Scope{Name: "Indicators (Falcon Intelligence)", Read: true}
	scopeReports    = base.Scope{Name: "Reports (Falcon Intelligence)", Read: true}
)

// intelAPI is the minimal slice of the gofalcon intel client this module
// consumes, declared next to its consumer so handlers can be tested against a
// tiny fake rather than all of gofalcon. GetMitreReport takes an io.Writer that
// receives the report body and the variadic ClientOption, mirroring the
// gofalcon client signature.
type intelAPI interface {
	QueryIntelActorEntities(params *intel.QueryIntelActorEntitiesParams, opts ...intel.ClientOption) (*intel.QueryIntelActorEntitiesOK, error)
	QueryIntelIndicatorEntities(params *intel.QueryIntelIndicatorEntitiesParams, opts ...intel.ClientOption) (*intel.QueryIntelIndicatorEntitiesOK, error)
	QueryIntelReportEntities(params *intel.QueryIntelReportEntitiesParams, opts ...intel.ClientOption) (*intel.QueryIntelReportEntitiesOK, error)
	GetMitreReport(params *intel.GetMitreReportParams, writer io.Writer, opts ...intel.ClientOption) (*intel.GetMitreReportOK, error)
}

// Module registers the intel tools. It holds only the shared, concurrency-safe
// Falcon client and configuration; handlers are stateless and reentrant.
// Logger must be non-nil.
type Module struct {
	API    intelAPI
	Logger *slog.Logger
}

// Name reports the module name.
func (m *Module) Name() string { return "intel" }

// Description reports a one-line summary of the module.
func (m *Module) Description() string {
	return "Search Falcon threat intelligence: adversaries, indicators, reports, and MITRE ATT&CK profiles"
}

// searchSchema builds a search input schema, applying the shared limit
// bounds/default (min 1, max 5000, default 10) and offset minimum the tag
// syntax cannot express.
func searchSchema[In any]() *jsonschema.Schema {
	return base.SchemaFor[In](func(s *jsonschema.Schema) {
		s.Properties["limit"].Minimum = jsonschema.Ptr(1.0)
		s.Properties["limit"].Maximum = jsonschema.Ptr(5000.0)
		s.Properties["limit"].Default = json.RawMessage(`10`)
		s.Properties["offset"].Minimum = jsonschema.Ptr(0.0)
	})
}

var (
	searchActorsSchema     = searchSchema[ActorsInput]()
	searchIndicatorsSchema = searchSchema[IndicatorsInput]()
	searchReportsSchema    = searchSchema[ReportsInput]()
)

// RegisterTools registers the four intel tools into r. All are read-only.
func (m *Module) RegisterTools(r base.Registrar) {
	base.AddTool(r, &mcp.Tool{
		Name: "search_actors",
		Description: "Research threat actors and adversary groups tracked by CrowdStrike intelligence using intel FQL (fields: name, actor_type, target_countries, target_industries, motivations, created_date, last_activity_date). Consult falcon://intel/actors/fql-guide before constructing filter expressions. Returns full actor profiles.\n" +
			"Responses include `pagination.total` (the total number of records matching the filter, " +
			"or null when the API does not report a count) — use it to answer \"how many\" questions.",
		InputSchema: searchActorsSchema,
	}, m.searchActors)

	base.AddTool(r, &mcp.Tool{
		Name: "search_indicators",
		Description: "Search threat indicators/IOCs from CrowdStrike intelligence using intel FQL (fields: type, indicator, malicious_confidence, malware_families, kill_chains, published_date, threat_types, vulnerabilities). Consult falcon://intel/indicators/fql-guide before constructing filter expressions. Returns full indicator details.\n" +
			"Responses include `pagination.total` (the total number of records matching the filter, " +
			"or null when the API does not report a count) — use it to answer \"how many\" questions.",
		InputSchema: searchIndicatorsSchema,
	}, m.searchIndicators)

	base.AddTool(r, &mcp.Tool{
		Name: "search_reports",
		Description: "Search CrowdStrike intelligence publications and threat reports using intel FQL (fields: name, type, sub_type, actors, target_countries, target_industries, motivations, tags, created_date). Consult falcon://intel/reports/fql-guide before constructing filter expressions. Returns full report metadata.\n" +
			"Responses include `pagination.total` (the total number of records matching the filter, " +
			"or null when the API does not report a count) — use it to answer \"how many\" questions.",
		InputSchema: searchReportsSchema,
	}, m.searchReports)

	base.AddTool(r, &mcp.Tool{
		Name:        "get_mitre_report",
		Description: "Generate a MITRE ATT&CK report (TTPs) for a threat actor. Accepts an actor name (e.g. 'WARP PANDA') or numeric ID; format 'json' (parsed) or 'csv' (raw text).",
	}, m.getMitreReport)
}

// RegisterResources publishes the three intel FQL guides as MCP resources,
// mirroring falcon-mcp's falcon://intel/{actors,indicators,reports}/fql-guide
// resources.
func (m *Module) RegisterResources(s *mcp.Server) {
	base.TextResource(s, actorsFQLGuideURI, "search_actors_fql_guide",
		"Contains the guide for the `filter` param of the `falcon_search_actors` tool.",
		"text/markdown", actorsFQLGuide)
	base.TextResource(s, indicatorsFQLGuideURI, "search_indicators_fql_guide",
		"Contains the guide for the `filter` param of the `falcon_search_indicators` tool.",
		"text/markdown", indicatorsFQLGuide)
	base.TextResource(s, reportsFQLGuideURI, "search_reports_fql_guide",
		"Contains the guide for the `filter` param of the `falcon_search_reports` tool.",
		"text/markdown", reportsFQLGuide)
}

// RegisterPrompts is a no-op: the intel module exposes no prompts.
func (m *Module) RegisterPrompts(_ *mcp.Server) {}

// ActorsInput is the input for falcon_search_actors.
type ActorsInput struct {
	Filter string `json:"filter,omitempty" jsonschema:"intel FQL filter (e.g. name:'FANCY BEAR', animal_classifier:'BEAR'). See falcon://intel/actors/fql-guide for syntax."`
	Limit  int    `json:"limit,omitempty" jsonschema:"maximum results to return"`
	Offset int    `json:"offset,omitempty" jsonschema:"pagination offset"`
	Sort   string `json:"sort,omitempty" jsonschema:"intel FQL sort (e.g. created_date|desc)"`
	Q      string `json:"q,omitempty" jsonschema:"free-text search across all indexed fields"`
}

func (m *Module) searchActors(ctx context.Context, _ *mcp.CallToolRequest, in ActorsInput) (*mcp.CallToolResult, base.SearchResult[*models.ActorActorDocument], error) {
	var zero base.SearchResult[*models.ActorActorDocument]
	limit := int64(in.Limit)
	if limit == 0 {
		limit = defaultLimit
	}
	m.Logger.Debug("search_actors", "filter", in.Filter, "limit", limit, "offset", in.Offset, "sort", in.Sort, "q", in.Q)

	params := intel.NewQueryIntelActorEntitiesParamsWithContext(ctx)
	params.Limit = &limit
	if in.Filter != "" {
		params.Filter = &in.Filter
	}
	if in.Offset != 0 {
		params.Offset = new(int64(in.Offset))
	}
	if in.Sort != "" {
		params.Sort = &in.Sort
	}
	if in.Q != "" {
		params.Q = &in.Q
	}

	resp, err := m.API.QueryIntelActorEntities(params)
	if err != nil {
		if details, ok := actorsFQLBadRequest(err); ok {
			return nil, base.FQLError[*models.ActorActorDocument](details, in.Filter, actorsFQLGuide), nil
		}
	}
	if e := base.APIError(err, resp, scopeActors); e != nil {
		return nil, zero, e
	}

	actors := resp.Payload.Resources
	m.Logger.Debug("search_actors query complete", "matched", len(actors))
	return nil, base.Found(actors, in.Filter).WithMeta(resp.Payload.Meta), nil
}

// IndicatorsInput is the input for falcon_search_indicators.
type IndicatorsInput struct {
	Filter           string `json:"filter,omitempty" jsonschema:"intel FQL filter (e.g. type:'domain', malicious_confidence:'high'). See falcon://intel/indicators/fql-guide for syntax."`
	Limit            int    `json:"limit,omitempty" jsonschema:"maximum results to return"`
	Offset           int    `json:"offset,omitempty" jsonschema:"pagination offset"`
	Sort             string `json:"sort,omitempty" jsonschema:"intel FQL sort (e.g. published_date|desc)"`
	Q                string `json:"q,omitempty" jsonschema:"free-text search across all indexed fields"`
	IncludeDeleted   bool   `json:"include_deleted,omitempty" jsonschema:"include deleted indicators as well as published ones"`
	IncludeRelations bool   `json:"include_relations,omitempty" jsonschema:"include related indicators"`
}

func (m *Module) searchIndicators(ctx context.Context, _ *mcp.CallToolRequest, in IndicatorsInput) (*mcp.CallToolResult, base.SearchResult[*models.DomainPublicIndicatorV3], error) {
	var zero base.SearchResult[*models.DomainPublicIndicatorV3]
	limit := int64(in.Limit)
	if limit == 0 {
		limit = defaultLimit
	}
	m.Logger.Debug("search_indicators", "filter", in.Filter, "limit", limit, "offset", in.Offset, "sort", in.Sort, "q", in.Q,
		"include_deleted", in.IncludeDeleted, "include_relations", in.IncludeRelations)

	params := intel.NewQueryIntelIndicatorEntitiesParamsWithContext(ctx)
	params.Limit = &limit
	if in.Filter != "" {
		params.Filter = &in.Filter
	}
	if in.Offset != 0 {
		params.Offset = new(int64(in.Offset))
	}
	if in.Sort != "" {
		params.Sort = &in.Sort
	}
	if in.Q != "" {
		params.Q = &in.Q
	}
	if in.IncludeDeleted {
		params.IncludeDeleted = &in.IncludeDeleted
	}
	if in.IncludeRelations {
		params.IncludeRelations = &in.IncludeRelations
	}

	resp, err := m.API.QueryIntelIndicatorEntities(params)
	if err != nil {
		if details, ok := indicatorsFQLBadRequest(err); ok {
			return nil, base.FQLError[*models.DomainPublicIndicatorV3](details, in.Filter, indicatorsFQLGuide), nil
		}
	}
	if e := base.APIError(err, resp, scopeIndicators); e != nil {
		return nil, zero, e
	}

	indicators := resp.Payload.Resources
	m.Logger.Debug("search_indicators query complete", "matched", len(indicators))
	return nil, base.Found(indicators, in.Filter).WithMeta(resp.Payload.Meta), nil
}

// ReportsInput is the input for falcon_search_reports.
type ReportsInput struct {
	Filter string `json:"filter,omitempty" jsonschema:"intel FQL filter (e.g. type:'notice', target_industries:'Technology'). See falcon://intel/reports/fql-guide for syntax."`
	Limit  int    `json:"limit,omitempty" jsonschema:"maximum results to return"`
	Offset int    `json:"offset,omitempty" jsonschema:"pagination offset"`
	Sort   string `json:"sort,omitempty" jsonschema:"intel FQL sort (e.g. created_date|desc)"`
	Q      string `json:"q,omitempty" jsonschema:"free-text search across all indexed fields"`
}

func (m *Module) searchReports(ctx context.Context, _ *mcp.CallToolRequest, in ReportsInput) (*mcp.CallToolResult, base.SearchResult[*models.DomainNewsDocument], error) {
	var zero base.SearchResult[*models.DomainNewsDocument]
	limit := int64(in.Limit)
	if limit == 0 {
		limit = defaultLimit
	}
	m.Logger.Debug("search_reports", "filter", in.Filter, "limit", limit, "offset", in.Offset, "sort", in.Sort, "q", in.Q)

	params := intel.NewQueryIntelReportEntitiesParamsWithContext(ctx)
	params.Limit = &limit
	if in.Filter != "" {
		params.Filter = &in.Filter
	}
	if in.Offset != 0 {
		params.Offset = new(int64(in.Offset))
	}
	if in.Sort != "" {
		params.Sort = &in.Sort
	}
	if in.Q != "" {
		params.Q = &in.Q
	}

	resp, err := m.API.QueryIntelReportEntities(params)
	if err != nil {
		if reportsFQLBadRequest(err) {
			return nil, base.FQLError[*models.DomainNewsDocument](nil, in.Filter, reportsFQLGuide), nil
		}
	}
	if e := base.APIError(err, resp, scopeReports); e != nil {
		return nil, zero, e
	}

	reports := resp.Payload.Resources
	m.Logger.Debug("search_reports query complete", "matched", len(reports))
	return nil, base.Found(reports, in.Filter).WithMeta(resp.Payload.Meta), nil
}

// actorsFQLBadRequest reports whether err is a 400-class actor query error and,
// if so, extracts the API error details for an FQL-error response. gofalcon
// surfaces 400s as a typed *intel.QueryIntelActorEntitiesBadRequest whose
// MsaErrorsOnly payload carries the errors; classify with errors.As rather than
// string matching.
func actorsFQLBadRequest(err error) ([]base.FQLErrorDetail, bool) {
	var badReq *intel.QueryIntelActorEntitiesBadRequest
	if !errors.As(err, &badReq) || badReq.Payload == nil {
		return nil, false
	}
	return base.FQLErrorDetails(badReq.Payload.Errors), true
}

// indicatorsFQLBadRequest reports whether err is a 400-class indicator query
// error and, if so, extracts the API error details. The payload is a
// *models.MsaErrorsOnly.
func indicatorsFQLBadRequest(err error) ([]base.FQLErrorDetail, bool) {
	var badReq *intel.QueryIntelIndicatorEntitiesBadRequest
	if !errors.As(err, &badReq) || badReq.Payload == nil {
		return nil, false
	}
	return base.FQLErrorDetails(badReq.Payload.Errors), true
}

// reportsFQLBadRequest reports whether err is a 400-class report query error.
// Unlike the actor and indicator endpoints, gofalcon's
// *intel.QueryIntelReportEntitiesBadRequest carries no error payload (the
// swagger spec defines no 400 schema for this operation), so there are no
// per-error details to surface; the FQL-error response still carries the guide
// and correction hint.
func reportsFQLBadRequest(err error) bool {
	var badReq *intel.QueryIntelReportEntitiesBadRequest
	return errors.As(err, &badReq)
}
