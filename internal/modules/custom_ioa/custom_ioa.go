// Package custom_ioa implements the nine Custom IOA tools over the gofalcon
// custom_ioa client: searching rule groups and their rules, discovering
// platforms and rule types, and creating, updating, and deleting rule groups
// and behavioral detection rules. It registers the rule-groups FQL guide
// resource.
//
// Two live-API quirks shape this module:
//
//   - get_ioa_platforms is a single call, not a query-then-get. The
//     GetPlatformsMixin0 detail endpoint is unusable via gofalcon because the
//     API returns platform id as a string ("windows") while models.DomainPlatform
//     types it as *int64, so every detail unmarshal fails. QueryPlatformsMixin0
//     already returns the canonical platform values (windows, mac, linux)
//     directly, so the module returns those.
//   - get_ioa_rule_types is a two-step query-then-get: the query returns string
//     IDs and GetRuleTypes returns the full rule-type records.
package custom_ioa

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strconv"

	"github.com/crowdstrike/gofalcon/falcon/client/custom_ioa"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/go-openapi/runtime"
	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/crowdstrike/falcon-mcp/internal/modules/base"
	"github.com/crowdstrike/falcon-mcp/internal/modules/registry"
)

// Factory builds the custom_ioa module from shared deps. The generated
// aggregator (internal/mcpserver) collects it, so the module needs no init side
// effect. This module does no bulk detail fetch, so it ignores Deps.Concurrency.
var Factory registry.Factory = func(d registry.Deps) base.Module {
	return &Module{API: d.API.CustomIoa, Logger: d.Logger}
}

// defaultRuleGroupLimit is the rule-group search page size applied when the
// caller omits limit.
const defaultRuleGroupLimit = 10

// defaultRuleTypeLimit is the rule-type page size applied when the caller omits
// limit.
const defaultRuleTypeLimit = 100

// errInvalidInput classifies client-side validation failures in the mutating
// tools.
var errInvalidInput = errors.New("custom_ioa: invalid input")

// CrowdStrike API scopes required by this module's operations. Surfaced on a
// 403 via base.APIError, referenced directly at each call site.
var (
	scopeCustomIOARead  = base.Scope{Name: "Custom IOA Rules", Read: true}
	scopeCustomIOAWrite = base.Scope{Name: "Custom IOA Rules", Write: true}
)

// customIOAAPI is the minimal slice of the gofalcon custom_ioa client this
// module consumes, declared next to its consumer so handlers can be tested
// against a tiny fake rather than all of gofalcon.
type customIOAAPI interface {
	QueryRuleGroupsFull(params *custom_ioa.QueryRuleGroupsFullParams, opts ...custom_ioa.ClientOption) (*custom_ioa.QueryRuleGroupsFullOK, error)
	QueryPlatformsMixin0(params *custom_ioa.QueryPlatformsMixin0Params, opts ...custom_ioa.ClientOption) (*custom_ioa.QueryPlatformsMixin0OK, error)
	QueryRuleTypes(params *custom_ioa.QueryRuleTypesParams, opts ...custom_ioa.ClientOption) (*custom_ioa.QueryRuleTypesOK, error)
	GetRuleTypes(params *custom_ioa.GetRuleTypesParams, opts ...custom_ioa.ClientOption) (*custom_ioa.GetRuleTypesOK, error)
	CreateRuleGroupMixin0(params *custom_ioa.CreateRuleGroupMixin0Params, opts ...custom_ioa.ClientOption) (*custom_ioa.CreateRuleGroupMixin0Created, error)
	UpdateRuleGroupMixin0(params *custom_ioa.UpdateRuleGroupMixin0Params, opts ...custom_ioa.ClientOption) (*custom_ioa.UpdateRuleGroupMixin0OK, error)
	DeleteRuleGroupsMixin0(params *custom_ioa.DeleteRuleGroupsMixin0Params, opts ...custom_ioa.ClientOption) (*custom_ioa.DeleteRuleGroupsMixin0OK, error)
	CreateRule(params *custom_ioa.CreateRuleParams, opts ...custom_ioa.ClientOption) (*custom_ioa.CreateRuleCreated, error)
	UpdateRulesV2(params *custom_ioa.UpdateRulesV2Params, opts ...custom_ioa.ClientOption) (*custom_ioa.UpdateRulesV2OK, error)
	DeleteRules(params *custom_ioa.DeleteRulesParams, opts ...custom_ioa.ClientOption) (*custom_ioa.DeleteRulesOK, error)
}

// Module registers the Custom IOA tools. It holds only the shared,
// concurrency-safe Falcon client and configuration; handlers are stateless and
// reentrant. Logger must be non-nil.
type Module struct {
	API    customIOAAPI
	Logger *slog.Logger
}

// Name reports the module name.
func (m *Module) Name() string { return "custom_ioa" }

// Description reports a one-line summary of the module.
func (m *Module) Description() string {
	return "Search, create, update, and delete Custom IOA behavioral detection rules and rule groups"
}

// searchRuleGroupsSchema is the input schema for falcon_search_ioa_rule_groups.
// It is inferred from SearchInput's struct tags, then a mutate func adds the
// limit bounds/default the tag syntax cannot express.
var searchRuleGroupsSchema = base.SchemaFor[SearchInput](func(s *jsonschema.Schema) {
	s.Properties["limit"].Minimum = jsonschema.Ptr(1.0)
	s.Properties["limit"].Maximum = jsonschema.Ptr(500.0)
	s.Properties["limit"].Default = json.RawMessage(`10`)
	s.Properties["offset"].Minimum = jsonschema.Ptr(0.0)
})

// ruleTypesSchema is the input schema for falcon_get_ioa_rule_types.
var ruleTypesSchema = base.SchemaFor[RuleTypesInput](func(s *jsonschema.Schema) {
	s.Properties["limit"].Minimum = jsonschema.Ptr(1.0)
	s.Properties["limit"].Maximum = jsonschema.Ptr(500.0)
	s.Properties["limit"].Default = json.RawMessage(`100`)
	s.Properties["offset"].Minimum = jsonschema.Ptr(0.0)
})

// RegisterTools registers the nine Custom IOA tools into r.
func (m *Module) RegisterTools(r base.Registrar) {
	base.AddTool(r, &mcp.Tool{
		Name: "search_ioa_rule_groups",
		Description: "Search Custom IOA rule groups by platform, name, or enabled state, and " +
			"return their contained behavioral detection rules. Consult " +
			"falcon://custom-ioa/rule-groups/fql-guide before constructing filter expressions. " +
			"Returns full rule group records including their rules." +
			" Responses include `pagination.total` (the total number of records matching the filter, " +
			"or null when the API does not report a count) — use it to answer \"how many\" questions.",
		InputSchema: searchRuleGroupsSchema,
	}, m.searchRuleGroups)

	base.AddTool(r, &mcp.Tool{
		Name: "get_ioa_platforms",
		Description: "Get the platforms available for Custom IOA rule groups. Use this to " +
			"discover valid platform values (windows, mac, linux) before creating a rule " +
			"group. Returns the platform identifiers.",
	}, m.getPlatforms)

	base.AddTool(r, &mcp.Tool{
		Name: "get_ioa_rule_types",
		Description: "Get the Custom IOA rule types available in your environment. Use this to " +
			"discover valid rule type IDs, required fields, and disposition IDs before " +
			"creating a behavioral detection rule. Returns rule type details including " +
			"platform, fields, and dispositions.",
		InputSchema: ruleTypesSchema,
	}, m.getRuleTypes)

	base.AddTool(r, &mcp.Tool{
		Name: "create_ioa_rule_group",
		Description: "Create a Custom IOA rule group, a platform-scoped container for " +
			"behavioral detection rules. Use falcon_get_ioa_platforms for valid platform " +
			"values, then falcon_create_ioa_rule to add rules. Returns the created group.",
		Annotations: base.MutatingAnnotations(),
	}, m.createRuleGroup)

	base.AddTool(r, &mcp.Tool{
		Name: "update_ioa_rule_group",
		Description: "Update a Custom IOA rule group's name, description, or enabled state. " +
			"Requires the current rulegroup_version for optimistic locking — get it from " +
			"falcon_search_ioa_rule_groups. Returns the updated group.",
		Annotations: idempotentMutatingAnnotations(),
	}, m.updateRuleGroup)

	base.AddTool(r, &mcp.Tool{
		Name: "delete_ioa_rule_groups",
		Description: "Permanently delete Custom IOA rule groups by ID, removing all rules " +
			"within them. Use falcon_search_ioa_rule_groups to find rule group IDs. Idempotent.",
		Annotations: base.DestructiveAnnotations(true),
	}, m.deleteRuleGroups)

	base.AddTool(r, &mcp.Tool{
		Name: "create_ioa_rule",
		Description: "Create a Custom IOA behavioral detection rule within a rule group. Use " +
			"falcon_get_ioa_rule_types first to discover rule type IDs, required fields, and " +
			"valid disposition IDs. The field_values define the behavioral matching criteria. " +
			"Returns the created rule.",
		Annotations: base.MutatingAnnotations(),
	}, m.createRule)

	base.AddTool(r, &mcp.Tool{
		Name: "update_ioa_rule",
		Description: "Update a Custom IOA behavioral detection rule. Requires the rule group's " +
			"current rulegroup_version and the rule instance_id — get both from " +
			"falcon_search_ioa_rule_groups. Returns the updated rule.",
		Annotations: idempotentMutatingAnnotations(),
	}, m.updateRule)

	base.AddTool(r, &mcp.Tool{
		Name: "delete_ioa_rules",
		Description: "Delete Custom IOA behavioral detection rules from a rule group by rule " +
			"instance ID. Use falcon_search_ioa_rule_groups to find the rule group ID and rule " +
			"instance IDs. Idempotent.",
		Annotations: base.DestructiveAnnotations(true),
	}, m.deleteRules)
}

// idempotentMutatingAnnotations returns annotations for non-destructive update
// tools: readOnlyHint=false, destructiveHint=false, idempotentHint=true. base
// offers MutatingAnnotations (idempotent=false) and DestructiveAnnotations
// (destructive=true) but not this combination, which the Python module applies
// to its update tools. All four hints are set explicitly because MCP defaults
// DestructiveHint to true when omitted.
func idempotentMutatingAnnotations() *mcp.ToolAnnotations {
	return &mcp.ToolAnnotations{
		ReadOnlyHint:    false,
		IdempotentHint:  true,
		OpenWorldHint:   new(true),
		DestructiveHint: new(false),
	}
}

// RegisterResources publishes the rule-groups FQL guide as an MCP resource,
// mirroring falcon-mcp's falcon://custom-ioa/rule-groups/fql-guide resource.
func (m *Module) RegisterResources(s *mcp.Server) {
	base.TextResource(s,
		fqlGuideURI,
		"search_ioa_rule_groups_fql_guide",
		"Contains the guide for the `filter` param of the `falcon_search_ioa_rule_groups` tool.",
		"text/markdown",
		fqlGuide,
	)
}

// RegisterPrompts is a no-op: the Custom IOA module exposes no prompts.
func (m *Module) RegisterPrompts(_ *mcp.Server) {}

// SearchInput is the input for falcon_search_ioa_rule_groups.
type SearchInput struct {
	Filter string `json:"filter,omitempty" jsonschema:"rule-group FQL filter (e.g. platform:'windows'+enabled:true). See falcon://custom-ioa/rule-groups/fql-guide for syntax."`
	Limit  int    `json:"limit,omitempty" jsonschema:"maximum results to return"`
	Offset int    `json:"offset,omitempty" jsonschema:"starting index of the overall result set from which to return IDs"`
	Sort   string `json:"sort,omitempty" jsonschema:"rule-group FQL sort (e.g. modified_on.desc, name.asc)"`
	Q      string `json:"q,omitempty" jsonschema:"free-text match query across all filter string fields"`
}

func (m *Module) searchRuleGroups(ctx context.Context, _ *mcp.CallToolRequest, in SearchInput) (*mcp.CallToolResult, base.SearchResult[*models.APIRuleGroupV1], error) {
	var zero base.SearchResult[*models.APIRuleGroupV1]
	limit := int64(in.Limit)
	if limit == 0 {
		limit = defaultRuleGroupLimit
	}
	m.Logger.Debug("search_ioa_rule_groups", "filter", in.Filter, "limit", limit, "offset", in.Offset, "sort", in.Sort, "q", in.Q)

	params := custom_ioa.NewQueryRuleGroupsFullParamsWithContext(ctx)
	params.Limit = &limit
	if in.Filter != "" {
		params.Filter = &in.Filter
	}
	// This endpoint types its offset query param as a string while reporting a
	// numeric offset back in meta.pagination, so the numeric input is formatted
	// here rather than exposing the string form to callers.
	if in.Offset != 0 {
		params.Offset = new(strconv.Itoa(in.Offset))
	}
	if in.Sort != "" {
		params.Sort = &in.Sort
	}
	if in.Q != "" {
		params.Q = &in.Q
	}

	resp, err := m.API.QueryRuleGroupsFull(params)
	if err != nil {
		if details, ok := ruleGroupsFQLBadRequest(err); ok {
			return nil, base.FQLError[*models.APIRuleGroupV1](details, in.Filter, fqlGuide), nil
		}
	}
	if e := base.APIError(err, resp, scopeCustomIOARead); e != nil {
		return nil, zero, e
	}

	groups := resp.Payload.Resources
	m.Logger.Debug("search_ioa_rule_groups query complete", "matched", len(groups))
	return nil, base.Found(groups, in.Filter).WithMeta(resp.Payload.Meta), nil
}

// Platform is one available Custom IOA platform. The Custom IOA platform detail
// endpoint (GetPlatformsMixin0) is unusable via gofalcon — it types the platform
// id as *int64 while the API returns a string, so every detail unmarshal fails.
// QueryPlatformsMixin0 returns the canonical platform values directly, so this
// module wraps each into a Platform object. A struct (rather than a bare string)
// is required because the result envelope's output schema types every resource
// element as an object.
type Platform struct {
	ID string `json:"id"`
}

// getPlatforms returns the available Custom IOA platform identifiers. It is a
// single call, not a two-step query-then-get: the GetPlatformsMixin0 detail
// endpoint is unusable via gofalcon (it types platform id as *int64 while the
// API returns a string), and QueryPlatformsMixin0 already returns the canonical
// platform values.
func (m *Module) getPlatforms(ctx context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, base.EntitiesResult[Platform], error) {
	var zero base.EntitiesResult[Platform]
	m.Logger.Debug("get_ioa_platforms")

	params := custom_ioa.NewQueryPlatformsMixin0ParamsWithContext(ctx)
	resp, err := m.API.QueryPlatformsMixin0(params)
	if e := base.APIError(err, resp, scopeCustomIOARead); e != nil {
		return nil, zero, e
	}

	platforms := make([]Platform, 0, len(resp.Payload.Resources))
	for _, id := range resp.Payload.Resources {
		platforms = append(platforms, Platform{ID: id})
	}
	m.Logger.Debug("get_ioa_platforms complete", "count", len(platforms))
	return nil, base.Entities(platforms).WithMeta(resp.Payload.Meta), nil
}

// RuleTypesInput is the input for falcon_get_ioa_rule_types.
type RuleTypesInput struct {
	Limit  int `json:"limit,omitempty" jsonschema:"maximum results to return"`
	Offset int `json:"offset,omitempty" jsonschema:"starting index of the overall result set from which to return IDs"`
}

func (m *Module) getRuleTypes(ctx context.Context, _ *mcp.CallToolRequest, in RuleTypesInput) (*mcp.CallToolResult, base.EntitiesResult[*models.APIRuleTypeV1], error) {
	var zero base.EntitiesResult[*models.APIRuleTypeV1]
	limit := int64(in.Limit)
	if limit == 0 {
		limit = defaultRuleTypeLimit
	}
	m.Logger.Debug("get_ioa_rule_types", "limit", limit, "offset", in.Offset)

	qp := custom_ioa.NewQueryRuleTypesParamsWithContext(ctx)
	qp.Limit = &limit
	// Same string-typed offset param as the rule-groups query; see searchRuleGroups.
	if in.Offset != 0 {
		qp.Offset = new(strconv.Itoa(in.Offset))
	}

	qresp, err := m.API.QueryRuleTypes(qp)
	if e := base.APIError(err, qresp, scopeCustomIOARead); e != nil {
		return nil, zero, e
	}

	ids := qresp.Payload.Resources
	if len(ids) == 0 {
		return nil, base.Entities([]*models.APIRuleTypeV1{}).WithMeta(qresp.Payload.Meta), nil
	}

	gp := custom_ioa.NewGetRuleTypesParamsWithContext(ctx)
	gp.Ids = ids
	gresp, err := m.API.GetRuleTypes(gp)
	if e := base.APIError(err, gresp, scopeCustomIOARead); e != nil {
		return nil, zero, e
	}

	// Preserve the query-step order in case the details endpoint reorders results.
	types := reorderRuleTypes(ids, gresp.Payload.Resources)
	m.Logger.Debug("get_ioa_rule_types complete", "count", len(types))
	return nil, base.Entities(types).WithMeta(qresp.Payload.Meta), nil
}

// reorderRuleTypes reorders rule types to match the query-step ID order. Rule
// types carry a string ID; entities not referenced by ids are appended.
func reorderRuleTypes(ids []string, types []*models.APIRuleTypeV1) []*models.APIRuleTypeV1 {
	byID := make(map[string]*models.APIRuleTypeV1, len(types))
	for _, t := range types {
		if t != nil && t.ID != nil {
			byID[*t.ID] = t
		}
	}
	out := make([]*models.APIRuleTypeV1, 0, len(types))
	placed := make(map[string]struct{}, len(types))
	for _, id := range ids {
		if t, ok := byID[id]; ok {
			if _, done := placed[id]; !done {
				out = append(out, t)
				placed[id] = struct{}{}
			}
		}
	}
	for _, t := range types {
		if t == nil || t.ID == nil {
			out = append(out, t)
			continue
		}
		if _, done := placed[*t.ID]; !done {
			out = append(out, t)
		}
	}
	return out
}

// ruleGroupsFQLBadRequest reports whether err is a 400-class rule-group query
// error and, if so, returns synthetic FQL error details for an FQL-error
// response. Unlike most gofalcon query operations, QueryRuleGroupsFull has no
// typed *BadRequest response — a malformed FQL filter surfaces as a generic
// *runtime.APIError with an empty body and HTTP 400. So rather than errors.As
// on a typed payload, this classifies by HTTP status via the go-openapi
// runtime.ClientResponseStatus interface (the same mechanism base.APIError uses
// internally) and synthesizes a detail, since the empty 400 body carries no
// message of its own. A 500 (which this endpoint returns for an unknown filter
// field) is intentionally left to base.APIError as a server error.
func ruleGroupsFQLBadRequest(err error) ([]base.FQLErrorDetail, bool) {
	var st runtime.ClientResponseStatus
	if !errors.As(err, &st) || !st.IsCode(400) {
		return nil, false
	}
	return []base.FQLErrorDetail{{
		Code:    400,
		Message: "The request was rejected with HTTP 400, which for this endpoint indicates an invalid FQL filter expression.",
	}}, true
}
