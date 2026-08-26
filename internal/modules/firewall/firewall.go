// Package firewall implements the five firewall-management tools over the
// gofalcon firewall_management client: searching firewall rules, rule groups,
// and policy-scoped rules, plus creating and deleting rule groups. It registers
// the firewall search FQL guide resource.
//
// The three search tools follow the two-step query-then-get pattern: a query
// call returns matching IDs, then a get-by-IDs call fetches full records. Rule
// and policy-rule searches both hydrate through GetRules; rule-group search
// hydrates through GetRuleGroups.
package firewall

import (
	"context"
	"errors"
	"log/slog"
	"strconv"

	"github.com/crowdstrike/gofalcon/falcon/client/firewall_management"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/crowdstrike/falcon-mcp/internal/modules/base"
	"github.com/crowdstrike/falcon-mcp/internal/modules/registry"
)

// Factory builds the firewall module from shared deps. The generated aggregator
// (internal/mcpserver) collects it, so the module needs no init side effect.
var Factory registry.Factory = func(d registry.Deps) base.Module {
	return &Module{API: d.API.FirewallManagement, Concurrency: d.Concurrency, Logger: d.Logger}
}

// defaultLimit is the search page size applied when the caller omits limit.
const defaultLimit = 10

// detailBatchSize is the maximum number of IDs fetched per get-by-IDs details
// call. The firewall get endpoints take IDs as query parameters, so keep chunks
// modest to stay within URL length limits.
const detailBatchSize = 100

// CrowdStrike API scopes required by this module's operations. Surfaced on a
// 403 via base.APIError, referenced directly at each call site.
var (
	scopeFirewallRead  = base.Scope{Name: "Firewall Management", Read: true}
	scopeFirewallWrite = base.Scope{Name: "Firewall Management", Write: true}
)

// firewallAPI is the minimal slice of the gofalcon firewall_management client
// this module consumes, declared next to its consumer so handlers can be tested
// against a tiny fake rather than all of gofalcon.
type firewallAPI interface {
	QueryRules(params *firewall_management.QueryRulesParams, opts ...firewall_management.ClientOption) (*firewall_management.QueryRulesOK, error)
	GetRules(params *firewall_management.GetRulesParams, opts ...firewall_management.ClientOption) (*firewall_management.GetRulesOK, error)
	QueryRuleGroups(params *firewall_management.QueryRuleGroupsParams, opts ...firewall_management.ClientOption) (*firewall_management.QueryRuleGroupsOK, error)
	GetRuleGroups(params *firewall_management.GetRuleGroupsParams, opts ...firewall_management.ClientOption) (*firewall_management.GetRuleGroupsOK, error)
	QueryPolicyRules(params *firewall_management.QueryPolicyRulesParams, opts ...firewall_management.ClientOption) (*firewall_management.QueryPolicyRulesOK, error)
	CreateRuleGroup(params *firewall_management.CreateRuleGroupParams, opts ...firewall_management.ClientOption) (*firewall_management.CreateRuleGroupCreated, error)
	DeleteRuleGroups(params *firewall_management.DeleteRuleGroupsParams, opts ...firewall_management.ClientOption) (*firewall_management.DeleteRuleGroupsOK, error)
}

// Module registers the firewall tools. It holds only the shared, concurrency-
// safe Falcon client and configuration; handlers are stateless and reentrant.
// Logger must be non-nil.
type Module struct {
	API         firewallAPI
	Concurrency int
	Logger      *slog.Logger
}

// Name reports the module name.
func (m *Module) Name() string { return "firewall" }

// Description reports a one-line summary of the module.
func (m *Module) Description() string {
	return "Search and manage Falcon firewall rules and rule groups"
}

var (
	searchRulesSchema       = base.SearchSchema[SearchRulesInput](base.SearchSchemaOpts{MaxLimit: 5000, DefaultLimit: defaultLimit})
	searchRuleGroupsSchema  = base.SearchSchema[SearchRuleGroupsInput](base.SearchSchemaOpts{MaxLimit: 5000, DefaultLimit: defaultLimit})
	searchPolicyRulesSchema = base.SearchSchema[SearchPolicyRulesInput](base.SearchSchemaOpts{MaxLimit: 5000, DefaultLimit: defaultLimit})
)

// RegisterTools registers the five firewall tools into r.
func (m *Module) RegisterTools(r base.Registrar) {
	base.AddTool(r, &mcp.Tool{
		Name: "search_firewall_rules",
		Description: "Search firewall rules and return full rule details.\n\n" +
			"Use this to find firewall rules by name, platform, or enabled state. Consult\n" +
			"falcon://firewall/rules/fql-guide before constructing filter expressions.\n" +
			"Returns complete rule objects including conditions and actions.\n" +
			"Responses include `pagination.total` (the total number of records matching the filter, " +
			"or null when the API does not report a count) — use it to answer \"how many\" questions. " +
			"For cursor-based paging, use `pagination.next` as the `after` parameter on the next call.",
		InputSchema: searchRulesSchema,
	}, m.searchFirewallRules)

	base.AddTool(r, &mcp.Tool{
		Name: "search_firewall_rule_groups",
		Description: "Search firewall rule groups and return full rule group details.\n\n" +
			"Use this to find rule groups by name, platform, or enabled state. Consult\n" +
			"falcon://firewall/rules/fql-guide before constructing filter expressions.\n" +
			"Returns rule group objects including their contained rules.\n" +
			"Responses include `pagination.total` (the total number of records matching the filter, " +
			"or null when the API does not report a count) — use it to answer \"how many\" questions. " +
			"For cursor-based paging, use `pagination.next` as the `after` parameter on the next call.",
		InputSchema: searchRuleGroupsSchema,
	}, m.searchFirewallRuleGroups)

	base.AddTool(r, &mcp.Tool{
		Name: "search_firewall_policy_rules",
		Description: "Search firewall rules within a specific policy container.\n\n" +
			"Use this when you need rules scoped to a particular policy. Consult\n" +
			"falcon://firewall/rules/fql-guide before constructing filter expressions.\n" +
			"Returns full rule details for the specified policy.\n" +
			"Responses include `pagination.total` (the total number of records matching the filter, " +
			"or null when the API does not report a count) — use it to answer \"how many\" questions.",
		InputSchema: searchPolicyRulesSchema,
	}, m.searchFirewallPolicyRules)

	base.AddTool(r, &mcp.Tool{
		Name: "create_firewall_rule_group",
		Description: "Create a firewall rule group.\n\n" +
			"Provide a name, platform, and either rules or a clone_id. Returns a list\n" +
			"containing the created rule group object.",
		Annotations: base.MutatingAnnotations(false),
	}, m.createFirewallRuleGroup)

	base.AddTool(r, &mcp.Tool{
		Name: "delete_firewall_rule_groups",
		Description: "Delete firewall rule groups by ID.\n\n" +
			"Permanently removes the specified rule groups and all rules within them.\n" +
			"Returns an empty list on success.",
		Annotations: base.DestructiveAnnotations(true),
	}, m.deleteFirewallRuleGroups)
}

// RegisterResources publishes the firewall search FQL guide as an MCP resource,
// mirroring falcon-mcp's falcon://firewall/rules/fql-guide resource.
func (m *Module) RegisterResources(s *mcp.Server) {
	base.TextResource(s,
		fqlGuideURI,
		"search_firewall_rules_fql_guide",
		"Contains the guide for the `filter` param of firewall search tools.",
		"text/markdown",
		fqlGuide,
	)
}

// RegisterPrompts is a no-op: the firewall module exposes no prompts.
func (m *Module) RegisterPrompts(_ *mcp.Server) {}

// SearchRulesInput is the input for falcon_search_firewall_rules.
//
// Pagination is cursor-only: pass pagination.next from the previous response as
// after.
type SearchRulesInput struct {
	Filter string `json:"filter,omitempty" jsonschema:"FQL filter expression. See falcon://firewall/rules/fql-guide for syntax."`
	Limit  int    `json:"limit,omitempty" jsonschema:"maximum number of rule IDs to return (max 5000)"`
	Sort   string `json:"sort,omitempty" jsonschema:"FQL sort (e.g. modified_on.desc, name.asc)"`
	After  string `json:"after,omitempty" jsonschema:"Pagination token from a previous query response."`
}

func (m *Module) searchFirewallRules(ctx context.Context, req *mcp.CallToolRequest, in SearchRulesInput) (*mcp.CallToolResult, base.SearchResult[*models.FwmgrFirewallRuleV1], error) {
	var zero base.SearchResult[*models.FwmgrFirewallRuleV1]
	limit := int64(in.Limit)
	if limit == 0 {
		limit = defaultLimit
	}
	m.Logger.Debug("search_firewall_rules", "filter", in.Filter, "limit", limit, "sort", in.Sort, "after", in.After)

	params := firewall_management.NewQueryRulesParamsWithContext(ctx)
	params.Limit = &limit
	if in.Filter != "" {
		params.Filter = &in.Filter
	}
	if in.Sort != "" {
		params.Sort = &in.Sort
	}
	if in.After != "" {
		params.After = &in.After
	}

	resp, err := m.API.QueryRules(params)
	if err != nil {
		if details, ok := rulesFQLBadRequest(err); ok {
			return nil, base.FQLError[*models.FwmgrFirewallRuleV1](details, in.Filter, fqlGuide), nil
		}
	}
	if e := base.APIError(err, resp, scopeFirewallRead); e != nil {
		return nil, zero, e
	}

	ids := resp.Payload.Resources
	m.Logger.Debug("search_firewall_rules query complete", "matched_ids", len(ids))
	if len(ids) == 0 {
		return nil, base.Found([]*models.FwmgrFirewallRuleV1{}, in.Filter).WithMeta(resp.Payload.Meta), nil
	}
	rules, err := m.fetchRuleDetails(ctx, req, ids)
	if err != nil {
		return nil, zero, err
	}
	return nil, base.Found(rules, in.Filter).WithMeta(resp.Payload.Meta), nil
}

// SearchRuleGroupsInput is the input for falcon_search_firewall_rule_groups.
//
// Pagination is cursor-only: pass pagination.next from the previous response as
// after.
type SearchRuleGroupsInput struct {
	Filter string `json:"filter,omitempty" jsonschema:"FQL filter expression. See falcon://firewall/rules/fql-guide for syntax."`
	Limit  int    `json:"limit,omitempty" jsonschema:"maximum number of rule group IDs to return (max 5000)"`
	Sort   string `json:"sort,omitempty" jsonschema:"FQL sort (e.g. modified_on.desc, name.asc)"`
	After  string `json:"after,omitempty" jsonschema:"Pagination token from a previous query response."`
}

func (m *Module) searchFirewallRuleGroups(ctx context.Context, req *mcp.CallToolRequest, in SearchRuleGroupsInput) (*mcp.CallToolResult, base.SearchResult[*models.FwmgrAPIRuleGroupV1], error) {
	var zero base.SearchResult[*models.FwmgrAPIRuleGroupV1]
	limit := int64(in.Limit)
	if limit == 0 {
		limit = defaultLimit
	}
	m.Logger.Debug("search_firewall_rule_groups", "filter", in.Filter, "limit", limit, "sort", in.Sort, "after", in.After)

	params := firewall_management.NewQueryRuleGroupsParamsWithContext(ctx)
	params.Limit = &limit
	if in.Filter != "" {
		params.Filter = &in.Filter
	}
	if in.Sort != "" {
		params.Sort = &in.Sort
	}
	if in.After != "" {
		params.After = &in.After
	}

	resp, err := m.API.QueryRuleGroups(params)
	if err != nil {
		if details, ok := ruleGroupsFQLBadRequest(err); ok {
			return nil, base.FQLError[*models.FwmgrAPIRuleGroupV1](details, in.Filter, fqlGuide), nil
		}
	}
	if e := base.APIError(err, resp, scopeFirewallRead); e != nil {
		return nil, zero, e
	}

	ids := resp.Payload.Resources
	m.Logger.Debug("search_firewall_rule_groups query complete", "matched_ids", len(ids))
	if len(ids) == 0 {
		return nil, base.Found([]*models.FwmgrAPIRuleGroupV1{}, in.Filter).WithMeta(resp.Payload.Meta), nil
	}
	groups, err := m.fetchRuleGroupDetails(ctx, req, ids)
	if err != nil {
		return nil, zero, err
	}
	return nil, base.Found(groups, in.Filter).WithMeta(resp.Payload.Meta), nil
}

// SearchPolicyRulesInput is the input for falcon_search_firewall_policy_rules.
type SearchPolicyRulesInput struct {
	PolicyID string `json:"policy_id" jsonschema:"policy container ID to query rules within (required)"`
	Filter   string `json:"filter,omitempty" jsonschema:"FQL filter expression. See falcon://firewall/rules/fql-guide for syntax."`
	Limit    int    `json:"limit,omitempty" jsonschema:"maximum number of policy rule IDs to return (max 5000)"`
	Offset   int    `json:"offset,omitempty" jsonschema:"starting index of the overall result set from which to return IDs"`
	Sort     string `json:"sort,omitempty" jsonschema:"FQL sort (e.g. modified_on.desc, name.asc)"`
}

func (m *Module) searchFirewallPolicyRules(ctx context.Context, req *mcp.CallToolRequest, in SearchPolicyRulesInput) (*mcp.CallToolResult, base.SearchResult[*models.FwmgrFirewallRuleV1], error) {
	var zero base.SearchResult[*models.FwmgrFirewallRuleV1]
	if in.PolicyID == "" {
		return nil, zero, base.InvalidInput("search firewall policy rules", "policy_id must not be empty")
	}
	limit := int64(in.Limit)
	if limit == 0 {
		limit = defaultLimit
	}
	m.Logger.Debug("search_firewall_policy_rules", "policy_id", in.PolicyID, "filter", in.Filter, "limit", limit, "offset", in.Offset, "sort", in.Sort)

	params := firewall_management.NewQueryPolicyRulesParamsWithContext(ctx)
	params.ID = &in.PolicyID
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

	resp, err := m.API.QueryPolicyRules(params)
	if err != nil {
		if details, ok := policyRulesFQLBadRequest(err); ok {
			return nil, base.FQLError[*models.FwmgrFirewallRuleV1](details, in.Filter, fqlGuide), nil
		}
	}
	if e := base.APIError(err, resp, scopeFirewallRead); e != nil {
		return nil, zero, e
	}

	ids := resp.Payload.Resources
	m.Logger.Debug("search_firewall_policy_rules query complete", "matched_ids", len(ids))
	if len(ids) == 0 {
		return nil, base.Found([]*models.FwmgrFirewallRuleV1{}, in.Filter).WithMeta(resp.Payload.Meta), nil
	}
	rules, err := m.fetchRuleDetails(ctx, req, ids)
	if err != nil {
		return nil, zero, err
	}
	return nil, base.Found(rules, in.Filter).WithMeta(resp.Payload.Meta), nil
}

// fetchRuleDetails fetches full firewall rule records for the given IDs,
// chunking and fetching concurrently when the set exceeds a single details
// call's capacity. GetRules may reorder results, so KeyFn restores the query
// step's sort. It emits per-chunk progress notifications when req carries a
// progress token.
func (m *Module) fetchRuleDetails(ctx context.Context, req *mcp.CallToolRequest, ids []string) ([]*models.FwmgrFirewallRuleV1, error) {
	return base.FetchDetails(ctx, base.FetchDetailsParams[*models.FwmgrFirewallRuleV1]{
		IDs:         ids,
		ChunkSize:   detailBatchSize,
		Concurrency: m.Concurrency,
		Progress:    base.ProgressFunc(ctx, req),
		Fetch: func(ctx context.Context, chunk []string) ([]*models.FwmgrFirewallRuleV1, error) {
			params := firewall_management.NewGetRulesParamsWithContext(ctx)
			params.Ids = chunk
			resp, err := m.API.GetRules(params)
			if e := base.APIError(err, resp, scopeFirewallRead); e != nil {
				return nil, e
			}
			return resp.Payload.Resources, nil
		},
		KeyFn: func(r *models.FwmgrFirewallRuleV1) string { return base.Deref(r.ID) },
	})
}

// fetchRuleGroupDetails is the rule-group counterpart of fetchRuleDetails,
// hydrating IDs through GetRuleGroups.
func (m *Module) fetchRuleGroupDetails(ctx context.Context, req *mcp.CallToolRequest, ids []string) ([]*models.FwmgrAPIRuleGroupV1, error) {
	return base.FetchDetails(ctx, base.FetchDetailsParams[*models.FwmgrAPIRuleGroupV1]{
		IDs:         ids,
		ChunkSize:   detailBatchSize,
		Concurrency: m.Concurrency,
		Progress:    base.ProgressFunc(ctx, req),
		Fetch: func(ctx context.Context, chunk []string) ([]*models.FwmgrAPIRuleGroupV1, error) {
			params := firewall_management.NewGetRuleGroupsParamsWithContext(ctx)
			params.Ids = chunk
			resp, err := m.API.GetRuleGroups(params)
			if e := base.APIError(err, resp, scopeFirewallRead); e != nil {
				return nil, e
			}
			return resp.Payload.Resources, nil
		},
		KeyFn: func(g *models.FwmgrAPIRuleGroupV1) string { return base.Deref(g.ID) },
	})
}

// fwmgrFQLDetails flattens the firewall service's FwmgrMsaspecError values into
// base.FQLErrorDetail. The firewall_management BadRequest payloads carry
// []*models.FwmgrMsaspecError rather than the []*models.MsaAPIError that
// base.FQLErrorDetails accepts, so this module supplies field accessors for that
// type.
func fwmgrFQLDetails(errs []*models.FwmgrMsaspecError) []base.FQLErrorDetail {
	return base.FQLErrorDetailsFrom(errs,
		func(e *models.FwmgrMsaspecError) *int32 { return e.Code },
		func(e *models.FwmgrMsaspecError) *string { return e.Message })
}

// rulesFQLBadRequest reports whether err is a 400-class QueryRules error and, if
// so, extracts the API error details for an FQL-error response. gofalcon
// surfaces 400s as a typed *firewall_management.QueryRulesBadRequest; classify
// with errors.As rather than string matching.
func rulesFQLBadRequest(err error) ([]base.FQLErrorDetail, bool) {
	var badReq *firewall_management.QueryRulesBadRequest
	if !errors.As(err, &badReq) || badReq.Payload == nil {
		return nil, false
	}
	return fwmgrFQLDetails(badReq.Payload.Errors), true
}

// ruleGroupsFQLBadRequest is the QueryRuleGroups counterpart of
// rulesFQLBadRequest.
func ruleGroupsFQLBadRequest(err error) ([]base.FQLErrorDetail, bool) {
	var badReq *firewall_management.QueryRuleGroupsBadRequest
	if !errors.As(err, &badReq) || badReq.Payload == nil {
		return nil, false
	}
	return fwmgrFQLDetails(badReq.Payload.Errors), true
}

// policyRulesFQLBadRequest is the QueryPolicyRules counterpart of
// rulesFQLBadRequest.
func policyRulesFQLBadRequest(err error) ([]base.FQLErrorDetail, bool) {
	var badReq *firewall_management.QueryPolicyRulesBadRequest
	if !errors.As(err, &badReq) || badReq.Payload == nil {
		return nil, false
	}
	return fwmgrFQLDetails(badReq.Payload.Errors), true
}
