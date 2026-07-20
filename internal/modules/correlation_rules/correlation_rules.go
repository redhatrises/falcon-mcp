// Package correlation_rules implements the NG-SIEM correlation-rule tools over
// the gofalcon correlation_rules client: searching rules, creating them,
// updating them, and deleting them. It registers the correlation-rules search
// FQL guide resource.
//
// Unlike falcon-mcp's two-step search modules, search is a single combined call
// (CombinedRulesGetV2) that returns full rule records, so the module does no
// bulk detail fetch and ignores Deps.Concurrency.
package correlation_rules

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"

	"github.com/crowdstrike/gofalcon/falcon/client/correlation_rules"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/crowdstrike/falcon-mcp/internal/modules/base"
	"github.com/crowdstrike/falcon-mcp/internal/modules/registry"
)

// Factory builds the correlation_rules module from shared deps. The generated
// aggregator (internal/mcpserver) collects it, so the module needs no init side
// effect. Search is a single combined call, so this module ignores
// Deps.Concurrency.
var Factory registry.Factory = func(d registry.Deps) base.Module {
	return &Module{API: d.API.CorrelationRules, Logger: d.Logger}
}

// defaultLimit is the search page size applied when the caller omits limit,
// matching falcon-mcp's default of 20.
const defaultLimit = 20

// errInvalidInput classifies client-side validation failures in the mutating
// tools.
var errInvalidInput = errors.New("correlation_rules: invalid input")

// CrowdStrike API scopes required by this module's operations. Surfaced on a
// 403 via base.APIError, referenced directly at each call site.
var (
	scopeCorrelationRead  = base.Scope{Name: "Correlation Rules", Read: true}
	scopeCorrelationWrite = base.Scope{Name: "Correlation Rules", Write: true}
)

// correlationRulesAPI is the minimal slice of the gofalcon correlation_rules
// client this module consumes, declared next to its consumer so handlers can be
// tested against a tiny fake rather than all of gofalcon.
type correlationRulesAPI interface {
	CombinedRulesGetV2(params *correlation_rules.CombinedRulesGetV2Params, opts ...correlation_rules.ClientOption) (*correlation_rules.CombinedRulesGetV2OK, error)
	EntitiesRulesPostV1(params *correlation_rules.EntitiesRulesPostV1Params, opts ...correlation_rules.ClientOption) (*correlation_rules.EntitiesRulesPostV1OK, error)
	EntitiesRulesPatchV1(params *correlation_rules.EntitiesRulesPatchV1Params, opts ...correlation_rules.ClientOption) (*correlation_rules.EntitiesRulesPatchV1OK, error)
	EntitiesRulesDeleteV1(params *correlation_rules.EntitiesRulesDeleteV1Params, opts ...correlation_rules.ClientOption) (*correlation_rules.EntitiesRulesDeleteV1OK, error)
}

// Module registers the correlation-rules tools. It holds only the shared,
// concurrency-safe Falcon client and configuration; handlers are stateless and
// reentrant. Logger must be non-nil.
type Module struct {
	API    correlationRulesAPI
	Logger *slog.Logger
}

// Name reports the module name.
func (m *Module) Name() string { return "correlation_rules" }

// Description reports a one-line summary of the module.
func (m *Module) Description() string {
	return "Search, create, update, and delete NG-SIEM correlation rules"
}

// searchCorrelationRulesSchema is the input schema for
// falcon_search_correlation_rules. It is inferred from SearchInput's struct
// tags, then a mutate func adds the limit bounds/default and offset minimum the
// tag syntax cannot express.
var searchCorrelationRulesSchema = base.SchemaFor[SearchInput](func(s *jsonschema.Schema) {
	s.Properties["limit"].Minimum = jsonschema.Ptr(1.0)
	s.Properties["limit"].Maximum = jsonschema.Ptr(500.0)
	s.Properties["limit"].Default = json.RawMessage(`20`)
	s.Properties["offset"].Minimum = jsonschema.Ptr(0.0)
})

// RegisterTools registers the four correlation-rules tools into r.
func (m *Module) RegisterTools(r base.Registrar) {
	base.AddTool(r, &mcp.Tool{
		Name: "search_correlation_rules",
		Description: "Search NG-SIEM correlation rules by name, status, severity, or MITRE " +
			"tactic/technique. Consult falcon://correlation-rules/search/fql-guide before " +
			"constructing filter expressions. Returns full rule objects; use the `rule_id` " +
			"field when passing results to update or delete tools. Filter with state:'published' " +
			"to get one result per rule.",
		InputSchema: searchCorrelationRulesSchema,
	}, m.searchCorrelationRules)

	base.AddTool(r, &mcp.Tool{
		Name: "create_correlation_rule",
		Description: "Create a new NG-SIEM correlation rule that wraps a user-provided CQL query " +
			"as a scheduled detection rule. Validate the CQL query against NG-SIEM before " +
			"creating the rule. Returns the created rule record.",
		Annotations: base.MutatingAnnotations(),
	}, m.createCorrelationRule)

	base.AddTool(r, &mcp.Tool{
		Name: "update_correlation_rule",
		Description: "Update an existing NG-SIEM correlation rule and auto-publish a new version " +
			"(no separate publish step). To enable/disable a rule, set status to 'active' or " +
			"'inactive'. Only provided fields are changed; omitted fields retain current values.",
		Annotations: idempotentMutatingAnnotations(),
	}, m.updateCorrelationRule)

	base.AddTool(r, &mcp.Tool{
		Name: "delete_correlation_rules",
		Description: "Permanently delete NG-SIEM correlation rules by rule ID, removing the rules " +
			"and all their versions. This action cannot be undone — use " +
			"falcon_search_correlation_rules to confirm IDs before deleting. Returns an empty " +
			"list on success.",
		Annotations: base.DestructiveAnnotations(true),
	}, m.deleteCorrelationRules)
}

// RegisterResources publishes the correlation-rules search FQL guide as an MCP
// resource, mirroring falcon-mcp's falcon://correlation-rules/search/fql-guide
// resource.
func (m *Module) RegisterResources(s *mcp.Server) {
	base.TextResource(s,
		fqlGuideURI,
		"search_correlation_rules_fql_guide",
		"Contains the guide for the `filter` param of the `falcon_search_correlation_rules` tool.",
		"text/markdown",
		fqlGuide,
	)
}

// RegisterPrompts is a no-op: the correlation_rules module exposes no prompts.
func (m *Module) RegisterPrompts(_ *mcp.Server) {}

// idempotentMutatingAnnotations returns annotations for a non-destructive
// mutator that is safe to repeat with the same arguments (readOnlyHint=false,
// destructiveHint=false, idempotentHint=true, openWorldHint=true). base exposes
// helpers for non-idempotent mutators and destructive tools but not this
// combination, which the update tool requires (a repeated update converges on
// the same rule state).
func idempotentMutatingAnnotations() *mcp.ToolAnnotations {
	openWorld := true
	destructive := false
	return &mcp.ToolAnnotations{
		ReadOnlyHint:    false,
		IdempotentHint:  true,
		OpenWorldHint:   &openWorld,
		DestructiveHint: &destructive,
	}
}

// SearchInput is the input for falcon_search_correlation_rules.
type SearchInput struct {
	Filter string `json:"filter,omitempty" jsonschema:"FQL filter expression. See falcon://correlation-rules/search/fql-guide for syntax (e.g. status:'active'+severity:>50)."`
	Limit  int    `json:"limit,omitempty" jsonschema:"maximum number of rules to return (max 500)"`
	Offset int    `json:"offset,omitempty" jsonschema:"starting index for pagination"`
	Sort   string `json:"sort,omitempty" jsonschema:"FQL sort expression (e.g. last_updated_on.desc, created_on.asc)"`
}

func (m *Module) searchCorrelationRules(ctx context.Context, _ *mcp.CallToolRequest, in SearchInput) (*mcp.CallToolResult, base.SearchResult[*models.CorrelationrulesapiRuleV1], error) {
	var zero base.SearchResult[*models.CorrelationrulesapiRuleV1]
	limit := int64(in.Limit)
	if limit == 0 {
		limit = defaultLimit
	}
	m.Logger.Debug("search_correlation_rules", "filter", in.Filter, "limit", limit, "offset", in.Offset, "sort", in.Sort)

	params := correlation_rules.NewCombinedRulesGetV2ParamsWithContext(ctx)
	params.Limit = &limit
	if in.Filter != "" {
		params.Filter = &in.Filter
	}
	if in.Offset != 0 {
		offset := int64(in.Offset)
		params.Offset = &offset
	}
	if in.Sort != "" {
		params.Sort = &in.Sort
	}

	resp, err := m.API.CombinedRulesGetV2(params)
	if err != nil {
		if details, ok := fqlBadRequest(err); ok {
			return nil, base.FQLError[*models.CorrelationrulesapiRuleV1](details, in.Filter, fqlGuide), nil
		}
	}
	if e := base.APIError(err, resp, scopeCorrelationRead); e != nil {
		return nil, zero, e
	}

	// CombinedRulesGetV2 returns full rule records in one call, so no detail
	// fetch step is needed.
	rules := resp.Payload.Resources
	m.Logger.Debug("search_correlation_rules query complete", "matched", len(rules))
	return nil, base.Found(rules, in.Filter).WithMeta(resp.Payload.Meta), nil
}

// fqlBadRequest reports whether err is a 400-class correlation-rules query error
// and, if so, extracts the API error details for an FQL-error response. gofalcon
// surfaces 400s as a typed *correlation_rules.CombinedRulesGetV2BadRequest whose
// payload carries []*models.MsaAPIError; classify with errors.As rather than
// string matching.
func fqlBadRequest(err error) ([]base.FQLErrorDetail, bool) {
	var badReq *correlation_rules.CombinedRulesGetV2BadRequest
	if !errors.As(err, &badReq) || badReq.Payload == nil {
		return nil, false
	}
	return base.FQLErrorDetails(badReq.Payload.Errors), true
}

// wrapInvalid builds an errInvalidInput-wrapped error for op with detail,
// classifying client-side validation failures in the mutating tools.
func wrapInvalid(op, detail string) error {
	return fmt.Errorf("%s: %w: %s", op, errInvalidInput, detail)
}
