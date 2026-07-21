package cloud

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/crowdstrike/gofalcon/falcon/client/cloud_policies"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/crowdstrike/falcon-mcp/internal/modules/base"
)

// errInvalidInput classifies client-side validation failures in the mutating
// suppression-rule tools.
var errInvalidInput = errors.New("cloud: invalid input")

// validSuppressionReasons is the set of accepted suppression_reason values.
var validSuppressionReasons = map[string]struct{}{
	"accept-risk": {}, "compensating-control": {}, "false-positive": {},
}

// policiesAPI is the slice of the gofalcon cloud_policies client this module
// consumes (CSPM IOM suppression rules).
type policiesAPI interface {
	QuerySuppressionRules(*cloud_policies.QuerySuppressionRulesParams, ...cloud_policies.ClientOption) (*cloud_policies.QuerySuppressionRulesOK, error)
	GetSuppressionRules(*cloud_policies.GetSuppressionRulesParams, ...cloud_policies.ClientOption) (*cloud_policies.GetSuppressionRulesOK, error)
	CreateSuppressionRule(*cloud_policies.CreateSuppressionRuleParams, ...cloud_policies.ClientOption) (*cloud_policies.CreateSuppressionRuleOK, error)
	DeleteSuppressionRules(*cloud_policies.DeleteSuppressionRulesParams, ...cloud_policies.ClientOption) (*cloud_policies.DeleteSuppressionRulesOK, error)
}

// --- Search suppression rules ---

// SearchSuppressionRulesInput is the input for falcon_search_cspm_suppression_rules.
type SearchSuppressionRulesInput struct {
	Limit  int `json:"limit,omitempty" jsonschema:"maximum number of suppression rules to return"`
	Offset int `json:"offset,omitempty" jsonschema:"starting index for pagination"`
}

var searchCSPMSuppressionRulesSchema = base.SchemaFor[SearchSuppressionRulesInput](limitBounds(500, 100))

// searchCSPMSuppressionRules queries suppression rule IDs, then fetches full
// rule details.
func (m *Module) searchCSPMSuppressionRules(ctx context.Context, _ *mcp.CallToolRequest, in SearchSuppressionRulesInput) (*mcp.CallToolResult, base.EntitiesResult[*models.ApimodelsSuppressionRule], error) {
	var zero base.EntitiesResult[*models.ApimodelsSuppressionRule]
	m.Logger.Debug("search_cspm_suppression_rules", "limit", in.Limit, "offset", in.Offset)

	qparams := cloud_policies.NewQuerySuppressionRulesParamsWithContext(ctx)
	limit := int64(in.Limit)
	if limit == 0 {
		limit = 100
	}
	qparams.Limit = &limit
	if in.Offset != 0 {
		offset := int64(in.Offset)
		qparams.Offset = &offset
	}

	qresp, err := m.Policies.QuerySuppressionRules(qparams)
	if e := base.APIError(err, qresp, scopePoliciesRead); e != nil {
		return nil, zero, e
	}
	ids := qresp.Payload.Resources
	if len(ids) == 0 {
		return nil, base.Entities([]*models.ApimodelsSuppressionRule{}).WithMeta(qresp.Payload.Meta), nil
	}

	rules, err := m.getSuppressionRules(ctx, ids)
	if err != nil {
		return nil, zero, err
	}
	return nil, base.Entities(rules).WithMeta(qresp.Payload.Meta), nil
}

// getSuppressionRules fetches full suppression rule details for the given IDs,
// preserving the requested order in case the details endpoint reorders results.
func (m *Module) getSuppressionRules(ctx context.Context, ids []string) ([]*models.ApimodelsSuppressionRule, error) {
	params := cloud_policies.NewGetSuppressionRulesParamsWithContext(ctx)
	params.Ids = ids
	resp, err := m.Policies.GetSuppressionRules(params)
	if e := base.APIError(err, resp, scopePoliciesRead); e != nil {
		return nil, e
	}
	return reorderRulesByID(ids, resp.Payload.Resources), nil
}

// reorderRulesByID reorders rules to match ids, restoring the query step's order.
func reorderRulesByID(ids []string, rules []*models.ApimodelsSuppressionRule) []*models.ApimodelsSuppressionRule {
	byID := make(map[string]*models.ApimodelsSuppressionRule, len(rules))
	for _, r := range rules {
		if r != nil && r.ID != nil {
			byID[*r.ID] = r
		}
	}
	out := make([]*models.ApimodelsSuppressionRule, 0, len(rules))
	placed := make(map[string]struct{}, len(rules))
	for _, id := range ids {
		if r, ok := byID[id]; ok {
			if _, done := placed[id]; !done {
				out = append(out, r)
				placed[id] = struct{}{}
			}
		}
	}
	for _, r := range rules {
		if r == nil || r.ID == nil {
			out = append(out, r)
			continue
		}
		if _, done := placed[*r.ID]; !done {
			out = append(out, r)
		}
	}
	return out
}

// --- Create suppression rule ---

// CreateSuppressionRuleInput is the input for falcon_create_cspm_suppression_rule.
type CreateSuppressionRuleInput struct {
	Name              string   `json:"name" jsonschema:"Name for the suppression rule. Should be descriptive."`
	SuppressionReason string   `json:"suppression_reason" jsonschema:"Reason for suppression. Values: accept-risk, compensating-control, false-positive."`
	RuleIDs           []string `json:"rule_ids,omitempty" jsonschema:"Specific rule IDs to suppress. If not provided, use rule_severities or rule_names to scope."`
	RuleNames         []string `json:"rule_names,omitempty" jsonschema:"Rule names to suppress (supports wildcards)."`
	RuleSeverities    []string `json:"rule_severities,omitempty" jsonschema:"Rule severities to suppress. Values: critical, high, medium, low, informational."`
	CloudProviders    []string `json:"cloud_providers,omitempty" jsonschema:"Limit suppression to specific cloud providers. Values: aws, azure, gcp."`
	AccountIDs        []string `json:"account_ids,omitempty" jsonschema:"Limit suppression to specific cloud account IDs."`
	Regions           []string `json:"regions,omitempty" jsonschema:"Limit suppression to specific cloud regions. Ex: ['us-east-1', 'eu-west-1']."`
	ResourceIDs       []string `json:"resource_ids,omitempty" jsonschema:"Limit suppression to specific resource IDs."`
	ResourceTypes     []string `json:"resource_types,omitempty" jsonschema:"Limit suppression to specific resource types. Ex: ['AWS::S3::Bucket']."`
	ExpirationDate    string   `json:"expiration_date,omitempty" jsonschema:"Optional expiration date in RFC 3339 format (e.g. 2025-12-31T23:59:59Z). WARNING: Omitting this creates a PERMANENT suppression."`
}

// createCSPMSuppressionRule creates a CSPM IOM suppression rule, then fetches the
// created rule's full details. It requires a valid suppression reason and at
// least one rule selection (ids, names, or severities), matching the Python
// module's validation.
func (m *Module) createCSPMSuppressionRule(ctx context.Context, _ *mcp.CallToolRequest, in CreateSuppressionRuleInput) (*mcp.CallToolResult, base.EntitiesResult[*models.ApimodelsSuppressionRule], error) {
	var zero base.EntitiesResult[*models.ApimodelsSuppressionRule]

	if _, ok := validSuppressionReasons[in.SuppressionReason]; !ok {
		return nil, zero, wrapInvalid("create suppression rule",
			fmt.Sprintf("invalid suppression_reason %q (must be one of: %s)", in.SuppressionReason, validReasonsList()))
	}

	ruleFilter := &models.SuppressionrulesRuleSelectionFilter{}
	hasRuleSelection := false
	if len(in.RuleIDs) > 0 {
		ruleFilter.RuleIds = in.RuleIDs
		hasRuleSelection = true
	}
	if len(in.RuleNames) > 0 {
		ruleFilter.RuleNames = in.RuleNames
		hasRuleSelection = true
	}
	if len(in.RuleSeverities) > 0 {
		ruleFilter.RuleSeverities = in.RuleSeverities
		hasRuleSelection = true
	}
	if !hasRuleSelection {
		return nil, zero, wrapInvalid("create suppression rule",
			"at least one rule selection parameter is required (rule_ids, rule_names, or rule_severities)")
	}

	assetFilter := &models.SuppressionrulesScopeAssetFilter{}
	hasAssetFilter := false
	if len(in.CloudProviders) > 0 {
		assetFilter.CloudProviders = in.CloudProviders
		hasAssetFilter = true
	}
	if len(in.AccountIDs) > 0 {
		assetFilter.AccountIds = in.AccountIDs
		hasAssetFilter = true
	}
	if len(in.Regions) > 0 {
		assetFilter.Regions = in.Regions
		hasAssetFilter = true
	}
	if len(in.ResourceIDs) > 0 {
		assetFilter.ResourceIds = in.ResourceIDs
		hasAssetFilter = true
	}
	if len(in.ResourceTypes) > 0 {
		assetFilter.ResourceTypes = in.ResourceTypes
		hasAssetFilter = true
	}

	scopeType := "all_assets"
	if hasAssetFilter {
		scopeType = "asset_filter"
	}

	body := &models.SuppressionrulesCreateSuppressionRuleRequest{
		Name:                strPtr(in.Name),
		Domain:              strPtr("CSPM"),
		Subdomain:           strPtr("IOM"),
		SuppressionReason:   strPtr(in.SuppressionReason),
		RuleSelectionType:   strPtr("rule_selection_filter"),
		RuleSelectionFilter: ruleFilter,
		ScopeType:           strPtr(scopeType),
	}
	if hasAssetFilter {
		body.ScopeAssetFilter = assetFilter
	}
	if in.ExpirationDate != "" {
		body.SuppressionExpirationDate = in.ExpirationDate
	}

	m.Logger.Debug("create_cspm_suppression_rule", "name", in.Name, "reason", in.SuppressionReason, "scope_type", scopeType)

	params := cloud_policies.NewCreateSuppressionRuleParamsWithContext(ctx)
	params.Body = body
	resp, err := m.Policies.CreateSuppressionRule(params)
	if e := base.APIError(err, resp, scopePoliciesWrite); e != nil {
		return nil, zero, e
	}

	createdIDs := resp.Payload.Resources
	if len(createdIDs) == 0 {
		return nil, base.Entities([]*models.ApimodelsSuppressionRule{}).WithMeta(resp.Payload.Meta), nil
	}

	// The create endpoint returns created rule IDs — fetch full details.
	rules, err := m.getSuppressionRules(ctx, createdIDs)
	if err != nil {
		return nil, zero, err
	}
	return nil, base.Entities(rules).WithMeta(resp.Payload.Meta), nil
}

// --- Delete suppression rules ---

// DeleteSuppressionRulesInput is the input for falcon_delete_cspm_suppression_rules.
type DeleteSuppressionRulesInput struct {
	IDs []string `json:"ids" jsonschema:"List of suppression rule IDs to delete. Use falcon_search_cspm_suppression_rules to find rule IDs."`
}

// deleteCSPMSuppressionRules deletes suppression rules by ID, re-activating any
// findings they suppressed.
func (m *Module) deleteCSPMSuppressionRules(ctx context.Context, _ *mcp.CallToolRequest, in DeleteSuppressionRulesInput) (*mcp.CallToolResult, base.EntitiesResult[*models.ApimodelsSuppressionRule], error) {
	var zero base.EntitiesResult[*models.ApimodelsSuppressionRule]
	if len(in.IDs) == 0 {
		return nil, zero, wrapInvalid("delete suppression rules", "ids must not be empty")
	}
	m.Logger.Debug("delete_cspm_suppression_rules", "ids", len(in.IDs))

	params := cloud_policies.NewDeleteSuppressionRulesParamsWithContext(ctx)
	params.Ids = in.IDs
	resp, err := m.Policies.DeleteSuppressionRules(params)
	if e := base.APIError(err, resp, scopePoliciesWrite); e != nil {
		return nil, zero, e
	}
	return nil, base.Entities(resp.Payload.Resources).WithMeta(resp.Payload.Meta), nil
}

// strPtr returns a pointer to s. Used for the gofalcon required *string body fields.
func strPtr(s string) *string { return &s }

// validReasonsList renders the accepted suppression reasons as a sorted,
// comma-separated string for error messages.
func validReasonsList() string {
	reasons := make([]string, 0, len(validSuppressionReasons))
	for r := range validSuppressionReasons {
		reasons = append(reasons, r)
	}
	sort.Strings(reasons)
	return strings.Join(reasons, ", ")
}

// wrapInvalid builds an errInvalidInput-wrapped error for op with detail.
func wrapInvalid(op, detail string) error {
	return fmt.Errorf("%s: %w: %s", op, errInvalidInput, detail)
}
