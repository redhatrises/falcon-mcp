package firewall

import (
	"context"
	"fmt"

	"github.com/crowdstrike/gofalcon/falcon/client/firewall_management"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/crowdstrike/falcon-mcp/internal/modules/base"
)

// CreateInput is the input for falcon_create_firewall_rule_group. Provide name
// and platform plus either rules or clone_id; when cloning, the rules field is
// ignored by the API.
type CreateInput struct {
	Name        string                                `json:"name,omitempty" jsonschema:"rule group name (required)"`
	Platform    string                                `json:"platform,omitempty" jsonschema:"target platform (e.g. windows, mac, linux) (required)"`
	Rules       []*models.FwmgrAPIRuleCreateRequestV1 `json:"rules,omitempty" jsonschema:"rule definitions; required unless clone_id is set"`
	Description string                                `json:"description,omitempty" jsonschema:"rule group description"`
	Enabled     *bool                                 `json:"enabled,omitempty" jsonschema:"whether this rule group is enabled; defaults to true"`
	CloneID     string                                `json:"clone_id,omitempty" jsonschema:"rule group ID to clone from; when set, rules is ignored"`
	Library     bool                                  `json:"library,omitempty" jsonschema:"set true when cloning from the CrowdStrike rule group library"`
	Comment     string                                `json:"comment,omitempty" jsonschema:"audit log comment for this action"`
}

func (m *Module) createFirewallRuleGroup(ctx context.Context, _ *mcp.CallToolRequest, in CreateInput) (*mcp.CallToolResult, base.EntitiesResult[string], error) {
	var zero base.EntitiesResult[string]
	if err := in.validate(); err != nil {
		return nil, zero, err
	}
	m.Logger.Debug("create_firewall_rule_group", "name", in.Name, "platform", in.Platform, "clone_id", in.CloneID, "rules", len(in.Rules))

	// Enabled defaults to true, matching the Python module's default.
	enabled := true
	if in.Enabled != nil {
		enabled = *in.Enabled
	}
	body := &models.FwmgrAPIRuleGroupCreateRequestV1{
		Name:     &in.Name,
		Platform: &in.Platform,
		Enabled:  &enabled,
	}
	if in.Description != "" {
		body.Description = &in.Description
	}
	if len(in.Rules) > 0 {
		body.Rules = in.Rules
	}

	params := firewall_management.NewCreateRuleGroupParamsWithContext(ctx)
	params.Body = body
	if in.CloneID != "" {
		params.CloneID = &in.CloneID
	}
	if in.Comment != "" {
		params.Comment = &in.Comment
	}
	if in.Library {
		library := "true"
		params.Library = &library
	}

	resp, err := m.API.CreateRuleGroup(params)
	if e := base.APIError(err, resp, scopeFirewallWrite); e != nil {
		return nil, zero, e
	}
	return nil, base.Entities(resp.Payload.Resources).WithMeta(resp.Payload.Meta), nil
}

// validate enforces the client-side constraints on a create request, mirroring
// the Python module: name and platform are required, and either rules or a
// clone_id must be provided.
func (in CreateInput) validate() error {
	if in.Name == "" || in.Platform == "" {
		return wrapInvalid("create firewall rule group", "name and platform are required")
	}
	if len(in.Rules) == 0 && in.CloneID == "" {
		return wrapInvalid("create firewall rule group", "provide rules or clone_id")
	}
	return nil
}

// DeleteInput is the input for falcon_delete_firewall_rule_groups.
type DeleteInput struct {
	IDs     []string `json:"ids" jsonschema:"rule group IDs to delete (required, non-empty)"`
	Comment string   `json:"comment,omitempty" jsonschema:"audit log comment for this action"`
}

func (m *Module) deleteFirewallRuleGroups(ctx context.Context, _ *mcp.CallToolRequest, in DeleteInput) (*mcp.CallToolResult, base.EntitiesResult[string], error) {
	var zero base.EntitiesResult[string]
	if len(in.IDs) == 0 {
		return nil, zero, wrapInvalid("delete firewall rule groups", "ids must not be empty")
	}
	m.Logger.Debug("delete_firewall_rule_groups", "ids", len(in.IDs))

	params := firewall_management.NewDeleteRuleGroupsParamsWithContext(ctx)
	params.Ids = in.IDs
	if in.Comment != "" {
		params.Comment = &in.Comment
	}

	resp, err := m.API.DeleteRuleGroups(params)
	if e := base.APIError(err, resp, scopeFirewallWrite); e != nil {
		return nil, zero, e
	}
	return nil, base.Entities(resp.Payload.Resources).WithMeta(resp.Payload.Meta), nil
}

// wrapInvalid builds an errInvalidInput-wrapped error for op with detail.
func wrapInvalid(op, detail string) error {
	return fmt.Errorf("%s: %w: %s", op, errInvalidInput, detail)
}
