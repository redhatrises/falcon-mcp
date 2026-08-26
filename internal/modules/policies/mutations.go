package policies

import (
	"context"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/crowdstrike/falcon-mcp/internal/modules/base"
)

// CreateInput is the input for falcon_create_policy. settings is an opaque
// per-type object passed through unchanged; building detailed settings is out of
// scope, so cloning via clone_id then adjusting with update_policy is preferred.
type CreateInput struct {
	PolicyType   string `json:"policy_type" jsonschema:"policy type to create: prevention, sensor_update, firewall, device_control, response, or content_update"`
	Name         string `json:"name,omitempty" jsonschema:"name for the new policy (required)"`
	PlatformName string `json:"platform_name,omitempty" jsonschema:"target platform (Windows, Mac, Linux); required for all types except content_update"`
	Description  string `json:"description,omitempty" jsonschema:"description for the policy"`
	Settings     any    `json:"settings,omitempty" jsonschema:"opaque per-type settings object, passed through unchanged; prefer clone_id for v1"`
	CloneID      string `json:"clone_id,omitempty" jsonschema:"ID of an existing policy to clone settings from; an alternative to settings"`
}

func (m *Module) createPolicy(ctx context.Context, _ *mcp.CallToolRequest, in CreateInput) (*mcp.CallToolResult, base.EntitiesResult[map[string]any], error) {
	var zero base.EntitiesResult[map[string]any]
	b, ok := m.backends[in.PolicyType]
	if !ok {
		return nil, zero, invalidType(in.PolicyType)
	}
	if in.Name == "" {
		return nil, zero, base.InvalidInput("create policy", "a name is required to create a policy")
	}
	if in.Settings != nil && !supportsSettings[in.PolicyType] {
		return nil, zero, base.InvalidInput("create policy", settingsUnsupportedMsg(in.PolicyType))
	}
	if createNeedsPlatform[in.PolicyType] && in.PlatformName == "" {
		return nil, zero, base.InvalidInput("create policy", "a platform_name (e.g. Windows, Mac, Linux) is required to create a "+in.PolicyType+" policy")
	}
	m.Logger.Debug("create_policy", "type", in.PolicyType, "name", in.Name, "platform", in.PlatformName)

	records, meta, err := b.create(ctx, createSpec{
		name:         in.Name,
		platformName: in.PlatformName,
		description:  in.Description,
		settings:     in.Settings,
		cloneID:      in.CloneID,
	})
	if e := base.APIError(err, nil, writeScope(in.PolicyType)); e != nil {
		return nil, zero, e
	}
	return nil, base.Entities(records).WithMeta(meta), nil
}

// UpdateInput is the input for falcon_update_policy. platform_name is not
// updatable after creation, so it is absent here.
type UpdateInput struct {
	PolicyType  string `json:"policy_type" jsonschema:"policy type to update: prevention, sensor_update, firewall, device_control, response, or content_update"`
	ID          string `json:"id,omitempty" jsonschema:"ID of the policy to update (required)"`
	Name        string `json:"name,omitempty" jsonschema:"new name for the policy"`
	Description string `json:"description,omitempty" jsonschema:"new description for the policy"`
	Settings    any    `json:"settings,omitempty" jsonschema:"opaque per-type settings object, passed through unchanged; unspecified fields are left unchanged"`
}

func (m *Module) updatePolicy(ctx context.Context, _ *mcp.CallToolRequest, in UpdateInput) (*mcp.CallToolResult, base.EntitiesResult[map[string]any], error) {
	var zero base.EntitiesResult[map[string]any]
	b, ok := m.backends[in.PolicyType]
	if !ok {
		return nil, zero, invalidType(in.PolicyType)
	}
	if in.ID == "" {
		return nil, zero, base.InvalidInput("update policy", "a policy id is required to update a policy")
	}
	if in.Settings != nil && !supportsSettings[in.PolicyType] {
		return nil, zero, base.InvalidInput("update policy", settingsUnsupportedMsg(in.PolicyType))
	}
	m.Logger.Debug("update_policy", "type", in.PolicyType, "id", in.ID)

	records, meta, err := b.update(ctx, updateSpec{
		id:          in.ID,
		name:        in.Name,
		description: in.Description,
		settings:    in.Settings,
	})
	if e := base.APIError(err, nil, writeScope(in.PolicyType)); e != nil {
		return nil, zero, e
	}
	return nil, base.Entities(records).WithMeta(meta), nil
}

// DeleteInput is the input for falcon_delete_policies.
type DeleteInput struct {
	PolicyType string   `json:"policy_type" jsonschema:"policy type to delete: prevention, sensor_update, firewall, device_control, response, or content_update"`
	IDs        []string `json:"ids" jsonschema:"IDs of the policies to delete (required, non-empty)"`
}

func (m *Module) deletePolicies(ctx context.Context, _ *mcp.CallToolRequest, in DeleteInput) (*mcp.CallToolResult, base.ActionResult, error) {
	b, ok := m.backends[in.PolicyType]
	if !ok {
		return nil, base.ActionResult{}, invalidType(in.PolicyType)
	}
	if len(in.IDs) == 0 {
		return nil, base.ActionResult{}, base.InvalidInput("delete policies", "a non-empty ids list is required")
	}
	m.Logger.Debug("delete_policies", "type", in.PolicyType, "ids", len(in.IDs))

	meta, err := b.deleteByIDs(ctx, in.IDs)
	if e := base.APIError(err, nil, writeScope(in.PolicyType)); e != nil {
		return nil, base.ActionResult{}, e
	}
	return nil, base.ActionResult{Ok: true}.WithMeta(meta), nil
}

// ActionInput is the input for falcon_perform_policy_action.
type ActionInput struct {
	PolicyType string   `json:"policy_type" jsonschema:"policy type: prevention, sensor_update, firewall, device_control, response, or content_update"`
	ActionName string   `json:"action_name" jsonschema:"action: enable, disable, add-host-group, remove-host-group (all types); add-rule-group, remove-rule-group (prevention only); override-allow, override-pause, override-revert (content_update). Validated per type."`
	IDs        []string `json:"ids" jsonschema:"IDs of the policies to act on (required, non-empty)"`
	GroupID    string   `json:"group_id,omitempty" jsonschema:"group ID for group actions: a host group ID for add/remove-host-group, a rule group ID for add/remove-rule-group; omit for other actions"`
}

func (m *Module) performPolicyAction(ctx context.Context, _ *mcp.CallToolRequest, in ActionInput) (*mcp.CallToolResult, base.EntitiesResult[map[string]any], error) {
	var zero base.EntitiesResult[map[string]any]
	b, ok := m.backends[in.PolicyType]
	if !ok {
		return nil, zero, invalidType(in.PolicyType)
	}
	if !validActions[in.PolicyType][in.ActionName] {
		return nil, zero, base.InvalidInput("perform policy action", "invalid action_name "+quote(in.ActionName)+" for "+in.PolicyType+"; "+validActionsHint(in.PolicyType))
	}
	if len(in.IDs) == 0 {
		return nil, zero, base.InvalidInput("perform policy action", "a non-empty ids list is required")
	}
	if _, isGroupAction := groupActionParam[in.ActionName]; isGroupAction && in.GroupID == "" {
		return nil, zero, base.InvalidInput("perform policy action", "action_name "+quote(in.ActionName)+" requires a group_id (the host group ID for host-group actions, or the rule group ID for rule-group actions)")
	}
	m.Logger.Debug("perform_policy_action", "type", in.PolicyType, "action", in.ActionName, "ids", len(in.IDs), "has_group", in.GroupID != "")

	records, meta, err := b.action(ctx, in.ActionName, in.IDs, in.GroupID)
	if e := base.APIError(err, nil, writeScope(in.PolicyType)); e != nil {
		return nil, zero, e
	}
	return nil, base.Entities(records).WithMeta(meta), nil
}

// PrecedenceInput is the input for falcon_set_policy_precedence.
type PrecedenceInput struct {
	PolicyType   string   `json:"policy_type" jsonschema:"policy type: prevention, sensor_update, firewall, device_control, response, or content_update"`
	IDs          []string `json:"ids" jsonschema:"the COMPLETE ordered list of non-Default policy IDs for the platform, highest precedence first (required, non-empty)"`
	PlatformName string   `json:"platform_name,omitempty" jsonschema:"target platform (Windows, Mac, Linux); required for all types except content_update"`
}

func (m *Module) setPolicyPrecedence(ctx context.Context, _ *mcp.CallToolRequest, in PrecedenceInput) (*mcp.CallToolResult, base.ActionResult, error) {
	b, ok := m.backends[in.PolicyType]
	if !ok {
		return nil, base.ActionResult{}, invalidType(in.PolicyType)
	}
	if len(in.IDs) == 0 {
		return nil, base.ActionResult{}, base.InvalidInput("set policy precedence", "a non-empty ids list is required")
	}
	if precedenceNeedsPlatform[in.PolicyType] && in.PlatformName == "" {
		return nil, base.ActionResult{}, base.InvalidInput("set policy precedence", "a platform_name is required to set precedence for "+in.PolicyType+" policies")
	}
	m.Logger.Debug("set_policy_precedence", "type", in.PolicyType, "ids", len(in.IDs), "platform", in.PlatformName)

	meta, err := b.setPrecedence(ctx, in.IDs, in.PlatformName)
	if e := base.APIError(err, nil, writeScope(in.PolicyType)); e != nil {
		return nil, base.ActionResult{}, e
	}
	return nil, base.ActionResult{Ok: true}.WithMeta(meta), nil
}

// quote wraps s in single quotes for readable error messages.
func quote(s string) string { return "'" + s + "'" }

// settingsUnsupportedMsg explains why a settings object was rejected for a
// policy type whose create/update model has no settings field.
func settingsUnsupportedMsg(policyType string) string {
	return quote(policyType) + " policies do not accept a 'settings' object — the endpoint has no such field and would silently ignore it"
}

// validActionsHint renders the sorted valid actions for a type, for error text.
func validActionsHint(policyType string) string {
	set := validActions[policyType]
	// Stable, human-friendly ordering: the four common actions first, then extras.
	order := []string{"enable", "disable", "add-host-group", "remove-host-group", "add-rule-group", "remove-rule-group", "override-allow", "override-pause", "override-revert"}
	var valid []string
	for _, a := range order {
		if set[a] {
			valid = append(valid, a)
		}
	}
	return "valid actions are: " + strings.Join(valid, ", ")
}
