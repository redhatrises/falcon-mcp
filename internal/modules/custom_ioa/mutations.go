package custom_ioa

import (
	"context"
	"fmt"

	"github.com/crowdstrike/gofalcon/falcon/client/custom_ioa"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/crowdstrike/falcon-mcp/internal/modules/base"
)

// validPlatforms are the accepted platform values for create_ioa_rule_group.
var validPlatforms = map[string]bool{
	"windows": true, "mac": true, "linux": true,
}

// validSeverities are the accepted pattern_severity values for IOA rules.
var validSeverities = map[string]bool{
	"critical": true, "high": true, "medium": true, "low": true, "informational": true,
}

// FieldValue mirrors a Custom IOA rule field value. It defines one matching
// criterion for a behavioral detection rule; the required fields depend on the
// rule type (discover them with falcon_get_ioa_rule_types).
type FieldValue struct {
	Name       string            `json:"name" jsonschema:"the field name (required), e.g. GrandparentImageFilename"`
	Value      string            `json:"value" jsonschema:"the match value (required); typically a regex or literal"`
	Label      string            `json:"label,omitempty" jsonschema:"an optional human-readable label for the field"`
	Type       string            `json:"type,omitempty" jsonschema:"an optional field type, e.g. excludable"`
	FinalValue string            `json:"final_value,omitempty" jsonschema:"an optional resolved value"`
	Values     []FieldValueEntry `json:"values,omitempty" jsonschema:"optional label/value pairs for multi-value fields"`
}

// FieldValueEntry is one label/value pair within a multi-value rule field.
type FieldValueEntry struct {
	Label string `json:"label,omitempty" jsonschema:"the entry label, e.g. include or exclude"`
	Value string `json:"value,omitempty" jsonschema:"the entry value"`
}

// toModel converts a FieldValue into the gofalcon request model.
func (fv FieldValue) toModel() *models.DomainFieldValue {
	name := fv.Name
	value := fv.Value
	fieldType := fv.Type
	out := &models.DomainFieldValue{
		Name:       &name,
		Value:      &value,
		Type:       &fieldType,
		Label:      fv.Label,
		FinalValue: fv.FinalValue,
	}
	for _, e := range fv.Values {
		label := e.Label
		val := e.Value
		out.Values = append(out.Values, &models.DomainValueItem{Label: &label, Value: &val})
	}
	return out
}

// fieldValuesToModels converts a slice of FieldValue into gofalcon models.
func fieldValuesToModels(fvs []FieldValue) []*models.DomainFieldValue {
	out := make([]*models.DomainFieldValue, 0, len(fvs))
	for _, fv := range fvs {
		out = append(out, fv.toModel())
	}
	return out
}

// CreateGroupInput is the input for falcon_create_ioa_rule_group.
type CreateGroupInput struct {
	Name        string `json:"name" jsonschema:"name for the new rule group (required)"`
	Platform    string `json:"platform" jsonschema:"platform the group applies to: windows, mac, or linux (required)"`
	Description string `json:"description,omitempty" jsonschema:"optional description for the rule group"`
	Comment     string `json:"comment,omitempty" jsonschema:"optional audit comment explaining the creation"`
}

func (m *Module) createRuleGroup(ctx context.Context, _ *mcp.CallToolRequest, in CreateGroupInput) (*mcp.CallToolResult, base.EntitiesResult[*models.APIRuleGroupV1], error) {
	var zero base.EntitiesResult[*models.APIRuleGroupV1]
	if in.Name == "" {
		return nil, zero, wrapInvalid("create IOA rule group", "name must not be empty")
	}
	if !validPlatforms[in.Platform] {
		return nil, zero, wrapInvalid("create IOA rule group", fmt.Sprintf("invalid platform %q (want windows, mac, or linux)", in.Platform))
	}
	m.Logger.Debug("create_ioa_rule_group", "name", in.Name, "platform", in.Platform)

	body := &models.APIRuleGroupCreateRequestV1{
		Name:     &in.Name,
		Platform: &in.Platform,
	}
	if in.Description != "" {
		body.Description = &in.Description
	}
	if in.Comment != "" {
		body.Comment = &in.Comment
	}

	params := custom_ioa.NewCreateRuleGroupMixin0ParamsWithContext(ctx)
	params.Body = body

	resp, err := m.API.CreateRuleGroupMixin0(params)
	if e := base.APIError(err, resp, scopeCustomIOAWrite); e != nil {
		return nil, zero, e
	}
	return nil, base.Entities(resp.Payload.Resources).WithMeta(resp.Payload.Meta), nil
}

// UpdateGroupInput is the input for falcon_update_ioa_rule_group. Only the set
// fields are sent; Enabled is a pointer so an explicit false is distinguishable
// from "unset".
type UpdateGroupInput struct {
	ID               string `json:"id" jsonschema:"ID of the rule group to update (required)"`
	RulegroupVersion int64  `json:"rulegroup_version" jsonschema:"current version of the rule group for optimistic locking (required); get it from falcon_search_ioa_rule_groups"`
	Name             string `json:"name,omitempty" jsonschema:"new name for the rule group"`
	Description      string `json:"description,omitempty" jsonschema:"new description for the rule group"`
	Enabled          *bool  `json:"enabled,omitempty" jsonschema:"whether the rule group should be enabled or disabled"`
	Comment          string `json:"comment,omitempty" jsonschema:"optional audit comment explaining the update"`
}

func (m *Module) updateRuleGroup(ctx context.Context, _ *mcp.CallToolRequest, in UpdateGroupInput) (*mcp.CallToolResult, base.EntitiesResult[*models.APIRuleGroupV1], error) {
	var zero base.EntitiesResult[*models.APIRuleGroupV1]
	if in.ID == "" {
		return nil, zero, wrapInvalid("update IOA rule group", "id must not be empty")
	}
	m.Logger.Debug("update_ioa_rule_group", "id", in.ID, "version", in.RulegroupVersion)

	body := &models.APIRuleGroupModifyRequestV1{
		ID:               &in.ID,
		RulegroupVersion: &in.RulegroupVersion,
	}
	if in.Name != "" {
		body.Name = &in.Name
	}
	if in.Description != "" {
		body.Description = &in.Description
	}
	if in.Enabled != nil {
		body.Enabled = in.Enabled
	}
	if in.Comment != "" {
		body.Comment = &in.Comment
	}

	params := custom_ioa.NewUpdateRuleGroupMixin0ParamsWithContext(ctx)
	params.Body = body

	resp, err := m.API.UpdateRuleGroupMixin0(params)
	if e := base.APIError(err, resp, scopeCustomIOAWrite); e != nil {
		return nil, zero, e
	}
	return nil, base.Entities(resp.Payload.Resources).WithMeta(resp.Payload.Meta), nil
}

// DeleteGroupsInput is the input for falcon_delete_ioa_rule_groups.
type DeleteGroupsInput struct {
	IDs     []string `json:"ids" jsonschema:"IDs of the rule groups to delete (required, non-empty)"`
	Comment string   `json:"comment,omitempty" jsonschema:"optional audit comment explaining the deletion"`
}

func (m *Module) deleteRuleGroups(ctx context.Context, _ *mcp.CallToolRequest, in DeleteGroupsInput) (*mcp.CallToolResult, base.ActionResult, error) {
	if len(in.IDs) == 0 {
		return nil, base.ActionResult{}, wrapInvalid("delete IOA rule groups", "ids must not be empty")
	}
	m.Logger.Debug("delete_ioa_rule_groups", "ids", len(in.IDs))

	params := custom_ioa.NewDeleteRuleGroupsMixin0ParamsWithContext(ctx)
	params.Ids = in.IDs
	if in.Comment != "" {
		params.Comment = &in.Comment
	}

	resp, err := m.API.DeleteRuleGroupsMixin0(params)
	if e := base.APIError(err, resp, scopeCustomIOAWrite); e != nil {
		return nil, base.ActionResult{}, e
	}
	return nil, base.ActionResult{Ok: true}.WithMeta(resp.Payload.Meta), nil
}

// CreateRuleInput is the input for falcon_create_ioa_rule.
type CreateRuleInput struct {
	RulegroupID     string       `json:"rulegroup_id" jsonschema:"ID of the rule group to add the rule to (required)"`
	Name            string       `json:"name" jsonschema:"name for the new rule (required)"`
	RuletypeID      string       `json:"ruletype_id" jsonschema:"rule type ID defining the detection category (required); use falcon_get_ioa_rule_types"`
	DispositionID   int32        `json:"disposition_id" jsonschema:"disposition ID for the action taken when the rule fires (required); use falcon_get_ioa_rule_types"`
	PatternSeverity string       `json:"pattern_severity" jsonschema:"severity: critical, high, medium, low, or informational (required)"`
	FieldValues     []FieldValue `json:"field_values" jsonschema:"field value objects defining the rule's matching criteria (required); use falcon_get_ioa_rule_types to discover required fields"`
	Description     string       `json:"description,omitempty" jsonschema:"optional description for the rule"`
	Comment         string       `json:"comment,omitempty" jsonschema:"optional audit comment explaining the creation"`
}

func (m *Module) createRule(ctx context.Context, _ *mcp.CallToolRequest, in CreateRuleInput) (*mcp.CallToolResult, base.EntitiesResult[*models.APIRuleV1], error) {
	var zero base.EntitiesResult[*models.APIRuleV1]
	if err := in.validate(); err != nil {
		return nil, zero, err
	}
	m.Logger.Debug("create_ioa_rule", "rulegroup_id", in.RulegroupID, "name", in.Name, "ruletype_id", in.RuletypeID)

	body := &models.APIRuleCreateV1{
		RulegroupID:     &in.RulegroupID,
		Name:            &in.Name,
		RuletypeID:      &in.RuletypeID,
		DispositionID:   &in.DispositionID,
		PatternSeverity: &in.PatternSeverity,
		FieldValues:     fieldValuesToModels(in.FieldValues),
	}
	if in.Description != "" {
		body.Description = &in.Description
	}
	if in.Comment != "" {
		body.Comment = &in.Comment
	}

	params := custom_ioa.NewCreateRuleParamsWithContext(ctx)
	params.Body = body

	resp, err := m.API.CreateRule(params)
	if e := base.APIError(err, resp, scopeCustomIOAWrite); e != nil {
		return nil, zero, e
	}
	return nil, base.Entities(resp.Payload.Resources).WithMeta(resp.Payload.Meta), nil
}

// validate enforces the client-side constraints on a rule create request.
func (in CreateRuleInput) validate() error {
	if in.RulegroupID == "" {
		return wrapInvalid("create IOA rule", "rulegroup_id must not be empty")
	}
	if in.Name == "" {
		return wrapInvalid("create IOA rule", "name must not be empty")
	}
	if in.RuletypeID == "" {
		return wrapInvalid("create IOA rule", "ruletype_id must not be empty")
	}
	if !validSeverities[in.PatternSeverity] {
		return wrapInvalid("create IOA rule", fmt.Sprintf("invalid pattern_severity %q (want critical, high, medium, low, or informational)", in.PatternSeverity))
	}
	if len(in.FieldValues) == 0 {
		return wrapInvalid("create IOA rule", "field_values must not be empty")
	}
	return nil
}

// UpdateRuleInput is the input for falcon_update_ioa_rule. Only the set fields
// are applied to the rule; Enabled is a pointer so an explicit false is
// distinguishable from "unset".
type UpdateRuleInput struct {
	RulegroupID      string       `json:"rulegroup_id" jsonschema:"ID of the rule group containing the rule (required)"`
	RulegroupVersion int64        `json:"rulegroup_version" jsonschema:"current version of the rule group for optimistic locking (required); get it from falcon_search_ioa_rule_groups"`
	InstanceID       string       `json:"instance_id" jsonschema:"instance ID of the rule to update (required); get it from falcon_search_ioa_rule_groups"`
	Name             string       `json:"name,omitempty" jsonschema:"new name for the rule"`
	Description      string       `json:"description,omitempty" jsonschema:"new description for the rule"`
	Enabled          *bool        `json:"enabled,omitempty" jsonschema:"whether the rule should be enabled or disabled"`
	PatternSeverity  string       `json:"pattern_severity,omitempty" jsonschema:"new severity: critical, high, medium, low, or informational"`
	DispositionID    *int32       `json:"disposition_id,omitempty" jsonschema:"new disposition ID for the action taken when the rule fires"`
	FieldValues      []FieldValue `json:"field_values,omitempty" jsonschema:"updated field value objects defining the rule's matching criteria"`
	Comment          string       `json:"comment,omitempty" jsonschema:"optional audit comment explaining the update"`
}

func (m *Module) updateRule(ctx context.Context, _ *mcp.CallToolRequest, in UpdateRuleInput) (*mcp.CallToolResult, base.EntitiesResult[*models.APIRuleV1], error) {
	var zero base.EntitiesResult[*models.APIRuleV1]
	if err := in.validate(); err != nil {
		return nil, zero, err
	}
	m.Logger.Debug("update_ioa_rule", "rulegroup_id", in.RulegroupID, "instance_id", in.InstanceID, "version", in.RulegroupVersion)

	version := in.RulegroupVersion
	ruleUpdate := &models.APIRuleUpdateV2{
		InstanceID:       &in.InstanceID,
		RulegroupVersion: &version,
	}
	if in.Name != "" {
		ruleUpdate.Name = &in.Name
	}
	if in.Description != "" {
		ruleUpdate.Description = &in.Description
	}
	if in.Enabled != nil {
		ruleUpdate.Enabled = in.Enabled
	}
	if in.PatternSeverity != "" {
		ruleUpdate.PatternSeverity = &in.PatternSeverity
	}
	if in.DispositionID != nil {
		ruleUpdate.DispositionID = in.DispositionID
	}
	if in.FieldValues != nil {
		ruleUpdate.FieldValues = fieldValuesToModels(in.FieldValues)
	}

	body := &models.APIRuleUpdatesRequestV2{
		RulegroupID:      &in.RulegroupID,
		RulegroupVersion: &version,
		RuleUpdates:      []*models.APIRuleUpdateV2{ruleUpdate},
	}
	if in.Comment != "" {
		body.Comment = &in.Comment
	}

	params := custom_ioa.NewUpdateRulesV2ParamsWithContext(ctx)
	params.Body = body

	resp, err := m.API.UpdateRulesV2(params)
	if e := base.APIError(err, resp, scopeCustomIOAWrite); e != nil {
		return nil, zero, e
	}
	return nil, base.Entities(resp.Payload.Resources).WithMeta(resp.Payload.Meta), nil
}

// validate enforces the client-side constraints on a rule update request.
func (in UpdateRuleInput) validate() error {
	if in.RulegroupID == "" {
		return wrapInvalid("update IOA rule", "rulegroup_id must not be empty")
	}
	if in.InstanceID == "" {
		return wrapInvalid("update IOA rule", "instance_id must not be empty")
	}
	if in.PatternSeverity != "" && !validSeverities[in.PatternSeverity] {
		return wrapInvalid("update IOA rule", fmt.Sprintf("invalid pattern_severity %q (want critical, high, medium, low, or informational)", in.PatternSeverity))
	}
	return nil
}

// DeleteRulesInput is the input for falcon_delete_ioa_rules.
type DeleteRulesInput struct {
	RuleGroupID string   `json:"rule_group_id" jsonschema:"ID of the rule group containing the rules to delete (required)"`
	IDs         []string `json:"ids" jsonschema:"instance IDs of the rules to delete (required, non-empty); get them from falcon_search_ioa_rule_groups"`
	Comment     string   `json:"comment,omitempty" jsonschema:"optional audit comment explaining the deletion"`
}

func (m *Module) deleteRules(ctx context.Context, _ *mcp.CallToolRequest, in DeleteRulesInput) (*mcp.CallToolResult, base.ActionResult, error) {
	if in.RuleGroupID == "" {
		return nil, base.ActionResult{}, wrapInvalid("delete IOA rules", "rule_group_id must not be empty")
	}
	if len(in.IDs) == 0 {
		return nil, base.ActionResult{}, wrapInvalid("delete IOA rules", "ids must not be empty")
	}
	m.Logger.Debug("delete_ioa_rules", "rule_group_id", in.RuleGroupID, "ids", len(in.IDs))

	params := custom_ioa.NewDeleteRulesParamsWithContext(ctx)
	params.RuleGroupID = in.RuleGroupID
	params.Ids = in.IDs
	if in.Comment != "" {
		params.Comment = &in.Comment
	}

	resp, err := m.API.DeleteRules(params)
	if e := base.APIError(err, resp, scopeCustomIOAWrite); e != nil {
		return nil, base.ActionResult{}, e
	}
	return nil, base.ActionResult{Ok: true}.WithMeta(resp.Payload.Meta), nil
}

// wrapInvalid builds an errInvalidInput-wrapped error for op with detail.
func wrapInvalid(op, detail string) error {
	return fmt.Errorf("%s: %w: %s", op, errInvalidInput, detail)
}
