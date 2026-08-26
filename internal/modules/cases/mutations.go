package cases

import (
	"context"
	"fmt"
	"slices"

	"github.com/crowdstrike/gofalcon/falcon/client/cases"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/crowdstrike/falcon-mcp/internal/modules/base"
)

// validTagActions are the accepted action values for manage_case_tags.
var validTagActions = map[string]bool{"add": true, "remove": true}

// descriptionFormats are the accepted values for a case description_format.
var descriptionFormats = []string{"markdown", "plaintext"}

// validDescriptionFormat reports whether format is an accepted description_format.
func validDescriptionFormat(format string) bool {
	return slices.Contains(descriptionFormats, format)
}

// CreateInput is the input for falcon_create_case. Name and severity are
// required; the remaining fields are optional.
type CreateInput struct {
	Name               string   `json:"name" jsonschema:"case name (max 256 characters) (required)"`
	Severity           int      `json:"severity" jsonschema:"severity level (1-100). 1=Informational, ~25=Low, ~50=Medium, ~75=High, 100=Critical (required)"`
	Description        string   `json:"description,omitempty" jsonschema:"case description (max 2048 characters)"`
	DescriptionFormat  string   `json:"description_format,omitempty" jsonschema:"rendering format for the description. Values: markdown, plaintext"`
	Status             string   `json:"status,omitempty" jsonschema:"initial status. Values: new, in_progress. Defaults to 'new' if omitted"`
	AssignedToUserUUID string   `json:"assigned_to_user_uuid,omitempty" jsonschema:"UUID of the user to assign the case to"`
	Tags               []string `json:"tags,omitempty" jsonschema:"tags to apply (128 combined character limit across all tags)"`
	TemplateID         string   `json:"template_id,omitempty" jsonschema:"template ID to apply to the case"`
	AlertIDs           []string `json:"alert_ids,omitempty" jsonschema:"alert composite IDs to attach as evidence (from Alerts v2 API). Max 100 total evidence items"`
	EventIDs           []string `json:"event_ids,omitempty" jsonschema:"LogScale event IDs to attach as evidence (from falcon_search_ngsiem). Max 100 total evidence items"`
}

func (m *Module) createCase(ctx context.Context, _ *mcp.CallToolRequest, in CreateInput) (*mcp.CallToolResult, base.EntitiesResult[*models.SdkCaseVM], error) {
	var zero base.EntitiesResult[*models.SdkCaseVM]
	if in.Name == "" {
		return nil, zero, wrapInvalid("create case", "name must not be empty")
	}
	if in.Severity < 1 || in.Severity > 100 {
		return nil, zero, wrapInvalid("create case", "severity must be between 1 and 100")
	}
	if in.DescriptionFormat != "" && !validDescriptionFormat(in.DescriptionFormat) {
		return nil, zero, wrapInvalid("create case", fmt.Sprintf("invalid description_format %q (want 'markdown' or 'plaintext')", in.DescriptionFormat))
	}
	m.Logger.Debug("create_case", "name", in.Name, "severity", in.Severity, "alerts", len(in.AlertIDs), "events", len(in.EventIDs))

	severity := int64(in.Severity)
	body := &models.OperationsCreateCaseRequest{
		Name:     &in.Name,
		Severity: &severity,
	}
	if in.Description != "" {
		body.Description = &in.Description
	}
	if in.DescriptionFormat != "" {
		body.DescriptionFormat = in.DescriptionFormat
	}
	if in.Status != "" {
		body.Status = &in.Status
	}
	if in.AssignedToUserUUID != "" {
		body.AssignedToUserUUID = &in.AssignedToUserUUID
	}
	if len(in.Tags) > 0 {
		body.Tags = in.Tags
	}
	if in.TemplateID != "" {
		body.Template = &models.SdkTemplateSelector{ID: &in.TemplateID}
	}
	if evidence := buildEvidence(in.AlertIDs, in.EventIDs); evidence != nil {
		body.Evidence = evidence
	}

	params := cases.NewEntitiesCasesPutV2ParamsWithContext(ctx)
	params.Body = body

	resp, err := m.Cases.EntitiesCasesPutV2(params)
	if e := base.APIError(err, resp, scopeCasesWrite); e != nil {
		return nil, zero, e
	}
	return nil, base.Entities(resp.Payload.Resources).WithMeta(resp.Payload.Meta), nil
}

// buildEvidence assembles the create-case evidence block from alert and event
// IDs, or returns nil when both are empty so no evidence key is sent.
func buildEvidence(alertIDs, eventIDs []string) *models.OperationsCreateCaseRequestEvidence {
	if len(alertIDs) == 0 && len(eventIDs) == 0 {
		return nil
	}
	evidence := &models.OperationsCreateCaseRequestEvidence{}
	for _, aid := range alertIDs {
		evidence.Alerts = append(evidence.Alerts, &models.SdkAlertEvidenceSelector{ID: new(aid)})
	}
	for _, eid := range eventIDs {
		evidence.Events = append(evidence.Events, &models.SdkEventEvidenceSelector{ID: new(eid)})
	}
	return evidence
}

// UpdateInput is the input for falcon_update_case. Only the fields that are set
// are sent; unspecified fields are left unchanged. Severity and
// RemoveUserAssignment are pointers so an explicit value is distinguished from
// "unset".
type UpdateInput struct {
	ID                   string `json:"id" jsonschema:"case ID to update (the opaque system ID, not reference_id) (required)"`
	Name                 string `json:"name,omitempty" jsonschema:"new case name"`
	Description          string `json:"description,omitempty" jsonschema:"new case description"`
	DescriptionFormat    string `json:"description_format,omitempty" jsonschema:"rendering format for the description. Values: markdown, plaintext"`
	Status               string `json:"status,omitempty" jsonschema:"new status. Values: new, in_progress, closed, reopened"`
	Severity             *int   `json:"severity,omitempty" jsonschema:"new severity (1-100)"`
	AssignedToUserUUID   string `json:"assigned_to_user_uuid,omitempty" jsonschema:"UUID of user to assign. Use remove_user_assignment=true to unassign instead"`
	RemoveUserAssignment *bool  `json:"remove_user_assignment,omitempty" jsonschema:"set to true to remove the current user assignment"`
	TemplateID           string `json:"template_id,omitempty" jsonschema:"template ID to apply to the case"`
	ExpectedVersion      *int   `json:"expected_version,omitempty" jsonschema:"expected case version for optimistic concurrency. If provided and mismatched, the update returns 409 Conflict"`
}

func (m *Module) updateCase(ctx context.Context, _ *mcp.CallToolRequest, in UpdateInput) (*mcp.CallToolResult, base.EntitiesResult[*models.SdkCaseVM], error) {
	var zero base.EntitiesResult[*models.SdkCaseVM]
	if in.ID == "" {
		return nil, zero, wrapInvalid("update case", "id must not be empty")
	}
	if in.Severity != nil && (*in.Severity < 1 || *in.Severity > 100) {
		return nil, zero, wrapInvalid("update case", "severity must be between 1 and 100")
	}
	if in.DescriptionFormat != "" && !validDescriptionFormat(in.DescriptionFormat) {
		return nil, zero, wrapInvalid("update case", fmt.Sprintf("invalid description_format %q (want 'markdown' or 'plaintext')", in.DescriptionFormat))
	}

	fields := &models.OperationsCaseFieldChanges{}
	hasField := false
	if in.Name != "" {
		fields.Name = &in.Name
		hasField = true
	}
	if in.Description != "" {
		fields.Description = &in.Description
		hasField = true
	}
	if in.DescriptionFormat != "" {
		fields.DescriptionFormat = in.DescriptionFormat
		hasField = true
	}
	if in.Status != "" {
		fields.Status = &in.Status
		hasField = true
	}
	if in.Severity != nil {
		fields.Severity = new(int64(*in.Severity))
		hasField = true
	}
	if in.AssignedToUserUUID != "" {
		fields.AssignedToUserUUID = &in.AssignedToUserUUID
		hasField = true
	}
	if in.RemoveUserAssignment != nil {
		fields.RemoveUserAssignment = in.RemoveUserAssignment
		hasField = true
	}
	if in.TemplateID != "" {
		fields.Template = &models.SdkTemplateSelector{ID: &in.TemplateID}
		hasField = true
	}
	if !hasField {
		return nil, zero, wrapInvalid("update case", "at least one field to update must be provided")
	}
	m.Logger.Debug("update_case", "id", in.ID, "has_expected_version", in.ExpectedVersion != nil)

	body := &models.OperationsUpdateCaseRequest{
		ID:     &in.ID,
		Fields: fields,
	}
	if in.ExpectedVersion != nil {
		body.ExpectedVersion = int64(*in.ExpectedVersion)
	}

	params := cases.NewEntitiesCasesPatchV2ParamsWithContext(ctx)
	params.Body = body

	resp, err := m.Cases.EntitiesCasesPatchV2(params)
	if e := base.APIError(err, resp, scopeCasesWrite); e != nil {
		return nil, zero, e
	}
	return nil, base.Entities(resp.Payload.Resources).WithMeta(resp.Payload.Meta), nil
}

// AlertEvidenceInput is the input for falcon_add_case_alert_evidence.
type AlertEvidenceInput struct {
	ID       string   `json:"id" jsonschema:"case ID to add alert evidence to (required)"`
	AlertIDs []string `json:"alert_ids" jsonschema:"alert composite IDs to attach (from Alerts v2 API). Max 100 total evidence items per case (required, non-empty)"`
}

func (m *Module) addCaseAlertEvidence(ctx context.Context, _ *mcp.CallToolRequest, in AlertEvidenceInput) (*mcp.CallToolResult, base.EntitiesResult[*models.SdkCaseVM], error) {
	var zero base.EntitiesResult[*models.SdkCaseVM]
	if in.ID == "" {
		return nil, zero, wrapInvalid("add case alert evidence", "id must not be empty")
	}
	if len(in.AlertIDs) == 0 {
		return nil, zero, wrapInvalid("add case alert evidence", "alert_ids must not be empty")
	}
	m.Logger.Debug("add_case_alert_evidence", "id", in.ID, "alerts", len(in.AlertIDs))

	body := &models.OperationsAddAlertsToCaseRequest{ID: &in.ID}
	for _, aid := range in.AlertIDs {
		body.Alerts = append(body.Alerts, &models.SdkAlertEvidenceSelector{ID: new(aid)})
	}

	params := cases.NewEntitiesAlertEvidencePostV1ParamsWithContext(ctx)
	params.Body = body

	resp, err := m.Cases.EntitiesAlertEvidencePostV1(params)
	if e := base.APIError(err, resp, scopeCasesWrite); e != nil {
		return nil, zero, e
	}
	return nil, base.Entities(resp.Payload.Resources).WithMeta(resp.Payload.Meta), nil
}

// EventEvidenceInput is the input for falcon_add_case_event_evidence.
type EventEvidenceInput struct {
	ID       string   `json:"id" jsonschema:"case ID to add event evidence to (required)"`
	EventIDs []string `json:"event_ids" jsonschema:"LogScale event IDs to attach (from falcon_search_ngsiem). Max 100 total evidence items per case (required, non-empty)"`
}

func (m *Module) addCaseEventEvidence(ctx context.Context, _ *mcp.CallToolRequest, in EventEvidenceInput) (*mcp.CallToolResult, base.EntitiesResult[*models.SdkCaseVM], error) {
	var zero base.EntitiesResult[*models.SdkCaseVM]
	if in.ID == "" {
		return nil, zero, wrapInvalid("add case event evidence", "id must not be empty")
	}
	if len(in.EventIDs) == 0 {
		return nil, zero, wrapInvalid("add case event evidence", "event_ids must not be empty")
	}
	m.Logger.Debug("add_case_event_evidence", "id", in.ID, "events", len(in.EventIDs))

	body := &models.OperationsAddEventsToCaseRequest{ID: &in.ID}
	for _, eid := range in.EventIDs {
		body.Events = append(body.Events, &models.SdkEventEvidenceSelector{ID: new(eid)})
	}

	params := cases.NewEntitiesEventEvidencePostV1ParamsWithContext(ctx)
	params.Body = body

	resp, err := m.Cases.EntitiesEventEvidencePostV1(params)
	if e := base.APIError(err, resp, scopeCasesWrite); e != nil {
		return nil, zero, e
	}
	return nil, base.Entities(resp.Payload.Resources).WithMeta(resp.Payload.Meta), nil
}

// TagsInput is the input for falcon_manage_case_tags.
type TagsInput struct {
	ID     string   `json:"id" jsonschema:"case ID to manage tags for (required)"`
	Action string   `json:"action" jsonschema:"action to perform. Values: 'add' or 'remove' (required)"`
	Tags   []string `json:"tags" jsonschema:"tags to add or remove. 128 combined character limit across all tags on a case (required, non-empty)"`
}

func (m *Module) manageCaseTags(ctx context.Context, _ *mcp.CallToolRequest, in TagsInput) (*mcp.CallToolResult, base.EntitiesResult[*models.SdkCaseVM], error) {
	var zero base.EntitiesResult[*models.SdkCaseVM]
	if in.ID == "" {
		return nil, zero, wrapInvalid("manage case tags", "id must not be empty")
	}
	if !validTagActions[in.Action] {
		return nil, zero, wrapInvalid("manage case tags", fmt.Sprintf("invalid action %q (want 'add' or 'remove')", in.Action))
	}
	if len(in.Tags) == 0 {
		return nil, zero, wrapInvalid("manage case tags", "tags must not be empty")
	}
	m.Logger.Debug("manage_case_tags", "id", in.ID, "action", in.Action, "tags", len(in.Tags))

	if in.Action == "add" {
		params := cases.NewEntitiesCaseTagsPostV1ParamsWithContext(ctx)
		params.Body = &models.OperationsAddTagsToCaseRequest{ID: &in.ID, Tags: in.Tags}
		resp, err := m.Cases.EntitiesCaseTagsPostV1(params)
		if e := base.APIError(err, resp, scopeCasesWrite); e != nil {
			return nil, zero, e
		}
		return nil, base.Entities(resp.Payload.Resources).WithMeta(resp.Payload.Meta), nil
	}

	// remove
	params := cases.NewEntitiesCaseTagsDeleteV1ParamsWithContext(ctx)
	params.ID = in.ID
	params.Tag = in.Tags
	resp, err := m.Cases.EntitiesCaseTagsDeleteV1(params)
	if e := base.APIError(err, resp, scopeCasesWrite); e != nil {
		return nil, zero, e
	}
	return nil, base.Entities(resp.Payload.Resources).WithMeta(resp.Payload.Meta), nil
}

// wrapInvalid builds an errInvalidInput-wrapped error for op with detail.
func wrapInvalid(op, detail string) error {
	return fmt.Errorf("%s: %w: %s", op, errInvalidInput, detail)
}
