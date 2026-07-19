package quarantine

import (
	"context"

	"github.com/crowdstrike/gofalcon/falcon/client/quarantine"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/crowdstrike/falcon-mcp/internal/modules/base"
)

// UpdateInput is the input for falcon_update_quarantined_files. Provide either
// IDs or Filter (not both). Action must be a reversible action (release or
// unrelease).
type UpdateInput struct {
	Action  string   `json:"action" jsonschema:"reversible action to apply: release or unrelease"`
	IDs     []string `json:"ids,omitempty" jsonschema:"quarantine file ID(s) to update; provide ids OR filter"`
	Filter  string   `json:"filter,omitempty" jsonschema:"FQL filter expression selecting records to update; provide ids OR filter. See falcon://quarantine/files/search/fql-guide for syntax."`
	Comment string   `json:"comment,omitempty" jsonschema:"optional audit comment describing why the action is being taken"`
}

func (m *Module) updateQuarantinedFiles(ctx context.Context, _ *mcp.CallToolRequest, in UpdateInput) (*mcp.CallToolResult, base.ActionResult, error) {
	action, err := normalizeRestoreAction(in.Action)
	if err != nil {
		return nil, base.ActionResult{}, err
	}
	if len(in.IDs) == 0 && in.Filter == "" {
		return nil, base.ActionResult{}, wrapInvalid("update quarantined files", "provide either ids or filter")
	}
	m.Logger.Debug("update_quarantined_files", "action", action, "ids", len(in.IDs), "filter", in.Filter)

	if len(in.IDs) > 0 {
		return m.applyActionByIDs(ctx, in.IDs, action, in.Comment)
	}
	return m.applyActionByQuery(ctx, action, in.Filter, in.Comment)
}

// DeleteInput is the input for falcon_delete_quarantined_files. Provide either
// IDs or Filter (not both).
type DeleteInput struct {
	IDs     []string `json:"ids,omitempty" jsonschema:"quarantine file ID(s) to delete; provide ids OR filter"`
	Filter  string   `json:"filter,omitempty" jsonschema:"FQL filter expression selecting records to delete; provide ids OR filter. See falcon://quarantine/files/search/fql-guide for syntax."`
	Comment string   `json:"comment,omitempty" jsonschema:"optional audit comment describing why the records are being deleted"`
}

func (m *Module) deleteQuarantinedFiles(ctx context.Context, _ *mcp.CallToolRequest, in DeleteInput) (*mcp.CallToolResult, base.ActionResult, error) {
	if len(in.IDs) == 0 && in.Filter == "" {
		return nil, base.ActionResult{}, wrapInvalid("delete quarantined files", "provide either ids or filter")
	}
	m.Logger.Debug("delete_quarantined_files", "ids", len(in.IDs), "filter", in.Filter)

	if len(in.IDs) > 0 {
		return m.applyActionByIDs(ctx, in.IDs, "delete", in.Comment)
	}
	return m.applyActionByQuery(ctx, "delete", in.Filter, in.Comment)
}

// applyActionByIDs applies a quarantine action to a specific set of record IDs.
func (m *Module) applyActionByIDs(ctx context.Context, ids []string, action, comment string) (*mcp.CallToolResult, base.ActionResult, error) {
	params := quarantine.NewUpdateQuarantinedDetectsByIdsParamsWithContext(ctx)
	params.Body = &models.DomainEntitiesPatchRequest{
		Ids:     ids,
		Action:  action,
		Comment: comment,
	}

	resp, err := m.API.UpdateQuarantinedDetectsByIds(params)
	if e := base.APIError(err, resp, scopeQuarantineWrite); e != nil {
		return nil, base.ActionResult{}, e
	}
	return nil, base.ActionResult{Ok: true}, nil
}

// applyActionByQuery applies a quarantine action to records selected by filter.
func (m *Module) applyActionByQuery(ctx context.Context, action, filter, comment string) (*mcp.CallToolResult, base.ActionResult, error) {
	params := quarantine.NewUpdateQfByQueryParamsWithContext(ctx)
	params.Body = &models.DomainQueriesPatchRequest{
		Action:  action,
		Filter:  filter,
		Comment: comment,
	}

	resp, err := m.API.UpdateQfByQuery(params)
	if e := base.APIError(err, resp, scopeQuarantineWrite); e != nil {
		return nil, base.ActionResult{}, e
	}
	return nil, base.ActionResult{Ok: true}, nil
}
