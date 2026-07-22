package quarantine

import (
	"context"
	"strings"

	"github.com/crowdstrike/gofalcon/falcon/client/quarantine"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/crowdstrike/falcon-mcp/internal/modules/base"
)

// UpdateInput is the input for falcon_update_quarantined_files. Provide either
// IDs or Filter (not both). Action must be a reversible action (release or
// unrelease). Prefer falcon_preview_quarantine_actions before filter-based
// updates to understand blast radius; preview is recommended, not enforced.
type UpdateInput struct {
	Action  string   `json:"action" jsonschema:"reversible action to apply: release or unrelease"`
	IDs     []string `json:"ids,omitempty" jsonschema:"quarantine file ID(s) to update; provide ids OR filter"`
	Filter  string   `json:"filter,omitempty" jsonschema:"specific FQL filter selecting records to update (not empty or bare *); provide ids OR filter. Prefer falcon_preview_quarantine_actions first. See falcon://quarantine/files/search/fql-guide."`
	Comment string   `json:"comment,omitempty" jsonschema:"optional audit comment describing why the action is being taken"`
}

func (m *Module) updateQuarantinedFiles(ctx context.Context, _ *mcp.CallToolRequest, in UpdateInput) (*mcp.CallToolResult, base.ActionResult, error) {
	action, err := normalizeRestoreAction(in.Action)
	if err != nil {
		return nil, base.ActionResult{}, err
	}
	if len(in.IDs) == 0 && strings.TrimSpace(in.Filter) == "" {
		return nil, base.ActionResult{}, wrapInvalid("update quarantined files", "provide either ids or filter")
	}
	m.Logger.Debug("update_quarantined_files", "action", action, "ids", len(in.IDs), "filter", in.Filter)

	if len(in.IDs) > 0 {
		return m.applyActionByIDs(ctx, in.IDs, action, in.Comment)
	}
	filter, err := validateMutationFilter("update quarantined files", in.Filter)
	if err != nil {
		return nil, base.ActionResult{}, err
	}
	return m.applyActionByQuery(ctx, action, filter, in.Comment)
}

// DeleteInput is the input for falcon_delete_quarantined_files. Provide either
// IDs or Filter (not both). Prefer falcon_preview_quarantine_actions before
// filter-based deletes; preview is recommended, not enforced.
type DeleteInput struct {
	IDs     []string `json:"ids,omitempty" jsonschema:"quarantine file ID(s) to delete; provide ids OR filter"`
	Filter  string   `json:"filter,omitempty" jsonschema:"specific FQL filter selecting records to delete (not empty or bare *); provide ids OR filter. Prefer falcon_preview_quarantine_actions first. See falcon://quarantine/files/search/fql-guide."`
	Comment string   `json:"comment,omitempty" jsonschema:"optional audit comment describing why the records are being deleted"`
}

func (m *Module) deleteQuarantinedFiles(ctx context.Context, _ *mcp.CallToolRequest, in DeleteInput) (*mcp.CallToolResult, base.ActionResult, error) {
	if len(in.IDs) == 0 && strings.TrimSpace(in.Filter) == "" {
		return nil, base.ActionResult{}, wrapInvalid("delete quarantined files", "provide either ids or filter")
	}
	m.Logger.Debug("delete_quarantined_files", "ids", len(in.IDs), "filter", in.Filter)

	if len(in.IDs) > 0 {
		return m.applyActionByIDs(ctx, in.IDs, "delete", in.Comment)
	}
	filter, err := validateMutationFilter("delete quarantined files", in.Filter)
	if err != nil {
		return nil, base.ActionResult{}, err
	}
	return m.applyActionByQuery(ctx, "delete", filter, in.Comment)
}

// validateMutationFilter rejects empty, whitespace-only, and bare-wildcard
// filters on filter-based quarantine mutations so mass actions require a
// specific FQL expression. Preview is still optional (agent-guided), not a hard
// gate — requiring it would be a larger product change.
func validateMutationFilter(op, filter string) (string, error) {
	f := strings.TrimSpace(filter)
	if f == "" {
		return "", wrapInvalid(op, "filter must not be empty; use a specific FQL expression or pass ids")
	}
	// Bare wildcards and empty quoted values match essentially everything.
	switch f {
	case "*", "''", `""`:
		return "", wrapInvalid(op, "filter is too broad; use a specific FQL expression (e.g. hostname:'HOST' or id:'...') or pass ids, and prefer falcon_preview_quarantine_actions first")
	}
	return f, nil
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
	return nil, base.ActionResult{Ok: true}.WithMeta(resp.Payload.Meta), nil
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
	return nil, base.ActionResult{Ok: true}.WithMeta(resp.Payload.Meta), nil
}
