package shield

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/crowdstrike/gofalcon/falcon/client/saas_security"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/crowdstrike/falcon-mcp/internal/modules/base"
)

// errInvalidInput classifies a client input validation failure (empty required
// field, unparseable date). Wrapped with wrapInvalid so callers can branch.
var errInvalidInput = errors.New("shield: invalid input")

// wrapInvalid builds an errInvalidInput-wrapped error for op with detail.
func wrapInvalid(op, detail string) error {
	return fmt.Errorf("%s: %w: %s", op, errInvalidInput, detail)
}

const dismissShieldCheckDescription = "Dismiss a Falcon Shield (SaaS Security) posture check to suppress it from the failed checks list.\n\n" +
	"Use this only when a check is intentionally accepted as a known risk; omit entities to dismiss " +
	"the entire check for all entities, or provide specific entity names to dismiss only those. " +
	"This action is permanent and cannot be undone from the API — the dismissal reason is recorded in audit logs."

// DismissInput is the input for falcon_dismiss_shield_check.
type DismissInput struct {
	ID       string `json:"id" jsonschema:"Security check ID. Obtain from the id field in results returned by search_shield_checks."`
	Reason   string `json:"reason" jsonschema:"Required explanation for the dismissal. This is written to the audit log and visible to other administrators."`
	Entities string `json:"entities,omitempty" jsonschema:"Comma-separated entity names to dismiss. If omitted, dismisses the entire check for all entities. If provided, only the specified entities are dismissed and the check remains active for others."`
}

// dismissShieldCheck dismisses a posture check. When entities is provided it
// dismisses only those affected entities (DismissAffectedEntityV3); otherwise it
// dismisses the whole check (DismissSecurityCheckV3), mirroring the Python
// module's branch on the presence of the entities argument. Both endpoints
// return no entity records, so the tool returns an ActionResult.
func (m *Module) dismissShieldCheck(ctx context.Context, _ *mcp.CallToolRequest, in DismissInput) (*mcp.CallToolResult, base.ActionResult, error) {
	if in.ID == "" {
		return nil, base.ActionResult{}, wrapInvalid("dismiss shield check", "id must not be empty")
	}
	if in.Reason == "" {
		return nil, base.ActionResult{}, wrapInvalid("dismiss shield check", "reason must not be empty")
	}
	m.Logger.Debug("dismiss_shield_check", "id", in.ID, "scoped_entities", in.Entities != "")

	// Branch on the normalized entity list: if the caller supplied real entity
	// names, dismiss only those (DismissAffectedEntityV3); otherwise dismiss the
	// whole check (DismissSecurityCheckV3). Normalizing first means a blank or
	// comma-only entities value falls back to a whole-check dismiss rather than
	// posting an empty entity list.
	if entities := normalizeEntities(in.Entities); entities != "" {
		p := saas_security.NewDismissAffectedEntityV3ParamsWithContext(ctx)
		p.ID = in.ID
		p.Body = saas_security.DismissAffectedEntityV3Body{
			Reason:   in.Reason,
			Entities: entities,
		}
		resp, err := m.API.DismissAffectedEntityV3(p)
		if e := base.APIError(err, resp, scopeShieldWrite); e != nil {
			return nil, base.ActionResult{}, e
		}
		return nil, base.ActionResult{Ok: true}.WithMeta(resp.Payload.Meta), nil
	}

	p := saas_security.NewDismissSecurityCheckV3ParamsWithContext(ctx)
	p.ID = in.ID
	p.Body = saas_security.DismissSecurityCheckV3Body{Reason: in.Reason}
	resp, err := m.API.DismissSecurityCheckV3(p)
	if e := base.APIError(err, resp, scopeShieldWrite); e != nil {
		return nil, base.ActionResult{}, e
	}
	return nil, base.ActionResult{Ok: true}.WithMeta(resp.Payload.Meta), nil
}

// normalizeEntities trims whitespace around each comma-separated entity name and
// drops empties, mirroring the Python module's [e.strip() for e in split(",")].
// The gofalcon DismissAffectedEntityV3 body takes a single comma-separated
// string, so the cleaned names are re-joined.
func normalizeEntities(s string) string {
	parts := strings.Split(s, ",")
	cleaned := make([]string, 0, len(parts))
	for _, p := range parts {
		if t := strings.TrimSpace(p); t != "" {
			cleaned = append(cleaned, t)
		}
	}
	return strings.Join(cleaned, ",")
}
