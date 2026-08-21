package idp

import (
	"context"
	"fmt"

	"github.com/crowdstrike/gofalcon/falcon/client/identity_protection"
	"github.com/crowdstrike/gofalcon/falcon/models"

	"github.com/crowdstrike/falcon-mcp/internal/modules/base"
)

// investigationParams carries the per-run knobs shared across investigation
// types.
type investigationParams struct {
	includeAssociations bool
	includeAccounts     bool
	includeIncidents    bool
	timelineStartTime   string
	timelineEndTime     string
	timelineEventTypes  []string
	relationshipDepth   int
	limit               int
}

// runGraphQL executes a GraphQL query string against the Identity Protection
// endpoint and returns the decoded top-level "data" object. Only a transport/API
// failure (non-200, or an SDK error) is returned as a *base.Error, with scope
// hints on a 403.
//
// A GraphQL document that carries an "errors" array on an HTTP 200 is NOT
// treated as a failure: only a top-level "error" key counts as one. Returning
// the "data" object as-is also preserves GraphQL partial successes, where "data"
// and "errors" legitimately co-occur.
func (m *Module) runGraphQL(ctx context.Context, query string) (map[string]any, *base.Error) {
	params := identity_protection.NewAPIPreemptProxyPostGraphqlParamsWithContext(ctx)
	params.Body = &models.SwaggerGraphQLQuery{Query: &query}

	resp, err := m.API.APIPreemptProxyPostGraphql(params)
	if e := base.APIError(err, resp, scopeIdentityProtection); e != nil {
		return nil, e
	}

	if resp.Payload == nil {
		return map[string]any{}, nil
	}
	data, _ := resp.Payload.Data.(map[string]any)
	if data == nil {
		return map[string]any{}, nil
	}
	return data, nil
}

// entityNodes extracts data.entities.nodes from a decoded GraphQL data object as
// a slice of objects. A missing or malformed path yields an empty slice.
func entityNodes(data map[string]any) []map[string]any {
	entities, _ := data["entities"].(map[string]any)
	if entities == nil {
		return nil
	}
	nodes, _ := entities["nodes"].([]any)
	return toObjects(nodes)
}

// toObjects filters a JSON array to its object elements.
func toObjects(in []any) []map[string]any {
	out := make([]map[string]any, 0, len(in))
	for _, n := range in {
		if obj, ok := n.(map[string]any); ok {
			out = append(out, obj)
		}
	}
	return out
}

// runInvestigation dispatches to the handler for one investigation type. The
// type is validated upfront by validateInput, so the default arm is an
// unreachable invariant guard; it and an API failure are the only paths that
// return a *base.Error.
func (m *Module) runInvestigation(ctx context.Context, investigationType string, entityIDs []string, p investigationParams) (any, *base.Error) {
	switch investigationType {
	case investigationEntityDetails:
		return m.entityDetailsBatch(ctx, entityIDs, p)
	case investigationTimeline:
		return m.timelinesBatch(ctx, entityIDs, p)
	case investigationRelationships:
		return m.relationshipsBatch(ctx, entityIDs, p)
	case investigationRiskAssessment:
		return m.riskAssessmentBatch(ctx, entityIDs)
	default:
		m.Logger.Error("runInvestigation received an unvalidated investigation type", "type", investigationType)
		return nil, &base.Error{
			Message:    fmt.Sprintf("internal error: unhandled investigation type %q", investigationType),
			StatusCode: 500,
		}
	}
}

// entityDetailsBatch fetches detailed entity information for all IDs in a single
// query.
func (m *Module) entityDetailsBatch(ctx context.Context, entityIDs []string, p investigationParams) (any, *base.Error) {
	query := buildEntityDetailsQuery(entityIDs, true, p.includeAssociations, p.includeIncidents, p.includeAccounts)
	data, err := m.runGraphQL(ctx, query)
	if err != nil {
		return nil, err
	}
	entities := entityNodes(data)
	return map[string]any{"entities": entities, "entity_count": len(entities)}, nil
}

// timelinesBatch fetches a timeline per entity, one query per entity.
func (m *Module) timelinesBatch(ctx context.Context, entityIDs []string, p investigationParams) (any, *base.Error) {
	// Filter once for the whole batch: every query would otherwise reject the same
	// values, and a silently narrowed timeline (fewer events than the caller asked
	// for) carries no signal without this.
	categories, rejected := filterTimelineCategories(p.timelineEventTypes)
	if len(rejected) > 0 {
		m.Logger.Warn("Ignoring unrecognized timeline event types", "rejected", rejected)
	}

	timelines := make([]any, 0, len(entityIDs))
	for _, id := range entityIDs {
		query := buildTimelineQuery(id, p.timelineStartTime, p.timelineEndTime, categories, p.limit)
		data, err := m.runGraphQL(ctx, query)
		if err != nil {
			return nil, err
		}
		timeline, _ := data["timeline"].(map[string]any)
		nodes := []map[string]any{}
		pageInfo := map[string]any{}
		if timeline != nil {
			if raw, ok := timeline["nodes"].([]any); ok {
				nodes = toObjects(raw)
			}
			if pi, ok := timeline["pageInfo"].(map[string]any); ok {
				pageInfo = pi
			}
		}
		timelines = append(timelines, map[string]any{
			"entity_id": id,
			"timeline":  nodes,
			"page_info": pageInfo,
		})
	}
	return map[string]any{"timelines": timelines, "entity_count": len(entityIDs)}, nil
}

// relationshipsBatch analyzes relationships per entity, one query per entity.
func (m *Module) relationshipsBatch(ctx context.Context, entityIDs []string, p investigationParams) (any, *base.Error) {
	relationships := make([]any, 0, len(entityIDs))
	for _, id := range entityIDs {
		query := buildRelationshipQuery(id, p.relationshipDepth, true, p.limit)
		data, err := m.runGraphQL(ctx, query)
		if err != nil {
			return nil, err
		}
		entities := entityNodes(data)
		if len(entities) > 0 {
			associations, _ := entities[0]["associations"].([]any)
			relationships = append(relationships, map[string]any{
				"entity_id":          id,
				"associations":       normalizeArray(associations),
				"relationship_count": len(associations),
			})
		} else {
			relationships = append(relationships, map[string]any{
				"entity_id":          id,
				"associations":       []any{},
				"relationship_count": 0,
			})
		}
	}
	return map[string]any{"relationships": relationships, "entity_count": len(entityIDs)}, nil
}

// riskAssessmentBatch performs a risk assessment for all IDs in a single query.
func (m *Module) riskAssessmentBatch(ctx context.Context, entityIDs []string) (any, *base.Error) {
	query := buildRiskAssessmentQuery(entityIDs, true)
	data, err := m.runGraphQL(ctx, query)
	if err != nil {
		return nil, err
	}
	entities := entityNodes(data)
	assessments := make([]any, 0, len(entities))
	for _, e := range entities {
		assessments = append(assessments, map[string]any{
			"entityId":           e["entityId"],
			"primaryDisplayName": e["primaryDisplayName"],
			"riskScore":          getOr(e, "riskScore", 0),
			"riskScoreSeverity":  getOr(e, "riskScoreSeverity", "LOW"),
			"riskFactors":        normalizeArray(asArray(e["riskFactors"])),
		})
	}
	return map[string]any{"risk_assessments": assessments, "entity_count": len(assessments)}, nil
}

// getOr returns m[key] when key is present, otherwise def. An explicitly-present
// null value is preserved (returned as nil); only an absent key yields the
// default, which is what riskAssessmentBatch's riskScore / riskScoreSeverity
// fallbacks rely on.
func getOr(m map[string]any, key string, def any) any {
	if v, ok := m[key]; ok {
		return v
	}
	return def
}

// asArray coerces v to a JSON array, or nil when it is not one.
func asArray(v any) []any {
	arr, _ := v.([]any)
	return arr
}

// normalizeArray returns a non-nil slice so an absent array serializes as [] not
// null.
func normalizeArray(in []any) []any {
	if in == nil {
		return []any{}
	}
	return in
}
