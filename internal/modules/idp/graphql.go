package idp

import (
	"context"
	"fmt"

	"github.com/crowdstrike/gofalcon/falcon/client/identity_protection"
	"github.com/crowdstrike/gofalcon/falcon/models"

	"github.com/crowdstrike/falcon-mcp/internal/modules/base"
)

// investigationParams carries the per-run knobs shared across investigation
// types, mirroring the Python investigation_params dict.
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
// treated as a failure: this mirrors the Python module, whose GraphQL path
// returns the response body verbatim on 200 and whose _is_error check looks only
// for a top-level "error" key (never the GraphQL "errors" array). Returning the
// "data" object as-is also preserves GraphQL partial successes, where "data" and
// "errors" legitimately co-occur.
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
// a slice of objects, mirroring the Python data.get("entities", {}).get("nodes",
// []). A missing or malformed path yields an empty slice.
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

// runInvestigation dispatches to the handler for one investigation type,
// mirroring the Python _execute_single_investigation. An unknown type yields a
// map with an "error" key (as data), matching the Python warning path; only an
// API failure returns a *base.Error.
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
		m.Logger.Warn("Unknown investigation type", "type", investigationType)
		return map[string]any{"error": fmt.Sprintf("Unknown investigation type: %s", investigationType)}, nil
	}
}

// entityDetailsBatch fetches detailed entity information for all IDs in a single
// query, mirroring _get_entity_details_batch.
func (m *Module) entityDetailsBatch(ctx context.Context, entityIDs []string, p investigationParams) (any, *base.Error) {
	query := buildEntityDetailsQuery(entityIDs, true, p.includeAssociations, p.includeIncidents, p.includeAccounts)
	data, err := m.runGraphQL(ctx, query)
	if err != nil {
		return nil, err
	}
	entities := entityNodes(data)
	return map[string]any{"entities": entities, "entity_count": len(entities)}, nil
}

// timelinesBatch fetches a timeline per entity, mirroring
// _get_entity_timelines_batch (one query per entity).
func (m *Module) timelinesBatch(ctx context.Context, entityIDs []string, p investigationParams) (any, *base.Error) {
	timelines := make([]any, 0, len(entityIDs))
	for _, id := range entityIDs {
		query := buildTimelineQuery(id, p.timelineStartTime, p.timelineEndTime, p.timelineEventTypes, p.limit)
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

// relationshipsBatch analyzes relationships per entity, mirroring
// _analyze_relationships_batch (one query per entity).
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

// riskAssessmentBatch performs a risk assessment for all IDs in a single query,
// mirroring _assess_risks_batch.
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

// getOr returns m[key] when key is present, otherwise def. It mirrors Python's
// dict.get(key, default): an explicitly-present null value is preserved (returned
// as nil), and only an absent key yields the default. This matches
// _assess_risks_batch's entity.get("riskScore", 0) / .get("riskScoreSeverity",
// "LOW") fallbacks.
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
// null, matching the Python default of [].
func normalizeArray(in []any) []any {
	if in == nil {
		return []any{}
	}
	return in
}
