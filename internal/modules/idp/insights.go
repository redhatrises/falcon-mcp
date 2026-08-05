package idp

// This file derives cross-investigation insights: correlations that only exist
// once two or more investigation types have run against the same entities.

// generateInsights derives cross-investigation insights from the per-type
// results. It returns nil when no insight applies, so the key is omitted from
// the response entirely rather than serialized as an empty object.
func generateInsights(results map[string]any, entityIDs []string) map[string]any {
	insights := map[string]any{}

	_, hasTimeline := results[investigationTimeline]
	_, hasRelationships := results[investigationRelationships]
	if hasTimeline && hasRelationships {
		insights["activity_relationship_correlation"] = analyzeActivityRelationships(
			asMap(results[investigationTimeline]),
			asMap(results[investigationRelationships]),
		)
	}

	if len(entityIDs) > 1 {
		insights["multi_entity_patterns"] = analyzeMultiEntityPatterns(results, entityIDs)
	}

	if len(insights) == 0 {
		return nil
	}
	return insights
}

// analyzeActivityRelationships counts timelines and relationships and returns
// the basic correlation structure.
func analyzeActivityRelationships(timelineAnalysis, relationshipAnalysis map[string]any) map[string]any {
	timelines := asArray(timelineAnalysis["timelines"])
	relationships := asArray(relationshipAnalysis["relationships"])
	return map[string]any{
		"related_entity_activities": []any{},
		"suspicious_patterns":       []any{},
		"timeline_count":            len(timelines),
		"relationship_count":        len(relationships),
	}
}

// analyzeMultiEntityPatterns tallies risk factor types across entities and
// surfaces those present in more than one entity as common_risk_factors, with
// the count and percentage.
func analyzeMultiEntityPatterns(results map[string]any, entityIDs []string) map[string]any {
	patterns := map[string]any{
		"common_risk_factors":    []any{},
		"shared_relationships":   []any{},
		"coordinated_activities": []any{},
	}

	risk := asMap(results[investigationRiskAssessment])
	if risk == nil {
		return patterns
	}

	assessments := asArray(risk["risk_assessments"])
	// Count occurrences of each risk factor type across assessments. Insertion
	// order is tracked separately because a Go map does not preserve it, and the
	// output order must be deterministic.
	counts := map[string]int{}
	var typeOrder []string
	for _, a := range assessments {
		am, ok := a.(map[string]any)
		if !ok {
			continue
		}
		for _, rf := range asArray(am["riskFactors"]) {
			rfm, ok := rf.(map[string]any)
			if !ok {
				continue
			}
			riskType, ok := rfm["type"].(string)
			if !ok {
				continue
			}
			if _, seen := counts[riskType]; !seen {
				typeOrder = append(typeOrder, riskType)
			}
			counts[riskType]++
		}
	}

	common := []any{}
	for _, riskType := range typeOrder {
		count := counts[riskType]
		if count > 1 {
			common = append(common, map[string]any{
				"risk_type":    riskType,
				"entity_count": count,
				"percentage":   roundTo1(float64(count) / float64(len(entityIDs)) * 100),
			})
		}
	}
	patterns["common_risk_factors"] = common
	return patterns
}

// asMap coerces v to a JSON object, or nil when it is not one.
func asMap(v any) map[string]any {
	m, _ := v.(map[string]any)
	return m
}

// roundTo1 rounds x to one decimal place, half away from zero.
func roundTo1(x float64) float64 {
	scaled := x * 10
	if scaled >= 0 {
		scaled = float64(int64(scaled + 0.5))
	} else {
		scaled = float64(int64(scaled - 0.5))
	}
	return scaled / 10
}
