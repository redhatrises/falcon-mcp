package guardian

import (
	"context"
	"fmt"
	"time"

	"github.com/crowdstrike/gofalcon/falcon/client/aidr_events"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"golang.org/x/sync/errgroup"

	"github.com/crowdstrike/falcon-mcp/internal/modules/base"
)

// --- get_guardian_inventory ---

// GetInventoryInput is the input for falcon_get_guardian_inventory.
type GetInventoryInput struct {
	TimeRange string `json:"time_range,omitempty" jsonschema:"Lookback window for the rollups (e.g., '24h', '7d'). Filters LastSeen (Timestamp for detections). Default: '7d'"`
}

var getInventorySchema = guardianSchema[GetInventoryInput](schemaOpts{defaultTimeRange: inventoryDefaultLookback})

func (m *Module) getInventory(ctx context.Context, _ *mcp.CallToolRequest, in GetInventoryInput) (*mcp.CallToolResult, any, error) {
	return nil, m.inventoryData(ctx, firstNonEmpty(in.TimeRange, inventoryDefaultLookback)), nil
}

// inventoryData rolls up agent, session, tool, and detection aggregates into a
// fleet snapshot. Following the upstream module, a failed leg contributes an
// empty section rather than aborting the whole snapshot.
func (m *Module) inventoryData(ctx context.Context, timeRange string) map[string]any {
	var (
		agentMaps, sessionMaps, toolMaps, detectionMaps []map[string]any
		agentNote, sessionNote, toolNote, detectionNote []string
	)
	g, _ := errgroup.WithContext(ctx)
	g.Go(func() error {
		p := aidr_events.NewAggregateAgentsV1ParamsWithContext(ctx)
		call := func(t string) (aidrResp[*models.MsahandlerAggregateAgentsBucket], error) {
			p.TimeRange = &t
			ok, err := m.API.AggregateAgentsV1(p)
			r := aidrResp[*models.MsahandlerAggregateAgentsBucket]{raw: ok}
			if ok != nil && ok.Payload != nil {
				r.resources, r.meta = ok.Payload.Resources, ok.Payload.Meta
			}
			return r, err
		}
		agentMaps, agentNote, _ = queryLeg(m.Logger, queryOpts{op: "get_guardian_inventory:agents", timeRange: timeRange, isAggregate: true}, call)
		return nil
	})
	g.Go(func() error {
		p := aidr_events.NewAggregateAgentSessionsV1ParamsWithContext(ctx)
		call := func(t string) (aidrResp[*models.MsahandlerAggregateAgentSessionsBucket], error) {
			p.TimeRange = &t
			ok, err := m.API.AggregateAgentSessionsV1(p)
			r := aidrResp[*models.MsahandlerAggregateAgentSessionsBucket]{raw: ok}
			if ok != nil && ok.Payload != nil {
				r.resources, r.meta = ok.Payload.Resources, ok.Payload.Meta
			}
			return r, err
		}
		sessionMaps, sessionNote, _ = queryLeg(m.Logger, queryOpts{op: "get_guardian_inventory:sessions", timeRange: timeRange, isAggregate: true}, call)
		return nil
	})
	g.Go(func() error {
		p := aidr_events.NewAggregateToolsV1ParamsWithContext(ctx)
		p.Limit = optInt64(100)
		call := func(t string) (aidrResp[*models.MsahandlerAggregateToolsBucket], error) {
			p.TimeRange = &t
			ok, err := m.API.AggregateToolsV1(p)
			r := aidrResp[*models.MsahandlerAggregateToolsBucket]{raw: ok}
			if ok != nil && ok.Payload != nil {
				r.resources, r.meta = ok.Payload.Resources, ok.Payload.Meta
			}
			return r, err
		}
		toolMaps, toolNote, _ = queryLeg(m.Logger, queryOpts{op: "get_guardian_inventory:tools", timeRange: timeRange, isAggregate: true}, call)
		return nil
	})
	g.Go(func() error {
		p := aidr_events.NewAggregateDetectionsV1ParamsWithContext(ctx)
		call := func(t string) (aidrResp[*models.MsahandlerAggregateDetectionsBucket], error) {
			p.TimeRange = &t
			ok, err := m.API.AggregateDetectionsV1(p)
			r := aidrResp[*models.MsahandlerAggregateDetectionsBucket]{raw: ok}
			if ok != nil && ok.Payload != nil {
				r.resources, r.meta = ok.Payload.Resources, ok.Payload.Meta
			}
			return r, err
		}
		detectionMaps, detectionNote, _ = queryLeg(m.Logger, queryOpts{op: "get_guardian_inventory:detections", timeRange: timeRange, isAggregate: true}, call)
		return nil
	})
	_ = g.Wait()

	// Agent rollup by product: prefer the friendly AgentProductName, else the
	// numeric tag; counts may arrive as JSON strings, so each goes through asInt.
	agentsByProduct := map[string]int{}
	totalAgents := 0
	for _, r := range agentMaps {
		product := firstBucketKey(r, "AgentProductName", "AgentProduct")
		count := asInt(bucketCount(r))
		agentsByProduct[product] = count
		totalAgents += count
	}

	sessionsByProduct := map[string]int{}
	totalSessions := 0
	for _, r := range sessionMaps {
		product := firstBucketKey(r, "ProductName", "Product")
		count := asInt(bucketCount(r))
		sessionsByProduct[product] = count
		totalSessions += count
	}

	toolsByName := map[string]int{}
	for _, r := range toolMaps {
		name := stringVal(r, "Name")
		if name == "" {
			name = "unknown"
		}
		toolsByName[name] = asInt(bucketCount(r))
	}

	scoredHosts := map[string]struct{}{}
	maxScore := 0
	unattributedRows := 0
	for _, r := range detectionMaps {
		if host := stringVal(r, "AgentId"); host != "" {
			scoredHosts[host] = struct{}{}
		}
		if isUnattributedTag(r["AgenticProductTag"]) {
			unattributedRows++
		}
		if s := asInt(r["maxDetectionScore"]); s > maxScore {
			maxScore = s
		}
	}

	result := map[string]any{
		"agents": map[string]any{
			"total":      totalAgents,
			"by_product": agentsByProduct,
			"window":     timeRange,
		},
		"sessions": map[string]any{
			"by_product":         sessionsByProduct,
			"total":              totalSessions,
			"products_reporting": len(sessionsByProduct),
			"window":             timeRange,
			"truncated":          len(sessionMaps) >= aggregateGroupLimit,
			"note": "Keyed by product name (numeric tag ID for products the API cannot " +
				"resolve). This counts logical AIAgentSession rows per product; " +
				"agents.by_product counts agents, which is a different metric.",
		},
		"tools": map[string]any{
			"by_name": toolsByName,
		},
		"detections": map[string]any{
			"hosts_with_detections": len(scoredHosts),
			"max_score":             maxScore,
			"unattributed_rows":     unattributedRows,
			"truncated":             len(detectionMaps) >= aggregateGroupLimit,
			"window":                timeRange,
		},
	}

	notices := concatNotices(agentNote, sessionNote, toolNote, detectionNote)
	if len(notices) > 0 {
		result["notices"] = notices
	}
	return result
}

// --- agent_detail fan-out (backs generate_guardian_report) ---

// agentProfile verifies an agent, then gathers its host-scoped activity. Every
// leg is scoped by SensorId (aid): a host usually runs several AI agents, so the
// numbers cover all of them. Without an aid the event legs report that instead
// of running unfiltered.
func (m *Module) agentProfile(ctx context.Context, agentID string) (map[string]any, error) {
	if err := sanitizeGuardianValue(agentID); err != nil {
		return nil, err
	}
	agent, apiErr := m.fetchAgent(ctx, agentID)
	if apiErr != nil {
		return nil, apiErr
	}
	sensorID := agent.SensorID
	product := agent.AgentProduct

	if sensorID == "" {
		missing := map[string]any{"error": missingAidMessage}
		return map[string]any{
			"instance":            agent,
			"tools":               missing,
			"executions":          missing,
			"tool_usage":          missing,
			"skill_usage":         missing,
			"detections":          missing,
			"max_detection_score": missing,
		}, nil
	}

	var (
		toolsMaps, execMaps, toolUsageMaps, skillUsageMaps, detMaps, scoreMaps []map[string]any
		toolsN, execN, toolUsageN, skillUsageN, detN, scoreN                   []string
		toolsErr, execErr, toolUsageErr, skillUsageErr, detErr, scoreErr       *base.Error
	)
	g, _ := errgroup.WithContext(ctx)
	g.Go(func() error {
		p := aidr_events.NewQueryToolsV1ParamsWithContext(ctx)
		p.SensorID = &sensorID
		p.Limit = optInt64(100)
		call := func(t string) (aidrResp[*models.MsahandlerToolResource], error) {
			p.TimeRange = &t
			ok, e := m.API.QueryToolsV1(p)
			r := aidrResp[*models.MsahandlerToolResource]{raw: ok}
			if ok != nil && ok.Payload != nil {
				r.resources, r.meta = ok.Payload.Resources, ok.Payload.Meta
			}
			return r, e
		}
		toolsMaps, toolsN, toolsErr = queryLeg(m.Logger, queryOpts{op: "agent_profile:tools", timeRange: logscaleFanoutLookback, limit: 100}, call)
		return nil
	})
	g.Go(func() error {
		p := aidr_events.NewQueryExecutionsV1ParamsWithContext(ctx)
		p.Aid = &sensorID
		p.Limit = optInt64(100)
		call := func(t string) (aidrResp[*models.MsahandlerExecutionResource], error) {
			p.TimeRange = &t
			ok, e := m.API.QueryExecutionsV1(p)
			r := aidrResp[*models.MsahandlerExecutionResource]{raw: ok}
			if ok != nil && ok.Payload != nil {
				r.resources, r.meta = ok.Payload.Resources, ok.Payload.Meta
			}
			return r, e
		}
		execMaps, execN, execErr = queryLeg(m.Logger, queryOpts{op: "agent_profile:executions", timeRange: logscaleFanoutLookback, limit: 100}, call)
		return nil
	})
	g.Go(func() error {
		p := aidr_events.NewQueryToolUsageV1ParamsWithContext(ctx)
		p.Aid = &sensorID
		p.Limit = optInt64(100)
		call := func(t string) (aidrResp[*models.MsahandlerToolUsageResource], error) {
			p.TimeRange = &t
			ok, e := m.API.QueryToolUsageV1(p)
			r := aidrResp[*models.MsahandlerToolUsageResource]{raw: ok}
			if ok != nil && ok.Payload != nil {
				r.resources, r.meta = ok.Payload.Resources, ok.Payload.Meta
			}
			return r, e
		}
		toolUsageMaps, toolUsageN, toolUsageErr = queryLeg(m.Logger, queryOpts{op: "agent_profile:tool_usage", timeRange: logscaleFanoutLookback, limit: 100}, call)
		return nil
	})
	g.Go(func() error {
		p := aidr_events.NewQuerySkillUsageV1ParamsWithContext(ctx)
		p.Aid = &sensorID
		p.Limit = optInt64(100)
		call := func(t string) (aidrResp[*models.MsahandlerSkillUsageResource], error) {
			p.TimeRange = &t
			ok, e := m.API.QuerySkillUsageV1(p)
			r := aidrResp[*models.MsahandlerSkillUsageResource]{raw: ok}
			if ok != nil && ok.Payload != nil {
				r.resources, r.meta = ok.Payload.Resources, ok.Payload.Meta
			}
			return r, e
		}
		skillUsageMaps, skillUsageN, skillUsageErr = queryLeg(m.Logger, queryOpts{op: "agent_profile:skill_usage", timeRange: logscaleFanoutLookback, limit: 100}, call)
		return nil
	})
	g.Go(func() error {
		p := aidr_events.NewQueryDetectionsV1ParamsWithContext(ctx)
		p.AgentID = &sensorID
		p.Limit = optInt64(50)
		call := func(t string) (aidrResp[*models.MsahandlerDetectionResource], error) {
			p.TimeRange = &t
			ok, e := m.API.QueryDetectionsV1(p)
			r := aidrResp[*models.MsahandlerDetectionResource]{raw: ok}
			if ok != nil && ok.Payload != nil {
				r.resources, r.meta = ok.Payload.Resources, ok.Payload.Meta
			}
			return r, e
		}
		detMaps, detN, detErr = queryLeg(m.Logger, queryOpts{op: "agent_profile:detections", timeRange: detectionsDefaultLookback, limit: 50}, call)
		return nil
	})
	g.Go(func() error {
		p := aidr_events.NewAggregateDetectionsV1ParamsWithContext(ctx)
		p.AgentID = &sensorID
		call := func(t string) (aidrResp[*models.MsahandlerAggregateDetectionsBucket], error) {
			p.TimeRange = &t
			ok, e := m.API.AggregateDetectionsV1(p)
			r := aidrResp[*models.MsahandlerAggregateDetectionsBucket]{raw: ok}
			if ok != nil && ok.Payload != nil {
				r.resources, r.meta = ok.Payload.Resources, ok.Payload.Meta
			}
			return r, e
		}
		scoreMaps, scoreN, scoreErr = queryLeg(m.Logger, queryOpts{op: "agent_profile:detection_score", timeRange: detectionsDefaultLookback, isAggregate: true}, call)
		return nil
	})
	_ = g.Wait()

	return map[string]any{
		"instance":            agent,
		"tools":               subResult(toolsMaps, toolsN, toolsErr, 50),
		"executions":          subResult(execMaps, execN, execErr, 100),
		"tool_usage":          subResult(toolUsageMaps, toolUsageN, toolUsageErr, 100),
		"skill_usage":         subResult(skillUsageMaps, skillUsageN, skillUsageErr, 100),
		"detections":          subResult(detMaps, detN, detErr, 50),
		"max_detection_score": pickDetectionScore(scoreMaps, scoreN, scoreErr, sensorID, product),
	}, nil
}

// pickDetectionScore selects this agent's detection score from the aggregate,
// preferring an exact match on both AgentId (== SensorId) and AgenticProductTag
// (== Product). Most rows leave the tag unattributed, so those fall back to a
// host-scoped maximum. Returns a bare score, a host-scoped map, an error map, or
// nil when there is no row for this host.
func pickDetectionScore(maps []map[string]any, notices []string, apiErr *base.Error, sensorID string, product any) any {
	if apiErr != nil {
		out := map[string]any{"error": apiErr.Message}
		if len(notices) > 0 {
			out["notices"] = notices
		}
		return out
	}
	want := tagKey(product)
	var hostFallback *int
	for _, r := range maps {
		if stringVal(r, "AgentId") != sensorID {
			continue
		}
		tag := r["AgenticProductTag"]
		if want != "" && !isUnattributedTag(tag) && tagKey(tag) == want {
			return r["maxDetectionScore"]
		}
		if isUnattributedTag(tag) {
			if score := r["maxDetectionScore"]; score != nil {
				s := asInt(score)
				if hostFallback != nil {
					s = max(*hostFallback, s)
				}
				hostFallback = &s
			}
		}
	}
	if hostFallback != nil {
		return map[string]any{
			"host_max_score": *hostFallback,
			"scope":          "host",
			"note": "The detection carries no product tag, so it cannot be tied to one " +
				"agent. This is the highest score on this HOST and may belong to a " +
				"different AI agent running on it.",
		}
	}
	return nil
}

// --- generate_guardian_report ---

// GenerateReportInput is the input for falcon_generate_guardian_report.
type GenerateReportInput struct {
	ReportType    string `json:"report_type" jsonschema:"Report type: fleet_summary, agent_detail, skill_threat, or sensitive_access."`
	TimeRange     string `json:"time_range,omitempty" jsonschema:"Lookback window. Affects only fleet_summary and sensitive_access; agent_detail and skill_threat use their own per-leg windows and ignore this. Default: '7d'"`
	ProductFilter string `json:"product_filter,omitempty" jsonschema:"Optional product filter for fleet-level reports."`
	AgentID       string `json:"agent_id,omitempty" jsonschema:"Required for agent_detail report. The AIAgent Id."`
}

var generateReportSchema = withEnum(
	guardianSchema[GenerateReportInput](schemaOpts{defaultTimeRange: "7d"}),
	"report_type", "fleet_summary", "agent_detail", "skill_threat", "sensitive_access")

func (m *Module) generateReport(ctx context.Context, _ *mcp.CallToolRequest, in GenerateReportInput) (*mcp.CallToolResult, any, error) {
	tr := firstNonEmpty(in.TimeRange, "7d")
	generatedAt := time.Now().UTC().Format("2006-01-02T15:04:05Z")

	switch in.ReportType {
	case "fleet_summary":
		inventory := m.inventoryData(ctx, tr)
		skills, apiErr := m.fleetSkillInventory(ctx, GetFleetSkillInventoryInput{})
		if apiErr != nil {
			return nil, nil, apiErr
		}
		report := map[string]any{
			"report_type":  "fleet_summary",
			"generated_at": generatedAt,
			"time_range":   tr,
			"data":         map[string]any{"inventory": inventory, "skills": skills},
		}
		notices := noticesOf(inventory)
		if skills.Meta != nil {
			notices = append(notices, skills.Meta.Notices...)
		}
		if len(notices) > 0 {
			report["notices"] = notices
		}
		return nil, report, nil

	case "agent_detail":
		if in.AgentID == "" {
			return nil, nil, base.InvalidInput("generate_guardian_report", "agent_id is required for agent_detail report")
		}
		agent, err := m.agentProfile(ctx, in.AgentID)
		if err != nil {
			return nil, nil, err
		}
		return nil, map[string]any{
			"report_type":  "agent_detail",
			"generated_at": generatedAt,
			"data":         map[string]any{"agent": agent},
		}, nil

	case "skill_threat":
		skills, apiErr := m.fleetSkillInventory(ctx, GetFleetSkillInventoryInput{})
		if apiErr != nil {
			return nil, nil, apiErr
		}
		return nil, map[string]any{
			"report_type":  "skill_threat",
			"generated_at": generatedAt,
			"data":         map[string]any{"skills": skills},
		}, nil

	case "sensitive_access":
		return m.sensitiveAccessReport(ctx, tr, generatedAt)

	default:
		return nil, nil, base.InvalidInput("generate_guardian_report",
			fmt.Sprintf("invalid report_type %q; valid: fleet_summary, agent_detail, skill_threat, sensitive_access", in.ReportType))
	}
}

// sensitiveAccessReport drills into the most recent sessions and reports any
// sensitive file activity found in each.
func (m *Module) sensitiveAccessReport(ctx context.Context, tr, generatedAt string) (*mcp.CallToolResult, any, error) {
	sessions, apiErr := m.executionsList(ctx, SearchExecutionsInput{TimeRange: tr})
	if apiErr != nil {
		return nil, nil, apiErr
	}
	var notices []string
	if sessions.Meta != nil {
		notices = sessions.Meta.Notices
	}

	seen := map[string]struct{}{}
	var sids []string
	for _, r := range mapsOf(sessions.Resources) {
		sid := stringVal(r, "AgenticSessionId")
		if sid == "" {
			continue
		}
		if _, dup := seen[sid]; dup {
			continue
		}
		seen[sid] = struct{}{}
		sids = append(sids, sid)
		if len(sids) >= maxSensitiveSessions {
			break
		}
	}

	var sensitive []map[string]any
	for _, sid := range sids {
		events := m.fileEventsData(ctx, GetFileEventsInput{SessionID: sid, SensitiveOnly: true, TimeRange: tr})
		if nonEmptyMaps(events["module_writes"]) || nonEmptyMaps(events["tool_file_access"]) {
			sensitive = append(sensitive, map[string]any{"session_id": sid, "file_events": events})
		}
	}

	report := map[string]any{
		"report_type":  "sensitive_access",
		"generated_at": generatedAt,
		"time_range":   tr,
		"data":         map[string]any{"sensitive_sessions": sensitive},
	}
	if len(notices) > 0 {
		report["notices"] = notices
	}
	return nil, report, nil
}

// --- inventory bucket + notice helpers ---

// firstBucketKey returns the first non-empty bucket key among the given fields,
// falling back to the numeric tag via tagKey, then "unknown".
func firstBucketKey(r map[string]any, nameField, tagField string) string {
	if name := stringVal(r, nameField); name != "" {
		return name
	}
	if key := tagKey(r[tagField]); key != "" {
		return key
	}
	return "unknown"
}

// bucketCount reads an aggregate bucket count, accepting the "count" or "_count"
// spelling.
func bucketCount(r map[string]any) any {
	if v, ok := r["count"]; ok {
		return v
	}
	return r["_count"]
}

// concatNotices flattens several notice slices into one.
func concatNotices(groups ...[]string) []string {
	var out []string
	for _, g := range groups {
		out = append(out, g...)
	}
	return out
}

// noticesOf reads a "notices" string slice from a rollup map.
func noticesOf(m map[string]any) []string {
	raw, ok := m["notices"].([]string)
	if !ok {
		return nil
	}
	return append([]string{}, raw...)
}

// nonEmptyMaps reports whether v is a non-empty []map[string]any.
func nonEmptyMaps(v any) bool {
	s, ok := v.([]map[string]any)
	return ok && len(s) > 0
}
