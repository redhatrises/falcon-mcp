package guardian

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/crowdstrike/gofalcon/falcon/client/aidr_events"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"golang.org/x/sync/errgroup"

	"github.com/crowdstrike/falcon-mcp/internal/modules/base"
)

// missingAidMessage stands in for an event query that cannot be scoped to a
// single agent, returned instead of issuing an unfiltered query that would
// surface fleet-wide activity under an agent-scoped key.
const missingAidMessage = "Agent record has no SensorId; cannot scope event queries to this agent."

// maxSensitiveSessions caps how many recent sessions the sensitive_access report
// drills into.
const maxSensitiveSessions = 3

// queryLeg runs one route through the ladder for a fan-out and returns its
// resources as maps plus advisory notices. A failure is returned as *base.Error
// for the caller to record on that leg rather than aborting the whole fan-out.
func queryLeg[T any](l *slog.Logger, o queryOpts, call aidrCall[T]) ([]map[string]any, []string, *base.Error) {
	res, meta, apiErr := runQuery(l, o, call)
	if apiErr != nil {
		return nil, nil, apiErr
	}
	var notices []string
	if meta != nil {
		notices = meta.Notices
	}
	return mapsOf(res), notices, nil
}

// subResult formats one sub-query of a fan-out, preserving failures. Truncating
// resources directly would turn an API error into an empty list, hiding a failed
// query behind "no activity".
func subResult(maps []map[string]any, notices []string, apiErr *base.Error, limit int) any {
	if apiErr != nil {
		return map[string]any{"error": apiErr.Message}
	}
	if limit > 0 && len(maps) > limit {
		maps = maps[:limit]
	}
	if len(notices) > 0 {
		return map[string]any{"results": maps, "notices": notices}
	}
	return maps
}

// --- get_guardian_agent ---

// GetAgentInput is the input for falcon_get_guardian_agent.
type GetAgentInput struct {
	AgentID string `json:"agent_id" jsonschema:"The AIAgent Id (the opaque record token from a search result's Id field, e.g. 'ASCWQseSk3b76g...'), NOT the 32-hex SensorId and NOT the AgentIds[] content-hash value."`
}

func (m *Module) getAgent(ctx context.Context, _ *mcp.CallToolRequest, in GetAgentInput) (*mcp.CallToolResult, any, error) {
	if err := sanitizeGuardianValue(in.AgentID); err != nil {
		return nil, nil, err
	}
	agent, apiErr := m.fetchAgent(ctx, in.AgentID)
	if apiErr != nil {
		return nil, nil, apiErr
	}
	return nil, agent, nil
}

// fetchAgent resolves one AIAgent record by its Id, returning a not-found error
// when the entity store has no such agent.
func (m *Module) fetchAgent(ctx context.Context, agentID string) (*models.MsahandlerAgentResource, *base.Error) {
	params := aidr_events.NewEntitiesAgentsV1ParamsWithContext(ctx)
	params.Ids = []string{agentID}
	ok, err := m.API.EntitiesAgentsV1(params)
	if e := base.APIError(err, ok, scopeAIDRRead); e != nil {
		return nil, e
	}
	if ok == nil || ok.Payload == nil || len(ok.Payload.Resources) == 0 {
		return nil, &base.Error{Message: fmt.Sprintf("No agent found with agent_id: %s", agentID)}
	}
	return ok.Payload.Resources[0], nil
}

// --- get_guardian_session_detail ---

// GetSessionDetailInput is the input for falcon_get_guardian_session_detail.
type GetSessionDetailInput struct {
	SessionID       string `json:"session_id" jsonschema:"The AgenticSessionId (UUID) of the session to get details for."`
	IncludeActivity *bool  `json:"include_activity,omitempty" jsonschema:"If true (default), also fetches the graph activity (tools, skills, processes, models, MCP servers) for this session."`
}

var getSessionDetailSchema = base.SchemaFor[GetSessionDetailInput](func(s *jsonschema.Schema) {
	if p, ok := s.Properties["include_activity"]; ok {
		p.Default = []byte("true")
	}
})

func (m *Module) getSessionDetail(ctx context.Context, _ *mcp.CallToolRequest, in GetSessionDetailInput) (*mcp.CallToolResult, any, error) {
	if err := sanitizeGuardianValue(in.SessionID); err != nil {
		return nil, nil, err
	}
	includeActivity := in.IncludeActivity == nil || *in.IncludeActivity

	// The AgenticSessionId keys the executions entity directly; this is the
	// verification path.
	execParams := aidr_events.NewEntitiesExecutionsV1ParamsWithContext(ctx)
	execParams.ID = in.SessionID
	execOK, err := m.API.EntitiesExecutionsV1(execParams)
	if e := base.APIError(err, execOK, scopeAIDRRead); e != nil {
		return nil, nil, e
	}
	if execOK == nil || execOK.Payload == nil || len(execOK.Payload.Resources) == 0 {
		return nil, nil, &base.Error{Message: fmt.Sprintf("No session found with session_id: %s", in.SessionID)}
	}

	// Per-invocation tools and skills are session-scoped on the LogScale usage
	// endpoints; both state the window explicitly so an older session still returns.
	var (
		toolMaps, skillMaps []map[string]any
	)
	g, _ := errgroup.WithContext(ctx)
	g.Go(func() error {
		p := aidr_events.NewQueryToolUsageV1ParamsWithContext(ctx)
		p.SessionID = &in.SessionID
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
		toolMaps, _, _ = queryLeg(m.Logger, queryOpts{op: "get_guardian_session_detail:tools", timeRange: logscaleFanoutLookback, limit: 100}, call)
		return nil
	})
	g.Go(func() error {
		p := aidr_events.NewQuerySkillUsageV1ParamsWithContext(ctx)
		p.SessionID = &in.SessionID
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
		skillMaps, _, _ = queryLeg(m.Logger, queryOpts{op: "get_guardian_session_detail:skills", timeRange: logscaleFanoutLookback, limit: 100}, call)
		return nil
	})
	_ = g.Wait()

	result := map[string]any{
		"executions": execOK.Payload.Resources,
		"tools":      toolMaps,
		"skills":     skillMaps,
	}
	if includeActivity {
		result["activity"] = m.graphActivity(ctx, in.SessionID)
	}
	return nil, result, nil
}

// graphActivity fetches the session-activity graph for a single vertex ID,
// returning an error map when the vertex does not resolve.
func (m *Module) graphActivity(ctx context.Context, vertexID string) any {
	params := aidr_events.NewEntitiesSessionActivityV1ParamsWithContext(ctx)
	params.Ids = []string{vertexID}
	ok, err := m.API.EntitiesSessionActivityV1(params)
	if e := base.APIError(err, ok, scopeAIDRRead); e != nil {
		return map[string]any{"error": e.Message, "vertex_ids": []string{vertexID}}
	}
	if ok == nil || ok.Payload == nil || len(ok.Payload.Resources) == 0 {
		return map[string]any{"error": fmt.Sprintf("No session found for: %s", vertexID), "vertex_ids": []string{vertexID}}
	}
	return ok.Payload.Resources[0]
}

// --- get_guardian_session_activity ---

// GetSessionActivityInput is the input for falcon_get_guardian_session_activity.
type GetSessionActivityInput struct {
	SessionID string `json:"session_id" jsonschema:"Vertex ID (aisess:{aid}:{uuid}) or inventory AgenticSessionId (UUID). Comma-separated vertex IDs accepted."`
}

func (m *Module) getSessionActivity(ctx context.Context, _ *mcp.CallToolRequest, in GetSessionActivityInput) (*mcp.CallToolResult, any, error) {
	var ids []string
	for _, v := range strings.Split(in.SessionID, ",") {
		if v = strings.TrimSpace(v); v != "" {
			ids = append(ids, v)
		}
	}
	if len(ids) == 0 {
		return nil, nil, &base.Error{Message: fmt.Sprintf("No valid session IDs provided: %s", in.SessionID)}
	}
	params := aidr_events.NewEntitiesSessionActivityV1ParamsWithContext(ctx)
	params.Ids = ids
	ok, err := m.API.EntitiesSessionActivityV1(params)
	if e := base.APIError(err, ok, scopeAIDRRead); e != nil {
		return nil, nil, e
	}
	if ok == nil || ok.Payload == nil || len(ok.Payload.Resources) == 0 {
		return nil, nil, &base.Error{Message: fmt.Sprintf("No session(s) found for: %s", in.SessionID)}
	}
	if len(ids) == 1 {
		return nil, ok.Payload.Resources[0], nil
	}
	return nil, ok.Payload.Resources, nil
}

// --- get_guardian_process_tree ---

// GetProcessTreeInput is the input for falcon_get_guardian_process_tree.
type GetProcessTreeInput struct {
	SessionID string `json:"session_id" jsonschema:"AgenticSessionId (UUID) or vertex key (aisess:...)."`
	Depth     int    `json:"depth,omitempty" jsonschema:"Process tree depth (1=direct spawns, 2=grandchildren, 3=max)."`
}

var getProcessTreeSchema = base.SchemaFor[GetProcessTreeInput](func(s *jsonschema.Schema) {
	if p, ok := s.Properties["depth"]; ok {
		p.Minimum = jsonschema.Ptr(1.0)
		p.Maximum = jsonschema.Ptr(3.0)
		p.Default = []byte("2")
	}
})

func (m *Module) getProcessTree(ctx context.Context, _ *mcp.CallToolRequest, in GetProcessTreeInput) (*mcp.CallToolResult, any, error) {
	params := aidr_events.NewEntitiesProcessTreeV1ParamsWithContext(ctx)
	params.ID = in.SessionID
	params.Depth = optInt64(firstNonZero(in.Depth, 2))
	ok, err := m.API.EntitiesProcessTreeV1(params)
	if err != nil {
		return nil, nil, base.APIError(err, ok, scopeAIDRRead)
	}
	if ok == nil || ok.Payload == nil || len(ok.Payload.Resources) == 0 {
		// No vertex resolved. When the payload itself carried errors, surface
		// them rather than a generic not-found; only a clean empty payload
		// falls through to the not-found message.
		if e := base.APIError(nil, ok, scopeAIDRRead); e != nil {
			return nil, nil, e
		}
	}
	res, warnings := graphResult(ok, ok.Payload, in.SessionID)
	if warnings != nil {
		return nil, nil, warnings
	}
	return nil, res, nil
}

// --- get_guardian_network_events ---

// GetNetworkEventsInput is the input for falcon_get_guardian_network_events.
type GetNetworkEventsInput struct {
	SessionID string `json:"session_id" jsonschema:"AgenticSessionId (UUID) or vertex key (aisess:...)."`
}

func (m *Module) getNetworkEvents(ctx context.Context, _ *mcp.CallToolRequest, in GetNetworkEventsInput) (*mcp.CallToolResult, any, error) {
	params := aidr_events.NewEntitiesNetworkEventsV1ParamsWithContext(ctx)
	params.ID = in.SessionID
	ok, err := m.API.EntitiesNetworkEventsV1(params)
	if err != nil {
		return nil, nil, base.APIError(err, ok, scopeAIDRRead)
	}
	if ok == nil || ok.Payload == nil || len(ok.Payload.Resources) == 0 {
		// No vertex resolved. When the payload itself carried errors, surface
		// them rather than a generic not-found; only a clean empty payload
		// falls through to the not-found message.
		if e := base.APIError(nil, ok, scopeAIDRRead); e != nil {
			return nil, nil, e
		}
	}
	var payload *networkPayload
	if ok != nil && ok.Payload != nil {
		payload = &networkPayload{errors: ok.Payload.Errors, resources: ok.Payload.Resources}
	}
	res, warnings := graphResultN(payload, in.SessionID)
	if warnings != nil {
		return nil, nil, warnings
	}
	return nil, res, nil
}

// networkPayload adapts the network-events payload to the shared graph-result
// helper, which only needs the errors and the first resource vertex.
type networkPayload struct {
	errors    []*models.MsahandlerMSAError
	resources []*models.MsahandlerGraphSessionVertex
}

// --- get_guardian_classified_file_access ---

// GetClassifiedFileAccessInput is the input for falcon_get_guardian_classified_file_access.
type GetClassifiedFileAccessInput struct {
	ProcessID string `json:"process_id" jsonschema:"Process vertex ID (pid:{aid}:{upid}). Get from session activity or process tree results."`
}

func (m *Module) getClassifiedFileAccess(ctx context.Context, _ *mcp.CallToolRequest, in GetClassifiedFileAccessInput) (*mcp.CallToolResult, any, error) {
	params := aidr_events.NewEntitiesClassifiedFileAccessV1ParamsWithContext(ctx)
	params.ID = in.ProcessID
	ok, err := m.API.EntitiesClassifiedFileAccessV1(params)
	if e := base.APIError(err, ok, scopeAIDRRead); e != nil {
		return nil, nil, e
	}
	if ok == nil || ok.Payload == nil || len(ok.Payload.Resources) == 0 {
		return nil, nil, &base.Error{Message: fmt.Sprintf("No classified file access found for process: %s", in.ProcessID)}
	}
	return nil, ok.Payload.Resources[0], nil
}

// graphResult returns the first graph vertex (as a map so partial-result
// warnings can be attached) or a not-found error. It reproduces the process-tree
// handler's contract: a transport failure is fatal, but payload errors alongside
// a resolved vertex are attached as _warnings rather than failing the call.
func graphResult(ok *aidr_events.EntitiesProcessTreeV1OK, payload *models.MsahandlerProcessTreeResponse, id string) (map[string]any, *base.Error) {
	if ok == nil || payload == nil || len(payload.Resources) == 0 {
		return nil, &base.Error{Message: fmt.Sprintf("No session found for: %s", id)}
	}
	out := mapsOf(payload.Resources[:1])
	if len(out) == 0 {
		return nil, &base.Error{Message: fmt.Sprintf("No session found for: %s", id)}
	}
	first := out[0]
	if len(payload.Errors) > 0 {
		first["_warnings"] = mapsOf(payload.Errors)
	}
	return first, nil
}

// graphResultN is graphResult for the network-events payload shape.
func graphResultN(payload *networkPayload, id string) (map[string]any, *base.Error) {
	if payload == nil || len(payload.resources) == 0 {
		return nil, &base.Error{Message: fmt.Sprintf("No session found for: %s", id)}
	}
	out := mapsOf(payload.resources[:1])
	if len(out) == 0 {
		return nil, &base.Error{Message: fmt.Sprintf("No session found for: %s", id)}
	}
	first := out[0]
	if len(payload.errors) > 0 {
		first["_warnings"] = mapsOf(payload.errors)
	}
	return first, nil
}

// --- get_guardian_fleet_skill_inventory ---

// GetFleetSkillInventoryInput is the input for falcon_get_guardian_fleet_skill_inventory.
type GetFleetSkillInventoryInput struct {
	NameFilter string `json:"name_filter,omitempty" jsonschema:"Filter skills by name pattern (supports wildcards via 'like')."`
	TimeRange  string `json:"time_range,omitempty" jsonschema:"Lookback window (e.g., '24h', '7d'). Filters LastSeen. Sent to the API as requested; if refused, Guardian retries narrower and reports it in 'notices'. Default: '7d'"`
	Limit      int    `json:"limit,omitempty" jsonschema:"Maximum number of results to return. [1-500]"`
}

var getFleetSkillInventorySchema = guardianSchema[GetFleetSkillInventoryInput](schemaOpts{defaultLimit: 100, defaultTimeRange: "7d"})

func (m *Module) getFleetSkillInventory(ctx context.Context, _ *mcp.CallToolRequest, in GetFleetSkillInventoryInput) (*mcp.CallToolResult, base.SearchResult[*models.MsahandlerAggregateSkillsBucket], error) {
	out, apiErr := m.fleetSkillInventory(ctx, in)
	if apiErr != nil {
		return nil, base.SearchResult[*models.MsahandlerAggregateSkillsBucket]{}, apiErr
	}
	return nil, out, nil
}

func (m *Module) fleetSkillInventory(ctx context.Context, in GetFleetSkillInventoryInput) (base.SearchResult[*models.MsahandlerAggregateSkillsBucket], *base.Error) {
	limit := firstNonZero(in.Limit, 100)
	params := aidr_events.NewAggregateSkillsV1ParamsWithContext(ctx)
	params.NameFilter = optStr(in.NameFilter)
	call := func(t string) (aidrResp[*models.MsahandlerAggregateSkillsBucket], error) {
		params.TimeRange = &t
		ok, err := m.API.AggregateSkillsV1(params)
		r := aidrResp[*models.MsahandlerAggregateSkillsBucket]{raw: ok}
		if ok != nil && ok.Payload != nil {
			r.resources, r.meta = ok.Payload.Resources, ok.Payload.Meta
		}
		return r, err
	}
	res, meta, apiErr := runQuery(m.Logger, queryOpts{op: "get_guardian_fleet_skill_inventory", timeRange: firstNonEmpty(in.TimeRange, "7d"), limit: limit, isAggregate: true}, call)
	if apiErr != nil {
		return base.SearchResult[*models.MsahandlerAggregateSkillsBucket]{}, apiErr
	}
	return base.Found(res, "").WithMeta(meta), nil
}

// --- get_guardian_detection_scores ---

// GetDetectionScoresInput is the input for falcon_get_guardian_detection_scores.
type GetDetectionScoresInput struct {
	AgentID   string `json:"agent_id,omitempty" jsonschema:"Filter by AgentId. WARNING: A 32-hex SENSOR/host ID (AIAgent.SensorId / aid), NOT the 64-hex AIAgent.Id."`
	Product   string `json:"product,omitempty" jsonschema:"Filter by AI product name (e.g., 'Kiro', 'CLAUDE_CODE'). Human-readable names are auto-normalized."`
	TimeRange string `json:"time_range,omitempty" jsonschema:"Time range (e.g., '1h', '24h', '7d'). Sent to the API as requested; if refused, Guardian retries narrower and reports it in 'notices'. Default: '7d'"`
}

var getDetectionScoresSchema = guardianSchema[GetDetectionScoresInput](schemaOpts{defaultTimeRange: detectionsDefaultLookback})

func (m *Module) getDetectionScores(ctx context.Context, _ *mcp.CallToolRequest, in GetDetectionScoresInput) (*mcp.CallToolResult, base.SearchResult[*models.MsahandlerAggregateDetectionsBucket], error) {
	var zero base.SearchResult[*models.MsahandlerAggregateDetectionsBucket]
	if e := rejectAgentIDsToken(in.AgentID); e != nil {
		return nil, zero, e
	}
	product := in.Product
	if product != "" {
		product = normalizeProductName(product)
	}
	params := aidr_events.NewAggregateDetectionsV1ParamsWithContext(ctx)
	params.AgentID = optStr(in.AgentID)
	params.Product = optStr(product)
	call := func(t string) (aidrResp[*models.MsahandlerAggregateDetectionsBucket], error) {
		params.TimeRange = &t
		ok, err := m.API.AggregateDetectionsV1(params)
		r := aidrResp[*models.MsahandlerAggregateDetectionsBucket]{raw: ok}
		if ok != nil && ok.Payload != nil {
			r.resources, r.meta = ok.Payload.Resources, ok.Payload.Meta
		}
		return r, err
	}
	res, meta, apiErr := runQuery(m.Logger, queryOpts{op: "get_guardian_detection_scores", timeRange: firstNonEmpty(in.TimeRange, detectionsDefaultLookback), isAggregate: true}, call)
	if apiErr != nil {
		return nil, zero, apiErr
	}
	return nil, base.Found(res, "").WithMeta(meta), nil
}

// --- pivot_on_guardian_attribute ---

// PivotInput is the input for falcon_pivot_on_guardian_attribute.
type PivotInput struct {
	Attribute string `json:"attribute" jsonschema:"Attribute to pivot on: Product, HostName, Skill, or Name."`
	Value     string `json:"value" jsonschema:"Value to search for."`
	TimeRange string `json:"time_range,omitempty" jsonschema:"Lookback window (e.g., '1h', '24h', '7d'). Sent to the API as requested; if refused, Guardian retries narrower and reports it in 'notices'. Default: '7d'"`
	Limit     int    `json:"limit,omitempty" jsonschema:"Maximum number of results to return. [1-500]"`
}

var pivotSchema = withEnum(
	guardianSchema[PivotInput](schemaOpts{defaultLimit: 50, defaultTimeRange: "7d"}),
	"attribute", "Product", "HostName", "Skill", "Name")

func (m *Module) pivot(ctx context.Context, _ *mcp.CallToolRequest, in PivotInput) (*mcp.CallToolResult, base.SearchResult[map[string]any], error) {
	var zero base.SearchResult[map[string]any]
	limit := firstNonZero(in.Limit, 50)
	tr := firstNonEmpty(in.TimeRange, "7d")

	switch in.Attribute {
	case "Product", "HostName":
		params := aidr_events.NewQueryAgentsV1ParamsWithContext(ctx)
		if in.Attribute == "Product" {
			params.Product = optStr(normalizeProductName(in.Value))
		} else {
			params.Hostname = &in.Value
		}
		params.Limit = optInt64(limit)
		call := func(t string) (aidrResp[map[string]any], error) {
			params.TimeRange = &t
			ok, err := m.API.QueryAgentsV1(params)
			r := aidrResp[map[string]any]{raw: ok}
			if ok != nil && ok.Payload != nil {
				r.resources, r.meta = mapsOf(ok.Payload.Resources), ok.Payload.Meta
			}
			return r, err
		}
		return m.pivotResult(queryOpts{op: "pivot_on_guardian_attribute:agents", timeRange: tr, limit: limit}, call, zero)
	case "Skill":
		params := aidr_events.NewQuerySkillsV1ParamsWithContext(ctx)
		params.NameFilter = &in.Value
		params.Limit = optInt64(limit)
		call := func(t string) (aidrResp[map[string]any], error) {
			params.TimeRange = &t
			ok, err := m.API.QuerySkillsV1(params)
			r := aidrResp[map[string]any]{raw: ok}
			if ok != nil && ok.Payload != nil {
				r.resources, r.meta = mapsOf(ok.Payload.Resources), ok.Payload.Meta
			}
			return r, err
		}
		return m.pivotResult(queryOpts{op: "pivot_on_guardian_attribute:skills", timeRange: tr, limit: limit}, call, zero)
	case "Name":
		return m.pivotName(ctx, in.Value, tr, limit, zero)
	default:
		return nil, zero, base.InvalidInput("pivot_on_guardian_attribute",
			fmt.Sprintf("invalid attribute %q; allowed: Product, HostName, Skill, Name", in.Attribute))
	}
}

// pivotResult shapes a single-leg pivot branch into the shared search envelope.
func (m *Module) pivotResult(o queryOpts, call aidrCall[map[string]any], zero base.SearchResult[map[string]any]) (*mcp.CallToolResult, base.SearchResult[map[string]any], error) {
	res, meta, apiErr := runQuery(m.Logger, o, call)
	if apiErr != nil {
		return nil, zero, apiErr
	}
	return nil, base.Found(res, "").WithMeta(meta), nil
}

// pivotName merges per-invocation skill-usage and tool-usage, deduped by sensor
// (aid); rows without an aid are all kept.
func (m *Module) pivotName(ctx context.Context, value, tr string, limit int, zero base.SearchResult[map[string]any]) (*mcp.CallToolResult, base.SearchResult[map[string]any], error) {
	var (
		skillMaps, toolMaps       []map[string]any
		skillNotices, toolNotices []string
		skillErr, toolErr         *base.Error
	)
	g, _ := errgroup.WithContext(ctx)
	g.Go(func() error {
		p := aidr_events.NewQuerySkillUsageV1ParamsWithContext(ctx)
		p.Name = &value
		p.Limit = optInt64(limit)
		call := func(t string) (aidrResp[*models.MsahandlerSkillUsageResource], error) {
			p.TimeRange = &t
			ok, e := m.API.QuerySkillUsageV1(p)
			r := aidrResp[*models.MsahandlerSkillUsageResource]{raw: ok}
			if ok != nil && ok.Payload != nil {
				r.resources, r.meta = ok.Payload.Resources, ok.Payload.Meta
			}
			return r, e
		}
		skillMaps, skillNotices, skillErr = queryLeg(m.Logger, queryOpts{op: "pivot_on_guardian_attribute:skill_usage", timeRange: tr, limit: limit}, call)
		return nil
	})
	g.Go(func() error {
		p := aidr_events.NewQueryToolUsageV1ParamsWithContext(ctx)
		p.ToolName = &value
		p.Limit = optInt64(limit)
		call := func(t string) (aidrResp[*models.MsahandlerToolUsageResource], error) {
			p.TimeRange = &t
			ok, e := m.API.QueryToolUsageV1(p)
			r := aidrResp[*models.MsahandlerToolUsageResource]{raw: ok}
			if ok != nil && ok.Payload != nil {
				r.resources, r.meta = ok.Payload.Resources, ok.Payload.Meta
			}
			return r, e
		}
		toolMaps, toolNotices, toolErr = queryLeg(m.Logger, queryOpts{op: "pivot_on_guardian_attribute:tool_usage", timeRange: tr, limit: limit}, call)
		return nil
	})
	_ = g.Wait()
	if skillErr != nil {
		return nil, zero, skillErr
	}
	if toolErr != nil {
		return nil, zero, toolErr
	}

	seen := map[string]struct{}{}
	var results []map[string]any
	for _, r := range append(skillMaps, toolMaps...) {
		iid, _ := r["aid"].(string)
		if iid != "" {
			if _, dup := seen[iid]; dup {
				continue
			}
			seen[iid] = struct{}{}
		}
		results = append(results, r)
	}

	// Two merged legs have no single API pagination block, so synthesize one from
	// the merged count and blank an unusable full-page total, keeping every pivot
	// branch on the same envelope shape.
	returned := len(results)
	if limit > 0 && len(results) > limit {
		results = results[:limit]
	}
	offset := int64(0)
	pageLimit := int64(limit)
	pag := &base.Paging{Offset: &offset, Limit: &pageLimit}
	if limit <= 0 || returned < limit {
		total := int64(returned)
		pag.Total = &total
	}
	meta := attachNotices(&base.Meta{Pagination: pag}, concatNotices(skillNotices, toolNotices))
	return nil, base.Found(results, "").WithMeta(meta), nil
}

// --- get_guardian_file_events ---

// GetFileEventsInput is the input for falcon_get_guardian_file_events.
type GetFileEventsInput struct {
	SessionID     string `json:"session_id" jsonschema:"AgenticSessionId (UUID) or vertex key (aisess:...)."`
	SensitiveOnly bool   `json:"sensitive_only,omitempty" jsonschema:"Only show access to sensitive paths (.env, credentials, secrets, keys, tokens)."`
	TimeRange     string `json:"time_range,omitempty" jsonschema:"Lookback window for the tool-usage leg (raw events). Default: '2h'"`
	Limit         int    `json:"limit,omitempty" jsonschema:"Maximum number of results to return. [1-500]"`
}

var getFileEventsSchema = guardianSchema[GetFileEventsInput](schemaOpts{defaultLimit: 100, defaultTimeRange: logscaleToolDefault})

func (m *Module) getFileEvents(ctx context.Context, _ *mcp.CallToolRequest, in GetFileEventsInput) (*mcp.CallToolResult, any, error) {
	return nil, m.fileEventsData(ctx, in), nil
}

// fileEventsData gathers file activity from the graph layer (module writes) and
// the inventory tool-usage layer (file-tool access), optionally filtered to
// sensitive paths. A leg failure is not fatal: each contributes what it can.
func (m *Module) fileEventsData(ctx context.Context, in GetFileEventsInput) map[string]any {
	limit := firstNonZero(in.Limit, 100)
	tr := firstNonEmpty(in.TimeRange, logscaleToolDefault)
	inventorySessionID := extractSessionIDFromVertexKey(in.SessionID)

	var (
		graphVertices []*models.MsahandlerGraphSessionVertex
		invMaps       []map[string]any
	)
	g, _ := errgroup.WithContext(ctx)
	g.Go(func() error {
		p := aidr_events.NewEntitiesFileEventsV1ParamsWithContext(ctx)
		p.ID = in.SessionID
		ok, err := m.API.EntitiesFileEventsV1(p)
		if err == nil && ok != nil && ok.Payload != nil {
			graphVertices = ok.Payload.Resources
		}
		return nil
	})
	g.Go(func() error {
		p := aidr_events.NewQueryToolUsageV1ParamsWithContext(ctx)
		p.SessionID = optStr(inventorySessionID)
		p.Limit = optInt64(limit)
		call := func(t string) (aidrResp[*models.MsahandlerToolUsageResource], error) {
			p.TimeRange = &t
			ok, e := m.API.QueryToolUsageV1(p)
			r := aidrResp[*models.MsahandlerToolUsageResource]{raw: ok}
			if ok != nil && ok.Payload != nil {
				r.resources, r.meta = ok.Payload.Resources, ok.Payload.Meta
			}
			return r, e
		}
		invMaps, _, _ = queryLeg(m.Logger, queryOpts{op: "get_guardian_file_events:tool_usage", timeRange: tr, limit: limit}, call)
		return nil
	})
	_ = g.Wait()

	moduleWrites := collectModuleWrites(graphVertices)
	toolFileAccess := collectToolFileAccess(invMaps, limit)

	if in.SensitiveOnly {
		moduleWrites = filterSensitiveWrites(moduleWrites)
		toolFileAccess = filterSensitiveAccess(toolFileAccess)
	}

	return map[string]any{
		"module_writes":    capMaps(moduleWrites, limit),
		"tool_file_access": capMaps(toolFileAccess, limit),
	}
}

// sensitivePatterns are the path fragments that mark a file as sensitive.
var sensitivePatterns = []string{".env", "credential", "secret", ".key", ".pem", "token", "password"}

// fileToolNames are the AgenticToolName values that touch files.
var fileToolNames = map[string]struct{}{"Read": {}, "Write": {}, "Edit": {}, "Glob": {}, "Grep": {}}

// collectModuleWrites walks the graph vertices' session→process→module-written
// edges and flattens each into a write record. Edges come back null when the
// target vertex does not resolve, so each is checked before being read.
func collectModuleWrites(vertices []*models.MsahandlerGraphSessionVertex) []map[string]any {
	var writes []map[string]any
	if len(vertices) == 0 || vertices[0] == nil {
		return writes
	}
	for _, procEdge := range vertices[0].SessionProcessPid {
		if procEdge == nil || procEdge.Process == nil {
			continue
		}
		proc := procEdge.Process
		procName := base.Deref(proc.ImageFileName)
		if procName == "" {
			procName = base.Deref(proc.ID)
		}
		for _, modEdge := range proc.ModuleWrittenMod {
			if modEdge == nil {
				continue
			}
			var file, sha256 string
			if mod := modEdge.Module; mod != nil {
				if file = base.Deref(mod.TargetFileName); file == "" {
					file = base.Deref(mod.ImageFileName)
				}
				sha256 = base.Deref(mod.SHA256HashData)
			}
			writes = append(writes, map[string]any{
				"process":   procName,
				"file":      file,
				"sha256":    sha256,
				"timestamp": base.Deref(modEdge.EventCloudTime),
			})
		}
	}
	return writes
}

// collectToolFileAccess filters inventory tool-usage rows to the file tools and
// projects each to a tool/path/command_line record.
func collectToolFileAccess(rows []map[string]any, limit int) []map[string]any {
	var out []map[string]any
	if limit > 0 && len(rows) > limit {
		rows = rows[:limit]
	}
	for _, r := range rows {
		name, _ := r["AgenticToolName"].(string)
		if _, ok := fileToolNames[name]; !ok {
			continue
		}
		out = append(out, map[string]any{
			"tool":         name,
			"path":         stringVal(r, "AgenticPath"),
			"command_line": stringVal(r, "CommandLine"),
		})
	}
	return out
}

// filterSensitiveWrites keeps only module writes whose file path looks sensitive.
func filterSensitiveWrites(writes []map[string]any) []map[string]any {
	var out []map[string]any
	for _, w := range writes {
		if containsAny(strings.ToLower(stringVal(w, "file")), sensitivePatterns) {
			out = append(out, w)
		}
	}
	return out
}

// filterSensitiveAccess keeps only tool file-access rows whose path or command
// line looks sensitive.
func filterSensitiveAccess(access []map[string]any) []map[string]any {
	var out []map[string]any
	for _, a := range access {
		hay := strings.ToLower(stringVal(a, "path") + stringVal(a, "command_line"))
		if containsAny(hay, sensitivePatterns) {
			out = append(out, a)
		}
	}
	return out
}

// extractSessionIDFromVertexKey returns the inventory session UUID from a vertex
// key (aisess:{aid}:{uuid}) or the raw UUID unchanged.
func extractSessionIDFromVertexKey(sessionID string) string {
	if strings.HasPrefix(sessionID, "aisess:") {
		parts := strings.SplitN(sessionID, ":", 3)
		if len(parts) == 3 {
			return parts[2]
		}
	}
	return sessionID
}

// --- small helpers for the map-shaped inventory rows ---

func stringVal(m map[string]any, key string) string {
	if m == nil {
		return ""
	}
	s, _ := m[key].(string)
	return s
}

func containsAny(hay string, needles []string) bool {
	for _, n := range needles {
		if strings.Contains(hay, n) {
			return true
		}
	}
	return false
}

func capMaps(in []map[string]any, limit int) []map[string]any {
	if in == nil {
		return []map[string]any{}
	}
	if limit > 0 && len(in) > limit {
		return in[:limit]
	}
	return in
}
