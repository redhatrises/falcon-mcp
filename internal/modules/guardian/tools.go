package guardian

import (
	"context"
	"encoding/json"
	"strconv"

	"github.com/crowdstrike/gofalcon/falcon/client/aidr_events"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/crowdstrike/falcon-mcp/internal/modules/base"
)

// RegisterTools registers all Guardian tools into r, in the upstream order.
func (m *Module) RegisterTools(r base.Registrar) {
	base.AddTool(r, &mcp.Tool{Name: "search_guardian_agents", Description: searchAgentsDescription, InputSchema: searchAgentsSchema}, m.searchAgents)
	base.AddTool(r, &mcp.Tool{Name: "get_guardian_agent", Description: getAgentDescription}, m.getAgent)
	base.AddTool(r, &mcp.Tool{Name: "search_guardian_mcp_servers", Description: searchMCPServersDescription, InputSchema: searchMCPServersSchema}, m.searchMCPServers)
	base.AddTool(r, &mcp.Tool{Name: "get_guardian_agent_sessions", Description: getAgentSessionsDescription, InputSchema: getAgentSessionsSchema}, m.getAgentSessions)
	base.AddTool(r, &mcp.Tool{Name: "get_guardian_session_detail", Description: getSessionDetailDescription, InputSchema: getSessionDetailSchema}, m.getSessionDetail)
	base.AddTool(r, &mcp.Tool{Name: "get_guardian_session_activity", Description: getSessionActivityDescription}, m.getSessionActivity)
	base.AddTool(r, &mcp.Tool{Name: "search_guardian_tools", Description: searchToolsDescription, InputSchema: searchToolsSchema}, m.searchTools)
	base.AddTool(r, &mcp.Tool{Name: "search_guardian_tool_usage", Description: searchToolUsageDescription, InputSchema: searchToolUsageSchema}, m.searchToolUsage)
	base.AddTool(r, &mcp.Tool{Name: "search_guardian_executions", Description: searchExecutionsDescription, InputSchema: searchExecutionsSchema}, m.searchExecutions)
	base.AddTool(r, &mcp.Tool{Name: "search_guardian_prompts", Description: searchPromptsDescription, InputSchema: searchPromptsSchema}, m.searchPrompts)
	base.AddTool(r, &mcp.Tool{Name: "get_guardian_inventory", Description: getInventoryDescription, InputSchema: getInventorySchema}, m.getInventory)
	base.AddTool(r, &mcp.Tool{Name: "search_guardian_skills", Description: searchSkillsDescription, InputSchema: searchSkillsSchema}, m.searchSkills)
	base.AddTool(r, &mcp.Tool{Name: "search_guardian_skill_usage", Description: searchSkillUsageDescription, InputSchema: searchSkillUsageSchema}, m.searchSkillUsage)
	base.AddTool(r, &mcp.Tool{Name: "get_guardian_fleet_skill_inventory", Description: getFleetSkillInventoryDescription, InputSchema: getFleetSkillInventorySchema}, m.getFleetSkillInventory)
	base.AddTool(r, &mcp.Tool{Name: "search_guardian_os_users", Description: searchOSUsersDescription, InputSchema: searchOSUsersSchema}, m.searchOSUsers)
	base.AddTool(r, &mcp.Tool{Name: "pivot_on_guardian_attribute", Description: pivotDescription, InputSchema: pivotSchema}, m.pivot)
	base.AddTool(r, &mcp.Tool{Name: "get_guardian_process_tree", Description: getProcessTreeDescription, InputSchema: getProcessTreeSchema}, m.getProcessTree)
	base.AddTool(r, &mcp.Tool{Name: "get_guardian_network_events", Description: getNetworkEventsDescription}, m.getNetworkEvents)
	base.AddTool(r, &mcp.Tool{Name: "get_guardian_file_events", Description: getFileEventsDescription, InputSchema: getFileEventsSchema}, m.getFileEvents)
	base.AddTool(r, &mcp.Tool{Name: "get_guardian_classified_file_access", Description: getClassifiedFileAccessDescription}, m.getClassifiedFileAccess)
	base.AddTool(r, &mcp.Tool{Name: "generate_guardian_report", Description: generateReportDescription, InputSchema: generateReportSchema}, m.generateReport)
	base.AddTool(r, &mcp.Tool{Name: "search_guardian_detections", Description: searchDetectionsDescription, InputSchema: searchDetectionsSchema}, m.searchDetections)
	base.AddTool(r, &mcp.Tool{Name: "get_guardian_detection_scores", Description: getDetectionScoresDescription, InputSchema: getDetectionScoresSchema}, m.getDetectionScores)
	base.AddTool(r, &mcp.Tool{Name: "search_guardian_installs", Description: searchInstallsDescription, InputSchema: searchInstallsSchema}, m.searchInstalls)
	base.AddTool(r, &mcp.Tool{Name: "search_guardian_models", Description: searchModelsDescription, InputSchema: searchModelsSchema}, m.searchModels)
}

// schemaOpts carries the numeric bounds and defaults a Guardian input schema
// needs beyond the struct-tag descriptions.
type schemaOpts struct {
	defaultLimit     int    // limit default; 0 = tool has no limit param
	defaultTimeRange string // time_range default; "" = tool has no time_range param
}

// guardianSchema builds an input schema from In's struct tags, then applies the
// limit range [1,500], the offset floor 0, and the limit/time_range defaults the
// jsonschema struct-tag syntax cannot express.
func guardianSchema[In any](o schemaOpts) *jsonschema.Schema {
	return base.SchemaFor[In](func(s *jsonschema.Schema) {
		if p, ok := s.Properties["limit"]; ok {
			p.Minimum = jsonschema.Ptr(1.0)
			p.Maximum = jsonschema.Ptr(500.0)
			if o.defaultLimit > 0 {
				p.Default = json.RawMessage(strconv.Itoa(o.defaultLimit))
			}
		}
		if p, ok := s.Properties["offset"]; ok {
			p.Minimum = jsonschema.Ptr(0.0)
		}
		if p, ok := s.Properties["time_range"]; ok && o.defaultTimeRange != "" {
			p.Default = json.RawMessage(strconv.Quote(o.defaultTimeRange))
		}
	})
}

// withEnum constrains the named string property to a fixed set of values, so a
// client discovers the allowed inputs from the schema instead of only the prose
// description. The handler still validates at runtime for the dynamic-catalog
// and direct-call paths that do not run schema validation.
func withEnum(s *jsonschema.Schema, field string, values ...string) *jsonschema.Schema {
	if p, ok := s.Properties[field]; ok {
		enum := make([]any, len(values))
		for i, v := range values {
			enum[i] = v
		}
		p.Enum = enum
	}
	return s
}

// firstNonEmpty returns v when non-empty, else def. Used to apply a parameter
// default in the handler, since the schema default is advisory.
func firstNonEmpty(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

// firstNonZero returns v when non-zero, else def.
func firstNonZero(v, def int) int {
	if v == 0 {
		return def
	}
	return v
}

// searchList runs a single-call query route and returns the standard search
// envelope. It centralizes the runQuery + base.Found + WithMeta wiring the plain
// list tools share.
func searchList[T any](m *Module, o queryOpts, call aidrCall[T]) (base.SearchResult[T], *base.Error) {
	res, meta, apiErr := runQuery(m.Logger, o, call)
	if apiErr != nil {
		return base.SearchResult[T]{}, apiErr
	}
	return base.Found(res, "").WithMeta(meta), nil
}

// --- search_guardian_agents ---

// SearchAgentsInput is the input for falcon_search_guardian_agents.
type SearchAgentsInput struct {
	Product   string `json:"product,omitempty" jsonschema:"Filter by AI product name (e.g., 'CLAUDE_CODE', 'CURSOR'). Human-readable names are auto-normalized."`
	Hostname  string `json:"hostname,omitempty" jsonschema:"Filter by hostname of the device running the agent."`
	TimeRange string `json:"time_range,omitempty" jsonschema:"Lookback window (e.g., '1h', '24h', '7d', '30d'). Filters LastSeen. Sent to the API as requested; if refused, Guardian retries narrower and reports it in 'notices'. Default: '7d'"`
	Limit     int    `json:"limit,omitempty" jsonschema:"Maximum number of results to return. [1-500]"`
	Offset    int    `json:"offset,omitempty" jsonschema:"Index of the first record to return, for paging. Pair with limit; read pagination in the response to page. The API refuses an offset above 1000 — narrow time_range instead of paging deeper."`
}

var searchAgentsSchema = guardianSchema[SearchAgentsInput](schemaOpts{defaultLimit: 50, defaultTimeRange: "7d"})

func (m *Module) searchAgents(ctx context.Context, _ *mcp.CallToolRequest, in SearchAgentsInput) (*mcp.CallToolResult, base.SearchResult[*models.MsahandlerAgentResource], error) {
	var zero base.SearchResult[*models.MsahandlerAgentResource]
	limit := firstNonZero(in.Limit, 50)
	product := in.Product
	if product != "" {
		product = normalizeProductName(product)
	}
	params := aidr_events.NewQueryAgentsV1ParamsWithContext(ctx)
	params.Product = optStr(product)
	params.Hostname = optStr(in.Hostname)
	params.Limit = optInt64(limit)
	params.Offset = optInt64(in.Offset)
	call := func(t string) (aidrResp[*models.MsahandlerAgentResource], error) {
		params.TimeRange = &t
		ok, err := m.API.QueryAgentsV1(params)
		r := aidrResp[*models.MsahandlerAgentResource]{raw: ok}
		if ok != nil && ok.Payload != nil {
			r.resources, r.meta = ok.Payload.Resources, ok.Payload.Meta
		}
		return r, err
	}
	out, apiErr := searchList(m, queryOpts{op: "search_guardian_agents", timeRange: firstNonEmpty(in.TimeRange, "7d"), limit: limit}, call)
	if apiErr != nil {
		return nil, zero, apiErr
	}
	return nil, out, nil
}

// --- search_guardian_mcp_servers ---

// SearchMCPServersInput is the input for falcon_search_guardian_mcp_servers.
type SearchMCPServersInput struct {
	TimeRange string `json:"time_range,omitempty" jsonschema:"Time range (e.g., '24h', '7d'). Filters LastSeen. Sent to the API as requested; if refused, Guardian retries narrower and reports it in 'notices'. Default: '7d'"`
	Limit     int    `json:"limit,omitempty" jsonschema:"Maximum number of results to return. [1-500]"`
	Offset    int    `json:"offset,omitempty" jsonschema:"Index of the first record to return, for paging. Pair with limit; read pagination in the response to page. The API refuses an offset above 1000 — narrow time_range instead of paging deeper."`
}

var searchMCPServersSchema = guardianSchema[SearchMCPServersInput](schemaOpts{defaultLimit: 100, defaultTimeRange: "7d"})

func (m *Module) searchMCPServers(ctx context.Context, _ *mcp.CallToolRequest, in SearchMCPServersInput) (*mcp.CallToolResult, base.SearchResult[*models.MsahandlerMCPServerResource], error) {
	var zero base.SearchResult[*models.MsahandlerMCPServerResource]
	limit := firstNonZero(in.Limit, 100)
	params := aidr_events.NewQueryMcpServerNamesV1ParamsWithContext(ctx)
	params.Limit = optInt64(limit)
	params.Offset = optInt64(in.Offset)
	call := func(t string) (aidrResp[*models.MsahandlerMCPServerResource], error) {
		params.TimeRange = &t
		ok, err := m.API.QueryMcpServerNamesV1(params)
		r := aidrResp[*models.MsahandlerMCPServerResource]{raw: ok}
		if ok != nil && ok.Payload != nil {
			r.resources, r.meta = ok.Payload.Resources, ok.Payload.Meta
		}
		return r, err
	}
	out, apiErr := searchList(m, queryOpts{op: "search_guardian_mcp_servers", timeRange: firstNonEmpty(in.TimeRange, "7d"), limit: limit}, call)
	if apiErr != nil {
		return nil, zero, apiErr
	}
	return nil, out, nil
}

// --- get_guardian_agent_sessions ---

// GetAgentSessionsInput is the input for falcon_get_guardian_agent_sessions.
type GetAgentSessionsInput struct {
	Product   string `json:"product,omitempty" jsonschema:"Filter by AI product name (e.g., 'CLAUDE_CODE', 'CURSOR'). Human-readable names are auto-normalized."`
	TimeRange string `json:"time_range,omitempty" jsonschema:"Time range (e.g., '24h', '7d'). Filters LastSeen. Sent to the API as requested; if refused, Guardian retries narrower and reports it in 'notices'. Default: '7d'"`
	Limit     int    `json:"limit,omitempty" jsonschema:"Maximum number of results to return. [1-500]"`
	Offset    int    `json:"offset,omitempty" jsonschema:"Index of the first record to return, for paging. Pair with limit; read pagination in the response to page. The API refuses an offset above 1000 — narrow time_range instead of paging deeper."`
}

var getAgentSessionsSchema = guardianSchema[GetAgentSessionsInput](schemaOpts{defaultLimit: 50, defaultTimeRange: "7d"})

// AgentSessionsResult is the output for falcon_get_guardian_agent_sessions. Note
// is declared first so it serializes as the first JSON key: when a caller raises
// limit to count rows, the envelope can exceed the client's tool-output budget
// and spill to a file of which only a short preview reaches the model, and the
// note has to land inside that preview to be read.
type AgentSessionsResult struct {
	Note      string                                   `json:"note"`
	Resources []*models.MsahandlerAgentSessionResource `json:"resources"`
	Meta      *base.Meta                               `json:"meta,omitempty"`
}

func (m *Module) getAgentSessions(ctx context.Context, _ *mcp.CallToolRequest, in GetAgentSessionsInput) (*mcp.CallToolResult, AgentSessionsResult, error) {
	var zero AgentSessionsResult
	limit := firstNonZero(in.Limit, 50)
	product := in.Product
	if product != "" {
		product = normalizeProductName(product)
	}
	params := aidr_events.NewQueryAgentSessionsV1ParamsWithContext(ctx)
	params.Product = optStr(product)
	params.Limit = optInt64(limit)
	params.Offset = optInt64(in.Offset)
	call := func(t string) (aidrResp[*models.MsahandlerAgentSessionResource], error) {
		params.TimeRange = &t
		ok, err := m.API.QueryAgentSessionsV1(params)
		r := aidrResp[*models.MsahandlerAgentSessionResource]{raw: ok}
		if ok != nil && ok.Payload != nil {
			r.resources, r.meta = ok.Payload.Resources, ok.Payload.Meta
		}
		return r, err
	}
	res, meta, apiErr := runQuery(m.Logger, queryOpts{op: "get_guardian_agent_sessions", timeRange: firstNonEmpty(in.TimeRange, "7d"), limit: limit}, call)
	if apiErr != nil {
		return nil, zero, apiErr
	}
	if res == nil {
		res = []*models.MsahandlerAgentSessionResource{}
	}
	return nil, AgentSessionsResult{Note: agentSessionsHint, Resources: res, Meta: meta}, nil
}

// --- search_guardian_tools ---

// SearchToolsInput is the input for falcon_search_guardian_tools.
type SearchToolsInput struct {
	SensorID  string `json:"sensor_id,omitempty" jsonschema:"Filter by the tool's own host sensor ID (32-hex aid / AIAgent.SensorId). This identifies a host, so it returns the tools of every agent on that host rather than one agent's. The store is thinly populated, so an agent's SensorId often matches nothing; search_guardian_tool_usage(aid=...) covers the same host from the event side."`
	TimeRange string `json:"time_range,omitempty" jsonschema:"Time range (e.g., '24h', '7d'). Filters LastSeen. Sent to the API as requested; if refused, Guardian retries narrower and reports it in 'notices'. Default: '7d'"`
	Limit     int    `json:"limit,omitempty" jsonschema:"Maximum number of results to return. [1-500]"`
	Offset    int    `json:"offset,omitempty" jsonschema:"Index of the first record to return, for paging. Pair with limit; read pagination in the response to page. The API refuses an offset above 1000 — narrow time_range instead of paging deeper."`
}

var searchToolsSchema = guardianSchema[SearchToolsInput](schemaOpts{defaultLimit: 100, defaultTimeRange: "7d"})

func (m *Module) searchTools(ctx context.Context, _ *mcp.CallToolRequest, in SearchToolsInput) (*mcp.CallToolResult, base.SearchResult[*models.MsahandlerToolResource], error) {
	var zero base.SearchResult[*models.MsahandlerToolResource]
	limit := firstNonZero(in.Limit, 100)
	params := aidr_events.NewQueryToolsV1ParamsWithContext(ctx)
	params.SensorID = optStr(in.SensorID)
	params.Limit = optInt64(limit)
	params.Offset = optInt64(in.Offset)
	call := func(t string) (aidrResp[*models.MsahandlerToolResource], error) {
		params.TimeRange = &t
		ok, err := m.API.QueryToolsV1(params)
		r := aidrResp[*models.MsahandlerToolResource]{raw: ok}
		if ok != nil && ok.Payload != nil {
			r.resources, r.meta = ok.Payload.Resources, ok.Payload.Meta
		}
		return r, err
	}
	out, apiErr := searchList(m, queryOpts{op: "search_guardian_tools", timeRange: firstNonEmpty(in.TimeRange, "7d"), limit: limit}, call)
	if apiErr != nil {
		return nil, zero, apiErr
	}
	return nil, out, nil
}

// --- search_guardian_tool_usage ---

// SearchToolUsageInput is the input for falcon_search_guardian_tool_usage.
type SearchToolUsageInput struct {
	ToolName  string `json:"tool_name,omitempty" jsonschema:"Filter by tool name. Exact and case-sensitive, not a substring or a wildcard. Use the spelling the event store uses ('Bash', 'Read', 'Edit', 'Grep', or lowercase names such as 'apply_diff'), because the inventory can differ: search_guardian_tools and get_guardian_inventory's tools.by_name list 'bash' where these events carry 'Bash'. A mismatched case returns zero rows rather than an error, so an empty result does not prove the tool was never used — try the other capitalization before reporting a zero."`
	Aid       string `json:"aid,omitempty" jsonschema:"Filter by sensor ID (aid) — identifies a HOST, not a single agent."`
	SessionID string `json:"session_id,omitempty" jsonschema:"Filter by AgenticSessionId."`
	TimeRange string `json:"time_range,omitempty" jsonschema:"Time range (e.g., '2h', '24h', '7d'). Defaults to '2h', matching the API — widen it explicitly to look further back, up to a 7-day maximum (this route scans raw events; a wider window is refused and narrowed back to 7d). Sent to the API as requested; if refused, Guardian retries narrower and reports it in 'notices'. Default: '2h'"`
	Limit     int    `json:"limit,omitempty" jsonschema:"Maximum number of results to return. [1-500]"`
	Offset    int    `json:"offset,omitempty" jsonschema:"Index of the first record to return, for paging. Pair with limit; read pagination in the response to page. The API refuses an offset above 1000 — narrow time_range instead of paging deeper."`
}

var searchToolUsageSchema = guardianSchema[SearchToolUsageInput](schemaOpts{defaultLimit: 100, defaultTimeRange: logscaleToolDefault})

func (m *Module) searchToolUsage(ctx context.Context, _ *mcp.CallToolRequest, in SearchToolUsageInput) (*mcp.CallToolResult, base.SearchResult[*models.MsahandlerToolUsageResource], error) {
	var zero base.SearchResult[*models.MsahandlerToolUsageResource]
	limit := firstNonZero(in.Limit, 100)
	params := aidr_events.NewQueryToolUsageV1ParamsWithContext(ctx)
	params.ToolName = optStr(in.ToolName)
	params.Aid = optStr(in.Aid)
	params.SessionID = optStr(in.SessionID)
	params.Limit = optInt64(limit)
	params.Offset = optInt64(in.Offset)
	call := func(t string) (aidrResp[*models.MsahandlerToolUsageResource], error) {
		params.TimeRange = &t
		ok, err := m.API.QueryToolUsageV1(params)
		r := aidrResp[*models.MsahandlerToolUsageResource]{raw: ok}
		if ok != nil && ok.Payload != nil {
			r.resources, r.meta = ok.Payload.Resources, ok.Payload.Meta
		}
		return r, err
	}
	out, apiErr := searchList(m, queryOpts{op: "search_guardian_tool_usage", timeRange: firstNonEmpty(in.TimeRange, logscaleToolDefault), limit: limit}, call)
	if apiErr != nil {
		return nil, zero, apiErr
	}
	return nil, out, nil
}

// --- search_guardian_executions ---

// SearchExecutionsInput is the input for falcon_search_guardian_executions.
type SearchExecutionsInput struct {
	SessionID string `json:"session_id,omitempty" jsonschema:"Filter by AgenticSessionId (UUID)."`
	Aid       string `json:"aid,omitempty" jsonschema:"Filter by sensor ID (aid). Identifies a HOST, not a single agent."`
	TimeRange string `json:"time_range,omitempty" jsonschema:"Time range (e.g., '2h', '24h', '7d'). Defaults to '2h', matching the API — widen it explicitly to look further back, up to a 7-day maximum (this route scans raw events; a wider window is refused and narrowed back to 7d). Sent to the API as requested; if refused, Guardian retries narrower and reports it in 'notices'. Default: '2h'"`
	Limit     int    `json:"limit,omitempty" jsonschema:"Maximum number of results to return. [1-500]"`
	Offset    int    `json:"offset,omitempty" jsonschema:"Index of the first record to return, for paging. Pair with limit; read pagination in the response to page. The API refuses an offset above 1000 — narrow time_range instead of paging deeper."`
}

var searchExecutionsSchema = guardianSchema[SearchExecutionsInput](schemaOpts{defaultLimit: 100, defaultTimeRange: logscaleToolDefault})

func (m *Module) searchExecutions(ctx context.Context, _ *mcp.CallToolRequest, in SearchExecutionsInput) (*mcp.CallToolResult, base.SearchResult[*models.MsahandlerExecutionResource], error) {
	var zero base.SearchResult[*models.MsahandlerExecutionResource]
	res, apiErr := m.executionsList(ctx, in)
	if apiErr != nil {
		return nil, zero, apiErr
	}
	return nil, res, nil
}

// executionsList runs the executions query and returns the search envelope. It
// is factored out so the sensitive_access report can reuse the same call.
func (m *Module) executionsList(ctx context.Context, in SearchExecutionsInput) (base.SearchResult[*models.MsahandlerExecutionResource], *base.Error) {
	limit := firstNonZero(in.Limit, 100)
	params := aidr_events.NewQueryExecutionsV1ParamsWithContext(ctx)
	params.SessionID = optStr(in.SessionID)
	params.Aid = optStr(in.Aid)
	params.Limit = optInt64(limit)
	params.Offset = optInt64(in.Offset)
	call := func(t string) (aidrResp[*models.MsahandlerExecutionResource], error) {
		params.TimeRange = &t
		ok, err := m.API.QueryExecutionsV1(params)
		r := aidrResp[*models.MsahandlerExecutionResource]{raw: ok}
		if ok != nil && ok.Payload != nil {
			r.resources, r.meta = ok.Payload.Resources, ok.Payload.Meta
		}
		return r, err
	}
	return searchList(m, queryOpts{op: "search_guardian_executions", timeRange: firstNonEmpty(in.TimeRange, logscaleToolDefault), limit: limit}, call)
}

// --- search_guardian_prompts ---

// SearchPromptsInput is the input for falcon_search_guardian_prompts.
type SearchPromptsInput struct {
	SessionID string `json:"session_id" jsonschema:"AgenticSessionId to search prompts within."`
	Aid       string `json:"aid,omitempty" jsonschema:"Optional sensor ID (aid) filter — identifies a HOST, not a single agent."`
	TimeRange string `json:"time_range,omitempty" jsonschema:"Time range (e.g., '2h', '24h', '7d'). Defaults to '2h', matching the API — widen it explicitly for older prompts, up to a 7-day maximum (this route scans raw events; a wider window is refused and narrowed back to 7d). Sent to the API as requested; if refused, Guardian retries narrower and reports it in 'notices'. Default: '2h'"`
	Limit     int    `json:"limit,omitempty" jsonschema:"Maximum number of results to return. [1-500]"`
	Offset    int    `json:"offset,omitempty" jsonschema:"Index of the first record to return, for paging. Pair with limit; read pagination in the response to page. The API refuses an offset above 1000 — narrow time_range instead of paging deeper."`
}

var searchPromptsSchema = guardianSchema[SearchPromptsInput](schemaOpts{defaultLimit: 100, defaultTimeRange: logscaleToolDefault})

func (m *Module) searchPrompts(ctx context.Context, _ *mcp.CallToolRequest, in SearchPromptsInput) (*mcp.CallToolResult, base.SearchResult[*models.MsahandlerPromptResource], error) {
	var zero base.SearchResult[*models.MsahandlerPromptResource]
	limit := firstNonZero(in.Limit, 100)
	params := aidr_events.NewQueryPromptsV1ParamsWithContext(ctx)
	params.SessionID = optStr(in.SessionID)
	params.Aid = optStr(in.Aid)
	params.Limit = optInt64(limit)
	params.Offset = optInt64(in.Offset)
	call := func(t string) (aidrResp[*models.MsahandlerPromptResource], error) {
		params.TimeRange = &t
		ok, err := m.API.QueryPromptsV1(params)
		r := aidrResp[*models.MsahandlerPromptResource]{raw: ok}
		if ok != nil && ok.Payload != nil {
			r.resources, r.meta = ok.Payload.Resources, ok.Payload.Meta
		}
		return r, err
	}
	out, apiErr := searchList(m, queryOpts{op: "search_guardian_prompts", timeRange: firstNonEmpty(in.TimeRange, logscaleToolDefault), limit: limit}, call)
	if apiErr != nil {
		return nil, zero, apiErr
	}
	return nil, out, nil
}

// --- search_guardian_skills ---

// SearchSkillsInput is the input for falcon_search_guardian_skills.
type SearchSkillsInput struct {
	NameFilter string `json:"name_filter,omitempty" jsonschema:"Filter skills by name pattern (supports wildcards via 'like')."`
	TimeRange  string `json:"time_range,omitempty" jsonschema:"Time range (e.g., '24h', '7d'). Filters LastSeen. Sent to the API as requested; if refused, Guardian retries narrower and reports it in 'notices'. Default: '7d'"`
	Limit      int    `json:"limit,omitempty" jsonschema:"Maximum number of results to return. [1-500]"`
	Offset     int    `json:"offset,omitempty" jsonschema:"Index of the first record to return, for paging. Pair with limit; read pagination in the response to page. The API refuses an offset above 1000 — narrow time_range instead of paging deeper."`
}

var searchSkillsSchema = guardianSchema[SearchSkillsInput](schemaOpts{defaultLimit: 100, defaultTimeRange: "7d"})

func (m *Module) searchSkills(ctx context.Context, _ *mcp.CallToolRequest, in SearchSkillsInput) (*mcp.CallToolResult, base.SearchResult[*models.MsahandlerSkillResource], error) {
	var zero base.SearchResult[*models.MsahandlerSkillResource]
	limit := firstNonZero(in.Limit, 100)
	params := aidr_events.NewQuerySkillsV1ParamsWithContext(ctx)
	params.NameFilter = optStr(in.NameFilter)
	params.Limit = optInt64(limit)
	params.Offset = optInt64(in.Offset)
	call := func(t string) (aidrResp[*models.MsahandlerSkillResource], error) {
		params.TimeRange = &t
		ok, err := m.API.QuerySkillsV1(params)
		r := aidrResp[*models.MsahandlerSkillResource]{raw: ok}
		if ok != nil && ok.Payload != nil {
			r.resources, r.meta = ok.Payload.Resources, ok.Payload.Meta
		}
		return r, err
	}
	out, apiErr := searchList(m, queryOpts{op: "search_guardian_skills", timeRange: firstNonEmpty(in.TimeRange, "7d"), limit: limit}, call)
	if apiErr != nil {
		return nil, zero, apiErr
	}
	return nil, out, nil
}

// --- search_guardian_skill_usage ---

// SearchSkillUsageInput is the input for falcon_search_guardian_skill_usage.
type SearchSkillUsageInput struct {
	Name      string `json:"name,omitempty" jsonschema:"Filter by skill name. Exact and case-sensitive, not a substring or a wildcard — a wrong name returns zero rows rather than an error. Take the name verbatim from search_guardian_skills or get_guardian_fleet_skill_inventory. Most skills have no events in the default 2h window, so widen time_range before concluding a skill was never used."`
	SessionID string `json:"session_id,omitempty" jsonschema:"Filter by AgenticSessionId."`
	Aid       string `json:"aid,omitempty" jsonschema:"Filter by sensor ID (aid) — identifies a HOST, not a single agent."`
	TimeRange string `json:"time_range,omitempty" jsonschema:"Time range (e.g., '2h', '24h', '7d'). Defaults to '2h', matching the API — widen it explicitly to look further back, up to a 7-day maximum (this route scans raw events; a wider window is refused and narrowed back to 7d). Sent to the API as requested; if refused, Guardian retries narrower and reports it in 'notices'. Default: '2h'"`
	Limit     int    `json:"limit,omitempty" jsonschema:"Maximum number of results to return. [1-500]"`
	Offset    int    `json:"offset,omitempty" jsonschema:"Index of the first record to return, for paging. Pair with limit; read pagination in the response to page. The API refuses an offset above 1000 — narrow time_range instead of paging deeper."`
}

var searchSkillUsageSchema = guardianSchema[SearchSkillUsageInput](schemaOpts{defaultLimit: 100, defaultTimeRange: logscaleToolDefault})

func (m *Module) searchSkillUsage(ctx context.Context, _ *mcp.CallToolRequest, in SearchSkillUsageInput) (*mcp.CallToolResult, base.SearchResult[*models.MsahandlerSkillUsageResource], error) {
	var zero base.SearchResult[*models.MsahandlerSkillUsageResource]
	limit := firstNonZero(in.Limit, 100)
	params := aidr_events.NewQuerySkillUsageV1ParamsWithContext(ctx)
	params.Name = optStr(in.Name)
	params.SessionID = optStr(in.SessionID)
	params.Aid = optStr(in.Aid)
	params.Limit = optInt64(limit)
	params.Offset = optInt64(in.Offset)
	call := func(t string) (aidrResp[*models.MsahandlerSkillUsageResource], error) {
		params.TimeRange = &t
		ok, err := m.API.QuerySkillUsageV1(params)
		r := aidrResp[*models.MsahandlerSkillUsageResource]{raw: ok}
		if ok != nil && ok.Payload != nil {
			r.resources, r.meta = ok.Payload.Resources, ok.Payload.Meta
		}
		return r, err
	}
	out, apiErr := searchList(m, queryOpts{op: "search_guardian_skill_usage", timeRange: firstNonEmpty(in.TimeRange, logscaleToolDefault), limit: limit}, call)
	if apiErr != nil {
		return nil, zero, apiErr
	}
	return nil, out, nil
}

// --- search_guardian_os_users ---

// SearchOSUsersInput is the input for falcon_search_guardian_os_users.
type SearchOSUsersInput struct {
	Aid       string `json:"aid,omitempty" jsonschema:"Filter by the OS user's sensor ID (aid)."`
	Username  string `json:"username,omitempty" jsonschema:"Filter by OS username."`
	ObjectSid string `json:"object_sid,omitempty" jsonschema:"Filter by the OS user's ObjectSid (AD security identifier)."`
	TimeRange string `json:"time_range,omitempty" jsonschema:"Time range (e.g., '24h', '7d'). Filters LastSeen. Sent to the API as requested; if refused, Guardian retries narrower and reports it in 'notices'. Default: '7d'"`
	Limit     int    `json:"limit,omitempty" jsonschema:"Maximum number of results to return. [1-500]"`
	Offset    int    `json:"offset,omitempty" jsonschema:"Index of the first record to return, for paging. Pair with limit; read pagination in the response to page. The API refuses an offset above 1000 — narrow time_range instead of paging deeper."`
}

var searchOSUsersSchema = guardianSchema[SearchOSUsersInput](schemaOpts{defaultLimit: 50, defaultTimeRange: "7d"})

func (m *Module) searchOSUsers(ctx context.Context, _ *mcp.CallToolRequest, in SearchOSUsersInput) (*mcp.CallToolResult, base.SearchResult[*models.MsahandlerOSUserResource], error) {
	var zero base.SearchResult[*models.MsahandlerOSUserResource]
	limit := firstNonZero(in.Limit, 50)
	params := aidr_events.NewQueryAgentOSUsersV1ParamsWithContext(ctx)
	params.Aid = optStr(in.Aid)
	params.Username = optStr(in.Username)
	params.ObjectSid = optStr(in.ObjectSid)
	params.Limit = optInt64(limit)
	params.Offset = optInt64(in.Offset)
	call := func(t string) (aidrResp[*models.MsahandlerOSUserResource], error) {
		params.TimeRange = &t
		ok, err := m.API.QueryAgentOSUsersV1(params)
		r := aidrResp[*models.MsahandlerOSUserResource]{raw: ok}
		if ok != nil && ok.Payload != nil {
			r.resources, r.meta = ok.Payload.Resources, ok.Payload.Meta
		}
		return r, err
	}
	out, apiErr := searchList(m, queryOpts{op: "search_guardian_os_users", timeRange: firstNonEmpty(in.TimeRange, "7d"), limit: limit}, call)
	if apiErr != nil {
		return nil, zero, apiErr
	}
	return nil, out, nil
}

// --- search_guardian_detections ---

// SearchDetectionsInput is the input for falcon_search_guardian_detections.
type SearchDetectionsInput struct {
	AgentID   string `json:"agent_id,omitempty" jsonschema:"Filter by the detection's AgentId. WARNING: This takes a 32-hex SENSOR/host ID (AIAgent.SensorId / aid), NOT the 64-hex AIAgent.Id — the API parameter name is misleading."`
	Product   string `json:"product,omitempty" jsonschema:"Filter by AI product name (e.g., 'Kiro', 'CLAUDE_CODE'). Human-readable names are auto-normalized."`
	TimeRange string `json:"time_range,omitempty" jsonschema:"Time range (e.g., '1h', '24h', '7d'). Filters the detection Timestamp. Sent to the API as requested; if refused, Guardian retries narrower and reports it in 'notices'. Default: '7d'"`
	Limit     int    `json:"limit,omitempty" jsonschema:"Maximum number of results to return. [1-500]"`
	Offset    int    `json:"offset,omitempty" jsonschema:"Index of the first record to return, for paging. Pair with limit; read pagination in the response to page. The API refuses an offset above 1000 — narrow time_range instead of paging deeper."`
}

var searchDetectionsSchema = guardianSchema[SearchDetectionsInput](schemaOpts{defaultLimit: 50, defaultTimeRange: detectionsDefaultLookback})

func (m *Module) searchDetections(ctx context.Context, _ *mcp.CallToolRequest, in SearchDetectionsInput) (*mcp.CallToolResult, base.SearchResult[*models.MsahandlerDetectionResource], error) {
	var zero base.SearchResult[*models.MsahandlerDetectionResource]
	if e := rejectAgentIDsToken(in.AgentID); e != nil {
		return nil, zero, e
	}
	limit := firstNonZero(in.Limit, 50)
	product := in.Product
	if product != "" {
		product = normalizeProductName(product)
	}
	params := aidr_events.NewQueryDetectionsV1ParamsWithContext(ctx)
	params.AgentID = optStr(in.AgentID)
	params.Product = optStr(product)
	params.Limit = optInt64(limit)
	params.Offset = optInt64(in.Offset)
	call := func(t string) (aidrResp[*models.MsahandlerDetectionResource], error) {
		params.TimeRange = &t
		ok, err := m.API.QueryDetectionsV1(params)
		r := aidrResp[*models.MsahandlerDetectionResource]{raw: ok}
		if ok != nil && ok.Payload != nil {
			r.resources, r.meta = ok.Payload.Resources, ok.Payload.Meta
		}
		return r, err
	}
	out, apiErr := searchList(m, queryOpts{op: "search_guardian_detections", timeRange: firstNonEmpty(in.TimeRange, detectionsDefaultLookback), limit: limit}, call)
	if apiErr != nil {
		return nil, zero, apiErr
	}
	return nil, out, nil
}

// --- search_guardian_installs ---

// SearchInstallsInput is the input for falcon_search_guardian_installs.
type SearchInstallsInput struct {
	SensorID  string `json:"sensor_id,omitempty" jsonschema:"Filter by sensor ID (32-hex aid / AIAgent.SensorId)."`
	Product   string `json:"product,omitempty" jsonschema:"Filter by AI product name (e.g., 'Codex', 'CLAUDE_CODE'). Human-readable names are auto-normalized."`
	Hostname  string `json:"hostname,omitempty" jsonschema:"Filter by hostname of the device the agent is installed on."`
	TimeRange string `json:"time_range,omitempty" jsonschema:"Time range (e.g., '24h', '7d'). Filters LastSeen. Sent to the API as requested; if refused, Guardian retries narrower and reports it in 'notices'. Default: '7d'"`
	Limit     int    `json:"limit,omitempty" jsonschema:"Maximum number of results to return. [1-500]"`
	Offset    int    `json:"offset,omitempty" jsonschema:"Index of the first record to return, for paging. Pair with limit; read pagination in the response to page. The API refuses an offset above 1000 — narrow time_range instead of paging deeper."`
}

var searchInstallsSchema = guardianSchema[SearchInstallsInput](schemaOpts{defaultLimit: 50, defaultTimeRange: "7d"})

func (m *Module) searchInstalls(ctx context.Context, _ *mcp.CallToolRequest, in SearchInstallsInput) (*mcp.CallToolResult, base.SearchResult[*models.MsahandlerInstallResource], error) {
	var zero base.SearchResult[*models.MsahandlerInstallResource]
	limit := firstNonZero(in.Limit, 50)
	product := in.Product
	if product != "" {
		product = normalizeProductName(product)
	}
	params := aidr_events.NewQueryAgentInstallationsV1ParamsWithContext(ctx)
	params.SensorID = optStr(in.SensorID)
	params.Product = optStr(product)
	params.Hostname = optStr(in.Hostname)
	params.Limit = optInt64(limit)
	params.Offset = optInt64(in.Offset)
	call := func(t string) (aidrResp[*models.MsahandlerInstallResource], error) {
		params.TimeRange = &t
		ok, err := m.API.QueryAgentInstallationsV1(params)
		r := aidrResp[*models.MsahandlerInstallResource]{raw: ok}
		if ok != nil && ok.Payload != nil {
			r.resources, r.meta = ok.Payload.Resources, ok.Payload.Meta
		}
		return r, err
	}
	out, apiErr := searchList(m, queryOpts{op: "search_guardian_installs", timeRange: firstNonEmpty(in.TimeRange, "7d"), limit: limit}, call)
	if apiErr != nil {
		return nil, zero, apiErr
	}
	return nil, out, nil
}

// --- search_guardian_models ---

// SearchModelsInput is the input for falcon_search_guardian_models.
type SearchModelsInput struct {
	TimeRange string `json:"time_range,omitempty" jsonschema:"Time range (e.g., '24h', '7d'). Filters LastSeen. Sent to the API as requested; if refused, Guardian retries narrower and reports it in 'notices'. Default: '7d'"`
	Limit     int    `json:"limit,omitempty" jsonschema:"Maximum number of results to return. [1-500]"`
	Offset    int    `json:"offset,omitempty" jsonschema:"Index of the first record to return, for paging. Pair with limit; read pagination in the response to page. The API refuses an offset above 1000 — narrow time_range instead of paging deeper."`
}

var searchModelsSchema = guardianSchema[SearchModelsInput](schemaOpts{defaultLimit: 50, defaultTimeRange: "7d"})

func (m *Module) searchModels(ctx context.Context, _ *mcp.CallToolRequest, in SearchModelsInput) (*mcp.CallToolResult, base.SearchResult[*models.MsahandlerModelResource], error) {
	var zero base.SearchResult[*models.MsahandlerModelResource]
	limit := firstNonZero(in.Limit, 50)
	params := aidr_events.NewQueryModelNamesV1ParamsWithContext(ctx)
	params.Limit = optInt64(limit)
	params.Offset = optInt64(in.Offset)
	call := func(t string) (aidrResp[*models.MsahandlerModelResource], error) {
		params.TimeRange = &t
		ok, err := m.API.QueryModelNamesV1(params)
		r := aidrResp[*models.MsahandlerModelResource]{raw: ok}
		if ok != nil && ok.Payload != nil {
			r.resources, r.meta = ok.Payload.Resources, ok.Payload.Meta
		}
		return r, err
	}
	out, apiErr := searchList(m, queryOpts{op: "search_guardian_models", timeRange: firstNonEmpty(in.TimeRange, "7d"), limit: limit}, call)
	if apiErr != nil {
		return nil, zero, apiErr
	}
	return nil, out, nil
}
