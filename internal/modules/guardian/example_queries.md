# Example Guardian API Calls

## AI Entity & Event Examples

### 1. List all AI agents (last 7 days)

```
GET /aidr/queries/agents/v1?time_range=7d&limit=50
```

Returns all agent instances active in the last 7 days. `7d` is just an
example value here, not a maximum; see "Time windows" in the query guide.

### 2. List agents filtered by product

```
GET /aidr/queries/agents/v1?product=CLAUDE_CODE&time_range=7d&limit=10
```

### 3. List agents filtered by hostname

```
GET /aidr/queries/agents/v1?hostname=dev-laptop-01&time_range=7d
```

### 4. Get agent details by ID

```
GET /aidr/entities/agents/v1?ids=<agent_id>
```

`<agent_id>` is the opaque `Id` record token from a search result, not the
32-hex SensorId and not the AgentIds[] content-hash value.

### 5. List agent sessions (optionally by product)

```
GET /aidr/queries/agent-sessions/v1?product=CLAUDE_CODE&time_range=7d&limit=20
```

There is **no host/sensor filter** on this route. To find the sessions on a
specific host, use the per-process executions instead (keyed by `aid`, carrying
`AgenticSessionId`): `GET /aidr/queries/executions/v1?aid=<aid>&time_range=7d`.
Each session row carries the nested `Cim.AIAgentSession` (sessionId,
modelsInvoked, workingDirectory).

### 6. List per-process executions for a session

```
GET /aidr/queries/executions/v1?session_id=<session_id>&time_range=7d
```

Returns the flat `AgenticSessionId`, `AgenticModel`, and token counts per
process invocation. Also filterable by `aid`.

### 7. Get execution detail by session id

```
GET /aidr/entities/executions/v1?id=<session_id>
```

### 8. List tool usage for a session (per-invocation)

```
GET /aidr/queries/tool-usage/v1?session_id=<session_id>&time_range=7d&limit=100
```

### 9. List Bash tool usage across fleet

```
GET /aidr/queries/tool-usage/v1?tool_name=Bash&time_range=7d&limit=50
```

### 10. List the tool inventory for a host (AITool entity)

```
GET /aidr/queries/tools/v1?sensor_id=<aid>&time_range=7d&limit=100
```

### 11. List skill frontmatters (fleet inventory)

```
GET /aidr/queries/skills/v1?name_filter=review&time_range=7d
```

### 12. List per-invocation skill usage

```
GET /aidr/queries/skill-usage/v1?name=code-review&session_id=<session_id>&time_range=7d
```

`name` is an exact match on `AgenticSkill`.

### 13. List OS users that ran agents

```
GET /aidr/queries/agent-os-users/v1?aid=<aid>&time_range=7d
```

Also filterable by `username` and `object_sid`.

### 14. List MCP server names (fleet-wide)

```
GET /aidr/queries/mcp-server-names/v1?time_range=7d&limit=100
```

No agent/sensor filter.

### 15. Search prompts within a session

```
GET /aidr/queries/prompts/v1?session_id=<session_id>&time_range=7d
```

### 16. Fleet aggregates

```
GET /aidr/aggregates/agents/v1?time_range=7d
GET /aidr/aggregates/agent-sessions/v1?time_range=7d
GET /aidr/aggregates/tools/v1?time_range=7d&limit=100
GET /aidr/aggregates/skills/v1?time_range=7d
GET /aidr/aggregates/detections/v1?time_range=7d
```

The agents and agent-sessions aggregates group **by product tag ID**;
agent-sessions returns `count` as a JSON string.

## Agentic Graph Examples

### 17. Get full session activity (tools, models, processes, skills)

```
GET /aidr/entities/session-activity/v1?ids=aisess:aabbccdd:session-uuid
```

Also accepts plain session UUIDs (server resolves vertex key):

```
GET /aidr/entities/session-activity/v1?ids=session-uuid-here
```

### 18. Get process tree (depth 2)

```
GET /aidr/entities/process-tree/v1?id=aisess:aabbccdd:session-uuid&depth=2
```

### 19. Get network connections from session

```
GET /aidr/entities/network-events/v1?id=aisess:aabbccdd:session-uuid
```

### 20. Get file write activity from session

```
GET /aidr/entities/file-events/v1?id=aisess:aabbccdd:session-uuid
```

## Common Patterns

### Fleet Inventory (combine aggregate calls)

Call these in parallel for a fleet overview. `time_range` is sent as
requested on each call; if a route refuses a wide window, Guardian retries
narrower and reports it in `notices`:
```
GET /aidr/aggregates/agents/v1?time_range=7d
GET /aidr/aggregates/agent-sessions/v1?time_range=7d
GET /aidr/aggregates/tools/v1?time_range=7d&limit=100
GET /aidr/aggregates/detections/v1?time_range=7d
```
The agents and agent-sessions aggregates both group **by product tag ID**;
agent-sessions `count` is a JSON string.

### Agent Investigation (drill down)

1. Find the agent: `GET /aidr/queries/agents/v1?hostname=suspect-host&time_range=7d`
2. Get its sessions on the host (executions are keyed by `aid` and carry
   `AgenticSessionId`): `GET /aidr/queries/executions/v1?aid=<aid>&time_range=7d`
3. Get session activity: `GET /aidr/entities/session-activity/v1?ids=<session_id>`
4. Get process tree: `GET /aidr/entities/process-tree/v1?id=<session_id>&depth=3`
5. Get network events: `GET /aidr/entities/network-events/v1?id=<session_id>`
6. Get detections for the host: `GET /aidr/queries/detections/v1?agent_id=<aid>&time_range=7d`

### Pivot from known attribute

Find all agents on a specific host:
```
GET /aidr/queries/agents/v1?hostname=prod-server-01&time_range=7d
```

Find skill frontmatters matching a pattern:
```
GET /aidr/queries/skills/v1?name_filter=review&time_range=7d
```

### Detections involving AI agents

What fired in the last 7 days:
```
GET /aidr/queries/detections/v1?time_range=7d&limit=50
```

For one host (⚠️ `agent_id` here takes the 32-hex **SensorId**, not `AIAgent.Id`):
```
GET /aidr/queries/detections/v1?agent_id=<aid>&time_range=7d
```

Agentic Threat Score per agent:
```
GET /aidr/aggregates/detections/v1?time_range=7d
```
Join each row onto agents with **BOTH** keys —
`AgentId == AIAgent.SensorId` AND `AgenticProductTag == AIAgent.AgentProduct`. A
SensorId-only join mis-attributes one host's worst detection to every agent on
that host. Rows with a null `AgenticProductTag` cannot be attributed at all.

### Installs and models

```
GET /aidr/queries/agent-installations/v1?sensor_id=<aid>&product=CODEX&time_range=7d&limit=50
GET /aidr/queries/model-names/v1?time_range=7d
```
`model-names` is fleet-wide with only a `time_range` filter. For the model used
per session, prefer `queries/agent-sessions/v1`
(`Cim.AIAgentSession.modelsInvoked`) or `queries/executions/v1`
(`AgenticModel`).
