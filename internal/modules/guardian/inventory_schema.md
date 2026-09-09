# AI Entity & LogScale Event Field Reference

The backend splits AI telemetry across two layers:

1. **AI Entity Store** — identity and catalog entities (AIAgent, AIAgentSession,
   AITool, AISkillFrontmatter, MCPServerName, AIAgentInstallation, AIModelName,
   AIAgentOSUser). Queried by `sensor_id`/`product`/`hostname` within a
   `time_range` window on `LastSeen`.
2. **LogScale Events** — per-invocation activity (`AgenticSessionStart`,
   `AgenticToolRequest`, `AgenticUserPromptSubmit`) via `queries/executions`,
   `queries/tool-usage`, `queries/skill-usage`, `queries/prompts`. Queried by
   `aid`/`session_id` within a `time_range` window (defaults to 2h).

## Product Tag IDs

The entity-store `Product`/`AgentProduct` field is a numeric tag ID (not a
string name). Human names are accepted on query parameters and normalized
server-side.

⚠️ **Two encodings exist and must not be mixed:** entity sources (agents,
sessions, installs, models, detections) return the **tag ID**; LogScale event
sources return the product **name**. A tag ID decoded from JSON is a float whose
default string form is exponent notation — normalize to a plain integer string
before comparing, or a join silently misses.

| Product | Tag ID |
|---------|--------|
| `CLAUDE` | 213584428666145 |
| `CLAUDE_CODE` | 213584428666146 |
| `CLAUDE_COWORK` | 213584428666147 |
| `OPENCLAW` | 213584428666148 |
| `GITHUB_COPILOT` | 213584428666189 |
| `KIRO` | 213584428666190 |
| `ZERO_AGENT` | 213584428666191 |
| `MPC_BUILDER` | 213584428666192 |
| `QUICKWORK_AGENT` | 213584428666193 |
| `AGENT_ORCHA` | 213584428666194 |
| `AGENT_SMITH` | 213584428666195 |
| `ANTIGRAVITY` | 213584428666196 |
| `CODEX` | 213584428666200 |
| `CURSOR` | 213584428666201 |
| `GENERIC` | 213584428666221 |
| `MICROSOFT_COPILOT` | 213584428666293 |
| `CHATGPT_DESKTOP` | 213584428666294 |
| `WINDSURF` | 213584428666295 |
| `JETBRAINS` | 213584428666296 |
| `EXPERIMENTAL` | 213584428666297 |
| `CLINE` | 213584428666298 |
| `CONTINUE_DEV` | 213584428666299 |

## AIAgent (entity store)

Returned by `queries/agents/v1`, `entities/agents/v1`, `aggregates/agents/v1`.

| Field | Type | Description |
|-------|------|-------------|
| `Id` | String | Unique agent record token (opaque, e.g. `ASCWQseSk3b76g...`). Pass to `entities/agents/v1?ids=` / get_guardian_agent. |
| `AgentIds` | Array | The agent's content hash(es) (width varies). Carried in the record; not a filter parameter. |
| `SensorId` | String | CrowdStrike sensor ID (aid): a **32-hex HOST** id. Use for `aid`/`sensor_id` filters on the event and host-scoped queries. Not unique per agent. |
| `AgentName` | String | Agent name |
| `AgentProduct` | String | Product tag ID (see mapping above) |
| `AgentProductName` | String | Friendly product name (sibling of `AgentProduct`; omitted for unresolved tags) |
| `Hostname` | String | Device hostname (joined from FalconHost) |
| `SpiffeId` | String | SPIFFE workload identity |
| `LastExecutionTime` | DateTime | Last observed execution |
| `LastInventoryTime` | DateTime | Last inventory refresh |
| `FirstSeen` / `LastSeen` | DateTime | Seen window. **`LastSeen` is what `time_range` filters.** |

`CustomerId` is **never returned** by any Guardian endpoint.

## Agent Sessions — AIAgentSession (entity store)

Returned by `queries/agent-sessions/v1`, `entities/agent-sessions/v1`,
`aggregates/agent-sessions/v1`.

| Field | Type | Description |
|-------|------|-------------|
| `Id` | String | Session record id (use for `entities/agent-sessions/v1?ids=`) |
| `Product` | String | Product tag ID |
| `ProductName` | String | Friendly product name (sibling of `Product`; omitted for unresolved tags) |
| `Name` | String | Session name |
| `FirstSeen` / `LastSeen` | DateTime | Seen window (`LastSeen` is filtered) |
| `Cim.AIAgentSession.sessionId` | String | The AgenticSessionId (UUID) |
| `Cim.AIAgentSession.modelsInvoked` | Array | Models used in the session |
| `Cim.AIAgentSession.workingDirectory` | String | Working directory |
| `Cim.AIAgentSession.startTime` / `updatedTime` | DateTime | Session timing |

`SensorId` and `AIAgentIds` are **not returned** — they are never populated on
this entity upstream.

## Executions — LogScale `AgenticSessionStart`

Returned by `queries/executions/v1`, `entities/executions/v1`. One row per
process invocation.

| Field | Type | Description |
|-------|------|-------------|
| `AgenticSessionId` | String | Session UUID (**flat** — drill into the graph with this) |
| `AgenticModel` | String | LLM model used |
| `AgenticWorkingDirectory` | String | Working directory path |
| `AgenticInputTokens` | Number | Input token count |
| `AgenticOutputTokens` | Number | Output token count |
| `ContextProcessId` | String | Context process ID |
| `ProcessTags` | Multi-value | Product tag ID(s) for the process |
| `aid` | String | Sensor ID (no hyphens) |
| `timestamp` | Number | Event time (epoch milliseconds) |

## Tool Usage — LogScale `AgenticToolRequest`

Returned by `queries/tool-usage/v1`.

| Field | Type | Description |
|-------|------|-------------|
| `AgenticSessionId` | String | Session this tool was used in |
| `AgenticTool` | String | Tool type (numeric enum) |
| `AgenticToolName` | String | Tool name (e.g., "Bash", "Read", "Write", "Edit") |
| `AgenticToolUseId` | String | Unique tool use identifier |
| `AgenticPath` | String | File path (Read/Write/Edit/Glob tools) |
| `AgenticDescription` | String | Agent's stated purpose for this tool use |
| `AgenticPattern` | String | Pattern for Glob/Grep tools |
| `AgenticQuery` | String | Search query for Grep/WebSearch tools |
| `AgenticSkill` | String | Skill name for the Skill tool |
| `CommandLine` | String | Command line/arguments (Bash tool) |
| `Url` | String | URL for WebFetch/WebSearch tools |
| `aid` | String | Sensor ID |

## Tool Catalog — AITool (entity store)

Returned by `queries/tools/v1`, `aggregates/tools/v1`.

| Field | Type | Description |
|-------|------|-------------|
| `Id` | String | Tool record id |
| `Name` | String | Tool name |
| `SensorId` | String | The tool's host sensor ID |
| `FirstSeen` / `LastSeen` | DateTime | Seen window |

## Skills — AISkillFrontmatter (entity store)

Returned by `queries/skills/v1`, `aggregates/skills/v1`.

| Field | Type | Description |
|-------|------|-------------|
| `Id` | String | Skill frontmatter record id |
| `SkillName` | String | Skill name |
| `SkillDescription` | String | Skill description |
| `SkillDirectoryHash` | String | Content hash of the skill directory |
| `FirstSeen` / `LastSeen` | DateTime | Seen window |

Per-invocation skill events come from LogScale (`queries/skill-usage/v1`):
`AgenticSessionId`, `AgenticSkill`, `AgenticToolUseId`, `aid`.

## MCP Server Names — MCPServerName (entity store)

Returned by `queries/mcp-server-names/v1`. **Fleet-wide, no agent filter.**

| Field | Type | Description |
|-------|------|-------------|
| `Id` | String | MCP server name record id (a hashed dedup key) |
| `Cim.MCPServerName.serverName` | String | Human-friendly server name |
| `LastUsedTime` / `LastInventoryTime` | DateTime | Usage/inventory timing |
| `FirstSeen` / `LastSeen` | DateTime | Seen window |

## OS Users — AIAgentOSUser (entity store)

Returned by `queries/agent-os-users/v1`, `entities/agent-os-users/v1`.

| Field | Type | Description |
|-------|------|-------------|
| `Aid` | String | Host sensor ID |
| `Username` | String | OS username |
| `ObjectSid` | String | AD security identifier |
| `FirstSeen` / `LastSeen` | DateTime | Seen window |

## Model Names — AIModelName (entity store)

Returned by `queries/model-names/v1`. **Fleet-wide, only `time_range` filters.**

| Field | Type | Description |
|-------|------|-------------|
| `Id` | String | Model name record id (a hashed dedup key) |
| `Cim.AIModelName.modelName` | String | Human-friendly model name |
| `LastUsedTime` / `LastInventoryTime` | DateTime | Usage/inventory timing |
| `FirstSeen` / `LastSeen` | DateTime | Seen window |

## Prompts — LogScale `AgenticUserPromptSubmit`

Returned by `queries/prompts/v1`.

| Field | Type | Description |
|-------|------|-------------|
| `AgenticPrompt` | String | The user prompt text |
| `AgenticSessionId` | String | Session the prompt belongs to |
| `aid` | String | Sensor ID (a HOST) |
| `timestamp` | String | Epoch **milliseconds as a STRING**, not a number. Coerce with `int()` before comparing or sorting |
| `ProcessTags` | Multi-value | Product tag ID(s) for the emitting process |

To name a session by its opening prompt: group by `AgenticSessionId` and take the
row with `min(int(timestamp))`.

## Installs — AIAgentInstallationView (entity store)

Returned by `queries/agent-installations/v1`.

| Field | Type | Description |
|-------|------|-------------|
| `Id` | String | Install record id |
| `SensorId` | String | Host sensor ID |
| `Hostname` | String | Device hostname |
| `AgentName` / `AgentProduct` | String | Agent name / product tag ID |
| `AgentProductName` | String | Friendly product name (sibling of `AgentProduct`; omitted for unresolved tags) |
| `AgentVersion` | String | Installed version |
| `InstallSource` | String | Where the install came from |
| `AgentDeclarationPath` / `BinaryPath` | String | On-disk paths |
| `FileSha256` | String | Binary SHA256 |
| `LastExecutionTime` / `LastInventoryTime` | DateTime | Timing |
| `FirstSeen` / `LastSeen` | DateTime | Seen window |

## Time Filtering

All `queries/*` and `aggregates/*` accept `time_range`. Entity-store sources
filter `LastSeen`; LogScale event queries (executions, tool-usage, skill-usage,
prompts) default to **2 hours** when omitted:

```
GET /aidr/queries/tool-usage/v1?time_range=7d
```

There is no pre-emptive ceiling in Guardian's code; the requested window is
sent to the API as asked, and the API decides what it will serve (see the
"Time windows" section of the query guide for the retry ladder used when it
refuses). Only the `entities/*` routes reject `time_range` outright.

## Cross-Layer Linkage

The Agentic Graph endpoints resolve an `AgenticSessionId` UUID to its vertex key
automatically. A vertex key `aisess:{aid}:{AgenticSessionId}` is also accepted.
