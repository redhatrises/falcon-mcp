# Guardian API Reference

Guardian uses structured Falcon MSA API endpoints to query AI agent telemetry data, where clients interact with typed REST parameters.

## Two Query Layers

- **AI Entity Store**: agent identity and catalogs (AIAgent, AIAgentSession,
  AITool, AISkillFrontmatter, MCPServerName, AIAgentInstallation, AIModelName,
  AIAgentOSUser). Filtered by `sensor_id`/`product`/`hostname` and windowed by
  `time_range` on `LastSeen`.
- **LogScale Events**: per-invocation activity (`AgenticSessionStart`,
  `AgenticToolRequest`, `AgenticUserPromptSubmit`) surfaced by
  `queries/executions`, `queries/tool-usage`, `queries/skill-usage`, and
  `queries/prompts`. Filtered by `aid`/`session_id` and windowed by
  `time_range`, which defaults to **2 hours** when omitted.

## ⚠️ Three identifiers — do not conflate

| Identifier | Shape | What it is | Endpoints that take it |
|---|---|---|---|
| `Id` | opaque record token (e.g. `ASCWQseSk3b76g...`) | one AIAgent record | entities/agents (`ids`); pass to get_guardian_agent |
| `AgentIds[]` | content hash (width varies) | the agent's content hash(es) | **no endpoint takes it.** It is carried in the record only — no filter parameter accepts it, and nothing joins against it any more (see below) |
| `aid` / `SensorId` | **32-hex** | a HOST/sensor | tools, agent-os-users, installs (`sensor_id`); executions/tool-usage/skill-usage/prompts (`aid`); detections (`agent_id`; misleadingly named). Not a filter on agent-sessions — that route has no host filter. |

**Many hosts run more than one AI agent** — up to 13 observed — so anything
keyed only by `aid`/`sensor_id` covers every agent on that machine, not one
agent.

⚠️ **No entity can be scoped to a single agent.** The API used to return
reverse-relationship arrays (`UsedByAIAgents[]` on tools/skills/models/
mcp-server-names, `RanByAIAgents[]` on sessions, `UsedAIAgentSessions[]` on OS
users, `UsedByAIAgentOSUsers[]` on agents), which allowed a client-side join on
`AgentIds[]`. **All of them were removed and none are returned now** — verified
live across every affected route. So per-agent attribution is not possible for
tools, skills, models or MCP servers; `sensor_id`/`aid` (HOST scope) is the
finest grain that exists. Do not build a client-side join on these entities.

## ⚠️ Two product encodings

- **Entity sources** (agents, sessions, installs, models, detections) return the
  product as a **numeric tag ID**, e.g. `213584428666200`. The encoding is not
  consistent across sources: `queries/agents` returns it as a JSON **string**
  (`"213584428666221"`) while `aggregates/detections` returns a JSON **int**
  (`0` for unattributed). Coerce both sides with `str()` before comparing, or the
  join silently misses. (Python's `json` decodes an integer literal to `int`, not
  `float`, so no exponent form is involved.) Each product tag field is also
  decorated server-side with a friendly `<field>Name` sibling
  (`AgentProductName` / `ProductName` / `AgenticProductTagName`) resolved to a
  readable name (e.g. "Claude Code"); unrecognized tags are left undecorated (no
  sibling).
- **LogScale event sources** return product **names**.

On *input* you always pass a human name (`CLAUDE_CODE`, `Claude Code`,
`claude-code` all normalize); unknown names are a 400. On *output* the encodings
differ, so joining a LogScale row to an entity row requires mapping. Mixing them
yields a silent empty join.

## Time windows: sent as requested, the API decides

There is no pre-emptive per-route ceiling in Guardian's code. Whatever
`time_range` the caller asks for is sent to the API as asked. The `/aidr`
lookback limits differ between deployments, so the API, not this client, is
the authority on what it will serve.

Every `queries/*` and `aggregates/*` route accepts `time_range`. The
entity-store queries and aggregates filter `LastSeen` (or `Timestamp` for
detections). The LogScale-backed event sources (`queries/executions`,
`queries/tool-usage`, `queries/skill-usage`, `queries/prompts`) default to
**2 hours** when `time_range` is omitted — widen it explicitly to reach older
activity.

The maximum lookback splits cleanly by layer, and is enforced server-side:

- **Entity and aggregate routes** (agents, agent-sessions, tools, skills,
  models, mcp-server-names, installs, os-users, detections, all aggregates)
  serve up to **90 days**.
- **LogScale event routes** (`queries/executions`, `queries/tool-usage`,
  `queries/skill-usage`, `queries/prompts`) cap at **7 days** — they scan raw
  event data, which cannot be scanned over longer windows. `7d` is inclusive
  (`168h` is accepted, `8d` is refused with a 400 naming the 7-day maximum).

These are the observed limits, but the client applies no pre-emptive ceiling:
whatever `time_range` the caller asks for is still sent as asked, and the API
remains the authority. When it refuses, the ladder below narrows reactively.

If the API refuses the requested window (a 504 timeout, or a 400 that names
`time_range`), Guardian retries with progressively narrower windows (`7d`,
`24h`, `6h`, `1h`) until one succeeds, and reports the narrowing in
`notices`. There is a 30-second wall-clock budget on this retry ladder. If it
runs out before a window succeeds, `notices` says so and asks the caller to
retry with a smaller `time_range` directly. Read `notices` before reporting
any count: a narrowed window means the numbers cover less time than asked
for.

Only the **entity fetch-by-id** and **threat-graph** routes reject
`time_range` outright, at any width, with a 400: every `entities/*` route
(`entities/agents`, `entities/executions`, `entities/session-activity`,
`entities/process-tree`, `entities/network-events`, `entities/file-events`,
`entities/classified-file-access`). These have no time dimension.

## API Endpoint Pattern

```
/aidr/{queries|entities|aggregates}/{resource}/v1
```

- **queries** — List/search with filters (GET, returns paginated results)
- **entities** — Get full details by IDs (GET with `?ids=id1&ids=id2` or `?id=vertex-key`)
- **aggregates** — Counts and summaries (GET, returns grouped counts)

## Available Endpoints

### AI Entity & Event Queries

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/aidr/queries/agents/v1` | Search agent instances |
| GET | `/aidr/entities/agents/v1` | Get agents by IDs |
| GET | `/aidr/aggregates/agents/v1` | Agent counts by product |
| GET | `/aidr/queries/agent-sessions/v1` | Search agent sessions (entity store) |
| GET | `/aidr/aggregates/agent-sessions/v1` | Session counts by product; `count` is a JSON string |
| GET | `/aidr/queries/executions/v1` | Per-process invocations (LogScale) |
| GET | `/aidr/entities/executions/v1` | Execution detail by session id |
| GET | `/aidr/queries/tools/v1` | AITool inventory |
| GET | `/aidr/aggregates/tools/v1` | Tool counts by name |
| GET | `/aidr/queries/tool-usage/v1` | Per-invocation tool events (LogScale) |
| GET | `/aidr/queries/skills/v1` | AISkillFrontmatter inventory |
| GET | `/aidr/aggregates/skills/v1` | Skill counts by name |
| GET | `/aidr/queries/skill-usage/v1` | Per-invocation skill events (LogScale) |
| GET | `/aidr/queries/agent-os-users/v1` | OS users that ran AI agents |
| GET | `/aidr/queries/mcp-server-names/v1` | MCP server names (fleet-wide) |
| GET | `/aidr/queries/prompts/v1` | Search prompts (LogScale) |
| GET | `/aidr/queries/detections/v1` | Detections involving AI agent processes |
| GET | `/aidr/aggregates/detections/v1` | Max detection severity per agent + product |
| GET | `/aidr/queries/agent-installations/v1` | AI agent installations |
| GET | `/aidr/queries/model-names/v1` | AI model names (fleet-wide) |

### Agentic Graph (Security Telemetry)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/aidr/entities/session-activity/v1` | Full graph activity for sessions |
| GET | `/aidr/entities/process-tree/v1` | Spawned process tree |
| GET | `/aidr/entities/network-events/v1` | Network connections |
| GET | `/aidr/entities/file-events/v1` | File write activity |
| GET | `/aidr/entities/classified-file-access/v1` | FDP classified file access |

## Query Parameters (GET endpoints)

### Common Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `time_range` | string | Lookback window: `1h`, `24h`, `7d`, `30d`. Max lookback is 90d on entity/aggregate routes and 7d on LogScale event routes (see "Time windows" above). Sent to the API as requested; no pre-emptive ceiling is applied client-side. If the API refuses the window, Guardian retries narrower windows and reports this in `notices`. Rejected only by `entities/*` routes; see "Time windows" above. |
| `limit` | int | Max results (1–500, default 50) |
| `offset` | int | Pagination offset. **Capped at 1000** — a higher value is a 400 (`offset must not exceed 1000; use time_range filters for deep pagination`). To reach older records, narrow `time_range` rather than paging deeper. |

Also note `time_range` accepts only `h` (hours) and `d` (days). Minutes are
rejected with a 400 (`invalid time_range unit: "m"`), so use `1h`, not `60m`.

### Agents (`/aidr/queries/agents/v1`)

AIAgent entity + FalconHost. `time_range` filters `LastSeen`.

| Parameter | Description |
|-----------|-------------|
| `product` | Filter by product (e.g., `CLAUDE_CODE`, `CURSOR`) |
| `hostname` | Filter by device hostname |

Returns records carrying the opaque `Id`, the 32-hex `SensorId`, the
`AgentIds[]` content hash(es), `AgentProduct`, `AgentName`, `Hostname`, and the seen timestamps.

### Agent Sessions (`/aidr/queries/agent-sessions/v1`)

Backed by the AIAgentSession entity store; `time_range` filters `LastSeen`.

| Parameter | Description |
|-----------|-------------|
| `product` | Filter by product |

Returns `Id`, `Product` (+ friendly `ProductName`), `Name`, the seen
timestamps, and the nested `Cim.AIAgentSession` (`sessionId`, `modelsInvoked[]`,
`startTime`, `workingDirectory`, `updatedTime`).

⚠️ **Results are fleet-wide and cannot be attributed to an agent or a host.**
There is no `sensor_id` and no agent filter — the entity's inherited
`SensorId`/`AIAgentIds` are never populated upstream and are not returned. A
count from this route is a count for the whole product, so do not report it as
one agent's session count, and do not rank agents by grouping these rows on
`Product` — that ranks products. There is no per-agent session count anywhere in
this API. The tool response carries a `note` saying the same. For a single host,
and for the flat process grain with per-execution model and token counts, use
`queries/executions/v1` instead.

### Executions (`/aidr/queries/executions/v1`)

Backed by LogScale `AgenticSessionStart` events — one row per process
invocation. Defaults to 2h when `time_range` is omitted; max 7d (see "Time windows").

| Parameter | Description |
|-----------|-------------|
| `session_id` | Filter by AgenticSessionId |
| `aid` | Filter by sensor ID (aid). Identifies a HOST |

Returns `aid`, `AgenticSessionId`, `AgenticModel`, `AgenticWorkingDirectory`,
`AgenticInputTokens`, `AgenticOutputTokens`, `ContextProcessId`, `ProcessTags`,
`timestamp`. Each row carries a **flat `AgenticSessionId`**, so this is the
right source for session IDs to drill into with the graph endpoints.

### Tools (`/aidr/queries/tools/v1`)

AITool entity store — the inventory of which tools exist. `time_range` filters
`LastSeen`.

| Parameter | Description |
|-----------|-------------|
| `sensor_id` | Filter by the tool's host sensor ID (32-hex aid) |

Rows are flat: `Id`, `Name`, `SensorId`, `FirstSeen`/`LastSeen`. There is **no
per-agent filter and no way to attribute a tool to one agent** — `sensor_id`
scopes to the tool's HOST, covering every agent on it.

⚠️ **This store is thinly populated.** It covers far fewer hosts than the agent
store does, so an agent's sensor often matches nothing at all. For the tools an
agent's host actually invoked, use `queries/tool-usage/v1?aid=<aid>` — the event
side is far better populated and carries the command lines.

### Tool Usage (`/aidr/queries/tool-usage/v1`)

Backed by LogScale `AgenticToolRequest` events — per-invocation grain with file
paths and command lines. Defaults to 2h when `time_range` is omitted; max 7d.

| Parameter | Description |
|-----------|-------------|
| `tool_name` | **Exact, case-sensitive** match on `AgenticToolName` |
| `aid` | Filter by sensor ID (aid) |
| `session_id` | Filter by session ID |

⚠️ **`tool_name` is exact and case-sensitive, and the two stores disagree on
spelling.** A mismatch returns zero rows with HTTP 200, not an error, so it is
indistinguishable from "this tool was never used". `tool_name='bash'` matches
nothing where `tool_name='Bash'` matches.

The AITool inventory (`aggregates/tools`, `queries/tools`, and
`get_guardian_inventory`'s `tools.by_name`) lists lowercase names — `bash`,
`edit`, `grep`, `code_search`, `execute` — while these events carry `Bash`,
`Edit`, `Grep`. Some names really are lowercase in both (`apply_diff`,
`list_files`, `read_file`, `mcp__*`), and both `glob` and `Glob` exist as
distinct names, so the case cannot be guessed or normalized. Do not hand a name
straight from the inventory to `tool_name` and read an empty result as absence —
try the other capitalization first.

### Skills (`/aidr/queries/skills/v1`)

AISkillFrontmatterView entity store. `time_range` filters `LastSeen`.

| Parameter | Description |
|-----------|-------------|
| `name_filter` | **Substring** filter on skill name (wildcard via 'like') |

Returns `Id`, `SkillName`, `SkillDescription`, `SkillDirectoryHash`, and the
seen timestamps.

### Skill Usage (`/aidr/queries/skill-usage/v1`)

Backed by LogScale `AgenticToolRequest` (AgenticTool == '13'). Defaults to 2h; max 7d.

| Parameter | Description |
|-----------|-------------|
| `name` | Filter by skill name (**exact** match on `AgenticSkill`) |
| `aid` | Filter by sensor ID (aid) |
| `session_id` | Filter by session ID |

### OS Users (`/aidr/queries/agent-os-users/v1`)

AIAgentOSUser entity store. `time_range` filters `LastSeen`.

| Parameter | Description |
|-----------|-------------|
| `aid` | Filter by the OS user's sensor ID (aid) |
| `username` | Filter by OS username |
| `object_sid` | Filter by ObjectSid (AD security identifier) |

Returns `Aid`, `Username`, `ObjectSid`, and the seen timestamps.

### MCP Server Names (`/aidr/queries/mcp-server-names/v1`)

MCPServerName entity store. **Fleet-wide — no agent/sensor filter.**
`time_range` filters `LastSeen`.

Returns the human-friendly name in `Cim.MCPServerName.serverName` (the `Id` is
only a hashed dedup key) and the used/seen timestamps.

### Prompts (`/aidr/queries/prompts/v1`)

Backed by LogScale `AgenticUserPromptSubmit` events. Defaults to 2h; max 7d.

| Parameter | Description |
|-----------|-------------|
| `session_id` | Filter by session ID |
| `aid` | Filter by sensor ID (aid) |

### Detections (`/aidr/queries/detections/v1`)

Alert source. `time_range` filters the detection `Timestamp`. Always scoped
server-side to `HasAgenticProcess == true`; that is not client-controllable.

| Parameter | Description |
|-----------|-------------|
| `agent_id` | ⚠️ Takes a **32-hex SENSOR/host ID** (`== AIAgent.SensorId`), NOT the opaque `AIAgent.Id` and NOT the `AgentIds[]` content hash. The parameter name is misleading. |
| `product` | Filter by product name → resolved to a tag ID |

⚠️ **`product` takes the name the API expects on input, not a value the API
returns on output.** `product=CLAUDE_CODE` works; feeding back the numeric
`AgenticProductTag` value from a response returns a 400. Use the
human-readable product name only.

Response: `AssignedToName, AgentId, CompositeId, CreatedTimestamp, DataDomains,
Name, Product, RiskScore, Severity, SeverityName, Sha256, SourceHosts,
SourceProducts, Status, Tactic, Technique, UserNames, HasAgenticProcess,
AgenticProductTag, AgenticProductTagName, Timestamp`.

- `Severity` (0–100) and `RiskScore` (0–100) are **different** metrics.
- `DataDomains` and `SourceProducts` are **arrays**.
- `AssignedToName`, `SourceHosts`, `UserNames` are frequently `null`.
- The product field is **`AgenticProductTag`** (friendly name in the
  `AgenticProductTagName` sibling when resolved). It is **unattributed on many
  rows**, encoded as `null` here and as `0` on `aggregates/detections`. Those
  detections cannot be tied to a product or a specific agent.

### Detection Scores (`/aidr/aggregates/detections/v1`)

The **"Agentic Threat Score"**. Same parameters as `queries/detections/v1`.
Fixed `GroupBy(AgentId, AgenticProductTag)` with `max(Severity)` as
`maxDetectionScore`.

⚠️ **Joining these rows onto agents requires BOTH keys:**

```
detections.AgentId == agent.SensorId && detections.AgenticProductTag == agent.AgentProduct
```

`AgentId` alone identifies a HOST, and many hosts run more than one AI agent, so
a single-key join attaches one host's worst detection to *every* agent on that
host. Both sides of the product key are numeric tag IDs — normalize each to a
plain integer string before comparing (a JSON float renders in exponent form
otherwise).

⚠️ **The two detection endpoints encode "no product" differently.**
`aggregates/detections` uses `0`; `queries/detections` uses a real `null`.
Neither is a member of the product taxonomy (every real tag is ~2.1e14), so treat
**both `0` and `null` as unattributed**. Most aggregate rows are unattributed
this way, so an exact two-key join resolves only a small fraction of agents.

Capped at 500 groups, no pagination.

### Installs (`/aidr/queries/agent-installations/v1`)

AIAgentInstallationView entity. `time_range` filters `LastSeen`.

| Parameter | Description |
|-----------|-------------|
| `sensor_id` | Filter by sensor ID (32-hex aid) |
| `product` | Filter by product name |
| `hostname` | Filter by hostname |

Returns `Id`, `SensorId`, `Hostname`, `AgentName`, `AgentProduct`,
`AgentVersion`, `InstallSource`, `AgentDeclarationPath`, `BinaryPath`,
`FileSha256`, `LastExecutionTime`, and the seen timestamps.

### Models (`/aidr/queries/model-names/v1`)

AIModelName entity. **Fleet-wide — the only server-side filter is `time_range`
on `LastSeen`.** There is no name/product/sensor scalar to filter on.

Returns the human-friendly name in `Cim.AIModelName.modelName` (the `Id` is only
a hashed dedup key) and the used/seen timestamps. For the model used per
session, prefer `queries/agent-sessions/v1`
(`Cim.AIAgentSession.modelsInvoked`) or `queries/executions/v1`
(`AgenticModel`).

### Agent Aggregates (`/aidr/aggregates/agents/v1`)

Accepts `time_range`, `limit`, `offset`. Groups agent counts by product
(`AgentProduct`, a numeric tag ID; each bucket also carries a friendly
`AgentProductName`).

### Session Aggregates (`/aidr/aggregates/agent-sessions/v1`)

Groups session counts **by product** (`Product`, a numeric tag ID; each bucket
also carries a friendly `ProductName`), and `count` comes back as a **JSON
string** (`"7"`); coerce before arithmetic. Accepts `time_range` (filters
`LastSeen`) and `product`.

### Tool Aggregates (`/aidr/aggregates/tools/v1`)

AITool entity aggregate. Accepts `time_range`, `limit`, `sensor_id`. Groups by
`Name`.

### Skill Aggregates (`/aidr/aggregates/skills/v1`)

AISkillFrontmatter aggregate. Accepts `time_range`, `name_filter`. Groups by
`SkillName`.

| Parameter | Description |
|-----------|-------------|
| `name_filter` | Substring filter on skill name |

## Aggregate truncation

All aggregates cap at **500 groups with no pagination** (`offset` is accepted but
always applied as 0 internally). A response with exactly 500 rows is very likely
truncated. Narrow with `sensor_id`, `product`, or a shorter `time_range`.

## Error contract

| Status | Meaning | What to do |
|---|---|---|
| **400** | A parameter is not in the endpoint's allowlist, or an unknown product name | Read the message. It names the offending parameter. Do not retry unchanged. |
| **403** | Missing `AIDR:read`, or the `cloud.falcon-guardian.mcp-api.enable-query` flag is off for this CID | An access problem, not a query problem |
| **500** | Server-side query error | Report it; not caller-fixable |
| **504** | **Your query was too broad.** The engine aborted it. **This does NOT mean the API is broken.** | Narrow the window or add a filter (`aid`, `product`, `session_id`). Guardian retries automatically with progressively smaller windows and reports which one succeeded in `notices`. |

## Entities Parameters (GET endpoints)

Entities endpoints use query parameters for IDs:

```
GET /aidr/entities/agents/v1?ids=id1&ids=id2
GET /aidr/entities/executions/v1?id=session-uuid
```

`entities/agents` takes `ids` (agent record tokens, repeatable, max 100).
`entities/executions` takes a single `id` (an AgenticSessionId UUID) and an
optional `context_process_id`.

## Agentic Graph Parameters

```
GET /aidr/entities/session-activity/v1?ids=aisess:{aid}:{session_uuid}
GET /aidr/entities/process-tree/v1?id=aisess:{aid}:{session_uuid}&depth=2
GET /aidr/entities/network-events/v1?id=aisess:{aid}:{session_uuid}
GET /aidr/entities/file-events/v1?id=aisess:{aid}:{session_uuid}
GET /aidr/entities/classified-file-access/v1?id=pid:{aid}:{upid}
```

- `ids` / `id` — Session IDs (vertex keys or UUIDs; server resolves automatically)
- `depth` — Process tree depth (1–3, default 2; only for process-tree endpoint)

## Agentic Graph Vertex ID Format

Each vertex has a scoped ID: `{type_prefix}:{aid}:{unique_id}`

| Vertex Type | ID Pattern | Example |
|-------------|-----------|---------|
| AISession | `aisess:{aid}:{id}` | `aisess:aaaa0000bbbb1111:eb5ca156-1128-44ab-b933-3154a36e8a54` |
| AIAgent | `aiagent:{aid}:{hash}` | `aiagent:aaaa0000bbbb1111:a1b2c3...` |
| AITool | `aitool:{aid}:{hash}` | `aitool:aaaa0000bbbb1111:d4e5f6...` |
| AIModel | `aimod:{aid}:{hash}` | `aimod:aaaa0000bbbb1111:7a8b9c...` |

## Cross-Layer Linkage

The Agentic Graph endpoints resolve an `AgenticSessionId` UUID to its vertex key
automatically — pass a UUID and the server resolves it. A vertex key
(`aisess:{aid}:{uuid}`) is also accepted directly.

## Response Format

All endpoints return the standard Falcon API envelope:

```json
{
  "meta": {
    "pagination": {"offset": 0, "limit": 50, "total": 123},
    "query_time": 0.045,
    "trace_id": "uuid"
  },
  "resources": [...],
  "errors": []
}
```

⚠️ **`meta.pagination.total` is NOT a match count on a full page.** It is
synthesized as `offset + len(page)`, so on a full page it merely restates the
cursor. Guardian blanks it out (reports `null`) on full pages and forwards the
real count only on a short page, where the rows genuinely ran out. To know
whether more data exists, page until a short page comes back.

## Tips

- Product values are UPPER_SNAKE_CASE on input: `CLAUDE_CODE`, `CURSOR`,
  `CLAUDE_COWORK` (human names like `Claude Code` are normalized). Entity
  sources return them as **numeric tag IDs** on output. On detections, the
  filter takes the name, not the tag.
- `time_range` is sent to the API as requested; there is no pre-emptive
  client-side ceiling. LogScale event queries default to 2h when the parameter
  is omitted. Only the `entities/*` routes reject `time_range` outright.
- Agentic Graph endpoints accept both vertex keys and session UUIDs.
- Use aggregates for fleet-wide counts; use queries for individual records.
- `sensitive_only` filtering for file events is done client-side after receiving results.
- An empty `resources: []` with HTTP 200 is a valid response — it means no data
  matches the given filters. Widen `time_range` or relax filters to find data.

## Composed Tools

Some MCP tools fan out to several `/aidr` routes and merge the results. Read
this before trusting a merged result's scope or counts.

### get_guardian_agent

A single lookup: fetches one AIAgent record by its `Id` (the opaque record
token) via `entities/agents/v1` and returns it. It does **not** fan out. For a
one-shot overview of every facet, use
`generate_guardian_report(report_type='agent_detail')`.

Which follow-up key to use depends on the route:

- `search_guardian_tool_usage`, `search_guardian_executions`,
  `search_guardian_skill_usage`, `search_guardian_prompts`,
  `search_guardian_detections` and `search_guardian_tools` all take the record's
  `SensorId` (as `aid`, `agent_id` or `sensor_id`). Every one of them is
  therefore **HOST-scoped**, not agent-scoped.
- The record's `AgentIds[]` is not usable as a follow-up key. No parameter
  accepts it, and the arrays it used to join against are gone.
- `get_guardian_agent_sessions` takes **neither** — it has no agent or host
  filter, so it cannot be scoped to this agent. Use
  `search_guardian_executions(aid=...)` for the host's session grain.

### generate_guardian_report — agent_detail

Fans out from one agent (verified via `entities/agents/v1`). **Every leg is
HOST-scoped by `SensorId`/`aid`**, so every count covers all the AI agents on
that host, not just the requested one: `tools`, `executions`, `tool_usage`,
`skill_usage`, `detections`. Nothing finer exists — the entities carry no agent
filter and no longer return any reverse-relationship array.

- `tools` is the thinnest leg. The AITool store covers few hosts, so it is empty
  for most agents. `tool_usage` answers the same question from the event side and
  is far better populated.
- `max_detection_score` is matched on both `SensorId` and the product tag, so it
  IS agent-specific — but it can be `None` even when `detections` is non-empty,
  because many detections carry no `AgenticProductTag`.

There is no `sessions` leg — the agent-sessions route has no host filter, and
`executions` (keyed by `aid`, carrying `AgenticSessionId`) already covers the
host's sessions.

### get_guardian_inventory

Four aggregate rollups over a single `time_range`. `agents.by_product` counts
AGENTS; `sessions.by_product` counts logical AIAgentSession rows — a different
metric, so do not relabel one as the other. Both product buckets are keyed by
the numeric product tag ID. Read `notices` before reporting any count.

### pivot_on_guardian_attribute

Allowed attributes: `Product`, `HostName`, `Skill`, `Name`. `Product` and
`HostName` search agents; `Skill` searches skill frontmatters (substring on
name); `Name` merges per-invocation skill-usage and tool-usage, deduped by
sensor (`aid`). Returns the `{results, pagination}` envelope for every branch.
