// MIT License
//
// Copyright (c) 2026 CrowdStrike
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

package guardian

// Tool descriptions, ported verbatim from the upstream Python guardian module so
// the Go tool names and descriptions stay 1:1 with it for client compatibility.

const searchAgentsDescription = `List AI agents from the AIAgent entity store.

Use this to find agents by product or hostname. Returns full agent
records, including the opaque record token ` + "`Id`" + ` (pass to
get_guardian_agent), the 32-hex ` + "`SensorId`" + ` (` + "`== aid`" + `, identifies the
HOST), and the ` + "`AgentIds[]`" + ` content hash(es) (width varies). See
falcon://guardian/inventory/schema-guide for the full field reference
and the ` + "`Id`" + ` vs ` + "`SensorId`" + ` vs ` + "`AgentIds`" + ` distinction.`

const getAgentDescription = `Get a specific AI agent's record from the AIAgent entity store.

Use when you have an AIAgent ` + "`Id`" + ` (the opaque record token from a
search result, not the 32-hex ` + "`SensorId`/`aid`" + ` and not the
` + "`AgentIds[]`" + ` content-hash value) and want the full agent record. The record carries
` + "`SensorId`" + `, which the host-scoped follow-up tools
(get_guardian_agent_sessions, search_guardian_tools,
search_guardian_tool_usage, search_guardian_detections) take as
` + "`aid`/`sensor_id`" + `. For a one-shot overview of every facet, use
generate_guardian_report with report_type='agent_detail'. For
discovering agents by criteria, use search_guardian_agents instead.`

const searchMCPServersDescription = `List MCP server names observed across the fleet (MCPServerName entity).

Use this to see which MCP servers agents have connected to. The
human-friendly server name lives in ` + "`Cim.MCPServerName.serverName`" + ` (the
` + "`Id`" + ` is only a hashed dedup key). The endpoint carries no agent/sensor
filter, so this is fleet-wide. To see which MCP servers a single session
connected to, use get_guardian_session_detail (its activity graph
exposes them under ` + "`ConnectedMcpMcpsrv`" + `).`

const getAgentSessionsDescription = `List AI agent sessions across the fleet, filtered by product.

These rows cannot be tied to one agent or host. The AIAgentSession entity
offers no agent or host filter, its ` + "`SensorId`" + ` and ` + "`AIAgentIds`" + ` are never
populated upstream, and nothing on a session points back to the agent that
ran it. Two questions therefore have no answer here: how many sessions a
single agent had, and which agents ran the most. ` + "`Product`" + ` names the
software rather than an agent, and many agents share a product, so
grouping these rows by ` + "`Product`" + ` counts products.

Returns session records carrying ` + "`Id`" + `, ` + "`Product`" + ` (with a friendly
` + "`ProductName`" + `), ` + "`Name`" + `, the seen timestamps, and a nested
` + "`Cim.AIAgentSession`" + ` holding ` + "`sessionId`" + `, ` + "`modelsInvoked`" + ` and
` + "`workingDirectory`" + `; see falcon://guardian/inventory/schema-guide for the
full field reference. The result also carries ` + "`notices`" + ` if the requested
window had to be narrowed.

For a single host, use search_guardian_executions(aid=...) — the
host-scoped session grain, which also reports the model and token counts
for each process. For a ready-made count by product, use
` + "`sessions.by_product`" + ` from get_guardian_inventory.`

const getSessionDetailDescription = `Get detailed information about a specific AI session.

Use when you have an AgenticSessionId (UUID) and need full context. For
discovering sessions by criteria, use get_guardian_agent_sessions
instead. Returns the session's process executions plus the
per-invocation tools and skills used. When ` + "`include_activity`" + ` is true,
also returns the threat-graph activity (which adds processes, models,
MCP servers, and child sessions as edges).`

const getSessionActivityDescription = `Get activity for one or more AI sessions.

Use this to see full graph relationships including tools, models, processes,
sub-agents, and MCP servers. Accepts vertex IDs or inventory session IDs.
Returns session activity with all connected graph entities.`

const searchToolsDescription = `List AI tools from the AITool entity store — the inventory of which tools exist.

Use this to see what tools are present. A tool cannot be attributed to a
single agent: rows are flat (` + "`Id`" + `, ` + "`Name`" + `, ` + "`SensorId`" + `, the seen
timestamps) and there is no per-agent filter, so ` + "`sensor_id`" + ` narrows to
the tool's host, which covers every agent on it. Coverage is also thin —
the store spans few hosts, so most agents match nothing here. For the
tools an agent's host actually invoked, prefer
search_guardian_tool_usage(aid=...), which also carries file paths and
command lines.`

const searchToolUsageDescription = `List AI tool usage from LogScale AgenticToolRequest events.

Use this to find tool invocations by name, sensor (aid), or session;
the default window is 2 hours, so widen ` + "`time_range`" + ` explicitly for
anything beyond current activity, up to the 7-day maximum this route
allows (it scans raw LogScale events; a wider window is refused and the
ladder narrows it back to 7d). Returns tool usage records
(AgenticToolName, AgenticPath, CommandLine, aid). If the requested
window had to be narrowed, the result is ` + "`{results, notices}`" + ` instead
of a bare list; read ` + "`notices`" + ` before reporting counts.`

const searchExecutionsDescription = `List AI agent process executions, with the model and token counts for each.

This is the only Guardian tool that reports token usage
(` + "`AgenticInputTokens`" + ` / ` + "`AgenticOutputTokens`" + `), so use it for any question
about tokens consumed, model cost, or which model a process ran. It is
backed by LogScale ` + "`AgenticSessionStart`" + ` events, so each row is one
process a session spawned, carrying the model, the token counts, the
working directory, a flat ` + "`AgenticSessionId`" + ` and the host ` + "`aid`" + `. That also
makes it the only way to see the sessions on a given host — pass ` + "`aid`" + ` —
because the agent-sessions entity has no host filter at all. The default
window is 2 hours, so widen ` + "`time_range`" + ` explicitly for older activity, up
to the 7 days this route allows — it scans raw LogScale events, and a
wider window is refused, after which the retry ladder narrows it back to
7d and reports the change in ` + "`notices`" + `.`

const searchPromptsDescription = `Search for AI prompts within a session (LogScale AgenticUserPromptSubmit).

Use this to retrieve prompt content for a specific session; the
default window is 2 hours, so widen ` + "`time_range`" + ` explicitly to reach
older prompts, up to the 7-day maximum this route allows (it scans raw
LogScale events; a wider window is refused and the ladder narrows it back
to 7d). Returns prompt records including ` + "`AgenticPrompt`" + `,
` + "`AgenticSessionId`" + `, ` + "`aid`" + `, and a ` + "`timestamp`" + ` that is epoch
milliseconds encoded as a string — see
falcon://guardian/inventory/schema-guide for the full field
reference. If the requested window had to be narrowed, the result is
` + "`{results, notices}`" + ` instead of a bare list.`

const getInventoryDescription = `Get a summary overview of AI activity in your environment.

Use this for a high-level fleet snapshot: agent counts by product,
session counts by product, top tools by name, and a detection summary.
` + "`agents.by_product`" + ` counts AGENTS while ` + "`sessions.by_product`" + ` counts
logical AIAgentSession rows — different metrics, so do not relabel one
as the other. Both product buckets are keyed by the friendly product
name (e.g. "Claude Code") when the API resolves the tag, falling back to
the numeric tag ID for unrecognized products. Read ` + "`notices`" + ` before
reporting any count.`

const searchSkillsDescription = `List AI skill frontmatters (AISkillFrontmatterView entity).

Use this for the fleet-wide inventory of skills. Each row carries
` + "`SkillName`" + `, ` + "`SkillDescription`" + `, and the seen timestamps; the endpoint
has no agent_id filter. For per-invocation skill events, use
search_guardian_skill_usage instead.`

const searchSkillUsageDescription = `List per-invocation AI skill events (LogScale AgenticToolRequest).

Use this for the session-scoped grain of skill invocations
(` + "`AgenticSkill`" + `, ` + "`AgenticSessionId`" + `, ` + "`aid`" + `), distinct from the
AISkillFrontmatter inventory (search_guardian_skills). The default
window is 2 hours, so widen ` + "`time_range`" + ` explicitly for older activity,
up to the 7-day maximum this route allows (it scans raw LogScale events;
a wider window is refused and the ladder narrows it back to 7d).`

const getFleetSkillInventoryDescription = `Get a fleet-wide skill usage rollup by name (AISkill aggregate).

Use this to see which skills are most used, optionally filtered by name
pattern. Returns grouped ` + "`{SkillName, count}`" + ` buckets. This is an
aggregate with no server-side pagination; ` + "`limit`" + ` is applied
client-side. For the per-skill records, use search_guardian_skills
instead.`

const searchOSUsersDescription = `List OS users that have run AI agents (AIAgentOSUser entity).

Use this to find which OS accounts ran agents, by sensor, username, or
AD ObjectSid.`

const pivotDescription = `Pivot from a known attribute value to the agents or activity carrying it.

Use this to pivot from a known attribute to the agents (or activity)
with that value:

- ` + "`Product`" + ` — agents of a product (value normalized like
  search_guardian_agents).
- ` + "`HostName`" + ` — agents on a host.
- ` + "`Skill`" + ` — skill frontmatters matching a name pattern (substring).
- ` + "`Name`" + ` — merges per-invocation skill-usage and tool-usage, deduped
  by sensor (` + "`aid`" + `); rows without an ` + "`aid`" + ` are all kept.

Returns matching agents or activity rows with pagination metadata for
every branch.`

const getProcessTreeDescription = `Get the spawned process tree for an AI session.

Use this to see what processes an AI session launched. Returns process
tree with command lines, image filenames, and timestamps.`

const getNetworkEventsDescription = `Get outbound network connections from an AI session's processes.

Use this to see what network activity an AI session generated.
Returns destination IPs, ports, protocols, and timestamps.`

const getFileEventsDescription = `Get file activity for processes spawned from an AI session.

Use this to see files written by spawned processes and file tool
usage; use ` + "`sensitive_only`" + ` to filter to credential and secret paths.
Returns combined file events from the graph and inventory layers.
The graph leg has no time dimension; ` + "`time_range`" + ` applies only to
the tool-usage leg, which defaults to 2 hours.`

const getClassifiedFileAccessDescription = `Get classified/sensitive file access for an AI agent process.

Use this to see which files a process accessed that Falcon Data
Protection (FDP) classified, and whether it triggered a data
protection policy violation. Returns data pattern categories (PII,
credentials, etc.), classification policy names, rule actions
(allowed/blocked), and individual file details (path, name, SHA256,
timestamps).`

const generateReportDescription = `Generate a structured Guardian report.

Use this to produce fleet_summary, agent_detail, skill_threat, or
sensitive_access reports; agent_detail requires agent_id.
` + "`time_range`" + ` applies only to fleet_summary and sensitive_access; the
other two types use their own per-leg windows. Returns a structured
report with timestamp and data.`

const searchDetectionsDescription = `List detections involving AI agent processes.

Use this to find security detections (alerts) that involved an AI
agent; every row is agent-related, scoped server-side and not
client-controllable. ` + "`agent_id`" + ` takes the 32-hex SENSOR/host ID
(` + "`== AIAgent.SensorId`/`aid`" + `), NOT the 64-hex ` + "`AIAgent.Id`" + ` — passing
the latter returns zero rows with no error, and because it identifies
a host, a detection cannot be pinned to one agent on a multi-agent
host. See falcon://guardian/events/query-guide for the full field
reference and a ` + "`product`" + ` filter trap: it takes the product name,
not the numeric tag value the API itself returns in responses.`

const getDetectionScoresDescription = `Get the Agentic Threat Score for each agent.

Returns rows of ` + "`{AgentId, AgenticProductTag, maxDetectionScore}`" + `.
Joining these onto agents needs BOTH ` + "`AgentId == AIAgent.SensorId`" + `
AND ` + "`AgenticProductTag == AIAgent.AgentProduct`" + `, because ` + "`AgentId`" + `
identifies a HOST and a host usually runs several AI agents; most
rows leave the product tag unattributed, so an exact join resolves
few agents (the agent_detail report handles that fallback and labels
the result host-scoped). ` + "`offset`" + ` is silently ignored here and the
grouping caps at 500 groups; see falcon://guardian/events/query-guide
for the join details and read ` + "`notices`" + ` before treating this as
fleet-complete.`

const searchInstallsDescription = `List AI agent installations (AIAgentInstallationView entity).

Use this to find install records by sensor, product, or hostname.
Returns ` + "`Id`" + `, ` + "`SensorId`" + `, ` + "`Hostname`" + `, ` + "`AgentName`" + `, ` + "`AgentProduct`" + `,
` + "`AgentVersion`" + `, ` + "`InstallSource`" + `, ` + "`AgentDeclarationPath`" + `, ` + "`BinaryPath`" + `,
` + "`FileSha256`" + `, ` + "`LastExecutionTime`" + `, and the seen timestamps — see
falcon://guardian/inventory/schema-guide for the full field reference.`

const searchModelsDescription = `List AI model names (AIModelName entity).

Returns the human-friendly model name in ` + "`Cim.AIModelName.modelName`" + `
(the ` + "`Id`" + ` is only a hashed dedup key) and the seen timestamps. There is
no name/product/sensor scalar to filter on, so the only server-side
filter is ` + "`time_range`" + ` on LastSeen. For the model used per session,
prefer get_guardian_agent_sessions (its
` + "`Cim.AIAgentSession.modelsInvoked`" + `) or search_guardian_executions (its
` + "`AgenticModel`" + `). This tool reports no usage volume — for per-process
model plus token counts (` + "`AgenticInputTokens`/`AgenticOutputTokens`" + `), use
search_guardian_executions.`

// agentSessionsHint is the advisory note attached to a get_guardian_agent_sessions
// result. The rows invite two wrong counts, so it names both and the query that
// answers each.
const agentSessionsHint = "These rows are fleet-wide and cannot be tied to one agent or " +
	"host, because this entity has no agent or host filter. So two counts are not " +
	"derivable here: a single agent's session total (use search_guardian_executions(aid=...), " +
	"the host-scoped session grain) and a per-agent ranking, which does not exist anywhere in " +
	"this API. `Product` names the software and many agents share a product, so grouping these " +
	"rows by `Product`/`ProductName` counts products rather than agents; for a ready-made " +
	"product rollup use `sessions.by_product` from get_guardian_inventory."
