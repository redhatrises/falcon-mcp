# AI Entity Field Reference (Agentic Graph Layer)

## Reading the graph

Two shapes catch every caller out.

⚠️ **Vertices key on `__id`, never `Id`.** There is no `Id` field anywhere in the
graph. The tables below name `__id` for that reason.

⚠️ **An edge wraps its target under a differently-named key.** The edge key comes
from the table of outgoing edges (`UsedToolAitool`), but the vertex inside sits
under a short key (`AiTool`), alongside an `EventCloudTime` for the edge itself.
So the path is `UsedToolAitool[].AiTool`, not `UsedToolAitool[].AiToolVertex`. The
short keys are `AiTool`, `AiSkill`, `AiModel`, `McpServer` and `Process`.

⚠️ **Several vertices carry an enum ordinal where you expect a name**, and the
graph holds nothing that resolves it. Each one is called out below. Read names
from the flat `tools` / `skills` / `executions` keys of the same
`get_guardian_session_detail` response instead — those come from the event store
and do carry names.

## AiAgentVertex

⚠️ **Not populated.** The `SessionRunByAiagent` edge is present, but the `AiAgent`
object inside it comes back empty. This vertex has no usable fields, so no
per-agent join is possible through the graph — the same wall the removed
reverse-relationship arrays leave you at. For the agent record, call
`search_guardian_agents` or `get_guardian_agent`.

## AiSessionVertex

| Field | Description |
|-------|-------------|
| `__id` | Vertex ID (format: `aisess:{aid}:{session_uuid}`) |
| `DisplayName` | Same string as `__id` |
| `AgenticProduct` | ⚠️ **An integer enum ordinal, not a name.** The graph layer is no better than the LogScale event here, and nothing in the graph maps the ordinal to a product. Use `Product` / `ProductName` from `get_guardian_agent_sessions` instead — you already hold that row, because its `sessionId` is what you passed to fetch this graph. |
| `AgenticSessionId` | Session UUID |

### Outgoing Edges

| Edge | Target | Description |
|------|--------|-------------|
| `UsedToolAitool` | AiToolVertex | Tools used during the session |
| `InvokesModelAimod` | AiModelVertex | Models invoked |
| `ConnectedMcpMcpsrv` | McpServerVertex | MCP servers connected |
| `LoadedSkillAiskill` | AiSkillVertex | Skills loaded |
| `SessionProcessPid` | ProcessVertex | Processes spawned by session |
| `SessionRunByAiagent` | AiAgentVertex | ⚠️ Present but empty — see AiAgentVertex |
| `ChildSessionAisess` | AiSessionVertex | Sub-agent child sessions (often null) |

## AiToolVertex

| Field | Description |
|-------|-------------|
| `__id` | Vertex ID (format: `aitool:{aid}:{session_uuid}\|{ordinal}`) |
| `DisplayName` | Same string as `__id`, so it also ends in the ordinal |
| `AgenticTool` | ⚠️ **An integer enum ordinal, not a name.** This vertex carries no tool name at all. Passing the ordinal to `tool_name` returns zero rows. For names, read the flat `tools` key of the same `get_guardian_session_detail` response, which carries `AgenticToolName` ("Bash", "Read", "apply_diff") next to the same `AgenticToolUseId`. |

## AiModelVertex

| Field | Description |
|-------|-------------|
| `__id` | Vertex ID (format: `aimod:{aid}:{model_name}`) |
| `DisplayName` | Same string as `__id` |
| `AgenticModel` | Model name/identifier (e.g., "claude-sonnet-4-6"). A real name, not an ordinal. |

## AiSkillVertex

| Field | Description |
|-------|-------------|
| `__id` | Vertex ID (format: `aiskill:{aid}:{session_uuid}\|{slug}`) |
| `DisplayName` | Same string as `__id` |
| `AgenticSkill` | Skill name (e.g., "git:pr-create"). A real name, not an ordinal. |

## McpServerVertex

| Field | Description |
|-------|-------------|
| `__id` | Vertex ID (format: `mcpsrv:{aid}:{session_uuid}\|{server_name}`) |
| `DisplayName` | Same string as `__id` |

⚠️ **No name field.** The server name is only the suffix after the final `|` in
`__id` / `DisplayName` — split on it to read the name. For a fleet-wide list, use
`search_guardian_mcp_servers`.

## ProcessVertex (bridged from AI sessions)

| Field | Description |
|-------|-------------|
| `__id` | Vertex ID (format: `pid:{aid}:{upid}`) |
| `DisplayName` | Same string as `__id` |
| `CommandLine` | Full command line of the process |
| `ImageFileName` | Executable path/name |
| `SHA256HashData` | SHA256 hash of the executable |
| `ProcessStartTime` | Process start timestamp |
| `ProcessEndTime` | Process end timestamp |
| `UserName` | User who ran the process |
| `UserUid` | ⚠️ **A list, not a scalar** — it is the outgoing edge below, and it comes back unresolved. Do not read a user ID from it. |
| `Tags` | Process tags |
| `NetworkConnectCount` | Number of network connections |
| `GenericFileWrittenCount` | Number of files written |
| `DnsRequestCount` | Number of DNS requests |
| `ParentProcessId` | Parent process ID |

⚠️ **Expect nulls.** Through `get_guardian_session_detail` this vertex arrives
flat, with none of the outgoing edges below resolved, and the timestamp, count and
user fields are commonly empty. Treat every field here as optional. For the
processes an AI session launched, `get_guardian_process_tree` walks the spawn tree
and returns command lines and image filenames directly.

Note: `MD5HashData` is NOT available on ProcessVertex — use ModuleVertex for MD5 hashes.

### Outgoing Edges from ProcessVertex

| Edge | Target | Description |
|------|--------|-------------|
| `ChildProcessPid` | ProcessVertex | Child processes (recursive) |
| `Ipv4Ip4` | Ipv4Vertex | IPv4 network connections |
| `AccessedWebWeb` | WebAccessVertex | HTTP/HTTPS web access |
| `PrimaryModuleMod` | ModuleVertex | Executable being run |
| `ModuleWrittenMod` | ModuleVertex | Files/binaries written by process |
| `UserUid` | UserIdVertex | OS user who ran the process |
| `UserSessionUses` | UserSessionVertex | User session that owns the process |

### Edge Properties: ProcessIpv4Ipv4 (network connection)

| Field | Description |
|-------|-------------|
| `RemoteAddressIP4` | Remote IP address |
| `RemotePort` | Remote port number |
| `LocalAddressIP4` | Local IP address |
| `LocalPort` | Local port number |
| `Protocol` | Protocol (TCP/UDP) |
| `ConnectionDirection` | Inbound/outbound |
| `ConnectionFlags` | Connection flags |
| `EventCloudTime` | When connection was observed |

### Edge Properties: ProcessModuleWrittenModule (file write)

| Field | Description |
|-------|-------------|
| `EventCloudTime` | When file was written |
| `IsOnNetwork` | Whether file is on a network path |
| `IsOnRemovableDisk` | Whether file is on removable media |

## Ipv4Vertex


| Field | Description |
|-------|-------------|
| `Id` | Vertex ID |
| `RemoteAddressIP4` | IP address |
| `LocalAddressIP4` | Local IP address |
| `RemoteIp` | Remote IP (alternate field) |

## ModuleVertex


| Field | Description |
|-------|-------------|
| `Id` | Vertex ID |
| `ImageFileName` | File name/path |
| `SHA256HashData` | SHA256 hash |
| `MD5HashData` | MD5 hash |
| `TargetFileName` | Target file path (for written files) |

## WebAccessVertex

| Field | Description |
|-------|-------------|
| `Id` | Vertex ID |
| `HostUrl` | URL accessed |

## UserIdVertex

Reached via `UserUid` edge from ProcessVertex.

| Field | Description |
|-------|-------------|
| `Id` | Vertex ID |
| `UserName` | OS username |
| `UserSid` | Security Identifier (SID) |
| `LogonDomain` | Active Directory / domain name |
| `UserIsAdmin` | Whether the user has admin privileges |
| `LogonType` | Logon type (interactive, service, etc.) |

## UserSessionVertex

Reached via `UserSessionUses` edge from ProcessVertex.

| Field | Description |
|-------|-------------|
| `Id` | Vertex ID |
| `UserName` | OS username |
| `UserSid` | Security Identifier (SID) |
| `LogonDomain` | Active Directory / domain name |
| `UserIsAdmin` | Whether the user has admin privileges |
| `LogonType` | Logon type |
| `RemoteAddressIP4` | Remote IP if session is from a remote login |

## Edge Properties (common to all edges)

| Field | Description |
|-------|-------------|
| `EventCloudTime` | When the edge was created (cloud timestamp) |
| `Id` | Edge ID |
| `__typename` | Edge type name |
