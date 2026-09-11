<!-- meta:title Real Time Response -->
<!-- meta:description Initiate and inspect Real Time Response sessions, run read-only RTR commands during host investigations, and audit and summarize RTR activity -->
<!-- meta:section modules -->
<!-- meta:link-base /falcon-mcp/ -->
<!-- frontmatter:sidebar order:10 -->

Initiate and inspect Real Time Response sessions, run read-only RTR commands during host investigations, and audit and summarize RTR activity

> [!NOTE]
> This module is not available on CrowdStrike's hosted Falcon MCP; it is only available when self-hosting this server. See [module overview](/falcon-mcp/modules/overview/#crowdstrike-hosted-mcp-differences).

## API Scopes

- `Real time response:read`
- `real-time-response-audit:read`
- `Real time response:write`

## Tools

### `falcon_search_rtr_sessions`

**Required scopes:** `Real time response:read`

Search RTR sessions in your CrowdStrike environment by hostname, agent ID, user, origin, or creation time. Consult falcon://rtr/sessions/search/fql-guide before constructing filter expressions. Returns full session details including host info, commands executed, and status.
Responses include `pagination.total` (the total number of records matching the filter, or null when the API does not report a count) — use it to answer "how many" questions.

**Example prompts:**

- "Find all active RTR sessions"
- "Show me RTR sessions for host abc123"

### `falcon_search_rtr_audit_sessions`

**Required scopes:** `real-time-response-audit:read`

Search RTR audit sessions for accountability and timeline evidence: who used RTR, when, against which host, and optionally which command activity Falcon recorded. This is read-only audit visibility; it does not open sessions or run commands. Consult falcon://rtr/audit/sessions/search/fql-guide before constructing filter expressions.
Responses include `pagination.total` (the total number of records matching the filter, or null when the API does not report a count) — use it to answer "how many" questions.

**Example prompts:**

- "Show me RTR audit activity from the last 7 days"
- "Who used RTR against host BRR-WB-LIB-22?"

### `falcon_aggregate_rtr_sessions`

**Required scopes:** `Real time response:read`

Summarize RTR session activity with Falcon aggregation buckets. Use this before detailed searches when the user asks which hosts, users, origins, commands, or time windows account for RTR activity. Consult falcon://rtr/sessions/aggregate-guide. Returns aggregation buckets, not individual session records.

**Example prompts:**

- "Summarize RTR sessions by command for the last 30 days"
- "Which hosts have the most RTR activity this week?"

### `falcon_get_rtr_session_details`

**Required scopes:** `Real time response:read`

Retrieve full details for the given RTR session IDs. Use when you already have session IDs from search results; to discover sessions by criteria use falcon_search_rtr_sessions instead. Returns full session records.

**Example prompts:**

- "Get details for RTR session abc123"

### `falcon_init_rtr_session`

> [!NOTE]
> This tool modifies data.

**Required scopes:** `Real time response:read`

Initialize or reuse an RTR session for a single host, opening a live connection for executing read-only commands. Use queue_offline=true if the host may be offline. Returns session records containing the session_id needed for subsequent commands.

**Example prompts:**

- "Start an RTR session on host xyz"

### `falcon_pulse_rtr_session`

> [!NOTE]
> This tool modifies data.

**Required scopes:** `Real time response:read`

Refresh an RTR session timeout for a single host, keeping an existing session alive by resetting its inactivity timer. Use this to prevent session expiration during long investigations.

**Example prompts:**

- "Refresh the RTR session to keep it alive"

### `falcon_execute_rtr_read_only_command`

> [!NOTE]
> This tool modifies data.

**Required scopes:** `Real time response:read`

Execute a read-only RTR command on a single host, limited to hunt-and-triage commands (ls, ps, cat, filehash, reg). Does not expose admin or remediation commands. Returns command records containing a cloud_request_id for polling output via falcon_check_rtr_command_status.

**Example prompts:**

- "Run 'ps' on this host via RTR"
- "List running processes on host xyz"

### `falcon_run_rtr_read_only_command_and_wait`

> [!NOTE]
> This tool modifies data.

**Required scopes:** `Real time response:read`

Execute a read-only RTR command and poll until completion, accumulating output chunks into one result. Use this for simple, focused evidence collection when you want the command output directly and do not need to manage a cloud_request_id. Limited to read-only commands; it does not expose RTR admin or remediation APIs.

**Example prompts:**

- "Run 'ps' via RTR and return the output when it completes"
- "Check C:\Windows\win.ini on this RTR session and wait for the result"

### `falcon_check_rtr_command_status`

**Required scopes:** `Real time response:read`

Get the status and output for an RTR command execution. Poll this after falcon_execute_rtr_read_only_command to retrieve command output; use sequence_id to paginate through large output chunks. Returns status records with stdout, stderr, and a complete flag.

**Example prompts:**

- "Check the status of RTR command request abc123"

### `falcon_list_rtr_session_files`

**Required scopes:** `Real time response:write`

List files extracted during an RTR session, such as files pulled with the get command. Returns file metadata for artifacts captured during the session.

**Example prompts:**

- "List files extracted during RTR session abc123"

### `falcon_delete_rtr_session`

> [!CAUTION]
> This tool performs destructive operations.

**Required scopes:** `Real time response:read`

Close an RTR session and release the host connection. Use this when the investigation is complete to free session resources. Idempotent.

**Example prompts:**

- "End the RTR session abc123"

## Resources

- **`falcon://rtr/sessions/search/fql-guide`**: Contains the guide for the `filter` param of the `falcon_search_rtr_sessions` tool.
- **`falcon://rtr/audit/sessions/search/fql-guide`**: Contains the guide for the `filter` param of the `falcon_search_rtr_audit_sessions` tool.
- **`falcon://rtr/sessions/aggregate-guide`**: Explains how to summarize RTR session activity with the `falcon_aggregate_rtr_sessions` tool.
- **`falcon://rtr/workflows/investigation-guide`**: Provides a safe read-only RTR workflow for endpoint investigation tools.
