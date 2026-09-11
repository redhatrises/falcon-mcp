<!-- meta:title Detections -->
<!-- meta:description Search, retrieve, and triage Falcon detections/alerts (EPP, IDP, XDR, OverWatch, NG-SIEM) -->
<!-- meta:section modules -->
<!-- meta:link-base /falcon-mcp/ -->
<!-- frontmatter:sidebar order:10 -->

Search, retrieve, and triage Falcon detections/alerts (EPP, IDP, XDR, OverWatch, NG-SIEM)

## API Scopes

- `Alerts:read`
- `Alerts:write`

## Tools

### `falcon_search_detections`

**Required scopes:** `Alerts:read`

Search for detections/alerts in CrowdStrike Falcon using FQL. Use this to discover detections by severity, status, hostname, time range, or other attributes — the general tool for alert and detection queries. Covers alerts across all Falcon products: endpoint (EPP), identity (IDP), XDR, OverWatch, and NG-SIEM. Consult falcon://detections/search/fql-guide before constructing filter expressions. Returns full alert records including process context, device info, tactic/technique details, and threat classification. Responses include `pagination.total` (the total number of records matching the filter, or null when the API does not report a count) — use it to answer "how many" questions.

**Example prompts:**

- "Show me new high severity detections from the last 7 days"
- "Find all unassigned critical detections"

### `falcon_get_detection_details`

**Required scopes:** `Alerts:read`

Retrieve full details for detection/alert composite IDs you already have. Use when you have specific composite ID(s); for discovering detections by criteria (severity, status, hostname, etc.) use falcon_search_detections instead. Returns full detection records; alerts hidden from the Falcon UI are omitted when include_hidden is false.

**Example prompts:**

- "Get me the details for this detection"

### `falcon_aggregate_detections`

**Required scopes:** `Alerts:read`

Count and summarize detections (also called alerts) without retrieving each record. Use this for "how many" and "top N" questions — alerts per severity, status, tactic, or host, distinct host counts, and alert volume over time — instead of paging through falcon_search_detections. Consult falcon://detections/search/fql-guide before constructing filter expressions. Returns one aggregation per request holding `buckets`, which key on `label` with a `count`; single-value aggregations (`cardinality`, `max`, `min`, `avg`, `sum`) report their answer as `value` instead.

**Example prompts:**

- "How many detections do we have by severity?"
- "What are the top 10 hosts by alert count this week?"
- "Show me alert volume per day for the last 30 days"
- "How many distinct hosts have critical alerts?"

### `falcon_update_detections`

> [!NOTE]
> This tool modifies data.

**Required scopes:** `Alerts:write`

Update the status, assignment, UI visibility, comments, and tags of one or more detections/alerts. Change status (new, in_progress, reopened, closed); assign by UUID, user id, or full name, or unassign; append a comment; show or hide in the UI; or add/remove tags. Resolution is tag-based — the conventional tags true_positive, false_positive, or ignored populate the console's Resolution view, so closing without one returns a hint. At least one update field beyond ids is required. Requests over 1000 detection IDs are chunked automatically; if a later chunk fails after earlier ones applied, the result carries a partial_success block listing the updated and failed/remaining ids so only the remainder need be retried.

**Example prompts:**

- "Mark detection abc123 as in_progress"
- "Assign detection abc123 to analyst@example.com"
- "Close these detections and add a comment: resolved via playbook"
- "Mark detection abc123 as a true positive and close it"
- "Remove all fc/ prefixed tags from this detection"

## Resources

- **`falcon://detections/search/fql-guide`**: Contains the guide for the `filter` param of the `falcon_search_detections` tool.
