<!-- meta:title NGSIEM -->
<!-- meta:description Run search queries against CrowdStrike Next-Gen SIEM via its asynchronous job-based search API -->
<!-- meta:section modules -->
<!-- meta:link-base /falcon-mcp/ -->
<!-- frontmatter:sidebar order:10 -->

Run search queries against CrowdStrike Next-Gen SIEM via its asynchronous job-based search API

## API Scopes

- `NGSIEM:read`
- `NGSIEM:write`

## Tools

### `falcon_search_ngsiem`

**Required scopes:** `NGSIEM:read`, `NGSIEM:write`

Execute a CQL (CrowdStrike Query Language) query against CrowdStrike Next-Gen SIEM.

Use this to search security events, logs, and telemetry with CQL. CQL is a
pipe-based language (`filter | command | command`): start from a tag or field
filter (e.g. `#event_simpleName=ProcessRollup2`, `UserName=*`) and pipe into
commands like `groupBy([...], function=count())` and `sort()`; keep the time
range tight. Consult `falcon://ngsiem/search/cql-guide` to construct the query —
it has the pipe model, core commands, and working examples (distinct count, time
bucketing, regex match, filtering on an aggregate). Returns `results` with the
matching event records, `query_used` echoing what you sent, and `job` carrying
the run's `parsed_query`, `event_count`, `processed_events`, and `warnings`; on a
failure, timeout, or empty result it returns an error/empty dict carrying the CQL
guide. Note: the API does not return detailed CQL parser diagnostics — a
malformed query may error or silently return unexpected/empty results rather
than a helpful message, so a result is not proof the query parsed as intended.
Compare `job.parsed_query` against the query you sent before trusting the rows:
an unrecognized word becomes a free-text stage instead of an error, so
`| limit 5` parses as `| limit | 5`, ignores the 5 entirely, and returns the
API's default row cap with no error and no warning. Use `head(5)` to cap rows.
Search times out after FALCON_MCP_NGSIEM_TIMEOUT seconds (default: 300).

**Example prompts:**

- "Run this CQL query for the last 24 hours: #event_simpleName=ProcessRollup2"
- "Search NGSIEM for DNS events from January 2025"

## Resources

- **`falcon://ngsiem/search/cql-guide`**: Contains the CQL authoring guide for the `query_string` param of the `falcon_search_ngsiem` tool.
