<!-- meta:title IOC -->
<!-- meta:description Search, create, and delete custom Falcon IOCs (indicators of compromise) -->
<!-- meta:section modules -->
<!-- meta:link-base /falcon-mcp/ -->
<!-- frontmatter:sidebar order:10 -->

Search, create, and delete custom Falcon IOCs (indicators of compromise)

## API Scopes

- `IOC Management:read`
- `IOC Management:write`

## Tools

### `falcon_search_iocs`

**Required scopes:** `IOC Management:read`

Search custom IOCs in CrowdStrike Falcon using IOC FQL (fields: type, value, action, source, severity_number, expiration, expired, applied_globally, metadata.filename.raw). Consult falcon://ioc/search/fql-guide before constructing filter expressions. Returns full indicator records.
Responses include `pagination.total` (the total number of records matching the filter, or null when the API does not report a count) — use it to answer "how many" questions. For cursor-based paging, use `pagination.next` as the `after` parameter on the next call.

**Example prompts:**

- "Find all active domain IOCs"
- "Show me SHA256 hash IOCs with prevent action"

### `falcon_add_ioc`

> [!NOTE]
> This tool modifies data.

**Required scopes:** `IOC Management:write`

Create one or more custom IOCs. Provide type/value (plus optional action, severity, expiration, etc.) for a single IOC, or a bulk indicators array. Returns the created indicator records.

**Example prompts:**

- "Block the domain evil.example.com"
- "Add a SHA256 hash IOC with prevent action"

### `falcon_remove_iocs`

> [!CAUTION]
> This tool performs destructive operations.

**Required scopes:** `IOC Management:write`

Delete custom IOCs by IDs or FQL filter. If both are given, filter takes precedence. Returns the deleted IOC IDs. Idempotent.

**Example prompts:**

- "Delete IOC with ID abc123"
- "Remove all expired IOCs"

## Resources

- **`falcon://ioc/search/fql-guide`**: Contains the guide for the `filter` param of the `falcon_search_iocs` tool.
