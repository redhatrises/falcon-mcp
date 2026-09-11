<!-- meta:title Host Groups -->
<!-- meta:description Search, create, update, and delete Falcon host groups and manage their membership -->
<!-- meta:section modules -->
<!-- meta:link-base /falcon-mcp/ -->
<!-- frontmatter:sidebar order:10 -->

Search, create, update, and delete Falcon host groups and manage their membership

## API Scopes

- `Host Groups:read`
- `Host Groups:write`

## Tools

### `falcon_search_host_groups`

**Required scopes:** `Host Groups:read`

Search host groups in CrowdStrike Falcon using host-group FQL (fields: name, group_type, created_by, created_timestamp, modified_by, modified_timestamp). Consult falcon://host-groups/search/fql-guide before constructing filter expressions. Returns full group records.
Responses include `pagination.total` (the total number of records matching the filter, or null when the API does not report a count) — use it to answer "how many" questions.

**Example prompts:**

- "Show me all static host groups"
- "Find host groups created in the last 30 days"

### `falcon_search_host_group_members`

**Required scopes:** `Host Groups:read`

List the member devices of a host group. The filter and sort operate on HOST/DEVICE attributes (e.g. platform_name, hostname), not group attributes. Consult falcon://hosts/search/fql-guide before constructing filter expressions. Returns full host device records.
Responses include `pagination.total` (the total number of records matching the filter, or null when the API does not report a count) — use it to answer "how many" questions.

**Example prompts:**

- "List the Windows hosts in host group abc123"
- "Show me the members of the Production Servers group"

### `falcon_create_host_group`

> [!NOTE]
> This tool modifies data.

**Required scopes:** `Host Groups:write`

Create a host group of type static, staticByID, or dynamic. A dynamic group requires an assignment_rule (host FQL) that auto-includes matching hosts; the API rejects an assignment_rule on static and staticByID groups, which are created empty and populated afterwards via falcon_perform_host_group_action. Returns the created host group record.

**Example prompts:**

- "Create a static host group called 'Critical Servers'"
- "Create a dynamic host group for all Windows hosts"

### `falcon_update_host_group`

> [!NOTE]
> This tool modifies data.

**Required scopes:** `Host Groups:write`

Update an existing host group's name, description, or assignment_rule. name and description are safe for any group type; only set assignment_rule on dynamic groups. Unspecified fields are left unchanged. Returns the updated host group record.

**Example prompts:**

- "Rename host group abc123 to 'Decommissioned'"
- "Update the assignment rule for the dynamic Windows group"

### `falcon_delete_host_groups`

> [!CAUTION]
> This tool performs destructive operations.

**Required scopes:** `Host Groups:write`

Permanently delete one or more host groups by ID. This removes the groups only; the member hosts are not affected. Idempotent — deleting an already-absent group succeeds.

**Example prompts:**

- "Delete host group abc123"

### `falcon_perform_host_group_action`

> [!NOTE]
> This tool modifies data.

**Required scopes:** `Host Groups:write`

Add or remove hosts from static host groups. The filter selects which hosts to act on using HOST/DEVICE FQL (see the hosts FQL guide). Applies to static groups only.

**Example prompts:**

- "Add the hosts matching platform_name Windows to group abc123"
- "Remove host device xyz from host group abc123"

## Resources

- **`falcon://host-groups/search/fql-guide`**: Contains the guide for the `filter` param of the `falcon_search_host_groups` tool.
