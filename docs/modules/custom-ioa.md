<!-- meta:title Custom IOA -->
<!-- meta:description Search, create, update, and delete Custom IOA (Indicators of Attack) behavioral detection rules and rule groups -->
<!-- meta:section modules -->
<!-- meta:link-base /falcon-mcp/ -->
<!-- frontmatter:sidebar order:10 -->

Search, create, update, and delete Custom IOA (Indicators of Attack) behavioral detection rules and rule groups

## API Scopes

- `Custom IOA Rules:read`
- `Custom IOA Rules:write`

## Tools

### `falcon_search_ioa_rule_groups`

**Required scopes:** `Custom IOA Rules:read`

Search Custom IOA rule groups by platform, name, or enabled state, and return their contained behavioral detection rules. Consult falcon://custom-ioa/rule-groups/fql-guide before constructing filter expressions. Returns full rule group records including their rules. Responses include `pagination.total` (the total number of records matching the filter, or null when the API does not report a count) — use it to answer "how many" questions.

**Example prompts:**

- "Find enabled Windows Custom IOA rule groups"

### `falcon_get_ioa_platforms`

**Required scopes:** `Custom IOA Rules:read`

Get the platforms available for Custom IOA rule groups. Use this to discover valid platform values (windows, mac, linux) before creating a rule group. Returns the platform identifiers.

**Example prompts:**

- "What platforms are available for Custom IOA rule groups?"

### `falcon_get_ioa_rule_types`

**Required scopes:** `Custom IOA Rules:read`

Get the Custom IOA rule types available in your environment. Use this to discover valid rule type IDs, required fields, and disposition IDs before creating a behavioral detection rule. Returns rule type details including platform, fields, and dispositions.

**Example prompts:**

- "What Custom IOA rule types are available?"

### `falcon_create_ioa_rule_group`

> [!NOTE]
> This tool modifies data.

**Required scopes:** `Custom IOA Rules:write`

Create a Custom IOA rule group, a platform-scoped container for behavioral detection rules. Use falcon_get_ioa_platforms for valid platform values, then falcon_create_ioa_rule to add rules. Returns the created group.

**Example prompts:**

- "Create a Windows IOA rule group named 'Suspicious PowerShell Activity'"

### `falcon_update_ioa_rule_group`

> [!NOTE]
> This tool modifies data.

**Required scopes:** `Custom IOA Rules:write`

Update a Custom IOA rule group's name, description, or enabled state. Requires the current rulegroup_version for optimistic locking — get it from falcon_search_ioa_rule_groups. Returns the updated group.

**Example prompts:**

- "Disable IOA rule group abc123"

### `falcon_delete_ioa_rule_groups`

> [!CAUTION]
> This tool performs destructive operations.

**Required scopes:** `Custom IOA Rules:write`

Permanently delete Custom IOA rule groups by ID, removing all rules within them. Use falcon_search_ioa_rule_groups to find rule group IDs. Idempotent.

**Example prompts:**

- "Delete Custom IOA rule groups abc123 and def456"

### `falcon_create_ioa_rule`

> [!NOTE]
> This tool modifies data.

**Required scopes:** `Custom IOA Rules:write`

Create a Custom IOA behavioral detection rule within a rule group. Use falcon_get_ioa_rule_types first to discover rule type IDs, required fields, and valid disposition IDs. The field_values define the behavioral matching criteria. Returns the created rule.

**Example prompts:**

- "Add a process creation rule to IOA group abc123 that detects cmd.exe spawned from Word"

### `falcon_update_ioa_rule`

> [!NOTE]
> This tool modifies data.

**Required scopes:** `Custom IOA Rules:write`

Update a Custom IOA behavioral detection rule. Requires the rule group's current rulegroup_version and the rule instance_id — get both from falcon_search_ioa_rule_groups. Returns the updated rule.

**Example prompts:**

- "Enable IOA rule instance abc in group xyz"

### `falcon_delete_ioa_rules`

> [!CAUTION]
> This tool performs destructive operations.

**Required scopes:** `Custom IOA Rules:write`

Delete Custom IOA behavioral detection rules from a rule group by rule instance ID. Use falcon_search_ioa_rule_groups to find the rule group ID and rule instance IDs. Idempotent.

**Example prompts:**

- "Delete rules from IOA group abc123"

## Resources

- **`falcon://custom-ioa/rule-groups/fql-guide`**: Contains the guide for the `filter` param of the `falcon_search_ioa_rule_groups` tool.
