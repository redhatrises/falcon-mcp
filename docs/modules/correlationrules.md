<!-- meta:title Correlation Rules -->
<!-- meta:description Search, create, update, and delete NG-SIEM correlation rules -->
<!-- meta:section modules -->
<!-- meta:link-base /falcon-mcp/ -->
<!-- frontmatter:sidebar order:10 -->

Search, create, update, and delete NG-SIEM correlation rules

## API Scopes

- `Correlation Rules:read`
- `Correlation Rules:write`

## Tools

### `falcon_search_correlation_rules`

**Required scopes:** `Correlation Rules:read`

Search NG-SIEM correlation rules by name, status, severity, or MITRE tactic/technique. Consult falcon://correlation-rules/search/fql-guide before constructing filter expressions. Returns full rule objects; use the `rule_id` field when passing results to update or delete tools. Filter with state:'published' to get one result per rule. Responses include `pagination.total` (the total number of records matching the filter, or null when the API does not report a count) — use it to answer "how many" questions.

**Example prompts:**

- "Show me all active high-severity correlation rules"
- "Find correlation rules covering lateral movement tactics"

### `falcon_create_correlation_rule`

> [!NOTE]
> This tool modifies data.

**Required scopes:** `Correlation Rules:write`

Create a new NG-SIEM correlation rule that wraps a user-provided CQL query as a scheduled detection rule. Validate the CQL query against NG-SIEM before creating the rule. Returns the created rule record.

**Example prompts:**

- "Create a correlation rule using this CQL query: #event_simpleName=ProcessRollup2 | CommandLine=*-EncodedCommand*"

### `falcon_update_correlation_rule`

> [!NOTE]
> This tool modifies data.

**Required scopes:** `Correlation Rules:write`

Update an existing NG-SIEM correlation rule and auto-publish a new version (no separate publish step). To enable/disable a rule, set status to 'active' or 'inactive'. Only provided fields are changed; omitted fields retain current values.

**Example prompts:**

- "Disable the correlation rule — set its status to inactive"
- "Update the rule severity to critical (90)"

### `falcon_delete_correlation_rules`

> [!CAUTION]
> This tool performs destructive operations.

**Required scopes:** `Correlation Rules:write`

Permanently delete NG-SIEM correlation rules by rule ID, removing the rules and all their versions. This action cannot be undone — use falcon_search_correlation_rules to confirm IDs before deleting. Returns an empty list on success.

**Example prompts:**

- "Delete the test correlation rule we created"

## Resources

- **`falcon://correlation-rules/search/fql-guide`**: Contains the guide for the `filter` param of the `falcon_search_correlation_rules` tool.
