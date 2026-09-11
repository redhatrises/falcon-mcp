<!-- meta:title Policies -->
<!-- meta:description Search and manage Falcon host-based policies across all six types — prevention, sensor update, firewall, device control, response, and content update — behind a single policy_type discriminator -->
<!-- meta:section modules -->
<!-- meta:link-base /falcon-mcp/ -->
<!-- frontmatter:sidebar order:10 -->

Search and manage Falcon host-based policies across all six types — prevention, sensor update, firewall, device control, response, and content update — behind a single policy_type discriminator

> [!NOTE]
> CrowdStrike's hosted Falcon MCP does not use these unified, `policy_type`-discriminated tools. It instead exposes six policy-type-specific variants of each tool below, suffixed by type (`_prevention`, `_sensor_update`, `_firewall`, `_device_control`, `_response`, `_content_update`) with no `policy_type` parameter — for example `falcon_search_policies` here corresponds to `falcon_search_policies_firewall`, `falcon_search_policies_prevention`, etc. on the hosted MCP. See [module overview](/falcon-mcp/modules/overview/#crowdstrike-hosted-mcp-differences).

## API Scopes

- `Content Update Policies:read`
- `Device Control Policies:read`
- `Firewall Management:read`
- `Prevention Policies:read`
- `Response Policies:read`
- `Sensor Update Policies:read`
- `Content Update Policies:write`
- `Device Control Policies:write`
- `Firewall Management:write`
- `Prevention Policies:write`
- `Response Policies:write`
- `Sensor Update Policies:write`

## Tools

### `falcon_search_policies`

**Required scopes:** `Content Update Policies:read`, `Device Control Policies:read`, `Firewall Management:read`, `Prevention Policies:read`, `Response Policies:read`, `Sensor Update Policies:read`

Search host-based policies of a given type (prevention, sensor_update, firewall, device_control, response, or content_update) by name, platform, enabled state, or timestamp. Select which policy API is queried with policy_type. Consult falcon://policies/search/fql-guide before constructing filter expressions — the name match operator differs per type. Returns full policy records including id, name, platform_name, enabled, settings, and assigned host groups.
Responses include `pagination.total` (the total number of records matching the filter, or null when the API does not report a count) — use it to answer "how many" questions.

**Example prompts:**

- "List all firewall policies"
- "Show enabled sensor update policies for Windows"
- "Find prevention policies whose name contains 'default'"

### `falcon_search_policy_members`

**Required scopes:** `Content Update Policies:read`, `Device Control Policies:read`, `Firewall Management:read`, `Prevention Policies:read`, `Response Policies:read`, `Sensor Update Policies:read`

List the host devices governed by a specific policy. Provide the policy_type and policy id; the filter and sort operate on HOST/DEVICE attributes, not policy attributes. Consult falcon://hosts/search/fql-guide before constructing filter expressions. Differs from falcon_search_policies (which returns the policy object) and falcon_search_host_group_members (one group's hosts). Returns full host device records.
Responses include `pagination.total` (the total number of records matching the filter, or null when the API does not report a count) — use it to answer "how many" questions.

**Example prompts:**

- "What hosts are assigned to firewall policy 1a2b3c?"

### `falcon_create_policy`

> [!NOTE]
> This tool modifies data.

**Required scopes:** `Content Update Policies:write`, `Device Control Policies:write`, `Firewall Management:write`, `Prevention Policies:write`, `Response Policies:write`, `Sensor Update Policies:write`

Create a host-based policy of the given policy_type. Provide a name and (for every type except content_update) a platform_name. Detailed per-type settings construction is out of scope; prefer cloning an existing policy with clone_id then adjusting via falcon_update_policy. New policies are created disabled. Returns the created policy record.

**Example prompts:**

- "Create a disabled firewall policy named 'Test FW' for Windows"

### `falcon_update_policy`

> [!NOTE]
> This tool modifies data.

**Required scopes:** `Content Update Policies:write`, `Device Control Policies:write`, `Firewall Management:write`, `Prevention Policies:write`, `Response Policies:write`, `Sensor Update Policies:write`

Update an existing host-based policy of the given policy_type. Provide the policy id plus any fields to change (name, description, settings). platform_name is not updatable after creation. Uses PATCH semantics — unspecified fields are left unchanged. Returns the updated policy record.

**Example prompts:**

- "Rename prevention policy 1a2b3c to 'Servers - Strict'"

### `falcon_delete_policies`

> [!CAUTION]
> This tool performs destructive operations.

**Required scopes:** `Content Update Policies:write`, `Device Control Policies:write`, `Firewall Management:write`, `Prevention Policies:write`, `Response Policies:write`, `Sensor Update Policies:write`

Permanently delete one or more host-based policies of the given policy_type by ID. A policy must usually be DISABLED before deletion (an enabled policy returns HTTP 400); disable it first with falcon_perform_policy_action. The Default policy of each type cannot be deleted. Idempotent.

**Example prompts:**

- "Delete firewall policy 1a2b3c"

### `falcon_perform_policy_action`

> [!NOTE]
> This tool modifies data.

**Required scopes:** `Content Update Policies:write`, `Device Control Policies:write`, `Firewall Management:write`, `Prevention Policies:write`, `Response Policies:write`, `Sensor Update Policies:write`

Perform an action on one or more policies of the given policy_type: enable/disable, attach/detach host groups or rule groups, or (content_update only) content overrides. action_name is validated per type. The add/remove-host-group and add/remove-rule-group actions require a group_id. Returns the updated policy records.

**Example prompts:**

- "Disable prevention policy 1a2b3c"
- "Add host group 9z8y7x to sensor update policy 1a2b3c"

### `falcon_set_policy_precedence`

> [!NOTE]
> This tool modifies data.

**Required scopes:** `Content Update Policies:write`, `Device Control Policies:write`, `Firewall Management:write`, `Prevention Policies:write`, `Response Policies:write`, `Sensor Update Policies:write`

Set the precedence (evaluation order) of policies for a platform. The ids list must be the COMPLETE ordered set of non-Default policies for the platform, highest precedence first; partial lists are rejected. platform_name is required for every type except content_update. Returns the API response.

**Example prompts:**

- "Set the precedence order of these Windows prevention policies: 1a2b3c, 4d5e6f, 7g8h9i"

## Resources

- **`falcon://policies/search/fql-guide`**: Contains the guide for the `filter` param of the `falcon_search_policies` tool.
