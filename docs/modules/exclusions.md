<!-- meta:title Exclusions -->
<!-- meta:description Search, create, update, and delete Falcon exclusions across four types — IOA, machine learning, sensor visibility, and certificate-based — behind a single exclusion_type discriminator -->
<!-- meta:section modules -->
<!-- meta:link-base /falcon-mcp/ -->
<!-- frontmatter:sidebar order:10 -->

Search, create, update, and delete Falcon exclusions across four types — IOA, machine learning, sensor visibility, and certificate-based — behind a single exclusion_type discriminator

## API Scopes

- `IOA Exclusions:read`
- `Machine Learning Exclusions:read`
- `Sensor Visibility Exclusions:read`
- `IOA Exclusions:write`
- `Machine Learning Exclusions:write`
- `Sensor Visibility Exclusions:write`

## Tools

### `falcon_search_exclusions`

**Required scopes:** `IOA Exclusions:read`, `Machine Learning Exclusions:read`, `Sensor Visibility Exclusions:read`

Search IOA, machine learning, sensor visibility, or certificate-based exclusions by name, value, scope, or timestamp. Select which API is queried with exclusion_type. Consult falcon://exclusions/search/fql-guide before constructing filter expressions — the available fields differ per type. Returns full exclusion records including id, scope, and timestamps. Responses include `pagination.total` (the total number of records matching the filter, or null when the API does not report a count) — use it to answer "how many" questions.

**Example prompts:**

- "Show me my most recent IOA and machine learning exclusions"
- "List sensor visibility exclusions created in the last 7 days"

### `falcon_create_exclusion`

> [!NOTE]
> This tool modifies data.

**Required scopes:** `IOA Exclusions:write`, `Machine Learning Exclusions:write`, `Sensor Visibility Exclusions:write`

Create an exclusion of the given exclusion_type. 'ioa' needs name, pattern_id, ifn_regex, and cl_regex; 'ml' and 'sensor_visibility' need value (sensor_visibility also needs host_groups); 'certificate' needs name, certificate, and status. applied_globally is honored only for 'ml' and 'certificate'; the 'ioa' and 'sensor_visibility' APIs have no such field, so applied_globally:true is rejected for those types rather than silently narrowing the exclusion's scope — use host_groups instead. Returns the created exclusion record(s).

**Example prompts:**

- "Create an ML exclusion for /tmp/foo.sh applied to all hosts"
- "Add a sensor visibility exclusion for C:\Temp\* on the Workstations group"

### `falcon_update_exclusion`

> [!NOTE]
> This tool modifies data.

**Required scopes:** `IOA Exclusions:write`, `Machine Learning Exclusions:write`, `Sensor Visibility Exclusions:write`

Update an existing exclusion of the given exclusion_type. Provide the id plus the same fields used when creating that type. All four types update via HTTP PATCH. As with create, applied_globally:true is rejected for 'ioa' and 'sensor_visibility'. Returns the updated exclusion record(s).

**Example prompts:**

- "Update IOA exclusion abc123 to also match a new command line regex"

### `falcon_delete_exclusions`

> [!CAUTION]
> This tool performs destructive operations.

**Required scopes:** `IOA Exclusions:write`, `Machine Learning Exclusions:write`, `Sensor Visibility Exclusions:write`

Delete one or more exclusions of the given exclusion_type by ID, with an optional audit comment. Idempotent.

**Example prompts:**

- "Delete the certificate exclusion with ID abc123"

### `falcon_get_certificate_details`

**Required scopes:** `Machine Learning Exclusions:read`

Retrieve the code-signing certificate metadata for a file by SHA256 (issuer, subject, serial, thumbprint, validity window). Use this as the pre-flight lookup before building a certificate-based exclusion, then pass the result as the certificate argument to falcon_create_exclusion. Returns certificate metadata for the given hash.

**Example prompts:**

- "Look up the signing certificate for SHA256 3dd9a..."

## Resources

- **`falcon://exclusions/search/fql-guide`**: Contains the guide for the `filter` param of the `falcon_search_exclusions` tool.
