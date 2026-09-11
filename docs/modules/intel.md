<!-- meta:title Intel -->
<!-- meta:description Search Falcon threat intelligence: adversaries, indicators, reports, and MITRE ATT&CK profiles -->
<!-- meta:section modules -->
<!-- meta:link-base /falcon-mcp/ -->
<!-- frontmatter:sidebar order:10 -->

Search Falcon threat intelligence: adversaries, indicators, reports, and MITRE ATT&CK profiles

## API Scopes

- `Actors (Falcon Intelligence):read`
- `Indicators (Falcon Intelligence):read`
- `Reports (Falcon Intelligence):read`

## Tools

### `falcon_search_actors`

**Required scopes:** `Actors (Falcon Intelligence):read`

Research threat actors and adversary groups tracked by CrowdStrike intelligence using intel FQL (fields: name, actor_type, target_countries, target_industries, motivations, created_date, last_activity_date). Consult falcon://intel/actors/fql-guide before constructing filter expressions. Returns full actor profiles.
Responses include `pagination.total` (the total number of records matching the filter, or null when the API does not report a count) — use it to answer "how many" questions.

**Example prompts:**

- "Find threat actors targeting financial services"
- "Search for BEAR adversary groups"

### `falcon_search_indicators`

**Required scopes:** `Indicators (Falcon Intelligence):read`

Search threat indicators/IOCs from CrowdStrike intelligence using intel FQL (fields: type, indicator, malicious_confidence, malware_families, kill_chains, published_date, threat_types, vulnerabilities). Consult falcon://intel/indicators/fql-guide before constructing filter expressions. Returns full indicator details.
Responses include `pagination.total` (the total number of records matching the filter, or null when the API does not report a count) — use it to answer "how many" questions.

**Example prompts:**

- "Find intelligence IOCs of type domain published this year"

### `falcon_search_reports`

**Required scopes:** `Reports (Falcon Intelligence):read`

Search CrowdStrike intelligence publications and threat reports using intel FQL (fields: name, type, sub_type, actors, target_countries, target_industries, motivations, tags, created_date). Consult falcon://intel/reports/fql-guide before constructing filter expressions. Returns full report metadata.
Responses include `pagination.total` (the total number of records matching the filter, or null when the API does not report a count) — use it to answer "how many" questions.

**Example prompts:**

- "Find intelligence reports published in the last 30 days"

### `falcon_get_mitre_report`

**Required scopes:** `Actors (Falcon Intelligence):read`

Generate a MITRE ATT&CK report for a threat actor — its tactics, techniques, and procedures (TTPs). Accepts an actor name (e.g. 'WARP PANDA') or numeric ID. Format 'json' returns a parsed list; 'csv' returns raw CSV text.

**Example prompts:**

- "Generate MITRE ATT&CK report for FANCY BEAR"

## Resources

- **`falcon://intel/actors/fql-guide`**: Contains the guide for the `filter` param of the `falcon_search_actors` tool.
- **`falcon://intel/indicators/fql-guide`**: Contains the guide for the `filter` param of the `falcon_search_indicators` tool.
- **`falcon://intel/reports/fql-guide`**: Contains the guide for the `filter` param of the `falcon_search_reports` tool.
