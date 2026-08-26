Falcon Query Language (FQL) - Search AgentWorks Agent Versions Guide

Use this guide to build the `filter` parameter for `falcon_search_agentworks_agent_versions`.
This tool lists the versions of AgentWorks (Charlotte AI) agents so you can find a specific
`version_id` — for example to invoke a non-published version. Filter by `agent_id` to scope
to one agent's versions. The `filter` parameter is optional but almost always used.

=== BASIC SYNTAX ===
field_name:[operator]'value'

=== OPERATORS ===
• = (default): field_name:'value'
• !: field_name:!'value' (not equal)
• >, >=, <, <=: created_at:>'2024-01-01T00:00:00Z' (timestamp fields)
• []: field_name:['value1','value2'] (multiple values, OR logic)

=== DATA TYPES ===
• String: 'value'
• Boolean: true or false (unquoted)
• Timestamp: 'YYYY-MM-DDTHH:MM:SSZ' (UTC) or relative 'now-7d'

=== COMBINING ===
• + = AND: agent_id:'abc123'+is_published:true
• , = OR:  model:'gpt-4o',model:'claude-3-5-sonnet'
• () = GROUPING: agent_id:'abc123'+(is_published:true,is_enabled:true)

Use + for AND and , for OR — do NOT use the words AND/OR. Values must be single-quoted
(booleans are unquoted).

=== COMMON PATTERNS ===
• All versions of one agent: agent_id:'abc123'
• Published versions of an agent: agent_id:'abc123'+is_published:true
• Enabled versions only: is_enabled:true
• Versions on a specific model: model:'gpt-4o'
• A version by name: name:'v2-experiment'
• Created after a date: created_at:>'2024-01-01T00:00:00Z'

=== SORTING ===
The `sort` parameter is separate from `filter`. Supported field: created_at.
Ex: created_at|desc

=== falcon_search_agentworks_agent_versions FQL filter available fields ===

|Field|Type|Description|
|-|-|-|
|agent_id|String|ID of the agent this version belongs to. Use to scope to one agent's versions. Ex: agent_id:'abc123'|
|name|String|Exact match to the version name (case-sensitive). Ex: name:'v2-experiment'|
|model|String|Backing model of the version. Ex: model:'gpt-4o'|
|is_published|Boolean|Whether the version is published. Ex: is_published:true|
|is_enabled|Boolean|Whether the version is enabled. Ex: is_enabled:true|
|created_at|Timestamp|Date and time the version was created. Also the supported sort field. Ex: created_at:>'2024-01-01T00:00:00Z'|
