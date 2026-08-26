Falcon Query Language (FQL) - Search AgentWorks Agents Guide

Use this guide to build the `filter` parameter for `falcon_search_agentworks_agents`.
This tool lists AgentWorks (Charlotte AI) agents so you can find their IDs and active
versions before invoking one or inspecting its versions. The `filter` parameter is
optional — omit it to list all agents.

=== BASIC SYNTAX ===
field_name:[operator]'value'

=== OPERATORS ===
• = (default): field_name:'value'
• !: field_name:!'value' (not equal)
• >, >=, <, <=: created_date:>'2024-01-01T00:00:00Z' (timestamp fields)
• []: field_name:['value1','value2'] (multiple values, OR logic)

=== DATA TYPES ===
• String: 'value'
• Timestamp: 'YYYY-MM-DDTHH:MM:SSZ' (UTC) or relative 'now-7d'

=== COMBINING ===
• + = AND: template_id:'general'+active_version.model:'gpt-4o'
• , = OR:  active_version.model:'gpt-4o',active_version.model:'claude-3-5-sonnet'
• () = GROUPING: template_id:'general'+(active_version.model:'gpt-4o',active_version.model:'claude-3-5-sonnet')

Use + for AND and , for OR — do NOT use the words AND/OR. Values must be single-quoted.

=== COMMON PATTERNS ===
• Agents built from a template: template_id:'general'
• Agents whose active version uses a model: active_version.model:'gpt-4o'
• Agents that have a published version: published_version_ids:!''
• Created after a date: created_date:>'2024-01-01T00:00:00Z'

=== SORTING ===
The `sort` parameter is separate from `filter`. Supported field: created_date.
Ex: created_date|desc

=== falcon_search_agentworks_agents FQL filter available fields ===

|Field|Type|Description|
|-|-|-|
|template_id|String|ID of the template the agent was built from. Ex: template_id:'general'|
|active_version.model|String|Backing model of the agent's active version. Ex: active_version.model:'gpt-4o'|
|published_version_ids|String|IDs of the agent's published versions. Supports negation to find agents with (or without) a published version. Ex: published_version_ids:!''|
|created_date|Timestamp|Date and time the agent was created. Also the supported sort field. Ex: created_date:>'2024-01-01T00:00:00Z'|
