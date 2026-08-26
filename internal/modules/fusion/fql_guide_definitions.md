Falcon Query Language (FQL) - Search Workflow Definitions Guide

=== BASIC SYNTAX ===
property_name:[operator]'value'

=== AVAILABLE OPERATORS ===
• No operator = equals (default)
• ! = not equal to
• > = greater than
• >= = greater than or equal
• < = less than
• <= = less than or equal
• ~ = text match (ignores case, spaces, punctuation)
• * = wildcard matching (not supported on all fields — see endpoint-specific notes below)

=== DATA TYPES & SYNTAX ===
• Strings: 'value' or ['exact_value'] for exact match
• Dates: 'YYYY-MM-DDTHH:MM:SSZ' (UTC format) or relative: 'now-7d', 'now-24h' (lowercase, single-quoted)
• Booleans: true or false (no quotes)
• Numbers: 123 (no quotes)
• Wildcards: 'partial*' or '*partial' or '*partial*'

=== COMBINING CONDITIONS ===
• + = AND condition (e.g., platform_name:'Windows'+status:'normal')
• , = OR condition (e.g., severity_name:'Critical',severity_name:'High')
• ( ) = Group expressions

IMPORTANT: Use + for AND and , for OR — do NOT use the words AND/OR.
Values must be single-quoted. Relative dates must be lowercase ('now-7d' not 'NOW-7d').

=== falcon_search_workflow_definitions FQL filter options ===

|Name|Type|Operators|Description|
|-|-|-|-|
|name.raw|String|Yes|Workflow name, unanalyzed. This is the ONLY field that does exact and substring name matching. Note name.raw is not returned in the response entity, which carries `name` instead. Ex (exact): name.raw:'Adversary Exposure Mitigation' Ex (substring): name.raw:*'*Exposure*'|
|name|String|Yes|Workflow name, analyzed into tokens. Matches WHOLE tokens with ~ only: name:~'Multi-' matches but name:~'Multi-Ag' does not, and exact (name:'Full Name') returns zero rows. Prefer name.raw. Ex: name:~'Exposure'|
|id|String|No|Workflow definition ID (32 hex characters). Not unique in a result set: the endpoint returns multiple versions of the same definition. Ex: id:'2617e3fcf0804945ba6389328f3444f4'|
|enabled|Boolean|No|Whether the definition is enabled. A disabled definition is refused by falcon_execute_workflow with a 412. Ex: enabled:true|
|trigger.type|String|No|How the workflow starts. Verified values: 'On demand', 'Signal', 'Scheduled'. The list is partial — these three covered 2973 of 3340 definitions on the test tenant. Only 'On demand' and 'Scheduled' can be run by falcon_execute_workflow; 'Signal' is refused with a 412. Ex: trigger.type:'On demand'|
|version|Number|Yes|Definition version. Numeric operators work. Ex: version:>1|
|last_modified_timestamp|Timestamp|Yes|When the definition was last changed. Range and relative dates work. Ex: last_modified_timestamp:>'now-30d'|
|description|String|Yes|Definition description, analyzed. Use ~ for token matching. Ex: description:~'containment'|
|mock_activities|Boolean|No|Whether the definition has mocked activities. Sparse — set on only 419 of 3340 definitions on the test tenant, so false does not mean "all the rest". Ex: mock_activities:true|

=== IMPORTANT NOTES ===
• Use name.raw, NOT name, to match a workflow by name. `name` is analyzed and
matches whole tokens with ~ only, so name:'Full Workflow Name' returns ZERO
rows even when that workflow exists. name.raw:'Full Workflow Name' returns it.
• An unknown filter field returns a 400 that names it, so a typo is loud. A
known field with an unsupported operator returns an empty 200 instead, which
is quiet — check the operator column above.
• Records are LARGE: a definition embeds its full action configuration,
including whole Charlotte AI prompts and NG-SIEM queries. Narrow the filter
rather than raising the limit.
• The same definition ID appears more than once, one row per version, so a
result set can hold more rows than the limit you asked for. Read `version`
and `enabled` to tell versions apart.
• Not every returned field is filterable: has_validation_errors and
trigger.name are in the response but rejected as filter fields.
• sort uses DOT notation and a bare property defaults to descending. Verified to
reorder: name, last_modified_timestamp, version, enabled, id. The pipe form
(name|desc) is rejected with a 400. Nested fields such as trigger.type and
name.raw are not sortable, because the accepted pattern allows no dot inside the
property name.

=== COMMON FILTER EXAMPLES ===
• Workflows you can run on demand: enabled:true+trigger.type:'On demand'
• One workflow by exact name: name.raw:'Adversary Exposure Mitigation'
• Workflows whose name contains a word: name.raw:*'*Exposure*'
• Disabled workflows: enabled:false
• Recently changed: last_modified_timestamp:>'now-30d'
