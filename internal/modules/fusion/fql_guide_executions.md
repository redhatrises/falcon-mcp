Falcon Query Language (FQL) - Search Workflow Executions Guide

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

=== falcon_search_workflow_executions FQL filter options ===

|Name|Type|Operators|Description|
|-|-|-|-|
|ui_status|String|No|Execution status as displayed, and the field to filter status on. Values: 'Completed', 'Failed', 'In progress', 'Action required'. This matches the `status` value in the response entity. 'Action required' means the run is waiting on a human and will not finish on its own. Ex: ui_status:'Completed'|
|status|String|No|Execution status in the API's INTERNAL vocabulary, which differs from what the response shows: 'Succeeded', 'Failed', 'In progress', 'Canceled'. An execution the response reports as 'Completed' matches status:'Succeeded', not status:'Completed'. Use ui_status unless you specifically need 'Canceled', which ui_status has no equivalent for. Ex: status:'Canceled'|
|id|String|No|Execution ID. The response entity calls this `execution_id`, which is rejected as a filter field with a 400. Ex: id:'0e6a7a46545b926f3dff9fd2dab82fb3'|
|definition_id|String|No|ID of the workflow definition that ran. The way to list one workflow's run history. Ex: definition_id:'2617e3fcf0804945ba6389328f3444f4'|
|definition_name|String|Yes|Name of the workflow that ran, analyzed. Matches whole tokens with ~ only — exact, wildcard and :* all return zero rows here. Ex: definition_name:~'Exposure'|
|started_timestamp|Timestamp|Yes|When the run started. The response entity calls this `start_timestamp`, which is rejected as a filter field with a 400. Ex: started_timestamp:>'now-7d'|
|completed_timestamp|Timestamp|Yes|When the run finished. The response entity calls this `end_timestamp`, which is rejected as a filter field with a 400. Ex: completed_timestamp:>'now-1d'|
|definition_version|Number|Yes|Version of the definition that ran. Numeric operators work. Ex: definition_version:>1|
|test_mode|Boolean|No|Whether the run was a test execution. Ex: test_mode:true|
|contains_mocks|Boolean|No|Whether the run used mocked activity output. Ex: contains_mocks:true|

=== RESPONSE FIELD vs FILTER FIELD ===
Several fields are named one way in the response and another way in a filter.
Filtering on the response name returns a 400.

|Response field|Filter field|
|-|-|
|execution_id|id|
|start_timestamp|started_timestamp|
|end_timestamp|completed_timestamp|
|status|ui_status (displayed values), or status (internal values)|

=== IMPORTANT NOTES ===
• Filter status via ui_status. The `status` field exists but uses a different
vocabulary: an execution the response reports as 'Completed' is
status:'Succeeded'. 'Failed' and 'In progress' are spelled the same in both,
which is why the mismatch is easy to miss.
• An unknown filter field returns a 400 that names it. A known field with an
unsupported operator returns an empty 200 instead.
• Records are LARGE: an execution embeds the entire triggering event, such as a
full detection or case object. Narrow the filter rather than raising the limit.
• pagination.total saturates at 10000. A reported total of exactly 10000 means
"at least 10000", not an exact count. Narrow the filter to get a real count.
• To look executions up directly by ID, without building a filter, use
falcon_get_workflow_execution_results — it takes up to 500 IDs and offers
skip_fields to trim oversized records.
• sort uses DOT notation and a bare property defaults to descending. Verified to
reorder: started_timestamp, completed_timestamp, definition_id,
definition_name, definition_version, ui_status, status, id. The pipe form
(started_timestamp|desc) is rejected with a 400.
• PREFER DESCENDING on a long history. This endpoint hydrates matches by ID
internally, and an execution that is still indexed but no longer retrievable
makes the whole call fail with a 404 naming those IDs. Ascending order reaches
the oldest records first, so it is the order most likely to hit them. Narrow by
started_timestamp instead of paging back through everything.

=== COMMON FILTER EXAMPLES ===
• Runs that completed: ui_status:'Completed'
• Recent completed runs: ui_status:'Completed'+started_timestamp:>'now-7d'
• Runs waiting on a human: ui_status:'Action required'
• One workflow's run history: definition_id:'2617e3fcf0804945ba6389328f3444f4'
• Finished in the last day: completed_timestamp:>'now-1d'
