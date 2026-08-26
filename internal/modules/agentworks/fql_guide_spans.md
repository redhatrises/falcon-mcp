Falcon Query Language (FQL) - Search AgentWorks Spans Guide

Use this guide to build the `filter` parameter for `falcon_search_agentworks_spans`.
Spans are the execution trace of an AgentWorks (Charlotte AI) run: each span records a
step (an LLM call, an agent turn, a reply). Use spans to observe what an invocation did.

ALWAYS include a filter — a span query without one scans everything and is rejected or
returns nothing useful. In practice you scope by `trace_id` (the `ai_trace_id` returned
by falcon_invoke_agentworks_agent) and a recent `start_time` window (spans are retained
for roughly the last 90 days).

=== BASIC SYNTAX ===
field_name:[operator]'value'

=== OPERATORS ===
• = (default): field_name:'value'
• !: field_name:!'value' (not equal)
• >, >=, <, <=: start_time:>'2024-01-01T00:00:00Z' (timestamp/number fields)
• []: field_name:['value1','value2'] (multiple values, OR logic)

=== DATA TYPES ===
• String: 'value'
• Number: 1234 (unquoted)
• Timestamp: 'YYYY-MM-DDTHH:MM:SSZ' (UTC) or relative 'now-7d'

=== COMBINING ===
• + = AND: trace_id:'abc123'+status:'error'
• , = OR:  span_type:'llm',span_type:'aw_agent'
• () = GROUPING: trace_id:'abc123'+(status:'error',span_type:'llm')

Use + for AND and , for OR — do NOT use the words AND/OR. Values must be single-quoted
(numbers are unquoted).

=== COMMON PATTERNS ===
• All spans for one run: trace_id:'abc123'
• Errored steps in a run: trace_id:'abc123'+status:'error'
• LLM calls in a run: trace_id:'abc123'+span_type:'llm'
• Spans in a recent window: trace_id:'abc123'+start_time:>'now-7d'
• Slow steps: trace_id:'abc123'+duration_ms:>5000

=== SORTING ===
The `sort` parameter is separate from `filter`. Supported field: start_time.
Ex: start_time|desc

=== falcon_search_agentworks_spans FQL filter available fields ===

|Field|Type|Description|
|-|-|-|
|trace_id|String|Trace ID of the run. This is the ai_trace_id returned by falcon_invoke_agentworks_agent. The primary way to scope a span query. Ex: trace_id:'abc123'|
|span_type|String|Kind of step. Values: llm, aw_agent, aiplatform_agent, aw_agent_response, aiplatform_agent_response, charlotteai_reply, charlotteai_agent. Ex: span_type:'llm'|
|status|String|Outcome of the step. Values: unset, ok, error. Ex: status:'error'|
|name|String|Exact match to the span name (case-sensitive). Ex: name:'plan'|
|duration_ms|Number|Step duration in milliseconds. Ex: duration_ms:>5000|
|start_time|Timestamp|When the step started. Also the supported sort field; spans are retained for roughly the last 90 days. Ex: start_time:>'now-7d'|
