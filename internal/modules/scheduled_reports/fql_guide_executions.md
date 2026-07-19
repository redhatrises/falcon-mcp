Falcon Query Language (FQL) - Search Report Executions Guide

Use this guide to build the `filter` parameter for `falcon_search_report_executions`.
This tool queries the execution history of scheduled reports and scheduled searches.

=== BASIC SYNTAX ===
field_name:[operator]'value'

=== OPERATORS ===
• = (default): field_name:'value'
• !: field_name:!'value' (not equal)
• >, >=, <, <=: created_on:>'2024-01-01T00:00:00Z' (timestamp fields)
• []: field_name:['value1','value2'] (multiple values, OR logic)

=== DATA TYPES ===
• String: 'value'
• Number: 123 (no quotes)
• Timestamp: 'YYYY-MM-DDTHH:MM:SSZ' (UTC) or relative 'now-7d'

=== COMBINING ===
• + = AND: status:'DONE'+created_on:>'2023-01-01'
• , = OR:  status:'FAILED',status:'NO_DATA'
• () = GROUPING: type:'event_search'+(status:'DONE',status:'PROCESSING')

Use + for AND and , for OR — do NOT use the words AND/OR. Values must be single-quoted.

=== VALUE CASING ===
• Status values are case-sensitive and must be ALL CAPS (e.g. 'DONE').
• Type values must be all lowercase (e.g. 'event_search').

=== COMMON PATTERNS ===
• Completed executions: status:'DONE'
• Failed executions: status:'FAILED'
• Currently running: status:'PROCESSING'
• Queued executions: status:'PENDING'
• All executions for an entity: scheduled_report_id:'e163544433ab1020b1a4117d1a8421b5'
• Successful runs after a date: status:'DONE'+created_on:>'2023-01-01'
• Completed scheduled search executions: type:'event_search'+status:'DONE'
• Executions with more than 100 results: result_metadata.result_count:>100

=== falcon_search_report_executions FQL filter available fields ===

|Field|Type|Description|
|-|-|-|
|id|String|Unique ID of an execution. Supports multiple values. Ex: id:'f1984ff006a94980b352f18ee79aed77'|
|created_on|Timestamp|Date and time an execution was generated. Ex: created_on:>'2021-10-12T03:00'|
|expiration_on|Timestamp|Date and time an execution will be deleted (30 days after it is generated). Ex: expiration_on:<'2021-12-03T03:30'|
|last_updated_on|Timestamp|Date and time of the last update (a status change) to the execution. Ex: last_updated_on:>'2021-10-12'|
|result_metadata.*|Various|Scheduled search result details. Fields: execution_start, execution_duration, execution_finish, report_file_name, report_finish, result_count, result_id, search_window_start, search_window_end, queue_duration, queue_start. Ex: result_metadata.result_count:>100|
|scheduled_report_id|String|Unique ID of the scheduled report/search entity. Supports multiple values and negation. Ex: scheduled_report_id:'e163544433ab1020b1a4117d1a8421b5'|
|shared_with|String|Unique ID of a user shared on the scheduled report that generated the execution. Supports negation. Ex: shared_with:'ae6b126d-0b73-452d-b807-afc58f097aad'|
|status|String|Current status of an execution (ALL CAPS). Values: PENDING, PROCESSING, DONE, FAILED, FAILED_NOTIFICATION, NO_DATA. Supports multiple values and negation. Ex: status:'DONE'|
|type|String|Entity type (all lowercase). Values: event_search, cloud_security_posture_detections_ioa, cloud_security_posture_detections_iom, cloud_security_image_vulnerabilities, cloud_security_container_vulnerabilities, cloud_security_container_details, cloud_security_image_detections, dashboard, discover_applications, filevantage, hosts, spotlight_installed_patches, spotlight_remediations, spotlight_vulnerabilities, spotlight_vulnerability_logic. Ex: type:'event_search'|
|user_id|String|ID of the user who created the entity that generated the execution. Supports multiple values and negation. Ex: user_id:'diana.hudson@email.com'|
