Falcon Query Language (FQL) - Search Scheduled Reports Guide

Use this guide to build the `filter` parameter for `falcon_search_scheduled_reports`.
This tool queries scheduled report and scheduled search entities in your CrowdStrike
environment.

=== BASIC SYNTAX ===
field_name:[operator]'value'

=== OPERATORS ===
• = (default): field_name:'value'
• !: field_name:!'value' (not equal)
• >, >=, <, <=: created_on:>'2024-01-01T00:00:00Z' (timestamp fields)
• []: field_name:['value1','value2'] (multiple values, OR logic)

=== DATA TYPES ===
• String: 'value'
• Timestamp: 'YYYY-MM-DDTHH:MM:SSZ' (UTC) or relative 'now-7d'

=== COMBINING ===
• + = AND: status:'ACTIVE'+type:'event_search'
• , = OR:  type:'hosts',type:'filevantage'
• () = GROUPING: status:'ACTIVE'+(type:'hosts',type:'filevantage')

Use + for AND and , for OR — do NOT use the words AND/OR. Values must be single-quoted.

=== VALUE CASING ===
• Status values are case-sensitive and must be ALL CAPS (e.g. 'ACTIVE').
• Type values must be all lowercase (e.g. 'event_search').

=== COMMON PATTERNS ===
• Active reports/searches: status:'ACTIVE'
• Scheduled searches only: type:'event_search'
• Scheduled reports only: type:!'event_search'
• Active scheduled searches: status:'ACTIVE'+type:'event_search'
• Created after a date: created_on:>'2023-01-01'
• Created by a specific user: user_id:'user@email.com'
• Last execution failed: last_execution.status:'FAILED'
• Specific report types: type:['hosts','spotlight_remediations']

=== falcon_search_scheduled_reports FQL filter available fields ===

|Field|Type|Description|
|-|-|-|
|id|String|Unique ID of a scheduled report/search entity. Supports multiple values. Ex: id:'45c59557ded4413cafb8ff81e7640456'|
|created_on|Timestamp|Date and time the entity was created. Ex: created_on:>'2021-10-12T03:00'|
|description|String|A single term found in the entity description (all lowercase). Supports multiple values and negation. Ex: description:'process'|
|expiration_on|Timestamp|Date and time a STOPPED entity will be deleted (30 days after it is stopped). Ex: expiration_on:<'2021-12-03T03:30'|
|last_execution.last_updated_on|Timestamp|Date and time of the last scheduled or manual execution. Ex: last_execution.last_updated_on:>'2021-09-22T11:30'|
|last_execution.status|String|Status of the last execution (ALL CAPS). Values: PENDING, PROCESSING, DONE, FAILED, FAILED_NOTIFICATION, NO_DATA. Ex: last_execution.status:'FAILED'|
|last_updated_on|Timestamp|Date and time of the last update to the entity. Ex: last_updated_on:>'2021-10-12'|
|name|String|Exact match to the full entity name (case-sensitive). Supports multiple values and negation. Ex: name:'My Test Report'|
|next_execution_on|Timestamp|Date and time of the next scheduled execution. Ex: next_execution_on:<'2021-11-01'|
|shared_with|String|Unique ID of a user the report has been shared with (scheduled searches cannot be shared). Supports negation. Ex: shared_with:'26eab16d-0b73-452d-b807-afc58f097aad'|
|start_on|Timestamp|Date and time to begin generating executions. Ex: start_on:<'2021-10-01'|
|status|String|Current status of the entity (ALL CAPS). Values: ACTIVE, PENDING, STOPPED, UPDATING. Supports multiple values and negation. Ex: status:'PENDING'|
|stop_on|Timestamp|Date and time to stop generating executions. Ex: stop_on:'2021-12-31'|
|type|String|Entity type (all lowercase). Values: event_search, cloud_security_posture_detections_ioa, cloud_security_posture_detections_iom, cloud_security_image_vulnerabilities, cloud_security_container_vulnerabilities, cloud_security_container_details, cloud_security_image_detections, dashboard, discover_applications, filevantage, hosts, spotlight_installed_patches, spotlight_remediations, spotlight_vulnerabilities, spotlight_vulnerability_logic. Ex: type:'event_search'|
|user_id|String|Username (typically an email) that created the entity. Supports multiple values and negation. Ex: user_id:'diana.hudson@email.com'|
