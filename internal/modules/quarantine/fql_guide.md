Quarantine Files FQL Filter Guide

Use this guide to build the `filter` parameter for `falcon_search_quarantined_files`,
`falcon_preview_quarantine_actions`, `falcon_update_quarantined_files`, and
`falcon_delete_quarantined_files`.

=== BASIC SYNTAX ===
field_name:[operator]'value'

=== OPERATORS ===
• No operator = equals (default): field_name:'value'
• ! = not equal to: field_name:!'value'
• >, >=, <, <= = range (timestamp/number fields): field_name:>'2026-03-01T00:00:00Z'
• ~ = contains (case-insensitive): field_name:~'partial'
• !~ = does not contain: field_name:!~'exclude'
• * = wildcard matching (text fields): field_name:'prefix*' or field_name:'*suffix*'

=== COMBINING CONDITIONS ===
• + = AND condition
• , = OR condition
• ( ) = Group expressions

=== AVAILABLE FIELDS ===

|Field|Type|Description|
|-|-|-|
|id|String|Quarantine file record ID. Ex: id:'1234567890abcdef'|
|state|String|Quarantine state (response field). Also queryable as `status` in FQL. Ex: state:'quarantined' or status:'released'|
|sha256|String|SHA256 hash of the quarantined file. Ex: sha256:'a1b2c3...'|
|date_updated|Timestamp|Last update timestamp. Ex: date_updated:>'2026-03-01T00:00:00Z'|
|hostname|String|Host name tied to the quarantine event (top-level field). Ex: hostname:'BRR-WB-LIB-22'|
|behaviors.username|String|Username associated with the quarantined behavior. Ex: behaviors.username:'alice'|
|behaviors.ioc_value|String|IOC value associated with the quarantined behavior. Ex: behaviors.ioc_value:'Shift - Print_d3lsk.exe'|

=== NOTES ===
• The response entity uses `state` for the quarantine status field.
• Both `state` and `status` work as FQL filter fields.

=== EXAMPLES ===

# Quarantined files for a host
hostname:'BRR-WB-LIB-22'

# Records updated recently
date_updated:>'2026-03-01T00:00:00Z'

# Released files for a user
status:'released'+behaviors.username:'alice'

# File hash on a specific host
sha256:'a1b2c3*'+hostname:'DC*'
