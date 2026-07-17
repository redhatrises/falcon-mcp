Falcon Query Language (FQL) - Sensor Usage Guide

Use this guide to build the `filter` parameter for `falcon_search_sensor_usage`.
This module queries CrowdStrike Falcon weekly sensor usage data.

=== BASIC SYNTAX ===
property_name:[operator]'value'

=== AVAILABLE OPERATORS ===
• No operator = equals (default) — all fields
• ! = not equal to — all fields
• > = greater than — date and integer fields
• >= = greater than or equal — date and integer fields
• < = less than — date and integer fields
• <= = less than or equal — date and integer fields

=== DATA TYPES & SYNTAX ===
• Dates: 'YYYY-MM-DD' (ISO 8601 format)
• Strings: 'value' (always single-quoted, including period, which is a numeric-looking string)

=== COMBINING CONDITIONS ===
• + = AND condition (e.g., event_date:'2024-06-11'+period:'30')
• , = OR condition
• ( ) = Group expressions

=== falcon_search_sensor_usage FQL filter options ===

|Field|Type|Operators|Description|
|-|-|-|-|
|event_date|Date|Yes|The final date of the results to be returned, in ISO 8601 format (YYYY-MM-DD). Data is available starting with the current date minus 2 days and going back 395 days; it is not available for the current date or the current date minus 1 day. Default: the current date minus 2 days. Ex: event_date:'2024-06-11'|
|period|String|Yes|The number of days of data to return. Even though it looks like a number, always quote it (for example '3' not 3). Minimum: '1'. Maximum: '395'. Default: '28'. Ex: period:'30'|
|selected_cids|String|No|A comma-separated list of up to 100 CID IDs to return data for. Available to Falcon Flight Control parent CIDs and to CIDs in multi-CID deployments with the access-account-billing-data feature flag enabled. Case-sensitive. Ex: selected_cids:'cid_1,cid_2,cid_3'|

=== IMPORTANT NOTES ===
• Use single quotes around all values, including period ('30', not 30).
• Date format must be ISO 8601: 'YYYY-MM-DD'.
• Combine conditions with + (AND) or , (OR); do NOT use the words AND/OR.
• selected_cids is case-sensitive and requires exactly correct capitalization.

=== COMMON FILTER EXAMPLES ===
• Usage ending on a specific date: event_date:'2024-06-11'
• Last 30 days of usage: period:'30'
• Combined date and period: event_date:'2024-06-11'+period:'30'
• Date comparison: event_date:>'2024-01-01'
• Period comparison: period:>='14'
