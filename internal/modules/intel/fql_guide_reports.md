Falcon Query Language (FQL) - Intel Query Report Entities Guide

Use this guide to build the `filter` parameter for `falcon_search_reports`. This
module queries CrowdStrike Falcon Intelligence publications and threat reports.

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
• * = wildcard matching (not supported on all fields)

=== DATA TYPES & SYNTAX ===
• Strings: 'value' or ['exact_value'] for exact match
• Dates: 'YYYY-MM-DDTHH:MM:SSZ' (UTC format) or relative: 'now-7d', 'now-24h' (lowercase, single-quoted)
• Booleans: true or false (no quotes)
• Numbers: 123 (no quotes)
• Wildcards: 'partial*' or '*partial' or '*partial*'

=== COMBINING CONDITIONS ===
• + = AND condition
• , = OR condition
• ( ) = Group expressions

IMPORTANT: Use + for AND and , for OR — do NOT use the words AND/OR.

=== falcon_search_reports FQL filter options ===

|Field|Type|Description|
|-|-|-|
|id|Number|The report's ID. Ex: 2583|
|actors|String|Names of adversaries included in a report. Ex: 'FANCY BEAR'|
|created_date|Timestamp|When the report was created (Unix epoch). Ex: 1754075803|
|description|String|A detailed description of the report.|
|last_modified_date|Timestamp|When the report was last modified (Unix epoch). Ex: 1754076191|
|motivations.value|String|Motivations included in the report. Ex: 'Criminal', 'State-Sponsored'|
|name|String|The report's name. Ex: 'CSA-250861 Newly Identified HAYWIRE KITTEN Infrastructure...'|
|type|String|The type of report. Ex: 'notice', 'tipper', 'periodic-report'|
|short_description|String|A truncated version of the report's description.|
|slug|String|URL-friendly identifier of the report. Ex: 'csa-250861', 'csit-25151'|
|sub_type|String|The subtype of the report. Ex: 'daily', 'yara'|
|tags|String|The report's tags. Ex: 'ransomware', 'espionage', 'vulnerabilities'|
|target_countries|String|Targeted countries. Ex: 'United States', 'Taiwan', 'Western Europe'|
|target_industries|String|Targeted industries. Ex: 'Technology', 'Government', 'Healthcare'|
|url|String|URL to the report's page.|

=== SORT FIELDS ===

Use `{field}.asc` or `{field}.desc` — prefer the dot separator, supported on
every Falcon sort endpoint. Valid values: name, target_countries,
target_industries, type, created_date, last_modified_date.

=== EXAMPLE USAGE ===

• type:'notice'
• name:'*ransomware*'
• created_date:>'2023-01-01T00:00:00Z'
• target_industries:'Healthcare'
• sort="created_date.desc"

=== IMPORTANT NOTES ===
• Use single quotes around string values: 'value'
• Use square brackets for exact matches: ['exact_value']
• Date format must be UTC: 'YYYY-MM-DDTHH:MM:SSZ'
