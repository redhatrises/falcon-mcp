Falcon Query Language (FQL) - Search IOCs Guide

Use this guide to build the `filter` parameter for `falcon_search_iocs`. This
module uses the Falcon IOC Service Collection combined endpoint
(indicator_combined_v1).

=== BASIC SYNTAX ===
property_name:[operator]'value'

=== AVAILABLE OPERATORS ===

**WORKING OPERATORS:**
• No operator = equals (default) - ALL FIELDS
• ! = not equal to - ALL FIELDS
• > = greater than - TIMESTAMP/NUMBER FIELDS ONLY
• >= = greater than or equal - TIMESTAMP/NUMBER FIELDS ONLY
• < = less than - TIMESTAMP/NUMBER FIELDS ONLY
• <= = less than or equal - TIMESTAMP/NUMBER FIELDS ONLY
• * = wildcard matching - TEXT FIELDS

=== DATA TYPES & SYNTAX ===
• Strings: 'value'
• Dates: 'YYYY-MM-DDTHH:MM:SSZ' (UTC format)
• Booleans: true or false (no quotes)
• Numbers: 123 (no quotes)
• Wildcards: 'partial*' or '*partial' or '*partial*'

=== COMBINING CONDITIONS ===
• + = AND condition
• , = OR condition
• ( ) = Group expressions

=== falcon_search_iocs FQL filter options ===

|Field|Type|Description|
|-|-|-|
|action|String|IOC action. Ex: action:'detect'|
|applied_globally|Boolean|Whether the IOC is applied globally. Ex: applied_globally:true|
|created_by|String|Username or identifier that created the IOC.|
|created_on|Timestamp|IOC creation timestamp.|
|expiration|Timestamp|IOC expiration time.|
|expired|Boolean|Whether the IOC is already expired. Ex: expired:false|
|metadata.filename.raw|String|Filename metadata (when provided).|
|modified_by|String|Username or identifier that last modified the IOC.|
|modified_on|Timestamp|IOC last modified timestamp.|
|severity_number|Number|Numeric severity value.|
|source|String|IOC source label. Ex: source:'mcp'|
|type|String|Indicator type. Examples: domain, ipv4, ipv6, md5, sha256|
|value|String|Indicator value. Ex: value:'malicious.example'|

=== SORT FIELDS ===

Use either `field.asc` / `field.desc` or `field|asc` / `field|desc`.

|Field|Description|
|-|-|
|action|Sort by action|
|applied_globally|Sort by global scope|
|created_on|Sort by creation timestamp|
|expiration|Sort by expiration timestamp|
|modified_on|Sort by last modification timestamp|
|severity_number|Sort by severity|
|source|Sort by source|
|type|Sort by IOC type|
|value|Sort by IOC value|

=== WORKING PATTERNS ===

**Active domain IOCs:**
• filter="type:'domain'+expired:false"

**IOCs from a source:**
• filter="source:'mcp'"

**IOC values containing a string:**
• filter="value:*example*"

**High severity IOCs first:**
• sort="severity_number.desc"

=== SYNTAX RULES ===
• Use single quotes around string values: 'value'
• Date format must be UTC: 'YYYY-MM-DDTHH:MM:SSZ'
• Combine conditions with + (AND) or , (OR)
• Use parentheses for grouping: (condition1,condition2)+condition3

=== NOTES ===
• Validate filters in a test environment before production use.
• If no results are returned, start with a broad filter and then refine.
