Falcon Query Language (FQL) - Search Custom IOA Rule Groups Guide

=== BASIC SYNTAX ===
property_name:[operator]'value'

=== AVAILABLE OPERATORS ===

**WORKING OPERATORS (verified on this endpoint):**
• No operator = equals (default) - ALL FIELDS
• ! = not equal to - ALL FIELDS
• > = greater than - TIMESTAMP FIELDS ONLY
• >= = greater than or equal - TIMESTAMP FIELDS ONLY
• < = less than - TIMESTAMP FIELDS ONLY
• <= = less than or equal - TIMESTAMP FIELDS ONLY
• ~ = text match (case insensitive) - TEXT FIELDS ONLY
• * = wildcard matching (e.g. name:*'*value*')

=== DATA TYPES & SYNTAX ===
• Strings: 'value' for exact match
• Dates: 'YYYY-MM-DDTHH:MM:SSZ' (UTC format)
• Booleans: true or false (no quotes)

=== COMBINING CONDITIONS ===
• + = AND condition
• , = OR condition
• ( ) = Group expressions

=== falcon_search_ioa_rule_groups FQL filter options ===

|Name|Type|Operators|Description|
|-|-|-|-|
|enabled|Boolean|No|Whether the rule group is enabled. Ex: enabled:true|
|platform|String|Yes|Platform for the rule group. Possible values: windows, mac, linux. Ex: platform:'windows'|
|name|String|Yes|Name of the rule group. Supports exact, text match (~), and wildcard. Ex: name:'Suspicious Process Creation', name:~'test', name:*'*test*'|
|description|String|Yes|Description of the rule group. Ex: description:~'lateral movement'|
|created_on|Timestamp|Yes|Creation timestamp (UTC). Ex: created_on:>'2024-01-01T00:00:00Z'|
|modified_on|Timestamp|Yes|Last modification timestamp (UTC). Ex: modified_on:>'2024-06-01T00:00:00Z'|
|created_by|String|Yes|Email of the user which created the group. Ex: created_by:'user@example.com'|
|modified_by|String|Yes|Email of the user which last modified the group. Ex: modified_by:'user@example.com'|
|rules.name|String|Yes|Name of rules within the group. Ex: rules.name:~'Block cmd.exe'|
|rules.description|String|Yes|Description of rules within the group.|
|rules.pattern_severity|String|Yes|Severity of rules. Possible values: critical, high, medium, low, informational. Ex: rules.pattern_severity:'high'|
|rules.ruletype_name|String|Yes|Rule type name for rules. Ex: rules.ruletype_name:'Process Creation'|
|rules.action_label|String|Yes|Action label for rules within the group. Ex: rules.action_label:'Detect'|
|rules.enabled|Boolean|No|Whether rules in the group are enabled. Ex: rules.enabled:true|

=== WORKING PATTERNS ===

**Basic Equality:**
• platform:'windows', platform:'mac', platform:'linux'
• enabled:true, enabled:false
• rules.pattern_severity:'high'

**Combined Conditions:**
• platform:'windows'+enabled:true
• platform:'windows'+rules.pattern_severity:'critical'

**Timestamp Comparisons:**
• created_on:>'2024-01-01T00:00:00Z'
• modified_on:>='2024-06-01T00:00:00Z'

**Name Matching:**
• name:'Suspicious Process Creation' (exact)
• name:~'test' (case-insensitive text match)
• name:*'*test*' (wildcard contains)

**Rule Sub-field Filters:**
• rules.ruletype_name:'Process Creation'
• rules.name:~'Block'
• rules.enabled:true

=== SYNTAX RULES ===
• Use single quotes around string values: 'value'
• Date format must be UTC: 'YYYY-MM-DDTHH:MM:SSZ'
• Combine conditions with + (AND) or , (OR)
• Use parentheses for grouping: (condition1,condition2)+condition3
• An unrecognized filter field is rejected by the API (HTTP 500), not silently
ignored — use only the fields listed above.
