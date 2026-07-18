Falcon Query Language (FQL) - Search Data Protection Classifications Guide

=== BASIC SYNTAX ===
property_name:[operator]'value'

=== AVAILABLE OPERATORS ===

**WORKING OPERATORS:**
• No operator = equals (default)
• ! = not equal to
• > = greater than - TIMESTAMP FIELDS ONLY
• >= = greater than or equal - TIMESTAMP FIELDS ONLY
• < = less than - TIMESTAMP FIELDS ONLY
• <= = less than or equal - TIMESTAMP FIELDS ONLY
• ~ = text match (ignores case, spaces, punctuation) - name only
• :*'*value*' = wildcard/substring match - created_by and modified_by

=== DATA TYPES & SYNTAX ===
• Strings: 'value' (use ~ for case-insensitive name matching)
• Dates: 'YYYY-MM-DD' or 'YYYY-MM-DDTHH:MM:SSZ' (UTC format)

=== COMBINING CONDITIONS ===
• + = AND condition
• , = OR condition

=== falcon_search_data_protection_classifications FQL filter options ===

|Name|Type|Operators|Description|
|-|-|-|-|
|name|String|Yes|Classification name. Use ~ for case-insensitive text match. Ex: name:~'credit'|
|created_at|Timestamp|Yes|Date the classification was created. Ex: created_at:>'2024-01-01'|
|modified_at|Timestamp|Yes|Date the classification was last modified. Ex: modified_at:>'2024-01-01'|
|created_by|String|Yes|Email of the user who created the classification. Use the wildcard match operator. Ex: created_by:*'*admin*'|
|modified_by|String|Yes|Email of the user who last modified the classification. Ex: modified_by:*'*admin*'|

=== WORKING PATTERNS ===

**Text Match (name):**
• name:~'credit'

**Wildcard/substring (created_by, modified_by):**
• created_by:*'*admin*'
• modified_by:*'*admin*'

**Timestamp Comparisons:**
• created_at:>'2024-01-01'
• modified_at:>'2024-06-01'

=== SORTING ===

Supported sort fields: name.asc, name.desc, created_at.asc, created_at.desc, modified_at.asc, modified_at.desc

=== PATTERNS TO AVOID ===
• Exact name equality (name:'Full Name') often returns nothing — use name:~
• The text-match operator ~ on created_by/modified_by returns nothing — use the wildcard match :*'*value*'

=== SYNTAX RULES ===
• Use single quotes around string values: 'value'
• Date format is UTC: 'YYYY-MM-DD' or 'YYYY-MM-DDTHH:MM:SSZ'
• Combine conditions with + (AND) or , (OR)
