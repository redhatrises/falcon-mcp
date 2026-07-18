Falcon Query Language (FQL) - Search Data Protection Policies Guide

=== BASIC SYNTAX ===
property_name:[operator]'value'

=== AVAILABLE OPERATORS ===

**WORKING OPERATORS:**
• No operator = equals (default)
• ! = not equal to
• > = greater than - TIMESTAMP/NUMBER FIELDS
• >= = greater than or equal - TIMESTAMP/NUMBER FIELDS
• < = less than - TIMESTAMP/NUMBER FIELDS
• <= = less than or equal - TIMESTAMP/NUMBER FIELDS
• ~ = text match (ignores case, spaces, punctuation) - name and description
• :*'*value*' = wildcard/substring match - created_by and modified_by

=== DATA TYPES & SYNTAX ===
• Strings: 'value' (use ~ for case-insensitive matching)
• Dates: 'YYYY-MM-DD' or 'YYYY-MM-DDTHH:MM:SSZ' (UTC format)
• Booleans: true or false (no quotes)
• Numbers: 123 (no quotes)

=== COMBINING CONDITIONS ===
• + = AND condition
• , = OR condition

=== IMPORTANT: platform_name parameter ===

The falcon_search_data_protection_policies tool requires a platform_name parameter ('win' or 'mac') which is separate from the FQL filter. The filter applies within the selected platform. platform_name is NOT a valid FQL filter field.

=== falcon_search_data_protection_policies FQL filter options ===

|Name|Type|Operators|Description|
|-|-|-|-|
|name|String|Yes|Policy name. Use ~ for case-insensitive text match. Ex: name:~'production'|
|is_enabled|Boolean|No|Whether the policy is enabled. Ex: is_enabled:true|
|is_default|Boolean|No|Whether this is the default policy. Ex: is_default:true|
|precedence|Integer|Yes|Policy precedence (evaluation order). Lower = higher priority. Ex: precedence:>0|
|description|String|Yes|Policy description text. Use ~ for text match. Ex: description:~'compliance'|
|created_at|Timestamp|Yes|Date the policy was created. Ex: created_at:>'2024-01-01'|
|modified_at|Timestamp|Yes|Date the policy was last modified. Ex: modified_at:>'2024-01-01'|
|created_by|String|Yes|Email of the user who created the policy. Use the wildcard match operator. Ex: created_by:*'*admin*'|
|modified_by|String|Yes|Email of the user who last modified the policy. Ex: modified_by:*'*admin*'|

=== WORKING PATTERNS ===

**Booleans:**
• is_enabled:true
• is_default:true

**Combined Conditions:**
• is_enabled:true+precedence:>0

**Text Match (name, description):**
• name:~'production'
• description:~'compliance'

**Wildcard/substring (created_by, modified_by):**
• created_by:*'*admin*'
• modified_by:*'*admin*'

**Numbers / Timestamps:**
• precedence:0
• created_at:>'2024-01-01'

=== SORTING ===

Supported sort fields: name.asc, name.desc, precedence.asc, precedence.desc, created_at.asc, created_at.desc

=== PATTERNS TO AVOID ===
• Exact name equality (name:'Full Name') often returns nothing — use name:~
• The text-match operator ~ on created_by/modified_by returns nothing — use the wildcard match :*'*value*'
• platform_name is not an FQL field — pass it as the platform_name parameter

=== SYNTAX RULES ===
• platform_name ('win' or 'mac') is required and is not an FQL filter
• Use single quotes around string values: 'value'
• Boolean values have no quotes: is_enabled:true
• Combine conditions with + (AND) or , (OR)
