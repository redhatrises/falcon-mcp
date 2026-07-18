Falcon Query Language (FQL) - Search Data Protection Content Patterns Guide

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
• ~ = text match (ignores case, spaces, punctuation) - name and example

=== DATA TYPES & SYNTAX ===
• Strings: 'value' (use ~ for case-insensitive matching)
• Booleans: true or false (no quotes)
• Dates: 'YYYY-MM-DD' or 'YYYY-MM-DDTHH:MM:SSZ' (UTC format)

=== COMBINING CONDITIONS ===
• + = AND condition
• , = OR condition

=== falcon_search_data_protection_content_patterns FQL filter options ===

|Name|Type|Operators|Description|
|-|-|-|-|
|name|String|Yes|Content pattern name. Use ~ for case-insensitive text match. Ex: name:~'credit'|
|type|String|Yes|Pattern type. Values: custom, predefined. Ex: type:'custom'|
|category|String|Yes|Pattern category. Values include: Custom, PII, PHI, PCI DSS, ITAR, Secret. Ex: category:'PII'|
|region|String|Yes|Geographic region (ISO 3166 alpha-3 code, or ALL). Ex: region:'ALL', region:'USA'|
|deleted|Boolean|No|Whether the content pattern has been deleted. Ex: deleted:false|
|example|String|Yes|Example text for the content pattern. Use ~ for text match. Ex: example:~'4111'|
|created|Timestamp|Yes|Date the content pattern was created. Ex: created:>'2024-01-01'|
|last_updated|Timestamp|Yes|Date the content pattern was last updated. Ex: last_updated:>'2024-01-01'|

=== WORKING PATTERNS ===

**Type / Category / Region:**
• type:'custom'
• type:'predefined'
• category:'PII'
• category:'Secret'
• region:'ALL'
• region:'USA'

**Booleans:**
• deleted:false

**Combined Conditions:**
• region:'USA'+type:'predefined'

**Text Match (name, example):**
• name:~'credit'

=== SORTING ===

Supported sort fields: name.asc, name.desc, category.asc, category.desc, region.asc, region.desc

=== PATTERNS TO AVOID ===
• Exact name equality (name:'Full Name') often returns nothing — use name:~
• Timestamp fields are named created and last_updated, NOT created_at/modified_at
• Category values are case-sensitive labels (Custom, PII, PHI, PCI DSS, ITAR, Secret), not free text
• Region uses ISO 3166 alpha-3 codes (USA, GBR, DEU, ...) or ALL — not two-letter codes

=== SYNTAX RULES ===
• Use single quotes around string values: 'value'
• Boolean values have no quotes: deleted:false
• type values are lowercase: 'custom', 'predefined'
• Combine conditions with + (AND) or , (OR)
