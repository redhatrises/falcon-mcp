Falcon Query Language (FQL) - Search Managed Assets Guide

=== BASIC SYNTAX ===
property_name:[operator]'value'

=== AVAILABLE OPERATORS ===
• No operator = equals (default)
• ! = not equal to
• > = greater than (timestamp/number fields)
• >= = greater than or equal (timestamp/number fields)
• < = less than (timestamp/number fields)
• <= = less than or equal (timestamp/number fields)
• * = wildcard matching (the * match operator with * globs inside the quotes)

=== DATA TYPES & SYNTAX ===
• Strings: 'value' or ['exact_value'] for exact match
• Wildcards: field:*'partial*' (the * match operator with * glob inside the quotes)
• Dates: 'YYYY-MM-DDTHH:MM:SSZ' (UTC format) or relative: 'now-7d', 'now-24h' (lowercase, single-quoted)
• Numbers: 123 (no quotes)

=== COMBINING CONDITIONS ===
• + = AND condition
• , = OR condition
• ( ) = Group expressions

IMPORTANT: Use + for AND and , for OR — do NOT use the words AND/OR.
Values must be single-quoted. Relative dates must be lowercase ('now-7d' not 'NOW-7d').

=== AUTOMATIC FILTERING ===
This tool automatically filters for managed assets only by adding entity_type:'managed' to all queries.
Your filter is wrapped in parentheses and AND-ed with that scope, so it cannot widen the result set:
specifying any other entity_type matches nothing. Parentheses and single quotes in your filter must be balanced.

=== falcon_search_managed_assets FQL filter options ===

|Name|Type|Operators|Description|
|-|-|-|-|
|platform_name|String|Yes|Operating system platform of the managed asset. Ex: platform_name:'Windows' Ex: platform_name:'Linux' Ex: platform_name:['Windows','Linux']|
|os_version|String|Yes|Operating system version of the managed asset. Ex: os_version:'Windows 10' Ex: os_version:*'Windows*'|
|hostname|String|Yes|Hostname of the managed asset. Ex: hostname:'PC-001' Ex: hostname:*'PC-*' Ex: hostname:['PC-001','PC-002']|
|country|String|Yes|Country where the managed asset is located. Ex: country:'United States of America' Ex: country:'Germany'|
|city|String|Yes|City where the managed asset is located. Ex: city:'New York' Ex: city:'London'|
|product_type_desc|String|Yes|Product type description of the managed asset. Ex: product_type_desc:'Workstation' Ex: product_type_desc:'Server'|
|external_ip|String|Yes|External IP address of the managed asset. Ex: external_ip:'192.0.2.1' Ex: external_ip:'192.0.2.0/24'|
|criticality|String|Yes|Criticality level assigned to the managed asset. Ex: criticality:'Critical' Ex: criticality:'High' Ex: criticality:'Unassigned'|
|internet_exposure|String|Yes|Whether the managed asset is exposed to the internet. Ex: internet_exposure:'Yes' Ex: internet_exposure:'No' Ex: internet_exposure:['Yes','Pending']|
|encryption_status|String|Yes|Overall drive encryption status of the managed asset. Ex: encryption_status:'Encrypted' Ex: encryption_status:'Not Encrypted' Ex: encryption_status:'Partially Encrypted'|
|encrypted_drives|String|Yes|Encrypted drives on the managed asset. Ex: encrypted_drives:'C:' Ex: encrypted_drives:*'C*'|
|unencrypted_drives|String|Yes|Unencrypted drives on the managed asset. Ex: unencrypted_drives:'D:' Ex: unencrypted_drives:*'D*'|
|os_security.secure_boot_requested_status|String|Yes|Whether Secure Boot has been requested on the managed asset. Ex: os_security.secure_boot_requested_status:'Enabled' Ex: os_security.secure_boot_requested_status:'Disabled'|
|os_security.credential_guard_status|String|Yes|Windows Credential Guard status on the managed asset. Ex: os_security.credential_guard_status:'Enabled' Ex: os_security.credential_guard_status:'Disabled'|
|os_security.iommu_protection_status|String|Yes|IOMMU/DMA protection status on the managed asset. Ex: os_security.iommu_protection_status:'Enabled' Ex: os_security.iommu_protection_status:'Disabled'|
|first_seen_timestamp|Timestamp|Yes|Date and time when the managed asset was first discovered. Ex: first_seen_timestamp:>'now-7d' Ex: first_seen_timestamp:>'2024-01-01T00:00:00Z'|
|last_seen_timestamp|Timestamp|Yes|Date and time when the managed asset was last seen. Ex: last_seen_timestamp:>'now-24h' Ex: last_seen_timestamp:<'now-30d'|

=== IMPORTANT NOTES ===
• entity_type:'managed' is automatically AND-ed with your filter — omit it; another entity_type matches nothing
• Parentheses and single quotes in your filter must be balanced, or the request is rejected
• Use single quotes around string values: 'value'
• Use square brackets for exact matches and multiple values: ['value1','value2']
• Wildcard matching uses the * operator with * globs inside the quotes: hostname:*'PC-*'
• Date format must be UTC: 'YYYY-MM-DDTHH:MM:SSZ' or relative: 'now-7d'

=== COMMON FILTER EXAMPLES ===
• Find Windows managed assets: platform_name:'Windows'
• Find unencrypted managed assets: encryption_status:'Not Encrypted'
• Find assets with Secure Boot disabled: os_security.secure_boot_requested_status:'Disabled'
• Find assets with Credential Guard disabled: os_security.credential_guard_status:'Disabled'
• Find critical managed assets: criticality:'Critical'
• Find internet-exposed assets: internet_exposure:'Yes'
• Find assets by hostname pattern: hostname:*'PC-*'
• Find recently seen assets: last_seen_timestamp:>'now-24h'

=== COMPLEX QUERY EXAMPLES ===
• Critical Windows assets that are not encrypted: platform_name:'Windows'+criticality:'Critical'+encryption_status:'Not Encrypted'
• Internet-exposed servers with Secure Boot disabled: product_type_desc:'Server'+internet_exposure:'Yes'+os_security.secure_boot_requested_status:'Disabled'
• Recently seen assets missing Credential Guard: last_seen_timestamp:>'now-7d'+os_security.credential_guard_status:'Disabled'
