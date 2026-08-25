Falcon Query Language (FQL) - Cloud Risks Guide

Use this guide to build the `filter` parameter for `falcon_search_cloud_risks`.

This endpoint validates filter fields server-side: an unknown field returns an
error (rather than silently empty results) that lists the supported fields.

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
• Dates: 'YYYY-MM-DDTHH:MM:SSZ' (UTC format)
• Booleans: true or false (no quotes)
• Numbers: 123 (no quotes)
• Wildcards: 'partial*' or '*partial' or '*partial*'

=== COMBINING CONDITIONS ===
• + = AND condition
• , = OR condition
• ( ) = Group expressions

IMPORTANT: Use + for AND and , for OR — do NOT use the words AND/OR.
Values must be single-quoted.

=== falcon_search_cloud_risks FQL filter available fields ===

|Name|Type|Description|
|-|-|-|
|account_id|String|Cloud account identifier. Ex: account_id:'123456789012'|
|account_name|String|Cloud account display name. Ex: account_name:'prod-account'|
|adversary|String|Associated adversary or threat group name. Ex: adversary:'COZY BEAR'|
|asset_gcrn|String|Global cloud resource name identifier. Ex: asset_gcrn:'arn:aws:ec2:us-east-1:123456789012:instance/i-1234'|
|asset_id|String|Asset identifier. Ex: asset_id:'abc123'|
|asset_name|String|Asset display name. Ex: asset_name:'my-ec2-instance'|
|asset_region|String|Cloud region where the asset resides. Ex: asset_region:'us-east-1'|
|asset_type|String|Type of cloud asset. Ex: asset_type:'AWS::EC2::Instance'|
|cloud_group|String|Cloud group identifier the asset belongs to. Ex: cloud_group:'my-group-id'|
|cloud_provider|String|Cloud provider name. Ex: cloud_provider:'aws'|
|first_seen|Timestamp|When the risk was first observed. Supports range operators. Use absolute ISO-8601 timestamps only. Ex: first_seen:>'2024-01-01T00:00:00Z'|
|groups|String|Cloud group associated with this risk. Ex: groups:'my-group-id'|
|groups.business_impact|String|Business impact level of the associated cloud group. Ex: groups.business_impact:'high'|
|groups.business_unit|String|Business unit of the associated cloud group. Ex: groups.business_unit:'engineering'|
|groups.environment|String|Environment tag of the associated cloud group. Ex: groups.environment:'production'|
|last_seen|Timestamp|When the risk was last observed. Supports range operators. Use absolute ISO-8601 timestamps only. Ex: last_seen:>'2024-01-01T00:00:00Z'|
|resolved_at|Timestamp|When the risk was resolved. Supports range operators. Ex: resolved_at:>'2024-01-01T00:00:00Z'|
|risk_factor|String|Risk factor identifier. Ex: risk_factor:'PUBLIC_ACCESS'|
|rule_id|String|ID of the rule that triggered the risk. Ex: rule_id:'ABC-001'|
|rule_name|String|Name of the rule that triggered the risk. Ex: rule_name:'S3 Bucket Public Access'|
|service_category|String|Cloud service category. Ex: service_category:'Storage'|
|severity|String|Risk severity level. Values: Critical, High, Medium, Low, Informational. Ex: severity:'Critical'|
|status|String|Risk lifecycle status. Values: Open, Resolved, Suppressed. Ex: status:'Open'|
|suppressed_by|String|User or entity who suppressed the risk. Ex: suppressed_by:'analyst@example.com'|
|suppressed_reason|String|Reason the risk was suppressed. Ex: suppressed_reason:'accepted_risk'|
|tags|String|Resource tags associated with the asset. Ex: tags:'Environment:Production'|
|threat_actors|String|Threat actors associated with the risk. Ex: threat_actors:'APT29'|

=== falcon_search_cloud_risks FQL filter sort fields ===

Use `field.asc` or `field.desc` suffix (prefer the dot separator, supported on every Falcon sort endpoint):

`account_id`, `account_name`, `asset_id`, `asset_name`, `asset_region`, `asset_type`,
`cloud_provider`, `first_seen`, `last_seen`, `resolved_at`, `rule_name`,
`service_category`, `severity`, `status`

=== falcon_search_cloud_risks FQL filter examples ===

# Open critical risks in AWS
severity:'Critical'+status:'Open'+cloud_provider:'aws'

# Risks in production group
groups.environment:'production'

# Risks first seen after a specific date (use absolute ISO-8601 only)
first_seen:>'2025-01-01T00:00:00Z'

# Resolved risks after a specific date
resolved_at:>'2025-01-01T00:00:00Z'+status:'Resolved'

# Suppressed risks
status:'Suppressed'

# Risks by service category
service_category:'Storage'+severity:'Critical'
