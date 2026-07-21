Falcon Query Language (FQL) - CSPM Assets Guide

Use this guide to build the `filter` parameter for `falcon_search_cspm_assets`.

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

=== falcon_search_cspm_assets FQL filter available fields ===

|Name|Type|Description|
|-|-|-|
|account_id|String|The cloud provider account ID. Ex: account_id:'123456789012'|
|account_name|String|The cloud provider account name. Ex: account_name:'production-account'|
|cloud_provider|String|The cloud provider hosting the resource. Values: AWS, Azure, GCP (case-sensitive). Ex: cloud_provider:'AWS' Ex: cloud_provider:['AWS', 'Azure']|
|resource_type|String|The cloud resource type in ARN or short format. Ex: resource_type:'AWS::EC2::Instance' Ex: resource_type:'ec2-instance' Ex: resource_type:*'*S3*'|
|resource_id|String|The unique identifier of the cloud resource. Ex: resource_id:'//ec2.amazonaws.com/i-1234567890abcdef0'|
|resource_name|String|The name of the cloud resource. Ex: resource_name:'my-bucket'|
|region|String|The cloud region where the resource is deployed. Ex: region:'us-east-1' Ex: region:['us-east-1', 'us-west-2']|
|tag_key|String|Filter by cloud resource tag key name. Ex: tag_key:'Environment' Ex: tag_key:'CostCenter'|
|tag_value|String|Filter by cloud resource tag value. Ex: tag_value:'Production' Ex: tag_value:'*web*'|
|tags|String|Filter by tag in key:value format. Ex: tags:'Environment:Production' Ex: tags:'CostCenter:12345'|
|tags_string|String|Filter by tag string representation. Supports wildcards. Ex: tags_string:'*Production*' Ex: tags_string:'*Environment*'|
|creation_time|Timestamp|Timestamp when the cloud resource was created (UTC). Ex: creation_time:>'2025-01-01T00:00:00Z' Ex: creation_time:<='2024-12-31T23:59:59Z'|
|updated_at|Timestamp|Timestamp when the asset was last updated in CrowdStrike (UTC). Ex: updated_at:>'2025-03-01T00:00:00Z'|
|active|Boolean|Indicates if the asset is currently active. Ex: active:true|
|service|String|The cloud service category. Examples: EC2, S3, API Gateway, Lambda, VPC. Ex: service:'EC2' Ex: service:*'*Gateway*'|
|service_category|String|The broader service category. Examples: Compute, Storage, Networking, Database. Ex: service_category:'Compute'|
|highest_severity|String|Highest severity finding associated with the asset. Values: critical, high, medium, informational. Ex: highest_severity:'critical' Ex: highest_severity:['critical', 'high']|
|severity|String|Severity associated with the asset. Ex: severity:'critical'|
|publicly_exposed|Boolean|Whether the resource is publicly exposed. Ex: publicly_exposed:true|
|status|String|Asset lifecycle status. Values: ResourceDiscovered, ResourceUpdated, ResourceDeleted. Ex: status:'ResourceDiscovered'|
|instance_state|String|Instance state for compute resources. Ex: instance_state:'running' Ex: instance_state:'stopped'|
|instance_id|String|Cloud instance identifier. Ex: instance_id:'i-0abc123def456'|
|managed_by|String|How the asset is managed by CrowdStrike. Values: Sensor, Snapshot, Unmanaged. Ex: managed_by:'Sensor' Ex: managed_by:'Unmanaged'|
|platform_name|String|OS platform name. Ex: platform_name:'Linux' Ex: platform_name:'Windows'|
|os_version|String|Operating system version. Ex: os_version:'Ubuntu 22.04'|
|cluster_id|String|Kubernetes cluster ID the asset belongs to. Ex: cluster_id:'6055bde7-acfe-48ae-9ee0-0ac1a60d8eac'|
|cluster_name|String|Kubernetes cluster name the asset belongs to. Ex: cluster_name:'prod-cluster'|
|cloud_group|String|Cloud group identifier for organizational grouping. Ex: cloud_group:'prod-group'|
|environment|String|Environment tag of the associated cloud group. Ex: environment:'production'|
|business_impact|String|Business impact level of the associated cloud group. Ex: business_impact:'high'|
|ioa_count|Number|Count of Indicators of Attack associated with the asset. Ex: ioa_count:>0 Ex: ioa_count:>=5|
|iom_count|Number|Count of Indicators of Misconfiguration associated with the asset. Ex: iom_count:>0 Ex: iom_count:>=10|

=== falcon_search_cspm_assets FQL filter examples ===

# Find AWS production assets by tag
tag_key:'Environment'+tag_value:'Production'+cloud_provider:'AWS'

# Find EC2 instances
resource_type:'AWS::EC2::Instance'

# Find assets using combined tag format
tags:'Environment:Production'

# Find assets by cloud provider and region
cloud_provider:'AWS'+region:['us-east-1', 'us-west-2']

# Find assets created in the last 30 days
creation_time:>'2025-02-16T00:00:00Z'

# Find assets by service category and active status
service_category:'Compute'+active:true

# Find assets with wildcard on resource type
resource_type:*'*S3*'

# Find assets by account and service
account_name:'production-account'+service:'Lambda'

# Find publicly exposed critical-severity assets
publicly_exposed:true+highest_severity:'critical'

# Find running instances managed by Sensor
instance_state:'running'+managed_by:'Sensor'

# Find assets with active misconfigurations
iom_count:>0+cloud_provider:'AWS'

=== Cloud Resource Tag Filtering Syntax ===

Cloud resource tags (AWS/Azure/GCP) use separate filter fields for keys and values.

AVAILABLE TAG FIELDS:
• tag_key — Filter by tag key name: tag_key:'Environment'
• tag_value — Filter by tag value: tag_value:'Production'
• tags — Filter by key:value pair: tags:'Environment:Production'
• tags_string — Filter by tag string with wildcards: tags_string:'*Production*'

EXAMPLES:
tag_key:'Environment'+tag_value:'Production'   # Key + value match
tags:'Environment:Production'                  # Combined key:value format
tags_string:'*Production*'                     # Wildcard tag search
tag_key:'CostCenter'                           # Any asset with this tag key
tag_key:'Env'+tag_value:'Prod'+cloud_provider:'AWS'  # Tags + provider

=== Common Use Cases ===

# Cost Management: Find resources by cost center
tags:'CostCenter:12345'+active:true

# Security: Find publicly exposed compute resources
service_category:'Compute'+publicly_exposed:true+cloud_provider:'AWS'

# Security: Find assets with critical findings
highest_severity:'critical'+managed_by:'Sensor'

# Multi-region inventory
cloud_provider:'AWS'+region:['us-east-1', 'eu-west-1']

# Recent changes: Assets updated in last 7 days
updated_at:>'2025-03-11T00:00:00Z'

# Find unmanaged assets with IOAs
managed_by:'Unmanaged'+ioa_count:>0
