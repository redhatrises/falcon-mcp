Falcon Query Language (FQL) - Case Configuration Aggregates Guide

Filters the records counted by falcon_aggregate_case_slas,
falcon_aggregate_case_templates, falcon_aggregate_case_access_tags, and
falcon_aggregate_case_notification_groups. These endpoints aggregate case
*configuration* objects, not cases themselves — to filter cases, see
falcon://cases/search/fql-guide.

=== OPERATORS (live-validated) ===

Exact match:      name:'BarelyTea Corp SLA'
Substring match:  name:*'*Corp*'
Comparison:       created_timestamp:>'now-30d'
AND:              name:*'*SLA*'+created_timestamp:>'now-90d'
OR:               name:'Analyst 1',name:'Analyst 2'

`~` (contains) and a trailing wildcard inside quotes ('Corp*') return no results on
these endpoints — use `:*` for substring matching.

An unsupported filter field returns an error naming the problem rather than an empty
result, so a failed filter is visible rather than silent.

=== AVAILABLE FIELDS ===

|Name|Type|Description|
|-|-|-|
|name|String|Display name of the SLA, template, or notification group. Not available on access tags. Exact match or `:*` substring. Ex: 'BarelyTea Corp SLA'|
|key|String|Access tag key. Access tags only. Ex: 'ANALYST1'|
|id|String|Unique identifier of the record.|
|cid|String|Customer ID owning the record.|
|created_by_name|String|Username that created the record. Not available on access tags. Ex: 'analyst@example.com'|
|updated_by_name|String|Username that last updated the record. Not available on access tags. Ex: 'analyst@example.com'|
|created_timestamp|Timestamp|Creation time (UTC). Not available on access tags. Ex: >'now-30d' or >'2026-01-01T00:00:00Z'|
|updated_timestamp|Timestamp|Last update time (UTC). Not available on access tags. Ex: >'now-7d'|

Access tags accept only `id`, `cid`, and `key`. The other endpoints accept every
field except `key`.

=== EXAMPLES ===

# Templates created in the last 30 days
created_timestamp:>'now-30d'

# Notification groups whose name mentions an analyst
name:*'*Analyst*'

# Records created by a specific user
created_by_name:'analyst@example.com'

# Access tags for a given key
key:'ANALYST1'
