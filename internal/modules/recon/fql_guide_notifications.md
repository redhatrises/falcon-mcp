Falcon Query Language (FQL) - Search Recon Notifications Guide

Use this guide to build the `filter` parameter for `falcon_search_recon_notifications`.
This tool queries Falcon Intelligence Recon notifications (recon alerts) — dark web
matches, leaked credentials, typosquatting matches, and breach summaries triggered by
your monitoring rules.

=== BASIC SYNTAX ===
field_name:[operator]'value'

=== OPERATORS ===
• = (default): field_name:'value'
• !: field_name:!'value' (not equal)
• >, >=, <, <=: field_name:>50 (comparison, mainly for numbers/timestamps)
• ~: field_name:~'partial' (text match, case insensitive — support is per-field, verify live)
• !~: field_name:!~'exclude' (not text match)
• *: field_name:'prefix*' or field_name:'*suffix*' (wildcards — support is per-field, verify live)

=== DATA TYPES ===
• String: 'value'
• Number: 123 (no quotes)
• Boolean: true/false (no quotes)
• Timestamp: 'YYYY-MM-DDTHH:MM:SSZ' or relative 'now-24h'

=== WILDCARDS ===
FQL operator support is per-operation. Query APIs silently return empty (HTTP 200)
for unsupported fields/operators — empty results do NOT confirm a filter is correct.
Use exact-match filters on confirmed fields when in doubt.
Relative timestamps: created_date:>'now-24h' (lowercase 'now', quoted).

=== COMBINING ===
• + = AND: status:'new'+rule_priority:'high'
• , = OR:  rule_topic:'SA_DOMAIN',rule_topic:'SA_TYPOSQUATTING'
• () = GROUPING: status:'new'+(rule_priority:'high',rule_priority:'medium')

=== ASSIGNEE NOTE ===
assigned_to_uuid requires a user UUID, NOT an email address. Look up the UUID in the
Falcon console under User Management before filtering.

=== COMMON PATTERNS ===
• New high-priority notifications: status:'new'+rule_priority:'high'
• Recent notifications (past 24h): created_date:>'now-24h'
• Recent notifications (past 7 days): created_date:>'now-7d'
• By site (e.g. stealer logs): item_site:'stealer_logs'
• By item type: item_type:'exposed_data'
• Leaked credential notifications: rule_topic:'SA_DOMAIN'+item_type:'exposed_data'
• Typosquatting notifications: rule_topic:'SA_TYPOSQUATTING'
• By monitoring rule: rule_name:'My Domain Watch'
• By rule ID: rule_id:'rule-abc123'

=== falcon_search_recon_notifications FQL filter available fields ===

|Field|Type|Description|
|-|-|-|
|id|String|Unique notification identifier. Ex: abc123def456|
|cid|String|Customer ID (CID). Ex: d61501xxxxxxxxxxxxxxxxxxxxa2da2158|
|user_uuid|String|UUID of the user who owns the monitoring rule that triggered this notification. Ex: 00000000-0000-0000-0000-000000000000|
|status|String|Notification review status. Confirmed values: new (newly triggered, not yet reviewed), in-progress (under investigation), closed-false-positive (reviewed, not a real threat), closed-true-positive (reviewed, confirmed threat). Ex: new|
|rule_id|String|ID of the monitoring rule that triggered this notification. Ex: rule-abc123|
|rule_name|String|Name of the monitoring rule that triggered this notification. Ex: Company Domain Watch|
|rule_topic|String|Topic category of the monitoring rule. Confirmed values: SA_DOMAIN (company domain monitoring), SA_TYPOSQUATTING (typosquatting domain detection), SA_EMAIL (email address monitoring), SA_IP (IP address monitoring), SA_BRAND_PRODUCT (brand and product mentions). Ex: SA_DOMAIN|
|rule_priority|String|Priority of the monitoring rule. Confirmed values: low, medium, high. Ex: medium|
|item_type|String|Type of the intelligence item that triggered the notification. Confirmed value: exposed_data. Ex: exposed_data|
|item_site|String|Site or platform where the intelligence item was found. Use this to filter notifications from specific dark-web forums or messaging platforms. Confirmed value: stealer_logs. Ex: stealer_logs, telegram.org|
|created_date|Timestamp|When the notification was created (ISO 8601 / relative). Relative dates: 'now-24h', 'now-7d', 'now-30d'. Ex: 2024-06-01T00:00:00Z|
|updated_date|Timestamp|When the notification was last updated (ISO 8601 / relative). Ex: 2024-06-01T00:00:00Z|
|assigned_to_uuid|String|UUID of the analyst the notification is assigned to. NOTE: This field requires a UUID, not an email address. To find a user's UUID, look it up in the Falcon console (Support -> User Management) before filtering here. Ex: 00000000-0000-0000-0000-000000000000|

=== FIELDS THAT ARE NOT QUERYABLE ===

• breach_summary.credential_statuses — Live testing confirmed this field causes a 400 FQL
parse failure on QueryNotificationsV1; it is NOT queryable via FQL. Breach credential
data is available in the notification response body (notification.breach_summary) but
cannot be used as a filter. To find breach notifications, filter by rule_topic:'SA_DOMAIN'
combined with item_type:'exposed_data' instead.
• breach_summary.is_retroactively_deduped and typosquatting.* fields appear in the
GetNotificationsDetailedV1 response body but their queryability on QueryNotificationsV1
is unconfirmed. Query APIs silently return empty (HTTP 200) for unsupported fields, so
empty results do NOT confirm a filter worked. Use rule_topic:'SA_TYPOSQUATTING' as the
reliable filter for typosquatting notifications.

=== COMPLEX FILTER EXAMPLES ===

# New high-priority notifications from the past 7 days
status:'new'+rule_priority:'high'+created_date:>'now-7d'

# Typosquatting notifications for any registered domain
rule_topic:'SA_TYPOSQUATTING'+created_date:>'now-30d'

# Exposed-data notifications from stealer logs
item_type:'exposed_data'+item_site:'stealer_logs'

# Domain monitoring notifications, unreviewed
rule_topic:'SA_DOMAIN'+status:'new'

# Unreviewed brand and domain notifications
status:'new'+(rule_topic:'SA_BRAND_PRODUCT',rule_topic:'SA_DOMAIN')
