Recon Notification Aggregation Guide

Use falcon_aggregate_recon_notifications to summarize Recon notifications with
Falcon aggregation buckets instead of paging through falcon_search_recon_notifications.

Supported aggregate types:
- terms: count records per distinct value of field
- date_histogram: time series (interval required)
- date_range: explicit time buckets (date_ranges required)
- range: numeric buckets (ranges required)
- cardinality: distinct-value count
- max / min: numeric extreme

The recon endpoint rejects sum, avg, and percentiles.

Recommended fields:
- status, rule_priority, rule_topic, created_date

date_histogram interval values are API-defined buckets such as hour, day, week, or month.

Example terms aggregation:
- type: terms
- field: status
- filter: created_date:>'now-7d'
- size: 10

Example date_range aggregation:
- type: date_range
- field: created_date
- date_ranges: [{"from": "now-7d", "to": "now"}]

Consult falcon://recon/notifications/search/fql-guide for filter syntax.
