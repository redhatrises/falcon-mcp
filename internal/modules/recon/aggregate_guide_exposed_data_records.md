Recon Exposed-Data Record Aggregation Guide

Use falcon_aggregate_recon_exposed_data_records to summarize leaked-credential
and exposed-data records with Falcon aggregation buckets instead of paging through
falcon_search_recon_exposed_data_records.

Supported aggregate types:
- terms: count records per distinct value of field
- date_histogram: time series (interval required)
- date_range: explicit time buckets (date_ranges required)
- range: numeric buckets (ranges required)
- cardinality: distinct-value count
- max / min: numeric extreme

The recon endpoint rejects sum, avg, and percentiles.

Supported fields:
- cid, notification_id, notification_group_id, created_date
- rule.id, rule.name, rule.topic
- source_category, site, author, file.name, credential_status
- bot.operating_system.hardware_id, bot.bot_id

Example terms aggregation:
- type: terms
- field: credential_status
- filter: created_date:>'now-7d'
- size: 10

Example date_range aggregation:
- type: date_range
- field: created_date
- date_ranges: [{"from": "now-7d", "to": "now"}]

Consult falcon://recon/exposed-data-records/search/fql-guide for filter syntax.
