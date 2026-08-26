Recon Rule Preview Guide

Use `falcon_preview_recon_rule` to estimate how noisy a prospective monitoring rule would
be before creating it. You supply a candidate rule definition and Falcon reports how many
notifications it would have produced, broken down by channel and site.

This tool takes a rule definition, not a notification search filter. To aggregate
notifications that already exist, use `falcon_aggregate_recon_notifications`.

=== THE FILTER IS RULE FQL, NOT SEARCH FQL ===
`filter` is the prospective rule's own match expression, written in the monitoring-rule
dialect and parenthesized per condition. It is a different language from the FQL used by
`falcon_search_recon_notifications` — fields like `status` or `created_date` are invalid
here. A bare value such as `example.com` is rejected as invalid FQL.

Verified expressions by topic:
| Topic            | Example filter                                    |
|------------------|---------------------------------------------------|
| SA_DOMAIN        | (domain:'example.com')                            |
| SA_EMAIL         | (email:'user@example.com')                        |
| SA_IP            | (ip:'1.2.3.4')                                    |
| SA_AUTHOR        | (author:'handle')                                 |
| SA_BRAND_PRODUCT | (phrase:'BrandName')+(keyword:'BrandName')        |
| SA_THIRD_PARTY   | (phrase:'VendorName')                             |
| SA_CUSTOM        | (keyword:'term')                                  |
| SA_VIP           | (keyword:'term')                                  |
| SA_CVE           | (keyword:'term')                                  |
| SA_ALIAS         | (keyword:'term')                                  |

Combine conditions with `+`. Using a condition word the topic does not support returns a
400 naming `filter.expressions[0]`.

=== TOPIC AND LOOKBACK CONSTRAINTS ===
`topic` must be one of the topics above. SA_TYPOSQUATTING is rejected — typosquatting
rules cannot be previewed. SA_BIN is accepted as a topic but has no supported condition
word, so it cannot be previewed in practice either.

`lookback_days` accepts only 7, 30, 180, and 365. Any other value, including 1, 14, or 90,
returns a 400. Omitting it previews against the full retained window and returns a single
`Total` count; supplying it adds a separate `Total - EDR` count for exposed-data matches.

=== READING THE RESPONSE ===
The breakdown is fixed — you cannot choose the aggregation fields. Three aggregations come
back, each with `label`/`count` buckets:
• channel — the kinds of sources that matched, e.g. public_repo, chat_medium, forum
• count — total matches; `Total`, plus `Total - EDR` when lookback_days is set
• site — the specific sites that matched, e.g. github.com, telegram.org

`sum_other_doc_count` on channel and site reports matches beyond the returned buckets.
A high total means the rule would be noisy; tighten the filter and preview again.

=== EXAMPLES ===

# How noisy would monitoring this domain be over the past 30 days?
topic: SA_DOMAIN, filter: (domain:'example.com'), lookback_days: 30

# Brand mention volume for the past week
topic: SA_BRAND_PRODUCT, filter: (phrase:'Acme')+(keyword:'Acme'), lookback_days: 7

# Full-window estimate for watching an executive's email
topic: SA_EMAIL, filter: (email:'ceo@example.com')
