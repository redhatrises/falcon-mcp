Falcon Query Language (FQL) - Intel Query Indicator Entities Guide

Use this guide to build the `filter` parameter for `falcon_search_indicators`.
This module queries CrowdStrike Falcon Intelligence indicators (IOCs).

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
• Dates: 'YYYY-MM-DDTHH:MM:SSZ' (UTC format) or relative: 'now-7d', 'now-24h' (lowercase, single-quoted)
• Booleans: true or false (no quotes)
• Numbers: 123 (no quotes)
• Wildcards: 'partial*' or '*partial' or '*partial*'

=== COMBINING CONDITIONS ===
• + = AND condition
• , = OR condition
• ( ) = Group expressions

IMPORTANT: Use + for AND and , for OR — do NOT use the words AND/OR.

=== falcon_search_indicators FQL filter options ===

|Field|Type|Description|
|-|-|-|
|id|String|The indicator ID. Format: {type}_{indicator}|
|created_date|Timestamp|When the indicator was created (Unix, UTC). Ex: 1753022288|
|deleted|Boolean|If true, include only published indicators; if false, only deleted. Ex: false|
|domain_types|String|Domain type of domain indicators. Values: ActorControlled, DGA, DynamicDNS, KnownGood, LegitimateCompromised, PhishingDomain, Sinkholed, StrategicWebCompromise, Unregistered|
|indicator|String|The indicator that was queried. Ex: 'all-deutsch.gl.at.ply.gg'|
|ip_address_types|String|Address type of ip_address indicators. Values: HtranDestinationNode, HtranProxy, LegitimateCompromised, Parking, PopularSite, SharedWebHost, Sinkhole, TorProxy|
|kill_chains|String|Kill chain stage. Values: reconnaissance, weaponization, delivery, exploitation, installation, c2, actionOnObjectives. Ex: 'delivery'|
|last_updated|Timestamp|When the indicator was last updated (Unix, UTC). Ex: 1753027269|
|malicious_confidence|String|Confidence the indicator is malicious. Values: high, medium, low, unverified. Ex: 'high'|
|malware_families|String|Associated malware family. Ex: 'Xworm', 'njRATLime'|
|published_date|Timestamp|When the indicator was first published (Unix, UTC). Ex: 1753022288|
|reports|String|Associated report ID (e.g. CSIT-XXXX or CSIR-XXXX).|
|targets|String|Targeted industries. Ex: Aerospace, Defense, Energy, Financial, Government, Healthcare, Technology|
|threat_types|String|Types of threats. Ex: 'ddos', 'mineware', 'banking'|
|type|String|Indicator type. Ex: domain, email_address, hash_md5, hash_sha256, ip_address, url, username (and more)|
|vulnerabilities|String|Associated vulnerabilities (CVEs). Ex: 'CVE-2023-1234'|

=== SORT FIELDS ===

Use `{field}|asc` or `{field}|desc`. Valid values: id, indicator, type,
published_date, last_updated, _marker.

=== EXAMPLE USAGE ===

• type:'domain'
• malicious_confidence:'high'
• type:'hash_md5'+malicious_confidence:'high'
• malicious_confidence:'high'+published_date:>'now-7d'
• published_date:>'now-30d'
• sort="published_date|desc"

Relative dates supported: published_date:>'now-7d' | published_date:>'now-30d' (lowercase 'now', quoted)

=== IMPORTANT NOTES ===
• Use single quotes around string values: 'value'
• Use square brackets for exact matches: ['exact_value']
• Date fields accept relative syntax ('now-Nd', 'now-Nh') or Unix epoch integers
