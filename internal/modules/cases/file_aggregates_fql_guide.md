Falcon Query Language (FQL) - Case File Aggregates Guide

Filters the files counted by falcon_aggregate_case_file_details. This aggregates
files uploaded to cases, not the cases themselves — to filter cases, see
falcon://cases/search/fql-guide.

These are uploaded attachments. They are distinct from a case record's
`analysis_results.files`, which lists forensic artifacts (malware paths and
hashes) observed in detections; that field is empty for cases that do have
attachments, so it cannot be used to answer questions about them.

=== OPERATORS (live-validated) ===

Exact match:      name:'report.pdf'
Substring match:  name:*'*.png'
AND:              case_id:'019f449a-558e-71ea-ba8f-106d7b265036'+name:*'*.png'
OR:               name:*'*.png',name:*'*.jpg'

`~` (contains) returns no results here — use `:*` for substring matching.

=== AVAILABLE FIELDS ===

|Name|Type|Description|
|-|-|-|
|name|String|File name of the attachment, including extension. Ex: *'*.png'|
|case_id|String|ID of the case the file is attached to. Prefer the case_ids parameter, which builds this filter for you. Ex: '019f449a-558e-71ea-ba8f-106d7b265036'|
|id|String|Unique identifier of the file itself.|
|cid|String|Customer ID owning the file.|
|file_size|String|Human-readable file size, not a number — compare it as a string. Ex: '114.8 KB'|

=== EXAMPLES ===

# Screenshots attached to any case
name:*'*.png'

# Files on one specific case
case_id:'019f449a-558e-71ea-ba8f-106d7b265036'

# PDFs or Word documents
name:*'*.pdf',name:*'*.docx'
