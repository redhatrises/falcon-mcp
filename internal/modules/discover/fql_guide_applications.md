Falcon Query Language (FQL) - Search Applications Guide

=== BASIC SYNTAX ===
property_name:[operator]'value'

=== AVAILABLE OPERATORS ===
• No operator = equals (default)
• ! = not equal to
• > = greater than (timestamp fields only)
• >= = greater than or equal (timestamp fields only)
• < = less than (timestamp fields only)
• <= = less than or equal (timestamp fields only)
• * = wildcard matching (supported on select string fields — see the Operators column)

=== DATA TYPES & SYNTAX ===
• Strings: 'value' or ['exact_value'] for exact match
• Wildcards: field:*'partial*' (the * match operator with * glob inside the quotes)
• Dates: 'YYYY-MM-DDTHH:MM:SSZ' (UTC format)
• Booleans: true or false (no quotes)

=== COMBINING CONDITIONS ===
• + = AND condition
• , = OR condition
• ( ) = Group expressions

IMPORTANT: Use + for AND and , for OR — do NOT use the words AND/OR.
Values must be single-quoted (except booleans and numbers).

=== falcon_search_applications FQL filter options ===

|Name|Type|Operators|Description|
|-|-|-|-|
|architectures|String|Yes|Application architecture. Unavailable for browser extensions. Ex: architectures:'x86' Ex: architectures:!'x64' Ex: architectures:['x86','x64']|
|category|String|Yes|Category the application is in. Unavailable for browser extensions. Ex: category:'IT/Security Apps' Ex: category:'Web Browsers'|
|cid|String|Yes|The application's customer ID. In multi-CID environments you can filter on both parent and child CIDs. Ex: cid:'cxxx4' Ex: cid:!'cxxx4'|
|first_seen_timestamp|Timestamp|Yes|Date and time the application was first seen. Ex: first_seen_timestamp:'2022-12-22T12:41:47.417Z'|
|groups|String|Yes|All application groups the application is assigned to. Ex: groups:'ExampleAppGroup' Ex: groups:['AppGroup1','AppGroup2']|
|id|String|Yes|Unique ID of the application. Each application ID represents a particular instance of an application on a particular asset. Ex: id:'a89xxxxx191'|
|installation_paths|String|Yes|File paths of the application or executable file to the folder on the asset. Ex: installation_paths:'C:\Program Files\Internet Explorer\iexplore.exe'|
|installation_timestamp|Timestamp|Yes|Date and time the application was installed, if available. Ex: installation_timestamp:'2023-01-11T00:00:00.000Z'|
|is_normalized|Boolean|Yes|Windows: whether the application name is normalized (true/false). Unavailable for browser extensions. Ex: is_normalized:true|
|is_suspicious|Boolean|Yes|Whether the application is suspicious based on how often it's been seen in a detection on that asset. Unavailable for browser extensions. Ex: is_suspicious:true|
|last_updated_timestamp|Timestamp|Yes|Date and time the installation fields of the application instance most recently changed. Ex: last_updated_timestamp:'2022-12-22T12:41:47.417Z'|
|last_used_file_hash|String|Yes|Windows and macOS: most recent file hash used for the application. Ex: last_used_file_hash:'0xxxa'|
|last_used_file_name|String|Yes|Windows and macOS: most recent file name used for the application. Ex: last_used_file_name:'setup.exe'|
|last_used_timestamp|Timestamp|Yes|Windows and macOS: date and time the application was most recently used. Ex: last_used_timestamp:'2023-01-10T23:00:00.000Z'|
|last_used_user_name|String|Yes|Windows and macOS: username of the account that most recently used the application. Ex: last_used_user_name:'Administrator'|
|last_used_user_sid|String|Yes|Windows and macOS: security identifier of the account that most recently used the application. Ex: last_used_user_sid:'S-1-x-x-xxx1'|
|name|String|Yes|Name of the application. Ex: name:'Chrome' Ex: name:*'Chrome*' Ex: name:['Chrome','Edge']|
|name_vendor|String|Yes|To group results by application: the app name and vendor name. Ex: name_vendor:'Chrome-Google'|
|name_vendor_version|String|Yes|To group results by application version: the app name, vendor name, and vendor version. Ex: name_vendor_version:'Chrome-Google-108.0.5359.99'|
|software_type|String|Yes|The type of software: 'application' or 'browser_extension'. Ex: software_type:'application'|
|vendor|String|Yes|Name of the application vendor. Ex: vendor:'Microsoft Corporation' Ex: vendor:'Google' Ex: vendor:*'Micro*'|
|version|String|Yes|Application version. Ex: version:'108.0.5359.99' Ex: version:['6.50.16403.0','6.50.16403.1']|
|versioning_scheme|String|Yes|Versioning scheme of the application. Unavailable for browser extensions. Ex: versioning_scheme:'semver'|

=== IMPORTANT NOTES ===
• A filter is REQUIRED — the applications endpoint rejects a request with no filter.
• Use single quotes around string values: 'value'
• Use square brackets for exact matches and multiple values: ['value1','value2']
• Wildcard matching uses the * operator with * globs inside the quotes: name:*'Chrome*'
• Date format must be UTC: 'YYYY-MM-DDTHH:MM:SSZ'
• Range operators (>, >=, <, <=) apply to timestamp fields only.
• Boolean values: true or false (no quotes)

=== COMMON FILTER EXAMPLES ===
• Find Chrome applications: name:'Chrome'
• Find applications from Microsoft: vendor:'Microsoft Corporation'
• Find applications by name prefix: name:*'Chrome*'
• Find suspicious applications: is_suspicious:true
• Find browser extensions: software_type:'browser_extension'
• Find applications used by a specific user: last_used_user_name:'Administrator'
