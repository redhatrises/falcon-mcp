package cloud

// Tool and parameter descriptions, kept 1:1 with the Python falcon-mcp cloud
// module. Filter/sort descriptions carry backticks or multi-line content that
// cannot live in a jsonschema struct tag, so they are consts applied to the
// schemas by their mutate funcs.

const (
	searchKubernetesContainersDescription = `Search for Kubernetes containers in your CrowdStrike container inventory.

Use this to find containers by cluster, namespace, image, or cloud provider.
Consult falcon://cloud/kubernetes-containers/fql-guide before constructing filter
expressions. Returns full container details including image, status, and vulnerabilities.`

	countKubernetesContainersDescription = `Count Kubernetes containers matching filter criteria.

Use this for aggregate counts without returning full container details. Consult
falcon://cloud/kubernetes-containers/fql-guide before constructing filter
expressions. Returns the matching container count as an integer.`

	searchImagesVulnerabilitiesDescription = `Search for container image vulnerabilities in CrowdStrike Image Assessments.

Use this to find CVEs affecting container images by severity, CVSS score, or
CVE ID. Consult falcon://cloud/images-vulnerabilities/fql-guide before constructing
filter expressions. Returns vulnerability details including CVE IDs, scores, and
impacted image counts.
` +
		"Responses include `pagination.total` (the total number of records matching the filter, " +
		"or null when the API does not report a count) — use it to answer \"how many\" questions."

	searchCSPMAssetsDescription = `Search for cloud assets in your CrowdStrike CSPM inventory.

Use this to find cloud resources (EC2, VPCs, S3, etc.) by provider, region,
resource type, or tags. Consult falcon://cloud/cspm-assets/fql-guide before
constructing filter expressions. Returns slimmed asset details with security
posture context (IOM/IOA counts, exposure, severity).
` +
		"Responses include `pagination.total` (the total number of records matching the filter, " +
		"or null when the API does not report a count) — use it to answer \"how many\" questions. " +
		"For cursor-based paging, use `pagination.next` as the `after` parameter on the next call."

	searchIOMFindingsDescription = `Search for CSPM Indicators of Misconfiguration (IOM) findings.

Use this to find specific compliance rule failures on individual cloud resources —
each IOM is a single rule-against-resource violation (e.g. "S3 bucket ACL allows
public write" on a named bucket). For aggregated risk posture combining multiple
IOMs and IOAs across assets, use falcon_search_cloud_risks instead. For runtime
behavioral threats, use falcon_search_detections. Consult
falcon://cloud/cspm-iom-findings/fql-guide before constructing filter expressions.
Returns IOM entities with cloud context, evaluation details, and resource information.
` +
		"Responses include `pagination.total` (the total number of records matching the filter, " +
		"or null when the API does not report a count) — use it to answer \"how many\" questions. " +
		"For cursor-based paging, use `pagination.next` as the `after` parameter on the next call."

	searchCSPMSuppressionRulesDescription = `Search for CSPM IOM suppression rules.

Use this to review existing suppressions before creating new ones. Returns
suppression rule objects including scope, reason, and expiration details.
Returns an empty list if no rules exist.
` +
		"Responses include `pagination.total` (the total number of records matching the filter, " +
		"or null when the API does not report a count) — use it to answer \"how many\" questions."

	createCSPMSuppressionRuleDescription = `Create a CSPM IOM suppression rule to hide matching findings.

Suppressed findings are still assessed but not surfaced in compliance scores.
Requires at least one rule selection (rule_ids, rule_names, or rule_severities)
and a suppression reason. Setting an expiration_date is strongly recommended to
avoid permanent suppressions. Returns the created suppression rule object.`

	deleteCSPMSuppressionRulesDescription = `Delete CSPM IOM suppression rules by ID.

Deleting a suppression rule re-activates all findings that were previously
suppressed by it. Use falcon_search_cspm_suppression_rules to find rule IDs
first. Returns a confirmation response.`

	searchCloudRisksDescription = `Search for cloud risks in your CrowdStrike environment.

Use this to find risks by severity, status, cloud provider, account, asset, rule,
or threat actor. Cloud risks aggregate IOM and IOA findings into per-asset risk
records and include threat intelligence attribution. For individual compliance rule
violations on specific resources, use falcon_search_iom_findings instead. Consult
falcon://cloud/cloud-risks/fql-guide before constructing filter expressions.
Returns full risk details including severity, lifecycle status, asset context, and
threat intelligence attribution.
` +
		"Responses include `pagination.total` (the total number of records matching the filter, " +
		"or null when the API does not report a count) — use it to answer \"how many\" questions."

	searchCloudGroupsDescription = `List cloud groups in your CrowdStrike environment.

Use this to discover available cloud groups before filtering risks by
` + "`cloud_group`" + ` or ` + "`groups.*`" + ` FQL fields in ` + "`falcon_search_cloud_risks`" + `.
Returns full group details including name, selectors, and tags.`

	getCloudGroupsDescription = `Get detailed information for cloud groups by ID.

Use when you already have specific cloud group IDs — for example, the ` + "`cloud_groups`" + `
field returned by ` + "`falcon_search_cloud_risks`" + `. Returns full group details including
name, selectors, business impact, and environment tags.`
)

const (
	kubernetesContainersFilterDescription = "FQL filter expression. See `falcon://cloud/kubernetes-containers/fql-guide` for syntax."

	kubernetesContainersSortDescription = `Sort kubernetes containers using these options:

cloud_name: Cloud provider name
cloud_region: Cloud region name
cluster_name: Kubernetes cluster name
container_name: Kubernetes container name
namespace: Kubernetes namespace name
last_seen: Timestamp when the container was last seen
first_seen: Timestamp when the container was first seen
running_status: Container running status which is either true or false

Sort either asc (ascending) or desc (descending).
Both formats are supported: 'container_name.desc' or 'container_name|desc'

When searching containers running vulnerable images, use 'image_vulnerability_count.desc' to get container with most images vulnerabilities.

Examples: 'container_name.desc', 'last_seen.desc'`

	imagesVulnerabilitiesFilterDescription = "FQL filter expression. See `falcon://cloud/images-vulnerabilities/fql-guide` for syntax."

	imagesVulnerabilitiesSortDescription = `Sort images vulnerabilities using these options:

cps_current_rating: CSP rating of the image vulnerability
cve_id: CVE ID of the image vulnerability
cvss_score: CVSS score of the image vulnerability
images_impacted: Number of images impacted by the vulnerability

Sort either asc (ascending) or desc (descending).
Both formats are supported: 'container_name.desc' or 'container_name|desc'

Examples: 'cvss_score.desc', 'cps_current_rating.asc'`

	cspmAssetsFilterDescription = "FQL filter expression. See `falcon://cloud/cspm-assets/fql-guide` for syntax."

	cspmAssetsSortDescription = `Sort cloud assets using these options:

cloud_provider: Cloud provider name (AWS, Azure, GCP)
account_id: Cloud account ID
account_name: Cloud account name
resource_type: Resource type (e.g., AWS::EC2::Instance)
region: Cloud region
creation_time: When the asset was created
updated_at: When the asset was last updated

Sort either asc (ascending) or desc (descending).
Both formats are supported: 'updated_at.desc' or 'updated_at|desc'

Examples: 'updated_at.desc', 'resource_type.asc'`

	cspmAssetsAfterDescription = "A pagination token used with the limit parameter to manage pagination of results. On your first request, don't provide an after token. On subsequent requests, provide the after token from the previous response to continue from that result set."

	iomFindingsFilterDescription = "FQL filter expression. See `falcon://cloud/cspm-iom-findings/fql-guide` for syntax."

	iomFindingsOffsetDescription = "Starting index of overall result set from which to return findings."

	iomFindingsSortDescription = `Sort IOM findings. Use |asc or |desc suffix to specify direction.

Common sort fields:
severity: Finding severity level
first_detected: When the finding was first detected
last_detected: When the finding was last seen
cloud_provider: Cloud provider name
service: Cloud service name
status: Finding status

Examples: 'severity|desc', 'last_detected|desc', 'first_detected|asc'`

	cloudRisksFilterDescription = "FQL filter expression. See `falcon://cloud/cloud-risks/fql-guide` for syntax."

	cloudRisksSortDescription = `Sort risks using field|asc or field|desc syntax.

Supported fields: account_id, account_name, asset_id, asset_name, asset_region, asset_type, cloud_provider, first_seen, last_seen, resolved_at, rule_name, service_category, severity, status

Examples: 'severity|desc', 'first_seen|desc', 'account_name|asc'`

	cloudGroupsFilterDescription = `FQL filter expression. Supports group properties: name, description, created_at, updated_at. Selector properties: cloud_provider, account_id, region. Group tags: business_unit, business_impact, environment.

Examples: "name:'prod-group'", "environment:'production'"`

	cloudGroupsSortDescription = "Sort groups. Default: name|asc. Examples: 'name|asc', 'created_at|desc'"
)
