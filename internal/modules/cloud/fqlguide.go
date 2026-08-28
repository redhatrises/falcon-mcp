package cloud

import _ "embed"

//go:generate go run github.com/crowdstrike/falcon-mcp/tools/genfqlguide -in kubernetes_containers_fql_guide.md
//go:generate go run github.com/crowdstrike/falcon-mcp/tools/genfqlguide -in images_vulnerabilities_fql_guide.md
//go:generate go run github.com/crowdstrike/falcon-mcp/tools/genfqlguide -in cspm_assets_fql_guide.md
//go:generate go run github.com/crowdstrike/falcon-mcp/tools/genfqlguide -in cspm_iom_findings_fql_guide.md
//go:generate go run github.com/crowdstrike/falcon-mcp/tools/genfqlguide -in cloud_risks_fql_guide.md
//go:generate go run github.com/crowdstrike/falcon-mcp/tools/genfqlguide -in cloud_insights_fql_guide.md

// FQL guide resource URIs, mirroring the Python falcon-mcp cloud module.
const (
	kubernetesContainersFQLGuideURI  = "falcon://cloud/kubernetes-containers/fql-guide"
	imagesVulnerabilitiesFQLGuideURI = "falcon://cloud/images-vulnerabilities/fql-guide"
	cspmAssetsFQLGuideURI            = "falcon://cloud/cspm-assets/fql-guide"
	cspmIOMFindingsFQLGuideURI       = "falcon://cloud/cspm-iom-findings/fql-guide"
	cloudRisksFQLGuideURI            = "falcon://cloud/cloud-risks/fql-guide"
	cloudInsightsFQLGuideURI         = "falcon://cloud/cloud-insights/fql-guide"
)

// kubernetesContainersFQLGuide is the FQL documentation for searching and
// counting Kubernetes containers. Whitespace is normalized by `go generate`.
//
//go:embed kubernetes_containers_fql_guide.md
var kubernetesContainersFQLGuide string

// imagesVulnerabilitiesFQLGuide is the FQL documentation for searching container
// image vulnerabilities. Whitespace is normalized by `go generate`.
//
//go:embed images_vulnerabilities_fql_guide.md
var imagesVulnerabilitiesFQLGuide string

// cspmAssetsFQLGuide is the FQL documentation for searching CSPM assets.
// Whitespace is normalized by `go generate`.
//
//go:embed cspm_assets_fql_guide.md
var cspmAssetsFQLGuide string

// cspmIOMFindingsFQLGuide is the FQL documentation for searching CSPM IOM
// findings. Whitespace is normalized by `go generate`.
//
//go:embed cspm_iom_findings_fql_guide.md
var cspmIOMFindingsFQLGuide string

// cloudRisksFQLGuide is the FQL documentation for searching cloud risks.
// Whitespace is normalized by `go generate`.
//
//go:embed cloud_risks_fql_guide.md
var cloudRisksFQLGuide string

// cloudInsightsFQLGuide is the FQL documentation for searching cloud insights.
// Whitespace is normalized by `go generate`.
//
//go:embed cloud_insights_fql_guide.md
var cloudInsightsFQLGuide string
