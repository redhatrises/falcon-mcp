// MIT License
//
// Copyright (c) 2026 CrowdStrike
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

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
