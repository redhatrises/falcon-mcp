// Package cloud implements the falcon-mcp cloud tools over several gofalcon
// clients: Kubernetes & container inventory (kubernetes_protection,
// container_vulnerabilities), CSPM assets (cloud_security_assets), CSPM IOM
// findings (cloud_security_detections), cloud risks and cloud groups
// (cloud_security), and CSPM IOM suppression rules (cloud_policies). It registers
// the five cloud FQL guide resources.
//
// The module provides read-only search/count/detail tools plus two mutating
// suppression-rule tools (create and delete). Search tools that hydrate details
// follow the two-step pattern (query IDs, then fetch full entities); the
// combined endpoints (containers, vulnerabilities, risks) return full records in
// a single call and skip the detail fetch.
package cloud

import (
	"context"
	"encoding/json"
	"log/slog"

	"github.com/crowdstrike/gofalcon/falcon/client/kubernetes_protection"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/crowdstrike/falcon-mcp/internal/modules/base"
	"github.com/crowdstrike/falcon-mcp/internal/modules/registry"
)

// detailBatchSize is the maximum number of IDs fetched per details call. The
// CSPM asset and IOM get endpoints take IDs as query parameters, so this matches
// the Python module's validated 100-ID-per-request limit to keep request URLs
// within limits.
const detailBatchSize = 100

// scopes required by this module's operations, surfaced on a 403 via
// base.APIError and passed at each call site.
var (
	scopeContainerImageRead = base.Scope{Name: "Falcon Container Image", Read: true}
	scopeAssetsRead         = base.Scope{Name: "Cloud Security API Assets", Read: true}
	scopeDetectionsRead     = base.Scope{Name: "Cloud Security API Detections", Read: true}
	scopeRisksRead          = base.Scope{Name: "Cloud Security API Risks", Read: true}
	scopeGroupsRead         = base.Scope{Name: "Cloud Groups V2", Read: true}
	scopePoliciesRead       = base.Scope{Name: "Cloud Security Policies", Read: true}
	scopePoliciesWrite      = base.Scope{Name: "Cloud Security Policies", Write: true}
)

// Factory builds the cloud module from shared deps. The generated aggregator
// (internal/mcpserver) collects it, so the module needs no init side effect.
var Factory registry.Factory = func(d registry.Deps) base.Module {
	return &Module{
		Kubernetes:  d.API.KubernetesProtection,
		Vulns:       d.API.ContainerVulnerabilities,
		Assets:      d.API.CloudSecurityAssets,
		Detections:  d.API.CloudSecurityDetections,
		CloudSec:    d.API.CloudSecurity,
		Policies:    d.API.CloudPolicies,
		Concurrency: d.Concurrency,
		Logger:      d.Logger,
	}
}

// Module registers the cloud tools. It holds only shared, concurrency-safe
// gofalcon sub-clients and configuration; handlers are stateless and reentrant.
// Logger must be non-nil. Each field is a narrow local interface over one
// gofalcon sub-client so handlers can be tested against small fakes.
type Module struct {
	Kubernetes  kubernetesAPI
	Vulns       vulnsAPI
	Assets      assetsAPI
	Detections  detectionsAPI
	CloudSec    cloudSecAPI
	Policies    policiesAPI
	Concurrency int // bounds concurrent detail fetches
	Logger      *slog.Logger
}

// kubernetesAPI is the slice of the gofalcon kubernetes_protection client this
// module consumes.
type kubernetesAPI interface {
	ContainerCombined(*kubernetes_protection.ContainerCombinedParams, ...kubernetes_protection.ClientOption) (*kubernetes_protection.ContainerCombinedOK, error)
	ContainerCount(*kubernetes_protection.ContainerCountParams, ...kubernetes_protection.ClientOption) (*kubernetes_protection.ContainerCountOK, error)
}

// Name reports the module name.
func (m *Module) Name() string { return "cloud" }

// Description reports a one-line summary of the module.
func (m *Module) Description() string {
	return "Search Falcon cloud resources: Kubernetes containers, image vulnerabilities, CSPM assets, IOM findings, cloud risks, groups, and suppression rules"
}

// limitBounds applies limit/offset constraints and default that the jsonschema
// struct-tag syntax cannot express. The minimum is always 1.
func limitBounds(maxLimit, def float64) func(*jsonschema.Schema) {
	return func(s *jsonschema.Schema) {
		s.Properties["limit"].Minimum = jsonschema.Ptr(1.0)
		s.Properties["limit"].Maximum = jsonschema.Ptr(maxLimit)
		s.Properties["limit"].Default = json.RawMessage(intJSON(def))
		if off, ok := s.Properties["offset"]; ok {
			off.Minimum = jsonschema.Ptr(0.0)
		}
	}
}

// intJSON renders a whole-number float as a JSON integer literal for a schema
// default (e.g. 10 not 10.0).
func intJSON(f float64) string {
	b, _ := json.Marshal(int64(f))
	return string(b)
}

// RegisterTools registers all cloud tools into r.
func (m *Module) RegisterTools(r base.Registrar) {
	base.AddTool(r, &mcp.Tool{
		Name:        "search_kubernetes_containers",
		Description: searchKubernetesContainersDescription,
		InputSchema: searchKubernetesContainersSchema,
	}, m.searchKubernetesContainers)

	base.AddTool(r, &mcp.Tool{
		Name:        "count_kubernetes_containers",
		Description: countKubernetesContainersDescription,
		InputSchema: countKubernetesContainersSchema,
	}, m.countKubernetesContainers)

	base.AddTool(r, &mcp.Tool{
		Name:        "search_images_vulnerabilities",
		Description: searchImagesVulnerabilitiesDescription,
		InputSchema: searchImagesVulnerabilitiesSchema,
	}, m.searchImagesVulnerabilities)

	base.AddTool(r, &mcp.Tool{
		Name:        "search_cspm_assets",
		Description: searchCSPMAssetsDescription,
		InputSchema: searchCSPMAssetsSchema,
	}, m.searchCSPMAssets)

	base.AddTool(r, &mcp.Tool{
		Name:        "search_iom_findings",
		Description: searchIOMFindingsDescription,
		InputSchema: searchIOMFindingsSchema,
	}, m.searchIOMFindings)

	base.AddTool(r, &mcp.Tool{
		Name:        "search_cspm_suppression_rules",
		Description: searchCSPMSuppressionRulesDescription,
		InputSchema: searchCSPMSuppressionRulesSchema,
	}, m.searchCSPMSuppressionRules)

	base.AddTool(r, &mcp.Tool{
		Name:        "create_cspm_suppression_rule",
		Description: createCSPMSuppressionRuleDescription,
		Annotations: base.DestructiveAnnotations(false),
	}, m.createCSPMSuppressionRule)

	base.AddTool(r, &mcp.Tool{
		Name:        "delete_cspm_suppression_rules",
		Description: deleteCSPMSuppressionRulesDescription,
		Annotations: base.DestructiveAnnotations(true),
	}, m.deleteCSPMSuppressionRules)

	base.AddTool(r, &mcp.Tool{
		Name:        "search_cloud_risks",
		Description: searchCloudRisksDescription,
		InputSchema: searchCloudRisksSchema,
	}, m.searchCloudRisks)

	base.AddTool(r, &mcp.Tool{
		Name:        "search_cloud_groups",
		Description: searchCloudGroupsDescription,
		InputSchema: searchCloudGroupsSchema,
	}, m.searchCloudGroups)

	base.AddTool(r, &mcp.Tool{
		Name:        "get_cloud_groups",
		Description: getCloudGroupsDescription,
	}, m.getCloudGroups)
}

// RegisterResources publishes the five cloud FQL guides as MCP resources,
// mirroring the Python falcon-mcp cloud resources.
func (m *Module) RegisterResources(s *mcp.Server) {
	base.TextResource(s, kubernetesContainersFQLGuideURI,
		"kubernetes_containers_fql_filter_guide",
		"Contains the guide for the `filter` param of the `falcon_search_kubernetes_containers` and `falcon_count_kubernetes_containers` tools.",
		"text/markdown", kubernetesContainersFQLGuide)
	base.TextResource(s, imagesVulnerabilitiesFQLGuideURI,
		"images_vulnerabilities_fql_filter_guide",
		"Contains the guide for the `filter` param of the `falcon_search_images_vulnerabilities` tool.",
		"text/markdown", imagesVulnerabilitiesFQLGuide)
	base.TextResource(s, cspmAssetsFQLGuideURI,
		"search_cspm_assets_fql_guide",
		"Contains the guide for the `filter` param of the `falcon_search_cspm_assets` tool.",
		"text/markdown", cspmAssetsFQLGuide)
	base.TextResource(s, cspmIOMFindingsFQLGuideURI,
		"search_iom_findings_fql_guide",
		"Contains the guide for the `filter` param of the `falcon_search_iom_findings` tool.",
		"text/markdown", cspmIOMFindingsFQLGuide)
	base.TextResource(s, cloudRisksFQLGuideURI,
		"search_cloud_risks_fql_guide",
		"Contains the guide for the `filter` param of the `falcon_search_cloud_risks` tool.",
		"text/markdown", cloudRisksFQLGuide)
}

// RegisterPrompts is a no-op: the cloud module exposes no prompts.
func (m *Module) RegisterPrompts(_ *mcp.Server) {}

// --- Kubernetes containers ---

// SearchContainersInput is the input for falcon_search_kubernetes_containers.
type SearchContainersInput struct {
	Filter string `json:"filter,omitempty" jsonschema:"FQL filter. See the fql-guide resource for syntax."`
	Limit  int    `json:"limit,omitempty" jsonschema:"maximum number of containers to return"`
	Offset int    `json:"offset,omitempty" jsonschema:"starting index of overall result set from which to return containers"`
	Sort   string `json:"sort,omitempty" jsonschema:"FQL sort (e.g. container_name.desc, last_seen.desc)"`
}

var searchKubernetesContainersSchema = base.SchemaFor[SearchContainersInput](func(s *jsonschema.Schema) {
	s.Properties["filter"].Description = kubernetesContainersFilterDescription
	s.Properties["sort"].Description = kubernetesContainersSortDescription
	limitBounds(9999, 10)(s)
})

func (m *Module) searchKubernetesContainers(ctx context.Context, _ *mcp.CallToolRequest, in SearchContainersInput) (*mcp.CallToolResult, base.SearchResult[*models.ModelsContainer], error) {
	var zero base.SearchResult[*models.ModelsContainer]
	m.Logger.Debug("search_kubernetes_containers", "filter", in.Filter, "limit", in.Limit, "offset", in.Offset, "sort", in.Sort)

	params := kubernetes_protection.NewContainerCombinedParamsWithContext(ctx)
	limit := int64(in.Limit)
	if limit == 0 {
		limit = 10
	}
	params.Limit = &limit
	if in.Filter != "" {
		params.Filter = &in.Filter
	}
	if in.Offset != 0 {
		params.Offset = new(int64(in.Offset))
	}
	if in.Sort != "" {
		params.Sort = &in.Sort
	}

	resp, err := m.Kubernetes.ContainerCombined(params)
	if e := base.APIError(err, resp, scopeContainerImageRead); e != nil {
		return nil, zero, e
	}
	return nil, base.Found(resp.Payload.Resources, in.Filter).WithMeta(resp.Payload.Meta), nil
}

// CountContainersInput is the input for falcon_count_kubernetes_containers.
type CountContainersInput struct {
	Filter string `json:"filter,omitempty" jsonschema:"FQL filter. See the fql-guide resource for syntax."`
}

var countKubernetesContainersSchema = base.SchemaFor[CountContainersInput](func(s *jsonschema.Schema) {
	s.Properties["filter"].Description = kubernetesContainersFilterDescription
})

// CountResult is the structured output for falcon_count_kubernetes_containers.
type CountResult struct {
	Count int64 `json:"count"`
}

func (m *Module) countKubernetesContainers(ctx context.Context, _ *mcp.CallToolRequest, in CountContainersInput) (*mcp.CallToolResult, CountResult, error) {
	m.Logger.Debug("count_kubernetes_containers", "filter", in.Filter)

	params := kubernetes_protection.NewContainerCountParamsWithContext(ctx)
	if in.Filter != "" {
		params.Filter = &in.Filter
	}

	resp, err := m.Kubernetes.ContainerCount(params)
	if e := base.APIError(err, resp, scopeContainerImageRead); e != nil {
		return nil, CountResult{}, e
	}
	var count int64
	if resp.Payload != nil && len(resp.Payload.Resources) > 0 && resp.Payload.Resources[0].Count != nil {
		count = *resp.Payload.Resources[0].Count
	}
	return nil, CountResult{Count: count}, nil
}
