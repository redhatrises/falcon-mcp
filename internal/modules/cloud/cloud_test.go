package cloud

import (
	"context"
	"errors"
	"testing"

	"github.com/crowdstrike/gofalcon/falcon/client/cloud_policies"
	"github.com/crowdstrike/gofalcon/falcon/client/cloud_security"
	"github.com/crowdstrike/gofalcon/falcon/client/cloud_security_assets"
	"github.com/crowdstrike/gofalcon/falcon/client/cloud_security_detections"
	"github.com/crowdstrike/gofalcon/falcon/client/container_vulnerabilities"
	"github.com/crowdstrike/gofalcon/falcon/client/kubernetes_protection"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/crowdstrike/falcon-mcp/internal/modules/base"
	"github.com/crowdstrike/falcon-mcp/internal/testutil"
)

// metaQueryTime is a non-zero query_time for test fakes, so a handler's
// normalized meta is a populated value rather than nil.
var metaQueryTime = 0.02

var testLogger = testutil.DiscardLogger()

// --- Fakes ---

type fakeKubernetes struct {
	combinedResp *kubernetes_protection.ContainerCombinedOK
	combinedErr  error
	countResp    *kubernetes_protection.ContainerCountOK
	countErr     error
}

func (f *fakeKubernetes) ContainerCombined(*kubernetes_protection.ContainerCombinedParams, ...kubernetes_protection.ClientOption) (*kubernetes_protection.ContainerCombinedOK, error) {
	return f.combinedResp, f.combinedErr
}
func (f *fakeKubernetes) ContainerCount(*kubernetes_protection.ContainerCountParams, ...kubernetes_protection.ClientOption) (*kubernetes_protection.ContainerCountOK, error) {
	return f.countResp, f.countErr
}

type fakeVulns struct {
	resp *container_vulnerabilities.ReadCombinedVulnerabilitiesOK
	err  error
}

func (f *fakeVulns) ReadCombinedVulnerabilities(*container_vulnerabilities.ReadCombinedVulnerabilitiesParams, ...container_vulnerabilities.ClientOption) (*container_vulnerabilities.ReadCombinedVulnerabilitiesOK, error) {
	return f.resp, f.err
}

type fakeAssets struct {
	queryResp *cloud_security_assets.CloudSecurityAssetsQueriesOK
	queryErr  error
	getResp   *cloud_security_assets.CloudSecurityAssetsEntitiesGetOK
	getCalls  int
	getIDs    []string
	lastQuery *cloud_security_assets.CloudSecurityAssetsQueriesParams
}

func (f *fakeAssets) CloudSecurityAssetsQueries(p *cloud_security_assets.CloudSecurityAssetsQueriesParams, _ ...cloud_security_assets.ClientOption) (*cloud_security_assets.CloudSecurityAssetsQueriesOK, error) {
	f.lastQuery = p
	return f.queryResp, f.queryErr
}
func (f *fakeAssets) CloudSecurityAssetsEntitiesGet(p *cloud_security_assets.CloudSecurityAssetsEntitiesGetParams, _ ...cloud_security_assets.ClientOption) (*cloud_security_assets.CloudSecurityAssetsEntitiesGetOK, error) {
	f.getCalls++
	f.getIDs = p.Ids
	return f.getResp, nil
}

type fakeDetections struct {
	queryResp *cloud_security_detections.CspmEvaluationsIomQueriesOK
	queryErr  error
	getResp   *cloud_security_detections.CspmEvaluationsIomEntitiesOK
	getCalls  int
	lastQuery *cloud_security_detections.CspmEvaluationsIomQueriesParams
}

func (f *fakeDetections) CspmEvaluationsIomQueries(p *cloud_security_detections.CspmEvaluationsIomQueriesParams, _ ...cloud_security_detections.ClientOption) (*cloud_security_detections.CspmEvaluationsIomQueriesOK, error) {
	f.lastQuery = p
	return f.queryResp, f.queryErr
}
func (f *fakeDetections) CspmEvaluationsIomEntities(*cloud_security_detections.CspmEvaluationsIomEntitiesParams, ...cloud_security_detections.ClientOption) (*cloud_security_detections.CspmEvaluationsIomEntitiesOK, error) {
	f.getCalls++
	return f.getResp, nil
}

type fakeCloudSec struct {
	risksResp    *cloud_security.CombinedCloudRisksOK
	risksErr     error
	listResp     *cloud_security.ListCloudGroupsExternalOK
	listErr      error
	byIDResp     *cloud_security.ListCloudGroupsByIDExternalOK
	byIDErr      error
	lastListLim  string
	lastByIDsLen int
}

func (f *fakeCloudSec) CombinedCloudRisks(*cloud_security.CombinedCloudRisksParams, ...cloud_security.ClientOption) (*cloud_security.CombinedCloudRisksOK, error) {
	return f.risksResp, f.risksErr
}
func (f *fakeCloudSec) ListCloudGroupsExternal(p *cloud_security.ListCloudGroupsExternalParams, _ ...cloud_security.ClientOption) (*cloud_security.ListCloudGroupsExternalOK, error) {
	if p.Limit != nil {
		f.lastListLim = *p.Limit
	}
	return f.listResp, f.listErr
}
func (f *fakeCloudSec) ListCloudGroupsByIDExternal(p *cloud_security.ListCloudGroupsByIDExternalParams, _ ...cloud_security.ClientOption) (*cloud_security.ListCloudGroupsByIDExternalOK, error) {
	f.lastByIDsLen = len(p.Ids)
	return f.byIDResp, f.byIDErr
}

type fakePolicies struct {
	queryResp  *cloud_policies.QuerySuppressionRulesOK
	queryErr   error
	getResp    *cloud_policies.GetSuppressionRulesOK
	getCalls   int
	createResp *cloud_policies.CreateSuppressionRuleOK
	createErr  error
	createBody *models.SuppressionrulesCreateSuppressionRuleRequest
	deleteResp *cloud_policies.DeleteSuppressionRulesOK
	deleteErr  error
	deleteIDs  []string
}

func (f *fakePolicies) QuerySuppressionRules(*cloud_policies.QuerySuppressionRulesParams, ...cloud_policies.ClientOption) (*cloud_policies.QuerySuppressionRulesOK, error) {
	return f.queryResp, f.queryErr
}
func (f *fakePolicies) GetSuppressionRules(*cloud_policies.GetSuppressionRulesParams, ...cloud_policies.ClientOption) (*cloud_policies.GetSuppressionRulesOK, error) {
	f.getCalls++
	return f.getResp, nil
}
func (f *fakePolicies) CreateSuppressionRule(p *cloud_policies.CreateSuppressionRuleParams, _ ...cloud_policies.ClientOption) (*cloud_policies.CreateSuppressionRuleOK, error) {
	f.createBody = p.Body
	return f.createResp, f.createErr
}
func (f *fakePolicies) DeleteSuppressionRules(p *cloud_policies.DeleteSuppressionRulesParams, _ ...cloud_policies.ClientOption) (*cloud_policies.DeleteSuppressionRulesOK, error) {
	f.deleteIDs = p.Ids
	return f.deleteResp, f.deleteErr
}

// --- Kubernetes containers ---

func TestSearchKubernetesContainersReturnsRecords(t *testing.T) {
	t.Parallel()
	f := &fakeKubernetes{combinedResp: &kubernetes_protection.ContainerCombinedOK{Payload: &models.ModelsContainerEntityResponse{
		Resources: []*models.ModelsContainer{{ContainerID: new("c1")}, {ContainerID: new("c2")}},
		Meta:      &models.MsaMetaInfo{QueryTime: &metaQueryTime},
	}}}
	m := &Module{Kubernetes: f, Logger: testLogger}

	_, out, err := m.searchKubernetesContainers(context.Background(), nil, SearchContainersInput{Filter: "running_status:true"})
	if err != nil {
		t.Fatalf("searchKubernetesContainers: %v", err)
	}
	if len(out.Resources) != 2 {
		t.Fatalf("expected 2 records, got %+v", out)
	}
	if out.FilterUsed != "running_status:true" {
		t.Fatalf("filter_used = %q", out.FilterUsed)
	}
}

func TestSearchKubernetesContainersEmpty(t *testing.T) {
	t.Parallel()
	f := &fakeKubernetes{combinedResp: &kubernetes_protection.ContainerCombinedOK{Payload: &models.ModelsContainerEntityResponse{Resources: []*models.ModelsContainer{}}}}
	m := &Module{Kubernetes: f, Logger: testLogger}

	_, out, err := m.searchKubernetesContainers(context.Background(), nil, SearchContainersInput{})
	if err != nil {
		t.Fatalf("searchKubernetesContainers: %v", err)
	}
	if out.Resources == nil || len(out.Resources) != 0 {
		t.Fatalf("expected non-nil empty slice, got %+v", out.Resources)
	}
}

func TestCountKubernetesContainers(t *testing.T) {
	t.Parallel()
	f := &fakeKubernetes{countResp: &kubernetes_protection.ContainerCountOK{Payload: &models.CommonCountResponse{
		Resources: []*models.CommonCountAsResource{{Count: new(int64(42))}},
	}}}
	m := &Module{Kubernetes: f, Logger: testLogger}

	_, out, err := m.countKubernetesContainers(context.Background(), nil, CountContainersInput{Filter: "cluster_name:'prod'"})
	if err != nil {
		t.Fatalf("countKubernetesContainers: %v", err)
	}
	if out.Count != 42 {
		t.Fatalf("expected count 42, got %d", out.Count)
	}
}

func TestCountKubernetesContainersEmptyResources(t *testing.T) {
	t.Parallel()
	f := &fakeKubernetes{countResp: &kubernetes_protection.ContainerCountOK{Payload: &models.CommonCountResponse{Resources: []*models.CommonCountAsResource{}}}}
	m := &Module{Kubernetes: f, Logger: testLogger}

	_, out, err := m.countKubernetesContainers(context.Background(), nil, CountContainersInput{})
	if err != nil {
		t.Fatalf("countKubernetesContainers: %v", err)
	}
	if out.Count != 0 {
		t.Fatalf("expected count 0 for empty resources, got %d", out.Count)
	}
}

// --- Images vulnerabilities ---

func TestSearchImagesVulnerabilities(t *testing.T) {
	t.Parallel()
	f := &fakeVulns{resp: &container_vulnerabilities.ReadCombinedVulnerabilitiesOK{Payload: &models.VulnerabilitiesAPICombinedVulnerability{
		Resources: []*models.ModelsAPIVulnerabilityCombined{{CveID: new("CVE-2025-1")}},
		Meta:      &models.MsaMetaInfo{QueryTime: &metaQueryTime},
	}}}
	m := &Module{Vulns: f, Logger: testLogger}

	_, out, err := m.searchImagesVulnerabilities(context.Background(), nil, SearchVulnerabilitiesInput{Filter: "cvss_score:>5"})
	if err != nil {
		t.Fatalf("searchImagesVulnerabilities: %v", err)
	}
	if len(out.Resources) != 1 {
		t.Fatalf("expected 1 record, got %+v", out)
	}
}

// --- CSPM assets ---

func TestSearchCSPMAssetsSlimsAndReturns(t *testing.T) {
	t.Parallel()
	f := &fakeAssets{
		queryResp: &cloud_security_assets.CloudSecurityAssetsQueriesOK{Payload: &models.AssetsGetResourceIDsResponse{
			Resources: []string{"a1", "a2"},
			Meta:      &models.RestCursorAndLimitMetaInfo{QueryTime: &metaQueryTime},
		}},
		getResp: &cloud_security_assets.CloudSecurityAssetsEntitiesGetOK{Payload: &models.AssetsGetResourcesResponse{
			Resources: []*models.ResourcesCloudResource{
				{ID: "a1", ResourceName: "bucket-1", CloudProvider: "AWS"},
				{ID: "a2", ResourceName: "vm-2", CloudProvider: "Azure"},
			},
		}},
	}
	m := &Module{Assets: f, Concurrency: 4, Logger: testLogger}

	_, out, err := m.searchCSPMAssets(context.Background(), nil, SearchCSPMAssetsInput{Filter: "cloud_provider:'AWS'"})
	if err != nil {
		t.Fatalf("searchCSPMAssets: %v", err)
	}
	if len(out.Resources) != 2 {
		t.Fatalf("expected 2 slimmed assets, got %+v", out)
	}
	if f.getCalls != 1 {
		t.Fatalf("expected one detail fetch, got %d", f.getCalls)
	}
	// Slimmed record keeps id/resource_name/cloud_provider and drops nothing added.
	first := out.Resources[0]
	if first["id"] != "a1" {
		t.Fatalf("expected slimmed id a1, got %v", first["id"])
	}
	if first["resource_name"] != "bucket-1" {
		t.Fatalf("expected resource_name bucket-1, got %v", first["resource_name"])
	}
	if _, ok := first["cloud_provider"]; !ok {
		t.Fatalf("expected cloud_provider key retained, got %+v", first)
	}
}

// TestSearchCSPMAssetsSlimming exercises slimCSPMAsset/slimCloudContext against a
// fully-populated asset: it asserts that (a) kept top-level fields survive, (b)
// bloat fields outside keepTopLevel are dropped, and (c) cloud_context is trimmed
// to the scalar/detections/insights subset while benchmark-style bloat is
// stripped. This locks in the Python-parity slimming behavior, which the
// happy-path test above does not exercise.
func TestSearchCSPMAssetsSlimming(t *testing.T) {
	t.Parallel()
	asset := &models.ResourcesCloudResource{
		ID:            "a1",
		ResourceName:  "bucket-1",
		CloudProvider: "AWS",
		Region:        "us-east-1",
		// Configuration is bloat outside keepTopLevel and must be dropped.
		Configuration: map[string]any{"raw": "big-blob"},
		CloudContext: &models.ResourcesCloudContext{
			CspmLicense:     "standard",
			ManagedBy:       "Sensor",
			PubliclyExposed: true,
			Detections: &models.ResourcesDetections{
				HighestSeverity: "critical",
				IomCounts:       new(int64(5)),
				IoaCounts:       new(int64(2)),
				Severities:      []string{"critical", "high"},
				// Compliant is benchmark bloat outside detectionsKeep and must be dropped.
				Compliant: &models.ResourcesCompliance{},
			},
			Insights: &models.InsightsInsight{
				External: []*models.InsightsExternal{{}},
			},
		},
	}
	f := &fakeAssets{
		queryResp: &cloud_security_assets.CloudSecurityAssetsQueriesOK{Payload: &models.AssetsGetResourceIDsResponse{Resources: []string{"a1"}}},
		getResp:   &cloud_security_assets.CloudSecurityAssetsEntitiesGetOK{Payload: &models.AssetsGetResourcesResponse{Resources: []*models.ResourcesCloudResource{asset}}},
	}
	m := &Module{Assets: f, Concurrency: 4, Logger: testLogger}

	_, out, err := m.searchCSPMAssets(context.Background(), nil, SearchCSPMAssetsInput{})
	if err != nil {
		t.Fatalf("searchCSPMAssets: %v", err)
	}
	if len(out.Resources) != 1 {
		t.Fatalf("expected 1 slimmed asset, got %d", len(out.Resources))
	}
	got := out.Resources[0]

	// Kept top-level fields survive.
	for _, k := range []string{"id", "resource_name", "cloud_provider", "region"} {
		if _, ok := got[k]; !ok {
			t.Errorf("expected top-level field %q retained, got %+v", k, got)
		}
	}
	// Bloat top-level field is dropped.
	if _, ok := got["configuration"]; ok {
		t.Errorf("expected bloat field configuration dropped, got %+v", got)
	}

	ctx, ok := got["cloud_context"].(map[string]any)
	if !ok {
		t.Fatalf("expected cloud_context object, got %T", got["cloud_context"])
	}
	// Scalar cloud_context fields kept.
	for _, k := range []string{"cspm_license", "managed_by", "publicly_exposed"} {
		if _, ok := ctx[k]; !ok {
			t.Errorf("expected cloud_context scalar %q retained, got %+v", k, ctx)
		}
	}
	// detections trimmed to counts/severity; benchmark bloat (compliant) dropped.
	det, ok := ctx["detections"].(map[string]any)
	if !ok {
		t.Fatalf("expected detections object, got %T", ctx["detections"])
	}
	for _, k := range []string{"highest_severity", "iom_counts", "ioa_counts", "severities"} {
		if _, ok := det[k]; !ok {
			t.Errorf("expected detections field %q retained, got %+v", k, det)
		}
	}
	if _, ok := det["compliant"]; ok {
		t.Errorf("expected detections bloat field compliant dropped, got %+v", det)
	}
	// insights keeps only external.
	ins, ok := ctx["insights"].(map[string]any)
	if !ok {
		t.Fatalf("expected insights object, got %T", ctx["insights"])
	}
	if _, ok := ins["external"]; !ok {
		t.Errorf("expected insights.external retained, got %+v", ins)
	}
	if _, ok := ins["details"]; ok {
		t.Errorf("expected insights.details dropped, got %+v", ins)
	}
}

func TestSearchCSPMAssetsEmptyNoFetch(t *testing.T) {
	t.Parallel()
	f := &fakeAssets{queryResp: &cloud_security_assets.CloudSecurityAssetsQueriesOK{Payload: &models.AssetsGetResourceIDsResponse{Resources: []string{}}}}
	m := &Module{Assets: f, Concurrency: 4, Logger: testLogger}

	_, out, err := m.searchCSPMAssets(context.Background(), nil, SearchCSPMAssetsInput{})
	if err != nil {
		t.Fatalf("searchCSPMAssets: %v", err)
	}
	if out.Resources == nil || len(out.Resources) != 0 {
		t.Fatalf("expected non-nil empty slice, got %+v", out.Resources)
	}
	if f.getCalls != 0 {
		t.Fatalf("expected no detail fetch on empty result, got %d", f.getCalls)
	}
}

func TestSearchCSPMAssetsFQLError(t *testing.T) {
	t.Parallel()
	badReq := &cloud_security_assets.CloudSecurityAssetsQueriesBadRequest{Payload: &models.RestCursorResponseFields{
		Errors: []*models.MsaAPIError{{Code: new(int32(400)), Message: new("found unknown filter values: bogus")}},
	}}
	f := &fakeAssets{queryErr: badReq}
	m := &Module{Assets: f, Concurrency: 4, Logger: testLogger}

	_, out, err := m.searchCSPMAssets(context.Background(), nil, SearchCSPMAssetsInput{Filter: "bogus:'x'"})
	if err != nil {
		t.Fatalf("searchCSPMAssets should return FQL error as data, got Go error: %v", err)
	}
	if len(out.Errors) != 1 || out.Errors[0].Code != 400 {
		t.Fatalf("expected one FQL error detail, got %+v", out.Errors)
	}
	if out.FQLGuide == "" {
		t.Fatal("expected FQL guide text in FQL-error response")
	}
	if f.getCalls != 0 {
		t.Fatalf("expected no detail fetch on FQL error, got %d", f.getCalls)
	}
}

// --- IOM findings ---

func TestSearchIOMFindingsReturnsDetails(t *testing.T) {
	t.Parallel()
	f := &fakeDetections{
		queryResp: &cloud_security_detections.CspmEvaluationsIomQueriesOK{Payload: &models.EvaluationsQueryIOMsResponse{
			Resources: []string{"i1", "i2"},
			Meta:      &models.RestCursorAndLimitMetaInfo{QueryTime: &metaQueryTime},
		}},
		getResp: &cloud_security_detections.CspmEvaluationsIomEntitiesOK{Payload: &models.EvaluationsGetIOMsResponse{
			Resources: []*models.EvaluationsEvaluation{{ID: "i1"}, {ID: "i2"}},
		}},
	}
	m := &Module{Detections: f, Concurrency: 4, Logger: testLogger}

	_, out, err := m.searchIOMFindings(context.Background(), nil, SearchIOMFindingsInput{Filter: "status:'open'"})
	if err != nil {
		t.Fatalf("searchIOMFindings: %v", err)
	}
	if len(out.Resources) != 2 {
		t.Fatalf("expected 2 IOM records, got %+v", out)
	}
	if f.getCalls != 1 {
		t.Fatalf("expected one detail fetch, got %d", f.getCalls)
	}
}

// TestSearchIOMFindingsSurfacesSiblingCursor pins that this endpoint's top-level
// "next" cursor — reported as a sibling of pagination rather than inside it — is
// folded into pagination.next, so a caller reads the cursor from the same place on
// every endpoint.
func TestSearchIOMFindingsSurfacesSiblingCursor(t *testing.T) {
	t.Parallel()
	f := &fakeDetections{
		queryResp: &cloud_security_detections.CspmEvaluationsIomQueriesOK{Payload: &models.EvaluationsQueryIOMsResponse{
			Resources: []string{},
			Meta:      &models.RestCursorAndLimitMetaInfo{QueryTime: &metaQueryTime, Next: "cursor-next"},
		}},
	}
	m := &Module{Detections: f, Concurrency: 4, Logger: testLogger}

	_, out, err := m.searchIOMFindings(context.Background(), nil, SearchIOMFindingsInput{})
	if err != nil {
		t.Fatalf("searchIOMFindings: %v", err)
	}
	if out.Meta == nil || out.Meta.Pagination == nil {
		t.Fatalf("result must carry pagination meta, got %+v", out.Meta)
	}
	if out.Meta.Pagination.Next != "cursor-next" {
		t.Errorf("pagination.next = %q, want cursor-next", out.Meta.Pagination.Next)
	}
}

func TestSearchIOMFindingsFQLError(t *testing.T) {
	t.Parallel()
	badReq := &cloud_security_detections.CspmEvaluationsIomQueriesBadRequest{Payload: &models.RestCursorResponseFields{
		Errors: []*models.MsaAPIError{{Code: new(int32(400)), Message: new("unknown field")}},
	}}
	f := &fakeDetections{queryErr: badReq}
	m := &Module{Detections: f, Concurrency: 4, Logger: testLogger}

	_, out, err := m.searchIOMFindings(context.Background(), nil, SearchIOMFindingsInput{Filter: "bogus:'x'"})
	if err != nil {
		t.Fatalf("searchIOMFindings should return FQL error as data, got: %v", err)
	}
	if len(out.Errors) != 1 {
		t.Fatalf("expected one FQL error detail, got %+v", out.Errors)
	}
	if f.getCalls != 0 {
		t.Fatalf("expected no detail fetch on FQL error, got %d", f.getCalls)
	}
}

// --- Cloud risks ---

func TestSearchCloudRisks(t *testing.T) {
	t.Parallel()
	f := &fakeCloudSec{risksResp: &cloud_security.CombinedCloudRisksOK{Payload: &models.RisksGetCloudRisksResponse{
		Resources: []*models.RisksUnionCloudRisk{{ID: new("r1")}},
		Meta:      &models.MsaMetaInfo{QueryTime: &metaQueryTime},
	}}}
	m := &Module{CloudSec: f, Logger: testLogger}

	_, out, err := m.searchCloudRisks(context.Background(), nil, SearchCloudRisksInput{Filter: "severity:'Critical'"})
	if err != nil {
		t.Fatalf("searchCloudRisks: %v", err)
	}
	if len(out.Resources) != 1 {
		t.Fatalf("expected 1 risk, got %+v", out)
	}
}

func TestSearchCloudRisksFQLError(t *testing.T) {
	t.Parallel()
	badReq := &cloud_security.CombinedCloudRisksBadRequest{Payload: &models.APICursorResponseFields{
		Errors: []*models.MsaAPIError{{Code: new(int32(400)), Message: new("unknown field")}},
	}}
	f := &fakeCloudSec{risksErr: badReq}
	m := &Module{CloudSec: f, Logger: testLogger}

	_, out, err := m.searchCloudRisks(context.Background(), nil, SearchCloudRisksInput{Filter: "bogus:'x'"})
	if err != nil {
		t.Fatalf("searchCloudRisks should return FQL error as data, got: %v", err)
	}
	if len(out.Errors) != 1 {
		t.Fatalf("expected one FQL error detail, got %+v", out.Errors)
	}
}

// --- Cloud groups ---

func TestSearchCloudGroupsConvertsLimitToString(t *testing.T) {
	t.Parallel()
	f := &fakeCloudSec{listResp: &cloud_security.ListCloudGroupsExternalOK{Payload: &models.AssetgroupmanagerV1ListCloudGroupsResponse{
		Resources: []*models.AssetgroupmanagerV1CloudGroup{{ID: "g1", Name: "prod"}},
	}}}
	m := &Module{CloudSec: f, Logger: testLogger}

	_, out, err := m.searchCloudGroups(context.Background(), nil, SearchCloudGroupsInput{Limit: 25})
	if err != nil {
		t.Fatalf("searchCloudGroups: %v", err)
	}
	if len(out.Resources) != 1 {
		t.Fatalf("expected 1 group, got %+v", out)
	}
	if f.lastListLim != "25" {
		t.Fatalf("expected limit forwarded as string \"25\", got %q", f.lastListLim)
	}
}

func TestSearchCloudGroupsDefaultLimit(t *testing.T) {
	t.Parallel()
	f := &fakeCloudSec{listResp: &cloud_security.ListCloudGroupsExternalOK{Payload: &models.AssetgroupmanagerV1ListCloudGroupsResponse{Resources: []*models.AssetgroupmanagerV1CloudGroup{}}}}
	m := &Module{CloudSec: f, Logger: testLogger}

	_, _, err := m.searchCloudGroups(context.Background(), nil, SearchCloudGroupsInput{})
	if err != nil {
		t.Fatalf("searchCloudGroups: %v", err)
	}
	if f.lastListLim != "100" {
		t.Fatalf("expected default limit \"100\", got %q", f.lastListLim)
	}
}

func TestGetCloudGroups(t *testing.T) {
	t.Parallel()
	f := &fakeCloudSec{byIDResp: &cloud_security.ListCloudGroupsByIDExternalOK{Payload: &models.AssetgroupmanagerV1ListCloudGroupsResponse{
		Resources: []*models.AssetgroupmanagerV1CloudGroup{{ID: "g1"}, {ID: "g2"}},
	}}}
	m := &Module{CloudSec: f, Logger: testLogger}

	_, out, err := m.getCloudGroups(context.Background(), nil, GetCloudGroupsInput{IDs: []string{"g1", "g2"}})
	if err != nil {
		t.Fatalf("getCloudGroups: %v", err)
	}
	if out.Total != 2 || len(out.Resources) != 2 {
		t.Fatalf("expected 2 groups, got %+v", out)
	}
	if f.lastByIDsLen != 2 {
		t.Fatalf("expected 2 IDs forwarded, got %d", f.lastByIDsLen)
	}
}

func TestGetCloudGroupsEmptyIDs(t *testing.T) {
	t.Parallel()
	f := &fakeCloudSec{}
	m := &Module{CloudSec: f, Logger: testLogger}

	_, out, err := m.getCloudGroups(context.Background(), nil, GetCloudGroupsInput{IDs: nil})
	if err != nil {
		t.Fatalf("getCloudGroups: %v", err)
	}
	if out.Resources == nil || len(out.Resources) != 0 {
		t.Fatalf("expected empty result for no IDs, got %+v", out)
	}
	if f.lastByIDsLen != 0 {
		t.Fatalf("expected no API call for empty IDs")
	}
}

// --- Suppression rules ---

func TestSearchCSPMSuppressionRules(t *testing.T) {
	t.Parallel()
	f := &fakePolicies{
		queryResp: &cloud_policies.QuerySuppressionRulesOK{Payload: &models.SuppressionrulesQuerySuppressionRulesResponse{
			Resources: []string{"s1", "s2"},
			Meta:      &models.MsaMetaInfo{QueryTime: &metaQueryTime},
		}},
		getResp: &cloud_policies.GetSuppressionRulesOK{Payload: &models.SuppressionrulesGetSuppressionRulesResponse{
			Resources: []*models.ApimodelsSuppressionRule{{ID: new("s1")}, {ID: new("s2")}},
		}},
	}
	m := &Module{Policies: f, Logger: testLogger}

	_, out, err := m.searchCSPMSuppressionRules(context.Background(), nil, SearchSuppressionRulesInput{})
	if err != nil {
		t.Fatalf("searchCSPMSuppressionRules: %v", err)
	}
	if out.Total != 2 {
		t.Fatalf("expected 2 rules, got %+v", out)
	}
	if f.getCalls != 1 {
		t.Fatalf("expected one detail fetch, got %d", f.getCalls)
	}
}

func TestSearchCSPMSuppressionRulesEmpty(t *testing.T) {
	t.Parallel()
	f := &fakePolicies{queryResp: &cloud_policies.QuerySuppressionRulesOK{Payload: &models.SuppressionrulesQuerySuppressionRulesResponse{Resources: []string{}}}}
	m := &Module{Policies: f, Logger: testLogger}

	_, out, err := m.searchCSPMSuppressionRules(context.Background(), nil, SearchSuppressionRulesInput{})
	if err != nil {
		t.Fatalf("searchCSPMSuppressionRules: %v", err)
	}
	if out.Resources == nil || len(out.Resources) != 0 {
		t.Fatalf("expected non-nil empty slice, got %+v", out.Resources)
	}
	if f.getCalls != 0 {
		t.Fatalf("expected no detail fetch on empty result, got %d", f.getCalls)
	}
}

func TestCreateCSPMSuppressionRuleBuildsBody(t *testing.T) {
	t.Parallel()
	f := &fakePolicies{
		createResp: &cloud_policies.CreateSuppressionRuleOK{Payload: &models.SuppressionrulesCreateSuppressionRuleResponse{Resources: []string{"new1"}}},
		getResp:    &cloud_policies.GetSuppressionRulesOK{Payload: &models.SuppressionrulesGetSuppressionRulesResponse{Resources: []*models.ApimodelsSuppressionRule{{ID: new("new1")}}}},
	}
	m := &Module{Policies: f, Logger: testLogger}

	_, out, err := m.createCSPMSuppressionRule(context.Background(), nil, CreateSuppressionRuleInput{
		Name:              "hide dev S3",
		SuppressionReason: "accept-risk",
		RuleSeverities:    []string{"low"},
		CloudProviders:    []string{"aws"},
		ExpirationDate:    "2025-12-31T23:59:59Z",
	})
	if err != nil {
		t.Fatalf("createCSPMSuppressionRule: %v", err)
	}
	if out.Total != 1 {
		t.Fatalf("expected created rule fetched, got %+v", out)
	}
	body := f.createBody
	if body == nil {
		t.Fatal("expected create body to be set")
	}
	if body.Name == nil || *body.Name != "hide dev S3" {
		t.Fatalf("body.Name = %v", body.Name)
	}
	if body.Domain == nil || *body.Domain != "CSPM" || body.Subdomain == nil || *body.Subdomain != "IOM" {
		t.Fatalf("expected CSPM/IOM domain, got %v/%v", body.Domain, body.Subdomain)
	}
	if body.RuleSelectionType == nil || *body.RuleSelectionType != "rule_selection_filter" {
		t.Fatalf("rule_selection_type = %v", body.RuleSelectionType)
	}
	if body.ScopeType == nil || *body.ScopeType != "asset_filter" {
		t.Fatalf("expected scope_type asset_filter (provider given), got %v", body.ScopeType)
	}
	if body.RuleSelectionFilter == nil || len(body.RuleSelectionFilter.RuleSeverities) != 1 {
		t.Fatalf("expected rule severities in selection filter, got %+v", body.RuleSelectionFilter)
	}
	if body.ScopeAssetFilter == nil || len(body.ScopeAssetFilter.CloudProviders) != 1 {
		t.Fatalf("expected cloud providers in asset filter, got %+v", body.ScopeAssetFilter)
	}
	if body.SuppressionExpirationDate != "2025-12-31T23:59:59Z" {
		t.Fatalf("expiration = %q", body.SuppressionExpirationDate)
	}
}

func TestCreateCSPMSuppressionRuleAllAssetsScope(t *testing.T) {
	t.Parallel()
	f := &fakePolicies{
		createResp: &cloud_policies.CreateSuppressionRuleOK{Payload: &models.SuppressionrulesCreateSuppressionRuleResponse{Resources: []string{"new1"}}},
		getResp:    &cloud_policies.GetSuppressionRulesOK{Payload: &models.SuppressionrulesGetSuppressionRulesResponse{Resources: []*models.ApimodelsSuppressionRule{{ID: new("new1")}}}},
	}
	m := &Module{Policies: f, Logger: testLogger}

	_, _, err := m.createCSPMSuppressionRule(context.Background(), nil, CreateSuppressionRuleInput{
		Name:              "hide all",
		SuppressionReason: "false-positive",
		RuleIDs:           []string{"CS-001"},
	})
	if err != nil {
		t.Fatalf("createCSPMSuppressionRule: %v", err)
	}
	if f.createBody.ScopeType == nil || *f.createBody.ScopeType != "all_assets" {
		t.Fatalf("expected scope_type all_assets when no asset filter, got %v", f.createBody.ScopeType)
	}
	if f.createBody.ScopeAssetFilter != nil {
		t.Fatalf("expected no scope_asset_filter when no asset scope, got %+v", f.createBody.ScopeAssetFilter)
	}
}

func TestCreateCSPMSuppressionRuleInvalidReason(t *testing.T) {
	t.Parallel()
	f := &fakePolicies{}
	m := &Module{Policies: f, Logger: testLogger}

	_, _, err := m.createCSPMSuppressionRule(context.Background(), nil, CreateSuppressionRuleInput{
		Name:              "x",
		SuppressionReason: "not-a-reason",
		RuleIDs:           []string{"CS-001"},
	})
	if !errors.Is(err, errInvalidInput) {
		t.Fatalf("expected errInvalidInput for bad reason, got %v", err)
	}
	if f.createBody != nil {
		t.Fatal("expected no API call on validation failure")
	}
}

func TestCreateCSPMSuppressionRuleNoRuleSelection(t *testing.T) {
	t.Parallel()
	f := &fakePolicies{}
	m := &Module{Policies: f, Logger: testLogger}

	_, _, err := m.createCSPMSuppressionRule(context.Background(), nil, CreateSuppressionRuleInput{
		Name:              "x",
		SuppressionReason: "accept-risk",
	})
	if !errors.Is(err, errInvalidInput) {
		t.Fatalf("expected errInvalidInput without rule selection, got %v", err)
	}
	if f.createBody != nil {
		t.Fatal("expected no API call on validation failure")
	}
}

func TestDeleteCSPMSuppressionRules(t *testing.T) {
	t.Parallel()
	f := &fakePolicies{deleteResp: &cloud_policies.DeleteSuppressionRulesOK{Payload: &models.SuppressionrulesDeleteSuppressionRulesResponse{
		Resources: []*models.ApimodelsSuppressionRule{{ID: new("s1")}},
	}}}
	m := &Module{Policies: f, Logger: testLogger}

	_, out, err := m.deleteCSPMSuppressionRules(context.Background(), nil, DeleteSuppressionRulesInput{IDs: []string{"s1"}})
	if err != nil {
		t.Fatalf("deleteCSPMSuppressionRules: %v", err)
	}
	if out.Total != 1 {
		t.Fatalf("expected 1 deleted rule returned, got %+v", out)
	}
	if len(f.deleteIDs) != 1 || f.deleteIDs[0] != "s1" {
		t.Fatalf("expected ids forwarded, got %+v", f.deleteIDs)
	}
}

func TestDeleteCSPMSuppressionRulesEmptyIDs(t *testing.T) {
	t.Parallel()
	f := &fakePolicies{}
	m := &Module{Policies: f, Logger: testLogger}

	_, _, err := m.deleteCSPMSuppressionRules(context.Background(), nil, DeleteSuppressionRulesInput{})
	if !errors.Is(err, errInvalidInput) {
		t.Fatalf("expected errInvalidInput for empty ids, got %v", err)
	}
	if f.deleteIDs != nil {
		t.Fatal("expected no API call for empty ids")
	}
}

// --- Annotations ---

func TestRegisterToolsAnnotations(t *testing.T) {
	t.Parallel()
	var entries []base.ToolEntry
	reg := testutil.CaptureRegistrar(func(e base.ToolEntry) { entries = append(entries, e) })
	m := &Module{Logger: testLogger}
	m.RegisterTools(reg)

	byName := map[string]*mcp.Tool{}
	for _, e := range entries {
		byName[e.Tool.Name] = e.Tool
	}

	// Read-only tools default to read-only annotations.
	readOnly := []string{
		"falcon_search_kubernetes_containers",
		"falcon_count_kubernetes_containers",
		"falcon_search_images_vulnerabilities",
		"falcon_search_cspm_assets",
		"falcon_search_iom_findings",
		"falcon_search_cspm_suppression_rules",
		"falcon_search_cloud_risks",
		"falcon_search_cloud_groups",
		"falcon_get_cloud_groups",
	}
	for _, name := range readOnly {
		tool := byName[name]
		if tool == nil {
			t.Fatalf("missing tool %s", name)
		}
		if tool.Annotations == nil || !tool.Annotations.ReadOnlyHint {
			t.Errorf("%s: expected ReadOnlyHint true", name)
		}
	}

	create := byName["falcon_create_cspm_suppression_rule"]
	if create == nil {
		t.Fatal("missing falcon_create_cspm_suppression_rule")
	}
	assertDestructive(t, "falcon_create_cspm_suppression_rule", create.Annotations, false)

	del := byName["falcon_delete_cspm_suppression_rules"]
	if del == nil {
		t.Fatal("missing falcon_delete_cspm_suppression_rules")
	}
	assertDestructive(t, "falcon_delete_cspm_suppression_rules", del.Annotations, true)
}

// assertDestructive verifies a tool carries destructive-mutator annotations,
// matching base.DestructiveAnnotations(idempotent).
func assertDestructive(t *testing.T, name string, a *mcp.ToolAnnotations, idempotent bool) {
	t.Helper()
	if a == nil {
		t.Fatalf("%s: annotations nil", name)
	}
	if a.ReadOnlyHint {
		t.Errorf("%s: ReadOnlyHint = true, want false", name)
	}
	if a.IdempotentHint != idempotent {
		t.Errorf("%s: IdempotentHint = %v, want %v", name, a.IdempotentHint, idempotent)
	}
	if a.DestructiveHint == nil || !*a.DestructiveHint {
		t.Errorf("%s: DestructiveHint = %v, want non-nil true", name, a.DestructiveHint)
	}
	if a.OpenWorldHint == nil || !*a.OpenWorldHint {
		t.Errorf("%s: OpenWorldHint = %v, want non-nil true", name, a.OpenWorldHint)
	}
}

// TestSearchCSPMAssetsAdvertisesNoOffset pins the pagination input surface for
// search_cspm_assets. The endpoint treats offset and after as mutually exclusive
// and caps offset at 10,000, so the cursor is the only way to traverse a full
// result set and offering an offset alongside it would give a caller two ways to
// page with no way to choose.
func TestSearchCSPMAssetsAdvertisesNoOffset(t *testing.T) {
	t.Parallel()

	if _, ok := searchCSPMAssetsSchema.Properties["offset"]; ok {
		t.Error("search_cspm_assets must not advertise an offset input")
	}
	if _, ok := searchCSPMAssetsSchema.Properties["after"]; !ok {
		t.Error("search_cspm_assets must advertise an after cursor")
	}
}

// TestSearchCSPMAssetsNeverSendsOffset pins that the handler cannot forward an
// offset alongside the cursor, which the endpoint rejects.
func TestSearchCSPMAssetsNeverSendsOffset(t *testing.T) {
	t.Parallel()
	f := &fakeAssets{queryResp: &cloud_security_assets.CloudSecurityAssetsQueriesOK{
		Payload: &models.AssetsGetResourceIDsResponse{Resources: []string{}},
	}}
	m := &Module{Assets: f, Concurrency: 4, Logger: testLogger}

	_, _, err := m.searchCSPMAssets(context.Background(), nil, SearchCSPMAssetsInput{After: "tok"})
	if err != nil {
		t.Fatalf("searchCSPMAssets: %v", err)
	}
	if f.lastQuery == nil {
		t.Fatal("query params must be recorded")
	}
	if f.lastQuery.Offset != nil {
		t.Errorf("offset = %v, want unset", *f.lastQuery.Offset)
	}
	if f.lastQuery.After == nil || *f.lastQuery.After != "tok" {
		t.Errorf("after = %v, want tok", f.lastQuery.After)
	}
}
