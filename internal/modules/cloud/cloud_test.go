package cloud

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sync"
	"testing"
	"time"

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
	// getMu guards the get counters below, which FetchDetails mutates from
	// concurrent hydration goroutines.
	getMu     sync.Mutex
	getCalls  int
	getIDs    []string
	lastQuery *cloud_security_assets.CloudSecurityAssetsQueriesParams
}

func (f *fakeAssets) CloudSecurityAssetsQueries(p *cloud_security_assets.CloudSecurityAssetsQueriesParams, _ ...cloud_security_assets.ClientOption) (*cloud_security_assets.CloudSecurityAssetsQueriesOK, error) {
	f.lastQuery = p
	return f.queryResp, f.queryErr
}
func (f *fakeAssets) CloudSecurityAssetsEntitiesGet(p *cloud_security_assets.CloudSecurityAssetsEntitiesGetParams, _ ...cloud_security_assets.ClientOption) (*cloud_security_assets.CloudSecurityAssetsEntitiesGetOK, error) {
	f.getMu.Lock()
	f.getCalls++
	f.getIDs = p.Ids
	f.getMu.Unlock()
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

	// Policy Framework (insight definitions catalog) fakes.
	queryRuleResp  *cloud_policies.QueryRuleOK
	queryRulePages []*cloud_policies.QueryRuleOK
	queryRuleErr   error
	queryRuleCalls int
	getRuleResp    *cloud_policies.GetRuleOK
	getRuleErr     error
	// getRuleMu guards the GetRule counters below, which FetchDetails mutates
	// from concurrent hydration goroutines.
	getRuleMu    sync.Mutex
	getRuleCalls int
	getRuleIDs   []string
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
func (f *fakePolicies) QueryRule(*cloud_policies.QueryRuleParams, ...cloud_policies.ClientOption) (*cloud_policies.QueryRuleOK, error) {
	idx := f.queryRuleCalls
	f.queryRuleCalls++
	if f.queryRulePages != nil {
		if idx >= len(f.queryRulePages) {
			idx = len(f.queryRulePages) - 1
		}
		return f.queryRulePages[idx], f.queryRuleErr
	}
	return f.queryRuleResp, f.queryRuleErr
}
func (f *fakePolicies) GetRule(p *cloud_policies.GetRuleParams, _ ...cloud_policies.ClientOption) (*cloud_policies.GetRuleOK, error) {
	f.getRuleMu.Lock()
	f.getRuleCalls++
	f.getRuleIDs = append(f.getRuleIDs, p.Ids...)
	f.getRuleMu.Unlock()
	if f.getRuleResp == nil && f.getRuleErr == nil {
		return &cloud_policies.GetRuleOK{Payload: &models.CommonGetRulesResponse{}}, nil
	}
	return f.getRuleResp, f.getRuleErr
}

// --- Kubernetes containers ---

func TestSearchKubernetesContainersReturnsRecords(t *testing.T) {
	t.Parallel()
	f := &fakeKubernetes{combinedResp: &kubernetes_protection.ContainerCombinedOK{Payload: &models.ModelsContainerEntityResponse{
		Resources: []*models.ModelsContainer{{ID: new("c1")}, {ID: new("c2")}},
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

// TestSearchIOMFindingsForwardsOffsetNeverAfter pins the offset-based pagination
// surface: the handler forwards the offset to the query params and never sets
// after (the cursor field is not part of the input).
func TestSearchIOMFindingsForwardsOffsetNeverAfter(t *testing.T) {
	t.Parallel()
	f := &fakeDetections{
		queryResp: &cloud_security_detections.CspmEvaluationsIomQueriesOK{Payload: &models.EvaluationsQueryIOMsResponse{
			Resources: []string{},
			Meta:      &models.RestCursorAndLimitMetaInfo{QueryTime: &metaQueryTime},
		}},
	}
	m := &Module{Detections: f, Concurrency: 4, Logger: testLogger}

	_, _, err := m.searchIOMFindings(context.Background(), nil, SearchIOMFindingsInput{Offset: 50})
	if err != nil {
		t.Fatalf("searchIOMFindings: %v", err)
	}
	if f.lastQuery == nil {
		t.Fatal("expected the query params to be captured")
	}
	if f.lastQuery.After != nil {
		t.Errorf("after = %v, want unset", *f.lastQuery.After)
	}
	if f.lastQuery.Offset == nil || *f.lastQuery.Offset != 50 {
		t.Errorf("offset = %v, want 50", f.lastQuery.Offset)
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
	if !errors.Is(err, base.ErrInvalidInput) {
		t.Fatalf("expected base.ErrInvalidInput for bad reason, got %v", err)
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
	if !errors.Is(err, base.ErrInvalidInput) {
		t.Fatalf("expected base.ErrInvalidInput without rule selection, got %v", err)
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
	if !errors.Is(err, base.ErrInvalidInput) {
		t.Fatalf("expected base.ErrInvalidInput for empty ids, got %v", err)
	}
	if f.deleteIDs != nil {
		t.Fatal("expected no API call for empty ids")
	}
}

// --- Annotations ---

func TestRegisterToolsAnnotations(t *testing.T) {
	t.Parallel()
	m := &Module{Logger: testLogger}
	byName := testutil.CollectTools(m)

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
		"falcon_search_cloud_insights",
		"falcon_get_cloud_asset_insights",
		"falcon_list_cloud_insight_definitions",
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

// --- Cloud insights ---

// insightAsset builds a typed CSPM asset entity carrying cloud_context.insights,
// the shape CloudSecurityAssetsEntitiesGet returns and the insight search and
// detail handlers read. Externals are typed insight entries (see insightExternal)
// so a test can pin polymorphic value fields — including a false boolean — that
// the pre-pointer model corrupted on a marshal round-trip.
func insightAsset(id string, externals ...*models.InsightsExternal) *models.ResourcesCloudResource {
	return &models.ResourcesCloudResource{
		ID:              id,
		ResourceName:    "res-" + id,
		ResourceType:    "AWS::S3::Bucket",
		CloudProvider:   "AWS",
		Region:          "us-east-1",
		AccountID:       "acct-1",
		AccountName:     "prod",
		ServiceCategory: "Storage",
		CloudContext: &models.ResourcesCloudContext{
			Insights: &models.InsightsInsight{External: externals},
		},
	}
}

// insightExternal builds one typed insight entry, setting the value pointer field
// selected by valueKey — the camelCase key (e.g. "booleanValue",
// "stringListValue") the API sends for that insight's value type.
func insightExternal(id, valueKey string, value any, ruleID string) *models.InsightsExternal {
	ext := &models.InsightsExternal{ID: new(id), RuleID: ruleID}
	switch valueKey {
	case "booleanValue":
		v, _ := value.(bool)
		ext.BooleanValue = new(v)
	case "stringValue":
		v, _ := value.(string)
		ext.StringValue = new(v)
	case "integerValue":
		v, _ := value.(int32)
		ext.IntegerValue = new(v)
	case "stringListValue":
		v, _ := value.([]string)
		ext.StringListValue = v
	}
	return ext
}

// genIDs makes n distinct rule IDs for pagination fakes.
func genIDs(prefix string, n int) []string {
	ids := make([]string, n)
	for i := range ids {
		ids[i] = fmt.Sprintf("%s-%04d", prefix, i)
	}
	return ids
}

// TestSearchCloudInsightsAutoFilter pins that an empty caller filter is
// auto-scoped: the handler pulls insight IDs from the PFM catalog, builds the
// insights.id:[…] filter, forwards it to the assets query, and reports the
// auto-filter on the response.
func TestSearchCloudInsightsAutoFilter(t *testing.T) {
	t.Parallel()
	pol := &fakePolicies{
		queryRuleResp: &cloud_policies.QueryRuleOK{Payload: &models.CommonQueryResponse{
			Resources: []string{"rule-1", "rule-2"},
		}},
		getRuleResp: &cloud_policies.GetRuleOK{Payload: &models.CommonGetRulesResponse{Resources: []*models.ApimodelsRule{
			{InsightID: "insight-b"},
			{InsightID: "insight-a"},
		}}},
	}
	assets := &fakeAssets{
		queryResp: &cloud_security_assets.CloudSecurityAssetsQueriesOK{Payload: &models.AssetsGetResourceIDsResponse{
			Resources: []string{"asset-1"},
			Meta:      &models.RestCursorAndLimitMetaInfo{QueryTime: &metaQueryTime},
		}},
		getResp: &cloud_security_assets.CloudSecurityAssetsEntitiesGetOK{Payload: &models.AssetsGetResourcesResponse{Resources: []*models.ResourcesCloudResource{
			insightAsset("asset-1", insightExternal("insight-a", "booleanValue", true, "rule-1")),
		}}},
	}
	m := &Module{Assets: assets, Policies: pol, Concurrency: 4, Logger: testLogger}

	_, out, err := m.searchCloudInsights(context.Background(), nil, SearchCloudInsightsInput{})
	if err != nil {
		t.Fatalf("searchCloudInsights: %v", err)
	}
	if !out.AutoFilterApplied {
		t.Error("expected AutoFilterApplied true when caller filter is empty")
	}
	if out.AutoFilterInsightCount != 2 {
		t.Errorf("AutoFilterInsightCount = %d, want 2", out.AutoFilterInsightCount)
	}
	if assets.lastQuery == nil || assets.lastQuery.Filter == nil {
		t.Fatal("expected assets query filter to be set")
	}
	// Insight IDs are sorted and quoted when the filter is built.
	wantFilter := "insights.id:['insight-a', 'insight-b']"
	if *assets.lastQuery.Filter != wantFilter {
		t.Errorf("assets filter = %q, want %q", *assets.lastQuery.Filter, wantFilter)
	}
	if len(out.Resources) != 1 {
		t.Fatalf("expected 1 grouped asset record, got %+v", out.Resources)
	}
	ins, ok := out.Resources[0]["insights"].([]map[string]any)
	if !ok || len(ins) != 1 {
		t.Fatalf("expected one grouped insight, got %T %+v", out.Resources[0]["insights"], out.Resources[0]["insights"])
	}
	if ins[0]["insight_id"] != "insight-a" {
		t.Errorf("insight_id = %v, want insight-a", ins[0]["insight_id"])
	}
	if ins[0]["value"] != true {
		t.Errorf("value = %v, want true", ins[0]["value"])
	}
}

// TestSearchCloudInsightsCallerFilter pins that a caller-supplied filter is
// forwarded verbatim, the PFM catalog is never consulted, and the auto-filter
// keys stay unset.
func TestSearchCloudInsightsCallerFilter(t *testing.T) {
	t.Parallel()
	pol := &fakePolicies{}
	assets := &fakeAssets{queryResp: &cloud_security_assets.CloudSecurityAssetsQueriesOK{Payload: &models.AssetsGetResourceIDsResponse{
		Resources: []string{},
		Meta:      &models.RestCursorAndLimitMetaInfo{QueryTime: &metaQueryTime},
	}}}
	m := &Module{Assets: assets, Policies: pol, Concurrency: 4, Logger: testLogger}

	const filter = "cloud_provider:'aws'"
	_, out, err := m.searchCloudInsights(context.Background(), nil, SearchCloudInsightsInput{Filter: filter})
	if err != nil {
		t.Fatalf("searchCloudInsights: %v", err)
	}
	if pol.queryRuleCalls != 0 {
		t.Errorf("expected no PFM QueryRule call for caller filter, got %d", pol.queryRuleCalls)
	}
	if out.AutoFilterApplied {
		t.Error("expected AutoFilterApplied false for caller filter")
	}
	if out.FilterUsed != filter {
		t.Errorf("FilterUsed = %q, want %q", out.FilterUsed, filter)
	}
	if assets.lastQuery == nil || assets.lastQuery.Filter == nil || *assets.lastQuery.Filter != filter {
		t.Errorf("assets filter = %v, want %q", assets.lastQuery.Filter, filter)
	}
	if out.Meta == nil {
		t.Error("expected empty result to still carry meta")
	}
}

// TestSearchCloudInsightsFQLError pins that a server-side FQL 400 becomes a data
// result echoing the expanded (auto-generated) filter, not the caller's empty
// one, and never fetches details.
func TestSearchCloudInsightsFQLError(t *testing.T) {
	t.Parallel()
	badReq := &cloud_security_assets.CloudSecurityAssetsQueriesBadRequest{Payload: &models.RestCursorResponseFields{
		Errors: []*models.MsaAPIError{{Code: new(int32(400)), Message: new("found unknown filter values: insights.id")}},
	}}
	pol := &fakePolicies{
		queryRuleResp: &cloud_policies.QueryRuleOK{Payload: &models.CommonQueryResponse{Resources: []string{"rule-1"}}},
		getRuleResp:   &cloud_policies.GetRuleOK{Payload: &models.CommonGetRulesResponse{Resources: []*models.ApimodelsRule{{InsightID: "insight-a"}}}},
	}
	assets := &fakeAssets{queryErr: badReq}
	m := &Module{Assets: assets, Policies: pol, Concurrency: 4, Logger: testLogger}

	_, out, err := m.searchCloudInsights(context.Background(), nil, SearchCloudInsightsInput{})
	if err != nil {
		t.Fatalf("searchCloudInsights should return FQL error as data, got Go error: %v", err)
	}
	if len(out.Errors) != 1 || out.Errors[0].Code != 400 {
		t.Fatalf("expected one FQL error detail, got %+v", out.Errors)
	}
	if out.FilterUsed != "insights.id:['insight-a']" {
		t.Errorf("FilterUsed = %q, want the expanded filter", out.FilterUsed)
	}
	if out.FQLGuide == "" {
		t.Error("expected FQL guide text in FQL-error response")
	}
	if assets.getCalls != 0 {
		t.Errorf("expected no detail fetch on FQL error, got %d", assets.getCalls)
	}
}

// TestSearchCloudInsightsEmptyCatalog pins the empty-catalog path: when PFM
// returns no insight rules and the caller gave no filter, the handler returns a
// message without ever querying assets or hydrating rule details.
func TestSearchCloudInsightsEmptyCatalog(t *testing.T) {
	t.Parallel()
	pol := &fakePolicies{queryRuleResp: &cloud_policies.QueryRuleOK{Payload: &models.CommonQueryResponse{Resources: []string{}}}}
	assets := &fakeAssets{}
	m := &Module{Assets: assets, Policies: pol, Concurrency: 4, Logger: testLogger}

	_, out, err := m.searchCloudInsights(context.Background(), nil, SearchCloudInsightsInput{})
	if err != nil {
		t.Fatalf("searchCloudInsights: %v", err)
	}
	if out.Message == "" {
		t.Error("expected an empty-catalog message")
	}
	if len(out.Resources) != 0 {
		t.Errorf("expected no resources, got %+v", out.Resources)
	}
	if pol.getRuleCalls != 0 {
		t.Errorf("expected no GetRule call when no rule IDs, got %d", pol.getRuleCalls)
	}
	if assets.lastQuery != nil {
		t.Error("expected assets query to be skipped on empty catalog")
	}
}

// TestGetCloudAssetInsightsEmptyIDs pins the input guard.
func TestGetCloudAssetInsightsEmptyIDs(t *testing.T) {
	t.Parallel()
	m := &Module{Assets: &fakeAssets{}, Concurrency: 4, Logger: testLogger}

	_, _, err := m.getCloudAssetInsights(context.Background(), nil, GetCloudAssetInsightsInput{})
	if !errors.Is(err, base.ErrInvalidInput) {
		t.Fatalf("expected base.ErrInvalidInput for empty asset_ids, got %v", err)
	}
}

// TestGetCloudAssetInsights pins that each requested asset with insight data
// yields one record carrying asset context and the raw cloud_context.insights.
func TestGetCloudAssetInsights(t *testing.T) {
	t.Parallel()
	assets := &fakeAssets{getResp: &cloud_security_assets.CloudSecurityAssetsEntitiesGetOK{Payload: &models.AssetsGetResourcesResponse{Resources: []*models.ResourcesCloudResource{
		insightAsset("asset-1", insightExternal("insight-a", "booleanValue", true, "rule-1")),
	}}}}
	m := &Module{Assets: assets, Concurrency: 4, Logger: testLogger}

	_, out, err := m.getCloudAssetInsights(context.Background(), nil, GetCloudAssetInsightsInput{AssetIDs: []string{"asset-1"}})
	if err != nil {
		t.Fatalf("getCloudAssetInsights: %v", err)
	}
	if out.Total != 1 || len(out.Resources) != 1 {
		t.Fatalf("expected 1 record, got %+v", out)
	}
	rec := out.Resources[0]
	if rec["asset_id"] != "asset-1" {
		t.Errorf("asset_id = %v, want asset-1", rec["asset_id"])
	}
	ins, ok := rec["insights"].(*models.InsightsInsight)
	if !ok {
		t.Fatalf("expected *models.InsightsInsight, got %T", rec["insights"])
	}
	if len(ins.External) == 0 {
		t.Errorf("expected raw insights.external retained, got %+v", ins)
	}
	if assets.getIDs == nil || assets.getIDs[0] != "asset-1" {
		t.Errorf("expected asset id forwarded to detail fetch, got %+v", assets.getIDs)
	}
}

// TestSearchCloudInsightsValueTypes pins that each polymorphic insight value
// survives the grouping. This is the regression guard for the raw-JSON fetch:
// marshaling the typed model injects a phantom zero-value dateValue and an
// always-present stringListValue while dropping a false booleanValue, so reading
// the value off the typed model returned the phantom date for every non-true
// boolean, string-list, and zero-numeric insight. Reading raw API JSON preserves
// exactly the one value key the API sent.
func TestSearchCloudInsightsValueTypes(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		valueKey string
		value    any
		want     any
	}{
		{"boolean false", "booleanValue", false, false},
		{"string list", "stringListValue", []string{"a", "b"}, []string{"a", "b"}},
		{"integer zero", "integerValue", int32(0), int32(0)},
		{"empty string", "stringValue", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assets := &fakeAssets{
				queryResp: &cloud_security_assets.CloudSecurityAssetsQueriesOK{Payload: &models.AssetsGetResourceIDsResponse{
					Resources: []string{"asset-1"},
					Meta:      &models.RestCursorAndLimitMetaInfo{QueryTime: &metaQueryTime},
				}},
				getResp: &cloud_security_assets.CloudSecurityAssetsEntitiesGetOK{Payload: &models.AssetsGetResourcesResponse{Resources: []*models.ResourcesCloudResource{
					insightAsset("asset-1", insightExternal("insight-a", tt.valueKey, tt.value, "rule-1")),
				}}},
			}
			m := &Module{Assets: assets, Concurrency: 4, Logger: testLogger}

			_, out, err := m.searchCloudInsights(context.Background(), nil, SearchCloudInsightsInput{Filter: "cloud_provider:'aws'"})
			if err != nil {
				t.Fatalf("searchCloudInsights: %v", err)
			}
			if len(out.Resources) != 1 {
				t.Fatalf("expected 1 grouped asset record, got %+v", out.Resources)
			}
			ins, ok := out.Resources[0]["insights"].([]map[string]any)
			if !ok || len(ins) != 1 {
				t.Fatalf("expected one grouped insight, got %T %+v", out.Resources[0]["insights"], out.Resources[0]["insights"])
			}
			if !reflect.DeepEqual(ins[0]["value"], tt.want) {
				t.Errorf("value = %#v, want %#v", ins[0]["value"], tt.want)
			}
		})
	}
}

// TestListCloudInsightDefinitions pins dedupe/merge: two rules sharing an
// insight_id collapse into one definition with merged, sorted providers and
// resource_types, a stripped name suffix, and controls deduped by name+framework.
func TestListCloudInsightDefinitions(t *testing.T) {
	t.Parallel()
	control := []*models.ApimodelsControl{
		{
			Name:              new("1.1"),
			SecurityFramework: []*models.ApimodelsSecurityFramework{{Name: new("CIS")}},
		},
	}
	pol := &fakePolicies{
		queryRuleResp: &cloud_policies.QueryRuleOK{Payload: &models.CommonQueryResponse{Resources: []string{"r1", "r2"}}},
		getRuleResp: &cloud_policies.GetRuleOK{Payload: &models.CommonGetRulesResponse{Resources: []*models.ApimodelsRule{
			{
				InsightID:     "insight-x",
				Category:      "Storage",
				Name:          new("Public bucket - S3"),
				Description:   new("desc"),
				Provider:      new("aws"),
				ResourceTypes: []*models.ApimodelsResourceType{{ResourceType: new("AWS::S3::Bucket")}},
				Controls:      control,
			},
			{
				InsightID:     "insight-x",
				Category:      "Storage",
				Name:          new("Public bucket - GCS"),
				Description:   new("desc"),
				Provider:      new("gcp"),
				ResourceTypes: []*models.ApimodelsResourceType{{ResourceType: new("GCP::Storage::Bucket")}},
				Controls:      control,
			},
		}}},
	}
	m := &Module{Policies: pol, Logger: testLogger}

	_, out, err := m.listCloudInsightDefinitions(context.Background(), nil, ListInsightDefinitionsInput{})
	if err != nil {
		t.Fatalf("listCloudInsightDefinitions: %v", err)
	}
	if len(out.Resources) != 1 {
		t.Fatalf("expected 1 deduped definition, got %d: %+v", len(out.Resources), out.Resources)
	}
	def := out.Resources[0]
	if def["insight_id"] != "insight-x" {
		t.Errorf("insight_id = %v, want insight-x", def["insight_id"])
	}
	if def["name"] != "Public bucket" {
		t.Errorf("name = %v, want stripped 'Public bucket'", def["name"])
	}
	if got, ok := def["providers"].([]string); !ok || !reflect.DeepEqual(got, []string{"aws", "gcp"}) {
		t.Errorf("providers = %v, want [aws gcp]", def["providers"])
	}
	if got, ok := def["resource_types"].([]string); !ok || !reflect.DeepEqual(got, []string{"AWS::S3::Bucket", "GCP::Storage::Bucket"}) {
		t.Errorf("resource_types = %v, want merged sorted", def["resource_types"])
	}
	if ctrls, ok := def["controls"].([]map[string]any); !ok || len(ctrls) != 1 {
		t.Errorf("expected controls deduped to 1, got %T %+v", def["controls"], def["controls"])
	}
	if out.Meta == nil || out.Meta.Pagination == nil || out.Meta.Pagination.Total == nil || *out.Meta.Pagination.Total != 1 {
		t.Errorf("expected pagination total 1, got %+v", out.Meta)
	}
}

// TestListCloudInsightDefinitionsCategoryFilter pins the case-insensitive
// category filter.
func TestListCloudInsightDefinitionsCategoryFilter(t *testing.T) {
	t.Parallel()
	pol := &fakePolicies{
		queryRuleResp: &cloud_policies.QueryRuleOK{Payload: &models.CommonQueryResponse{Resources: []string{"r1", "r2"}}},
		getRuleResp: &cloud_policies.GetRuleOK{Payload: &models.CommonGetRulesResponse{Resources: []*models.ApimodelsRule{
			{InsightID: "insight-a", Category: "Storage", Name: new("A")},
			{InsightID: "insight-b", Category: "Network", Name: new("B")},
		}}},
	}
	m := &Module{Policies: pol, Logger: testLogger}

	_, out, err := m.listCloudInsightDefinitions(context.Background(), nil, ListInsightDefinitionsInput{Categories: []string{"storage"}})
	if err != nil {
		t.Fatalf("listCloudInsightDefinitions: %v", err)
	}
	if len(out.Resources) != 1 {
		t.Fatalf("expected 1 definition after category filter, got %d", len(out.Resources))
	}
	if out.Resources[0]["category"] != "Storage" {
		t.Errorf("category = %v, want Storage", out.Resources[0]["category"])
	}
}

// TestListCloudInsightDefinitionsPaging pins client-side paging: limit/offset
// select a window and pagination meta reports the full total.
func TestListCloudInsightDefinitionsPaging(t *testing.T) {
	t.Parallel()
	pol := &fakePolicies{
		queryRuleResp: &cloud_policies.QueryRuleOK{Payload: &models.CommonQueryResponse{Resources: []string{"r1", "r2", "r3"}}},
		getRuleResp: &cloud_policies.GetRuleOK{Payload: &models.CommonGetRulesResponse{Resources: []*models.ApimodelsRule{
			{InsightID: "insight-a", Category: "C", Name: new("A")},
			{InsightID: "insight-b", Category: "C", Name: new("B")},
			{InsightID: "insight-c", Category: "C", Name: new("C")},
		}}},
	}
	m := &Module{Policies: pol, Logger: testLogger}

	_, out, err := m.listCloudInsightDefinitions(context.Background(), nil, ListInsightDefinitionsInput{Limit: 1, Offset: 1})
	if err != nil {
		t.Fatalf("listCloudInsightDefinitions: %v", err)
	}
	if len(out.Resources) != 1 {
		t.Fatalf("expected 1 definition in page, got %d", len(out.Resources))
	}
	if out.Resources[0]["insight_id"] != "insight-b" {
		t.Errorf("paged definition = %v, want insight-b (first-seen order)", out.Resources[0]["insight_id"])
	}
	p := out.Meta.Pagination
	if p == nil || *p.Total != 3 || *p.Offset != 1 || *p.Limit != 1 {
		t.Errorf("pagination = %+v, want total 3 offset 1 limit 1", p)
	}
}

// TestQueryPFMRuleIDsPaginatesUntilShortPage pins the PFM pagination stop
// condition: a full first page followed by a short page ends paging, and every
// collected ID is hydrated through GetRule.
func TestQueryPFMRuleIDsPaginatesUntilShortPage(t *testing.T) {
	t.Parallel()
	pol := &fakePolicies{
		queryRulePages: []*cloud_policies.QueryRuleOK{
			{Payload: &models.CommonQueryResponse{Resources: genIDs("p0", pfmQueryPageSize)}},
			{Payload: &models.CommonQueryResponse{Resources: genIDs("p1", 10)}},
		},
	}
	m := &Module{Policies: pol, Logger: testLogger}

	rules, err := m.fetchPFMRules(context.Background())
	if err != nil {
		t.Fatalf("fetchPFMRules: %v", err)
	}
	_ = rules
	if pol.queryRuleCalls != 2 {
		t.Errorf("QueryRule calls = %d, want 2 (full page then short page)", pol.queryRuleCalls)
	}
	if len(pol.getRuleIDs) != pfmQueryPageSize+10 {
		t.Errorf("hydrated IDs = %d, want %d", len(pol.getRuleIDs), pfmQueryPageSize+10)
	}
}

// TestInsightValuePrecedence pins the value-key selection order.
func TestInsightValuePrecedence(t *testing.T) {
	t.Parallel()
	// BooleanValue is consulted before StringValue.
	if got := insightValue(&models.InsightsExternal{StringValue: new("s"), BooleanValue: new(true)}); got != true {
		t.Errorf("value = %v, want true (BooleanValue wins)", got)
	}
	// No value-bearing field yields nil.
	if got := insightValue(&models.InsightsExternal{ID: new("x")}); got != nil {
		t.Errorf("value = %v, want nil", got)
	}
}

// pfmRuleFakeWith returns a fakePolicies whose single-page QueryRule/GetRule
// path hydrates one rule carrying insightID, so a fetchPFMRules call costs
// exactly one QueryRule and one GetRule.
func pfmRuleFakeWith(insightID string) *fakePolicies {
	return &fakePolicies{
		queryRuleResp: &cloud_policies.QueryRuleOK{Payload: &models.CommonQueryResponse{Resources: []string{"rule-1"}}},
		getRuleResp:   &cloud_policies.GetRuleOK{Payload: &models.CommonGetRulesResponse{Resources: []*models.ApimodelsRule{{InsightID: insightID}}}},
	}
}

// TestFetchPFMRulesCachesResult pins that a second fetchPFMRules for the same
// filter within the TTL is served from the cache: the catalog is queried and
// hydrated once, and both calls return equal rules.
func TestFetchPFMRulesCachesResult(t *testing.T) {
	t.Parallel()
	pol := pfmRuleFakeWith("insight-a")
	m := &Module{Policies: pol, Logger: testLogger}

	first, err := m.fetchPFMRules(context.Background())
	if err != nil {
		t.Fatalf("fetchPFMRules (first): %v", err)
	}
	second, err := m.fetchPFMRules(context.Background())
	if err != nil {
		t.Fatalf("fetchPFMRules (second): %v", err)
	}
	if pol.queryRuleCalls != 1 {
		t.Errorf("QueryRule calls = %d, want 1 (second call served from cache)", pol.queryRuleCalls)
	}
	if pol.getRuleCalls != 1 {
		t.Errorf("GetRule calls = %d, want 1 (second call served from cache)", pol.getRuleCalls)
	}
	if !reflect.DeepEqual(first, second) {
		t.Errorf("cached result = %+v, want %+v", second, first)
	}
}

// TestFetchPFMRulesExpiredEntryRefetches pins that an entry older than the TTL
// is treated as a miss: the next call re-queries the catalog and returns the
// freshly fetched rules, not the stale cached ones.
func TestFetchPFMRulesExpiredEntryRefetches(t *testing.T) {
	t.Parallel()
	pol := pfmRuleFakeWith("fresh")
	m := &Module{Policies: pol, Logger: testLogger}
	m.pfmCache = &pfmCacheEntry{
		fetchedAt: time.Now().Add(-2 * pfmRulesCacheTTL),
		rules:     []*models.ApimodelsRule{{InsightID: "stale"}},
	}

	rules, err := m.fetchPFMRules(context.Background())
	if err != nil {
		t.Fatalf("fetchPFMRules: %v", err)
	}
	if pol.queryRuleCalls != 1 {
		t.Errorf("QueryRule calls = %d, want 1 (expired entry forces refetch)", pol.queryRuleCalls)
	}
	if len(rules) != 1 || rules[0].InsightID != "fresh" {
		t.Errorf("rules = %+v, want the freshly fetched insight", rules)
	}
}

// TestFetchPFMRulesReturnsCopy pins that the returned slice is a copy: a caller
// reassigning an element of its result cannot corrupt the cached entry that the
// next call returns.
func TestFetchPFMRulesReturnsCopy(t *testing.T) {
	t.Parallel()
	pol := pfmRuleFakeWith("insight-a")
	m := &Module{Policies: pol, Logger: testLogger}

	first, err := m.fetchPFMRules(context.Background())
	if err != nil {
		t.Fatalf("fetchPFMRules (first): %v", err)
	}
	first[0] = &models.ApimodelsRule{InsightID: "mutated"}

	second, err := m.fetchPFMRules(context.Background())
	if err != nil {
		t.Fatalf("fetchPFMRules (second): %v", err)
	}
	if second[0].InsightID != "insight-a" {
		t.Errorf("cached slice mutated by caller: got %v, want insight-a", second[0].InsightID)
	}
}
