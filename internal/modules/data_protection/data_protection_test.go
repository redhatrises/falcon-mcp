package data_protection

import (
	"context"
	"errors"
	"log/slog"
	"testing"

	dp "github.com/crowdstrike/gofalcon/falcon/client/data_protection_configuration"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/crowdstrike/falcon-mcp/internal/modules/base"
)

// testLogger discards output; modules require a non-nil logger.
var testLogger = slog.New(slog.DiscardHandler)

func str(s string) *string { return &s }
func i32(v int32) *int32   { return &v }

// fakeAPI is a configurable test double for the dataProtectionAPI interface. It
// records the IDs each get call received so tests can assert the two-step search
// forwards the query results.
type fakeAPI struct {
	classQueryResp *dp.QueriesClassificationGetV2OK
	classQueryErr  error
	classGetResp   *dp.EntitiesClassificationGetV2OK
	classGetCalls  int
	classGetIDs    []string

	policyQueryResp *dp.QueriesPolicyGetV2OK
	policyQueryErr  error
	policyGetResp   *dp.EntitiesPolicyGetV2OK
	policyGetCalls  int

	patternQueryResp *dp.QueriesContentPatternGetV2OK
	patternQueryErr  error
	patternGetResp   *dp.EntitiesContentPatternGetOK
	patternGetCalls  int

	lastPlatformName string
}

func (f *fakeAPI) QueriesClassificationGetV2(*dp.QueriesClassificationGetV2Params, ...dp.ClientOption) (*dp.QueriesClassificationGetV2OK, error) {
	return f.classQueryResp, f.classQueryErr
}

func (f *fakeAPI) EntitiesClassificationGetV2(p *dp.EntitiesClassificationGetV2Params, _ ...dp.ClientOption) (*dp.EntitiesClassificationGetV2OK, error) {
	f.classGetCalls++
	f.classGetIDs = p.Ids
	return f.classGetResp, nil
}

func (f *fakeAPI) QueriesPolicyGetV2(p *dp.QueriesPolicyGetV2Params, _ ...dp.ClientOption) (*dp.QueriesPolicyGetV2OK, error) {
	f.lastPlatformName = p.PlatformName
	return f.policyQueryResp, f.policyQueryErr
}

func (f *fakeAPI) EntitiesPolicyGetV2(*dp.EntitiesPolicyGetV2Params, ...dp.ClientOption) (*dp.EntitiesPolicyGetV2OK, error) {
	f.policyGetCalls++
	return f.policyGetResp, nil
}

func (f *fakeAPI) QueriesContentPatternGetV2(*dp.QueriesContentPatternGetV2Params, ...dp.ClientOption) (*dp.QueriesContentPatternGetV2OK, error) {
	return f.patternQueryResp, f.patternQueryErr
}

func (f *fakeAPI) EntitiesContentPatternGet(*dp.EntitiesContentPatternGetParams, ...dp.ClientOption) (*dp.EntitiesContentPatternGetOK, error) {
	f.patternGetCalls++
	return f.patternGetResp, nil
}

// --- Classifications ---

func TestSearchClassificationsEmpty(t *testing.T) {
	t.Parallel()

	f := &fakeAPI{classQueryResp: &dp.QueriesClassificationGetV2OK{Payload: &models.ResponsesPolicySearchV1{Resources: []string{}}}}
	m := &Module{API: f, Concurrency: 4, Logger: testLogger}

	_, out, err := m.searchClassifications(context.Background(), nil, SearchInput{Filter: "name:~'x'"})
	if err != nil {
		t.Fatalf("searchClassifications: %v", err)
	}
	if len(out.Resources) != 0 || out.FilterUsed != "name:~'x'" {
		t.Fatalf("expected empty result, got %+v", out)
	}
	if out.Resources == nil {
		t.Fatalf("resources must be a non-nil empty slice for stable JSON array output")
	}
	if f.classGetCalls != 0 {
		t.Fatalf("expected no detail fetch on empty result, got %d get calls", f.classGetCalls)
	}
}

func TestSearchClassificationsReturnsDetails(t *testing.T) {
	t.Parallel()

	f := &fakeAPI{
		classQueryResp: &dp.QueriesClassificationGetV2OK{Payload: &models.ResponsesPolicySearchV1{Resources: []string{"c1", "c2"}, Meta: &models.MsaMetaInfo{}}},
		classGetResp: &dp.EntitiesClassificationGetV2OK{Payload: &models.PolicymanagerClassificationsResponse{
			Resources: []*models.PolicymanagerExternalClassification{
				{ID: str("c1"), Name: str("Credit Cards")},
				{ID: str("c2"), Name: str("SSNs")},
			},
		}},
	}
	m := &Module{API: f, Concurrency: 4, Logger: testLogger}

	_, out, err := m.searchClassifications(context.Background(), nil, SearchInput{Filter: "name:~'c'"})
	if err != nil {
		t.Fatalf("searchClassifications: %v", err)
	}
	if len(out.Resources) != 2 {
		t.Fatalf("expected 2 full records, got %+v", out)
	}
	if f.classGetCalls != 1 {
		t.Fatalf("expected exactly one detail fetch, got %d", f.classGetCalls)
	}
	if len(f.classGetIDs) != 2 || f.classGetIDs[0] != "c1" {
		t.Fatalf("detail fetch did not receive the query IDs: %v", f.classGetIDs)
	}
	if out.Meta != any(f.classQueryResp.Payload.Meta) {
		t.Fatalf("expected verbatim meta passthrough, got %+v", out.Meta)
	}
}

func TestSearchClassificationsFQLError(t *testing.T) {
	t.Parallel()

	badReq := &dp.QueriesClassificationGetV2BadRequest{Payload: &models.ResponsesPolicySearchV1{
		Errors: []*models.ResponsesError{{Code: i32(400), Message: str("invalid classification filter key: bogus")}},
	}}
	f := &fakeAPI{classQueryErr: badReq}
	m := &Module{API: f, Concurrency: 4, Logger: testLogger}

	_, out, err := m.searchClassifications(context.Background(), nil, SearchInput{Filter: "bogus:'x'"})
	if err != nil {
		t.Fatalf("expected FQL error to be a data result, not returned: %v", err)
	}
	if len(out.Errors) != 1 || out.Errors[0].Message != "invalid classification filter key: bogus" {
		t.Fatalf("expected FQL error detail, got %+v", out.Errors)
	}
	if out.FQLGuide == "" {
		t.Fatalf("expected the FQL guide to be attached to the error response")
	}
	if f.classGetCalls != 0 {
		t.Fatalf("expected no detail fetch on FQL error, got %d", f.classGetCalls)
	}
}

func TestSearchClassificationsAPIError(t *testing.T) {
	t.Parallel()

	f := &fakeAPI{classQueryErr: errors.New("boom")}
	m := &Module{API: f, Concurrency: 4, Logger: testLogger}

	_, _, err := m.searchClassifications(context.Background(), nil, SearchInput{})
	if err == nil {
		t.Fatal("expected a non-FQL transport error to be returned as a Go error")
	}
}

// --- Policies ---

func TestSearchPoliciesForwardsPlatformName(t *testing.T) {
	t.Parallel()

	f := &fakeAPI{
		policyQueryResp: &dp.QueriesPolicyGetV2OK{Payload: &models.ResponsesPolicySearchV1{Resources: []string{"p1"}, Meta: &models.MsaMetaInfo{}}},
		policyGetResp: &dp.EntitiesPolicyGetV2OK{Payload: &models.PolicymanagerPoliciesResponse{
			Resources: []*models.PolicymanagerExternalPolicy{{ID: str("p1"), Name: str("Default")}},
		}},
	}
	m := &Module{API: f, Concurrency: 4, Logger: testLogger}

	_, out, err := m.searchPolicies(context.Background(), nil, SearchPoliciesInput{PlatformName: "win", Filter: "is_enabled:true"})
	if err != nil {
		t.Fatalf("searchPolicies: %v", err)
	}
	if f.lastPlatformName != "win" {
		t.Fatalf("expected platform_name 'win' forwarded to query, got %q", f.lastPlatformName)
	}
	if len(out.Resources) != 1 {
		t.Fatalf("expected 1 full record, got %+v", out)
	}
	if f.policyGetCalls != 1 {
		t.Fatalf("expected one detail fetch, got %d", f.policyGetCalls)
	}
	if out.Meta != any(f.policyQueryResp.Payload.Meta) {
		t.Fatalf("expected verbatim meta passthrough, got %+v", out.Meta)
	}
}

func TestSearchPoliciesEmpty(t *testing.T) {
	t.Parallel()

	f := &fakeAPI{policyQueryResp: &dp.QueriesPolicyGetV2OK{Payload: &models.ResponsesPolicySearchV1{Resources: []string{}}}}
	m := &Module{API: f, Concurrency: 4, Logger: testLogger}

	_, out, err := m.searchPolicies(context.Background(), nil, SearchPoliciesInput{PlatformName: "mac"})
	if err != nil {
		t.Fatalf("searchPolicies: %v", err)
	}
	if out.Resources == nil || len(out.Resources) != 0 {
		t.Fatalf("expected non-nil empty slice, got %+v", out.Resources)
	}
	if f.policyGetCalls != 0 {
		t.Fatalf("expected no detail fetch on empty result, got %d", f.policyGetCalls)
	}
}

func TestSearchPoliciesFQLError(t *testing.T) {
	t.Parallel()

	badReq := &dp.QueriesPolicyGetV2BadRequest{Payload: &models.ResponsesPolicySearchV1{
		Errors: []*models.ResponsesError{{Code: i32(400), Message: str("invalid policy filter key: bogus")}},
	}}
	f := &fakeAPI{policyQueryErr: badReq}
	m := &Module{API: f, Concurrency: 4, Logger: testLogger}

	_, out, err := m.searchPolicies(context.Background(), nil, SearchPoliciesInput{PlatformName: "win", Filter: "bogus:'x'"})
	if err != nil {
		t.Fatalf("expected FQL error to be a data result: %v", err)
	}
	if len(out.Errors) != 1 || out.FQLGuide == "" {
		t.Fatalf("expected FQL error detail with guide, got %+v", out)
	}
}

// --- Content patterns ---

func TestSearchContentPatternsReturnsDetails(t *testing.T) {
	t.Parallel()

	f := &fakeAPI{
		patternQueryResp: &dp.QueriesContentPatternGetV2OK{Payload: &models.MsaspecQueryResponse{Resources: []string{"x1"}, Meta: &models.MsaMetaInfo{}}},
		patternGetResp: &dp.EntitiesContentPatternGetOK{Payload: &models.APIContentPatternMSAResponseV1{
			Resources: []*models.APIContentPatternV1{{ID: str("x1"), Name: "AWS Key", Type: str("custom")}},
		}},
	}
	m := &Module{API: f, Concurrency: 4, Logger: testLogger}

	_, out, err := m.searchContentPatterns(context.Background(), nil, SearchInput{Filter: "type:'custom'"})
	if err != nil {
		t.Fatalf("searchContentPatterns: %v", err)
	}
	if len(out.Resources) != 1 {
		t.Fatalf("expected 1 full record, got %+v", out)
	}
	if f.patternGetCalls != 1 {
		t.Fatalf("expected one detail fetch, got %d", f.patternGetCalls)
	}
	if out.Meta != any(f.patternQueryResp.Payload.Meta) {
		t.Fatalf("expected verbatim meta passthrough, got %+v", out.Meta)
	}
}

func TestSearchContentPatternsFQLError(t *testing.T) {
	t.Parallel()

	badReq := &dp.QueriesContentPatternGetV2BadRequest{Payload: &models.MsaspecResponseFields{
		Errors: []*models.MsaAPIError{{Code: i32(400), Message: str("invalid fql filter properties: [bogus]")}},
	}}
	f := &fakeAPI{patternQueryErr: badReq}
	m := &Module{API: f, Concurrency: 4, Logger: testLogger}

	_, out, err := m.searchContentPatterns(context.Background(), nil, SearchInput{Filter: "bogus:'x'"})
	if err != nil {
		t.Fatalf("expected FQL error to be a data result: %v", err)
	}
	if len(out.Errors) != 1 || out.Errors[0].Message != "invalid fql filter properties: [bogus]" {
		t.Fatalf("expected FQL error detail, got %+v", out.Errors)
	}
	if out.FQLGuide == "" {
		t.Fatalf("expected the FQL guide to be attached")
	}
	if f.patternGetCalls != 0 {
		t.Fatalf("expected no detail fetch on FQL error, got %d", f.patternGetCalls)
	}
}

func TestSearchContentPatternsEmpty(t *testing.T) {
	t.Parallel()

	f := &fakeAPI{patternQueryResp: &dp.QueriesContentPatternGetV2OK{Payload: &models.MsaspecQueryResponse{Resources: []string{}}}}
	m := &Module{API: f, Concurrency: 4, Logger: testLogger}

	_, out, err := m.searchContentPatterns(context.Background(), nil, SearchInput{})
	if err != nil {
		t.Fatalf("searchContentPatterns: %v", err)
	}
	if out.Resources == nil || len(out.Resources) != 0 {
		t.Fatalf("expected non-nil empty slice, got %+v", out.Resources)
	}
}

// --- Registration ---

// captureRegistrar records every tool registered via base.AddTool so tests can
// assert names and annotations without a live server.
type captureRegistrar struct{ tools []*mcp.Tool }

func (c *captureRegistrar) Add(e base.ToolEntry) { c.tools = append(c.tools, e.Tool) }

func TestRegisterToolsNamesAndAnnotations(t *testing.T) {
	t.Parallel()

	m := &Module{API: &fakeAPI{}, Concurrency: 4, Logger: testLogger}
	var r captureRegistrar
	m.RegisterTools(&r)

	want := map[string]bool{
		"falcon_search_data_protection_classifications":  false,
		"falcon_search_data_protection_policies":         false,
		"falcon_search_data_protection_content_patterns": false,
	}
	for _, tool := range r.tools {
		if _, ok := want[tool.Name]; !ok {
			t.Fatalf("unexpected tool registered: %q", tool.Name)
		}
		want[tool.Name] = true
		// All three are read-only search tools; AddTool applies the read-only
		// default when Annotations is nil.
		if tool.Annotations == nil || !tool.Annotations.ReadOnlyHint {
			t.Fatalf("tool %q should carry read-only annotations, got %+v", tool.Name, tool.Annotations)
		}
	}
	for name, seen := range want {
		if !seen {
			t.Fatalf("expected tool %q to be registered", name)
		}
	}
}
