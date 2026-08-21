package idp

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/crowdstrike/gofalcon/falcon/client/identity_protection"
	"github.com/crowdstrike/gofalcon/falcon/models"

	"github.com/crowdstrike/falcon-mcp/internal/modules/base"
	"github.com/crowdstrike/falcon-mcp/internal/testutil"
)

var testLogger = testutil.DiscardLogger()

// fixedNow pins the timestamp so summary output is deterministic in tests.
func fixedNow() time.Time { return time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC) }

// fakeIDP is a scripted double for idpAPI. Each call pops the next scripted
// response/error and records the submitted query, so tests can assert both the
// synthesized result and the exact GraphQL the handler built.
type fakeIDP struct {
	resps   []*identity_protection.APIPreemptProxyPostGraphqlOK
	errs    []error
	idx     int
	queries []string
}

func (f *fakeIDP) APIPreemptProxyPostGraphql(p *identity_protection.APIPreemptProxyPostGraphqlParams, _ ...identity_protection.ClientOption) (*identity_protection.APIPreemptProxyPostGraphqlOK, error) {
	if p.Body != nil && p.Body.Query != nil {
		f.queries = append(f.queries, *p.Body.Query)
	}
	i := f.idx
	f.idx++
	var resp *identity_protection.APIPreemptProxyPostGraphqlOK
	if i < len(f.resps) {
		resp = f.resps[i]
	}
	var err error
	if i < len(f.errs) {
		err = f.errs[i]
	}
	return resp, err
}

// okResp wraps a decoded GraphQL "data" object into an OK response payload.
func okResp(data map[string]any) *identity_protection.APIPreemptProxyPostGraphqlOK {
	return &identity_protection.APIPreemptProxyPostGraphqlOK{
		Payload: &models.SwaggerGraphQLResponse{Data: data},
	}
}

// entitiesData builds a data object with the given entity nodes under
// entities.nodes, the shape the resolve and detail queries return.
func entitiesData(nodes ...map[string]any) map[string]any {
	arr := make([]any, len(nodes))
	for i, n := range nodes {
		arr[i] = n
	}
	return map[string]any{"entities": map[string]any{"nodes": arr}}
}

func newModule(f *fakeIDP) *Module {
	return &Module{API: f, Logger: testLogger, now: fixedNow}
}

func TestValidateNoIdentifier(t *testing.T) {
	t.Parallel()
	f := &fakeIDP{}
	m := newModule(f)

	_, out, err := m.investigateEntity(context.Background(), nil, InvestigateInput{})
	if err != nil {
		t.Fatalf("unexpected Go error: %v", err)
	}
	if out.Error == "" {
		t.Fatalf("expected a data-level error for missing identifier")
	}
	if out.Summary == nil || out.Summary.Status != "failed" {
		t.Fatalf("expected failed summary, got %+v", out.Summary)
	}
	if f.idx != 0 {
		t.Fatalf("expected no API calls on validation failure, got %d", f.idx)
	}
}

func TestValidateBareWildcard(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		in   InvestigateInput
	}{
		{"entity_names star", InvestigateInput{EntityNames: "*"}},
		{"entity_names spaced star", InvestigateInput{EntityNames: "  * "}},
		{"email star", InvestigateInput{EmailAddresses: "*"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := &fakeIDP{}
			m := newModule(f)
			_, out, err := m.investigateEntity(context.Background(), nil, tc.in)
			if err != nil {
				t.Fatalf("unexpected Go error: %v", err)
			}
			if !strings.Contains(out.Error, "bare wildcard") {
				t.Fatalf("expected bare-wildcard error, got %q", out.Error)
			}
			if f.idx != 0 {
				t.Fatalf("expected no API calls, got %d", f.idx)
			}
		})
	}
}

func TestDirectEntityIDsSkipResolution(t *testing.T) {
	t.Parallel()
	// Only entity_details is requested; with direct IDs there is no resolve query,
	// so a single GraphQL call (the details batch) is expected.
	f := &fakeIDP{resps: []*identity_protection.APIPreemptProxyPostGraphqlOK{
		okResp(entitiesData(map[string]any{"entityId": "e1", "primaryDisplayName": "Alice"})),
	}}
	m := newModule(f)

	_, out, err := m.investigateEntity(context.Background(), nil, InvestigateInput{
		EntityIDs:          []string{"e1"},
		InvestigationTypes: []string{investigationEntityDetails},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out.Summary.Status != "completed" {
		t.Fatalf("expected completed, got %+v", out.Summary)
	}
	if len(out.Entities) != 1 || out.Entities[0] != "e1" {
		t.Fatalf("expected resolved [e1], got %v", out.Entities)
	}
	if f.idx != 1 {
		t.Fatalf("expected exactly 1 GraphQL call (details), got %d", f.idx)
	}
	details := asMap(out.EntityDetails)
	if details == nil {
		t.Fatalf("expected entity_details object, got %+v", out.EntityDetails)
	}
	if count, ok := details["entity_count"].(int); !ok || count != 1 {
		t.Fatalf("expected entity_details with 1 entity, got %+v", out.EntityDetails)
	}
}

func TestResolveByNameThenDetails(t *testing.T) {
	t.Parallel()
	// Call 1: resolve entity_names -> e1. Call 2: entity_details for e1.
	f := &fakeIDP{resps: []*identity_protection.APIPreemptProxyPostGraphqlOK{
		okResp(entitiesData(map[string]any{"entityId": "e1"})),
		okResp(entitiesData(map[string]any{"entityId": "e1", "primaryDisplayName": "Admin"})),
	}}
	m := newModule(f)

	_, out, err := m.investigateEntity(context.Background(), nil, InvestigateInput{
		EntityNames:        "Admin*",
		InvestigationTypes: []string{investigationEntityDetails},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(out.Entities) != 1 || out.Entities[0] != "e1" {
		t.Fatalf("expected [e1], got %v", out.Entities)
	}
	if f.idx != 2 {
		t.Fatalf("expected 2 calls (resolve + details), got %d", f.idx)
	}
	// The resolve query must carry a primaryDisplayNamePattern with the name.
	if !strings.Contains(f.queries[0], "primaryDisplayNamePattern") || !strings.Contains(f.queries[0], "Admin*") {
		t.Fatalf("resolve query missing name pattern: %s", f.queries[0])
	}
}

func TestNoEntitiesFound(t *testing.T) {
	t.Parallel()
	f := &fakeIDP{resps: []*identity_protection.APIPreemptProxyPostGraphqlOK{
		okResp(entitiesData()), // resolve returns no nodes
	}}
	m := newModule(f)

	_, out, err := m.investigateEntity(context.Background(), nil, InvestigateInput{
		EntityNames:        "Nobody",
		InvestigationTypes: []string{investigationEntityDetails},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(out.Error, "No entities found") {
		t.Fatalf("expected no-entities error, got %q", out.Error)
	}
	if out.SearchCriteria == nil || out.SearchCriteria.EntityNames != "Nobody" {
		t.Fatalf("expected search_criteria echoed, got %+v", out.SearchCriteria)
	}
	if f.idx != 1 {
		t.Fatalf("expected only the resolve call, got %d", f.idx)
	}
}

func TestEmailAndIPConflictPrefersUser(t *testing.T) {
	t.Parallel()
	f := &fakeIDP{resps: []*identity_protection.APIPreemptProxyPostGraphqlOK{
		okResp(entitiesData(map[string]any{"entityId": "u1"})),
		okResp(entitiesData(map[string]any{"entityId": "u1"})),
	}}
	m := newModule(f)

	_, out, err := m.investigateEntity(context.Background(), nil, InvestigateInput{
		EmailAddresses:     "user@example.com",
		IPAddresses:        []string{"1.1.1.1"},
		InvestigationTypes: []string{investigationEntityDetails},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	_ = out
	// The resolve query must use USER filters and must NOT contain the IP filter.
	q := f.queries[0]
	if !strings.Contains(q, "types: [USER]") {
		t.Fatalf("expected USER types filter, got %s", q)
	}
	if strings.Contains(q, "ENDPOINT") || strings.Contains(q, "1.1.1.1") {
		t.Fatalf("IP criterion should have been dropped, got %s", q)
	}
}

func TestRiskAssessmentDefaults(t *testing.T) {
	t.Parallel()
	// Entity with no riskScore/severity should get the defaults 0 / "LOW".
	f := &fakeIDP{resps: []*identity_protection.APIPreemptProxyPostGraphqlOK{
		okResp(entitiesData(map[string]any{"entityId": "e1", "primaryDisplayName": "Bob"})),
	}}
	m := newModule(f)

	_, out, err := m.investigateEntity(context.Background(), nil, InvestigateInput{
		EntityIDs:          []string{"e1"},
		InvestigationTypes: []string{investigationRiskAssessment},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	risk := asMap(out.RiskAssessment)
	assessments := asArray(risk["risk_assessments"])
	if len(assessments) != 1 {
		t.Fatalf("expected 1 assessment, got %d", len(assessments))
	}
	a, ok := assessments[0].(map[string]any)
	if !ok {
		t.Fatalf("assessment should be an object, got %T", assessments[0])
	}
	if a["riskScore"] != 0 || a["riskScoreSeverity"] != "LOW" {
		t.Fatalf("expected default risk 0/LOW, got %+v", a)
	}
	if _, ok := a["riskFactors"].([]any); !ok {
		t.Fatalf("expected riskFactors to be an array, got %T", a["riskFactors"])
	}
}

func TestGraphQLErrorsArrayDoesNotFail(t *testing.T) {
	t.Parallel()
	// A 200 response carrying a GraphQL "errors" array is NOT a failure: the body
	// is used verbatim, preserving partial successes. A resolve response with data
	// plus an errors array still yields the resolved entity, and a subsequent
	// details call completes normally.
	f := &fakeIDP{resps: []*identity_protection.APIPreemptProxyPostGraphqlOK{
		{Payload: &models.SwaggerGraphQLResponse{
			Data:   entitiesData(map[string]any{"entityId": "e1"}),
			Errors: []interface{}{map[string]any{"message": "partial resolver error"}},
		}},
		okResp(entitiesData(map[string]any{"entityId": "e1", "primaryDisplayName": "Admin"})),
	}}
	m := newModule(f)

	_, out, err := m.investigateEntity(context.Background(), nil, InvestigateInput{
		EntityNames:        "Admin",
		InvestigationTypes: []string{investigationEntityDetails},
	})
	if err != nil {
		t.Fatalf("a GraphQL errors array must not produce a Go error, got %v", err)
	}
	if out.Summary.Status != "completed" {
		t.Fatalf("expected completed despite errors array, got %+v", out.Summary)
	}
	if len(out.Entities) != 1 || out.Entities[0] != "e1" {
		t.Fatalf("expected the partial data to still resolve [e1], got %v", out.Entities)
	}
}

func TestUnknownInvestigationType(t *testing.T) {
	t.Parallel()
	f := &fakeIDP{resps: []*identity_protection.APIPreemptProxyPostGraphqlOK{
		okResp(entitiesData(map[string]any{"entityId": "e1"})),
	}}
	m := newModule(f)

	_, out, err := m.investigateEntity(context.Background(), nil, InvestigateInput{
		EntityIDs:          []string{"e1"},
		InvestigationTypes: []string{"bogus_type"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// An unknown investigation type aborts the whole call with a failed status and
	// an "Investigation failed during ..." error, returned as data (not a Go
	// error).
	if out.Summary.Status != "failed" {
		t.Fatalf("expected failed status for unknown type, got %+v", out.Summary)
	}
	if !strings.Contains(out.Error, "Investigation failed during bogus_type") ||
		!strings.Contains(out.Error, "Unknown investigation type: bogus_type") {
		t.Fatalf("expected 'Investigation failed during ...' error, got %q", out.Error)
	}
	// The failed summary reports the resolved-entity count.
	if out.Summary.EntityCount != 1 {
		t.Fatalf("expected entity_count 1 in failed summary, got %d", out.Summary.EntityCount)
	}
	// No GraphQL call is made for an unknown type.
	if f.idx != 0 {
		t.Fatalf("expected no GraphQL call for unknown type, got %d", f.idx)
	}
}

func TestAPIErrorSurfaces(t *testing.T) {
	t.Parallel()
	f := &fakeIDP{errs: []error{errFake}}
	m := newModule(f)

	_, _, err := m.investigateEntity(context.Background(), nil, InvestigateInput{
		EntityNames:        "Admin",
		InvestigationTypes: []string{investigationEntityDetails},
	})
	if err == nil {
		t.Fatalf("expected a Go error from a transport failure")
	}
}

// errFake is a stand-in transport error.
var errFake = &fakeErr{}

type fakeErr struct{}

func (*fakeErr) Error() string { return "fake transport failure" }

func TestMultiEntityInsights(t *testing.T) {
	t.Parallel()
	// Two entities, risk_assessment with a shared risk factor type -> insights
	// should surface a common_risk_factors entry.
	rf := func() []any { return []any{map[string]any{"type": "STALE_ACCOUNT", "severity": "HIGH"}} }
	f := &fakeIDP{resps: []*identity_protection.APIPreemptProxyPostGraphqlOK{
		okResp(entitiesData(
			map[string]any{"entityId": "e1", "riskFactors": rf()},
			map[string]any{"entityId": "e2", "riskFactors": rf()},
		)),
	}}
	m := newModule(f)

	_, out, err := m.investigateEntity(context.Background(), nil, InvestigateInput{
		EntityIDs:          []string{"e1", "e2"},
		InvestigationTypes: []string{investigationRiskAssessment},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	insights := asMap(out.CrossInvestigationInsight)
	if insights == nil {
		t.Fatalf("expected cross_investigation_insights for multiple entities")
	}
	patterns := asMap(insights["multi_entity_patterns"])
	common := asArray(patterns["common_risk_factors"])
	if len(common) != 1 {
		t.Fatalf("expected 1 common risk factor, got %+v", patterns)
	}
	c, ok := common[0].(map[string]any)
	if !ok {
		t.Fatalf("common risk factor should be an object, got %T", common[0])
	}
	if c["risk_type"] != "STALE_ACCOUNT" || c["entity_count"] != 2 {
		t.Fatalf("unexpected common risk factor: %+v", c)
	}
}

func TestToolRegistersReadOnly(t *testing.T) {
	t.Parallel()
	f := &fakeIDP{}
	m := newModule(f)
	var entries []base.ToolEntry
	m.RegisterTools(testutil.CaptureRegistrar(func(e base.ToolEntry) { entries = append(entries, e) }))
	if len(entries) != 1 {
		t.Fatalf("expected 1 tool, got %d", len(entries))
	}
	tool := entries[0].Tool
	if tool.Name != "falcon_idp_investigate_entity" {
		t.Fatalf("expected falcon_ prefixed name, got %q", tool.Name)
	}
	if tool.Annotations == nil || !tool.Annotations.ReadOnlyHint {
		t.Fatalf("expected read-only annotations, got %+v", tool.Annotations)
	}
}
