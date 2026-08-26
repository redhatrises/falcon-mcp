package zerotrustassessment

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"testing"

	"github.com/crowdstrike/gofalcon/falcon/client/zero_trust_assessment"
	"github.com/crowdstrike/gofalcon/falcon/models"

	"github.com/crowdstrike/falcon-mcp/internal/modules/base"
	"github.com/crowdstrike/falcon-mcp/internal/testutil"
)

var testLogger = testutil.DiscardLogger()

type fakeZTA struct {
	scoreResp  *zero_trust_assessment.GetAssessmentsByScoreV1OK
	scoreErr   error
	lastFilter string
	lastSort   string
	lastLimit  int64
	lastAfter  string
	scoreCalls int

	getResp  *zero_trust_assessment.GetAssessmentV1OK
	getErr   error
	getCalls int
	lastIDs  []string

	auditResp *zero_trust_assessment.GetAuditV1OK
	auditErr  error
}

func (f *fakeZTA) GetAssessmentsByScoreV1(p *zero_trust_assessment.GetAssessmentsByScoreV1Params, _ ...zero_trust_assessment.ClientOption) (*zero_trust_assessment.GetAssessmentsByScoreV1OK, error) {
	f.scoreCalls++
	f.lastFilter = p.Filter
	if p.Sort != nil {
		f.lastSort = *p.Sort
	}
	if p.Limit != nil {
		f.lastLimit = *p.Limit
	}
	if p.After != nil {
		f.lastAfter = *p.After
	}
	return f.scoreResp, f.scoreErr
}

func (f *fakeZTA) GetAssessmentV1(p *zero_trust_assessment.GetAssessmentV1Params, _ ...zero_trust_assessment.ClientOption) (*zero_trust_assessment.GetAssessmentV1OK, error) {
	f.getCalls++
	f.lastIDs = append(f.lastIDs, p.Ids...)
	return f.getResp, f.getErr
}

func (f *fakeZTA) GetAuditV1(*zero_trust_assessment.GetAuditV1Params, ...zero_trust_assessment.ClientOption) (*zero_trust_assessment.GetAuditV1OK, error) {
	return f.auditResp, f.auditErr
}

// signal builds a DomainSignalProperties keyed only by aid, enough for the
// ordering and not_found assertions.
func signal(aid string) *models.DomainSignalProperties {
	return &models.DomainSignalProperties{Aid: &aid}
}

// score builds a DomainZeroTrustSimpleAssessment for the score-query response.
func score(aid string, s int32) *models.DomainZeroTrustSimpleAssessment {
	return &models.DomainZeroTrustSimpleAssessment{Aid: &aid, Score: &s}
}

func TestBuildScoreFilter(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		min, max *int
		want     string
	}{
		{"neither bound defaults to all assessed", nil, nil, "score:>=0"},
		{"min only", new(50), nil, "score:>=50"},
		{"max only", nil, new(40), "score:<=40"},
		{"both bounds joined by AND", new(30), new(70), "score:>=30+score:<=70"},
		{"equal bounds", new(50), new(50), "score:>=50+score:<=50"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := buildScoreFilter(tc.min, tc.max); got != tc.want {
				t.Fatalf("buildScoreFilter = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestSearchValidationRejectsBadArgs(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		in   SearchInput
	}{
		{"invalid sort_order", SearchInput{SortOrder: "sideways"}},
		{"min greater than max", SearchInput{MinScore: new(80), MaxScore: new(20)}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := &fakeZTA{}
			m := &Module{API: f, Concurrency: 4, Logger: testLogger}
			_, _, err := m.searchAssessments(context.Background(), nil, tc.in)
			if err == nil {
				t.Fatal("expected a validation error, got nil")
			}
			if !errors.Is(err, base.ErrInvalidInput) {
				t.Fatalf("err = %v, want base.ErrInvalidInput", err)
			}
			if f.scoreCalls != 0 {
				t.Fatalf("expected no API call on validation failure, got %d", f.scoreCalls)
			}
		})
	}
}

func TestSearchDefaultsAndPassthrough(t *testing.T) {
	t.Parallel()
	f := &fakeZTA{scoreResp: &zero_trust_assessment.GetAssessmentsByScoreV1OK{
		Payload: &models.DomainAssessmentsByScoreResponse{Resources: nil},
	}}
	m := &Module{API: f, Concurrency: 4, Logger: testLogger}
	_, out, err := m.searchAssessments(context.Background(), nil, SearchInput{After: "cursor-1"})
	if err != nil {
		t.Fatalf("searchAssessments: %v", err)
	}
	if f.lastSort != "score|asc" {
		t.Errorf("sort = %q, want score|asc (default order)", f.lastSort)
	}
	if f.lastLimit != 100 {
		t.Errorf("limit = %d, want 100 (default)", f.lastLimit)
	}
	if f.lastFilter != "score:>=0" {
		t.Errorf("filter = %q, want score:>=0 (unbounded default)", f.lastFilter)
	}
	if f.lastAfter != "cursor-1" {
		t.Errorf("after = %q, want cursor-1", f.lastAfter)
	}
	// No scored hosts → empty envelope, no detail fetch, not_found omitted.
	if out.Resources == nil || len(out.Resources) != 0 {
		t.Errorf("expected empty non-nil resources, got %+v", out.Resources)
	}
	if f.getCalls != 0 {
		t.Errorf("expected no detail fetch on empty score result, got %d", f.getCalls)
	}
	if out.NotFound != nil {
		t.Errorf("expected not_found omitted on empty result, got %+v", out.NotFound)
	}
}

func TestSearchDescOrder(t *testing.T) {
	t.Parallel()
	f := &fakeZTA{scoreResp: &zero_trust_assessment.GetAssessmentsByScoreV1OK{
		Payload: &models.DomainAssessmentsByScoreResponse{Resources: nil},
	}}
	m := &Module{API: f, Concurrency: 4, Logger: testLogger}
	if _, _, err := m.searchAssessments(context.Background(), nil, SearchInput{SortOrder: "desc"}); err != nil {
		t.Fatalf("searchAssessments: %v", err)
	}
	if f.lastSort != "score|desc" {
		t.Fatalf("sort = %q, want score|desc", f.lastSort)
	}
}

func TestSearchFetchesDetailsInScoreOrder(t *testing.T) {
	t.Parallel()
	// Score query ranks a1 then a2; the details endpoint returns them scrambled.
	// The tool must restore the score-query order.
	meta := &models.DomainSearchAfterMeta{}
	f := &fakeZTA{
		scoreResp: &zero_trust_assessment.GetAssessmentsByScoreV1OK{Payload: &models.DomainAssessmentsByScoreResponse{
			Resources: []*models.DomainZeroTrustSimpleAssessment{score("a1", 10), score("a2", 20)},
			Meta:      meta,
		}},
		getResp: &zero_trust_assessment.GetAssessmentV1OK{Payload: &models.DomainAssessmentsResponse{
			Resources: []*models.DomainSignalProperties{signal("a2"), signal("a1")},
		}},
	}
	m := &Module{API: f, Concurrency: 4, Logger: testLogger}
	_, out, err := m.searchAssessments(context.Background(), nil, SearchInput{})
	if err != nil {
		t.Fatalf("searchAssessments: %v", err)
	}
	if len(out.Resources) != 2 {
		t.Fatalf("expected 2 resources, got %+v", out.Resources)
	}
	if *out.Resources[0].Aid != "a1" || *out.Resources[1].Aid != "a2" {
		t.Fatalf("expected score order a1,a2, got %q,%q", *out.Resources[0].Aid, *out.Resources[1].Aid)
	}
	testutil.AssertNormalizedMeta(t, out.Meta, meta)
	if out.NotFound != nil {
		t.Fatalf("expected not_found omitted when every scored host resolved, got %+v", out.NotFound)
	}
	if f.getCalls != 1 {
		t.Fatalf("expected 1 detail fetch, got %d", f.getCalls)
	}
}

func TestSearchReportsVanishedHosts(t *testing.T) {
	t.Parallel()
	// a2 was scored but disappeared before the detail fetch; it belongs in
	// not_found, and not_found is present because it is non-empty.
	f := &fakeZTA{
		scoreResp: &zero_trust_assessment.GetAssessmentsByScoreV1OK{Payload: &models.DomainAssessmentsByScoreResponse{
			Resources: []*models.DomainZeroTrustSimpleAssessment{score("a1", 10), score("a2", 20)},
		}},
		getResp: &zero_trust_assessment.GetAssessmentV1OK{Payload: &models.DomainAssessmentsResponse{
			Resources: []*models.DomainSignalProperties{signal("a1")},
		}},
	}
	m := &Module{API: f, Concurrency: 4, Logger: testLogger}
	_, out, err := m.searchAssessments(context.Background(), nil, SearchInput{})
	if err != nil {
		t.Fatalf("searchAssessments: %v", err)
	}
	if !reflect.DeepEqual(out.NotFound, []string{"a2"}) {
		t.Fatalf("not_found = %+v, want [a2]", out.NotFound)
	}

	// not_found must be serialized (omitempty but non-empty here).
	blob, err := json.Marshal(out)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var decoded map[string]json.RawMessage
	if err := json.Unmarshal(blob, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if _, ok := decoded["not_found"]; !ok {
		t.Fatalf("expected not_found key present when populated, got %s", blob)
	}
}

func TestSearchOmitsNotFoundKeyWhenEmpty(t *testing.T) {
	t.Parallel()
	f := &fakeZTA{
		scoreResp: &zero_trust_assessment.GetAssessmentsByScoreV1OK{Payload: &models.DomainAssessmentsByScoreResponse{
			Resources: []*models.DomainZeroTrustSimpleAssessment{score("a1", 10)},
		}},
		getResp: &zero_trust_assessment.GetAssessmentV1OK{Payload: &models.DomainAssessmentsResponse{
			Resources: []*models.DomainSignalProperties{signal("a1")},
		}},
	}
	m := &Module{API: f, Concurrency: 4, Logger: testLogger}
	_, out, err := m.searchAssessments(context.Background(), nil, SearchInput{})
	if err != nil {
		t.Fatalf("searchAssessments: %v", err)
	}
	blob, err := json.Marshal(out)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var decoded map[string]json.RawMessage
	if err := json.Unmarshal(blob, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if _, ok := decoded["not_found"]; ok {
		t.Fatalf("expected not_found omitted from search result when empty, got %s", blob)
	}
}

func TestGetEmptyShortCircuits(t *testing.T) {
	t.Parallel()
	f := &fakeZTA{}
	m := &Module{API: f, Concurrency: 4, Logger: testLogger}
	_, out, err := m.getAssessments(context.Background(), nil, GetInput{IDs: nil})
	if err != nil {
		t.Fatalf("getAssessments: %v", err)
	}
	if f.getCalls != 0 {
		t.Fatalf("expected short-circuit, got %d calls", f.getCalls)
	}
	if out.NotFound == nil {
		t.Fatalf("expected not_found present (non-nil) even when empty, got nil")
	}
}

func TestGetReturnsDetailsAndAlwaysEmitsNotFound(t *testing.T) {
	t.Parallel()
	f := &fakeZTA{getResp: &zero_trust_assessment.GetAssessmentV1OK{Payload: &models.DomainAssessmentsResponse{
		Resources: []*models.DomainSignalProperties{signal("a1")},
	}}}
	m := &Module{API: f, Concurrency: 4, Logger: testLogger}

	// a1 resolves, a2 does not — not_found lists a2 in request order.
	_, out, err := m.getAssessments(context.Background(), nil, GetInput{IDs: []string{"a1", "a2"}})
	if err != nil {
		t.Fatalf("getAssessments: %v", err)
	}
	if out.Total != 1 || len(out.Resources) != 1 {
		t.Fatalf("expected 1 resource, got total=%d resources=%+v", out.Total, out.Resources)
	}
	if !reflect.DeepEqual(out.NotFound, []string{"a2"}) {
		t.Fatalf("not_found = %+v, want [a2]", out.NotFound)
	}

	// not_found is always serialized on the get result, even when empty.
	all := &fakeZTA{getResp: &zero_trust_assessment.GetAssessmentV1OK{Payload: &models.DomainAssessmentsResponse{
		Resources: []*models.DomainSignalProperties{signal("a1")},
	}}}
	mAll := &Module{API: all, Concurrency: 4, Logger: testLogger}
	_, outAll, err := mAll.getAssessments(context.Background(), nil, GetInput{IDs: []string{"a1"}})
	if err != nil {
		t.Fatalf("getAssessments: %v", err)
	}
	blob, err := json.Marshal(outAll)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var decoded map[string]json.RawMessage
	if err := json.Unmarshal(blob, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	raw, ok := decoded["not_found"]
	if !ok {
		t.Fatalf("expected not_found always present on get result, got %s", blob)
	}
	if string(raw) != "[]" {
		t.Fatalf("expected empty not_found rendered as [], got %s", raw)
	}
}

func TestGetAudit(t *testing.T) {
	t.Parallel()
	meta := &models.DomainMetaInfo{}
	f := &fakeZTA{auditResp: &zero_trust_assessment.GetAuditV1OK{Payload: &models.DomainAuditResponse{
		Resources: []*models.CommonCIDAuditResult{{}},
		Meta:      meta,
	}}}
	m := &Module{API: f, Concurrency: 4, Logger: testLogger}
	_, out, err := m.getAudit(context.Background(), nil, struct{}{})
	if err != nil {
		t.Fatalf("getAudit: %v", err)
	}
	if out.Total != 1 || len(out.Resources) != 1 {
		t.Fatalf("expected 1 audit record, got total=%d resources=%+v", out.Total, out.Resources)
	}
	testutil.AssertNormalizedMeta(t, out.Meta, meta)
}

func TestMissingAIDsPreservesOrderAndNonNil(t *testing.T) {
	t.Parallel()
	got := missingAIDs([]string{"a", "b", "c"}, []*models.DomainSignalProperties{signal("b")})
	if !reflect.DeepEqual(got, []string{"a", "c"}) {
		t.Fatalf("missingAIDs = %+v, want [a c]", got)
	}
	if empty := missingAIDs(nil, nil); empty == nil {
		t.Fatal("missingAIDs must never return nil")
	}
}

func TestSearchSurfacesAPIError(t *testing.T) {
	t.Parallel()
	f := &fakeZTA{scoreErr: errors.New("upstream boom")}
	m := &Module{API: f, Concurrency: 4, Logger: testLogger}
	_, _, err := m.searchAssessments(context.Background(), nil, SearchInput{})
	if err == nil {
		t.Fatal("expected a Go error when the score query fails, got nil")
	}
	var apiErr *base.Error
	if !errors.As(err, &apiErr) {
		t.Fatalf("err = %v, want *base.Error", err)
	}
}

func TestGetSurfacesAPIError(t *testing.T) {
	t.Parallel()
	f := &fakeZTA{getErr: errors.New("upstream boom")}
	m := &Module{API: f, Concurrency: 4, Logger: testLogger}
	_, _, err := m.getAssessments(context.Background(), nil, GetInput{IDs: []string{"a1"}})
	if err == nil {
		t.Fatal("expected a Go error when the detail fetch fails, got nil")
	}
	var apiErr *base.Error
	if !errors.As(err, &apiErr) {
		t.Fatalf("err = %v, want *base.Error", err)
	}
}

func TestGetAuditSurfacesAPIError(t *testing.T) {
	t.Parallel()
	f := &fakeZTA{auditErr: errors.New("upstream boom")}
	m := &Module{API: f, Concurrency: 4, Logger: testLogger}
	_, _, err := m.getAudit(context.Background(), nil, struct{}{})
	if err == nil {
		t.Fatal("expected a Go error when the audit query fails, got nil")
	}
	var apiErr *base.Error
	if !errors.As(err, &apiErr) {
		t.Fatalf("err = %v, want *base.Error", err)
	}
}

func TestRegisterToolsReadOnly(t *testing.T) {
	t.Parallel()
	m := &Module{Logger: testLogger}
	byName := testutil.CollectTools(m)
	for _, name := range []string{"falcon_search_zta_assessments", "falcon_get_zta_assessments", "falcon_get_zta_audit"} {
		e, ok := byName[name]
		if !ok {
			t.Fatalf("missing tool %s", name)
		}
		testutil.AssertReadOnlyAnnotations(t, name, e.Annotations)
	}
}
