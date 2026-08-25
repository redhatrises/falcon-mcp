package detections

import (
	"context"
	"errors"
	"reflect"
	"strconv"
	"testing"

	"github.com/crowdstrike/gofalcon/falcon/client/alerts"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/crowdstrike/falcon-mcp/internal/modules/base"
	"github.com/crowdstrike/falcon-mcp/internal/testutil"
)

var testLogger = testutil.DiscardLogger()

// fakeAlerts is a configurable test double for the alertsAPI interface.
type fakeAlerts struct {
	queryResp  *alerts.QueryV2OK
	queryErr   error
	getResp    *alerts.GetV2OK
	getErr     error
	aggResp    *alerts.GetAggregateV2OK
	aggErr     error
	updateResp *alerts.UpdateV3OK
	updateErr  error

	lastUpdateBody  *models.DetectsapiPatchEntitiesAlertsV3Request
	lastQueryParams *alerts.QueryV2Params
	lastAggParams   *alerts.GetAggregateV2Params
	getCalls        int

	// updateBatches records the composite-ID count of each UpdateV3 call, in
	// order. updateFailOnCall (1-based) makes that call return updateErr; 0
	// disables scripted failure.
	updateBatches    []int
	updateFailOnCall int
}

func (f *fakeAlerts) QueryV2(p *alerts.QueryV2Params, _ ...alerts.ClientOption) (*alerts.QueryV2OK, error) {
	f.lastQueryParams = p
	return f.queryResp, f.queryErr
}

func (f *fakeAlerts) GetV2(p *alerts.GetV2Params, _ ...alerts.ClientOption) (*alerts.GetV2OK, error) {
	f.getCalls++
	return f.getResp, f.getErr
}

func (f *fakeAlerts) GetAggregateV2(p *alerts.GetAggregateV2Params, _ ...alerts.ClientOption) (*alerts.GetAggregateV2OK, error) {
	f.lastAggParams = p
	return f.aggResp, f.aggErr
}

func (f *fakeAlerts) UpdateV3(p *alerts.UpdateV3Params, _ ...alerts.ClientOption) (*alerts.UpdateV3OK, error) {
	f.lastUpdateBody = p.Body
	f.updateBatches = append(f.updateBatches, len(p.Body.CompositeIds))
	if f.updateFailOnCall != 0 && len(f.updateBatches) == f.updateFailOnCall {
		return nil, f.updateErr
	}
	if f.updateResp != nil {
		return f.updateResp, nil
	}
	return &alerts.UpdateV3OK{Payload: &models.DetectsapiResponseFields{}}, nil
}

func TestSearchDetectionsEmpty(t *testing.T) {
	t.Parallel()

	f := &fakeAlerts{queryResp: &alerts.QueryV2OK{Payload: &models.DetectsapiAlertQueryResponse{Resources: []string{}}}}
	m := &Module{API: f, Concurrency: 4, Logger: testLogger}

	_, out, err := m.searchDetections(context.Background(), nil, SearchInput{Filter: "status:'new'"})
	if err != nil {
		t.Fatalf("searchDetections: %v", err)
	}
	if len(out.Resources) != 0 || out.FilterUsed != "status:'new'" {
		t.Fatalf("expected empty result, got %+v", out)
	}
	if out.Resources == nil {
		t.Fatalf("resources must be a non-nil empty slice for stable JSON array output")
	}
	if f.getCalls != 0 {
		t.Fatalf("expected no detail fetch on empty result, got %d GetV2 calls", f.getCalls)
	}
}

func TestSearchDetectionsFQLError(t *testing.T) {
	t.Parallel()

	badReq := &alerts.QueryV2BadRequest{Payload: &models.DetectsapiAlertQueryResponse{
		Errors: []*models.MsaAPIError{{Code: new(int32(400)), Message: new("invalid filter")}},
	}}
	f := &fakeAlerts{queryErr: badReq}
	m := &Module{API: f, Concurrency: 4, Logger: testLogger}

	_, out, err := m.searchDetections(context.Background(), nil, SearchInput{Filter: "bogus"})
	if err != nil {
		t.Fatalf("expected FQL error to be formatted, not returned: %v", err)
	}
	if len(out.Errors) != 1 || out.Errors[0].Message != "invalid filter" {
		t.Fatalf("expected FQL error detail, got %+v", out.Errors)
	}
	if out.FQLGuide == "" || out.Hint == "" {
		t.Fatalf("expected fql_guide and hint to be populated")
	}
}

func TestSearchDetectionsFetchesDetails(t *testing.T) {
	t.Parallel()

	// GetV2 returns alerts scrambled relative to the query order; the tool must
	// reorder them back to the query step's sort (composite_id). The query meta
	// reports a full match count larger than this page, which must pass through
	// verbatim on Meta.
	matchTotal := int64(2048)
	f := &fakeAlerts{
		queryResp: &alerts.QueryV2OK{Payload: &models.DetectsapiAlertQueryResponse{
			Resources: []string{"id1", "id2"},
			Meta:      &models.MsaMetaInfo{Pagination: &models.MsaPaging{Total: &matchTotal}},
		}},
		getResp: &alerts.GetV2OK{Payload: &models.DetectsapiPostEntitiesAlertsV2Response{Resources: []*models.DetectsAlert{
			{CompositeID: new("id2")},
			{CompositeID: new("id1")},
		}}},
	}
	m := &Module{API: f, Concurrency: 4, Logger: testLogger}

	_, out, err := m.searchDetections(context.Background(), nil, SearchInput{})
	if err != nil {
		t.Fatalf("searchDetections: %v", err)
	}
	if len(out.Resources) != 2 {
		t.Fatalf("expected 2 resources, got %+v", out)
	}
	if !reflect.DeepEqual(out.Meta, base.NormalizedMeta(f.queryResp.Payload.Meta)) {
		t.Fatalf("expected query meta passed through verbatim, got %+v", out.Meta)
	}
	if got := *out.Resources[0].CompositeID; got != "id1" {
		t.Fatalf("expected query order restored (id1 first), got %q", got)
	}
	if got := *out.Resources[1].CompositeID; got != "id2" {
		t.Fatalf("expected query order restored (id2 second), got %q", got)
	}
	if f.getCalls != 1 {
		t.Fatalf("expected 1 GetV2 call, got %d", f.getCalls)
	}
}

func TestSearchDetectionsForwardsIncludeHiddenToQuery(t *testing.T) {
	t.Parallel()

	f := &fakeAlerts{queryResp: &alerts.QueryV2OK{Payload: &models.DetectsapiAlertQueryResponse{Resources: []string{}}}}
	m := &Module{API: f, Concurrency: 4, Logger: testLogger}

	hidden := false
	_, _, err := m.searchDetections(context.Background(), nil, SearchInput{IncludeHidden: &hidden})
	if err != nil {
		t.Fatalf("searchDetections: %v", err)
	}
	if f.lastQueryParams == nil || f.lastQueryParams.IncludeHidden == nil {
		t.Fatalf("include_hidden not forwarded to query step: %+v", f.lastQueryParams)
	}
	if *f.lastQueryParams.IncludeHidden != false {
		t.Fatalf("include_hidden = %v, want false at query step", *f.lastQueryParams.IncludeHidden)
	}
}

func TestAggregateDetectionsHappyPath(t *testing.T) {
	t.Parallel()

	name := "alert_aggregation"
	f := &fakeAlerts{aggResp: &alerts.GetAggregateV2OK{Payload: &models.DetectsapiAggregatesResponse{
		Resources: []*models.DetectsapiAggregationResult{{Name: &name}},
	}}}
	m := &Module{API: f, Concurrency: 4, Logger: testLogger}

	_, out, err := m.aggregateDetections(context.Background(), nil, AggregateInput{Field: "severity_name", Type: "terms"})
	if err != nil {
		t.Fatalf("aggregateDetections: %v", err)
	}
	if len(out.Resources) != 1 || out.Resources[0].Name == nil || *out.Resources[0].Name != name {
		t.Fatalf("expected one aggregation result, got %+v", out.Resources)
	}
	// include_hidden defaults to true to match the console.
	if f.lastAggParams == nil || f.lastAggParams.IncludeHidden == nil || !*f.lastAggParams.IncludeHidden {
		t.Fatalf("include_hidden should default to true, got %+v", f.lastAggParams)
	}
	// The alerts body sets type/field and omits percents.
	if len(f.lastAggParams.Body) != 1 {
		t.Fatalf("expected single-spec body, got %d", len(f.lastAggParams.Body))
	}
	if got := f.lastAggParams.Body[0]; got.Type == nil || *got.Type != "terms" || got.Field == nil || *got.Field != "severity_name" {
		t.Fatalf("body type/field not mapped: %+v", got)
	}
	// An unset size falls back to 10 so raw/dynamic callers match schema-aware ones.
	if got := f.lastAggParams.Body[0]; got.Size == nil || *got.Size != 10 {
		t.Fatalf("size should default to 10 when unset, got %+v", got.Size)
	}
}

func TestAggregateDetectionsSizePreserved(t *testing.T) {
	t.Parallel()

	f := &fakeAlerts{aggResp: &alerts.GetAggregateV2OK{Payload: &models.DetectsapiAggregatesResponse{
		Resources: []*models.DetectsapiAggregationResult{},
	}}}
	m := &Module{API: f, Concurrency: 4, Logger: testLogger}

	_, _, err := m.aggregateDetections(context.Background(), nil, AggregateInput{Field: "severity_name", Type: "terms", Size: 25})
	if err != nil {
		t.Fatalf("aggregateDetections: %v", err)
	}
	if got := f.lastAggParams.Body[0]; got.Size == nil || *got.Size != 25 {
		t.Fatalf("explicit size must be preserved, got %+v", got.Size)
	}
}

func TestAggregateDetectionsMissingCompanion(t *testing.T) {
	t.Parallel()

	f := &fakeAlerts{}
	m := &Module{API: f, Concurrency: 4, Logger: testLogger}

	// date_histogram without interval must be rejected client-side, before any
	// API call, as a soft-error hint.
	_, out, err := m.aggregateDetections(context.Background(), nil, AggregateInput{Field: "timestamp", Type: "date_histogram"})
	if err != nil {
		t.Fatalf("aggregateDetections: %v", err)
	}
	if out.Hint == "" {
		t.Fatalf("expected companion-missing hint, got %+v", out)
	}
	if f.lastAggParams != nil {
		t.Fatalf("expected no API call when a required companion is missing")
	}
}

func TestAggregateDetectionsFQLError(t *testing.T) {
	t.Parallel()

	badReq := &alerts.GetAggregateV2BadRequest{Payload: &models.DetectsapiAggregatesResponse{
		Errors: []*models.MsaAPIError{{Code: new(int32(400)), Message: new("invalid filter")}},
	}}
	f := &fakeAlerts{aggErr: badReq}
	m := &Module{API: f, Concurrency: 4, Logger: testLogger}

	_, out, err := m.aggregateDetections(context.Background(), nil, AggregateInput{Field: "status", Type: "terms", Filter: "bogus"})
	if err != nil {
		t.Fatalf("expected FQL error as a data result, not returned: %v", err)
	}
	if len(out.Errors) != 1 || out.Errors[0].Message != "invalid filter" {
		t.Fatalf("expected FQL error detail, got %+v", out.Errors)
	}
	if out.FQLGuide == "" || out.Hint == "" {
		t.Fatalf("expected fql_guide and hint to be populated")
	}
}

func TestAggregateDetectionsNonFilterBadRequestSurfacesRaw(t *testing.T) {
	t.Parallel()

	// A 400 that blames the sort (or any non-filter field) must NOT be relabeled
	// as an invalid-filter result; it surfaces raw through base.APIError so the
	// caller fixes the real problem instead of a filter that is fine.
	badReq := &alerts.GetAggregateV2BadRequest{Payload: &models.DetectsapiAggregatesResponse{
		Errors: []*models.MsaAPIError{{Code: new(int32(400)), Message: new("invalid sort field")}},
	}}
	f := &fakeAlerts{aggErr: badReq}
	m := &Module{API: f, Concurrency: 4, Logger: testLogger}

	_, out, err := m.aggregateDetections(context.Background(), nil, AggregateInput{Field: "status", Type: "terms", Sort: "severity.desc"})
	if err == nil {
		t.Fatalf("expected a Go error for a non-filter 400, got soft result %+v", out)
	}
	if len(out.Errors) != 0 || out.FQLGuide != "" {
		t.Fatalf("non-filter 400 must not be dressed as an FQL error, got %+v", out)
	}
}

func TestUpdateDetectionsValidation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		in      UpdateInput
		wantErr bool
	}{
		{"no ids", UpdateInput{Status: "closed"}, true},
		{"no fields", UpdateInput{IDs: []string{"x"}}, true},
		{"bad status", UpdateInput{IDs: []string{"x"}, Status: "frozen"}, true},
		{"two assignments", UpdateInput{IDs: []string{"x"}, AssignToUUID: "a", AssignToName: "b"}, true},
		{"unassign with assign", UpdateInput{IDs: []string{"x"}, Unassign: true, AssignToUUID: "a"}, true},
		{"valid status", UpdateInput{IDs: []string{"x"}, Status: "in_progress"}, false},
		{"valid unassign", UpdateInput{IDs: []string{"x"}, Unassign: true}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := &fakeAlerts{}
			m := &Module{API: f, Concurrency: 4, Logger: testLogger}
			_, _, err := m.updateDetections(context.Background(), nil, tc.in)
			if tc.wantErr && err == nil {
				t.Fatalf("expected error, got nil")
			}
			if tc.wantErr && !errors.Is(err, errInvalidInput) {
				t.Fatalf("expected errInvalidInput, got %v", err)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestUpdateDetectionsBooleanAsString(t *testing.T) {
	t.Parallel()

	f := &fakeAlerts{}
	m := &Module{API: f, Concurrency: 4, Logger: testLogger}
	show := false
	_, _, err := m.updateDetections(context.Background(), nil, UpdateInput{IDs: []string{"x"}, ShowInUI: &show})
	if err != nil {
		t.Fatalf("updateDetections: %v", err)
	}
	found := false
	for _, ap := range f.lastUpdateBody.ActionParameters {
		if *ap.Name == "show_in_ui" {
			found = true
			if *ap.Value != "false" {
				t.Fatalf("show_in_ui should be lowercase string, got %q", *ap.Value)
			}
		}
	}
	if !found {
		t.Fatalf("show_in_ui action parameter not sent")
	}
}

func TestUpdateDetectionsCloseWithoutResolutionHint(t *testing.T) {
	t.Parallel()

	f := &fakeAlerts{}
	m := &Module{API: f, Concurrency: 4, Logger: testLogger}
	_, out, err := m.updateDetections(context.Background(), nil, UpdateInput{IDs: []string{"x"}, Status: "closed"})
	if err != nil {
		t.Fatalf("updateDetections: %v", err)
	}
	if !out.Ok || out.Hint == "" {
		t.Fatalf("expected close-without-resolution hint, got %+v", out)
	}
}

func TestUpdateDetectionsMetaPassthrough(t *testing.T) {
	t.Parallel()

	meta := &models.MsaMetaInfo{Writes: &models.MsaResources{ResourcesAffected: new(int32(1))}}
	f := &fakeAlerts{updateResp: &alerts.UpdateV3OK{Payload: &models.DetectsapiResponseFields{Meta: meta}}}
	m := &Module{API: f, Concurrency: 4, Logger: testLogger}
	_, out, err := m.updateDetections(context.Background(), nil, UpdateInput{IDs: []string{"x"}, Status: "in_progress"})
	if err != nil {
		t.Fatalf("updateDetections: %v", err)
	}
	if !reflect.DeepEqual(out.Meta, base.NormalizedMeta(meta)) {
		t.Fatalf("expected meta passthrough, got %+v", out.Meta)
	}
}

// makeIDs returns n distinct composite IDs for chunking tests.
func makeIDs(n int) []string {
	ids := make([]string, n)
	for i := range ids {
		ids[i] = "id" + strconv.Itoa(i)
	}
	return ids
}

// TestUpdateDetectionsChunksLargeRequest verifies a request over the 1000-ID cap
// is split into successive UpdateV3 calls of at most maxUpdateCompositeIDs.
func TestUpdateDetectionsChunksLargeRequest(t *testing.T) {
	t.Parallel()

	f := &fakeAlerts{}
	m := &Module{API: f, Concurrency: 4, Logger: testLogger}
	_, out, err := m.updateDetections(context.Background(), nil, UpdateInput{IDs: makeIDs(2500), Status: "in_progress"})
	if err != nil {
		t.Fatalf("updateDetections: %v", err)
	}
	if !out.Ok || out.Partial != nil {
		t.Fatalf("expected full success with no partial, got %+v", out)
	}
	if want := []int{1000, 1000, 500}; !reflect.DeepEqual(f.updateBatches, want) {
		t.Fatalf("batch sizes = %v, want %v", f.updateBatches, want)
	}
}

// TestUpdateDetectionsPartialSuccessOnMidBatchFailure verifies a batch failure
// after progress returns a data result (nil Go error) carrying the applied and
// remaining IDs, and stops issuing further batches.
func TestUpdateDetectionsPartialSuccessOnMidBatchFailure(t *testing.T) {
	t.Parallel()

	ids := makeIDs(2500)
	f := &fakeAlerts{updateFailOnCall: 2, updateErr: errors.New("boom")}
	m := &Module{API: f, Concurrency: 4, Logger: testLogger}
	_, out, err := m.updateDetections(context.Background(), nil, UpdateInput{IDs: ids, Status: "in_progress"})
	if err != nil {
		t.Fatalf("mid-batch failure must be a data result, got Go error: %v", err)
	}
	if out.Ok || out.Partial == nil {
		t.Fatalf("expected Ok:false with partial success, got %+v", out)
	}
	if out.Partial.UpdatedCount != 1000 {
		t.Fatalf("UpdatedCount = %d, want 1000", out.Partial.UpdatedCount)
	}
	if !reflect.DeepEqual(out.Partial.UpdatedIDs, ids[:1000]) {
		t.Fatalf("UpdatedIDs mismatch: got %d ids", len(out.Partial.UpdatedIDs))
	}
	if !reflect.DeepEqual(out.Partial.FailedAndRemainingIDs, ids[1000:]) {
		t.Fatalf("FailedAndRemainingIDs mismatch: got %d ids", len(out.Partial.FailedAndRemainingIDs))
	}
	// The failing batch is the last call attempted: no batch is issued after it.
	if len(f.updateBatches) != 2 {
		t.Fatalf("expected 2 UpdateV3 calls before stopping, got %d", len(f.updateBatches))
	}
}

// TestUpdateDetectionsFirstBatchFailureReturnsError verifies a failure on the
// first batch (nothing applied) surfaces as a Go error with no partial result.
func TestUpdateDetectionsFirstBatchFailureReturnsError(t *testing.T) {
	t.Parallel()

	f := &fakeAlerts{updateFailOnCall: 1, updateErr: errors.New("boom")}
	m := &Module{API: f, Concurrency: 4, Logger: testLogger}
	_, out, err := m.updateDetections(context.Background(), nil, UpdateInput{IDs: makeIDs(2500), Status: "in_progress"})
	if err == nil {
		t.Fatalf("expected Go error when the first batch fails, got %+v", out)
	}
	if out.Partial != nil {
		t.Fatalf("expected no partial result on first-batch failure, got %+v", out.Partial)
	}
	if len(f.updateBatches) != 1 {
		t.Fatalf("expected to stop after the first failed batch, got %d calls", len(f.updateBatches))
	}
}

// TestRegisterResourcesServesFQLGuide verifies the detections module publishes
// its FQL guide as the falcon://detections/search/fql-guide resource, with the
// Python-matching name, and that reading it returns the embedded guide text.
func TestRegisterResourcesServesFQLGuide(t *testing.T) {
	t.Parallel()
	testutil.AssertServesFQLGuide(context.Background(), t, (&Module{API: &fakeAlerts{}, Concurrency: 4, Logger: testLogger}).RegisterResources, testutil.FQLGuideExpectation{
		Name: "falcon_search_detections_fql_guide",
		URI:  fqlGuideURI,
		Body: fqlGuide,
	})
}

// TestRegisterToolsAnnotations verifies mutator tools use complete annotations
// so DestructiveHint is never left nil (MCP default true).
func TestRegisterToolsAnnotations(t *testing.T) {
	t.Parallel()

	var entries []base.ToolEntry
	reg := testutil.CaptureRegistrar(func(e base.ToolEntry) { entries = append(entries, e) })
	m := &Module{API: &fakeAlerts{}, Concurrency: 4, Logger: testLogger}
	m.RegisterTools(reg)

	byName := map[string]*mcp.Tool{}
	for _, e := range entries {
		byName[e.Tool.Name] = e.Tool
	}

	// Read-only tools get default annotations from base.AddTool.
	for _, name := range []string{"falcon_search_detections", "falcon_get_detection_details"} {
		tool := byName[name]
		if tool == nil {
			t.Fatalf("missing tool %s", name)
		}
		testutil.AssertReadOnlyAnnotations(t, name, tool.Annotations)
	}

	update := byName["falcon_update_detections"]
	if update == nil {
		t.Fatal("missing falcon_update_detections")
	}
	testutil.AssertMutatingAnnotations(t, "falcon_update_detections", update.Annotations, false)
}
