package detections

import (
	"context"
	"errors"
	"reflect"
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
	updateResp *alerts.UpdateV3OK
	updateErr  error

	lastUpdateBody *models.DetectsapiPatchEntitiesAlertsV3Request
	getCalls       int
}

func (f *fakeAlerts) QueryV2(*alerts.QueryV2Params, ...alerts.ClientOption) (*alerts.QueryV2OK, error) {
	return f.queryResp, f.queryErr
}

func (f *fakeAlerts) GetV2(p *alerts.GetV2Params, _ ...alerts.ClientOption) (*alerts.GetV2OK, error) {
	f.getCalls++
	return f.getResp, f.getErr
}

func (f *fakeAlerts) UpdateV3(p *alerts.UpdateV3Params, _ ...alerts.ClientOption) (*alerts.UpdateV3OK, error) {
	f.lastUpdateBody = p.Body
	if f.updateResp != nil {
		return f.updateResp, f.updateErr
	}
	return &alerts.UpdateV3OK{Payload: &models.DetectsapiResponseFields{}}, f.updateErr
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
