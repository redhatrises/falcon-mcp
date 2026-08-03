package quarantine

import (
	"context"
	"errors"
	"log/slog"
	"reflect"
	"testing"

	"github.com/crowdstrike/gofalcon/falcon/client/quarantine"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/crowdstrike/falcon-mcp/internal/modules/base"
)

// metaQueryTime is a non-zero query_time for test fakes, so a handler's
// normalized meta is a populated value rather than nil.
var metaQueryTime = 0.02

// testLogger discards output; modules require a non-nil logger.
var testLogger = slog.New(slog.DiscardHandler)

// fakeQuarantine is a configurable test double for the quarantineAPI interface.
type fakeQuarantine struct {
	queryResp *quarantine.QueryQuarantineFilesOK
	queryErr  error
	getResp   *quarantine.GetQuarantineFilesOK
	getErr    error
	countResp *quarantine.ActionUpdateCountOK
	countErr  error
	byIDsResp *quarantine.UpdateQuarantinedDetectsByIdsOK
	byIDsErr  error
	byQryResp *quarantine.UpdateQfByQueryOK
	byQryErr  error

	getCalls      int
	lastByIDsBody *models.DomainEntitiesPatchRequest
	lastByQryBody *models.DomainQueriesPatchRequest

	// lastQueryOffset records the offset the handler sent, so a test can assert
	// the numeric input reaches the string-typed query param intact.
	lastQueryOffset *string
}

func (f *fakeQuarantine) QueryQuarantineFiles(p *quarantine.QueryQuarantineFilesParams, _ ...quarantine.ClientOption) (*quarantine.QueryQuarantineFilesOK, error) {
	f.lastQueryOffset = p.Offset
	return f.queryResp, f.queryErr
}

func (f *fakeQuarantine) GetQuarantineFiles(*quarantine.GetQuarantineFilesParams, ...quarantine.ClientOption) (*quarantine.GetQuarantineFilesOK, error) {
	f.getCalls++
	return f.getResp, f.getErr
}

func (f *fakeQuarantine) ActionUpdateCount(*quarantine.ActionUpdateCountParams, ...quarantine.ClientOption) (*quarantine.ActionUpdateCountOK, error) {
	return f.countResp, f.countErr
}

func (f *fakeQuarantine) UpdateQuarantinedDetectsByIds(p *quarantine.UpdateQuarantinedDetectsByIdsParams, _ ...quarantine.ClientOption) (*quarantine.UpdateQuarantinedDetectsByIdsOK, error) {
	f.lastByIDsBody = p.Body
	return f.byIDsResp, f.byIDsErr
}

func (f *fakeQuarantine) UpdateQfByQuery(p *quarantine.UpdateQfByQueryParams, _ ...quarantine.ClientOption) (*quarantine.UpdateQfByQueryOK, error) {
	f.lastByQryBody = p.Body
	return f.byQryResp, f.byQryErr
}

func str(s string) *string { return &s }

// queryOK builds a QueryQuarantineFiles response returning the given IDs.
func queryOK(ids ...string) *quarantine.QueryQuarantineFilesOK {
	return &quarantine.QueryQuarantineFilesOK{Payload: &models.MsaspecQueryResponse{Resources: ids}}
}

// getOK builds a GetQuarantineFiles response returning records for the given IDs.
func getOK(ids ...string) *quarantine.GetQuarantineFilesOK {
	files := make([]*models.QuarantineQuarantinedFile, 0, len(ids))
	for _, id := range ids {
		files = append(files, &models.QuarantineQuarantinedFile{ID: id})
	}
	return &quarantine.GetQuarantineFilesOK{Payload: &models.DomainMsaQfResponse{Resources: files}}
}

func TestSearchQuarantinedFilesSuccess(t *testing.T) {
	t.Parallel()

	f := &fakeQuarantine{queryResp: queryOK("q1", "q2"), getResp: getOK("q1", "q2")}
	f.queryResp.Payload.Meta = &models.MsaMetaInfo{QueryTime: &metaQueryTime}
	m := &Module{API: f, Concurrency: 4, Logger: testLogger}

	_, out, err := m.searchQuarantinedFiles(context.Background(), nil, SearchInput{Filter: "hostname:'DC01'"})
	if err != nil {
		t.Fatalf("searchQuarantinedFiles: %v", err)
	}
	if len(out.Resources) != 2 || out.FilterUsed != "hostname:'DC01'" {
		t.Fatalf("unexpected result: %+v", out)
	}
	if !reflect.DeepEqual(out.Meta, base.NormalizedMeta(f.queryResp.Payload.Meta)) {
		t.Fatalf("expected normalized meta, got %+v", out.Meta)
	}
}

// TestSearchQuarantinedFilesOffset covers the offset conversion. The tool takes a
// numeric offset, matching the numeric offset the endpoint reports back in
// meta.pagination, while the gofalcon query param is typed as a string; the handler
// bridges the two. A zero offset must leave the param unset rather than sending "0".
func TestSearchQuarantinedFilesOffset(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		offset int
		want   *string
	}{
		{"zero leaves the param unset", 0, nil},
		{"positive offset is sent as digits", 25, str("25")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			f := &fakeQuarantine{queryResp: queryOK("q1"), getResp: getOK("q1")}
			m := &Module{API: f, Concurrency: 4, Logger: testLogger}

			if _, _, err := m.searchQuarantinedFiles(context.Background(), nil, SearchInput{Offset: tt.offset}); err != nil {
				t.Fatalf("searchQuarantinedFiles: %v", err)
			}
			if !reflect.DeepEqual(f.lastQueryOffset, tt.want) {
				t.Errorf("query offset = %v, want %v", derefOrNil(f.lastQueryOffset), derefOrNil(tt.want))
			}
		})
	}
}

// derefOrNil renders a *string for a test failure message without panicking on nil.
func derefOrNil(p *string) string {
	if p == nil {
		return "<nil>"
	}
	return *p
}

func TestSearchQuarantinedFilesEmpty(t *testing.T) {
	t.Parallel()

	f := &fakeQuarantine{queryResp: queryOK()}
	m := &Module{API: f, Concurrency: 4, Logger: testLogger}

	_, out, err := m.searchQuarantinedFiles(context.Background(), nil, SearchInput{Filter: "hostname:'nope'"})
	if err != nil {
		t.Fatalf("searchQuarantinedFiles: %v", err)
	}
	if len(out.Resources) != 0 {
		t.Fatalf("expected empty result, got %+v", out)
	}
	if out.Resources == nil {
		t.Fatalf("resources must be a non-nil empty slice for stable JSON array output")
	}
	if f.getCalls != 0 {
		t.Fatalf("expected no detail fetch on empty result, got %d", f.getCalls)
	}
}

func TestSearchQuarantinedFilesReordersByID(t *testing.T) {
	t.Parallel()

	// Detail endpoint returns records out of query order; result must be
	// reordered back to the query step's sort.
	f := &fakeQuarantine{queryResp: queryOK("q1", "q2", "q3"), getResp: getOK("q3", "q1", "q2")}
	m := &Module{API: f, Concurrency: 4, Logger: testLogger}

	_, out, err := m.searchQuarantinedFiles(context.Background(), nil, SearchInput{})
	if err != nil {
		t.Fatalf("searchQuarantinedFiles: %v", err)
	}
	got := []string{out.Resources[0].ID, out.Resources[1].ID, out.Resources[2].ID}
	want := []string{"q1", "q2", "q3"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("reorder failed: got %v want %v", got, want)
		}
	}
}

func TestSearchQuarantinedFilesQueryAPIError(t *testing.T) {
	t.Parallel()

	f := &fakeQuarantine{queryErr: errors.New("boom")}
	m := &Module{API: f, Concurrency: 4, Logger: testLogger}

	_, _, err := m.searchQuarantinedFiles(context.Background(), nil, SearchInput{})
	if err == nil {
		t.Fatalf("expected query API error to be returned")
	}
	if f.getCalls != 0 {
		t.Fatalf("expected no detail fetch after query error")
	}
}

func TestSearchQuarantinedFilesDetailAPIError(t *testing.T) {
	t.Parallel()

	f := &fakeQuarantine{queryResp: queryOK("q1"), getErr: errors.New("detail boom")}
	m := &Module{API: f, Concurrency: 4, Logger: testLogger}

	_, _, err := m.searchQuarantinedFiles(context.Background(), nil, SearchInput{})
	if err == nil {
		t.Fatalf("expected detail API error to be returned")
	}
}

func TestPreviewQuarantineActionsSuccess(t *testing.T) {
	t.Parallel()

	f := &fakeQuarantine{countResp: &quarantine.ActionUpdateCountOK{Payload: &models.MsaAggregatesResponse{
		Resources: []*models.MsaAggregationResult{{Name: str("release")}, {Name: str("delete")}},
		Meta:      &models.MsaMetaInfo{QueryTime: &metaQueryTime},
	}}}
	m := &Module{API: f, Logger: testLogger}

	_, out, err := m.previewQuarantineActions(context.Background(), nil, PreviewInput{Filter: "state:'quarantined'"})
	if err != nil {
		t.Fatalf("previewQuarantineActions: %v", err)
	}
	if out.Total != 2 || len(out.Resources) != 2 {
		t.Fatalf("expected 2 action counts, got %+v", out)
	}
	if !reflect.DeepEqual(out.Meta, base.NormalizedMeta(f.countResp.Payload.Meta)) {
		t.Fatalf("expected normalized meta, got %+v", out.Meta)
	}
}

func TestPreviewQuarantineActionsRequiresFilter(t *testing.T) {
	t.Parallel()

	m := &Module{API: &fakeQuarantine{}, Logger: testLogger}
	_, _, err := m.previewQuarantineActions(context.Background(), nil, PreviewInput{})
	if !errors.Is(err, errInvalidInput) {
		t.Fatalf("expected errInvalidInput for empty filter, got %v", err)
	}
}

func TestPreviewQuarantineActionsAPIError(t *testing.T) {
	t.Parallel()

	f := &fakeQuarantine{countErr: errors.New("boom")}
	m := &Module{API: f, Logger: testLogger}
	_, _, err := m.previewQuarantineActions(context.Background(), nil, PreviewInput{Filter: "state:'quarantined'"})
	if err == nil {
		t.Fatalf("expected API error to be returned")
	}
}

func TestNormalizeRestoreAction(t *testing.T) {
	t.Parallel()

	tests := []struct {
		in      string
		want    string
		wantErr bool
	}{
		{"release", "release", false},
		{"unrelease", "unrelease", false},
		{"  RELEASE  ", "release", false},
		{"Unrelease", "unrelease", false},
		{"delete", "", true},
		{"", "", true},
		{"bogus", "", true},
	}
	for _, tc := range tests {
		got, err := normalizeRestoreAction(tc.in)
		if tc.wantErr {
			if !errors.Is(err, errInvalidInput) {
				t.Errorf("normalizeRestoreAction(%q): expected errInvalidInput, got %v", tc.in, err)
			}
			continue
		}
		if err != nil || got != tc.want {
			t.Errorf("normalizeRestoreAction(%q) = %q, %v; want %q, nil", tc.in, got, err, tc.want)
		}
	}
}

func TestUpdateQuarantinedFilesByIDs(t *testing.T) {
	t.Parallel()

	f := &fakeQuarantine{byIDsResp: &quarantine.UpdateQuarantinedDetectsByIdsOK{Payload: &models.MsaReplyMetaOnly{Meta: &models.MsaMetaInfo{QueryTime: &metaQueryTime}}}}
	m := &Module{API: f, Logger: testLogger}

	_, out, err := m.updateQuarantinedFiles(context.Background(), nil, UpdateInput{
		Action:  "release",
		IDs:     []string{"q1", "q2"},
		Comment: "cleared by analyst",
	})
	if err != nil {
		t.Fatalf("updateQuarantinedFiles: %v", err)
	}
	if !out.Ok {
		t.Fatalf("expected Ok=true, got %+v", out)
	}
	if f.lastByIDsBody == nil || f.lastByIDsBody.Action != "release" {
		t.Fatalf("expected release action in body, got %+v", f.lastByIDsBody)
	}
	if len(f.lastByIDsBody.Ids) != 2 || f.lastByIDsBody.Comment != "cleared by analyst" {
		t.Fatalf("unexpected body: %+v", f.lastByIDsBody)
	}
	if f.lastByQryBody != nil {
		t.Fatalf("expected by-query path not taken when ids provided")
	}
	if !reflect.DeepEqual(out.Meta, base.NormalizedMeta(f.byIDsResp.Payload.Meta)) {
		t.Fatalf("expected normalized meta, got %+v", out.Meta)
	}
}

func TestUpdateQuarantinedFilesByQueryNormalizesAction(t *testing.T) {
	t.Parallel()

	f := &fakeQuarantine{byQryResp: &quarantine.UpdateQfByQueryOK{Payload: &models.MsaReplyMetaOnly{}}}
	m := &Module{API: f, Logger: testLogger}

	_, out, err := m.updateQuarantinedFiles(context.Background(), nil, UpdateInput{
		Action: "  Unrelease  ",
		Filter: "state:'released'",
	})
	if err != nil {
		t.Fatalf("updateQuarantinedFiles: %v", err)
	}
	if !out.Ok {
		t.Fatalf("expected Ok=true, got %+v", out)
	}
	if f.lastByQryBody == nil || f.lastByQryBody.Action != "unrelease" {
		t.Fatalf("expected normalized unrelease action, got %+v", f.lastByQryBody)
	}
	if f.lastByQryBody.Filter != "state:'released'" {
		t.Fatalf("expected filter passed through, got %+v", f.lastByQryBody)
	}
}

func TestUpdateQuarantinedFilesRejectsBadAction(t *testing.T) {
	t.Parallel()

	f := &fakeQuarantine{}
	m := &Module{API: f, Logger: testLogger}

	// "delete" is not a reversible action for update; must be rejected before
	// any API call.
	_, _, err := m.updateQuarantinedFiles(context.Background(), nil, UpdateInput{Action: "delete", IDs: []string{"q1"}})
	if !errors.Is(err, errInvalidInput) {
		t.Fatalf("expected errInvalidInput for delete action, got %v", err)
	}
	if f.lastByIDsBody != nil || f.lastByQryBody != nil {
		t.Fatalf("expected no API call on invalid action")
	}
}

func TestUpdateQuarantinedFilesRequiresSelector(t *testing.T) {
	t.Parallel()

	f := &fakeQuarantine{}
	m := &Module{API: f, Logger: testLogger}

	_, _, err := m.updateQuarantinedFiles(context.Background(), nil, UpdateInput{Action: "release"})
	if !errors.Is(err, errInvalidInput) {
		t.Fatalf("expected errInvalidInput when neither ids nor filter provided, got %v", err)
	}
	if f.lastByIDsBody != nil || f.lastByQryBody != nil {
		t.Fatalf("expected no API call when selector missing")
	}
}

func TestUpdateQuarantinedFilesPrefersIDsOverFilter(t *testing.T) {
	t.Parallel()

	f := &fakeQuarantine{byIDsResp: &quarantine.UpdateQuarantinedDetectsByIdsOK{Payload: &models.MsaReplyMetaOnly{}}}
	m := &Module{API: f, Logger: testLogger}

	_, _, err := m.updateQuarantinedFiles(context.Background(), nil, UpdateInput{
		Action: "release",
		IDs:    []string{"q1"},
		Filter: "state:'quarantined'",
	})
	if err != nil {
		t.Fatalf("updateQuarantinedFiles: %v", err)
	}
	if f.lastByIDsBody == nil {
		t.Fatalf("expected by-ids path taken when both ids and filter provided")
	}
	if f.lastByQryBody != nil {
		t.Fatalf("expected by-query path NOT taken when ids present")
	}
}

func TestUpdateQuarantinedFilesAPIError(t *testing.T) {
	t.Parallel()

	f := &fakeQuarantine{byIDsErr: errors.New("boom")}
	m := &Module{API: f, Logger: testLogger}

	_, _, err := m.updateQuarantinedFiles(context.Background(), nil, UpdateInput{Action: "release", IDs: []string{"q1"}})
	if err == nil {
		t.Fatalf("expected API error to be returned")
	}
}

func TestDeleteQuarantinedFilesByIDs(t *testing.T) {
	t.Parallel()

	f := &fakeQuarantine{byIDsResp: &quarantine.UpdateQuarantinedDetectsByIdsOK{Payload: &models.MsaReplyMetaOnly{}}}
	m := &Module{API: f, Logger: testLogger}

	_, out, err := m.deleteQuarantinedFiles(context.Background(), nil, DeleteInput{IDs: []string{"q1"}, Comment: "malware"})
	if err != nil {
		t.Fatalf("deleteQuarantinedFiles: %v", err)
	}
	if !out.Ok {
		t.Fatalf("expected Ok=true, got %+v", out)
	}
	if f.lastByIDsBody == nil || f.lastByIDsBody.Action != "delete" {
		t.Fatalf("expected delete action in body, got %+v", f.lastByIDsBody)
	}
	if f.lastByIDsBody.Comment != "malware" {
		t.Fatalf("expected comment passed through, got %+v", f.lastByIDsBody)
	}
}

func TestDeleteQuarantinedFilesByQuery(t *testing.T) {
	t.Parallel()

	f := &fakeQuarantine{byQryResp: &quarantine.UpdateQfByQueryOK{Payload: &models.MsaReplyMetaOnly{Meta: &models.MsaMetaInfo{QueryTime: &metaQueryTime}}}}
	m := &Module{API: f, Logger: testLogger}

	_, out, err := m.deleteQuarantinedFiles(context.Background(), nil, DeleteInput{Filter: "hostname:'DC01'"})
	if err != nil {
		t.Fatalf("deleteQuarantinedFiles: %v", err)
	}
	if !out.Ok {
		t.Fatalf("expected Ok=true, got %+v", out)
	}
	if f.lastByQryBody == nil || f.lastByQryBody.Action != "delete" {
		t.Fatalf("expected delete action in query body, got %+v", f.lastByQryBody)
	}
	if f.lastByQryBody.Filter != "hostname:'DC01'" {
		t.Fatalf("expected filter passed through, got %+v", f.lastByQryBody)
	}
	if !reflect.DeepEqual(out.Meta, base.NormalizedMeta(f.byQryResp.Payload.Meta)) {
		t.Fatalf("expected normalized meta, got %+v", out.Meta)
	}
}

func TestDeleteQuarantinedFilesRequiresSelector(t *testing.T) {
	t.Parallel()

	f := &fakeQuarantine{}
	m := &Module{API: f, Logger: testLogger}

	_, _, err := m.deleteQuarantinedFiles(context.Background(), nil, DeleteInput{})
	if !errors.Is(err, errInvalidInput) {
		t.Fatalf("expected errInvalidInput when neither ids nor filter provided, got %v", err)
	}
	if f.lastByIDsBody != nil || f.lastByQryBody != nil {
		t.Fatalf("expected no API call when selector missing")
	}
}

func TestDeleteQuarantinedFilesAPIError(t *testing.T) {
	t.Parallel()

	f := &fakeQuarantine{byQryErr: errors.New("boom")}
	m := &Module{API: f, Logger: testLogger}

	_, _, err := m.deleteQuarantinedFiles(context.Background(), nil, DeleteInput{Filter: "hostname:'DC01'"})
	if err == nil {
		t.Fatalf("expected API error to be returned")
	}
}

// TestRegisterResourcesServesFQLGuide verifies the quarantine module publishes
// its FQL guide as the falcon://quarantine/files/search/fql-guide resource, with
// the Python-matching name, and that reading it returns the embedded guide text.
func TestRegisterResourcesServesFQLGuide(t *testing.T) {
	t.Parallel()

	srv := mcp.NewServer(&mcp.Implementation{Name: "test", Version: "test"}, nil)
	(&Module{API: &fakeQuarantine{}, Logger: testLogger}).RegisterResources(srv)

	ctx := context.Background()
	clientT, serverT := mcp.NewInMemoryTransports()
	ss, err := srv.Connect(ctx, serverT, nil)
	if err != nil {
		t.Fatalf("server connect: %v", err)
	}
	t.Cleanup(func() { _ = ss.Wait() })

	cs, err := mcp.NewClient(&mcp.Implementation{Name: "c", Version: "test"}, nil).Connect(ctx, clientT, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	t.Cleanup(func() { _ = cs.Close() })

	list, err := cs.ListResources(ctx, nil)
	if err != nil {
		t.Fatalf("ListResources: %v", err)
	}
	if len(list.Resources) != 1 {
		t.Fatalf("expected 1 resource, got %d", len(list.Resources))
	}
	if got := list.Resources[0]; got.Name != "falcon_search_quarantined_files_fql_guide" || got.URI != fqlGuideURI {
		t.Fatalf("resource = {name:%q uri:%q}, want falcon_search_quarantined_files_fql_guide / %s", got.Name, got.URI, fqlGuideURI)
	}

	read, err := cs.ReadResource(ctx, &mcp.ReadResourceParams{URI: fqlGuideURI})
	if err != nil {
		t.Fatalf("ReadResource: %v", err)
	}
	if len(read.Contents) != 1 || read.Contents[0].Text != fqlGuide {
		t.Fatalf("read content does not match embedded guide")
	}
}

// TestRegisterToolsAnnotations verifies each tool advertises the correct
// annotations: search and preview read-only, update mutating (non-destructive),
// delete destructive. This is the core validation that the Go registry emits
// tool annotations correctly for mutating actions.
func TestRegisterToolsAnnotations(t *testing.T) {
	t.Parallel()

	var entries []base.ToolEntry
	reg := captureRegistrar(func(e base.ToolEntry) { entries = append(entries, e) })
	m := &Module{API: &fakeQuarantine{}, Logger: testLogger}
	m.RegisterTools(reg)

	byName := map[string]*mcp.Tool{}
	for _, e := range entries {
		byName[e.Tool.Name] = e.Tool
	}

	search := byName["falcon_search_quarantined_files"]
	if search == nil {
		t.Fatal("missing falcon_search_quarantined_files")
	}
	assertReadOnlyAnnotations(t, "falcon_search_quarantined_files", search.Annotations)

	preview := byName["falcon_preview_quarantine_actions"]
	if preview == nil {
		t.Fatal("missing falcon_preview_quarantine_actions")
	}
	assertReadOnlyAnnotations(t, "falcon_preview_quarantine_actions", preview.Annotations)

	update := byName["falcon_update_quarantined_files"]
	if update == nil {
		t.Fatal("missing falcon_update_quarantined_files")
	}
	assertMutatingAnnotations(t, "falcon_update_quarantined_files", update.Annotations)

	del := byName["falcon_delete_quarantined_files"]
	if del == nil {
		t.Fatal("missing falcon_delete_quarantined_files")
	}
	assertDestructiveAnnotations(t, "falcon_delete_quarantined_files", del.Annotations, true)
}

// captureRegistrar adapts a func to base.Registrar for registration tests.
type captureRegistrar func(base.ToolEntry)

func (f captureRegistrar) Add(e base.ToolEntry) { f(e) }

func assertReadOnlyAnnotations(t *testing.T, name string, a *mcp.ToolAnnotations) {
	t.Helper()
	if a == nil {
		t.Fatalf("%s: annotations nil", name)
	}
	if !a.ReadOnlyHint {
		t.Errorf("%s: ReadOnlyHint = false, want true", name)
	}
	if a.DestructiveHint == nil || *a.DestructiveHint {
		t.Errorf("%s: DestructiveHint = %v, want non-nil false", name, a.DestructiveHint)
	}
}

func assertMutatingAnnotations(t *testing.T, name string, a *mcp.ToolAnnotations) {
	t.Helper()
	if a == nil {
		t.Fatalf("%s: annotations nil", name)
	}
	if a.ReadOnlyHint {
		t.Errorf("%s: ReadOnlyHint = true, want false", name)
	}
	if a.IdempotentHint {
		t.Errorf("%s: IdempotentHint = true, want false", name)
	}
	if a.DestructiveHint == nil || *a.DestructiveHint {
		t.Errorf("%s: DestructiveHint = %v, want non-nil false (MCP defaults omitted to true)", name, a.DestructiveHint)
	}
	if a.OpenWorldHint == nil || !*a.OpenWorldHint {
		t.Errorf("%s: OpenWorldHint = %v, want non-nil true", name, a.OpenWorldHint)
	}
}

func assertDestructiveAnnotations(t *testing.T, name string, a *mcp.ToolAnnotations, idempotent bool) {
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
