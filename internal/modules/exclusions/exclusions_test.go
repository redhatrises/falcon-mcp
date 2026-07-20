package exclusions

import (
	"context"
	"errors"
	"log/slog"
	"testing"

	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/crowdstrike/falcon-mcp/internal/modules/base"
)

// testLogger discards output; modules require a non-nil logger.
var testLogger = slog.New(slog.DiscardHandler)

// fakeBackend is a configurable test double for the backend interface. It
// records the last body/ids it received and returns canned raw bodies so handler
// behavior can be exercised without the gofalcon transport.
type fakeBackend struct {
	queryIDs  []string
	queryErr  error
	getBody   []byte
	getErr    error
	createRes []byte
	createErr error
	updateRes []byte
	updateErr error
	deleteErr error
	fqlDetail []base.FQLErrorDetail
	fqlOK     bool

	lastCreateBody any
	lastUpdateBody any
	lastDeleteIDs  []string
	lastComment    string
	lastQuery      queryArgs
	lastGetIDs     []string
}

func (f *fakeBackend) query(_ context.Context, a queryArgs) ([]string, error) {
	f.lastQuery = a
	return f.queryIDs, f.queryErr
}
func (f *fakeBackend) getRaw(_ context.Context, ids []string) ([]byte, error) {
	f.lastGetIDs = ids
	return f.getBody, f.getErr
}
func (f *fakeBackend) createRaw(_ context.Context, body any) ([]byte, error) {
	f.lastCreateBody = body
	return f.createRes, f.createErr
}
func (f *fakeBackend) updateRaw(_ context.Context, body any) ([]byte, error) {
	f.lastUpdateBody = body
	return f.updateRes, f.updateErr
}
func (f *fakeBackend) deleteByIDs(_ context.Context, ids []string, comment string) error {
	f.lastDeleteIDs = ids
	f.lastComment = comment
	return f.deleteErr
}
func (f *fakeBackend) classifyFQL(error) ([]base.FQLErrorDetail, bool) {
	return f.fqlDetail, f.fqlOK
}

// moduleWith builds a Module whose single named backend is fb.
func moduleWith(exclusionType string, fb backend) *Module {
	return &Module{
		backends: map[string]backend{exclusionType: fb},
		Logger:   testLogger,
	}
}

// ---- search --------------------------------------------------------------------

func TestSearchExclusionsSuccess(t *testing.T) {
	t.Parallel()
	fb := &fakeBackend{
		queryIDs: []string{"b", "a"},
		getBody:  []byte(`{"resources":[{"id":"a","value":"/x"},{"id":"b","value":"/y"}]}`),
	}
	m := moduleWith("ml", fb)

	_, out, err := m.searchExclusions(context.Background(), nil, SearchInput{ExclusionType: "ml", Filter: "applied_globally:true"})
	if err != nil {
		t.Fatalf("searchExclusions: %v", err)
	}
	if out.Total != 2 || out.FilterUsed != "applied_globally:true" {
		t.Fatalf("unexpected result: %+v", out)
	}
	// reorderByID should restore the query order [b, a].
	if out.Resources[0]["id"] != "b" || out.Resources[1]["id"] != "a" {
		t.Fatalf("expected query-order [b,a], got %v / %v", out.Resources[0]["id"], out.Resources[1]["id"])
	}
}

func TestSearchExclusionsEmpty(t *testing.T) {
	t.Parallel()
	fb := &fakeBackend{queryIDs: []string{}}
	m := moduleWith("ioa", fb)

	_, out, err := m.searchExclusions(context.Background(), nil, SearchInput{ExclusionType: "ioa"})
	if err != nil {
		t.Fatalf("searchExclusions: %v", err)
	}
	if out.Total != 0 || out.Resources == nil {
		t.Fatalf("expected non-nil empty slice, got %+v", out)
	}
	if len(fb.lastGetIDs) != 0 {
		t.Fatalf("expected no detail fetch on empty query, got %v", fb.lastGetIDs)
	}
}

func TestSearchExclusionsInvalidType(t *testing.T) {
	t.Parallel()
	m := moduleWith("ml", &fakeBackend{})
	_, _, err := m.searchExclusions(context.Background(), nil, SearchInput{ExclusionType: "bogus"})
	if !errors.Is(err, errInvalidInput) {
		t.Fatalf("expected errInvalidInput, got %v", err)
	}
}

func TestSearchExclusionsFQLError(t *testing.T) {
	t.Parallel()
	fb := &fakeBackend{
		queryErr:  errors.New("bad filter"),
		fqlDetail: []base.FQLErrorDetail{{Code: 400, Message: "invalid filter"}},
		fqlOK:     true,
	}
	m := moduleWith("certificate", fb)

	_, out, err := m.searchExclusions(context.Background(), nil, SearchInput{ExclusionType: "certificate", Filter: "bogus:'x'"})
	if err != nil {
		t.Fatalf("expected FQL error formatted, not returned: %v", err)
	}
	if len(out.Errors) != 1 || out.Errors[0].Message != "invalid filter" {
		t.Fatalf("expected FQL error detail, got %+v", out.Errors)
	}
	if out.FQLGuide == "" || out.Hint == "" {
		t.Fatalf("expected fql_guide and hint populated")
	}
}

func TestSearchExclusionsAPIError(t *testing.T) {
	t.Parallel()
	fb := &fakeBackend{queryErr: errors.New("boom")}
	m := moduleWith("ioa", fb)
	_, _, err := m.searchExclusions(context.Background(), nil, SearchInput{ExclusionType: "ioa"})
	if err == nil {
		t.Fatalf("expected non-FQL error returned")
	}
}

// TestSearchExclusionsClampAndSort verifies the query args the handler builds:
// certificate limit caps at 100, and ioa/ml/sensor_visibility get a .desc suffix
// appended to a bare sort while certificate is passed through unchanged.
func TestSearchExclusionsClampAndSort(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		typ       string
		limit     int
		sort      string
		wantLimit int64
		wantSort  string
	}{
		{"cert caps at 100", "certificate", 500, "", 100, ""},
		{"ml allows 500", "ml", 500, "", 500, ""},
		{"default limit 100", "ioa", 0, "", 100, ""},
		{"ioa bare sort gets .desc", "ioa", 10, "last_modified", 10, "last_modified.desc"},
		{"ml suffixed sort kept", "ml", 10, "created_on.asc", 10, "created_on.asc"},
		{"cert bare sort kept", "certificate", 10, "created_on", 10, "created_on"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			fb := &fakeBackend{queryIDs: []string{}}
			m := moduleWith(tc.typ, fb)
			_, _, err := m.searchExclusions(context.Background(), nil, SearchInput{ExclusionType: tc.typ, Limit: tc.limit, Sort: tc.sort})
			if err != nil {
				t.Fatalf("searchExclusions: %v", err)
			}
			if fb.lastQuery.limit != tc.wantLimit {
				t.Errorf("limit = %d, want %d", fb.lastQuery.limit, tc.wantLimit)
			}
			if fb.lastQuery.sort != tc.wantSort {
				t.Errorf("sort = %q, want %q", fb.lastQuery.sort, tc.wantSort)
			}
		})
	}
}

// ---- create / update -----------------------------------------------------------

func TestCreateExclusionInvalidType(t *testing.T) {
	t.Parallel()
	m := moduleWith("ml", &fakeBackend{})
	_, _, err := m.createExclusion(context.Background(), nil, MutateInput{ExclusionType: "bogus"})
	if !errors.Is(err, errInvalidInput) {
		t.Fatalf("expected errInvalidInput, got %v", err)
	}
}

func TestCreateExclusionSuccess(t *testing.T) {
	t.Parallel()
	fb := &fakeBackend{createRes: []byte(`{"resources":[{"id":"new","value":"/x"}]}`)}
	m := moduleWith("ml", fb)
	_, out, err := m.createExclusion(context.Background(), nil, MutateInput{ExclusionType: "ml", Value: "/x", HostGroups: []string{"g1"}})
	if err != nil {
		t.Fatalf("createExclusion: %v", err)
	}
	if out.Total != 1 || out.Resources[0]["id"] != "new" {
		t.Fatalf("expected created record, got %+v", out)
	}
	body, ok := fb.lastCreateBody.(*models.DomainExclusionsCreateReqV2)
	if !ok {
		t.Fatalf("expected ML create body, got %T", fb.lastCreateBody)
	}
	if len(body.Exclusions) != 1 || body.Exclusions[0].Value != "/x" || len(body.Exclusions[0].Groups) != 1 {
		t.Fatalf("unexpected ML create body: %+v", body.Exclusions[0])
	}
}

// TestCreateMLExclusionForwardsFlags verifies the ML create body carries
// applied_globally and is_descendant_process when the caller sets them (the
// gofalcon ML item models gained these fields in 7ccbeaf1), and leaves them
// false when the caller omits them.
func TestCreateMLExclusionForwardsFlags(t *testing.T) {
	t.Parallel()

	tru := true
	t.Run("forwards when set", func(t *testing.T) {
		t.Parallel()
		fb := &fakeBackend{createRes: []byte(`{"resources":[]}`)}
		m := moduleWith("ml", fb)
		_, _, err := m.createExclusion(context.Background(), nil, MutateInput{
			ExclusionType: "ml", Value: "/x",
			AppliedGlobally: &tru, IsDescendantProcess: &tru,
		})
		if err != nil {
			t.Fatal(err)
		}
		body, ok := fb.lastCreateBody.(*models.DomainExclusionsCreateReqV2)
		if !ok {
			t.Fatalf("expected ML create body, got %T", fb.lastCreateBody)
		}
		item := body.Exclusions[0]
		if !item.AppliedGlobally || !item.IsDescendantProcess {
			t.Fatalf("expected both flags true, got applied=%v descendant=%v", item.AppliedGlobally, item.IsDescendantProcess)
		}
	})

	t.Run("false when unset", func(t *testing.T) {
		t.Parallel()
		fb := &fakeBackend{createRes: []byte(`{"resources":[]}`)}
		m := moduleWith("ml", fb)
		_, _, err := m.createExclusion(context.Background(), nil, MutateInput{ExclusionType: "ml", Value: "/x"})
		if err != nil {
			t.Fatal(err)
		}
		body, ok := fb.lastCreateBody.(*models.DomainExclusionsCreateReqV2)
		if !ok {
			t.Fatalf("expected ML create body, got %T", fb.lastCreateBody)
		}
		item := body.Exclusions[0]
		if item.AppliedGlobally || item.IsDescendantProcess {
			t.Fatalf("expected both flags false when unset, got applied=%v descendant=%v", item.AppliedGlobally, item.IsDescendantProcess)
		}
	})

	t.Run("update forwards flags on singular body", func(t *testing.T) {
		t.Parallel()
		fb := &fakeBackend{updateRes: []byte(`{"resources":[]}`)}
		m := moduleWith("ml", fb)
		_, _, err := m.updateExclusion(context.Background(), nil, MutateInput{
			ExclusionType: "ml", ID: "e1", Value: "/x",
			AppliedGlobally: &tru, IsDescendantProcess: &tru,
		})
		if err != nil {
			t.Fatal(err)
		}
		item, ok := fb.lastUpdateBody.(*models.DomainExclusionUpdateReqV2)
		if !ok {
			t.Fatalf("expected singular ML update body, got %T", fb.lastUpdateBody)
		}
		if !item.AppliedGlobally || !item.IsDescendantProcess {
			t.Fatalf("expected both flags true on update, got applied=%v descendant=%v", item.AppliedGlobally, item.IsDescendantProcess)
		}
	})
}

func TestUpdateExclusionRequiresID(t *testing.T) {
	t.Parallel()
	m := moduleWith("ml", &fakeBackend{})
	_, _, err := m.updateExclusion(context.Background(), nil, MutateInput{ExclusionType: "ml", Value: "/x"})
	if !errors.Is(err, errInvalidInput) {
		t.Fatalf("expected errInvalidInput for missing id, got %v", err)
	}
}

// TestUpdateExclusionMLSingularBody verifies the ML update body is the singular
// DomainExclusionUpdateReqV2 (not the wrapped create shape) and carries the id.
func TestUpdateExclusionMLSingularBody(t *testing.T) {
	t.Parallel()
	fb := &fakeBackend{updateRes: []byte(`{"resources":[{"id":"e1"}]}`)}
	m := moduleWith("ml", fb)
	_, _, err := m.updateExclusion(context.Background(), nil, MutateInput{ExclusionType: "ml", ID: "e1", Value: "/x"})
	if err != nil {
		t.Fatalf("updateExclusion: %v", err)
	}
	body, ok := fb.lastUpdateBody.(*models.DomainExclusionUpdateReqV2)
	if !ok {
		t.Fatalf("expected singular ML update body, got %T", fb.lastUpdateBody)
	}
	if body.ID == nil || *body.ID != "e1" || body.Value != "/x" {
		t.Fatalf("unexpected ML update body: %+v", body)
	}
}

// TestCreateExclusionValidation covers the per-type required-field validation
// (the negative security cases: missing/invalid input must be rejected before
// any API call).
func TestCreateExclusionValidation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		in      MutateInput
		wantErr bool
	}{
		// IOA
		{"ioa missing fields", MutateInput{ExclusionType: "ioa", Name: "n"}, true},
		{"ioa catch-all regex", MutateInput{ExclusionType: "ioa", Name: "n", PatternID: "1", IfnRegex: ".*", ClRegex: ".*"}, true},
		{"ioa valid", MutateInput{ExclusionType: "ioa", Name: "n", PatternID: "1", IfnRegex: "a", ClRegex: "b"}, false},
		// ML
		{"ml missing value", MutateInput{ExclusionType: "ml"}, true},
		{"ml valid", MutateInput{ExclusionType: "ml", Value: "/x"}, false},
		// SV
		{"sv missing value", MutateInput{ExclusionType: "sensor_visibility", HostGroups: []string{"g1"}}, true},
		{"sv missing host_groups", MutateInput{ExclusionType: "sensor_visibility", Value: "/x"}, true},
		{"sv valid", MutateInput{ExclusionType: "sensor_visibility", Value: "/x", HostGroups: []string{"g1"}}, false},
		// Certificate
		{"cert missing certificate", MutateInput{ExclusionType: "certificate", Name: "n", Status: "enabled"}, true},
		{"cert bad status", MutateInput{ExclusionType: "certificate", Name: "n", Certificate: &Certificate{Issuer: "i"}, Status: "on"}, true},
		{"cert valid", MutateInput{ExclusionType: "certificate", Name: "n", Certificate: &Certificate{Issuer: "i"}, Status: "enabled"}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			fb := &fakeBackend{createRes: []byte(`{"resources":[]}`)}
			m := moduleWith(tc.in.ExclusionType, fb)
			_, _, err := m.createExclusion(context.Background(), nil, tc.in)
			if tc.wantErr && !errors.Is(err, errInvalidInput) {
				t.Fatalf("expected errInvalidInput, got %v", err)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

// TestCreateExclusionBodyShapes verifies each type produces the correct gofalcon
// body type: IOA/CB wrapped, ML wrapped-create, SV flat.
func TestCreateExclusionBodyShapes(t *testing.T) {
	t.Parallel()

	t.Run("ioa wrapped", func(t *testing.T) {
		t.Parallel()
		fb := &fakeBackend{createRes: []byte(`{"resources":[]}`)}
		m := moduleWith("ioa", fb)
		_, _, err := m.createExclusion(context.Background(), nil, MutateInput{ExclusionType: "ioa", Name: "n", PatternID: "1", IfnRegex: "a", ClRegex: "b", HostGroups: []string{"g1"}})
		if err != nil {
			t.Fatal(err)
		}
		body, ok := fb.lastCreateBody.(*models.DomainSsIoaExclusionsCreateReqV2)
		if !ok || len(body.Exclusions) != 1 {
			t.Fatalf("expected IOA wrapped body, got %T", fb.lastCreateBody)
		}
		if got := body.Exclusions[0]; got.Name == nil || *got.Name != "n" || len(got.HostGroups) != 1 {
			t.Fatalf("unexpected IOA item: %+v", got)
		}
	})

	t.Run("sv flat", func(t *testing.T) {
		t.Parallel()
		fb := &fakeBackend{createRes: []byte(`{"resources":[]}`)}
		m := moduleWith("sensor_visibility", fb)
		_, _, err := m.createExclusion(context.Background(), nil, MutateInput{ExclusionType: "sensor_visibility", Value: "/x", HostGroups: []string{"g1"}})
		if err != nil {
			t.Fatal(err)
		}
		body, ok := fb.lastCreateBody.(*models.SvExclusionsCreateReqV1)
		if !ok {
			t.Fatalf("expected SV flat body, got %T", fb.lastCreateBody)
		}
		if body.Value != "/x" || len(body.Groups) != 1 {
			t.Fatalf("unexpected SV body: %+v", body)
		}
	})

	t.Run("certificate wrapped with timestamps", func(t *testing.T) {
		t.Parallel()
		fb := &fakeBackend{createRes: []byte(`{"resources":[]}`)}
		m := moduleWith("certificate", fb)
		_, _, err := m.createExclusion(context.Background(), nil, MutateInput{
			ExclusionType: "certificate", Name: "n", Status: "enabled",
			Certificate: &Certificate{Issuer: "i", Subject: "s", Serial: "1", Thumbprint: "tp", ValidFrom: "2024-01-02T15:04:05Z", ValidTo: "2025-01-02T15:04:05Z"},
		})
		if err != nil {
			t.Fatal(err)
		}
		body, ok := fb.lastCreateBody.(*models.APICertBasedExclusionsCreateReqV1)
		if !ok || len(body.Exclusions) != 1 {
			t.Fatalf("expected CB wrapped body, got %T", fb.lastCreateBody)
		}
		item := body.Exclusions[0]
		if item.Certificate == nil || item.Certificate.ValidFrom == nil || item.Certificate.ValidTo == nil {
			t.Fatalf("expected parsed certificate timestamps, got %+v", item.Certificate)
		}
	})

	t.Run("certificate bad timestamp rejected", func(t *testing.T) {
		t.Parallel()
		m := moduleWith("certificate", &fakeBackend{})
		_, _, err := m.createExclusion(context.Background(), nil, MutateInput{
			ExclusionType: "certificate", Name: "n", Status: "enabled",
			Certificate: &Certificate{Issuer: "i", ValidFrom: "not-a-date"},
		})
		if !errors.Is(err, errInvalidInput) {
			t.Fatalf("expected errInvalidInput for bad timestamp, got %v", err)
		}
	})
}

// ---- delete --------------------------------------------------------------------

func TestDeleteExclusions(t *testing.T) {
	t.Parallel()

	t.Run("invalid type", func(t *testing.T) {
		t.Parallel()
		m := moduleWith("ml", &fakeBackend{})
		_, _, err := m.deleteExclusions(context.Background(), nil, DeleteInput{ExclusionType: "bogus", IDs: []string{"a"}})
		if !errors.Is(err, errInvalidInput) {
			t.Fatalf("expected errInvalidInput, got %v", err)
		}
	})

	t.Run("empty ids", func(t *testing.T) {
		t.Parallel()
		m := moduleWith("ml", &fakeBackend{})
		_, _, err := m.deleteExclusions(context.Background(), nil, DeleteInput{ExclusionType: "ml"})
		if !errors.Is(err, errInvalidInput) {
			t.Fatalf("expected errInvalidInput, got %v", err)
		}
	})

	t.Run("success passes ids and comment", func(t *testing.T) {
		t.Parallel()
		fb := &fakeBackend{}
		m := moduleWith("ml", fb)
		_, out, err := m.deleteExclusions(context.Background(), nil, DeleteInput{ExclusionType: "ml", IDs: []string{"a", "b"}, Comment: "cleanup"})
		if err != nil {
			t.Fatalf("deleteExclusions: %v", err)
		}
		if !out.Ok {
			t.Fatalf("expected Ok, got %+v", out)
		}
		if len(fb.lastDeleteIDs) != 2 || fb.lastComment != "cleanup" {
			t.Fatalf("unexpected delete args: ids=%v comment=%q", fb.lastDeleteIDs, fb.lastComment)
		}
	})

	t.Run("api error surfaced", func(t *testing.T) {
		t.Parallel()
		fb := &fakeBackend{deleteErr: errors.New("boom")}
		m := moduleWith("ml", fb)
		_, _, err := m.deleteExclusions(context.Background(), nil, DeleteInput{ExclusionType: "ml", IDs: []string{"a"}})
		if err == nil {
			t.Fatalf("expected API error surfaced")
		}
	})
}

// ---- get_certificate_details ---------------------------------------------------

func TestGetCertificateDetailsRequiresHash(t *testing.T) {
	t.Parallel()
	m := &Module{backends: map[string]backend{}, Logger: testLogger}
	_, _, err := m.getCertificateDetails(context.Background(), nil, CertDetailsInput{})
	if !errors.Is(err, errInvalidInput) {
		t.Fatalf("expected errInvalidInput, got %v", err)
	}
}

// ---- helpers -------------------------------------------------------------------

func TestDecodeResources(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		body string
		want int
	}{
		{"empty body", "", 0},
		{"null resources", `{"resources":null}`, 0},
		{"two records", `{"resources":[{"id":"a"},{"id":"b"}]}`, 2},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := decodeResources([]byte(tc.body))
			if err != nil {
				t.Fatalf("decodeResources: %v", err)
			}
			if len(got) != tc.want {
				t.Fatalf("got %d records, want %d", len(got), tc.want)
			}
			if got == nil {
				t.Fatalf("expected non-nil slice")
			}
		})
	}
}

func TestReorderByID(t *testing.T) {
	t.Parallel()
	records := []map[string]any{{"id": "a"}, {"id": "b"}, {"id": "c"}}
	got := reorderByID([]string{"c", "a", "b"}, records)
	if got[0]["id"] != "c" || got[1]["id"] != "a" || got[2]["id"] != "b" {
		t.Fatalf("unexpected order: %v", got)
	}

	// A record with no id is preserved (appended), never dropped.
	withUnkeyed := []map[string]any{{"id": "a"}, {"value": "no-id"}}
	got = reorderByID([]string{"a"}, withUnkeyed)
	if len(got) != 2 {
		t.Fatalf("expected unkeyed record preserved, got %v", got)
	}
}

func TestNormalizeSort(t *testing.T) {
	t.Parallel()
	tests := []struct {
		typ, in, want string
	}{
		{"ioa", "last_modified", "last_modified.desc"},
		{"ml", "created_on.asc", "created_on.asc"},
		{"sensor_visibility", "value|desc", "value|desc"},
		{"certificate", "created_on", "created_on"},
		{"ioa", "", ""},
	}
	for _, tc := range tests {
		if got := normalizeSort(tc.typ, tc.in); got != tc.want {
			t.Errorf("normalizeSort(%q, %q) = %q, want %q", tc.typ, tc.in, got, tc.want)
		}
	}
}

// ---- registration --------------------------------------------------------------

// TestRegisterToolsAnnotations verifies mutator tools set complete annotations so
// DestructiveHint is never left nil (MCP default true), and that the two
// read-only tools default to read-only.
func TestRegisterToolsAnnotations(t *testing.T) {
	t.Parallel()

	var entries []base.ToolEntry
	reg := captureRegistrar(func(e base.ToolEntry) { entries = append(entries, e) })
	m := &Module{backends: map[string]backend{}, Logger: testLogger}
	m.RegisterTools(reg)

	byName := map[string]*mcp.Tool{}
	for _, e := range entries {
		byName[e.Tool.Name] = e.Tool
	}

	for _, name := range []string{"falcon_create_exclusion", "falcon_update_exclusion"} {
		tool := byName[name]
		if tool == nil {
			t.Fatalf("missing tool %s", name)
		}
		assertMutatingAnnotations(t, name, tool.Annotations)
	}

	del := byName["falcon_delete_exclusions"]
	if del == nil {
		t.Fatal("missing falcon_delete_exclusions")
	}
	assertDestructiveAnnotations(t, "falcon_delete_exclusions", del.Annotations, true)

	for _, name := range []string{"falcon_search_exclusions", "falcon_get_certificate_details"} {
		tool := byName[name]
		if tool == nil {
			t.Fatalf("missing tool %s", name)
		}
		if tool.Annotations == nil || !tool.Annotations.ReadOnlyHint {
			t.Errorf("%s: expected read-only annotation", name)
		}
	}
}

// TestRegisterResourcesServesFQLGuide verifies the exclusions module publishes its
// FQL guide as the falcon://exclusions/search/fql-guide resource with the
// Python-matching name.
func TestRegisterResourcesServesFQLGuide(t *testing.T) {
	t.Parallel()

	srv := mcp.NewServer(&mcp.Implementation{Name: "test", Version: "test"}, nil)
	(&Module{backends: map[string]backend{}, Logger: testLogger}).RegisterResources(srv)

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
	if got := list.Resources[0]; got.Name != "falcon_search_exclusions_fql_guide" || got.URI != fqlGuideURI {
		t.Fatalf("resource = {name:%q uri:%q}, want falcon_search_exclusions_fql_guide / %s", got.Name, got.URI, fqlGuideURI)
	}

	read, err := cs.ReadResource(ctx, &mcp.ReadResourceParams{URI: fqlGuideURI})
	if err != nil {
		t.Fatalf("ReadResource: %v", err)
	}
	if len(read.Contents) != 1 || read.Contents[0].Text != fqlGuide {
		t.Fatalf("read content does not match embedded guide")
	}
}

// captureRegistrar adapts a func to base.Registrar for registration tests.
type captureRegistrar func(base.ToolEntry)

func (f captureRegistrar) Add(e base.ToolEntry) { f(e) }

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
		t.Errorf("%s: DestructiveHint = %v, want non-nil false", name, a.DestructiveHint)
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
