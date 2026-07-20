package ioc

import (
	"context"
	"errors"
	"log/slog"
	"testing"

	"github.com/crowdstrike/gofalcon/falcon/client/ioc"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/crowdstrike/falcon-mcp/internal/modules/base"
)

// testLogger discards output; modules require a non-nil logger.
var testLogger = slog.New(slog.DiscardHandler)

// fakeIoc is a configurable test double for the iocAPI interface.
type fakeIoc struct {
	searchResp *ioc.IndicatorCombinedV1OK
	searchErr  error
	createResp *ioc.IndicatorCreateV1Created
	createErr  error
	deleteResp *ioc.IndicatorDeleteV1OK
	deleteErr  error

	lastCreateBody *models.APIIndicatorCreateReqsV1
	lastDeleteIDs  []string
	lastDeleteReq  *ioc.IndicatorDeleteV1Params
}

func (f *fakeIoc) IndicatorCombinedV1(*ioc.IndicatorCombinedV1Params, ...ioc.ClientOption) (*ioc.IndicatorCombinedV1OK, error) {
	return f.searchResp, f.searchErr
}

func (f *fakeIoc) IndicatorCreateV1(p *ioc.IndicatorCreateV1Params, _ ...ioc.ClientOption) (*ioc.IndicatorCreateV1Created, error) {
	f.lastCreateBody = p.Body
	return f.createResp, f.createErr
}

func (f *fakeIoc) IndicatorDeleteV1(p *ioc.IndicatorDeleteV1Params, _ ...ioc.ClientOption) (*ioc.IndicatorDeleteV1OK, error) {
	f.lastDeleteIDs = p.Ids
	f.lastDeleteReq = p
	return f.deleteResp, f.deleteErr
}

func str(s string) *string { return &s }
func i32(v int32) *int32   { return &v }
func i64(v int64) *int64   { return &v }

func TestSearchIocsSuccess(t *testing.T) {
	t.Parallel()

	f := &fakeIoc{searchResp: &ioc.IndicatorCombinedV1OK{Payload: &models.APIIndicatorRespV1{
		Resources: []*models.APIIndicatorV1{{ID: "i1", Value: "evil.example"}},
		Meta:      &models.APIIndicatorsQueryMeta{Pagination: &models.APIIndicatorsQueryPaging{Total: i64(9), After: "cursor-next"}},
	}}}
	m := &Module{API: f, Logger: testLogger}

	_, out, err := m.searchIOCs(context.Background(), nil, SearchInput{Filter: "type:'domain'"})
	if err != nil {
		t.Fatalf("searchIOCs: %v", err)
	}
	if len(out.Resources) != 1 || out.FilterUsed != "type:'domain'" {
		t.Fatalf("unexpected result: %+v", out)
	}
	if out.Meta != any(f.searchResp.Payload.Meta) {
		t.Fatalf("Meta = %+v, want verbatim passthrough of the response meta", out.Meta)
	}
}

func TestSearchIocsEmpty(t *testing.T) {
	t.Parallel()

	f := &fakeIoc{searchResp: &ioc.IndicatorCombinedV1OK{Payload: &models.APIIndicatorRespV1{
		Resources: []*models.APIIndicatorV1{},
	}}}
	m := &Module{API: f, Logger: testLogger}

	_, out, err := m.searchIOCs(context.Background(), nil, SearchInput{})
	if err != nil {
		t.Fatalf("searchIOCs: %v", err)
	}
	if out.Resources == nil {
		t.Fatalf("expected non-nil empty slice, got %+v", out)
	}
	if out.Meta != nil {
		t.Fatalf("Meta = %+v, want nil when the response carries no meta", out.Meta)
	}
}

func TestSearchIocsFQLError(t *testing.T) {
	t.Parallel()

	badReq := &ioc.IndicatorCombinedV1BadRequest{Payload: &models.MsaspecResponseFields{
		Errors: []*models.MsaAPIError{{Code: i32(400), Message: str("invalid filter")}},
	}}
	f := &fakeIoc{searchErr: badReq}
	m := &Module{API: f, Logger: testLogger}

	_, out, err := m.searchIOCs(context.Background(), nil, SearchInput{Filter: "bogus"})
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

func TestSearchIocsAPIError(t *testing.T) {
	t.Parallel()

	f := &fakeIoc{searchErr: errors.New("boom")}
	m := &Module{API: f, Logger: testLogger}

	_, _, err := m.searchIOCs(context.Background(), nil, SearchInput{})
	if err == nil {
		t.Fatalf("expected non-FQL error to be returned")
	}
}

func TestAddIOCValidation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		in      AddInput
		wantErr bool
	}{
		{"missing type and value", AddInput{}, true},
		{"missing value", AddInput{Type: "domain"}, true},
		{"missing type", AddInput{Value: "evil.example"}, true},
		{"bad expiration", AddInput{Type: "domain", Value: "evil.example", Expiration: "not-a-date"}, true},
		{"valid single", AddInput{Type: "domain", Value: "evil.example"}, false},
		{"valid single with expiration", AddInput{Type: "domain", Value: "evil.example", Expiration: "2026-12-31T23:59:59Z"}, false},
		{"valid bulk", AddInput{Indicators: []*models.APIIndicatorCreateReqV1{{Type: "ipv4", Value: "1.2.3.4"}}}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := &fakeIoc{createResp: &ioc.IndicatorCreateV1Created{Payload: &models.APIIndicatorRespV1{}}}
			m := &Module{API: f, Logger: testLogger}
			_, _, err := m.addIOC(context.Background(), nil, tc.in)
			if tc.wantErr && !errors.Is(err, errInvalidInput) {
				t.Fatalf("expected errInvalidInput, got %v", err)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestAddIOCSingleBody(t *testing.T) {
	t.Parallel()

	f := &fakeIoc{createResp: &ioc.IndicatorCreateV1Created{Payload: &models.APIIndicatorRespV1{
		Resources: []*models.APIIndicatorV1{{ID: "new"}},
	}}}
	m := &Module{API: f, Logger: testLogger}

	_, out, err := m.addIOC(context.Background(), nil, AddInput{
		Type:     "sha256",
		Value:    "abc",
		Filename: "evil.exe",
		Comment:  "audit",
	})
	if err != nil {
		t.Fatalf("addIOC: %v", err)
	}
	if out.Total != 1 {
		t.Fatalf("expected created record returned, got %+v", out)
	}
	body := f.lastCreateBody
	if body.Comment != "audit" || len(body.Indicators) != 1 {
		t.Fatalf("unexpected body: %+v", body)
	}
	got := body.Indicators[0]
	if got.Type != "sha256" || got.Value != "abc" {
		t.Fatalf("unexpected indicator type/value: %+v", got)
	}
	if got.Action != defaultAction || got.Source != defaultSource {
		t.Fatalf("expected defaults action=%q source=%q, got action=%q source=%q", defaultAction, defaultSource, got.Action, got.Source)
	}
	if got.Metadata == nil || got.Metadata.Filename != "evil.exe" {
		t.Fatalf("expected filename merged into metadata, got %+v", got.Metadata)
	}
}

func TestAddIOCBulkTakesPrecedence(t *testing.T) {
	t.Parallel()

	f := &fakeIoc{createResp: &ioc.IndicatorCreateV1Created{Payload: &models.APIIndicatorRespV1{}}}
	m := &Module{API: f, Logger: testLogger}

	// Type/Value set but Indicators present: the bulk path wins and single
	// fields are ignored.
	_, _, err := m.addIOC(context.Background(), nil, AddInput{
		Type:       "domain",
		Value:      "ignored.example",
		Indicators: []*models.APIIndicatorCreateReqV1{{Type: "ipv4", Value: "1.2.3.4"}},
	})
	if err != nil {
		t.Fatalf("addIOC: %v", err)
	}
	body := f.lastCreateBody
	if len(body.Indicators) != 1 || body.Indicators[0].Value != "1.2.3.4" {
		t.Fatalf("expected bulk indicators to be sent verbatim, got %+v", body.Indicators)
	}
}

func TestRemoveIOCsValidation(t *testing.T) {
	t.Parallel()

	m := &Module{API: &fakeIoc{}, Logger: testLogger}
	_, _, err := m.removeIOCs(context.Background(), nil, RemoveInput{})
	if !errors.Is(err, errInvalidInput) {
		t.Fatalf("expected errInvalidInput, got %v", err)
	}
}

func TestRemoveIOCsSuccess(t *testing.T) {
	t.Parallel()

	f := &fakeIoc{deleteResp: &ioc.IndicatorDeleteV1OK{Payload: &models.APIIndicatorQueryRespV1{
		Resources: []string{"i1", "i2"},
	}}}
	m := &Module{API: f, Logger: testLogger}

	_, out, err := m.removeIOCs(context.Background(), nil, RemoveInput{IDs: []string{"i1", "i2"}, Comment: "cleanup"})
	if err != nil {
		t.Fatalf("removeIOCs: %v", err)
	}
	if out.Total != 2 || len(out.Resources) != 2 {
		t.Fatalf("expected 2 deleted ids, got %+v", out)
	}
	if len(f.lastDeleteIDs) != 2 {
		t.Fatalf("expected 2 ids passed, got %v", f.lastDeleteIDs)
	}
	if f.lastDeleteReq.Comment == nil || *f.lastDeleteReq.Comment != "cleanup" {
		t.Fatalf("expected comment passed through, got %v", f.lastDeleteReq.Comment)
	}
}

func TestRemoveIOCsByFilter(t *testing.T) {
	t.Parallel()

	f := &fakeIoc{deleteResp: &ioc.IndicatorDeleteV1OK{Payload: &models.APIIndicatorQueryRespV1{
		Resources: []string{"i1"},
	}}}
	m := &Module{API: f, Logger: testLogger}

	_, out, err := m.removeIOCs(context.Background(), nil, RemoveInput{Filter: "source:'mcp'"})
	if err != nil {
		t.Fatalf("removeIOCs: %v", err)
	}
	if out.Total != 1 {
		t.Fatalf("expected 1 deleted id, got %+v", out)
	}
	if f.lastDeleteReq.Filter == nil || *f.lastDeleteReq.Filter != "source:'mcp'" {
		t.Fatalf("expected filter passed through, got %v", f.lastDeleteReq.Filter)
	}
}

// TestRegisterResourcesServesFQLGuide verifies the IOC module publishes its FQL
// guide as the falcon://ioc/search/fql-guide resource, with the Python-matching
// name, and that reading it returns the embedded guide text.
func TestRegisterResourcesServesFQLGuide(t *testing.T) {
	t.Parallel()

	srv := mcp.NewServer(&mcp.Implementation{Name: "test", Version: "test"}, nil)
	(&Module{API: &fakeIoc{}, Logger: testLogger}).RegisterResources(srv)

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
	if got := list.Resources[0]; got.Name != "falcon_search_iocs_fql_guide" || got.URI != fqlGuideURI {
		t.Fatalf("resource = {name:%q uri:%q}, want falcon_search_iocs_fql_guide / %s", got.Name, got.URI, fqlGuideURI)
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
// annotations: search read-only, add_ioc mutating, remove_iocs destructive.
func TestRegisterToolsAnnotations(t *testing.T) {
	t.Parallel()

	var entries []base.ToolEntry
	reg := captureRegistrar(func(e base.ToolEntry) { entries = append(entries, e) })
	m := &Module{API: &fakeIoc{}, Logger: testLogger}
	m.RegisterTools(reg)

	byName := map[string]*mcp.Tool{}
	for _, e := range entries {
		byName[e.Tool.Name] = e.Tool
	}

	search := byName["falcon_search_iocs"]
	if search == nil {
		t.Fatal("missing falcon_search_iocs")
	}
	assertReadOnlyAnnotations(t, "falcon_search_iocs", search.Annotations)

	add := byName["falcon_add_ioc"]
	if add == nil {
		t.Fatal("missing falcon_add_ioc")
	}
	assertMutatingAnnotations(t, "falcon_add_ioc", add.Annotations)

	remove := byName["falcon_remove_iocs"]
	if remove == nil {
		t.Fatal("missing falcon_remove_iocs")
	}
	assertDestructiveAnnotations(t, "falcon_remove_iocs", remove.Annotations, true)
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
