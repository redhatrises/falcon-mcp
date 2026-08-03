package intel

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"reflect"
	"testing"

	"github.com/crowdstrike/gofalcon/falcon/client/intel"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/crowdstrike/falcon-mcp/internal/modules/base"
)

// testLogger discards output; modules require a non-nil logger.
var testLogger = slog.New(slog.DiscardHandler)

// fakeIntel is a configurable test double for the intelAPI interface.
type fakeIntel struct {
	actorsResp     *intel.QueryIntelActorEntitiesOK
	actorsErr      error
	indicatorsResp *intel.QueryIntelIndicatorEntitiesOK
	indicatorsErr  error
	reportsResp    *intel.QueryIntelReportEntitiesOK
	reportsErr     error
	mitreBody      []byte
	mitreErr       error

	lastActorsFilter string
	lastMitreActorID string
	lastMitreFormat  string
	actorsCalls      int
}

func (f *fakeIntel) QueryIntelActorEntities(p *intel.QueryIntelActorEntitiesParams, _ ...intel.ClientOption) (*intel.QueryIntelActorEntitiesOK, error) {
	f.actorsCalls++
	if p.Filter != nil {
		f.lastActorsFilter = *p.Filter
	}
	return f.actorsResp, f.actorsErr
}

func (f *fakeIntel) QueryIntelIndicatorEntities(*intel.QueryIntelIndicatorEntitiesParams, ...intel.ClientOption) (*intel.QueryIntelIndicatorEntitiesOK, error) {
	return f.indicatorsResp, f.indicatorsErr
}

func (f *fakeIntel) QueryIntelReportEntities(*intel.QueryIntelReportEntitiesParams, ...intel.ClientOption) (*intel.QueryIntelReportEntitiesOK, error) {
	return f.reportsResp, f.reportsErr
}

func (f *fakeIntel) GetMitreReport(p *intel.GetMitreReportParams, w io.Writer, _ ...intel.ClientOption) (*intel.GetMitreReportOK, error) {
	f.lastMitreActorID = p.ActorID
	f.lastMitreFormat = p.Format
	if f.mitreErr != nil {
		return nil, f.mitreErr
	}
	if _, err := w.Write(f.mitreBody); err != nil {
		return nil, err
	}
	return &intel.GetMitreReportOK{}, nil
}

func str(s string) *string { return &s }
func i32(v int32) *int32   { return &v }
func i64(v int64) *int64   { return &v }

func TestSearchActorsSuccess(t *testing.T) {
	t.Parallel()

	f := &fakeIntel{actorsResp: &intel.QueryIntelActorEntitiesOK{Payload: &models.ActorActorPaginatedResponse{
		Resources: []*models.ActorActorDocument{{ID: i64(2583), Name: "FANCY BEAR"}},
		Meta:      &models.MsaMetaInfo{Pagination: &models.MsaPaging{Total: i64(31)}},
	}}}
	m := &Module{API: f, Logger: testLogger}

	_, out, err := m.searchActors(context.Background(), nil, ActorsInput{Filter: "name:'FANCY BEAR'"})
	if err != nil {
		t.Fatalf("searchActors: %v", err)
	}
	if len(out.Resources) != 1 || out.FilterUsed != "name:'FANCY BEAR'" {
		t.Fatalf("unexpected result: %+v", out)
	}
	if !reflect.DeepEqual(out.Meta, base.NormalizedMeta(f.actorsResp.Payload.Meta)) {
		t.Fatalf("Meta = %+v, want verbatim passthrough of the response meta", out.Meta)
	}
}

func TestSearchActorsFQLError(t *testing.T) {
	t.Parallel()

	badReq := &intel.QueryIntelActorEntitiesBadRequest{Payload: &models.MsaErrorsOnly{
		Errors: []*models.MsaAPIError{{Code: i32(400), Message: str("invalid filter")}},
	}}
	f := &fakeIntel{actorsErr: badReq}
	m := &Module{API: f, Logger: testLogger}

	_, out, err := m.searchActors(context.Background(), nil, ActorsInput{Filter: "bogus"})
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

func TestSearchActorsAPIError(t *testing.T) {
	t.Parallel()

	f := &fakeIntel{actorsErr: errors.New("boom")}
	m := &Module{API: f, Logger: testLogger}

	_, _, err := m.searchActors(context.Background(), nil, ActorsInput{})
	if err == nil {
		t.Fatalf("expected non-FQL error to be returned")
	}
}

func TestSearchIndicatorsSuccess(t *testing.T) {
	t.Parallel()

	f := &fakeIntel{indicatorsResp: &intel.QueryIntelIndicatorEntitiesOK{Payload: &models.DomainPublicIndicatorsV3Response{
		Resources: []*models.DomainPublicIndicatorV3{{ID: str("domain_evil.example"), Indicator: str("evil.example")}},
		Meta:      &models.MsaMetaInfo{Pagination: &models.MsaPaging{Total: i64(88)}},
	}}}
	m := &Module{API: f, Logger: testLogger}

	_, out, err := m.searchIndicators(context.Background(), nil, IndicatorsInput{Filter: "type:'domain'", IncludeDeleted: true})
	if err != nil {
		t.Fatalf("searchIndicators: %v", err)
	}
	if out.FilterUsed != "type:'domain'" {
		t.Fatalf("unexpected result: %+v", out)
	}
	if !reflect.DeepEqual(out.Meta, base.NormalizedMeta(f.indicatorsResp.Payload.Meta)) {
		t.Fatalf("Meta = %+v, want verbatim passthrough of the response meta", out.Meta)
	}
}

func TestSearchIndicatorsFQLError(t *testing.T) {
	t.Parallel()

	badReq := &intel.QueryIntelIndicatorEntitiesBadRequest{Payload: &models.MsaErrorsOnly{
		Errors: []*models.MsaAPIError{{Code: i32(400), Message: str("bad indicator filter")}},
	}}
	f := &fakeIntel{indicatorsErr: badReq}
	m := &Module{API: f, Logger: testLogger}

	_, out, err := m.searchIndicators(context.Background(), nil, IndicatorsInput{Filter: "bogus"})
	if err != nil {
		t.Fatalf("expected FQL error formatted, not returned: %v", err)
	}
	if len(out.Errors) != 1 || out.Errors[0].Message != "bad indicator filter" {
		t.Fatalf("expected FQL error detail, got %+v", out.Errors)
	}
}

func TestSearchReportsSuccess(t *testing.T) {
	t.Parallel()

	f := &fakeIntel{reportsResp: &intel.QueryIntelReportEntitiesOK{Payload: &models.DomainNewsResponse{
		Resources: []*models.DomainNewsDocument{{ID: i64(42), Name: str("CSA-1")}},
		Meta:      &models.MsaMetaInfo{Pagination: &models.MsaPaging{Total: i64(7)}},
	}}}
	m := &Module{API: f, Logger: testLogger}

	_, out, err := m.searchReports(context.Background(), nil, ReportsInput{Filter: "type:'notice'"})
	if err != nil {
		t.Fatalf("searchReports: %v", err)
	}
	if out.FilterUsed != "type:'notice'" {
		t.Fatalf("unexpected result: %+v", out)
	}
	if !reflect.DeepEqual(out.Meta, base.NormalizedMeta(f.reportsResp.Payload.Meta)) {
		t.Fatalf("Meta = %+v, want verbatim passthrough of the response meta", out.Meta)
	}
}

// TestSearchReportsFQLError verifies the report 400 path: gofalcon's
// QueryIntelReportEntitiesBadRequest carries no payload, so the FQL-error
// response has no per-error details but still supplies the guide and hint.
func TestSearchReportsFQLError(t *testing.T) {
	t.Parallel()

	f := &fakeIntel{reportsErr: &intel.QueryIntelReportEntitiesBadRequest{}}
	m := &Module{API: f, Logger: testLogger}

	_, out, err := m.searchReports(context.Background(), nil, ReportsInput{Filter: "bogus"})
	if err != nil {
		t.Fatalf("expected FQL error formatted, not returned: %v", err)
	}
	if out.FQLGuide == "" || out.Hint == "" {
		t.Fatalf("expected fql_guide and hint populated, got %+v", out)
	}
	if out.FilterUsed != "bogus" {
		t.Fatalf("expected filter echoed, got %q", out.FilterUsed)
	}
}

func TestGetMitreReportNumericID(t *testing.T) {
	t.Parallel()

	f := &fakeIntel{mitreBody: []byte(`{"tactics":["TA0001"]}`)}
	m := &Module{API: f, Logger: testLogger}

	_, out, err := m.getMitreReport(context.Background(), nil, MitreInput{Actor: "236277", Format: "json"})
	if err != nil {
		t.Fatalf("getMitreReport: %v", err)
	}
	if f.actorsCalls != 0 {
		t.Fatalf("numeric ID must not trigger a name lookup, got %d calls", f.actorsCalls)
	}
	if out.ActorID != "236277" || f.lastMitreActorID != "236277" {
		t.Fatalf("expected actor ID passthrough, got %q / %q", out.ActorID, f.lastMitreActorID)
	}
	if string(out.Report) != `{"tactics":["TA0001"]}` {
		t.Fatalf("unexpected parsed report: %s", out.Report)
	}
}

func TestGetMitreReportNameResolution(t *testing.T) {
	t.Parallel()

	f := &fakeIntel{
		actorsResp: &intel.QueryIntelActorEntitiesOK{Payload: &models.ActorActorPaginatedResponse{
			Resources: []*models.ActorActorDocument{{ID: i64(2583), Name: "WARP PANDA"}},
		}},
		mitreBody: []byte(`{"ok":true}`),
	}
	m := &Module{API: f, Logger: testLogger}

	_, out, err := m.getMitreReport(context.Background(), nil, MitreInput{Actor: "WARP PANDA"})
	if err != nil {
		t.Fatalf("getMitreReport: %v", err)
	}
	if f.actorsCalls != 1 || f.lastActorsFilter != "name:'WARP PANDA'" {
		t.Fatalf("expected one name lookup on name:'WARP PANDA', got %d / %q", f.actorsCalls, f.lastActorsFilter)
	}
	if out.ActorID != "2583" || f.lastMitreActorID != "2583" {
		t.Fatalf("expected resolved ID 2583, got %q / %q", out.ActorID, f.lastMitreActorID)
	}
	if out.Format != "json" {
		t.Fatalf("expected default format json, got %q", out.Format)
	}
}

func TestGetMitreReportCSVRaw(t *testing.T) {
	t.Parallel()

	f := &fakeIntel{mitreBody: []byte("tactic,technique\nTA0001,T1566")}
	m := &Module{API: f, Logger: testLogger}

	_, out, err := m.getMitreReport(context.Background(), nil, MitreInput{Actor: "236277", Format: "CSV"})
	if err != nil {
		t.Fatalf("getMitreReport: %v", err)
	}
	if f.lastMitreFormat != "csv" {
		t.Fatalf("expected normalized format csv, got %q", f.lastMitreFormat)
	}
	if out.Raw != "tactic,technique\nTA0001,T1566" || out.Report != nil {
		t.Fatalf("expected raw CSV, got raw=%q report=%s", out.Raw, out.Report)
	}
}

func TestGetMitreReportEmptyJSON(t *testing.T) {
	t.Parallel()

	f := &fakeIntel{mitreBody: []byte("null")}
	m := &Module{API: f, Logger: testLogger}

	_, out, err := m.getMitreReport(context.Background(), nil, MitreInput{Actor: "1", Format: "json"})
	if err != nil {
		t.Fatalf("getMitreReport: %v", err)
	}
	if out.Report != nil {
		t.Fatalf("expected empty report for null body, got %s", out.Report)
	}
}

func TestGetMitreReportNotFound(t *testing.T) {
	t.Parallel()

	f := &fakeIntel{actorsResp: &intel.QueryIntelActorEntitiesOK{Payload: &models.ActorActorPaginatedResponse{
		Resources: []*models.ActorActorDocument{},
	}}}
	m := &Module{API: f, Logger: testLogger}

	_, _, err := m.getMitreReport(context.Background(), nil, MitreInput{Actor: "NOPE ACTOR"})
	if !errors.Is(err, errActorNotFound) {
		t.Fatalf("expected errActorNotFound, got %v", err)
	}
}

func TestGetMitreReportMissingID(t *testing.T) {
	t.Parallel()

	f := &fakeIntel{actorsResp: &intel.QueryIntelActorEntitiesOK{Payload: &models.ActorActorPaginatedResponse{
		Resources: []*models.ActorActorDocument{{Name: "NO ID"}},
	}}}
	m := &Module{API: f, Logger: testLogger}

	_, _, err := m.getMitreReport(context.Background(), nil, MitreInput{Actor: "NO ID"})
	if !errors.Is(err, errInvalidInput) {
		t.Fatalf("expected errInvalidInput, got %v", err)
	}
}

func TestGetMitreReportValidation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   MitreInput
	}{
		{"empty actor", MitreInput{Actor: "  "}},
		{"bad format", MitreInput{Actor: "1", Format: "xml"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			m := &Module{API: &fakeIntel{}, Logger: testLogger}
			_, _, err := m.getMitreReport(context.Background(), nil, tc.in)
			if !errors.Is(err, errInvalidInput) {
				t.Fatalf("expected errInvalidInput, got %v", err)
			}
		})
	}
}

// TestRegisterResourcesServesFQLGuides verifies the intel module publishes its
// three FQL guides as resources with the Python-matching names and URIs, and
// that reading each returns the embedded guide text.
func TestRegisterResourcesServesFQLGuides(t *testing.T) {
	t.Parallel()

	srv := mcp.NewServer(&mcp.Implementation{Name: "test", Version: "test"}, nil)
	(&Module{API: &fakeIntel{}, Logger: testLogger}).RegisterResources(srv)

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
	if len(list.Resources) != 3 {
		t.Fatalf("expected 3 resources, got %d", len(list.Resources))
	}

	want := map[string]string{
		actorsFQLGuideURI:     "falcon_search_actors_fql_guide",
		indicatorsFQLGuideURI: "falcon_search_indicators_fql_guide",
		reportsFQLGuideURI:    "falcon_search_reports_fql_guide",
	}
	byURI := map[string]string{}
	for _, r := range list.Resources {
		byURI[r.URI] = r.Name
	}
	for uri, name := range want {
		if byURI[uri] != name {
			t.Fatalf("resource %s = %q, want %q", uri, byURI[uri], name)
		}
		read, err := cs.ReadResource(ctx, &mcp.ReadResourceParams{URI: uri})
		if err != nil {
			t.Fatalf("ReadResource %s: %v", uri, err)
		}
		if len(read.Contents) != 1 || read.Contents[0].Text == "" {
			t.Fatalf("read content empty for %s", uri)
		}
	}
}

// TestRegisterToolsAnnotations verifies all four tools advertise read-only
// annotations (the intel module has no mutating tools).
func TestRegisterToolsAnnotations(t *testing.T) {
	t.Parallel()

	var entries []base.ToolEntry
	reg := captureRegistrar(func(e base.ToolEntry) { entries = append(entries, e) })
	m := &Module{API: &fakeIntel{}, Logger: testLogger}
	m.RegisterTools(reg)

	names := []string{
		"falcon_search_actors",
		"falcon_search_indicators",
		"falcon_search_reports",
		"falcon_get_mitre_report",
	}
	byName := map[string]*mcp.Tool{}
	for _, e := range entries {
		byName[e.Tool.Name] = e.Tool
	}
	if len(entries) != len(names) {
		t.Fatalf("expected %d tools, got %d", len(names), len(entries))
	}
	for _, n := range names {
		tool := byName[n]
		if tool == nil {
			t.Fatalf("missing %s", n)
		}
		assertReadOnlyAnnotations(t, n, tool.Annotations)
	}
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
