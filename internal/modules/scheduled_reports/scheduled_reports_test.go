package scheduledreports

import (
	"context"
	"errors"
	"io"
	"reflect"
	"strings"
	"testing"

	"github.com/crowdstrike/gofalcon/falcon/client/report_executions"
	"github.com/crowdstrike/gofalcon/falcon/client/scheduled_reports"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/go-openapi/runtime"

	"github.com/crowdstrike/falcon-mcp/internal/modules/base"
	"github.com/crowdstrike/falcon-mcp/internal/testutil"
)

// metaQueryTime is a non-zero query_time for test fakes, so a handler's
// normalized meta is a populated value rather than nil.
var metaQueryTime = 0.02

var testLogger = testutil.DiscardLogger()

// fakeReports is a configurable double for the reportsAPI interface. Each
// operation records its call count/inputs and returns the preconfigured
// response/error.
type fakeReports struct {
	queryResp *scheduled_reports.QueryOK
	queryErr  error

	getResp  *scheduled_reports.QueryByIDOK
	getCalls int
	getIDs   []string

	execResp  *scheduled_reports.ExecuteOK
	execErr   error
	execBody  []*models.DomainReportExecutionLaunchRequestV1
	execCalls int
}

func (f *fakeReports) Query(*scheduled_reports.QueryParams, ...scheduled_reports.ClientOption) (*scheduled_reports.QueryOK, error) {
	return f.queryResp, f.queryErr
}

func (f *fakeReports) QueryByID(p *scheduled_reports.QueryByIDParams, _ ...scheduled_reports.ClientOption) (*scheduled_reports.QueryByIDOK, error) {
	f.getCalls++
	f.getIDs = p.Ids
	return f.getResp, nil
}

func (f *fakeReports) Execute(p *scheduled_reports.ExecuteParams, _ ...scheduled_reports.ClientOption) (*scheduled_reports.ExecuteOK, error) {
	f.execCalls++
	f.execBody = p.Body
	return f.execResp, f.execErr
}

// fakeExecutions is a configurable double for the executionsAPI interface.
type fakeExecutions struct {
	queryResp *report_executions.ReportExecutionsQueryOK
	queryErr  error

	getResp  *report_executions.ReportExecutionsGetOK
	getCalls int
	getIDs   []string

	dlPayload *downloadPayload
	dlErr     error
	dlIDs     string
	dlCalls   int
}

func (f *fakeExecutions) ReportExecutionsQuery(*report_executions.ReportExecutionsQueryParams, ...report_executions.ClientOption) (*report_executions.ReportExecutionsQueryOK, error) {
	return f.queryResp, f.queryErr
}

func (f *fakeExecutions) ReportExecutionsGet(p *report_executions.ReportExecutionsGetParams, _ ...report_executions.ClientOption) (*report_executions.ReportExecutionsGetOK, error) {
	f.getCalls++
	f.getIDs = p.Ids
	return f.getResp, nil
}

func (f *fakeExecutions) ReportExecutionsDownloadGet(p *report_executions.ReportExecutionsDownloadGetParams, _ ...report_executions.ClientOption) (*downloadPayload, error) {
	f.dlCalls++
	f.dlIDs = p.Ids
	return f.dlPayload, f.dlErr
}

func newModule(r *fakeReports, e *fakeExecutions) *Module {
	return &Module{Reports: r, Executions: e, Concurrency: 4, Logger: testLogger}
}

// --- search_scheduled_reports ---

func TestSearchScheduledReportsSuccess(t *testing.T) {
	t.Parallel()

	r := &fakeReports{
		queryResp: &scheduled_reports.QueryOK{Payload: &models.MsaQueryResponse{
			Resources: []string{"r1", "r2"},
			Meta:      &models.MsaMetaInfo{QueryTime: &metaQueryTime},
		}},
		getResp: &scheduled_reports.QueryByIDOK{Payload: &models.DomainScheduledReportsResultV1{
			// Returned out of query order to exercise reordering by id.
			Resources: []*models.DomainScheduledReportV1{
				{ID: new("r2")},
				{ID: new("r1")},
			},
		}},
	}
	m := newModule(r, &fakeExecutions{})

	_, out, err := m.searchScheduledReports(context.Background(), nil, SearchReportsInput{Filter: "status:'ACTIVE'"})
	if err != nil {
		t.Fatalf("searchScheduledReports: %v", err)
	}
	if len(out.Resources) != 2 {
		t.Fatalf("expected 2 results, got %+v", out)
	}
	if *out.Resources[0].ID != "r1" || *out.Resources[1].ID != "r2" {
		t.Fatalf("results not reordered to query order: %q, %q", *out.Resources[0].ID, *out.Resources[1].ID)
	}
	if out.FilterUsed != "status:'ACTIVE'" {
		t.Fatalf("filter_used = %q", out.FilterUsed)
	}
	if r.getCalls != 1 {
		t.Fatalf("expected 1 detail fetch, got %d", r.getCalls)
	}
	if strings.Join(r.getIDs, ",") != "r1,r2" {
		t.Fatalf("detail fetch got IDs %v", r.getIDs)
	}
	if !reflect.DeepEqual(out.Meta, base.NormalizedMeta(r.queryResp.Payload.Meta)) {
		t.Fatalf("expected normalized meta, got %+v", out.Meta)
	}
}

func TestSearchScheduledReportsEmpty(t *testing.T) {
	t.Parallel()

	r := &fakeReports{queryResp: &scheduled_reports.QueryOK{Payload: &models.MsaQueryResponse{Resources: []string{}}}}
	m := newModule(r, &fakeExecutions{})

	_, out, err := m.searchScheduledReports(context.Background(), nil, SearchReportsInput{Filter: "status:'ACTIVE'"})
	if err != nil {
		t.Fatalf("searchScheduledReports: %v", err)
	}
	if len(out.Resources) != 0 {
		t.Fatalf("expected empty result, got %+v", out)
	}
	if out.Resources == nil {
		t.Fatal("resources must be a non-nil empty slice for stable JSON array output")
	}
	if r.getCalls != 0 {
		t.Fatalf("expected no detail fetch on empty result, got %d", r.getCalls)
	}
}

func TestSearchScheduledReportsFQLError(t *testing.T) {
	t.Parallel()

	badReq := &scheduled_reports.QueryBadRequest{Payload: &models.MsaReplyMetaOnly{
		Errors: []*models.MsaAPIError{{Code: new(int32(400)), Message: new("invalid filter")}},
	}}
	r := &fakeReports{queryErr: badReq}
	m := newModule(r, &fakeExecutions{})

	_, out, err := m.searchScheduledReports(context.Background(), nil, SearchReportsInput{Filter: "bogus:'x'"})
	if err != nil {
		t.Fatalf("FQL error should be a data result, not a Go error: %v", err)
	}
	if len(out.Errors) != 1 || out.Errors[0].Message != "invalid filter" {
		t.Fatalf("expected FQL error detail, got %+v", out.Errors)
	}
	if out.FQLGuide == "" {
		t.Fatal("expected fql_guide to be populated on FQL error")
	}
	if r.getCalls != 0 {
		t.Fatalf("expected no detail fetch on FQL error, got %d", r.getCalls)
	}
}

func TestSearchScheduledReportsAPIError(t *testing.T) {
	t.Parallel()

	r := &fakeReports{queryErr: errors.New("boom")}
	m := newModule(r, &fakeExecutions{})

	_, _, err := m.searchScheduledReports(context.Background(), nil, SearchReportsInput{})
	if err == nil {
		t.Fatal("expected a Go error for a non-FQL transport failure")
	}
}

// --- launch_scheduled_report ---

func TestLaunchScheduledReportSuccess(t *testing.T) {
	t.Parallel()

	r := &fakeReports{execResp: &scheduled_reports.ExecuteOK{Payload: &models.DomainReportExecutionsResponseV1{
		Resources: []*models.DomainReportExecutionV1{{ID: new("exec1")}},
		Meta:      &models.MsaMetaInfo{QueryTime: &metaQueryTime},
	}}}
	m := newModule(r, &fakeExecutions{})

	_, out, err := m.launchScheduledReport(context.Background(), nil, LaunchInput{ID: "report1"})
	if err != nil {
		t.Fatalf("launchScheduledReport: %v", err)
	}
	if out.Total != 1 || *out.Resources[0].ID != "exec1" {
		t.Fatalf("unexpected result %+v", out)
	}
	if r.execCalls != 1 {
		t.Fatalf("expected 1 execute call, got %d", r.execCalls)
	}
	// The Execute body must be a list of {id} objects preserving the entity ID.
	if len(r.execBody) != 1 || r.execBody[0].ID == nil || *r.execBody[0].ID != "report1" {
		t.Fatalf("execute body not shaped as [{id}]: %+v", r.execBody)
	}
	if !reflect.DeepEqual(out.Meta, base.NormalizedMeta(r.execResp.Payload.Meta)) {
		t.Fatalf("expected normalized meta, got %+v", out.Meta)
	}
}

func TestLaunchScheduledReportRequiresID(t *testing.T) {
	t.Parallel()

	r := &fakeReports{}
	m := newModule(r, &fakeExecutions{})

	_, _, err := m.launchScheduledReport(context.Background(), nil, LaunchInput{ID: "  "})
	if !errors.Is(err, errInvalidInput) {
		t.Fatalf("expected errInvalidInput for blank id, got %v", err)
	}
	if r.execCalls != 0 {
		t.Fatalf("expected no execute call for blank id, got %d", r.execCalls)
	}
}

// --- search_report_executions ---

func TestSearchReportExecutionsSuccess(t *testing.T) {
	t.Parallel()

	e := &fakeExecutions{
		queryResp: &report_executions.ReportExecutionsQueryOK{Payload: &models.MsaQueryResponse{
			Resources: []string{"e1", "e2"},
			Meta:      &models.MsaMetaInfo{QueryTime: &metaQueryTime},
		}},
		getResp: &report_executions.ReportExecutionsGetOK{Payload: &models.DomainReportExecutionsResponseV1{
			Resources: []*models.DomainReportExecutionV1{
				{ID: new("e2")},
				{ID: new("e1")},
			},
		}},
	}
	m := newModule(&fakeReports{}, e)

	_, out, err := m.searchReportExecutions(context.Background(), nil, SearchExecutionsInput{Filter: "status:'DONE'"})
	if err != nil {
		t.Fatalf("searchReportExecutions: %v", err)
	}
	if len(out.Resources) != 2 || *out.Resources[0].ID != "e1" || *out.Resources[1].ID != "e2" {
		t.Fatalf("unexpected/misordered result %+v", out)
	}
	if e.getCalls != 1 {
		t.Fatalf("expected 1 detail fetch, got %d", e.getCalls)
	}
	if !reflect.DeepEqual(out.Meta, base.NormalizedMeta(e.queryResp.Payload.Meta)) {
		t.Fatalf("expected normalized meta, got %+v", out.Meta)
	}
}

func TestSearchReportExecutionsEmpty(t *testing.T) {
	t.Parallel()

	e := &fakeExecutions{queryResp: &report_executions.ReportExecutionsQueryOK{Payload: &models.MsaQueryResponse{Resources: []string{}}}}
	m := newModule(&fakeReports{}, e)

	_, out, err := m.searchReportExecutions(context.Background(), nil, SearchExecutionsInput{})
	if err != nil {
		t.Fatalf("searchReportExecutions: %v", err)
	}
	if len(out.Resources) != 0 || out.Resources == nil {
		t.Fatalf("expected non-nil empty result, got %+v", out)
	}
	if e.getCalls != 0 {
		t.Fatalf("expected no detail fetch on empty result, got %d", e.getCalls)
	}
}

func TestSearchReportExecutionsAPIError(t *testing.T) {
	t.Parallel()

	e := &fakeExecutions{queryErr: errors.New("boom")}
	m := newModule(&fakeReports{}, e)

	_, _, err := m.searchReportExecutions(context.Background(), nil, SearchExecutionsInput{})
	if err == nil {
		t.Fatal("expected a Go error for a non-FQL transport failure")
	}
	if e.getCalls != 0 {
		t.Fatalf("expected no detail fetch after a query error, got %d", e.getCalls)
	}
}

func TestSearchReportExecutionsFQLError(t *testing.T) {
	t.Parallel()

	badReq := &report_executions.ReportExecutionsQueryBadRequest{Payload: &models.MsaReplyMetaOnly{
		Errors: []*models.MsaAPIError{{Code: new(int32(400)), Message: new("bad execution filter")}},
	}}
	e := &fakeExecutions{queryErr: badReq}
	m := newModule(&fakeReports{}, e)

	_, out, err := m.searchReportExecutions(context.Background(), nil, SearchExecutionsInput{Filter: "bogus:'x'"})
	if err != nil {
		t.Fatalf("FQL error should be a data result, not a Go error: %v", err)
	}
	if len(out.Errors) != 1 || out.Errors[0].Message != "bad execution filter" {
		t.Fatalf("expected FQL error detail, got %+v", out.Errors)
	}
	if e.getCalls != 0 {
		t.Fatalf("expected no detail fetch on FQL error, got %d", e.getCalls)
	}
}

// --- download_report_execution ---

func TestDownloadReportExecutionCSV(t *testing.T) {
	t.Parallel()

	e := &fakeExecutions{dlPayload: &downloadPayload{
		Body:        []byte("id,name\n1,alpha\n"),
		ContentType: "text/csv",
	}}
	m := newModule(&fakeReports{}, e)

	_, out, err := m.downloadReportExecution(context.Background(), nil, DownloadInput{ID: "exec1"})
	if err != nil {
		t.Fatalf("downloadReportExecution: %v", err)
	}
	if out.Format != "csv" {
		t.Fatalf("expected csv format, got %q", out.Format)
	}
	if out.Raw != "id,name\n1,alpha\n" {
		t.Fatalf("csv body not returned verbatim: %q", out.Raw)
	}
	if e.dlIDs != "exec1" {
		t.Fatalf("download called with ids %q", e.dlIDs)
	}
}

func TestDownloadReportExecutionJSON(t *testing.T) {
	t.Parallel()

	// The live download endpoint returns the report rows as a bare top-level
	// JSON array, not a {"resources": [...]} envelope (verified against a real
	// tenant). The handler must pass that array through verbatim.
	e := &fakeExecutions{dlPayload: &downloadPayload{
		Body:        []byte(`[{"a":1},{"a":2}]`),
		ContentType: "application/json; charset=utf-8",
	}}
	m := newModule(&fakeReports{}, e)

	_, out, err := m.downloadReportExecution(context.Background(), nil, DownloadInput{ID: "exec1"})
	if err != nil {
		t.Fatalf("downloadReportExecution: %v", err)
	}
	if out.Format != "json" {
		t.Fatalf("expected json format, got %q", out.Format)
	}
	if got := strings.ReplaceAll(string(out.Resources), " ", ""); got != `[{"a":1},{"a":2}]` {
		t.Fatalf("resources array not returned verbatim: %s", out.Resources)
	}
	if out.Raw != "" {
		t.Fatalf("raw should be empty for json format, got %q", out.Raw)
	}
}

func TestDownloadReportExecutionJSONEmptyArray(t *testing.T) {
	t.Parallel()

	// An execution with no rows downloads as a bare empty array `[]` (verified
	// live). It must succeed and surface an empty resources array, not error.
	e := &fakeExecutions{dlPayload: &downloadPayload{
		Body:        []byte(`[]`),
		ContentType: "application/json",
	}}
	m := newModule(&fakeReports{}, e)

	_, out, err := m.downloadReportExecution(context.Background(), nil, DownloadInput{ID: "exec1"})
	if err != nil {
		t.Fatalf("downloadReportExecution: %v", err)
	}
	if out.Format != "json" || string(out.Resources) != "[]" {
		t.Fatalf("expected empty json array, got %+v", out)
	}
}

func TestDownloadReportExecutionJSONEnvelopeFallback(t *testing.T) {
	t.Parallel()

	// Defensive: if a version/endpoint ever wraps rows in a {"resources": [...]}
	// object envelope, the handler unwraps it rather than returning the object.
	e := &fakeExecutions{dlPayload: &downloadPayload{
		Body:        []byte(`{"resources":[{"a":1},{"a":2}],"meta":{}}`),
		ContentType: "application/json",
	}}
	m := newModule(&fakeReports{}, e)

	_, out, err := m.downloadReportExecution(context.Background(), nil, DownloadInput{ID: "exec1"})
	if err != nil {
		t.Fatalf("downloadReportExecution: %v", err)
	}
	if out.Format != "json" {
		t.Fatalf("expected json format, got %q", out.Format)
	}
	if got := strings.ReplaceAll(string(out.Resources), " ", ""); got != `[{"a":1},{"a":2}]` {
		t.Fatalf("resources not unwrapped from envelope: %s", out.Resources)
	}
}

func TestDownloadReportExecutionJSONEmptyBody(t *testing.T) {
	t.Parallel()

	// A zero-length JSON body must not error; it maps to an empty array.
	e := &fakeExecutions{dlPayload: &downloadPayload{
		Body:        []byte(``),
		ContentType: "application/json",
	}}
	m := newModule(&fakeReports{}, e)

	_, out, err := m.downloadReportExecution(context.Background(), nil, DownloadInput{ID: "exec1"})
	if err != nil {
		t.Fatalf("downloadReportExecution: %v", err)
	}
	if out.Format != "json" || string(out.Resources) != "[]" {
		t.Fatalf("expected empty json array, got %+v", out)
	}
}

func TestDownloadReportExecutionPDFRejected(t *testing.T) {
	t.Parallel()

	e := &fakeExecutions{dlPayload: &downloadPayload{
		Body:        []byte("%PDF-1.7\n..."),
		ContentType: "application/pdf",
	}}
	m := newModule(&fakeReports{}, e)

	_, _, err := m.downloadReportExecution(context.Background(), nil, DownloadInput{ID: "exec1"})
	if !errors.Is(err, errUnsupportedFormat) {
		t.Fatalf("expected errUnsupportedFormat for PDF, got %v", err)
	}
}

func TestDownloadReportExecutionRequiresID(t *testing.T) {
	t.Parallel()

	e := &fakeExecutions{}
	m := newModule(&fakeReports{}, e)

	_, _, err := m.downloadReportExecution(context.Background(), nil, DownloadInput{ID: ""})
	if !errors.Is(err, errInvalidInput) {
		t.Fatalf("expected errInvalidInput for blank id, got %v", err)
	}
	if e.dlCalls != 0 {
		t.Fatalf("expected no download call for blank id, got %d", e.dlCalls)
	}
}

// --- tool registration / annotations ---

// recordingRegistrar captures registered tools so the test can assert on their
// names and annotations without a live MCP server.
type recordingRegistrar struct {
	entries []base.ToolEntry
}

func (r *recordingRegistrar) Add(e base.ToolEntry) { r.entries = append(r.entries, e) }

func TestRegisterToolsAnnotations(t *testing.T) {
	t.Parallel()

	m := newModule(&fakeReports{}, &fakeExecutions{})
	reg := &recordingRegistrar{}
	m.RegisterTools(reg)

	if len(reg.entries) != 4 {
		t.Fatalf("expected 4 tools, got %d", len(reg.entries))
	}

	byName := map[string]*base.ToolEntry{}
	for i := range reg.entries {
		byName[reg.entries[i].Tool.Name] = &reg.entries[i]
	}

	for _, want := range []string{
		"falcon_search_scheduled_reports",
		"falcon_launch_scheduled_report",
		"falcon_search_report_executions",
		"falcon_download_report_execution",
	} {
		if byName[want] == nil {
			t.Fatalf("tool %q not registered", want)
		}
	}

	// launch is a non-destructive mutator.
	launch := byName["falcon_launch_scheduled_report"].Tool
	if launch.Annotations == nil || launch.Annotations.ReadOnlyHint {
		t.Fatalf("launch should not be read-only: %+v", launch.Annotations)
	}
	if launch.Annotations.DestructiveHint == nil || *launch.Annotations.DestructiveHint {
		t.Fatalf("launch destructiveHint should be false, got %+v", launch.Annotations.DestructiveHint)
	}
	if launch.Annotations.IdempotentHint {
		t.Fatalf("launch idempotentHint should be false")
	}

	// The read tools keep the default read-only annotations.
	for _, name := range []string{
		"falcon_search_scheduled_reports",
		"falcon_search_report_executions",
		"falcon_download_report_execution",
	} {
		ann := byName[name].Tool.Annotations
		if ann == nil || !ann.ReadOnlyHint {
			t.Fatalf("%s should be read-only, got %+v", name, ann)
		}
	}
}

// --- downloadReader (raw body recovery) ---

// fakeClientResponse is a minimal runtime.ClientResponse for exercising
// downloadReader.ReadResponse directly.
type fakeClientResponse struct {
	code    int
	body    string
	headers map[string]string
}

func (r fakeClientResponse) Code() int { return r.code }
func (r fakeClientResponse) Message() string {
	return ""
}
func (r fakeClientResponse) GetHeader(name string) string { return r.headers[name] }
func (r fakeClientResponse) GetHeaders(string) []string   { return nil }
func (r fakeClientResponse) Body() io.ReadCloser          { return io.NopCloser(strings.NewReader(r.body)) }

func TestDownloadReaderCaptures200Body(t *testing.T) {
	t.Parallel()

	dr := &downloadReader{}
	resp := fakeClientResponse{
		code:    200,
		body:    "col1,col2\n",
		headers: map[string]string{"Content-Type": "text/csv"},
	}
	got, err := dr.ReadResponse(resp, nil)
	if err != nil {
		t.Fatalf("ReadResponse: %v", err)
	}
	if got == nil {
		t.Fatal("expected a non-nil OK to satisfy the generated type assertion")
	}
	if string(dr.body) != "col1,col2\n" {
		t.Fatalf("body not captured: %q", dr.body)
	}
	if dr.contentType != "text/csv" {
		t.Fatalf("content type not captured: %q", dr.contentType)
	}
}

// stubReader delegates ReadResponse so non-200 responses can be routed to a
// wrapped reader, exercising downloadReader's delegation path.
type stubReader struct{ called bool }

func (s *stubReader) ReadResponse(runtime.ClientResponse, runtime.Consumer) (any, error) {
	s.called = true
	return nil, errors.New("delegated")
}

func TestDownloadReaderDelegatesNon200(t *testing.T) {
	t.Parallel()

	orig := &stubReader{}
	dr := &downloadReader{orig: orig}
	resp := fakeClientResponse{code: 403, body: ""}

	_, err := dr.ReadResponse(resp, nil)
	if !orig.called {
		t.Fatal("expected non-200 to delegate to the wrapped reader")
	}
	if err == nil {
		t.Fatal("expected the delegated error to propagate")
	}
}
