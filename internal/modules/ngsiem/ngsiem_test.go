package ngsiem

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/crowdstrike/gofalcon/falcon/client/ngsiem"
	"github.com/crowdstrike/gofalcon/falcon/models"

	"github.com/crowdstrike/falcon-mcp/internal/modules/base"
)

// testLogger discards output; modules require a non-nil logger.
var testLogger = slog.New(slog.DiscardHandler)

func str(s string) *string { return &s }
func boolp(b bool) *bool   { return &b }

// call records the arguments of one API call so tests can assert on what the
// handler submitted (operation, repository, job id, body).
type call struct {
	op         string
	repository string
	id         string
	body       *models.APIQueryJobInput
}

// fakeNGSIEM is a scripted test double for the ngsiemAPI interface. startResps
// and pollResps are consumed in order (one per call); stopResp is returned for
// any StopSearchV1 call. A *Resp with a non-nil err is returned as the API error.
type fakeNGSIEM struct {
	startResp *ngsiem.StartSearchV1OK
	startErr  error

	pollResps []*ngsiem.GetSearchStatusV1OK
	pollErrs  []error
	pollIdx   int

	stopResp *ngsiem.StopSearchV1OK
	stopErr  error

	calls []call
}

func (f *fakeNGSIEM) StartSearchV1(p *ngsiem.StartSearchV1Params, _ ...ngsiem.ClientOption) (*ngsiem.StartSearchV1OK, error) {
	f.calls = append(f.calls, call{op: "StartSearchV1", repository: p.Repository, body: p.Body})
	return f.startResp, f.startErr
}

func (f *fakeNGSIEM) GetSearchStatusV1(p *ngsiem.GetSearchStatusV1Params, _ ...ngsiem.ClientOption) (*ngsiem.GetSearchStatusV1OK, error) {
	f.calls = append(f.calls, call{op: "GetSearchStatusV1", repository: p.Repository, id: p.ID})
	i := f.pollIdx
	f.pollIdx++
	var err error
	if i < len(f.pollErrs) {
		err = f.pollErrs[i]
	}
	var resp *ngsiem.GetSearchStatusV1OK
	if i < len(f.pollResps) {
		resp = f.pollResps[i]
	}
	return resp, err
}

func (f *fakeNGSIEM) StopSearchV1(p *ngsiem.StopSearchV1Params, _ ...ngsiem.ClientOption) (*ngsiem.StopSearchV1OK, error) {
	f.calls = append(f.calls, call{op: "StopSearchV1", repository: p.Repository, id: p.ID})
	return f.stopResp, f.stopErr
}

// newModule builds a Module with tiny poll/timeout durations so the poll loop
// runs fast in tests.
func newModule(f *fakeNGSIEM) *Module {
	return &Module{
		API:          f,
		Logger:       testLogger,
		PollInterval: time.Millisecond,
		Timeout:      50 * time.Millisecond,
	}
}

func startOK(id string) *ngsiem.StartSearchV1OK {
	return &ngsiem.StartSearchV1OK{Payload: &models.APIQueryJobResponse{ID: str(id)}}
}

func pollDone(events ...any) *ngsiem.GetSearchStatusV1OK {
	evs := make([]models.APIQueryJobsResultsEvents, 0, len(events))
	for _, e := range events {
		evs = append(evs, e)
	}
	return &ngsiem.GetSearchStatusV1OK{Payload: &models.APIQueryJobsResults{Done: boolp(true), Events: evs}}
}

func pollNotDone() *ngsiem.GetSearchStatusV1OK {
	return &ngsiem.GetSearchStatusV1OK{Payload: &models.APIQueryJobsResults{Done: boolp(false)}}
}

// pollCancelled returns a job that finished because it was cancelled server-side
// (Done=true, Cancelled=true) with no events.
func pollCancelled() *ngsiem.GetSearchStatusV1OK {
	return &ngsiem.GetSearchStatusV1OK{Payload: &models.APIQueryJobsResults{Done: boolp(true), Cancelled: boolp(true)}}
}

// TestSearchNGSIEMSuccess verifies a search that completes on the first poll
// returns the events, and that the start body carries the CQL query and the
// start time as an epoch-millisecond string.
func TestSearchNGSIEMSuccess(t *testing.T) {
	t.Parallel()

	f := &fakeNGSIEM{
		startResp: startOK("job-123"),
		pollResps: []*ngsiem.GetSearchStatusV1OK{pollDone(
			map[string]any{"aid": "agent-1", "event": "ProcessRollup2"},
			map[string]any{"aid": "agent-2", "event": "DnsRequest"},
		)},
	}
	m := newModule(f)

	_, out, err := m.searchNGSIEM(context.Background(), nil, SearchInput{
		QueryString: "#event_simpleName=ProcessRollup2",
		Start:       "2025-01-01T00:00:00Z",
		Repository:  "search-all",
	})
	if err != nil {
		t.Fatalf("searchNGSIEM: %v", err)
	}
	if out.Total != 2 || len(out.Resources) != 2 {
		t.Fatalf("expected 2 events, got %+v", out)
	}

	// Start call: operation, repository, query, epoch-ms start.
	start := f.calls[0]
	if start.op != "StartSearchV1" || start.repository != "search-all" {
		t.Fatalf("unexpected start call: %+v", start)
	}
	if start.body.QueryString == nil || *start.body.QueryString != "#event_simpleName=ProcessRollup2" {
		t.Fatalf("query not forwarded: %+v", start.body)
	}
	if start.body.Start != "1735689600000" {
		t.Fatalf("start not converted to epoch ms string, got %q", start.body.Start)
	}
	// Poll call targets the returned job id and repository.
	poll := f.calls[1]
	if poll.op != "GetSearchStatusV1" || poll.id != "job-123" || poll.repository != "search-all" {
		t.Fatalf("unexpected poll call: %+v", poll)
	}

	first, ok := out.Resources[0].(map[string]any)
	if !ok || first["aid"] != "agent-1" {
		t.Fatalf("unexpected first event: %#v", out.Resources[0])
	}
}

// TestSearchNGSIEMMultiplePolls verifies the handler keeps polling until the job
// reports done.
func TestSearchNGSIEMMultiplePolls(t *testing.T) {
	t.Parallel()

	f := &fakeNGSIEM{
		startResp: startOK("job-456"),
		pollResps: []*ngsiem.GetSearchStatusV1OK{
			pollNotDone(),
			pollNotDone(),
			pollDone(map[string]any{"aid": "agent-1"}),
		},
	}
	m := newModule(f)

	_, out, err := m.searchNGSIEM(context.Background(), nil, SearchInput{
		QueryString: "aid=abc123",
		Start:       "2025-01-01T00:00:00Z",
	})
	if err != nil {
		t.Fatalf("searchNGSIEM: %v", err)
	}
	if out.Total != 1 {
		t.Fatalf("expected 1 event, got %+v", out)
	}
	// 1 start + 3 polls.
	if len(f.calls) != 4 {
		t.Fatalf("expected 4 calls (1 start + 3 polls), got %d: %+v", len(f.calls), f.calls)
	}
}

// TestSearchNGSIEMStartError verifies a StartSearchV1 failure returns an API
// error and no polling occurs.
func TestSearchNGSIEMStartError(t *testing.T) {
	t.Parallel()

	f := &fakeNGSIEM{startErr: &ngsiem.StartSearchV1Forbidden{}}
	m := newModule(f)

	_, _, err := m.searchNGSIEM(context.Background(), nil, SearchInput{
		QueryString: "aid=abc123",
		Start:       "2025-01-01T00:00:00Z",
	})
	if err == nil {
		t.Fatal("expected an error from a forbidden start")
	}
	var apiErr *base.Error
	if !errors.As(err, &apiErr) {
		t.Fatalf("expected *base.Error, got %T: %v", err, err)
	}
	if len(f.calls) != 1 {
		t.Fatalf("expected only the start call, got %d: %+v", len(f.calls), f.calls)
	}
}

// TestSearchNGSIEM403AttachesScopes verifies a 403 on start surfaces the
// required NGSIEM read+write scopes via base.APIError.
func TestSearchNGSIEM403AttachesScopes(t *testing.T) {
	t.Parallel()

	f := &fakeNGSIEM{startErr: &ngsiem.StartSearchV1Forbidden{}}
	m := newModule(f)

	_, _, err := m.searchNGSIEM(context.Background(), nil, SearchInput{
		QueryString: "aid=abc123",
		Start:       "2025-01-01T00:00:00Z",
	})
	var apiErr *base.Error
	if !errors.As(err, &apiErr) {
		t.Fatalf("expected *base.Error, got %T: %v", err, err)
	}
	want := map[string]bool{"NGSIEM:read": false, "NGSIEM:write": false}
	for _, s := range apiErr.RequiredScopes {
		if _, ok := want[s]; ok {
			want[s] = true
		}
	}
	for scope, seen := range want {
		if !seen {
			t.Errorf("required scope %q not surfaced; got %v", scope, apiErr.RequiredScopes)
		}
	}
}

// TestSearchNGSIEMPollError verifies a failing GetSearchStatusV1 returns an API
// error.
func TestSearchNGSIEMPollError(t *testing.T) {
	t.Parallel()

	f := &fakeNGSIEM{
		startResp: startOK("job-789"),
		pollErrs:  []error{&ngsiem.GetSearchStatusV1InternalServerError{}},
	}
	m := newModule(f)

	_, _, err := m.searchNGSIEM(context.Background(), nil, SearchInput{
		QueryString: "aid=abc123",
		Start:       "2025-01-01T00:00:00Z",
	})
	if err == nil {
		t.Fatal("expected an error from a failing poll")
	}
	var apiErr *base.Error
	if !errors.As(err, &apiErr) {
		t.Fatalf("expected *base.Error, got %T: %v", err, err)
	}
}

// TestSearchNGSIEMTimeout verifies that exceeding the timeout stops the job and
// returns a timeout error naming the job id.
func TestSearchNGSIEMTimeout(t *testing.T) {
	t.Parallel()

	// Always-not-done polls force the loop to run until the timeout.
	notDone := make([]*ngsiem.GetSearchStatusV1OK, 0, 100)
	for range 100 {
		notDone = append(notDone, pollNotDone())
	}
	f := &fakeNGSIEM{
		startResp: startOK("job-timeout"),
		pollResps: notDone,
		stopResp:  &ngsiem.StopSearchV1OK{},
	}
	m := &Module{API: f, Logger: testLogger, PollInterval: time.Millisecond, Timeout: 5 * time.Millisecond}

	_, _, err := m.searchNGSIEM(context.Background(), nil, SearchInput{
		QueryString: "aid=abc123",
		Start:       "2025-01-01T00:00:00Z",
		Repository:  "search-all",
	})
	if err == nil {
		t.Fatal("expected a timeout error")
	}
	if !errors.Is(err, errSearch) {
		t.Fatalf("expected errSearch, got %v", err)
	}
	if !strings.Contains(err.Error(), "timed out") || !strings.Contains(err.Error(), "job-timeout") {
		t.Fatalf("timeout error should name the timeout and job id, got %q", err.Error())
	}

	// StopSearchV1 must have been called for cleanup, on the right job/repository.
	last := f.calls[len(f.calls)-1]
	if last.op != "StopSearchV1" || last.id != "job-timeout" || last.repository != "search-all" {
		t.Fatalf("expected a StopSearchV1 cleanup call, got %+v", last)
	}
}

// TestSearchNGSIEMCancelled verifies a job that finished because it was
// cancelled server-side (Done=true, Cancelled=true) is surfaced as an error
// rather than a misleading empty success.
func TestSearchNGSIEMCancelled(t *testing.T) {
	t.Parallel()

	f := &fakeNGSIEM{
		startResp: startOK("job-cancelled"),
		pollResps: []*ngsiem.GetSearchStatusV1OK{pollCancelled()},
	}
	m := newModule(f)

	_, _, err := m.searchNGSIEM(context.Background(), nil, SearchInput{
		QueryString: "aid=abc123",
		Start:       "2025-01-01T00:00:00Z",
	})
	if err == nil {
		t.Fatal("expected an error for a cancelled job")
	}
	if !errors.Is(err, errSearch) || !strings.Contains(err.Error(), "cancelled") {
		t.Fatalf("expected a cancelled errSearch naming the job, got %v", err)
	}
	if !strings.Contains(err.Error(), "job-cancelled") {
		t.Fatalf("cancelled error should name the job id, got %q", err.Error())
	}
}

// TestSearchNGSIEMMissingJobID verifies a start response with no job id returns
// an error and no polling occurs.
func TestSearchNGSIEMMissingJobID(t *testing.T) {
	t.Parallel()

	f := &fakeNGSIEM{startResp: &ngsiem.StartSearchV1OK{Payload: &models.APIQueryJobResponse{}}}
	m := newModule(f)

	_, _, err := m.searchNGSIEM(context.Background(), nil, SearchInput{
		QueryString: "aid=abc123",
		Start:       "2025-01-01T00:00:00Z",
	})
	if err == nil {
		t.Fatal("expected an error when the start response has no job id")
	}
	if !errors.Is(err, errSearch) || !strings.Contains(err.Error(), "no job id") {
		t.Fatalf("expected a no-job-id errSearch, got %v", err)
	}
	if len(f.calls) != 1 {
		t.Fatalf("expected only the start call, got %d: %+v", len(f.calls), f.calls)
	}
}

// TestSearchNGSIEMOptionalEndAndRepository verifies the end timestamp is
// converted to epoch ms and the repository is forwarded.
func TestSearchNGSIEMOptionalEndAndRepository(t *testing.T) {
	t.Parallel()

	f := &fakeNGSIEM{
		startResp: startOK("job-opt"),
		pollResps: []*ngsiem.GetSearchStatusV1OK{pollDone()},
	}
	m := newModule(f)

	_, out, err := m.searchNGSIEM(context.Background(), nil, SearchInput{
		QueryString: "aid=abc123",
		Start:       "2025-01-01T00:00:00Z",
		End:         "2025-02-06T00:00:00Z",
		Repository:  "investigate_view",
	})
	if err != nil {
		t.Fatalf("searchNGSIEM: %v", err)
	}
	if out.Resources == nil || len(out.Resources) != 0 || out.Total != 0 {
		t.Fatalf("expected empty non-nil resources, got %+v", out)
	}

	start := f.calls[0]
	if start.repository != "investigate_view" {
		t.Errorf("repository = %q, want investigate_view", start.repository)
	}
	if start.body.End != "1738800000000" {
		t.Errorf("end = %q, want 1738800000000", start.body.End)
	}
}

// TestSearchNGSIEMDefaultRepository verifies the repository defaults to
// search-all when the caller omits it.
func TestSearchNGSIEMDefaultRepository(t *testing.T) {
	t.Parallel()

	f := &fakeNGSIEM{startResp: startOK("job-default"), pollResps: []*ngsiem.GetSearchStatusV1OK{pollDone()}}
	m := newModule(f)

	if _, _, err := m.searchNGSIEM(context.Background(), nil, SearchInput{
		QueryString: "aid=abc123",
		Start:       "2025-01-01T00:00:00Z",
	}); err != nil {
		t.Fatalf("searchNGSIEM: %v", err)
	}
	if f.calls[0].repository != "search-all" {
		t.Errorf("repository = %q, want default search-all", f.calls[0].repository)
	}
}

// TestSearchNGSIEMSpecialCharsInQuery verifies special characters in the CQL
// query pass through unchanged.
func TestSearchNGSIEMSpecialCharsInQuery(t *testing.T) {
	t.Parallel()

	f := &fakeNGSIEM{startResp: startOK("job-special"), pollResps: []*ngsiem.GetSearchStatusV1OK{pollDone()}}
	m := newModule(f)

	q := `#event_simpleName=ProcessRollup2 | ComputerName="test's <host>" | count()`
	if _, _, err := m.searchNGSIEM(context.Background(), nil, SearchInput{
		QueryString: q,
		Start:       "2025-01-01T00:00:00Z",
	}); err != nil {
		t.Fatalf("searchNGSIEM: %v", err)
	}
	if got := f.calls[0].body.QueryString; got == nil || *got != q {
		t.Fatalf("query mutated: got %v, want %q", got, q)
	}
}

// TestSearchNGSIEMValidation covers the client-side input validation branches:
// a missing query and a malformed start timestamp both fail before any API call.
func TestSearchNGSIEMValidation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   SearchInput
	}{
		{"missing query", SearchInput{Start: "2025-01-01T00:00:00Z"}},
		{"bad start", SearchInput{QueryString: "aid=abc123", Start: "not-a-timestamp"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := &fakeNGSIEM{}
			m := newModule(f)
			_, _, err := m.searchNGSIEM(context.Background(), nil, tc.in)
			if err == nil {
				t.Fatal("expected a validation error")
			}
			if !errors.Is(err, errSearch) {
				t.Fatalf("expected errSearch, got %v", err)
			}
			if len(f.calls) != 0 {
				t.Fatalf("expected no API calls on invalid input, got %+v", f.calls)
			}
		})
	}
}

// TestSearchNGSIEMBadEndTimestamp verifies a malformed end timestamp fails after
// the start validates but before any API call.
func TestSearchNGSIEMBadEndTimestamp(t *testing.T) {
	t.Parallel()

	f := &fakeNGSIEM{}
	m := newModule(f)
	_, _, err := m.searchNGSIEM(context.Background(), nil, SearchInput{
		QueryString: "aid=abc123",
		Start:       "2025-01-01T00:00:00Z",
		End:         "nope",
	})
	if err == nil || !errors.Is(err, errSearch) {
		t.Fatalf("expected errSearch for bad end, got %v", err)
	}
	if len(f.calls) != 0 {
		t.Fatalf("expected no API calls on invalid end, got %+v", f.calls)
	}
}

// TestSearchNGSIEMContextCancel verifies the poll loop honors context
// cancellation instead of waiting out the timeout.
func TestSearchNGSIEMContextCancel(t *testing.T) {
	t.Parallel()

	f := &fakeNGSIEM{startResp: startOK("job-ctx"), pollResps: []*ngsiem.GetSearchStatusV1OK{pollNotDone()}}
	m := &Module{API: f, Logger: testLogger, PollInterval: time.Hour, Timeout: time.Hour}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, _, err := m.searchNGSIEM(ctx, nil, SearchInput{
		QueryString: "aid=abc123",
		Start:       "2025-01-01T00:00:00Z",
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
}

// TestDurationFromEnvUnset verifies an absent env var yields the default. The
// var name is unique to this test and set by nothing else, so its absence is
// reliable without needing to unset it.
func TestDurationFromEnvUnset(t *testing.T) {
	def := 7 * time.Second
	if got := durationFromEnv("FALCON_MCP_NGSIEM_TEST_DURATION_UNSET", def); got != def {
		t.Errorf("durationFromEnv(unset)=%v, want %v", got, def)
	}
}

// TestDurationFromEnvParsing covers the env override parsing: a valid positive
// integer is used; invalid or non-positive values fall back to the default.
func TestDurationFromEnvParsing(t *testing.T) {
	const name = "FALCON_MCP_NGSIEM_TEST_DURATION"
	def := 7 * time.Second

	tests := []struct {
		name  string
		value string
		want  time.Duration
	}{
		{"valid", "10", 10 * time.Second},
		{"zero", "0", def},
		{"negative", "-3", def},
		{"nonnumeric", "abc", def},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(name, tc.value)
			if got := durationFromEnv(name, def); got != tc.want {
				t.Errorf("durationFromEnv(%q)=%v, want %v", tc.value, got, tc.want)
			}
		})
	}
}

// TestSearchNGSIEMEmitsDebugLog verifies the injected logger receives a
// structured DEBUG entry naming the tool and query.
func TestSearchNGSIEMEmitsDebugLog(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	f := &fakeNGSIEM{startResp: startOK("job-log"), pollResps: []*ngsiem.GetSearchStatusV1OK{pollDone()}}
	m := &Module{API: f, Logger: logger, PollInterval: time.Millisecond, Timeout: 50 * time.Millisecond}
	if _, _, err := m.searchNGSIEM(context.Background(), nil, SearchInput{
		QueryString: "#event_simpleName=ProcessRollup2",
		Start:       "2025-01-01T00:00:00Z",
	}); err != nil {
		t.Fatalf("searchNGSIEM: %v", err)
	}

	var found bool
	for line := range strings.SplitSeq(strings.TrimSpace(buf.String()), "\n") {
		var rec map[string]any
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("log line not JSON: %q: %v", line, err)
		}
		if rec["level"] == "DEBUG" && rec["msg"] == "search_ngsiem starting" {
			if rec["query_string"] != "#event_simpleName=ProcessRollup2" {
				t.Errorf("query_string field = %v", rec["query_string"])
			}
			found = true
		}
	}
	if !found {
		t.Errorf("no DEBUG search_ngsiem starting log emitted; got:\n%s", buf.String())
	}
}
