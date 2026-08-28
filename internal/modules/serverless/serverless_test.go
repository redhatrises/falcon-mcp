package serverless

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"testing"

	"github.com/crowdstrike/gofalcon/falcon/client/serverless_vulnerabilities"
	"github.com/crowdstrike/gofalcon/falcon/models"

	"github.com/crowdstrike/falcon-mcp/internal/modules/base"
	"github.com/crowdstrike/falcon-mcp/internal/testutil"
)

var testLogger = testutil.DiscardLogger()

// fakeServerless is a configurable test double for the serverlessAPI interface.
// GetCombinedVulnerabilitiesSARIF returns the gofalcon typed OK, matching the
// client the module consumes in production.
type fakeServerless struct {
	ok  *serverless_vulnerabilities.GetCombinedVulnerabilitiesSARIFOK
	err error

	calls      int
	lastFilter string
	lastSort   string
	lastLimit  int64
	lastOffset int64
}

func (f *fakeServerless) GetCombinedVulnerabilitiesSARIF(p *serverless_vulnerabilities.GetCombinedVulnerabilitiesSARIFParams, _ ...serverless_vulnerabilities.ClientOption) (*serverless_vulnerabilities.GetCombinedVulnerabilitiesSARIFOK, error) {
	f.calls++
	if p.Filter != nil {
		f.lastFilter = *p.Filter
	}
	if p.Sort != nil {
		f.lastSort = *p.Sort
	}
	if p.Limit != nil {
		f.lastLimit = *p.Limit
	}
	if p.Offset != nil {
		f.lastOffset = *p.Offset
	}
	if f.err != nil {
		return nil, f.err
	}
	return f.ok, nil
}

// sarifOK builds a typed combined-SARIF success response carrying the given
// number of SARIF runs, matching the gofalcon model the client returns
// (resources is a single SARIF object whose runs field is the array of interest).
func sarifOK(runs int) *serverless_vulnerabilities.GetCombinedVulnerabilitiesSARIFOK {
	runList := make([]*models.ModelsRun, runs)
	for i := range runList {
		runList[i] = &models.ModelsRun{}
	}
	return &serverless_vulnerabilities.GetCombinedVulnerabilitiesSARIFOK{
		Payload: &models.VulnerabilitiesVulnerabilityEntitySARIFResponse{
			Resources: &models.ModelsVulnerabilitySARIF{
				Version: new("2.1.0"),
				Runs:    runList,
			},
		},
	}
}

func TestSearchServerlessVulnerabilitiesSuccess(t *testing.T) {
	t.Parallel()

	f := &fakeServerless{ok: sarifOK(1)}
	m := &Module{API: f, Logger: testLogger}

	_, out, err := m.searchServerlessVulnerabilities(context.Background(), nil, SearchInput{Filter: "cloud_provider:'aws'"})
	if err != nil {
		t.Fatalf("searchServerlessVulnerabilities: %v", err)
	}
	if len(out.Resources) != 1 || out.FilterUsed != "cloud_provider:'aws'" {
		t.Fatalf("unexpected result: %+v", out)
	}
	if out.Resources[0] == nil {
		t.Fatalf("expected a non-nil run, got %+v", out.Resources)
	}
}

// TestSearchServerlessVulnerabilitiesForwardsParams verifies the handler defaults
// the limit and forwards filter, offset, and sort to the API params.
func TestSearchServerlessVulnerabilitiesForwardsParams(t *testing.T) {
	t.Parallel()

	f := &fakeServerless{ok: sarifOK(0)}
	m := &Module{API: f, Logger: testLogger}

	_, _, err := m.searchServerlessVulnerabilities(context.Background(), nil, SearchInput{
		Filter: "severity:'HIGH'",
		Offset: 25,
		Sort:   "severity",
	})
	if err != nil {
		t.Fatalf("searchServerlessVulnerabilities: %v", err)
	}
	if f.lastLimit != defaultLimit {
		t.Errorf("limit = %d, want default %d", f.lastLimit, defaultLimit)
	}
	if f.lastFilter != "severity:'HIGH'" {
		t.Errorf("filter = %q", f.lastFilter)
	}
	if f.lastOffset != 25 {
		t.Errorf("offset = %d, want 25", f.lastOffset)
	}
	if f.lastSort != "severity" {
		t.Errorf("sort = %q", f.lastSort)
	}
}

func TestSearchServerlessVulnerabilitiesEmpty(t *testing.T) {
	t.Parallel()

	f := &fakeServerless{ok: sarifOK(0)}
	m := &Module{API: f, Logger: testLogger}

	_, out, err := m.searchServerlessVulnerabilities(context.Background(), nil, SearchInput{Filter: "runtime:'nodejs'"})
	if err != nil {
		t.Fatalf("searchServerlessVulnerabilities: %v", err)
	}
	if out.Resources == nil || len(out.Resources) != 0 {
		t.Fatalf("expected empty non-nil resources, got %+v", out)
	}
}

// TestSearchServerlessVulnerabilitiesRequiresFilter verifies the handler rejects
// an empty filter (required by the Python tool) before calling the API.
func TestSearchServerlessVulnerabilitiesRequiresFilter(t *testing.T) {
	t.Parallel()

	f := &fakeServerless{ok: sarifOK(0)}
	m := &Module{API: f, Logger: testLogger}

	_, _, err := m.searchServerlessVulnerabilities(context.Background(), nil, SearchInput{})
	if !errors.Is(err, base.ErrInvalidInput) {
		t.Fatalf("expected base.ErrInvalidInput, got %v", err)
	}
	if f.calls != 0 {
		t.Fatalf("expected no API call on empty filter, got %d", f.calls)
	}
}

func TestSearchServerlessVulnerabilitiesFQLError(t *testing.T) {
	t.Parallel()

	badReq := &serverless_vulnerabilities.GetCombinedVulnerabilitiesSARIFBadRequest{
		Payload: &models.MsaspecResponseFields{
			Errors: []*models.MsaAPIError{{Code: new(int32(400)), Message: new("invalid filter")}},
		},
	}
	f := &fakeServerless{err: badReq}
	m := &Module{API: f, Logger: testLogger}

	_, out, err := m.searchServerlessVulnerabilities(context.Background(), nil, SearchInput{Filter: "bogus::"})
	if err != nil {
		t.Fatalf("expected soft FQL error result, got Go error: %v", err)
	}
	if len(out.Errors) != 1 || out.Errors[0].Message != "invalid filter" {
		t.Fatalf("expected FQL error detail, got %+v", out.Errors)
	}
	if out.FQLGuide == "" {
		t.Fatalf("expected FQL guide in error result")
	}
	if out.FilterUsed != "bogus::" {
		t.Fatalf("expected filter echoed, got %q", out.FilterUsed)
	}
}

// TestSearchServerlessVulnerabilitiesEmitsDebugLog verifies the injected logger
// receives a structured DEBUG entry naming the tool and its filter.
func TestSearchServerlessVulnerabilitiesEmitsDebugLog(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	f := &fakeServerless{ok: sarifOK(0)}
	m := &Module{API: f, Logger: logger}
	if _, _, err := m.searchServerlessVulnerabilities(context.Background(), nil, SearchInput{Filter: "severity:'CRITICAL'"}); err != nil {
		t.Fatalf("searchServerlessVulnerabilities: %v", err)
	}

	var found bool
	for line := range strings.SplitSeq(strings.TrimSpace(buf.String()), "\n") {
		var rec map[string]any
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("log line not JSON: %q: %v", line, err)
		}
		if rec["level"] == "DEBUG" && rec["msg"] == "search_serverless_vulnerabilities" {
			if rec["filter"] != "severity:'CRITICAL'" {
				t.Errorf("filter field = %v, want severity:'CRITICAL'", rec["filter"])
			}
			found = true
		}
	}
	if !found {
		t.Errorf("no DEBUG search_serverless_vulnerabilities log emitted; got:\n%s", buf.String())
	}
}

// TestSarifRuns covers the SARIF run extraction helper directly, including the
// nil response, nil payload, and absent-resources cases.
func TestSarifRuns(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		resp *serverless_vulnerabilities.GetCombinedVulnerabilitiesSARIFOK
		want int
	}{
		{"nil response", nil, 0},
		{"nil payload", &serverless_vulnerabilities.GetCombinedVulnerabilitiesSARIFOK{}, 0},
		{"absent resources", &serverless_vulnerabilities.GetCombinedVulnerabilitiesSARIFOK{Payload: &models.VulnerabilitiesVulnerabilityEntitySARIFResponse{}}, 0},
		{"one run", sarifOK(1), 1},
		{"three runs", sarifOK(3), 3},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			runs, _ := sarifRuns(tc.resp)
			if len(runs) != tc.want {
				t.Fatalf("len(runs) = %d, want %d", len(runs), tc.want)
			}
		})
	}
}

// TestSarifRunsSurfacesMeta proves the meta sibling of resources is returned
// rather than discarded, and that it survives a response carrying no resources —
// the trace ID is what a caller quotes in a support request, so it must outlive
// an empty result.
func TestSarifRunsSurfacesMeta(t *testing.T) {
	t.Parallel()

	meta := &models.MsaMetaInfo{QueryTime: new(0.42), TraceID: new("trace-abc")}
	tests := []struct {
		name string
		resp *serverless_vulnerabilities.GetCombinedVulnerabilitiesSARIFOK
	}{
		{"with resources", &serverless_vulnerabilities.GetCombinedVulnerabilitiesSARIFOK{
			Payload: &models.VulnerabilitiesVulnerabilityEntitySARIFResponse{
				Resources: &models.ModelsVulnerabilitySARIF{Version: new("2.1.0"), Runs: []*models.ModelsRun{{}}},
				Meta:      meta,
			},
		}},
		{"resources absent", &serverless_vulnerabilities.GetCombinedVulnerabilitiesSARIFOK{
			Payload: &models.VulnerabilitiesVulnerabilityEntitySARIFResponse{Meta: meta},
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, got := sarifRuns(tc.resp)
			if got == nil {
				t.Fatal("meta is nil; the meta sibling of resources was discarded")
			}
			if got.TraceID == nil || *got.TraceID != "trace-abc" {
				t.Errorf("trace_id = %v, want trace-abc", got.TraceID)
			}
			if got.QueryTime == nil || *got.QueryTime != 0.42 {
				t.Errorf("query_time = %v, want 0.42", got.QueryTime)
			}
		})
	}
}

// TestSearchServerlessVulnerabilitiesAttachesMeta verifies the handler chains the
// response meta onto the result envelope rather than dropping it.
func TestSearchServerlessVulnerabilitiesAttachesMeta(t *testing.T) {
	t.Parallel()

	ok := &serverless_vulnerabilities.GetCombinedVulnerabilitiesSARIFOK{
		Payload: &models.VulnerabilitiesVulnerabilityEntitySARIFResponse{
			Resources: &models.ModelsVulnerabilitySARIF{Version: new("2.1.0"), Runs: []*models.ModelsRun{{}}},
			Meta:      &models.MsaMetaInfo{QueryTime: new(0.42), TraceID: new("trace-abc")},
		},
	}
	m := &Module{API: &fakeServerless{ok: ok}, Logger: testLogger}

	_, out, err := m.searchServerlessVulnerabilities(context.Background(), nil, SearchInput{Filter: "cloud_provider:'aws'"})
	if err != nil {
		t.Fatalf("searchServerlessVulnerabilities: %v", err)
	}
	if out.Meta == nil {
		t.Fatal("out.Meta is nil; the handler dropped the response metadata")
	}
	if out.Meta.TraceID != "trace-abc" {
		t.Errorf("trace_id = %q, want trace-abc", out.Meta.TraceID)
	}
	if out.Meta.QueryTime == nil || *out.Meta.QueryTime != 0.42 {
		t.Errorf("query_time = %v, want 0.42", out.Meta.QueryTime)
	}
}
