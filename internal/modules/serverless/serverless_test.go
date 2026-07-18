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
)

// testLogger discards output; modules require a non-nil logger.
var testLogger = slog.New(slog.DiscardHandler)

// fakeServerless is a configurable test double for the serverlessAPI interface.
// GetCombinedVulnerabilitiesSARIF returns the raw response body as an any
// ([]byte), matching the wrapped serverlessClient the module uses in production.
type fakeServerless struct {
	body []byte
	err  error

	calls      int
	lastFilter string
	lastSort   string
	lastLimit  int64
	lastOffset int64
}

func (f *fakeServerless) GetCombinedVulnerabilitiesSARIF(p *serverless_vulnerabilities.GetCombinedVulnerabilitiesSARIFParams, _ ...serverless_vulnerabilities.ClientOption) (any, error) {
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
	return f.body, nil
}

func str(s string) *string { return &s }
func i32(v int32) *int32   { return &v }

// sarifBody renders a combined-SARIF response body with the given number of
// runs, matching the live API shape (resources is a single SARIF object whose
// runs field is the array of interest).
func sarifBody(runs int) []byte {
	runList := make([]*models.ModelsRun, runs)
	for i := range runList {
		runList[i] = &models.ModelsRun{}
	}
	b, err := json.Marshal(sarifResponse{
		Resources: &models.ModelsVulnerabilitySARIF{
			Version: str("2.1.0"),
			Runs:    runList,
		},
	})
	if err != nil {
		panic(err)
	}
	return b
}

func TestSearchServerlessVulnerabilitiesSuccess(t *testing.T) {
	t.Parallel()

	f := &fakeServerless{body: sarifBody(1)}
	m := &Module{API: f, Logger: testLogger}

	_, out, err := m.searchServerlessVulnerabilities(context.Background(), nil, SearchInput{Filter: "cloud_provider:'aws'"})
	if err != nil {
		t.Fatalf("searchServerlessVulnerabilities: %v", err)
	}
	if out.Total != 1 || len(out.Resources) != 1 || out.FilterUsed != "cloud_provider:'aws'" {
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

	f := &fakeServerless{body: sarifBody(0)}
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

	f := &fakeServerless{body: sarifBody(0)}
	m := &Module{API: f, Logger: testLogger}

	_, out, err := m.searchServerlessVulnerabilities(context.Background(), nil, SearchInput{Filter: "runtime:'nodejs'"})
	if err != nil {
		t.Fatalf("searchServerlessVulnerabilities: %v", err)
	}
	if out.Resources == nil || len(out.Resources) != 0 || out.Total != 0 {
		t.Fatalf("expected empty non-nil resources, got %+v", out)
	}
}

// TestSearchServerlessVulnerabilitiesRequiresFilter verifies the handler rejects
// an empty filter (required by the Python tool) before calling the API.
func TestSearchServerlessVulnerabilitiesRequiresFilter(t *testing.T) {
	t.Parallel()

	f := &fakeServerless{body: sarifBody(0)}
	m := &Module{API: f, Logger: testLogger}

	_, _, err := m.searchServerlessVulnerabilities(context.Background(), nil, SearchInput{})
	if !errors.Is(err, errInvalidInput) {
		t.Fatalf("expected errInvalidInput, got %v", err)
	}
	if f.calls != 0 {
		t.Fatalf("expected no API call on empty filter, got %d", f.calls)
	}
}

func TestSearchServerlessVulnerabilitiesFQLError(t *testing.T) {
	t.Parallel()

	badReq := &serverless_vulnerabilities.GetCombinedVulnerabilitiesSARIFBadRequest{
		Payload: &models.MsaspecResponseFields{
			Errors: []*models.MsaAPIError{{Code: i32(400), Message: str("invalid filter")}},
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

	f := &fakeServerless{body: sarifBody(0)}
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

// TestDecodeRuns covers the SARIF body decode helper directly, including the
// live-shape single-object resources field and the empty/absent cases.
func TestDecodeRuns(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		body []byte
		want int
	}{
		{"nil body", nil, 0},
		{"empty resources object", []byte(`{"resources":null,"errors":[]}`), 0},
		{"one run", sarifBody(1), 1},
		{"three runs", sarifBody(3), 3},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			runs, err := decodeRuns(tc.body)
			if err != nil {
				t.Fatalf("decodeRuns: %v", err)
			}
			if len(runs) != tc.want {
				t.Fatalf("len(runs) = %d, want %d", len(runs), tc.want)
			}
		})
	}
}

// TestDecodeRunsInvalidJSON verifies a malformed body is a hard error, not a
// silent empty result.
func TestDecodeRunsInvalidJSON(t *testing.T) {
	t.Parallel()
	if _, err := decodeRuns([]byte(`{not json`)); err == nil {
		t.Fatal("expected an error decoding malformed body")
	}
}
