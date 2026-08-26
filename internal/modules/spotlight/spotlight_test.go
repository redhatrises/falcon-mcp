package spotlight

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"

	"github.com/crowdstrike/gofalcon/falcon/client/spotlight_vulnerabilities"
	"github.com/crowdstrike/gofalcon/falcon/models"

	"github.com/crowdstrike/falcon-mcp/internal/testutil"
)

var testLogger = testutil.DiscardLogger()

// fakeSpotlight is a configurable test double for the spotlightAPI interface.
type fakeSpotlight struct {
	resp *spotlight_vulnerabilities.CombinedQueryVulnerabilitiesOK
	err  error

	calls      int
	lastFilter string
	lastSort   string
	lastAfter  string
	lastFacet  []string
	lastLimit  int64
}

func (f *fakeSpotlight) CombinedQueryVulnerabilities(p *spotlight_vulnerabilities.CombinedQueryVulnerabilitiesParams, _ ...spotlight_vulnerabilities.ClientOption) (*spotlight_vulnerabilities.CombinedQueryVulnerabilitiesOK, error) {
	f.calls++
	f.lastFilter = p.Filter
	if p.Sort != nil {
		f.lastSort = *p.Sort
	}
	if p.After != nil {
		f.lastAfter = *p.After
	}
	if p.Limit != nil {
		f.lastLimit = *p.Limit
	}
	f.lastFacet = p.Facet
	return f.resp, f.err
}

func okResp(vulns ...*models.DomainBaseAPIVulnerabilityV2) *spotlight_vulnerabilities.CombinedQueryVulnerabilitiesOK {
	return &spotlight_vulnerabilities.CombinedQueryVulnerabilitiesOK{
		Payload: &models.DomainSPAPICombinedVulnerabilitiesResponse{Resources: vulns},
	}
}

func TestSearchVulnerabilitiesSuccess(t *testing.T) {
	t.Parallel()

	f := &fakeSpotlight{resp: okResp(&models.DomainBaseAPIVulnerabilityV2{ID: new("vuln-1")})}
	f.resp.Payload.Meta = &models.DomainSPAPIQueryMeta{Pagination: &models.DomainSPAPIQueryPaging{Total: new(int64(120)), After: new("cursor-next")}}
	m := &Module{API: f, Logger: testLogger}

	_, out, err := m.searchVulnerabilities(context.Background(), nil, SearchInput{Filter: "status:'open'"})
	if err != nil {
		t.Fatalf("searchVulnerabilities: %v", err)
	}
	if len(out.Resources) != 1 || out.FilterUsed != "status:'open'" {
		t.Fatalf("unexpected result: %+v", out)
	}
	testutil.AssertNormalizedMeta(t, out.Meta, f.resp.Payload.Meta)
	if *out.Resources[0].ID != "vuln-1" {
		t.Fatalf("unexpected resource: %+v", out.Resources[0])
	}
}

// TestSearchVulnerabilitiesForwardsParams verifies the handler defaults the
// limit and forwards filter, sort, after, and facet to the API params.
func TestSearchVulnerabilitiesForwardsParams(t *testing.T) {
	t.Parallel()

	f := &fakeSpotlight{resp: okResp()}
	m := &Module{API: f, Logger: testLogger}

	_, _, err := m.searchVulnerabilities(context.Background(), nil, SearchInput{
		Sort:  "created_timestamp.desc",
		After: "tok-123",
		Facet: []string{"cve", "host_info"},
	})
	if err != nil {
		t.Fatalf("searchVulnerabilities: %v", err)
	}
	if f.lastLimit != defaultLimit {
		t.Errorf("limit = %d, want default %d", f.lastLimit, defaultLimit)
	}
	if f.lastSort != "created_timestamp.desc" {
		t.Errorf("sort = %q", f.lastSort)
	}
	if f.lastAfter != "tok-123" {
		t.Errorf("after = %q", f.lastAfter)
	}
	if strings.Join(f.lastFacet, ",") != "cve,host_info" {
		t.Errorf("facet = %v", f.lastFacet)
	}
}

func TestSearchVulnerabilitiesEmpty(t *testing.T) {
	t.Parallel()

	f := &fakeSpotlight{resp: okResp()}
	m := &Module{API: f, Logger: testLogger}

	_, out, err := m.searchVulnerabilities(context.Background(), nil, SearchInput{})
	if err != nil {
		t.Fatalf("searchVulnerabilities: %v", err)
	}
	if out.Resources == nil || len(out.Resources) != 0 {
		t.Fatalf("expected empty non-nil resources, got %+v", out)
	}
	if out.Meta != nil {
		t.Fatalf("Meta = %+v, want nil when the response carries no meta", out.Meta)
	}
}

func TestSearchVulnerabilitiesFQLError(t *testing.T) {
	t.Parallel()

	badReq := &spotlight_vulnerabilities.CombinedQueryVulnerabilitiesBadRequest{
		Payload: &models.DomainSPAPICombinedVulnerabilitiesResponse{
			Errors: []*models.MsaAPIError{{Code: new(int32(400)), Message: new("invalid filter")}},
		},
	}
	f := &fakeSpotlight{err: badReq}
	m := &Module{API: f, Logger: testLogger}

	_, out, err := m.searchVulnerabilities(context.Background(), nil, SearchInput{Filter: "bogus::"})
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

// TestSearchVulnerabilitiesEmitsDebugLog verifies the injected logger receives a
// structured DEBUG entry naming the tool and its filter.
func TestSearchVulnerabilitiesEmitsDebugLog(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	f := &fakeSpotlight{resp: okResp()}
	m := &Module{API: f, Logger: logger}
	if _, _, err := m.searchVulnerabilities(context.Background(), nil, SearchInput{Filter: "cve.severity:'HIGH'"}); err != nil {
		t.Fatalf("searchVulnerabilities: %v", err)
	}

	var found bool
	for line := range strings.SplitSeq(strings.TrimSpace(buf.String()), "\n") {
		var rec map[string]any
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("log line not JSON: %q: %v", line, err)
		}
		if rec["level"] == "DEBUG" && rec["msg"] == "search_vulnerabilities" {
			if rec["filter"] != "cve.severity:'HIGH'" {
				t.Errorf("filter field = %v, want cve.severity:'HIGH'", rec["filter"])
			}
			found = true
		}
	}
	if !found {
		t.Errorf("no DEBUG search_vulnerabilities log emitted; got:\n%s", buf.String())
	}
}
