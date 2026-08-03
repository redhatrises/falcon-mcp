package discover

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"reflect"
	"strings"
	"testing"

	"github.com/crowdstrike/gofalcon/falcon/client/discover"
	"github.com/crowdstrike/gofalcon/falcon/models"

	"github.com/crowdstrike/falcon-mcp/internal/modules/base"
)

// testLogger discards output; modules require a non-nil logger.
var testLogger = slog.New(slog.DiscardHandler)

func str(s string) *string { return &s }
func i32(v int32) *int32   { return &v }

// fakeDiscover is a configurable test double for the discoverAPI interface. It
// records the last params each operation received so tests can assert on filter
// composition and limit defaulting.
type fakeDiscover struct {
	appsResp *discover.CombinedApplicationsOK
	appsErr  error
	appCalls int

	hostsResp *discover.CombinedHostsOK
	hostsErr  error
	hostCalls int

	lastAppFilter  string
	lastAppFacet   []string
	lastAppSort    string
	lastAppLimit   int64
	lastHostFilter string
	lastHostSort   string
	lastHostLimit  int64
}

func (f *fakeDiscover) CombinedApplications(p *discover.CombinedApplicationsParams, _ ...discover.ClientOption) (*discover.CombinedApplicationsOK, error) {
	f.appCalls++
	f.lastAppFilter = p.Filter
	f.lastAppFacet = p.Facet
	if p.Sort != nil {
		f.lastAppSort = *p.Sort
	}
	if p.Limit != nil {
		f.lastAppLimit = *p.Limit
	}
	return f.appsResp, f.appsErr
}

func (f *fakeDiscover) CombinedHosts(p *discover.CombinedHostsParams, _ ...discover.ClientOption) (*discover.CombinedHostsOK, error) {
	f.hostCalls++
	f.lastHostFilter = p.Filter
	if p.Sort != nil {
		f.lastHostSort = *p.Sort
	}
	if p.Limit != nil {
		f.lastHostLimit = *p.Limit
	}
	return f.hostsResp, f.hostsErr
}

func appsOK(apps ...*models.DomainDiscoverAPIApplication) *discover.CombinedApplicationsOK {
	return &discover.CombinedApplicationsOK{
		Payload: &models.DomainDiscoverAPICombinedApplicationsResponse{Resources: apps},
	}
}

func hostsOK(hosts ...*models.DomainDiscoverAPIHost) *discover.CombinedHostsOK {
	return &discover.CombinedHostsOK{
		Payload: &models.DomainDiscoverAPICombinedHostsResponse{Resources: hosts},
	}
}

func TestSearchApplicationsSuccess(t *testing.T) {
	t.Parallel()

	f := &fakeDiscover{appsResp: appsOK(&models.DomainDiscoverAPIApplication{ID: str("app-1"), Name: "Chrome"})}
	f.appsResp.Payload.Meta = &models.DomainDiscoverAPIMetaInfo{}
	m := &Module{API: f, Logger: testLogger}

	_, out, err := m.searchApplications(context.Background(), nil, ApplicationsInput{Filter: "name:'Chrome'"})
	if err != nil {
		t.Fatalf("searchApplications: %v", err)
	}
	if len(out.Resources) != 1 || out.FilterUsed != "name:'Chrome'" {
		t.Fatalf("unexpected result: %+v", out)
	}
	if out.Resources[0].Name != "Chrome" {
		t.Fatalf("unexpected resource: %+v", out.Resources[0])
	}
	if !reflect.DeepEqual(out.Meta, base.NormalizedMeta(f.appsResp.Payload.Meta)) {
		t.Fatalf("expected normalized meta, got %+v", out.Meta)
	}
}

// TestSearchApplicationsForwardsParams verifies the handler defaults the limit
// and forwards filter, facet, and sort to the API params.
func TestSearchApplicationsForwardsParams(t *testing.T) {
	t.Parallel()

	f := &fakeDiscover{appsResp: appsOK()}
	m := &Module{API: f, Logger: testLogger}

	_, _, err := m.searchApplications(context.Background(), nil, ApplicationsInput{
		Filter: "vendor:'Google'",
		Facet:  "host_info",
		Sort:   "name.asc",
	})
	if err != nil {
		t.Fatalf("searchApplications: %v", err)
	}
	if f.lastAppLimit != defaultLimit {
		t.Errorf("limit = %d, want default %d", f.lastAppLimit, defaultLimit)
	}
	if f.lastAppFilter != "vendor:'Google'" {
		t.Errorf("filter = %q", f.lastAppFilter)
	}
	if strings.Join(f.lastAppFacet, ",") != "host_info" {
		t.Errorf("facet = %v, want [host_info]", f.lastAppFacet)
	}
	if f.lastAppSort != "name.asc" {
		t.Errorf("sort = %q", f.lastAppSort)
	}
}

// TestSearchApplicationsCustomLimit verifies a caller-supplied limit overrides
// the default.
func TestSearchApplicationsCustomLimit(t *testing.T) {
	t.Parallel()

	f := &fakeDiscover{appsResp: appsOK()}
	m := &Module{API: f, Logger: testLogger}

	if _, _, err := m.searchApplications(context.Background(), nil, ApplicationsInput{Filter: "name:'Chrome'", Limit: 250}); err != nil {
		t.Fatalf("searchApplications: %v", err)
	}
	if f.lastAppLimit != 250 {
		t.Errorf("limit = %d, want 250", f.lastAppLimit)
	}
}

func TestSearchApplicationsEmpty(t *testing.T) {
	t.Parallel()

	f := &fakeDiscover{appsResp: appsOK()}
	m := &Module{API: f, Logger: testLogger}

	_, out, err := m.searchApplications(context.Background(), nil, ApplicationsInput{Filter: "name:'DoesNotExist'"})
	if err != nil {
		t.Fatalf("searchApplications: %v", err)
	}
	if out.Resources == nil || len(out.Resources) != 0 {
		t.Fatalf("expected empty non-nil resources, got %+v", out)
	}
}

func TestSearchApplicationsFQLError(t *testing.T) {
	t.Parallel()

	badReq := &discover.CombinedApplicationsBadRequest{
		Payload: &models.MsaspecResponseFields{
			Errors: []*models.MsaAPIError{{Code: i32(400), Message: str("invalid filter")}},
		},
	}
	f := &fakeDiscover{appsErr: badReq}
	m := &Module{API: f, Logger: testLogger}

	_, out, err := m.searchApplications(context.Background(), nil, ApplicationsInput{Filter: "bogus::"})
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

// TestSearchApplicationsAPIError verifies a non-FQL error (not a typed
// *CombinedApplicationsBadRequest) is returned as a hard Go error rather than
// swallowed into a soft FQL result. This exercises the base.APIError branch,
// which the FQL-error tests bypass.
func TestSearchApplicationsAPIError(t *testing.T) {
	t.Parallel()

	f := &fakeDiscover{appsErr: errors.New("boom")}
	m := &Module{API: f, Logger: testLogger}

	_, _, err := m.searchApplications(context.Background(), nil, ApplicationsInput{Filter: "name:'Chrome'"})
	if err == nil {
		t.Fatalf("expected non-FQL error to be returned as a Go error")
	}
}

func TestSearchUnmanagedAssetsSuccess(t *testing.T) {
	t.Parallel()

	f := &fakeDiscover{hostsResp: hostsOK(&models.DomainDiscoverAPIHost{ID: str("host-1"), Hostname: "PC-001"})}
	f.hostsResp.Payload.Meta = &models.DomainDiscoverAPIMetaInfo{}
	m := &Module{API: f, Logger: testLogger}

	_, out, err := m.searchUnmanagedAssets(context.Background(), nil, UnmanagedAssetsInput{Filter: "platform_name:'Windows'"})
	if err != nil {
		t.Fatalf("searchUnmanagedAssets: %v", err)
	}
	if len(out.Resources) != 1 {
		t.Fatalf("unexpected result: %+v", out)
	}
	if out.Resources[0].Hostname != "PC-001" {
		t.Fatalf("unexpected resource: %+v", out.Resources[0])
	}
	if !reflect.DeepEqual(out.Meta, base.NormalizedMeta(f.hostsResp.Payload.Meta)) {
		t.Fatalf("expected normalized meta, got %+v", out.Meta)
	}
}

// TestSearchUnmanagedAssetsAlwaysConstrainsUnmanaged verifies the tool prepends
// entity_type:'unmanaged' and ANDs the parenthesized user filter, both when a
// user filter is present and when it is absent. The comma cases cover the
// scope-escape regression: an unparenthesized caller filter with a top-level
// comma would bind as (scope AND a) OR b and return managed hosts.
func TestSearchUnmanagedAssetsAlwaysConstrainsUnmanaged(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		userFilter string
		wantFilter string
	}{
		{"with user filter", "platform_name:'Windows'", "entity_type:'unmanaged'+(platform_name:'Windows')"},
		{"no user filter", "", "entity_type:'unmanaged'"},
		{
			"top-level comma stays scoped",
			"platform_name:'Windows',entity_type:'managed'",
			"entity_type:'unmanaged'+(platform_name:'Windows',entity_type:'managed')",
		},
		{
			"quoted parens are not grouping",
			"hostname:'foo)bar'",
			"entity_type:'unmanaged'+(hostname:'foo)bar')",
		},
		{
			"balanced group passes through",
			"platform_name:'Windows'+(criticality:'Critical',criticality:'High')",
			"entity_type:'unmanaged'+(platform_name:'Windows'+(criticality:'Critical',criticality:'High'))",
		},
		{
			"nested groups",
			"((platform_name:'Windows'))",
			"entity_type:'unmanaged'+(((platform_name:'Windows')))",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := &fakeDiscover{hostsResp: hostsOK()}
			m := &Module{API: f, Logger: testLogger}

			_, out, err := m.searchUnmanagedAssets(context.Background(), nil, UnmanagedAssetsInput{Filter: tc.userFilter})
			if err != nil {
				t.Fatalf("searchUnmanagedAssets: %v", err)
			}
			if f.lastHostFilter != tc.wantFilter {
				t.Errorf("API filter = %q, want %q", f.lastHostFilter, tc.wantFilter)
			}
			if out.FilterUsed != tc.wantFilter {
				t.Errorf("FilterUsed = %q, want %q", out.FilterUsed, tc.wantFilter)
			}
		})
	}
}

// TestSearchUnmanagedAssetsForwardsParams verifies the handler defaults the
// limit and forwards sort to the API params.
func TestSearchUnmanagedAssetsForwardsParams(t *testing.T) {
	t.Parallel()

	f := &fakeDiscover{hostsResp: hostsOK()}
	m := &Module{API: f, Logger: testLogger}

	if _, _, err := m.searchUnmanagedAssets(context.Background(), nil, UnmanagedAssetsInput{Sort: "hostname.asc"}); err != nil {
		t.Fatalf("searchUnmanagedAssets: %v", err)
	}
	if f.lastHostLimit != defaultLimit {
		t.Errorf("limit = %d, want default %d", f.lastHostLimit, defaultLimit)
	}
	if f.lastHostSort != "hostname.asc" {
		t.Errorf("sort = %q", f.lastHostSort)
	}
}

func TestSearchUnmanagedAssetsEmpty(t *testing.T) {
	t.Parallel()

	f := &fakeDiscover{hostsResp: hostsOK()}
	m := &Module{API: f, Logger: testLogger}

	_, out, err := m.searchUnmanagedAssets(context.Background(), nil, UnmanagedAssetsInput{})
	if err != nil {
		t.Fatalf("searchUnmanagedAssets: %v", err)
	}
	if out.Resources == nil || len(out.Resources) != 0 {
		t.Fatalf("expected empty non-nil resources, got %+v", out)
	}
}

func TestSearchUnmanagedAssetsFQLError(t *testing.T) {
	t.Parallel()

	badReq := &discover.CombinedHostsBadRequest{
		Payload: &models.MsaspecResponseFields{
			Errors: []*models.MsaAPIError{{Code: i32(400), Message: str("invalid filter")}},
		},
	}
	f := &fakeDiscover{hostsErr: badReq}
	m := &Module{API: f, Logger: testLogger}

	_, out, err := m.searchUnmanagedAssets(context.Background(), nil, UnmanagedAssetsInput{Filter: "bogus::"})
	if err != nil {
		t.Fatalf("expected soft FQL error result, got Go error: %v", err)
	}
	if len(out.Errors) != 1 || out.Errors[0].Message != "invalid filter" {
		t.Fatalf("expected FQL error detail, got %+v", out.Errors)
	}
	if out.FQLGuide == "" {
		t.Fatalf("expected FQL guide in error result")
	}
	// The echoed filter includes the auto-applied unmanaged constraint.
	if out.FilterUsed != "entity_type:'unmanaged'+(bogus::)" {
		t.Fatalf("expected combined filter echoed, got %q", out.FilterUsed)
	}
}

// TestSearchUnmanagedAssetsMalformedFilterSoftError verifies a caller filter
// with unbalanced parentheses or an unterminated quote is rejected client-side
// instead of being wrapped, and that the rejection is reported as a soft FQL
// result carrying the guide rather than a hard Go error, matching the shape of
// an API-rejected filter so the model can self-correct either way.
//
// The stray-) case is the security-relevant one: wrapping alone would not
// contain it, because the stray ) closes the wrapping group early and lets the
// following top-level , escape the scope clause and return managed hosts. The
// API accepts that shape with HTTP 200 and the widened result set, so it must be
// caught here. The remaining cases the API would itself reject with a 400; they
// are rejected here to keep the paren-depth model sound.
func TestSearchUnmanagedAssetsMalformedFilterSoftError(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		userFilter string
	}{
		{"scope escape via stray close", "platform_name:'Windows'),entity_type:'managed'+(product_type_desc:'Server'"},
		{"unmatched close", "platform_name:'Windows')"},
		{"unclosed open", "(platform_name:'Windows'"},
		{"unterminated quote", "hostname:'foo"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := &fakeDiscover{hostsResp: hostsOK()}
			m := &Module{API: f, Logger: testLogger}

			_, out, err := m.searchUnmanagedAssets(context.Background(), nil, UnmanagedAssetsInput{Filter: tc.userFilter})
			if err != nil {
				t.Fatalf("expected soft FQL error result, got Go error: %v", err)
			}
			if len(out.Errors) != 1 {
				t.Fatalf("expected one FQL error detail, got %+v", out.Errors)
			}
			if out.FQLGuide == "" {
				t.Errorf("expected FQL guide so the caller can self-correct")
			}
			// No request was made, so the echoed filter is the caller's raw
			// input rather than a combined filter that was never built.
			if out.FilterUsed != tc.userFilter {
				t.Errorf("FilterUsed = %q, want raw caller filter %q", out.FilterUsed, tc.userFilter)
			}
			if f.hostCalls != 0 {
				t.Errorf("API called %d times, want 0 — malformed filter must not reach the API", f.hostCalls)
			}
		})
	}
}

// TestScopedFilter exercises filter scoping directly, covering the accept path
// where paren depth rises and returns to zero (which the handler tests reach
// only incidentally) alongside each rejection class. Rejections must surface
// errInvalidFilter and must not return a filter.
func TestScopedFilter(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		filter     string
		wantFilter string
		wantErr    bool
	}{
		{"empty", "", "entity_type:'unmanaged'", false},
		{"simple term", "platform_name:'Windows'", "entity_type:'unmanaged'+(platform_name:'Windows')", false},
		{"balanced group", "a:'1'+(b:'2',c:'3')", "entity_type:'unmanaged'+(a:'1'+(b:'2',c:'3'))", false},
		{"nested groups", "((a:'1'))", "entity_type:'unmanaged'+(((a:'1')))", false},
		{"parens inside quotes", "hostname:'foo)bar'", "entity_type:'unmanaged'+(hostname:'foo)bar')", false},
		{"unmatched close", "a:'1')", "", true},
		{"unclosed open", "(a:'1'", "", true},
		{"unterminated quote", "hostname:'foo", "", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := scopedFilter(tc.filter)
			if tc.wantErr {
				if !errors.Is(err, errInvalidFilter) {
					t.Fatalf("err = %v, want errInvalidFilter", err)
				}
				if got != "" {
					t.Errorf("filter = %q, want empty on rejection", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("scopedFilter(%q) = %v, want nil", tc.filter, err)
			}
			if got != tc.wantFilter {
				t.Errorf("filter = %q, want %q", got, tc.wantFilter)
			}
		})
	}
}

// FuzzScopedFilterCannotEscapeScope asserts the property the parenthesizing
// exists to guarantee: any filter scopedFilter accepts produces a combined
// filter with no comma at paren depth 0. A top-level comma is the escape, since
// FQL's , (OR) binds looser than + (AND), so "scope+a,b" groups as
// (scope AND a) OR b and the second branch carries no scope term.
//
// The caller filter is model-supplied and untrusted, so this covers the input
// space the table tests above can only sample.
func FuzzScopedFilterCannotEscapeScope(f *testing.F) {
	seeds := []string{
		"",
		"platform_name:'Windows'",
		"platform_name:'Windows',entity_type:'managed'",
		"platform_name:'Windows'),entity_type:'managed'+(a:'1'",
		"hostname:'foo)bar'",
		"((a:'1'))",
		"a:'),b+('c",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, userFilter string) {
		got, err := scopedFilter(userFilter)
		if err != nil {
			return // rejected: no filter reaches the API
		}
		if hasTopLevelComma(got) {
			t.Fatalf("scope escape: filter %q accepted, built %q with a top-level comma", userFilter, got)
		}
		if !strings.HasPrefix(got, unmanagedFilter) {
			t.Fatalf("built filter %q lost the scope clause", got)
		}
	})
}

// hasTopLevelComma reports whether s contains a , at paren depth 0, ignoring
// single-quoted values. It is deliberately written independently of
// checkFilterSyntax so the fuzz target does not assert a function against its
// own logic.
func hasTopLevelComma(s string) bool {
	depth, quoted := 0, false
	for _, r := range s {
		if r == '\'' {
			quoted = !quoted
			continue
		}
		if quoted {
			continue
		}
		switch r {
		case '(':
			depth++
		case ')':
			depth--
		case ',':
			if depth == 0 {
				return true
			}
		}
	}
	return false
}

// TestSearchUnmanagedAssetsAPIError verifies a non-FQL error is returned as a
// hard Go error rather than swallowed into a soft FQL result, exercising the
// base.APIError branch the FQL-error test bypasses.
func TestSearchUnmanagedAssetsAPIError(t *testing.T) {
	t.Parallel()

	f := &fakeDiscover{hostsErr: errors.New("boom")}
	m := &Module{API: f, Logger: testLogger}

	_, _, err := m.searchUnmanagedAssets(context.Background(), nil, UnmanagedAssetsInput{Filter: "platform_name:'Windows'"})
	if err == nil {
		t.Fatalf("expected non-FQL error to be returned as a Go error")
	}
}

// TestSearchEmitsDebugLog verifies the injected logger receives a structured
// DEBUG entry for each search tool carrying the filter the handler actually
// used. The unmanaged-assets case asserts the logged filter is the combined
// entity_type:'unmanaged'+... form, not the raw user filter, so a regression
// that logs in.Filter instead of the composed filter would fail here.
func TestSearchEmitsDebugLog(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	f := &fakeDiscover{appsResp: appsOK(), hostsResp: hostsOK()}
	m := &Module{API: f, Logger: logger}

	if _, _, err := m.searchApplications(context.Background(), nil, ApplicationsInput{Filter: "name:'Chrome'"}); err != nil {
		t.Fatalf("searchApplications: %v", err)
	}
	if _, _, err := m.searchUnmanagedAssets(context.Background(), nil, UnmanagedAssetsInput{Filter: "platform_name:'Windows'"}); err != nil {
		t.Fatalf("searchUnmanagedAssets: %v", err)
	}

	// Expected logged filter value per tool message. search_unmanaged_assets logs
	// the composed filter, not the raw user input.
	wantFilters := map[string]string{
		"search_applications":     "name:'Chrome'",
		"search_unmanaged_assets": "entity_type:'unmanaged'+(platform_name:'Windows')",
	}
	seen := map[string]bool{}
	for line := range strings.SplitSeq(strings.TrimSpace(buf.String()), "\n") {
		var rec map[string]any
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("log line not JSON: %q: %v", line, err)
		}
		if rec["level"] != "DEBUG" {
			continue
		}
		msg, ok := rec["msg"].(string)
		if !ok {
			continue
		}
		want, tracked := wantFilters[msg]
		if !tracked {
			continue
		}
		seen[msg] = true
		if rec["filter"] != want {
			t.Errorf("DEBUG %q filter = %v, want %q", msg, rec["filter"], want)
		}
	}
	for msg := range wantFilters {
		if !seen[msg] {
			t.Errorf("no DEBUG %q log emitted; got:\n%s", msg, buf.String())
		}
	}
}
