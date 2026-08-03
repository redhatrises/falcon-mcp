package recon

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"reflect"
	"testing"

	"github.com/crowdstrike/gofalcon/falcon/client/recon"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/go-openapi/runtime"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/crowdstrike/falcon-mcp/internal/modules/base"
)

// metaQueryTime is a non-zero query_time for test fakes, so a handler's
// normalized meta is a populated value rather than nil.
var metaQueryTime = 0.02

// The rules endpoint's monitoring-rule allowance, in the shape the live API
// reports it. Pending is genuinely zero, so the handler exercises a real zero
// rather than only populated fields. The projected JSON is asserted in
// base.TestNormalizeMetaRealTypes.
var (
	quotaTotal   = int32(500)
	quotaActive  = int32(371)
	quotaPending = int32(0)
)

// testLogger discards output; modules require a non-nil logger.
var testLogger = slog.New(slog.DiscardHandler)

func str(s string) *string { return &s }
func i32(v int32) *int32   { return &v }

// fakeRecon is a configurable test double for the reconAPI interface. Each
// operation records its call count and returns the preconfigured response/error.
type fakeRecon struct {
	notifQueryResp *recon.QueryNotificationsV1OK
	notifQueryErr  error
	notifGetResp   *recon.GetNotificationsDetailedV1OK
	notifGetCalls  int
	notifGetIDs    []string

	rulesQueryResp *recon.QueryRulesV1OK
	rulesQueryErr  error
	rulesGetResp   *recon.GetRulesV1OK
	rulesGetCalls  int

	edrQueryResp *recon.QueryNotificationsExposedDataRecordsV1OK
	edrQueryErr  error
	edrGetResp   *recon.GetNotificationsExposedDataRecordsV1OK
	edrGetCalls  int
}

func (f *fakeRecon) QueryNotificationsV1(*recon.QueryNotificationsV1Params, ...recon.ClientOption) (*recon.QueryNotificationsV1OK, error) {
	return f.notifQueryResp, f.notifQueryErr
}

func (f *fakeRecon) GetNotificationsDetailedV1(p *recon.GetNotificationsDetailedV1Params, _ ...recon.ClientOption) (*recon.GetNotificationsDetailedV1OK, error) {
	f.notifGetCalls++
	f.notifGetIDs = p.Ids
	return f.notifGetResp, nil
}

func (f *fakeRecon) QueryRulesV1(*recon.QueryRulesV1Params, ...recon.ClientOption) (*recon.QueryRulesV1OK, error) {
	return f.rulesQueryResp, f.rulesQueryErr
}

func (f *fakeRecon) GetRulesV1(*recon.GetRulesV1Params, ...recon.ClientOption) (*recon.GetRulesV1OK, error) {
	f.rulesGetCalls++
	return f.rulesGetResp, nil
}

func (f *fakeRecon) QueryNotificationsExposedDataRecordsV1(*recon.QueryNotificationsExposedDataRecordsV1Params, ...recon.ClientOption) (*recon.QueryNotificationsExposedDataRecordsV1OK, error) {
	return f.edrQueryResp, f.edrQueryErr
}

func (f *fakeRecon) GetNotificationsExposedDataRecordsV1(*recon.GetNotificationsExposedDataRecordsV1Params, ...recon.ClientOption) (*recon.GetNotificationsExposedDataRecordsV1OK, error) {
	f.edrGetCalls++
	return f.edrGetResp, nil
}

func newModule(f *fakeRecon) *Module {
	return &Module{API: f, Concurrency: 4, Logger: testLogger}
}

// --- search_recon_notifications ---

func TestSearchNotificationsSuccess(t *testing.T) {
	t.Parallel()

	f := &fakeRecon{
		notifQueryResp: &recon.QueryNotificationsV1OK{Payload: &models.DomainQueryResponse{
			Resources: []string{"n1", "n2"},
			Meta:      &models.DomainMsaMetaInfo{QueryTime: &metaQueryTime},
		}},
		notifGetResp: &recon.GetNotificationsDetailedV1OK{Payload: &models.DomainNotificationDetailsResponseV1{
			// Returned out of query order to exercise reordering by id.
			Resources: []*models.DomainDetailedNotificationV1{
				{ID: str("n2")},
				{ID: str("n1")},
			},
		}},
	}
	m := newModule(f)

	_, out, err := m.searchReconNotifications(context.Background(), nil, NotificationsInput{Filter: "status:'new'"})
	if err != nil {
		t.Fatalf("searchReconNotifications: %v", err)
	}
	if f.notifGetCalls != 1 {
		t.Fatalf("expected 1 detail fetch, got %d", f.notifGetCalls)
	}
	if len(out.Resources) != 2 {
		t.Fatalf("expected 2 resources, got %+v", out)
	}
	// Reordered back to query order n1, n2.
	if got := *out.Resources[0].ID; got != "n1" {
		t.Errorf("first resource id = %q, want n1 (reordered to query order)", got)
	}
	if out.FilterUsed != "status:'new'" {
		t.Errorf("FilterUsed = %q", out.FilterUsed)
	}
	if !reflect.DeepEqual(out.Meta, base.NormalizedMeta(f.notifQueryResp.Payload.Meta)) {
		t.Fatalf("expected normalized meta, got %+v", out.Meta)
	}
}

func TestSearchNotificationsEmpty(t *testing.T) {
	t.Parallel()

	f := &fakeRecon{notifQueryResp: &recon.QueryNotificationsV1OK{Payload: &models.DomainQueryResponse{
		Resources: []string{},
	}}}
	m := newModule(f)

	_, out, err := m.searchReconNotifications(context.Background(), nil, NotificationsInput{Filter: "status:'new'"})
	if err != nil {
		t.Fatalf("searchReconNotifications: %v", err)
	}
	if len(out.Resources) != 0 {
		t.Fatalf("expected empty result, got %+v", out)
	}
	if out.Resources == nil {
		t.Fatalf("resources must be a non-nil empty slice for stable JSON array output")
	}
	if f.notifGetCalls != 0 {
		t.Fatalf("expected no detail fetch on empty result, got %d", f.notifGetCalls)
	}
}

func TestSearchNotificationsFQLError(t *testing.T) {
	t.Parallel()

	badReq := &recon.QueryNotificationsV1BadRequest{Payload: &models.DomainErrorsOnly{
		Errors: []*models.DomainReconAPIError{{Code: i32(400), Message: str("invalid filter")}},
	}}
	f := &fakeRecon{notifQueryErr: badReq}
	m := newModule(f)

	_, out, err := m.searchReconNotifications(context.Background(), nil, NotificationsInput{Filter: "bogus::"})
	if err != nil {
		t.Fatalf("expected data result for FQL error, got Go error: %v", err)
	}
	if len(out.Errors) != 1 || out.Errors[0].Code != 400 || out.Errors[0].Message != "invalid filter" {
		t.Fatalf("expected surfaced FQL error detail, got %+v", out.Errors)
	}
	if out.FQLGuide == "" {
		t.Errorf("expected FQL guide inline in error response")
	}
	if f.notifGetCalls != 0 {
		t.Errorf("expected no detail fetch after FQL error, got %d", f.notifGetCalls)
	}
}

func TestSearchNotificationsPropagatesForbidden(t *testing.T) {
	t.Parallel()

	f := &fakeRecon{notifQueryErr: forbiddenErr{}}
	m := newModule(f)

	_, _, err := m.searchReconNotifications(context.Background(), nil, NotificationsInput{})
	var apiErr *base.Error
	if !errors.As(err, &apiErr) {
		t.Fatalf("expected *base.Error, got %v", err)
	}
	if apiErr.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", apiErr.StatusCode)
	}
	want := "Monitoring rules (Falcon Intelligence Recon):read"
	if len(apiErr.RequiredScopes) != 1 || apiErr.RequiredScopes[0] != want {
		t.Fatalf("required scopes = %v, want [%q]", apiErr.RequiredScopes, want)
	}
}

// --- search_recon_rules ---

func TestSearchRulesSuccess(t *testing.T) {
	t.Parallel()

	f := &fakeRecon{
		rulesQueryResp: &recon.QueryRulesV1OK{Payload: &models.DomainRuleQueryResponseV1{
			Resources: []string{"r1"},
			Meta: &models.DomainRuleMetaInfo{
				QueryTime: &metaQueryTime,
				Quota:     &models.DomainRuleQuota{Total: &quotaTotal, Active: &quotaActive, Pending: &quotaPending},
			},
		}},
		rulesGetResp: &recon.GetRulesV1OK{Payload: &models.DomainRulesEntitiesResponseV1{
			Resources: []*models.SadomainRule{{ID: str("r1")}},
		}},
	}
	m := newModule(f)

	_, out, err := m.searchReconRules(context.Background(), nil, RulesInput{Filter: "status:'active'"})
	if err != nil {
		t.Fatalf("searchReconRules: %v", err)
	}
	if f.rulesGetCalls != 1 {
		t.Fatalf("expected 1 detail fetch, got %d", f.rulesGetCalls)
	}
	if len(out.Resources) != 1 || *out.Resources[0].ID != "r1" {
		t.Fatalf("unexpected result %+v", out)
	}
	if !reflect.DeepEqual(out.Meta, base.NormalizedMeta(f.rulesQueryResp.Payload.Meta)) {
		t.Fatalf("expected normalized meta, got %+v", out.Meta)
	}
}

func TestSearchRulesFQLError(t *testing.T) {
	t.Parallel()

	badReq := &recon.QueryRulesV1BadRequest{Payload: &models.DomainErrorsOnly{
		Errors: []*models.DomainReconAPIError{{Code: i32(400), Message: str("bad rule filter")}},
	}}
	f := &fakeRecon{rulesQueryErr: badReq}
	m := newModule(f)

	_, out, err := m.searchReconRules(context.Background(), nil, RulesInput{Filter: "bogus::"})
	if err != nil {
		t.Fatalf("expected data result for FQL error, got Go error: %v", err)
	}
	if len(out.Errors) != 1 || out.Errors[0].Message != "bad rule filter" {
		t.Fatalf("expected surfaced FQL error detail, got %+v", out.Errors)
	}
	if f.rulesGetCalls != 0 {
		t.Errorf("expected no detail fetch after FQL error, got %d", f.rulesGetCalls)
	}
}

// --- search_recon_exposed_data_records ---

func TestSearchExposedDataRecordsSuccess(t *testing.T) {
	t.Parallel()

	f := &fakeRecon{
		edrQueryResp: &recon.QueryNotificationsExposedDataRecordsV1OK{Payload: &models.DomainQueryResponse{
			Resources: []string{"e1", "e2"},
			Meta:      &models.DomainMsaMetaInfo{QueryTime: &metaQueryTime},
		}},
		edrGetResp: &recon.GetNotificationsExposedDataRecordsV1OK{Payload: &models.APINotificationExposedDataRecordEntitiesResponseV1{
			Resources: []*models.APINotificationExposedDataRecordV1{
				{ID: str("e1")},
				{ID: str("e2")},
			},
		}},
	}
	m := newModule(f)

	_, out, err := m.searchReconExposedDataRecords(context.Background(), nil, ExposedDataRecordsInput{Filter: "domain:'example.com'"})
	if err != nil {
		t.Fatalf("searchReconExposedDataRecords: %v", err)
	}
	if f.edrGetCalls != 1 {
		t.Fatalf("expected 1 detail fetch, got %d", f.edrGetCalls)
	}
	if len(out.Resources) != 2 {
		t.Fatalf("expected 2 resources, got %+v", out)
	}
	if !reflect.DeepEqual(out.Meta, base.NormalizedMeta(f.edrQueryResp.Payload.Meta)) {
		t.Fatalf("expected normalized meta, got %+v", out.Meta)
	}
}

func TestSearchExposedDataRecordsFQLError(t *testing.T) {
	t.Parallel()

	badReq := &recon.QueryNotificationsExposedDataRecordsV1BadRequest{Payload: &models.DomainErrorsOnly{
		Errors: []*models.DomainReconAPIError{{Code: i32(400), Message: str("bad edr filter")}},
	}}
	f := &fakeRecon{edrQueryErr: badReq}
	m := newModule(f)

	_, out, err := m.searchReconExposedDataRecords(context.Background(), nil, ExposedDataRecordsInput{Filter: "bogus::"})
	if err != nil {
		t.Fatalf("expected data result for FQL error, got Go error: %v", err)
	}
	if len(out.Errors) != 1 || out.Errors[0].Message != "bad edr filter" {
		t.Fatalf("expected surfaced FQL error detail, got %+v", out.Errors)
	}
	if f.edrGetCalls != 0 {
		t.Errorf("expected no detail fetch after FQL error, got %d", f.edrGetCalls)
	}
}

// --- registration ---

func TestRegisterToolsAnnotations(t *testing.T) {
	t.Parallel()

	var entries []base.ToolEntry
	reg := captureRegistrar(func(e base.ToolEntry) { entries = append(entries, e) })
	newModule(&fakeRecon{}).RegisterTools(reg)

	names := []string{
		"falcon_search_recon_notifications",
		"falcon_search_recon_rules",
		"falcon_search_recon_exposed_data_records",
	}
	if len(entries) != len(names) {
		t.Fatalf("expected %d tools, got %d", len(names), len(entries))
	}
	byName := map[string]*mcp.Tool{}
	for _, e := range entries {
		byName[e.Tool.Name] = e.Tool
	}
	for _, n := range names {
		tool := byName[n]
		if tool == nil {
			t.Fatalf("missing %s", n)
		}
		assertReadOnlyAnnotations(t, n, tool.Annotations)
	}
}

func TestRegisterResourcesServesFQLGuides(t *testing.T) {
	t.Parallel()

	srv := mcp.NewServer(&mcp.Implementation{Name: "test", Version: "test"}, nil)
	newModule(&fakeRecon{}).RegisterResources(srv)

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
		notificationsFQLGuideURI:      "falcon_search_recon_notifications_fql_guide",
		rulesFQLGuideURI:              "falcon_search_recon_rules_fql_guide",
		exposedDataRecordsFQLGuideURI: "falcon_search_recon_exposed_data_records_fql_guide",
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

// forbiddenErr is a gofalcon-style error reporting HTTP 403 via the go-openapi
// runtime.ClientResponseStatus interface that base.statusOf inspects.
type forbiddenErr struct{}

func (forbiddenErr) Error() string       { return "forbidden" }
func (forbiddenErr) Code() int           { return http.StatusForbidden }
func (forbiddenErr) IsCode(c int) bool   { return c == http.StatusForbidden }
func (forbiddenErr) IsSuccess() bool     { return false }
func (forbiddenErr) IsRedirect() bool    { return false }
func (forbiddenErr) IsClientError() bool { return true }
func (forbiddenErr) IsServerError() bool { return false }

var _ runtime.ClientResponseStatus = forbiddenErr{}
