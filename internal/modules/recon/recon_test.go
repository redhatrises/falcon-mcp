package recon

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/crowdstrike/gofalcon/falcon/client/recon"
	"github.com/crowdstrike/gofalcon/falcon/models"

	"github.com/crowdstrike/falcon-mcp/internal/modules/base"
	"github.com/crowdstrike/falcon-mcp/internal/testutil"
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

var testLogger = testutil.DiscardLogger()

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

	notifAggResp *recon.AggregateNotificationsV1OK
	notifAggErr  error
	notifAggBody []*models.MsaAggregateQueryRequest

	edrAggResp *recon.AggregateNotificationsExposedDataRecordsV1OK
	edrAggErr  error

	previewResp *recon.PreviewRuleV1OK
	previewErr  error
	previewBody *models.DomainRulePreviewRequest
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

func (f *fakeRecon) AggregateNotificationsV1(p *recon.AggregateNotificationsV1Params, _ ...recon.ClientOption) (*recon.AggregateNotificationsV1OK, error) {
	f.notifAggBody = p.Body
	return f.notifAggResp, f.notifAggErr
}

func (f *fakeRecon) AggregateNotificationsExposedDataRecordsV1(*recon.AggregateNotificationsExposedDataRecordsV1Params, ...recon.ClientOption) (*recon.AggregateNotificationsExposedDataRecordsV1OK, error) {
	return f.edrAggResp, f.edrAggErr
}

func (f *fakeRecon) PreviewRuleV1(p *recon.PreviewRuleV1Params, _ ...recon.ClientOption) (*recon.PreviewRuleV1OK, error) {
	f.previewBody = p.Body
	return f.previewResp, f.previewErr
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
			Meta:      &models.MsaMetaInfo{QueryTime: &metaQueryTime},
		}},
		notifGetResp: &recon.GetNotificationsDetailedV1OK{Payload: &models.DomainNotificationDetailsResponseV1{
			// Returned out of query order to exercise reordering by id.
			Resources: []*models.DomainDetailedNotificationV1{
				{ID: new("n2")},
				{ID: new("n1")},
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
	testutil.AssertNormalizedMeta(t, out.Meta, f.notifQueryResp.Payload.Meta)
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
		Errors: []*models.DomainReconAPIError{{Code: new(int32(400)), Message: new("invalid filter")}},
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

	f := &fakeRecon{notifQueryErr: testutil.StatusErr(403)}
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
			Resources: []*models.SadomainRule{{ID: new("r1")}},
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
	testutil.AssertNormalizedMeta(t, out.Meta, f.rulesQueryResp.Payload.Meta)
}

func TestSearchRulesFQLError(t *testing.T) {
	t.Parallel()

	badReq := &recon.QueryRulesV1BadRequest{Payload: &models.DomainErrorsOnly{
		Errors: []*models.DomainReconAPIError{{Code: new(int32(400)), Message: new("bad rule filter")}},
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
			Meta:      &models.MsaMetaInfo{QueryTime: &metaQueryTime},
		}},
		edrGetResp: &recon.GetNotificationsExposedDataRecordsV1OK{Payload: &models.APINotificationExposedDataRecordEntitiesResponseV1{
			Resources: []*models.APINotificationExposedDataRecordV1{
				{ID: new("e1")},
				{ID: new("e2")},
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
	testutil.AssertNormalizedMeta(t, out.Meta, f.edrQueryResp.Payload.Meta)
}

func TestSearchExposedDataRecordsFQLError(t *testing.T) {
	t.Parallel()

	badReq := &recon.QueryNotificationsExposedDataRecordsV1BadRequest{Payload: &models.DomainErrorsOnly{
		Errors: []*models.DomainReconAPIError{{Code: new(int32(400)), Message: new("bad edr filter")}},
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

// --- aggregate + preview ---

func TestAggregateNotificationsSuccess(t *testing.T) {
	t.Parallel()

	f := &fakeRecon{notifAggResp: &recon.AggregateNotificationsV1OK{Payload: &models.DomainAggregatesResponse{
		Resources: []*models.DomainAggregationResult{{
			Name:    new("status"),
			Buckets: []*models.DomainAggregationResultItem{{Label: "new", Count: new(int64(7))}},
		}},
	}}}
	m := newModule(f)

	_, out, err := m.aggregateNotifications(context.Background(), nil, AggregateInput{Field: "status"})
	if err != nil {
		t.Fatalf("aggregateNotifications: %v", err)
	}
	if len(out.Resources) != 1 || *out.Resources[0].Name != "status" {
		t.Fatalf("unexpected resources %+v", out.Resources)
	}
	// The type defaults to terms, so the request body carries that.
	if len(f.notifAggBody) != 1 || f.notifAggBody[0].Type == nil || *f.notifAggBody[0].Type != base.AggregateTypeDefault {
		t.Fatalf("expected terms aggregate body, got %+v", f.notifAggBody)
	}
	if *f.notifAggBody[0].Field != "status" {
		t.Fatalf("field = %q, want status", *f.notifAggBody[0].Field)
	}
}

func TestAggregateNotificationsCompanionHint(t *testing.T) {
	t.Parallel()

	f := &fakeRecon{}
	m := newModule(f)

	// date_histogram without an interval must be caught before any API call.
	_, out, err := m.aggregateNotifications(context.Background(), nil, AggregateInput{Field: "created_date", Type: "date_histogram"})
	if err != nil {
		t.Fatalf("aggregateNotifications: %v", err)
	}
	if out.Hint == "" {
		t.Fatalf("expected companion hint for date_histogram without interval, got %+v", out)
	}
	if f.notifAggBody != nil {
		t.Fatalf("expected no API call when the request is incomplete, got body %+v", f.notifAggBody)
	}
}

func TestAggregateNotificationsFQLError(t *testing.T) {
	t.Parallel()

	badReq := &recon.AggregateNotificationsV1BadRequest{Payload: &models.DomainErrorsOnly{
		Errors: []*models.DomainReconAPIError{{Code: new(int32(400)), Message: new("invalid filter expression")}},
	}}
	f := &fakeRecon{notifAggErr: badReq}
	m := newModule(f)

	_, out, err := m.aggregateNotifications(context.Background(), nil, AggregateInput{Field: "status", Filter: "bogus::"})
	if err != nil {
		t.Fatalf("expected data result for FQL error, got Go error: %v", err)
	}
	if len(out.Errors) != 1 || out.Errors[0].Message != "invalid filter expression" {
		t.Fatalf("expected surfaced FQL error detail, got %+v", out.Errors)
	}
	if out.FQLGuide == "" {
		t.Errorf("expected FQL guide inline in error response")
	}
}

func TestAggregateNotificationsNonFilterBadRequestSurfacesRaw(t *testing.T) {
	t.Parallel()

	// A 400 that blames something other than the filter is a real error, not a
	// soft FQL result.
	badReq := &recon.AggregateNotificationsV1BadRequest{Payload: &models.DomainErrorsOnly{
		Errors: []*models.DomainReconAPIError{{Code: new(int32(400)), Message: new("field is not aggregatable")}},
	}}
	f := &fakeRecon{notifAggErr: badReq}
	m := newModule(f)

	_, _, err := m.aggregateNotifications(context.Background(), nil, AggregateInput{Field: "bogus"})
	if err == nil {
		t.Fatal("expected a Go error for a non-filter 400, got nil")
	}
}

func TestAggregateExposedDataRecordsSuccess(t *testing.T) {
	t.Parallel()

	f := &fakeRecon{edrAggResp: &recon.AggregateNotificationsExposedDataRecordsV1OK{Payload: &models.DomainAggregatesResponse{
		Resources: []*models.DomainAggregationResult{{Name: new("credential_status")}},
	}}}
	m := newModule(f)

	_, out, err := m.aggregateExposedDataRecords(context.Background(), nil, AggregateInput{Field: "credential_status"})
	if err != nil {
		t.Fatalf("aggregateExposedDataRecords: %v", err)
	}
	if len(out.Resources) != 1 || *out.Resources[0].Name != "credential_status" {
		t.Fatalf("unexpected resources %+v", out.Resources)
	}
}

func TestAggregateExposedDataRecordsFQLError(t *testing.T) {
	t.Parallel()

	badReq := &recon.AggregateNotificationsExposedDataRecordsV1BadRequest{Payload: &models.DomainErrorsOnly{
		Errors: []*models.DomainReconAPIError{{Code: new(int32(400)), Message: new("bad filter")}},
	}}
	f := &fakeRecon{edrAggErr: badReq}
	m := newModule(f)

	_, out, err := m.aggregateExposedDataRecords(context.Background(), nil, AggregateInput{Field: "site", Filter: "bogus::"})
	if err != nil {
		t.Fatalf("expected data result for FQL error, got Go error: %v", err)
	}
	if len(out.Errors) != 1 || out.Errors[0].Message != "bad filter" {
		t.Fatalf("expected surfaced FQL error detail, got %+v", out.Errors)
	}
}

func TestAggregateExposedDataRecordsNonFilterBadRequestSurfacesRaw(t *testing.T) {
	t.Parallel()

	// A 400 that blames something other than the filter is a real error, not a
	// soft FQL result.
	badReq := &recon.AggregateNotificationsExposedDataRecordsV1BadRequest{Payload: &models.DomainErrorsOnly{
		Errors: []*models.DomainReconAPIError{{Code: new(int32(400)), Message: new("field is not aggregatable")}},
	}}
	f := &fakeRecon{edrAggErr: badReq}
	m := newModule(f)

	_, _, err := m.aggregateExposedDataRecords(context.Background(), nil, AggregateInput{Field: "bogus"})
	if err == nil {
		t.Fatal("expected a Go error for a non-filter 400, got nil")
	}
}

func TestPreviewRuleSuccess(t *testing.T) {
	t.Parallel()

	f := &fakeRecon{previewResp: &recon.PreviewRuleV1OK{Payload: &models.DomainAggregatesResponse{
		Resources: []*models.DomainAggregationResult{{Name: new("preview")}},
	}}}
	m := newModule(f)

	_, out, err := m.previewRule(context.Background(), nil, PreviewInput{Filter: "example.com", Topic: "SA_DOMAIN", LookbackDays: 30})
	if err != nil {
		t.Fatalf("previewRule: %v", err)
	}
	if len(out.Resources) != 1 {
		t.Fatalf("expected 1 resource, got %+v", out.Resources)
	}
	if f.previewBody == nil || f.previewBody.Filter == nil || *f.previewBody.Filter != "example.com" {
		t.Fatalf("filter not passed through: %+v", f.previewBody)
	}
	if *f.previewBody.Topic != "SA_DOMAIN" {
		t.Fatalf("topic = %q, want SA_DOMAIN", *f.previewBody.Topic)
	}
	if f.previewBody.LookbackDays != 30 {
		t.Fatalf("lookback_days = %d, want 30", f.previewBody.LookbackDays)
	}
}

func TestPreviewRuleOmitsUnsetLookback(t *testing.T) {
	t.Parallel()

	f := &fakeRecon{previewResp: &recon.PreviewRuleV1OK{Payload: &models.DomainAggregatesResponse{}}}
	m := newModule(f)

	if _, _, err := m.previewRule(context.Background(), nil, PreviewInput{Filter: "x", Topic: "SA_EMAIL"}); err != nil {
		t.Fatalf("previewRule: %v", err)
	}
	if f.previewBody.LookbackDays != 0 {
		t.Fatalf("expected lookback_days unset (0), got %d", f.previewBody.LookbackDays)
	}
}

func TestPreviewRuleFQLError(t *testing.T) {
	t.Parallel()

	badReq := &recon.PreviewRuleV1BadRequest{Payload: &models.DomainErrorsOnly{
		Errors: []*models.DomainReconAPIError{{Code: new(int32(400)), Message: new("invalid filter")}},
	}}
	f := &fakeRecon{previewErr: badReq}
	m := newModule(f)

	_, out, err := m.previewRule(context.Background(), nil, PreviewInput{Filter: "bogus::", Topic: "SA_DOMAIN"})
	if err != nil {
		t.Fatalf("expected data result for FQL error, got Go error: %v", err)
	}
	if len(out.Errors) != 1 || out.Errors[0].Message != "invalid filter" {
		t.Fatalf("expected surfaced FQL error detail, got %+v", out.Errors)
	}
}

// --- registration ---

func TestRegisterToolsAnnotations(t *testing.T) {
	t.Parallel()

	byName := testutil.CollectTools(newModule(&fakeRecon{}))

	names := []string{
		"falcon_search_recon_notifications",
		"falcon_search_recon_rules",
		"falcon_search_recon_exposed_data_records",
		"falcon_aggregate_recon_notifications",
		"falcon_aggregate_recon_exposed_data_records",
		"falcon_preview_recon_rule",
	}
	if len(byName) != len(names) {
		t.Fatalf("expected %d tools, got %d", len(names), len(byName))
	}
	for _, n := range names {
		tool := byName[n]
		if tool == nil {
			t.Fatalf("missing %s", n)
		}
		testutil.AssertReadOnlyAnnotations(t, n, tool.Annotations)
	}
}

func TestRegisterResourcesServesFQLGuides(t *testing.T) {
	t.Parallel()

	testutil.AssertServesFQLGuide(context.Background(), t,
		newModule(&fakeRecon{}).RegisterResources,
		testutil.FQLGuideExpectation{Name: "falcon_search_recon_notifications_fql_guide", URI: notificationsFQLGuideURI, Body: notificationsFQLGuide},
		testutil.FQLGuideExpectation{Name: "falcon_search_recon_rules_fql_guide", URI: rulesFQLGuideURI, Body: rulesFQLGuide},
		testutil.FQLGuideExpectation{Name: "falcon_search_recon_exposed_data_records_fql_guide", URI: exposedDataRecordsFQLGuideURI, Body: exposedDataRecordsFQLGuide},
		testutil.FQLGuideExpectation{Name: "falcon_preview_recon_rule_guide", URI: previewRuleFQLGuideURI, Body: previewRuleFQLGuide},
	)
}
