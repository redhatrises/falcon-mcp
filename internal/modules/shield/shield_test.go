package shield

import (
	"context"
	"errors"
	"testing"

	"github.com/crowdstrike/gofalcon/falcon/client/saas_security"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/crowdstrike/falcon-mcp/internal/modules/base"
	"github.com/crowdstrike/falcon-mcp/internal/testutil"
)

var testLogger = testutil.DiscardLogger()

// fakeShield is a configurable test double for the shieldAPI interface. Each
// handler under test touches one method; the fake records the params it received
// so tests can assert on parameter mapping, and returns a preconfigured response
// or error.
type fakeShield struct {
	// captured params for assertions
	checksParams   *saas_security.GetSecurityChecksV3Params
	metricsParams  *saas_security.GetMetricsV3Params
	alertsParams   *saas_security.GetAlertsV3Params
	activityParams *saas_security.GetActivityMonitorV3Params
	dismissCheck   *saas_security.DismissSecurityCheckV3Params
	dismissEntity  *saas_security.DismissAffectedEntityV3Params

	// error to return from the next call (any method)
	err error

	// per-method responses (nil -> a minimal empty OK is synthesized)
	checksResp   *saas_security.GetSecurityChecksV3OK
	devicesResp  *saas_security.GetDeviceInventoryV3OK
	appsResp     *saas_security.GetAppInventoryOK
	appUsersResp *saas_security.GetAppInventoryUsersOK
	integResp    *saas_security.GetIntegrationsV3OK

	dismissCheckCalls  int
	dismissEntityCalls int
}

func (f *fakeShield) GetSecurityChecksV3(p *saas_security.GetSecurityChecksV3Params, _ ...saas_security.ClientOption) (*saas_security.GetSecurityChecksV3OK, error) {
	f.checksParams = p
	if f.err != nil {
		return nil, f.err
	}
	if f.checksResp != nil {
		return f.checksResp, nil
	}
	return &saas_security.GetSecurityChecksV3OK{Payload: &models.GetSecurityChecks{}}, nil
}

func (f *fakeShield) GetSecurityCheckAffectedV3(_ *saas_security.GetSecurityCheckAffectedV3Params, _ ...saas_security.ClientOption) (*saas_security.GetSecurityCheckAffectedV3OK, error) {
	if f.err != nil {
		return nil, f.err
	}
	return &saas_security.GetSecurityCheckAffectedV3OK{Payload: &models.GetAffected{}}, nil
}

func (f *fakeShield) GetSecurityCheckComplianceV3(_ *saas_security.GetSecurityCheckComplianceV3Params, _ ...saas_security.ClientOption) (*saas_security.GetSecurityCheckComplianceV3OK, error) {
	if f.err != nil {
		return nil, f.err
	}
	return &saas_security.GetSecurityCheckComplianceV3OK{Payload: &models.GetSecurityCompliance{}}, nil
}

func (f *fakeShield) GetMetricsV3(p *saas_security.GetMetricsV3Params, _ ...saas_security.ClientOption) (*saas_security.GetMetricsV3OK, error) {
	f.metricsParams = p
	if f.err != nil {
		return nil, f.err
	}
	return &saas_security.GetMetricsV3OK{Payload: &models.GetMetrics{}}, nil
}

func (f *fakeShield) GetAlertsV3(p *saas_security.GetAlertsV3Params, _ ...saas_security.ClientOption) (*saas_security.GetAlertsV3OK, error) {
	f.alertsParams = p
	if f.err != nil {
		return nil, f.err
	}
	return &saas_security.GetAlertsV3OK{Payload: &models.GetAlertsResponse{}}, nil
}

func (f *fakeShield) GetActivityMonitorV3(p *saas_security.GetActivityMonitorV3Params, _ ...saas_security.ClientOption) (*saas_security.GetActivityMonitorV3OK, error) {
	f.activityParams = p
	if f.err != nil {
		return nil, f.err
	}
	return &saas_security.GetActivityMonitorV3OK{Payload: &models.GetActivityMonitor{}}, nil
}

func (f *fakeShield) GetUserInventoryV3(_ *saas_security.GetUserInventoryV3Params, _ ...saas_security.ClientOption) (*saas_security.GetUserInventoryV3OK, error) {
	if f.err != nil {
		return nil, f.err
	}
	return &saas_security.GetUserInventoryV3OK{Payload: &models.GetUserInventory{}}, nil
}

func (f *fakeShield) GetDeviceInventoryV3(_ *saas_security.GetDeviceInventoryV3Params, _ ...saas_security.ClientOption) (*saas_security.GetDeviceInventoryV3OK, error) {
	if f.err != nil {
		return nil, f.err
	}
	if f.devicesResp != nil {
		return f.devicesResp, nil
	}
	return &saas_security.GetDeviceInventoryV3OK{Payload: &models.GetDeviceInventory{}}, nil
}

func (f *fakeShield) GetAppInventory(_ *saas_security.GetAppInventoryParams, _ ...saas_security.ClientOption) (*saas_security.GetAppInventoryOK, error) {
	if f.err != nil {
		return nil, f.err
	}
	if f.appsResp != nil {
		return f.appsResp, nil
	}
	return &saas_security.GetAppInventoryOK{Payload: &models.AppInventory{}}, nil
}

func (f *fakeShield) GetAppInventoryUsers(_ *saas_security.GetAppInventoryUsersParams, _ ...saas_security.ClientOption) (*saas_security.GetAppInventoryUsersOK, error) {
	if f.err != nil {
		return nil, f.err
	}
	if f.appUsersResp != nil {
		return f.appUsersResp, nil
	}
	return &saas_security.GetAppInventoryUsersOK{Payload: &models.AppInventoryUsers{}}, nil
}

func (f *fakeShield) GetAssetInventoryV3(_ *saas_security.GetAssetInventoryV3Params, _ ...saas_security.ClientOption) (*saas_security.GetAssetInventoryV3OK, error) {
	if f.err != nil {
		return nil, f.err
	}
	return &saas_security.GetAssetInventoryV3OK{Payload: &models.GetAssetInventory{}}, nil
}

func (f *fakeShield) GetIntegrationsV3(_ *saas_security.GetIntegrationsV3Params, _ ...saas_security.ClientOption) (*saas_security.GetIntegrationsV3OK, error) {
	if f.err != nil {
		return nil, f.err
	}
	if f.integResp != nil {
		return f.integResp, nil
	}
	return &saas_security.GetIntegrationsV3OK{Payload: &models.GetIntegrations{}}, nil
}

func (f *fakeShield) GetSystemUsersV3(_ *saas_security.GetSystemUsersV3Params, _ ...saas_security.ClientOption) (*saas_security.GetSystemUsersV3OK, error) {
	if f.err != nil {
		return nil, f.err
	}
	return &saas_security.GetSystemUsersV3OK{Payload: &models.GetSystemUsers{}}, nil
}

func (f *fakeShield) GetSupportedSaasV3(_ *saas_security.GetSupportedSaasV3Params, _ ...saas_security.ClientOption) (*saas_security.GetSupportedSaasV3OK, error) {
	if f.err != nil {
		return nil, f.err
	}
	return &saas_security.GetSupportedSaasV3OK{Payload: &models.GetSupportedSaas{}}, nil
}

func (f *fakeShield) GetSystemLogsV3(_ *saas_security.GetSystemLogsV3Params, _ ...saas_security.ClientOption) (*saas_security.GetSystemLogsV3OK, error) {
	if f.err != nil {
		return nil, f.err
	}
	return &saas_security.GetSystemLogsV3OK{Payload: &models.GetSystemLogs{}}, nil
}

func (f *fakeShield) DismissSecurityCheckV3(p *saas_security.DismissSecurityCheckV3Params, _ ...saas_security.ClientOption) (*saas_security.DismissSecurityCheckV3OK, error) {
	f.dismissCheck = p
	f.dismissCheckCalls++
	if f.err != nil {
		return nil, f.err
	}
	return &saas_security.DismissSecurityCheckV3OK{Payload: &models.DismissSecurityCheck{}}, nil
}

func (f *fakeShield) DismissAffectedEntityV3(p *saas_security.DismissAffectedEntityV3Params, _ ...saas_security.ClientOption) (*saas_security.DismissAffectedEntityV3OK, error) {
	f.dismissEntity = p
	f.dismissEntityCalls++
	if f.err != nil {
		return nil, f.err
	}
	return &saas_security.DismissAffectedEntityV3OK{Payload: &models.DismissAffected{}}, nil
}

func newModule(f *fakeShield) *Module { return &Module{API: f, Logger: testLogger} }

// --- search success / empty / error ---

func TestSearchChecksSuccess(t *testing.T) {
	t.Parallel()
	f := &fakeShield{checksResp: &saas_security.GetSecurityChecksV3OK{
		Payload: &models.GetSecurityChecks{
			Resources: []*models.SecurityCheckWithComplianceGetSecurityChecks{{ID: new("chk-1")}},
			Meta:      &models.MetaGetSecurityChecks{TraceID: new("t-1")},
		},
	}}
	m := newModule(f)

	_, out, err := m.searchShieldChecks(context.Background(), nil, SearchChecksInput{Status: "Failed", Limit: 5})
	if err != nil {
		t.Fatalf("searchShieldChecks: %v", err)
	}
	if len(out.Resources) != 1 {
		t.Fatalf("expected 1 resource, got %d", len(out.Resources))
	}
	if out.FQLGuide != "" || out.Hint != "" {
		t.Fatalf("non-empty result must not carry guide/hint: %+v", out)
	}
	if out.Meta == nil {
		t.Fatalf("expected meta passthrough")
	}
	// param mapping
	if f.checksParams.Status == nil || *f.checksParams.Status != "Failed" {
		t.Fatalf("status param not mapped: %+v", f.checksParams.Status)
	}
	if f.checksParams.Limit == nil || *f.checksParams.Limit != 5 {
		t.Fatalf("limit param not mapped: %+v", f.checksParams.Limit)
	}
}

func TestSearchChecksEmptyAttachesGuide(t *testing.T) {
	t.Parallel()
	m := newModule(&fakeShield{})

	_, out, err := m.searchShieldChecks(context.Background(), nil, SearchChecksInput{})
	if err != nil {
		t.Fatalf("searchShieldChecks: %v", err)
	}
	if out.Resources == nil {
		t.Fatalf("resources must be a non-nil empty slice")
	}
	if len(out.Resources) != 0 {
		t.Fatalf("expected empty resources, got %d", len(out.Resources))
	}
	if out.FQLGuide == "" {
		t.Fatalf("empty result should attach the query guide")
	}
	if out.Hint == "" {
		t.Fatalf("empty result should attach a hint")
	}
}

func TestSearchChecksAPIError(t *testing.T) {
	t.Parallel()
	m := newModule(&fakeShield{err: errors.New("boom")})

	_, _, err := m.searchShieldChecks(context.Background(), nil, SearchChecksInput{})
	if err == nil {
		t.Fatalf("expected error from API failure")
	}
	var apiErr *base.Error
	if !errors.As(err, &apiErr) {
		t.Fatalf("expected *base.Error, got %T", err)
	}
}

// --- impact normalization ---

func TestImpactNormalization(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in   string
		want *string
	}{
		{"low", new("Low")},
		{"MEDIUM", new("Medium")},
		{"High", new("High")},
		{"", nil},
		{"bogus", nil},
	}
	for _, c := range cases {
		f := &fakeShield{}
		m := newModule(f)
		_, _, err := m.searchShieldChecks(context.Background(), nil, SearchChecksInput{Impact: c.in})
		if err != nil {
			t.Fatalf("impact %q: %v", c.in, err)
		}
		got := f.checksParams.Impact
		switch {
		case c.want == nil && got != nil:
			t.Fatalf("impact %q: expected nil, got %q", c.in, *got)
		case c.want != nil && (got == nil || *got != *c.want):
			t.Fatalf("impact %q: expected %q, got %v", c.in, *c.want, got)
		}
	}
}

// metrics also normalizes impact.
func TestMetricsImpactNormalization(t *testing.T) {
	t.Parallel()
	f := &fakeShield{}
	m := newModule(f)
	_, _, err := m.getShieldPostureMetrics(context.Background(), nil, GetMetricsInput{Impact: "high"})
	if err != nil {
		t.Fatalf("getShieldPostureMetrics: %v", err)
	}
	if f.metricsParams.Impact == nil || *f.metricsParams.Impact != "High" {
		t.Fatalf("metrics impact not normalized: %v", f.metricsParams.Impact)
	}
}

// --- date parsing ---

func TestAlertsDateParsing(t *testing.T) {
	t.Parallel()
	f := &fakeShield{}
	m := newModule(f)
	_, _, err := m.searchShieldAlerts(context.Background(), nil, SearchAlertsInput{FromDate: "2026-01-01", ToDate: "2026-02-01"})
	if err != nil {
		t.Fatalf("searchShieldAlerts: %v", err)
	}
	if f.alertsParams.FromDate == nil || f.alertsParams.ToDate == nil {
		t.Fatalf("dates not parsed: from=%v to=%v", f.alertsParams.FromDate, f.alertsParams.ToDate)
	}
}

func TestAlertsInvalidDate(t *testing.T) {
	t.Parallel()
	m := newModule(&fakeShield{})
	_, _, err := m.searchShieldAlerts(context.Background(), nil, SearchAlertsInput{FromDate: "not-a-date"})
	if err == nil {
		t.Fatalf("expected error on invalid date")
	}
	if !errors.Is(err, errInvalidInput) {
		t.Fatalf("expected errInvalidInput, got %v", err)
	}
}

// --- required-id validation ---

func TestGetAffectedRequiresID(t *testing.T) {
	t.Parallel()
	m := newModule(&fakeShield{})
	_, _, err := m.getShieldCheckAffectedEntities(context.Background(), nil, GetAffectedInput{})
	if !errors.Is(err, errInvalidInput) {
		t.Fatalf("expected errInvalidInput for empty id, got %v", err)
	}
}

func TestGetComplianceRequiresID(t *testing.T) {
	t.Parallel()
	m := newModule(&fakeShield{})
	_, _, err := m.getShieldCheckCompliance(context.Background(), nil, GetComplianceInput{})
	if !errors.Is(err, errInvalidInput) {
		t.Fatalf("expected errInvalidInput for empty id, got %v", err)
	}
}

func TestGetAppUsersRequiresItemID(t *testing.T) {
	t.Parallel()
	m := newModule(&fakeShield{})
	_, _, err := m.getShieldAppUsers(context.Background(), nil, GetAppUsersInput{})
	if !errors.Is(err, errInvalidInput) {
		t.Fatalf("expected errInvalidInput for empty item_id, got %v", err)
	}
}

// --- dismiss branch selection ---

func TestDismissWholeCheck(t *testing.T) {
	t.Parallel()
	f := &fakeShield{}
	m := newModule(f)
	_, out, err := m.dismissShieldCheck(context.Background(), nil, DismissInput{ID: "chk-1", Reason: "accepted risk"})
	if err != nil {
		t.Fatalf("dismissShieldCheck: %v", err)
	}
	if !out.Ok {
		t.Fatalf("expected Ok result")
	}
	if f.dismissCheckCalls != 1 || f.dismissEntityCalls != 0 {
		t.Fatalf("expected whole-check dismiss, got check=%d entity=%d", f.dismissCheckCalls, f.dismissEntityCalls)
	}
	if f.dismissCheck.Body.Reason != "accepted risk" {
		t.Fatalf("reason not sent: %q", f.dismissCheck.Body.Reason)
	}
}

func TestDismissScopedEntities(t *testing.T) {
	t.Parallel()
	f := &fakeShield{}
	m := newModule(f)
	_, out, err := m.dismissShieldCheck(context.Background(), nil, DismissInput{
		ID: "chk-1", Reason: "known", Entities: " alice , bob ,",
	})
	if err != nil {
		t.Fatalf("dismissShieldCheck: %v", err)
	}
	if !out.Ok {
		t.Fatalf("expected Ok result")
	}
	if f.dismissEntityCalls != 1 || f.dismissCheckCalls != 0 {
		t.Fatalf("expected entity dismiss, got check=%d entity=%d", f.dismissCheckCalls, f.dismissEntityCalls)
	}
	// entities are trimmed and empties dropped, then comma-joined
	if got := f.dismissEntity.Body.Entities; got != "alice,bob" {
		t.Fatalf("entities not normalized: %q", got)
	}
	if f.dismissEntity.Body.Reason != "known" {
		t.Fatalf("reason not sent: %q", f.dismissEntity.Body.Reason)
	}
}

func TestDismissRequiresIDAndReason(t *testing.T) {
	t.Parallel()
	m := newModule(&fakeShield{})
	if _, _, err := m.dismissShieldCheck(context.Background(), nil, DismissInput{Reason: "r"}); !errors.Is(err, errInvalidInput) {
		t.Fatalf("expected errInvalidInput for empty id, got %v", err)
	}
	if _, _, err := m.dismissShieldCheck(context.Background(), nil, DismissInput{ID: "x"}); !errors.Is(err, errInvalidInput) {
		t.Fatalf("expected errInvalidInput for empty reason, got %v", err)
	}
}

// entities that are only whitespace/commas fall back to whole-check dismiss.
func TestDismissBlankEntitiesFallsBackToWholeCheck(t *testing.T) {
	t.Parallel()
	f := &fakeShield{}
	m := newModule(f)
	_, _, err := m.dismissShieldCheck(context.Background(), nil, DismissInput{ID: "chk-1", Reason: "r", Entities: "  , ,"})
	if err != nil {
		t.Fatalf("dismissShieldCheck: %v", err)
	}
	if f.dismissCheckCalls != 1 || f.dismissEntityCalls != 0 {
		t.Fatalf("blank entities should dismiss whole check, got check=%d entity=%d", f.dismissCheckCalls, f.dismissEntityCalls)
	}
}

// --- registration / annotations ---

func TestRegisterToolsNamesAndAnnotations(t *testing.T) {
	t.Parallel()
	m := newModule(&fakeShield{})
	var entries []base.ToolEntry
	m.RegisterTools(testutil.CaptureRegistrar(func(e base.ToolEntry) { entries = append(entries, e) }))

	byName := map[string]*mcp.Tool{}
	for _, e := range entries {
		byName[e.Tool.Name] = e.Tool
	}

	// 16 tools total, all prefixed with falcon_
	if len(entries) != 16 {
		t.Fatalf("expected 16 tools, got %d", len(entries))
	}
	wantReadOnly := []string{
		"falcon_search_shield_checks", "falcon_search_shield_alerts",
		"falcon_search_shield_users", "falcon_search_shield_devices",
		"falcon_search_shield_apps", "falcon_search_shield_data_shares",
		"falcon_get_shield_check_affected_entities", "falcon_get_shield_posture_metrics",
		"falcon_get_shield_check_compliance", "falcon_get_shield_activity_monitor",
		"falcon_get_shield_app_users", "falcon_get_shield_integrations",
		"falcon_get_shield_system_users", "falcon_get_shield_supported_saas",
		"falcon_get_shield_system_logs",
	}
	for _, n := range wantReadOnly {
		tool, ok := byName[n]
		if !ok {
			t.Fatalf("missing tool %q", n)
		}
		if tool.Annotations == nil || !tool.Annotations.ReadOnlyHint {
			t.Fatalf("%s should be read-only", n)
		}
	}

	// dismiss is destructive + idempotent, not read-only
	dismiss, ok := byName["falcon_dismiss_shield_check"]
	if !ok {
		t.Fatalf("missing dismiss tool")
	}
	if dismiss.Annotations == nil {
		t.Fatalf("dismiss annotations must be set")
	}
	if dismiss.Annotations.ReadOnlyHint {
		t.Fatalf("dismiss must not be read-only")
	}
	if dismiss.Annotations.DestructiveHint == nil || !*dismiss.Annotations.DestructiveHint {
		t.Fatalf("dismiss must be destructive")
	}
	if !dismiss.Annotations.IdempotentHint {
		t.Fatalf("dismiss should be idempotent")
	}
}

// TestSearchShieldAlertsPaginatesByCursorOnly pins the alerts pagination surface.
// Alerts page by the last_id cursor, so the tool must not advertise an offset
// alongside it or forward one to the API. The other Shield search tools have no
// cursor and keep their offset, so this is scoped to alerts.
func TestSearchShieldAlertsPaginatesByCursorOnly(t *testing.T) {
	t.Parallel()

	schema := base.SchemaFor[SearchAlertsInput](pagingSchema)
	if _, ok := schema.Properties["offset"]; ok {
		t.Error("search_shield_alerts must not advertise an offset input")
	}
	if _, ok := schema.Properties["last_id"]; !ok {
		t.Error("search_shield_alerts must advertise a last_id cursor")
	}

	f := &fakeShield{}
	m := &Module{API: f, Logger: testLogger}

	_, _, err := m.searchShieldAlerts(context.Background(), nil, SearchAlertsInput{LastID: "tok"})
	if err != nil {
		t.Fatalf("searchShieldAlerts: %v", err)
	}
	if f.alertsParams == nil {
		t.Fatal("alert params must be recorded")
	}
	if f.alertsParams.Offset != nil {
		t.Errorf("offset = %v, want unset", *f.alertsParams.Offset)
	}
	if f.alertsParams.LastID == nil || *f.alertsParams.LastID != "tok" {
		t.Errorf("last_id = %v, want tok", f.alertsParams.LastID)
	}
}
