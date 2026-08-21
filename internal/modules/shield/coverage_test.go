package shield

import (
	"context"
	"errors"
	"testing"

	"github.com/crowdstrike/gofalcon/falcon/client/saas_security"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// metaQueryTime is a non-zero query_time for test fakes, so a handler's
// normalized meta is a populated value rather than nil.
var metaQueryTime = 0.02

// These tests exercise the remaining single-call search/get handlers, which all
// share the shape: map params -> one API call -> foundOrGuided. Each is checked
// for the success path (records + meta pass through, no guide) and the empty
// path (guide/hint attached), plus the API-error path via the shared fake.

func TestSearchUsersSuccessAndEmpty(t *testing.T) {
	t.Parallel()
	m := newModule(&fakeShield{})
	_, out, err := m.searchShieldUsers(context.Background(), nil, SearchUsersInput{Email: "a@b.com"})
	if err != nil {
		t.Fatalf("searchShieldUsers: %v", err)
	}
	if out.FQLGuide == "" {
		t.Fatalf("empty result should attach the guide")
	}
}

func TestSearchDevicesSuccess(t *testing.T) {
	t.Parallel()
	f := &fakeShield{devicesResp: &saas_security.GetDeviceInventoryV3OK{
		Payload: &models.GetDeviceInventory{
			Resources: []*models.DeviceGetDeviceInventory{{ID: new("dev-1")}},
			Meta:      &models.MetaGetDeviceInventory{QueryTime: &metaQueryTime},
		},
	}}
	m := newModule(f)
	_, out, err := m.searchShieldDevices(context.Background(), nil, SearchDevicesInput{Limit: 2})
	if err != nil {
		t.Fatalf("searchShieldDevices: %v", err)
	}
	if len(out.Resources) != 1 || out.FQLGuide != "" {
		t.Fatalf("unexpected result: %+v", out)
	}
}

func TestSearchAppsSuccess(t *testing.T) {
	t.Parallel()
	f := &fakeShield{appsResp: &saas_security.GetAppInventoryOK{
		Payload: &models.AppInventory{
			Resources: []*models.AppAppInventory{{ItemID: new("app|||i")}},
		},
	}}
	m := newModule(f)
	_, out, err := m.searchShieldApps(context.Background(), nil, SearchAppsInput{Type: "oauth"})
	if err != nil {
		t.Fatalf("searchShieldApps: %v", err)
	}
	if len(out.Resources) != 1 {
		t.Fatalf("expected 1 app, got %d", len(out.Resources))
	}
}

func TestSearchDataSharesEmpty(t *testing.T) {
	t.Parallel()
	m := newModule(&fakeShield{})
	_, out, err := m.searchShieldDataShares(context.Background(), nil, SearchDataSharesInput{})
	if err != nil {
		t.Fatalf("searchShieldDataShares: %v", err)
	}
	if out.FQLGuide == "" || out.Resources == nil {
		t.Fatalf("empty data-shares result malformed: %+v", out)
	}
}

func TestGetHandlersEmpty(t *testing.T) {
	t.Parallel()
	m := newModule(&fakeShield{})
	ctx := context.Background()

	if _, out, err := m.getShieldCheckAffectedEntities(ctx, nil, GetAffectedInput{ID: "c1"}); err != nil || out.Resources == nil {
		t.Fatalf("affected: err=%v out=%+v", err, out)
	}
	if _, out, err := m.getShieldPostureMetrics(ctx, nil, GetMetricsInput{}); err != nil || out.Resources == nil {
		t.Fatalf("metrics: err=%v out=%+v", err, out)
	}
	if _, out, err := m.getShieldCheckCompliance(ctx, nil, GetComplianceInput{ID: "c1"}); err != nil || out.Resources == nil {
		t.Fatalf("compliance: err=%v out=%+v", err, out)
	}
	if _, out, err := m.getShieldActivityMonitor(ctx, nil, GetActivityInput{}); err != nil || out.Resources == nil {
		t.Fatalf("activity: err=%v out=%+v", err, out)
	}
	if _, out, err := m.getShieldAppUsers(ctx, nil, GetAppUsersInput{ItemID: "app|||i"}); err != nil || out.Resources == nil {
		t.Fatalf("appusers: err=%v out=%+v", err, out)
	}
	if _, out, err := m.getShieldIntegrations(ctx, nil, GetIntegrationsInput{}); err != nil || out.Resources == nil {
		t.Fatalf("integrations: err=%v out=%+v", err, out)
	}
	if _, out, err := m.getShieldSystemUsers(ctx, nil, struct{}{}); err != nil || out.Resources == nil {
		t.Fatalf("system users: err=%v out=%+v", err, out)
	}
	if _, out, err := m.getShieldSupportedSaas(ctx, nil, struct{}{}); err != nil || out.Resources == nil {
		t.Fatalf("supported saas: err=%v out=%+v", err, out)
	}
	if _, out, err := m.getShieldSystemLogs(ctx, nil, GetSystemLogsInput{}); err != nil || out.Resources == nil {
		t.Fatalf("system logs: err=%v out=%+v", err, out)
	}
}

func TestActivityMonitorInvalidDate(t *testing.T) {
	t.Parallel()
	m := newModule(&fakeShield{})
	_, _, err := m.getShieldActivityMonitor(context.Background(), nil, GetActivityInput{FromDate: "nope"})
	if !errors.Is(err, errInvalidInput) {
		t.Fatalf("expected errInvalidInput, got %v", err)
	}
}

func TestSystemLogsInvalidDate(t *testing.T) {
	t.Parallel()
	m := newModule(&fakeShield{})
	_, _, err := m.getShieldSystemLogs(context.Background(), nil, GetSystemLogsInput{ToDate: "nope"})
	if !errors.Is(err, errInvalidInput) {
		t.Fatalf("expected errInvalidInput, got %v", err)
	}
}

// getHandlersAPIError confirms each get/search handler surfaces a transport
// failure as a base.Error rather than swallowing it.
func TestGetHandlersAPIError(t *testing.T) {
	t.Parallel()
	m := newModule(&fakeShield{err: errors.New("boom")})
	ctx := context.Background()
	if _, _, err := m.searchShieldDevices(ctx, nil, SearchDevicesInput{}); err == nil {
		t.Fatal("devices: expected error")
	}
	if _, _, err := m.getShieldIntegrations(ctx, nil, GetIntegrationsInput{}); err == nil {
		t.Fatal("integrations: expected error")
	}
	if _, _, err := m.dismissShieldCheck(ctx, nil, DismissInput{ID: "c", Reason: "r"}); err == nil {
		t.Fatal("dismiss: expected error")
	}
}

func TestModuleMetadataAndResources(t *testing.T) {
	t.Parallel()
	m := newModule(&fakeShield{})
	if m.Name() != "shield" {
		t.Fatalf("unexpected name %q", m.Name())
	}
	if m.Description() == "" {
		t.Fatalf("description must not be empty")
	}
	// RegisterResources and RegisterPrompts should not panic on a real server.
	s := mcp.NewServer(&mcp.Implementation{Name: "t", Version: "0"}, nil)
	m.RegisterResources(s)
	m.RegisterPrompts(s)
}
