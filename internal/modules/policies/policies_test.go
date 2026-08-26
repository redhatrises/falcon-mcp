package policies

import (
	"context"
	"errors"
	"testing"

	"github.com/crowdstrike/gofalcon/falcon/models"

	"github.com/crowdstrike/falcon-mcp/internal/modules/base"
	"github.com/crowdstrike/falcon-mcp/internal/testutil"
)

var testLogger = testutil.DiscardLogger()

// fakeBackend is a configurable test double for the backend interface. It records
// the last args it received and returns canned records/meta so handler behavior
// can be exercised without the gofalcon transport.
type fakeBackend struct {
	searchRecords []map[string]any
	searchMeta    any
	searchErr     error
	createRecords []map[string]any
	createMeta    any
	createErr     error
	updateRecords []map[string]any
	updateErr     error
	deleteMeta    any
	deleteErr     error
	actionRecords []map[string]any
	actionErr     error
	precedenceErr error
	fqlDetail     []base.FQLErrorDetail
	fqlOK         bool

	memberDevices []*models.DeviceDevice
	membersMeta   any
	membersErr    error

	lastQuery      queryArgs
	lastMembersID  string
	lastCreate     createSpec
	lastUpdate     updateSpec
	lastDeleteIDs  []string
	lastActionName string
	lastActionIDs  []string
	lastGroupID    string
	lastPrecIDs    []string
	lastPlatform   string
}

func (f *fakeBackend) search(_ context.Context, a queryArgs) ([]map[string]any, any, error) {
	f.lastQuery = a
	if f.searchRecords == nil && f.searchErr == nil {
		return []map[string]any{}, f.searchMeta, nil
	}
	return f.searchRecords, f.searchMeta, f.searchErr
}
func (f *fakeBackend) members(_ context.Context, id string, a queryArgs) ([]*models.DeviceDevice, any, error) {
	f.lastMembersID = id
	f.lastQuery = a
	return f.memberDevices, f.membersMeta, f.membersErr
}
func (f *fakeBackend) create(_ context.Context, s createSpec) ([]map[string]any, any, error) {
	f.lastCreate = s
	return f.createRecords, f.createMeta, f.createErr
}
func (f *fakeBackend) update(_ context.Context, s updateSpec) ([]map[string]any, any, error) {
	f.lastUpdate = s
	return f.updateRecords, nil, f.updateErr
}
func (f *fakeBackend) deleteByIDs(_ context.Context, ids []string) (any, error) {
	f.lastDeleteIDs = ids
	return f.deleteMeta, f.deleteErr
}
func (f *fakeBackend) action(_ context.Context, actionName string, ids []string, groupID string) ([]map[string]any, any, error) {
	f.lastActionName = actionName
	f.lastActionIDs = ids
	f.lastGroupID = groupID
	return f.actionRecords, nil, f.actionErr
}
func (f *fakeBackend) setPrecedence(_ context.Context, ids []string, platformName string) (any, error) {
	f.lastPrecIDs = ids
	f.lastPlatform = platformName
	return nil, f.precedenceErr
}
func (f *fakeBackend) classifyFQL(error) ([]base.FQLErrorDetail, bool) {
	return f.fqlDetail, f.fqlOK
}

// moduleWith builds a Module whose single named backend is fb.
func moduleWith(policyType string, fb backend) *Module {
	return &Module{
		backends: map[string]backend{policyType: fb},
		Logger:   testLogger,
	}
}

// allTypesModule registers fb under every valid policy type, so validation tests
// can use a shared table where only a genuinely unknown policy_type misses.
func allTypesModule(fb backend) *Module {
	backends := make(map[string]backend, len(policyTypes))
	for _, t := range policyTypes {
		backends[t] = fb
	}
	return &Module{backends: backends, Logger: testLogger}
}

// ---- search --------------------------------------------------------------------

func TestSearchPoliciesSuccess(t *testing.T) {
	t.Parallel()
	meta := &models.MsaMetaInfo{QueryTime: &metaQueryTime}
	fb := &fakeBackend{
		searchRecords: []map[string]any{{"id": "a", "name": "n"}},
		searchMeta:    meta,
	}
	m := moduleWith("prevention", fb)

	_, out, err := m.searchPolicies(context.Background(), nil, SearchInput{PolicyType: "prevention", Filter: "enabled:true", Limit: 50})
	if err != nil {
		t.Fatalf("searchPolicies: %v", err)
	}
	if len(out.Resources) != 1 || out.FilterUsed != "enabled:true" {
		t.Fatalf("unexpected result: %+v", out)
	}
	testutil.AssertNormalizedMeta(t, out.Meta, meta)
	if fb.lastQuery.limit != 50 {
		t.Fatalf("limit = %d, want 50", fb.lastQuery.limit)
	}
}

func TestSearchPoliciesEmpty(t *testing.T) {
	t.Parallel()
	fb := &fakeBackend{} // search returns empty non-nil slice
	m := moduleWith("firewall", fb)

	_, out, err := m.searchPolicies(context.Background(), nil, SearchInput{PolicyType: "firewall"})
	if err != nil {
		t.Fatalf("searchPolicies: %v", err)
	}
	if out.Resources == nil || len(out.Resources) != 0 {
		t.Fatalf("expected non-nil empty slice, got %+v", out.Resources)
	}
	if out.Meta != nil {
		t.Fatalf("expected nil meta on empty query, got %+v", out.Meta)
	}
	// default limit applied
	if fb.lastQuery.limit != 100 {
		t.Fatalf("default limit = %d, want 100", fb.lastQuery.limit)
	}
}

func TestSearchPoliciesInvalidType(t *testing.T) {
	t.Parallel()
	m := moduleWith("prevention", &fakeBackend{})
	_, _, err := m.searchPolicies(context.Background(), nil, SearchInput{PolicyType: "bogus"})
	if !errors.Is(err, base.ErrInvalidInput) {
		t.Fatalf("expected base.ErrInvalidInput, got %v", err)
	}
}

func TestSearchPoliciesInvalidSort(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		sort    string
		wantErr bool
	}{
		{"platform_name rejected", "platform_name.asc", true},
		{"platform_name bare rejected", "platform_name", true},
		{"unknown field rejected", "bogus.desc", true},
		{"valid modified_timestamp", "modified_timestamp.desc", false},
		{"valid name pipe dir", "name|asc", false},
		{"empty ok", "", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			m := moduleWith("prevention", &fakeBackend{})
			_, _, err := m.searchPolicies(context.Background(), nil, SearchInput{PolicyType: "prevention", Sort: tc.sort})
			if tc.wantErr && !errors.Is(err, base.ErrInvalidInput) {
				t.Fatalf("sort %q: expected base.ErrInvalidInput, got %v", tc.sort, err)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("sort %q: unexpected error %v", tc.sort, err)
			}
		})
	}
}

func TestSearchPoliciesFQLError(t *testing.T) {
	t.Parallel()
	fb := &fakeBackend{
		searchErr: errors.New("bad filter"),
		fqlDetail: []base.FQLErrorDetail{{Code: 400, Message: "invalid filter"}},
		fqlOK:     true,
	}
	m := moduleWith("prevention", fb)

	_, out, err := m.searchPolicies(context.Background(), nil, SearchInput{PolicyType: "prevention", Filter: "bogus:'x'"})
	if err != nil {
		t.Fatalf("expected FQL error formatted, not returned: %v", err)
	}
	if len(out.Errors) != 1 || out.Errors[0].Message != "invalid filter" {
		t.Fatalf("expected FQL error detail, got %+v", out.Errors)
	}
	if out.FQLGuide == "" || out.Hint == "" {
		t.Fatalf("expected fql_guide and hint populated")
	}
}

func TestSearchPoliciesAPIError(t *testing.T) {
	t.Parallel()
	fb := &fakeBackend{searchErr: errors.New("boom")}
	m := moduleWith("prevention", fb)
	_, _, err := m.searchPolicies(context.Background(), nil, SearchInput{PolicyType: "prevention"})
	if err == nil {
		t.Fatalf("expected non-FQL error returned")
	}
}

func TestSearchPoliciesLimitClamp(t *testing.T) {
	t.Parallel()
	fb := &fakeBackend{}
	m := moduleWith("prevention", fb)
	_, _, err := m.searchPolicies(context.Background(), nil, SearchInput{PolicyType: "prevention", Limit: 9999})
	if err != nil {
		t.Fatal(err)
	}
	if fb.lastQuery.limit != 500 {
		t.Fatalf("limit clamp = %d, want 500", fb.lastQuery.limit)
	}
}

// ---- members -------------------------------------------------------------------

func TestSearchPolicyMembers(t *testing.T) {
	t.Parallel()

	t.Run("invalid type", func(t *testing.T) {
		t.Parallel()
		m := moduleWith("prevention", &fakeBackend{})
		_, _, err := m.searchPolicyMembers(context.Background(), nil, MembersInput{PolicyType: "bogus", ID: "p1"})
		if !errors.Is(err, base.ErrInvalidInput) {
			t.Fatalf("expected base.ErrInvalidInput, got %v", err)
		}
	})

	t.Run("requires id", func(t *testing.T) {
		t.Parallel()
		m := moduleWith("prevention", &fakeBackend{})
		_, _, err := m.searchPolicyMembers(context.Background(), nil, MembersInput{PolicyType: "prevention"})
		if !errors.Is(err, base.ErrInvalidInput) {
			t.Fatalf("expected base.ErrInvalidInput for missing id, got %v", err)
		}
	})

	t.Run("success passes id and returns devices", func(t *testing.T) {
		t.Parallel()
		did := "d1"
		meta := &models.MsaMetaInfo{QueryTime: &metaQueryTime}
		fb := &fakeBackend{memberDevices: []*models.DeviceDevice{{DeviceID: &did}}, membersMeta: meta}
		m := moduleWith("prevention", fb)
		_, out, err := m.searchPolicyMembers(context.Background(), nil, MembersInput{PolicyType: "prevention", ID: "p1", Limit: 10})
		if err != nil {
			t.Fatalf("searchPolicyMembers: %v", err)
		}
		if len(out.Resources) != 1 || out.Resources[0].DeviceID == nil || *out.Resources[0].DeviceID != did {
			t.Fatalf("unexpected members: %+v", out.Resources)
		}
		if fb.lastMembersID != "p1" {
			t.Fatalf("expected id p1 passed, got %q", fb.lastMembersID)
		}
		testutil.AssertNormalizedMeta(t, out.Meta, meta)
	})

	t.Run("api error surfaced", func(t *testing.T) {
		t.Parallel()
		fb := &fakeBackend{membersErr: errors.New("boom")}
		m := moduleWith("prevention", fb)
		_, _, err := m.searchPolicyMembers(context.Background(), nil, MembersInput{PolicyType: "prevention", ID: "p1"})
		if err == nil {
			t.Fatalf("expected API error surfaced")
		}
	})
}

// ---- create --------------------------------------------------------------------

func TestCreatePolicyValidation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		in      CreateInput
		wantErr bool
	}{
		{"invalid type", CreateInput{PolicyType: "bogus", Name: "n", PlatformName: "Windows"}, true},
		{"missing name", CreateInput{PolicyType: "prevention", PlatformName: "Windows"}, true},
		{"prevention missing platform", CreateInput{PolicyType: "prevention", Name: "n"}, true},
		{"prevention valid", CreateInput{PolicyType: "prevention", Name: "n", PlatformName: "Windows"}, false},
		{"content_update no platform needed", CreateInput{PolicyType: "content_update", Name: "n"}, false},
		{"content_update valid with platform ignored", CreateInput{PolicyType: "content_update", Name: "n", PlatformName: "all"}, false},
		{"firewall rejects settings", CreateInput{PolicyType: "firewall", Name: "n", PlatformName: "Windows", Settings: map[string]any{"x": 1}}, true},
		{"prevention accepts settings", CreateInput{PolicyType: "prevention", Name: "n", PlatformName: "Windows", Settings: map[string]any{"x": 1}}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			fb := &fakeBackend{createRecords: []map[string]any{{"id": "new"}}}
			// Register the backend under every valid type so only a genuinely
			// unknown policy_type ("bogus") misses; a valid type always resolves.
			m := allTypesModule(fb)
			_, _, err := m.createPolicy(context.Background(), nil, tc.in)
			if tc.wantErr && !errors.Is(err, base.ErrInvalidInput) {
				t.Fatalf("expected base.ErrInvalidInput, got %v", err)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestCreatePolicySuccess(t *testing.T) {
	t.Parallel()
	meta := &models.MsaMetaInfo{QueryTime: &metaQueryTime}
	fb := &fakeBackend{createRecords: []map[string]any{{"id": "new", "name": "n"}}, createMeta: meta}
	m := moduleWith("prevention", fb)
	_, out, err := m.createPolicy(context.Background(), nil, CreateInput{PolicyType: "prevention", Name: "n", PlatformName: "Windows", CloneID: "c1"})
	if err != nil {
		t.Fatalf("createPolicy: %v", err)
	}
	if out.Total != 1 || out.Resources[0]["id"] != "new" {
		t.Fatalf("expected created record, got %+v", out)
	}
	testutil.AssertNormalizedMeta(t, out.Meta, meta)
	if fb.lastCreate.name != "n" || fb.lastCreate.platformName != "Windows" || fb.lastCreate.cloneID != "c1" {
		t.Fatalf("unexpected create spec: %+v", fb.lastCreate)
	}
}

// ---- update --------------------------------------------------------------------

func TestUpdatePolicy(t *testing.T) {
	t.Parallel()

	t.Run("invalid type", func(t *testing.T) {
		t.Parallel()
		m := moduleWith("prevention", &fakeBackend{})
		_, _, err := m.updatePolicy(context.Background(), nil, UpdateInput{PolicyType: "bogus", ID: "p1"})
		if !errors.Is(err, base.ErrInvalidInput) {
			t.Fatalf("expected base.ErrInvalidInput, got %v", err)
		}
	})

	t.Run("requires id", func(t *testing.T) {
		t.Parallel()
		m := moduleWith("prevention", &fakeBackend{})
		_, _, err := m.updatePolicy(context.Background(), nil, UpdateInput{PolicyType: "prevention", Name: "n"})
		if !errors.Is(err, base.ErrInvalidInput) {
			t.Fatalf("expected base.ErrInvalidInput for missing id, got %v", err)
		}
	})

	t.Run("firewall rejects settings", func(t *testing.T) {
		t.Parallel()
		m := moduleWith("firewall", &fakeBackend{})
		_, _, err := m.updatePolicy(context.Background(), nil, UpdateInput{PolicyType: "firewall", ID: "p1", Settings: map[string]any{"x": 1}})
		if !errors.Is(err, base.ErrInvalidInput) {
			t.Fatalf("expected base.ErrInvalidInput for firewall settings, got %v", err)
		}
	})

	t.Run("success passes spec", func(t *testing.T) {
		t.Parallel()
		fb := &fakeBackend{updateRecords: []map[string]any{{"id": "p1"}}}
		m := moduleWith("prevention", fb)
		_, out, err := m.updatePolicy(context.Background(), nil, UpdateInput{PolicyType: "prevention", ID: "p1", Name: "new"})
		if err != nil {
			t.Fatalf("updatePolicy: %v", err)
		}
		if out.Total != 1 {
			t.Fatalf("expected updated record, got %+v", out)
		}
		if fb.lastUpdate.id != "p1" || fb.lastUpdate.name != "new" {
			t.Fatalf("unexpected update spec: %+v", fb.lastUpdate)
		}
	})
}

// ---- delete --------------------------------------------------------------------

func TestDeletePolicies(t *testing.T) {
	t.Parallel()

	t.Run("invalid type", func(t *testing.T) {
		t.Parallel()
		m := moduleWith("prevention", &fakeBackend{})
		_, _, err := m.deletePolicies(context.Background(), nil, DeleteInput{PolicyType: "bogus", IDs: []string{"a"}})
		if !errors.Is(err, base.ErrInvalidInput) {
			t.Fatalf("expected base.ErrInvalidInput, got %v", err)
		}
	})

	t.Run("empty ids", func(t *testing.T) {
		t.Parallel()
		m := moduleWith("prevention", &fakeBackend{})
		_, _, err := m.deletePolicies(context.Background(), nil, DeleteInput{PolicyType: "prevention"})
		if !errors.Is(err, base.ErrInvalidInput) {
			t.Fatalf("expected base.ErrInvalidInput, got %v", err)
		}
	})

	t.Run("success passes ids", func(t *testing.T) {
		t.Parallel()
		meta := &models.MsaMetaInfo{QueryTime: &metaQueryTime}
		fb := &fakeBackend{deleteMeta: meta}
		m := moduleWith("prevention", fb)
		_, out, err := m.deletePolicies(context.Background(), nil, DeleteInput{PolicyType: "prevention", IDs: []string{"a", "b"}})
		if err != nil {
			t.Fatalf("deletePolicies: %v", err)
		}
		if !out.Ok {
			t.Fatalf("expected Ok, got %+v", out)
		}
		testutil.AssertNormalizedMeta(t, out.Meta, meta)
		if len(fb.lastDeleteIDs) != 2 {
			t.Fatalf("expected 2 ids passed, got %v", fb.lastDeleteIDs)
		}
	})

	t.Run("api error surfaced", func(t *testing.T) {
		t.Parallel()
		fb := &fakeBackend{deleteErr: errors.New("boom")}
		m := moduleWith("prevention", fb)
		_, _, err := m.deletePolicies(context.Background(), nil, DeleteInput{PolicyType: "prevention", IDs: []string{"a"}})
		if err == nil {
			t.Fatalf("expected API error surfaced")
		}
	})
}

// ---- action --------------------------------------------------------------------

func TestPerformPolicyActionValidation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		in      ActionInput
		wantErr bool
	}{
		{"invalid type", ActionInput{PolicyType: "bogus", ActionName: "enable", IDs: []string{"a"}}, true},
		{"invalid action for firewall (rule-group)", ActionInput{PolicyType: "firewall", ActionName: "add-rule-group", IDs: []string{"a"}, GroupID: "g"}, true},
		{"rule-group rejected for sensor_update", ActionInput{PolicyType: "sensor_update", ActionName: "add-rule-group", IDs: []string{"a"}, GroupID: "g"}, true},
		{"rule-group rejected for response", ActionInput{PolicyType: "response", ActionName: "remove-rule-group", IDs: []string{"a"}, GroupID: "g"}, true},
		{"valid rule-group for prevention", ActionInput{PolicyType: "prevention", ActionName: "add-rule-group", IDs: []string{"a"}, GroupID: "g"}, false},
		{"content_update override valid", ActionInput{PolicyType: "content_update", ActionName: "override-allow", IDs: []string{"a"}}, false},
		{"content_update override invalid on prevention", ActionInput{PolicyType: "prevention", ActionName: "override-allow", IDs: []string{"a"}}, true},
		{"empty ids", ActionInput{PolicyType: "prevention", ActionName: "enable"}, true},
		{"host-group action needs group_id", ActionInput{PolicyType: "prevention", ActionName: "add-host-group", IDs: []string{"a"}}, true},
		{"host-group action with group_id ok", ActionInput{PolicyType: "prevention", ActionName: "add-host-group", IDs: []string{"a"}, GroupID: "g"}, false},
		{"enable ok no group", ActionInput{PolicyType: "prevention", ActionName: "enable", IDs: []string{"a"}}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			fb := &fakeBackend{actionRecords: []map[string]any{{"id": "a"}}}
			m := allTypesModule(fb)
			_, _, err := m.performPolicyAction(context.Background(), nil, tc.in)
			if tc.wantErr && !errors.Is(err, base.ErrInvalidInput) {
				t.Fatalf("expected base.ErrInvalidInput, got %v", err)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestPerformPolicyActionPassesArgs(t *testing.T) {
	t.Parallel()
	fb := &fakeBackend{actionRecords: []map[string]any{{"id": "a"}}}
	m := moduleWith("prevention", fb)
	_, out, err := m.performPolicyAction(context.Background(), nil, ActionInput{
		PolicyType: "prevention", ActionName: "add-host-group", IDs: []string{"a", "b"}, GroupID: "g1",
	})
	if err != nil {
		t.Fatalf("performPolicyAction: %v", err)
	}
	if out.Total != 1 {
		t.Fatalf("expected 1 record, got %+v", out)
	}
	if fb.lastActionName != "add-host-group" || len(fb.lastActionIDs) != 2 || fb.lastGroupID != "g1" {
		t.Fatalf("unexpected action args: name=%q ids=%v group=%q", fb.lastActionName, fb.lastActionIDs, fb.lastGroupID)
	}
}

// ---- precedence ----------------------------------------------------------------

func TestSetPolicyPrecedence(t *testing.T) {
	t.Parallel()

	t.Run("invalid type", func(t *testing.T) {
		t.Parallel()
		m := moduleWith("prevention", &fakeBackend{})
		_, _, err := m.setPolicyPrecedence(context.Background(), nil, PrecedenceInput{PolicyType: "bogus", IDs: []string{"a"}, PlatformName: "Windows"})
		if !errors.Is(err, base.ErrInvalidInput) {
			t.Fatalf("expected base.ErrInvalidInput, got %v", err)
		}
	})

	t.Run("empty ids", func(t *testing.T) {
		t.Parallel()
		m := moduleWith("prevention", &fakeBackend{})
		_, _, err := m.setPolicyPrecedence(context.Background(), nil, PrecedenceInput{PolicyType: "prevention", PlatformName: "Windows"})
		if !errors.Is(err, base.ErrInvalidInput) {
			t.Fatalf("expected base.ErrInvalidInput, got %v", err)
		}
	})

	t.Run("prevention requires platform", func(t *testing.T) {
		t.Parallel()
		m := moduleWith("prevention", &fakeBackend{})
		_, _, err := m.setPolicyPrecedence(context.Background(), nil, PrecedenceInput{PolicyType: "prevention", IDs: []string{"a"}})
		if !errors.Is(err, base.ErrInvalidInput) {
			t.Fatalf("expected base.ErrInvalidInput for missing platform, got %v", err)
		}
	})

	t.Run("content_update needs no platform", func(t *testing.T) {
		t.Parallel()
		fb := &fakeBackend{}
		m := moduleWith("content_update", fb)
		_, out, err := m.setPolicyPrecedence(context.Background(), nil, PrecedenceInput{PolicyType: "content_update", IDs: []string{"a", "b"}})
		if err != nil {
			t.Fatalf("setPolicyPrecedence: %v", err)
		}
		if !out.Ok {
			t.Fatalf("expected Ok")
		}
		if len(fb.lastPrecIDs) != 2 || fb.lastPlatform != "" {
			t.Fatalf("unexpected precedence args: ids=%v platform=%q", fb.lastPrecIDs, fb.lastPlatform)
		}
	})

	t.Run("prevention passes platform", func(t *testing.T) {
		t.Parallel()
		fb := &fakeBackend{}
		m := moduleWith("prevention", fb)
		_, _, err := m.setPolicyPrecedence(context.Background(), nil, PrecedenceInput{PolicyType: "prevention", IDs: []string{"a"}, PlatformName: "Windows"})
		if err != nil {
			t.Fatalf("setPolicyPrecedence: %v", err)
		}
		if fb.lastPlatform != "Windows" {
			t.Fatalf("expected platform Windows passed, got %q", fb.lastPlatform)
		}
	})
}

// ---- helpers -------------------------------------------------------------------

func TestValidateSort(t *testing.T) {
	t.Parallel()
	if err := validateSort("platform_name.desc"); err == nil {
		t.Fatal("expected platform_name sort rejected")
	}
	if err := validateSort("precedence"); err != nil {
		t.Fatalf("expected precedence valid, got %v", err)
	}
	if err := validateSort(""); err != nil {
		t.Fatalf("expected empty valid, got %v", err)
	}
}

func TestClampLimit(t *testing.T) {
	t.Parallel()
	tests := []struct {
		in   int
		max  int64
		want int64
	}{
		{0, 500, 100},
		{-5, 500, 100},
		{50, 500, 50},
		{9999, 500, 500},
		{9999, 5000, 5000},
	}
	for _, tc := range tests {
		if got := clampLimit(tc.in, tc.max); got != tc.want {
			t.Errorf("clampLimit(%d, %d) = %d, want %d", tc.in, tc.max, got, tc.want)
		}
	}
}

func TestReorderByID(t *testing.T) {
	t.Parallel()
	records := []map[string]any{{"id": "a"}, {"id": "b"}, {"id": "c"}}
	got := base.ReorderMapsByID([]string{"c", "a", "b"}, records)
	if got[0]["id"] != "c" || got[1]["id"] != "a" || got[2]["id"] != "b" {
		t.Fatalf("unexpected order: %v", got)
	}
	// A record with no id is preserved (appended), never dropped.
	withUnkeyed := []map[string]any{{"id": "a"}, {"name": "no-id"}}
	got = base.ReorderMapsByID([]string{"a"}, withUnkeyed)
	if len(got) != 2 {
		t.Fatalf("expected unkeyed record preserved, got %v", got)
	}
}

func TestConvertSettings(t *testing.T) {
	t.Parallel()

	t.Run("nil yields zero", func(t *testing.T) {
		t.Parallel()
		out, err := convertSettings[[]*models.PreventionSettingReqV1](nil)
		if err != nil {
			t.Fatal(err)
		}
		if out != nil {
			t.Fatalf("expected nil slice, got %v", out)
		}
	})

	t.Run("shape mismatch is invalid input", func(t *testing.T) {
		t.Parallel()
		// A string cannot decode into a []*PreventionSettingReqV1.
		_, err := convertSettings[[]*models.PreventionSettingReqV1]("not-a-list")
		if !errors.Is(err, base.ErrInvalidInput) {
			t.Fatalf("expected base.ErrInvalidInput, got %v", err)
		}
	})
}

func TestActionBody(t *testing.T) {
	t.Parallel()
	// No group_id -> no action parameters.
	b := actionBody("add-host-group", []string{"a"}, "")
	if len(b.Ids) != 1 || len(b.ActionParameters) != 0 {
		t.Fatalf("unexpected body without group: %+v", b)
	}
	// A group_id on a non-group action carries no parameter (nothing to bind it to).
	b = actionBody("enable", []string{"a"}, "g1")
	if len(b.ActionParameters) != 0 {
		t.Fatalf("expected no action parameter for non-group action, got %d", len(b.ActionParameters))
	}
	// Host-group actions bind the value under group_id; rule-group under rule_group_id.
	cases := map[string]string{
		"add-host-group":    "group_id",
		"remove-host-group": "group_id",
		"add-rule-group":    "rule_group_id",
		"remove-rule-group": "rule_group_id",
	}
	for action, wantName := range cases {
		b = actionBody(action, []string{"a"}, "g1")
		if len(b.ActionParameters) != 1 {
			t.Fatalf("%s: expected 1 action parameter, got %d", action, len(b.ActionParameters))
		}
		p := b.ActionParameters[0]
		if p.Name == nil || *p.Name != wantName || p.Value == nil || *p.Value != "g1" {
			t.Fatalf("%s: unexpected action parameter: %+v", action, p)
		}
	}
}

func TestToMaps(t *testing.T) {
	t.Parallel()
	name := "n"
	id := "p1"
	in := []*models.PreventionPolicyV1{{ID: &id, Name: &name}}
	out, err := base.ModelsToMaps(in)
	if err != nil {
		t.Fatalf("toMaps: %v", err)
	}
	if len(out) != 1 || out[0]["id"] != "p1" || out[0]["name"] != "n" {
		t.Fatalf("unexpected maps: %v", out)
	}
	// nil input yields a non-nil empty slice.
	empty, err := base.ModelsToMaps[*models.PreventionPolicyV1](nil)
	if err != nil {
		t.Fatal(err)
	}
	if empty == nil || len(empty) != 0 {
		t.Fatalf("expected non-nil empty slice, got %v", empty)
	}
}

// ---- registration --------------------------------------------------------------

// TestRegisterToolsAnnotations verifies mutator tools set complete annotations so
// DestructiveHint is never left nil (MCP default true), delete is destructive, and
// the two read-only search tools default to read-only.
func TestRegisterToolsAnnotations(t *testing.T) {
	t.Parallel()

	m := &Module{backends: map[string]backend{}, Logger: testLogger}
	byName := testutil.CollectTools(m)

	// All seven tools must be present with the falcon_ prefix.
	for _, name := range []string{
		"falcon_search_policies", "falcon_search_policy_members", "falcon_create_policy",
		"falcon_update_policy", "falcon_delete_policies", "falcon_perform_policy_action",
		"falcon_set_policy_precedence",
	} {
		if byName[name] == nil {
			t.Fatalf("missing tool %s", name)
		}
	}

	for _, name := range []string{"falcon_create_policy", "falcon_update_policy", "falcon_perform_policy_action", "falcon_set_policy_precedence"} {
		testutil.AssertMutatingAnnotations(t, name, byName[name].Annotations, false)
	}
	testutil.AssertDestructiveAnnotations(t, "falcon_delete_policies", byName["falcon_delete_policies"].Annotations, true)

	for _, name := range []string{"falcon_search_policies", "falcon_search_policy_members"} {
		tool := byName[name]
		if tool.Annotations == nil || !tool.Annotations.ReadOnlyHint {
			t.Errorf("%s: expected read-only annotation", name)
		}
	}
}

// TestRegisterResourcesServesFQLGuide verifies the policies module publishes its
// FQL guide as the falcon://policies/search/fql-guide resource with the
// Python-matching name.
func TestRegisterResourcesServesFQLGuide(t *testing.T) {
	t.Parallel()
	testutil.AssertServesFQLGuide(context.Background(), t, (&Module{backends: map[string]backend{}, Logger: testLogger}).RegisterResources, testutil.FQLGuideExpectation{
		Name: "falcon_search_policies_fql_guide",
		URI:  fqlGuideURI,
		Body: fqlGuide,
	})
}
