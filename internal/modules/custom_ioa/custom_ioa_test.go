package custom_ioa

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/crowdstrike/gofalcon/falcon/client/custom_ioa"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/go-openapi/runtime"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/crowdstrike/falcon-mcp/internal/modules/base"
	"github.com/crowdstrike/falcon-mcp/internal/testutil"
)

// metaQueryTime is a non-zero query_time for test fakes, so a handler's
// normalized meta is a populated value rather than nil.
var metaQueryTime = 0.02

var testLogger = testutil.DiscardLogger()

// fakeCustomIOA is a configurable test double for the customIOAAPI interface.
type fakeCustomIOA struct {
	queryGroupsResp *custom_ioa.QueryRuleGroupsFullOK
	queryGroupsErr  error

	queryPlatformsResp *custom_ioa.QueryPlatformsMixin0OK
	queryPlatformsErr  error

	queryRuleTypesResp *custom_ioa.QueryRuleTypesOK
	queryRuleTypesErr  error
	getRuleTypesResp   *custom_ioa.GetRuleTypesOK
	getRuleTypesErr    error
	getRuleTypesCalls  int

	createGroupResp  *custom_ioa.CreateRuleGroupMixin0Created
	createGroupErr   error
	updateGroupResp  *custom_ioa.UpdateRuleGroupMixin0OK
	updateGroupErr   error
	deleteGroupsMeta *models.MsaMetaInfo
	deleteGroupsErr  error
	createRuleResp   *custom_ioa.CreateRuleCreated
	createRuleErr    error
	updateRulesResp  *custom_ioa.UpdateRulesV2OK
	updateRulesErr   error
	deleteRulesMeta  *models.MsaMetaInfo
	deleteRulesErr   error

	lastCreateGroupBody *models.APIRuleGroupCreateRequestV1
	lastUpdateGroupBody *models.APIRuleGroupModifyRequestV1
	lastDeleteGroupIDs  []string
	lastDeleteGroupCmt  *string
	lastCreateRuleBody  *models.APIRuleCreateV1
	lastUpdateRulesBody *models.APIRuleUpdatesRequestV2
	lastDeleteRulesGrp  string
	lastDeleteRulesIDs  []string
	lastGetRuleTypeIDs  []string

	// lastGroupsOffset and lastRuleTypesOffset record the offset each handler
	// sent, so a test can assert the numeric input reaches the string-typed query
	// param intact.
	lastGroupsOffset    *string
	lastRuleTypesOffset *string
}

func (f *fakeCustomIOA) QueryRuleGroupsFull(p *custom_ioa.QueryRuleGroupsFullParams, _ ...custom_ioa.ClientOption) (*custom_ioa.QueryRuleGroupsFullOK, error) {
	f.lastGroupsOffset = p.Offset
	return f.queryGroupsResp, f.queryGroupsErr
}

func (f *fakeCustomIOA) QueryPlatformsMixin0(*custom_ioa.QueryPlatformsMixin0Params, ...custom_ioa.ClientOption) (*custom_ioa.QueryPlatformsMixin0OK, error) {
	return f.queryPlatformsResp, f.queryPlatformsErr
}

func (f *fakeCustomIOA) QueryRuleTypes(p *custom_ioa.QueryRuleTypesParams, _ ...custom_ioa.ClientOption) (*custom_ioa.QueryRuleTypesOK, error) {
	f.lastRuleTypesOffset = p.Offset
	return f.queryRuleTypesResp, f.queryRuleTypesErr
}

func (f *fakeCustomIOA) GetRuleTypes(p *custom_ioa.GetRuleTypesParams, _ ...custom_ioa.ClientOption) (*custom_ioa.GetRuleTypesOK, error) {
	f.getRuleTypesCalls++
	f.lastGetRuleTypeIDs = p.Ids
	return f.getRuleTypesResp, f.getRuleTypesErr
}

func (f *fakeCustomIOA) CreateRuleGroupMixin0(p *custom_ioa.CreateRuleGroupMixin0Params, _ ...custom_ioa.ClientOption) (*custom_ioa.CreateRuleGroupMixin0Created, error) {
	f.lastCreateGroupBody = p.Body
	return f.createGroupResp, f.createGroupErr
}

func (f *fakeCustomIOA) UpdateRuleGroupMixin0(p *custom_ioa.UpdateRuleGroupMixin0Params, _ ...custom_ioa.ClientOption) (*custom_ioa.UpdateRuleGroupMixin0OK, error) {
	f.lastUpdateGroupBody = p.Body
	return f.updateGroupResp, f.updateGroupErr
}

func (f *fakeCustomIOA) DeleteRuleGroupsMixin0(p *custom_ioa.DeleteRuleGroupsMixin0Params, _ ...custom_ioa.ClientOption) (*custom_ioa.DeleteRuleGroupsMixin0OK, error) {
	f.lastDeleteGroupIDs = p.Ids
	f.lastDeleteGroupCmt = p.Comment
	return &custom_ioa.DeleteRuleGroupsMixin0OK{Payload: &models.MsaReplyMetaOnly{Meta: f.deleteGroupsMeta}}, f.deleteGroupsErr
}

func (f *fakeCustomIOA) CreateRule(p *custom_ioa.CreateRuleParams, _ ...custom_ioa.ClientOption) (*custom_ioa.CreateRuleCreated, error) {
	f.lastCreateRuleBody = p.Body
	return f.createRuleResp, f.createRuleErr
}

func (f *fakeCustomIOA) UpdateRulesV2(p *custom_ioa.UpdateRulesV2Params, _ ...custom_ioa.ClientOption) (*custom_ioa.UpdateRulesV2OK, error) {
	f.lastUpdateRulesBody = p.Body
	return f.updateRulesResp, f.updateRulesErr
}

func (f *fakeCustomIOA) DeleteRules(p *custom_ioa.DeleteRulesParams, _ ...custom_ioa.ClientOption) (*custom_ioa.DeleteRulesOK, error) {
	f.lastDeleteRulesGrp = p.RuleGroupID
	f.lastDeleteRulesIDs = p.Ids
	return &custom_ioa.DeleteRulesOK{Payload: &models.MsaReplyMetaOnly{Meta: f.deleteRulesMeta}}, f.deleteRulesErr
}

// status400Err is a minimal runtime.ClientResponseStatus reporting HTTP 400, so
// tests can exercise the status-based FQL classification without a live call.
type status400Err struct{}

func (status400Err) Error() string        { return "status 400" }
func (status400Err) IsCode(code int) bool { return code == 400 }
func (status400Err) IsSuccess() bool      { return false }
func (status400Err) IsRedirect() bool     { return false }
func (status400Err) IsClientError() bool  { return true }
func (status400Err) IsServerError() bool  { return false }

// assert the fake satisfies the runtime interface at compile time.
var _ runtime.ClientResponseStatus = status400Err{}

// --- search_ioa_rule_groups ---

func TestSearchRuleGroupsSuccess(t *testing.T) {
	t.Parallel()

	f := &fakeCustomIOA{queryGroupsResp: &custom_ioa.QueryRuleGroupsFullOK{Payload: &models.APIRuleGroupsResponse{
		Resources: []*models.APIRuleGroupV1{{ID: new("g1"), Name: new("Suspicious")}},
		Meta:      &models.MsaMetaInfo{QueryTime: &metaQueryTime},
	}}}
	m := &Module{API: f, Logger: testLogger}

	_, out, err := m.searchRuleGroups(context.Background(), nil, SearchInput{Filter: "platform:'windows'"})
	if err != nil {
		t.Fatalf("searchRuleGroups: %v", err)
	}
	if len(out.Resources) != 1 || out.FilterUsed != "platform:'windows'" {
		t.Fatalf("unexpected result: %+v", out)
	}
	if !reflect.DeepEqual(out.Meta, base.NormalizedMeta(f.queryGroupsResp.Payload.Meta)) {
		t.Fatalf("expected normalized meta, got %+v", out.Meta)
	}
}

func TestSearchRuleGroupsEmpty(t *testing.T) {
	t.Parallel()

	f := &fakeCustomIOA{queryGroupsResp: &custom_ioa.QueryRuleGroupsFullOK{Payload: &models.APIRuleGroupsResponse{
		Resources: []*models.APIRuleGroupV1{},
	}}}
	m := &Module{API: f, Logger: testLogger}

	_, out, err := m.searchRuleGroups(context.Background(), nil, SearchInput{})
	if err != nil {
		t.Fatalf("searchRuleGroups: %v", err)
	}
	if len(out.Resources) != 0 || out.Resources == nil {
		t.Fatalf("expected non-nil empty slice, got %+v", out)
	}
}

// TestQueryOffsetConversion covers the offset conversion in both paginated Custom
// IOA tools. Each takes a numeric offset, matching the numeric offset the endpoint
// reports back in meta.pagination, while the gofalcon query params are typed as
// strings; the handlers bridge the two. A zero offset must leave the param unset
// rather than sending "0".
func TestQueryOffsetConversion(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		offset int
		want   *string
	}{
		{"zero leaves the param unset", 0, nil},
		{"positive offset is sent as digits", 25, new("25")},
	}

	for _, tt := range tests {
		t.Run("search_ioa_rule_groups/"+tt.name, func(t *testing.T) {
			t.Parallel()

			f := &fakeCustomIOA{queryGroupsResp: &custom_ioa.QueryRuleGroupsFullOK{Payload: &models.APIRuleGroupsResponse{
				Resources: []*models.APIRuleGroupV1{},
			}}}
			m := &Module{API: f, Logger: testLogger}

			if _, _, err := m.searchRuleGroups(context.Background(), nil, SearchInput{Offset: tt.offset}); err != nil {
				t.Fatalf("searchRuleGroups: %v", err)
			}
			if !reflect.DeepEqual(f.lastGroupsOffset, tt.want) {
				t.Errorf("query offset = %v, want %v", derefOrNil(f.lastGroupsOffset), derefOrNil(tt.want))
			}
		})

		t.Run("get_ioa_rule_types/"+tt.name, func(t *testing.T) {
			t.Parallel()

			f := &fakeCustomIOA{queryRuleTypesResp: &custom_ioa.QueryRuleTypesOK{Payload: &models.MsaQueryResponse{
				Resources: []string{},
			}}}
			m := &Module{API: f, Logger: testLogger}

			if _, _, err := m.getRuleTypes(context.Background(), nil, RuleTypesInput{Offset: tt.offset}); err != nil {
				t.Fatalf("getRuleTypes: %v", err)
			}
			if !reflect.DeepEqual(f.lastRuleTypesOffset, tt.want) {
				t.Errorf("query offset = %v, want %v", derefOrNil(f.lastRuleTypesOffset), derefOrNil(tt.want))
			}
		})
	}
}

// derefOrNil renders a *string for a test failure message without panicking on nil.
func derefOrNil(p *string) string {
	if p == nil {
		return "<nil>"
	}
	return *p
}

func TestSearchRuleGroupsFQLError(t *testing.T) {
	t.Parallel()

	// This endpoint has no typed *BadRequest; a bad FQL filter surfaces as a
	// generic 400. The module must classify by status and return a data result.
	f := &fakeCustomIOA{queryGroupsErr: status400Err{}}
	m := &Module{API: f, Logger: testLogger}

	_, out, err := m.searchRuleGroups(context.Background(), nil, SearchInput{Filter: "bogus(("})
	if err != nil {
		t.Fatalf("expected FQL error to be formatted, not returned: %v", err)
	}
	if len(out.Errors) != 1 || out.Errors[0].Code != 400 {
		t.Fatalf("expected one FQL error detail with code 400, got %+v", out.Errors)
	}
	if out.FQLGuide == "" || out.Hint == "" {
		t.Fatalf("expected fql_guide and hint to be populated")
	}
	if out.FilterUsed != "bogus((" {
		t.Fatalf("expected filter echoed, got %q", out.FilterUsed)
	}
}

func TestSearchRuleGroupsAPIError(t *testing.T) {
	t.Parallel()

	f := &fakeCustomIOA{queryGroupsErr: errors.New("boom")}
	m := &Module{API: f, Logger: testLogger}

	_, _, err := m.searchRuleGroups(context.Background(), nil, SearchInput{})
	if err == nil {
		t.Fatalf("expected non-FQL error to be returned")
	}
}

// --- get_ioa_platforms ---

func TestGetPlatforms(t *testing.T) {
	t.Parallel()

	f := &fakeCustomIOA{queryPlatformsResp: &custom_ioa.QueryPlatformsMixin0OK{Payload: &models.MsaQueryResponse{
		Resources: []string{"windows", "mac", "linux"},
		Meta:      &models.MsaMetaInfo{QueryTime: &metaQueryTime},
	}}}
	m := &Module{API: f, Logger: testLogger}

	_, out, err := m.getPlatforms(context.Background(), nil, struct{}{})
	if err != nil {
		t.Fatalf("getPlatforms: %v", err)
	}
	if out.Total != 3 || out.Resources[0].ID != "windows" {
		t.Fatalf("unexpected platforms: %+v", out)
	}
	if !reflect.DeepEqual(out.Meta, base.NormalizedMeta(f.queryPlatformsResp.Payload.Meta)) {
		t.Fatalf("expected normalized meta, got %+v", out.Meta)
	}
}

func TestGetPlatformsEmpty(t *testing.T) {
	t.Parallel()

	f := &fakeCustomIOA{queryPlatformsResp: &custom_ioa.QueryPlatformsMixin0OK{Payload: &models.MsaQueryResponse{
		Resources: []string{},
	}}}
	m := &Module{API: f, Logger: testLogger}

	_, out, err := m.getPlatforms(context.Background(), nil, struct{}{})
	if err != nil {
		t.Fatalf("getPlatforms: %v", err)
	}
	if out.Total != 0 || out.Resources == nil {
		t.Fatalf("expected non-nil empty slice, got %+v", out)
	}
}

// --- get_ioa_rule_types ---

func TestGetRuleTypesTwoStep(t *testing.T) {
	t.Parallel()

	f := &fakeCustomIOA{
		queryRuleTypesResp: &custom_ioa.QueryRuleTypesOK{Payload: &models.MsaQueryResponse{
			Resources: []string{"1", "2"},
			Meta:      &models.MsaMetaInfo{QueryTime: &metaQueryTime},
		}},
		getRuleTypesResp: &custom_ioa.GetRuleTypesOK{Payload: &models.APIRuleTypesResponse{
			// Returned out of query order to exercise reordering.
			Resources: []*models.APIRuleTypeV1{{ID: new("2")}, {ID: new("1")}},
		}},
	}
	m := &Module{API: f, Logger: testLogger}

	_, out, err := m.getRuleTypes(context.Background(), nil, RuleTypesInput{})
	if err != nil {
		t.Fatalf("getRuleTypes: %v", err)
	}
	if out.Total != 2 {
		t.Fatalf("expected 2 rule types, got %+v", out)
	}
	if *out.Resources[0].ID != "1" || *out.Resources[1].ID != "2" {
		t.Fatalf("expected query-order (1,2), got %q,%q", *out.Resources[0].ID, *out.Resources[1].ID)
	}
	if f.lastGetRuleTypeIDs[0] != "1" || f.lastGetRuleTypeIDs[1] != "2" {
		t.Fatalf("expected get called with query IDs, got %v", f.lastGetRuleTypeIDs)
	}
	if !reflect.DeepEqual(out.Meta, base.NormalizedMeta(f.queryRuleTypesResp.Payload.Meta)) {
		t.Fatalf("expected normalized meta, got %+v", out.Meta)
	}
}

func TestGetRuleTypesEmptySkipsFetch(t *testing.T) {
	t.Parallel()

	f := &fakeCustomIOA{queryRuleTypesResp: &custom_ioa.QueryRuleTypesOK{Payload: &models.MsaQueryResponse{
		Resources: []string{},
	}}}
	m := &Module{API: f, Logger: testLogger}

	_, out, err := m.getRuleTypes(context.Background(), nil, RuleTypesInput{})
	if err != nil {
		t.Fatalf("getRuleTypes: %v", err)
	}
	if out.Total != 0 || out.Resources == nil {
		t.Fatalf("expected non-nil empty slice, got %+v", out)
	}
	if f.getRuleTypesCalls != 0 {
		t.Fatalf("expected no detail fetch on empty query, got %d", f.getRuleTypesCalls)
	}
}

// --- create_ioa_rule_group ---

func TestCreateRuleGroupValidation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		in      CreateGroupInput
		wantErr bool
	}{
		{"missing name", CreateGroupInput{Platform: "windows"}, true},
		{"bad platform", CreateGroupInput{Name: "x", Platform: "solaris"}, true},
		{"empty platform", CreateGroupInput{Name: "x"}, true},
		{"valid", CreateGroupInput{Name: "x", Platform: "windows"}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := &fakeCustomIOA{createGroupResp: &custom_ioa.CreateRuleGroupMixin0Created{Payload: &models.APIRuleGroupsResponse{}}}
			m := &Module{API: f, Logger: testLogger}
			_, _, err := m.createRuleGroup(context.Background(), nil, tc.in)
			if tc.wantErr && !errors.Is(err, errInvalidInput) {
				t.Fatalf("expected errInvalidInput, got %v", err)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestCreateRuleGroupBody(t *testing.T) {
	t.Parallel()

	f := &fakeCustomIOA{createGroupResp: &custom_ioa.CreateRuleGroupMixin0Created{Payload: &models.APIRuleGroupsResponse{
		Resources: []*models.APIRuleGroupV1{{ID: new("new")}},
		Meta:      &models.MsaMetaInfo{QueryTime: &metaQueryTime},
	}}}
	m := &Module{API: f, Logger: testLogger}

	_, out, err := m.createRuleGroup(context.Background(), nil, CreateGroupInput{
		Name: "Grp", Platform: "windows", Description: "desc", Comment: "why",
	})
	if err != nil {
		t.Fatalf("createRuleGroup: %v", err)
	}
	if out.Total != 1 {
		t.Fatalf("expected created record, got %+v", out)
	}
	if !reflect.DeepEqual(out.Meta, base.NormalizedMeta(f.createGroupResp.Payload.Meta)) {
		t.Fatalf("expected normalized meta, got %+v", out.Meta)
	}
	b := f.lastCreateGroupBody
	if *b.Name != "Grp" || *b.Platform != "windows" || b.Description == nil || *b.Description != "desc" || b.Comment == nil || *b.Comment != "why" {
		t.Fatalf("unexpected create body: %+v", b)
	}
}

func TestCreateRuleGroupOmitsUnsetOptionals(t *testing.T) {
	t.Parallel()

	f := &fakeCustomIOA{createGroupResp: &custom_ioa.CreateRuleGroupMixin0Created{Payload: &models.APIRuleGroupsResponse{}}}
	m := &Module{API: f, Logger: testLogger}

	_, _, err := m.createRuleGroup(context.Background(), nil, CreateGroupInput{Name: "Grp", Platform: "mac"})
	if err != nil {
		t.Fatalf("createRuleGroup: %v", err)
	}
	if b := f.lastCreateGroupBody; b.Description != nil || b.Comment != nil {
		t.Fatalf("expected description/comment left nil, got desc=%v cmt=%v", b.Description, b.Comment)
	}
}

// --- update_ioa_rule_group ---

func TestUpdateRuleGroup(t *testing.T) {
	t.Parallel()

	t.Run("requires id", func(t *testing.T) {
		t.Parallel()
		m := &Module{API: &fakeCustomIOA{}, Logger: testLogger}
		_, _, err := m.updateRuleGroup(context.Background(), nil, UpdateGroupInput{Name: "x"})
		if !errors.Is(err, errInvalidInput) {
			t.Fatalf("expected errInvalidInput, got %v", err)
		}
	})

	t.Run("sends set fields and version", func(t *testing.T) {
		t.Parallel()
		f := &fakeCustomIOA{updateGroupResp: &custom_ioa.UpdateRuleGroupMixin0OK{Payload: &models.APIRuleGroupsResponse{
			Resources: []*models.APIRuleGroupV1{{ID: new("g1")}},
			Meta:      &models.MsaMetaInfo{QueryTime: &metaQueryTime},
		}}}
		m := &Module{API: f, Logger: testLogger}
		enabled := false
		_, out, err := m.updateRuleGroup(context.Background(), nil, UpdateGroupInput{
			ID: "g1", RulegroupVersion: 7, Name: "renamed", Enabled: &enabled,
		})
		if err != nil {
			t.Fatalf("updateRuleGroup: %v", err)
		}
		if out.Total != 1 {
			t.Fatalf("expected updated record, got %+v", out)
		}
		if !reflect.DeepEqual(out.Meta, base.NormalizedMeta(f.updateGroupResp.Payload.Meta)) {
			t.Fatalf("expected normalized meta, got %+v", out.Meta)
		}
		b := f.lastUpdateGroupBody
		if *b.ID != "g1" || *b.RulegroupVersion != 7 || b.Name == nil || *b.Name != "renamed" {
			t.Fatalf("unexpected update body: %+v", b)
		}
		if b.Enabled == nil || *b.Enabled {
			t.Fatalf("expected enabled=false sent explicitly, got %v", b.Enabled)
		}
	})

	t.Run("omits unset enabled", func(t *testing.T) {
		t.Parallel()
		f := &fakeCustomIOA{updateGroupResp: &custom_ioa.UpdateRuleGroupMixin0OK{Payload: &models.APIRuleGroupsResponse{}}}
		m := &Module{API: f, Logger: testLogger}
		_, _, err := m.updateRuleGroup(context.Background(), nil, UpdateGroupInput{ID: "g1", RulegroupVersion: 1, Description: "d"})
		if err != nil {
			t.Fatalf("updateRuleGroup: %v", err)
		}
		if f.lastUpdateGroupBody.Enabled != nil {
			t.Fatalf("expected enabled left unset")
		}
	})
}

// --- delete_ioa_rule_groups ---

func TestDeleteRuleGroups(t *testing.T) {
	t.Parallel()

	t.Run("empty ids", func(t *testing.T) {
		t.Parallel()
		m := &Module{API: &fakeCustomIOA{}, Logger: testLogger}
		_, _, err := m.deleteRuleGroups(context.Background(), nil, DeleteGroupsInput{})
		if !errors.Is(err, errInvalidInput) {
			t.Fatalf("expected errInvalidInput, got %v", err)
		}
	})

	t.Run("success with comment", func(t *testing.T) {
		t.Parallel()
		f := &fakeCustomIOA{deleteGroupsMeta: &models.MsaMetaInfo{QueryTime: &metaQueryTime}}
		m := &Module{API: f, Logger: testLogger}
		_, out, err := m.deleteRuleGroups(context.Background(), nil, DeleteGroupsInput{IDs: []string{"g1", "g2"}, Comment: "cleanup"})
		if err != nil {
			t.Fatalf("deleteRuleGroups: %v", err)
		}
		if !out.Ok {
			t.Fatalf("expected Ok, got %+v", out)
		}
		if len(f.lastDeleteGroupIDs) != 2 {
			t.Fatalf("expected 2 ids, got %v", f.lastDeleteGroupIDs)
		}
		if f.lastDeleteGroupCmt == nil || *f.lastDeleteGroupCmt != "cleanup" {
			t.Fatalf("expected comment passed, got %v", f.lastDeleteGroupCmt)
		}
		if !reflect.DeepEqual(out.Meta, base.NormalizedMeta(f.deleteGroupsMeta)) {
			t.Fatalf("expected normalized meta, got %+v", out.Meta)
		}
	})
}

// --- create_ioa_rule ---

func TestCreateRuleValidation(t *testing.T) {
	t.Parallel()

	valid := CreateRuleInput{
		RulegroupID: "g1", Name: "r", RuletypeID: "1", DispositionID: 20,
		PatternSeverity: "high", FieldValues: []FieldValue{{Name: "f", Value: "v"}},
	}
	tests := []struct {
		name string
		in   CreateRuleInput
	}{
		{"missing rulegroup_id", func() CreateRuleInput { c := valid; c.RulegroupID = ""; return c }()},
		{"missing name", func() CreateRuleInput { c := valid; c.Name = ""; return c }()},
		{"missing ruletype_id", func() CreateRuleInput { c := valid; c.RuletypeID = ""; return c }()},
		{"bad severity", func() CreateRuleInput { c := valid; c.PatternSeverity = "extreme"; return c }()},
		{"empty field_values", func() CreateRuleInput { c := valid; c.FieldValues = nil; return c }()},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			m := &Module{API: &fakeCustomIOA{}, Logger: testLogger}
			_, _, err := m.createRule(context.Background(), nil, tc.in)
			if !errors.Is(err, errInvalidInput) {
				t.Fatalf("expected errInvalidInput, got %v", err)
			}
		})
	}
}

func TestCreateRuleBody(t *testing.T) {
	t.Parallel()

	f := &fakeCustomIOA{createRuleResp: &custom_ioa.CreateRuleCreated{Payload: &models.APIRulesResponse{
		Resources: []*models.APIRuleV1{{InstanceID: new("r1")}},
		Meta:      &models.MsaMetaInfo{QueryTime: &metaQueryTime},
	}}}
	m := &Module{API: f, Logger: testLogger}

	_, out, err := m.createRule(context.Background(), nil, CreateRuleInput{
		RulegroupID: "g1", Name: "Block", RuletypeID: "5", DispositionID: 30, PatternSeverity: "critical",
		FieldValues: []FieldValue{{
			Name: "GrandparentImageFilename", Value: ".*winword.exe", Label: "GP", Type: "excludable",
			Values: []FieldValueEntry{{Label: "include", Value: "x"}},
		}},
	})
	if err != nil {
		t.Fatalf("createRule: %v", err)
	}
	if out.Total != 1 {
		t.Fatalf("expected created record, got %+v", out)
	}
	if !reflect.DeepEqual(out.Meta, base.NormalizedMeta(f.createRuleResp.Payload.Meta)) {
		t.Fatalf("expected normalized meta, got %+v", out.Meta)
	}
	b := f.lastCreateRuleBody
	if *b.RulegroupID != "g1" || *b.Name != "Block" || *b.RuletypeID != "5" || *b.DispositionID != 30 || *b.PatternSeverity != "critical" {
		t.Fatalf("unexpected create rule body: %+v", b)
	}
	if len(b.FieldValues) != 1 {
		t.Fatalf("expected one field value, got %d", len(b.FieldValues))
	}
	fv := b.FieldValues[0]
	if *fv.Name != "GrandparentImageFilename" || *fv.Value != ".*winword.exe" || fv.Label != "GP" || *fv.Type != "excludable" {
		t.Fatalf("unexpected field value: %+v", fv)
	}
	if len(fv.Values) != 1 || *fv.Values[0].Label != "include" || *fv.Values[0].Value != "x" {
		t.Fatalf("unexpected field value entries: %+v", fv.Values)
	}
}

// --- update_ioa_rule ---

func TestUpdateRuleValidation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   UpdateRuleInput
	}{
		{"missing rulegroup_id", UpdateRuleInput{InstanceID: "r1"}},
		{"missing instance_id", UpdateRuleInput{RulegroupID: "g1"}},
		{"bad severity", UpdateRuleInput{RulegroupID: "g1", InstanceID: "r1", PatternSeverity: "extreme"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			m := &Module{API: &fakeCustomIOA{}, Logger: testLogger}
			_, _, err := m.updateRule(context.Background(), nil, tc.in)
			if !errors.Is(err, errInvalidInput) {
				t.Fatalf("expected errInvalidInput, got %v", err)
			}
		})
	}
}

func TestUpdateRuleBody(t *testing.T) {
	t.Parallel()

	f := &fakeCustomIOA{updateRulesResp: &custom_ioa.UpdateRulesV2OK{Payload: &models.APIRulesResponse{
		Resources: []*models.APIRuleV1{{InstanceID: new("r1")}},
		Meta:      &models.MsaMetaInfo{QueryTime: &metaQueryTime},
	}}}
	m := &Module{API: f, Logger: testLogger}

	enabled := true
	disp := int32(10)
	_, out, err := m.updateRule(context.Background(), nil, UpdateRuleInput{
		RulegroupID: "g1", RulegroupVersion: 3, InstanceID: "r1", Name: "renamed",
		Enabled: &enabled, PatternSeverity: "low", DispositionID: &disp,
		FieldValues: []FieldValue{{Name: "f", Value: "v"}},
	})
	if err != nil {
		t.Fatalf("updateRule: %v", err)
	}
	if out.Total != 1 {
		t.Fatalf("expected updated record, got %+v", out)
	}
	if !reflect.DeepEqual(out.Meta, base.NormalizedMeta(f.updateRulesResp.Payload.Meta)) {
		t.Fatalf("expected normalized meta, got %+v", out.Meta)
	}
	b := f.lastUpdateRulesBody
	if *b.RulegroupID != "g1" || *b.RulegroupVersion != 3 {
		t.Fatalf("unexpected update envelope: %+v", b)
	}
	if len(b.RuleUpdates) != 1 {
		t.Fatalf("expected one rule update, got %d", len(b.RuleUpdates))
	}
	ru := b.RuleUpdates[0]
	if *ru.InstanceID != "r1" || *ru.RulegroupVersion != 3 || *ru.Name != "renamed" || *ru.PatternSeverity != "low" || *ru.DispositionID != 10 {
		t.Fatalf("unexpected rule update: %+v", ru)
	}
	if ru.Enabled == nil || !*ru.Enabled {
		t.Fatalf("expected enabled=true, got %v", ru.Enabled)
	}
	if len(ru.FieldValues) != 1 {
		t.Fatalf("expected field values propagated, got %d", len(ru.FieldValues))
	}
}

func TestUpdateRuleOmitsUnsetFields(t *testing.T) {
	t.Parallel()

	f := &fakeCustomIOA{updateRulesResp: &custom_ioa.UpdateRulesV2OK{Payload: &models.APIRulesResponse{}}}
	m := &Module{API: f, Logger: testLogger}

	_, _, err := m.updateRule(context.Background(), nil, UpdateRuleInput{RulegroupID: "g1", RulegroupVersion: 1, InstanceID: "r1"})
	if err != nil {
		t.Fatalf("updateRule: %v", err)
	}
	ru := f.lastUpdateRulesBody.RuleUpdates[0]
	if ru.Name != nil || ru.Enabled != nil || ru.PatternSeverity != nil || ru.DispositionID != nil || ru.FieldValues != nil {
		t.Fatalf("expected unset fields left nil, got %+v", ru)
	}
}

// --- delete_ioa_rules ---

func TestDeleteRules(t *testing.T) {
	t.Parallel()

	t.Run("missing rule_group_id", func(t *testing.T) {
		t.Parallel()
		m := &Module{API: &fakeCustomIOA{}, Logger: testLogger}
		_, _, err := m.deleteRules(context.Background(), nil, DeleteRulesInput{IDs: []string{"r1"}})
		if !errors.Is(err, errInvalidInput) {
			t.Fatalf("expected errInvalidInput, got %v", err)
		}
	})

	t.Run("empty ids", func(t *testing.T) {
		t.Parallel()
		m := &Module{API: &fakeCustomIOA{}, Logger: testLogger}
		_, _, err := m.deleteRules(context.Background(), nil, DeleteRulesInput{RuleGroupID: "g1"})
		if !errors.Is(err, errInvalidInput) {
			t.Fatalf("expected errInvalidInput, got %v", err)
		}
	})

	t.Run("success", func(t *testing.T) {
		t.Parallel()
		f := &fakeCustomIOA{deleteRulesMeta: &models.MsaMetaInfo{QueryTime: &metaQueryTime}}
		m := &Module{API: f, Logger: testLogger}
		_, out, err := m.deleteRules(context.Background(), nil, DeleteRulesInput{RuleGroupID: "g1", IDs: []string{"r1", "r2"}})
		if err != nil {
			t.Fatalf("deleteRules: %v", err)
		}
		if !out.Ok {
			t.Fatalf("expected Ok, got %+v", out)
		}
		if f.lastDeleteRulesGrp != "g1" || len(f.lastDeleteRulesIDs) != 2 {
			t.Fatalf("expected group g1 and 2 ids, got grp=%q ids=%v", f.lastDeleteRulesGrp, f.lastDeleteRulesIDs)
		}
		if !reflect.DeepEqual(out.Meta, base.NormalizedMeta(f.deleteRulesMeta)) {
			t.Fatalf("expected normalized meta, got %+v", out.Meta)
		}
	})
}

// --- write-scope error propagation ---

func TestMutatingScopeError(t *testing.T) {
	t.Parallel()

	// A transport error from a mutating op must be surfaced as a hard error, not
	// swallowed — otherwise a caller could believe a create/delete succeeded.
	f := &fakeCustomIOA{createGroupErr: errors.New("403 forbidden")}
	m := &Module{API: f, Logger: testLogger}
	_, _, err := m.createRuleGroup(context.Background(), nil, CreateGroupInput{Name: "x", Platform: "windows"})
	if err == nil {
		t.Fatalf("expected create error to propagate")
	}
}

// --- resources ---

// TestRegisterResourcesServesFQLGuide verifies the module publishes its FQL
// guide as the falcon://custom-ioa/rule-groups/fql-guide resource with the
// Python-matching name, and that reading it returns the embedded guide text.
func TestRegisterResourcesServesFQLGuide(t *testing.T) {
	t.Parallel()
	testutil.AssertServesFQLGuide(context.Background(), t, (&Module{API: &fakeCustomIOA{}, Logger: testLogger}).RegisterResources, testutil.FQLGuideExpectation{
		Name: "falcon_search_ioa_rule_groups_fql_guide",
		URI:  fqlGuideURI,
		Body: fqlGuide,
	})
}

// --- annotations ---

// TestRegisterToolsAnnotations verifies read-only tools default to read-only and
// mutating tools set complete annotations so DestructiveHint is never left nil
// (MCP default true). Update tools are non-destructive but idempotent.
func TestRegisterToolsAnnotations(t *testing.T) {
	t.Parallel()

	var entries []base.ToolEntry
	reg := testutil.CaptureRegistrar(func(e base.ToolEntry) { entries = append(entries, e) })
	m := &Module{API: &fakeCustomIOA{}, Logger: testLogger}
	m.RegisterTools(reg)

	byName := map[string]*mcp.Tool{}
	for _, e := range entries {
		byName[e.Tool.Name] = e.Tool
	}

	// Read-only tools.
	for _, name := range []string{
		"falcon_search_ioa_rule_groups",
		"falcon_get_ioa_platforms",
		"falcon_get_ioa_rule_types",
	} {
		tool := byName[name]
		if tool == nil {
			t.Fatalf("missing tool %s", name)
		}
		testutil.AssertReadOnlyAnnotations(t, name, tool.Annotations)
	}

	// Create tools: non-read-only, non-destructive, non-idempotent.
	for _, name := range []string{"falcon_create_ioa_rule_group", "falcon_create_ioa_rule"} {
		tool := byName[name]
		if tool == nil {
			t.Fatalf("missing tool %s", name)
		}
		testutil.AssertMutatingAnnotations(t, name, tool.Annotations, false)
	}

	// Update tools: non-read-only, non-destructive, idempotent.
	for _, name := range []string{"falcon_update_ioa_rule_group", "falcon_update_ioa_rule"} {
		tool := byName[name]
		if tool == nil {
			t.Fatalf("missing tool %s", name)
		}
		testutil.AssertMutatingAnnotations(t, name, tool.Annotations, true)
	}

	// Delete tools: destructive, idempotent.
	for _, name := range []string{"falcon_delete_ioa_rule_groups", "falcon_delete_ioa_rules"} {
		tool := byName[name]
		if tool == nil {
			t.Fatalf("missing tool %s", name)
		}
		testutil.AssertDestructiveAnnotations(t, name, tool.Annotations, true)
	}
}
