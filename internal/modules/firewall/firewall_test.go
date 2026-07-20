package firewall

import (
	"context"
	"errors"
	"log/slog"
	"testing"

	"github.com/crowdstrike/gofalcon/falcon/client/firewall_management"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/crowdstrike/falcon-mcp/internal/modules/base"
)

// testLogger discards output; modules require a non-nil logger.
var testLogger = slog.New(slog.DiscardHandler)

// fakeFirewall is a configurable test double for the firewallAPI interface. It
// records the last params passed to each operation so tests can assert on how
// the handlers translate their inputs.
type fakeFirewall struct {
	queryRulesResp *firewall_management.QueryRulesOK
	queryRulesErr  error
	getRulesResp   *firewall_management.GetRulesOK
	getRulesErr    error

	queryGroupsResp *firewall_management.QueryRuleGroupsOK
	queryGroupsErr  error
	getGroupsResp   *firewall_management.GetRuleGroupsOK
	getGroupsErr    error

	queryPolicyResp *firewall_management.QueryPolicyRulesOK
	queryPolicyErr  error

	createResp *firewall_management.CreateRuleGroupCreated
	createErr  error
	deleteResp *firewall_management.DeleteRuleGroupsOK
	deleteErr  error

	lastQueryRules   *firewall_management.QueryRulesParams
	lastGetRules     *firewall_management.GetRulesParams
	lastQueryGroups  *firewall_management.QueryRuleGroupsParams
	lastGetGroups    *firewall_management.GetRuleGroupsParams
	lastQueryPolicy  *firewall_management.QueryPolicyRulesParams
	lastCreateParams *firewall_management.CreateRuleGroupParams
	lastDeleteParams *firewall_management.DeleteRuleGroupsParams

	getRulesCalls  int
	getGroupsCalls int
}

func (f *fakeFirewall) QueryRules(p *firewall_management.QueryRulesParams, _ ...firewall_management.ClientOption) (*firewall_management.QueryRulesOK, error) {
	f.lastQueryRules = p
	return f.queryRulesResp, f.queryRulesErr
}

func (f *fakeFirewall) GetRules(p *firewall_management.GetRulesParams, _ ...firewall_management.ClientOption) (*firewall_management.GetRulesOK, error) {
	f.getRulesCalls++
	f.lastGetRules = p
	return f.getRulesResp, f.getRulesErr
}

func (f *fakeFirewall) QueryRuleGroups(p *firewall_management.QueryRuleGroupsParams, _ ...firewall_management.ClientOption) (*firewall_management.QueryRuleGroupsOK, error) {
	f.lastQueryGroups = p
	return f.queryGroupsResp, f.queryGroupsErr
}

func (f *fakeFirewall) GetRuleGroups(p *firewall_management.GetRuleGroupsParams, _ ...firewall_management.ClientOption) (*firewall_management.GetRuleGroupsOK, error) {
	f.getGroupsCalls++
	f.lastGetGroups = p
	return f.getGroupsResp, f.getGroupsErr
}

func (f *fakeFirewall) QueryPolicyRules(p *firewall_management.QueryPolicyRulesParams, _ ...firewall_management.ClientOption) (*firewall_management.QueryPolicyRulesOK, error) {
	f.lastQueryPolicy = p
	return f.queryPolicyResp, f.queryPolicyErr
}

func (f *fakeFirewall) CreateRuleGroup(p *firewall_management.CreateRuleGroupParams, _ ...firewall_management.ClientOption) (*firewall_management.CreateRuleGroupCreated, error) {
	f.lastCreateParams = p
	return f.createResp, f.createErr
}

func (f *fakeFirewall) DeleteRuleGroups(p *firewall_management.DeleteRuleGroupsParams, _ ...firewall_management.ClientOption) (*firewall_management.DeleteRuleGroupsOK, error) {
	f.lastDeleteParams = p
	return f.deleteResp, f.deleteErr
}

func str(s string) *string { return &s }
func i32(v int32) *int32   { return &v }

func newModule(f *fakeFirewall) *Module {
	return &Module{API: f, Concurrency: 4, Logger: testLogger}
}

// --- search_firewall_rules ---

func TestSearchFirewallRulesSuccess(t *testing.T) {
	t.Parallel()

	f := &fakeFirewall{
		queryRulesResp: &firewall_management.QueryRulesOK{Payload: &models.FwmgrAPIQueryResponse{
			Resources: []string{"r1", "r2"},
			Meta:      &models.FwmgrAPIMetaInfo{},
		}},
		getRulesResp: &firewall_management.GetRulesOK{Payload: &models.FwmgrAPIRulesResponse{
			Resources: []*models.FwmgrFirewallRuleV1{{ID: str("r1")}, {ID: str("r2")}},
		}},
	}
	m := newModule(f)

	_, out, err := m.searchFirewallRules(context.Background(), nil, SearchRulesInput{Filter: "enabled:true"})
	if err != nil {
		t.Fatalf("searchFirewallRules: %v", err)
	}
	if len(out.Resources) != 2 || out.FilterUsed != "enabled:true" {
		t.Fatalf("unexpected result: %+v", out)
	}
	if f.getRulesCalls != 1 {
		t.Fatalf("expected 1 detail fetch, got %d", f.getRulesCalls)
	}
	if out.Meta != any(f.queryRulesResp.Payload.Meta) {
		t.Fatalf("expected verbatim meta passthrough, got %+v", out.Meta)
	}
}

func TestSearchFirewallRulesEmpty(t *testing.T) {
	t.Parallel()

	f := &fakeFirewall{queryRulesResp: &firewall_management.QueryRulesOK{Payload: &models.FwmgrAPIQueryResponse{
		Resources: []string{},
	}}}
	m := newModule(f)

	_, out, err := m.searchFirewallRules(context.Background(), nil, SearchRulesInput{Filter: "enabled:true"})
	if err != nil {
		t.Fatalf("searchFirewallRules: %v", err)
	}
	if len(out.Resources) != 0 || out.Resources == nil {
		t.Fatalf("expected non-nil empty slice, got %+v", out)
	}
	if f.getRulesCalls != 0 {
		t.Fatalf("expected no detail fetch on empty result, got %d", f.getRulesCalls)
	}
}

func TestSearchFirewallRulesFQLError(t *testing.T) {
	t.Parallel()

	badReq := &firewall_management.QueryRulesBadRequest{Payload: &models.FwmgrMsaspecResponseFields{
		Errors: []*models.FwmgrMsaspecError{{Code: i32(400), Message: str("invalid filter")}},
	}}
	f := &fakeFirewall{queryRulesErr: badReq}
	m := newModule(f)

	_, out, err := m.searchFirewallRules(context.Background(), nil, SearchRulesInput{Filter: "bogus:::"})
	if err != nil {
		t.Fatalf("expected FQL error to be formatted, not returned: %v", err)
	}
	if len(out.Errors) != 1 || out.Errors[0].Message != "invalid filter" {
		t.Fatalf("expected FQL error detail, got %+v", out.Errors)
	}
	if out.FQLGuide == "" || out.Hint == "" {
		t.Fatalf("expected fql_guide and hint to be populated")
	}
	if f.getRulesCalls != 0 {
		t.Fatalf("expected no detail fetch on FQL error, got %d", f.getRulesCalls)
	}
}

func TestSearchFirewallRulesAPIError(t *testing.T) {
	t.Parallel()

	f := &fakeFirewall{queryRulesErr: errors.New("boom")}
	m := newModule(f)

	_, _, err := m.searchFirewallRules(context.Background(), nil, SearchRulesInput{})
	if err == nil {
		t.Fatalf("expected non-FQL error to be returned")
	}
}

func TestSearchFirewallRulesDetailFetchError(t *testing.T) {
	t.Parallel()

	// The query step succeeds and returns IDs, but the get-by-IDs detail fetch
	// fails: the error must propagate rather than be swallowed into an empty
	// result.
	f := &fakeFirewall{
		queryRulesResp: &firewall_management.QueryRulesOK{Payload: &models.FwmgrAPIQueryResponse{
			Resources: []string{"r1"},
		}},
		getRulesErr: errors.New("detail boom"),
	}
	m := newModule(f)

	_, _, err := m.searchFirewallRules(context.Background(), nil, SearchRulesInput{Filter: "enabled:true"})
	if err == nil {
		t.Fatalf("expected detail-fetch error to be returned")
	}
	if f.getRulesCalls != 1 {
		t.Fatalf("expected detail fetch to be attempted once, got %d", f.getRulesCalls)
	}
}

func TestSearchFirewallRulesPassesParams(t *testing.T) {
	t.Parallel()

	f := &fakeFirewall{queryRulesResp: &firewall_management.QueryRulesOK{Payload: &models.FwmgrAPIQueryResponse{
		Resources: []string{},
	}}}
	m := newModule(f)

	_, _, err := m.searchFirewallRules(context.Background(), nil, SearchRulesInput{
		Filter: "enabled:true", Limit: 25, Offset: 50, Sort: "name.asc", Q: "block", After: "tok",
	})
	if err != nil {
		t.Fatalf("searchFirewallRules: %v", err)
	}
	p := f.lastQueryRules
	if p.Limit == nil || *p.Limit != 25 {
		t.Errorf("limit = %v, want 25", p.Limit)
	}
	if p.Offset == nil || *p.Offset != "50" {
		t.Errorf("offset = %v, want \"50\"", p.Offset)
	}
	if p.Sort == nil || *p.Sort != "name.asc" {
		t.Errorf("sort = %v, want name.asc", p.Sort)
	}
	if p.Q == nil || *p.Q != "block" {
		t.Errorf("q = %v, want block", p.Q)
	}
	if p.After == nil || *p.After != "tok" {
		t.Errorf("after = %v, want tok", p.After)
	}
}

func TestSearchFirewallRulesDefaultLimit(t *testing.T) {
	t.Parallel()

	f := &fakeFirewall{queryRulesResp: &firewall_management.QueryRulesOK{Payload: &models.FwmgrAPIQueryResponse{
		Resources: []string{},
	}}}
	m := newModule(f)

	_, _, err := m.searchFirewallRules(context.Background(), nil, SearchRulesInput{})
	if err != nil {
		t.Fatalf("searchFirewallRules: %v", err)
	}
	if p := f.lastQueryRules; p.Limit == nil || *p.Limit != defaultLimit {
		t.Fatalf("expected default limit %d, got %v", defaultLimit, p.Limit)
	}
}

// --- search_firewall_rule_groups ---

func TestSearchFirewallRuleGroupsSuccess(t *testing.T) {
	t.Parallel()

	f := &fakeFirewall{
		queryGroupsResp: &firewall_management.QueryRuleGroupsOK{Payload: &models.FwmgrAPIQueryResponse{
			Resources: []string{"g1"},
			Meta:      &models.FwmgrAPIMetaInfo{},
		}},
		getGroupsResp: &firewall_management.GetRuleGroupsOK{Payload: &models.FwmgrAPIRuleGroupsResponse{
			Resources: []*models.FwmgrAPIRuleGroupV1{{ID: str("g1")}},
		}},
	}
	m := newModule(f)

	_, out, err := m.searchFirewallRuleGroups(context.Background(), nil, SearchRuleGroupsInput{Filter: "platform:'windows'"})
	if err != nil {
		t.Fatalf("searchFirewallRuleGroups: %v", err)
	}
	if len(out.Resources) != 1 {
		t.Fatalf("unexpected result: %+v", out)
	}
	if f.getGroupsCalls != 1 {
		t.Fatalf("expected 1 detail fetch, got %d", f.getGroupsCalls)
	}
	if out.Meta != any(f.queryGroupsResp.Payload.Meta) {
		t.Fatalf("expected verbatim meta passthrough, got %+v", out.Meta)
	}
}

func TestSearchFirewallRuleGroupsEmpty(t *testing.T) {
	t.Parallel()

	f := &fakeFirewall{queryGroupsResp: &firewall_management.QueryRuleGroupsOK{Payload: &models.FwmgrAPIQueryResponse{
		Resources: []string{},
	}}}
	m := newModule(f)

	_, out, err := m.searchFirewallRuleGroups(context.Background(), nil, SearchRuleGroupsInput{})
	if err != nil {
		t.Fatalf("searchFirewallRuleGroups: %v", err)
	}
	if len(out.Resources) != 0 || out.Resources == nil {
		t.Fatalf("expected non-nil empty slice, got %+v", out)
	}
	if f.getGroupsCalls != 0 {
		t.Fatalf("expected no detail fetch on empty result, got %d", f.getGroupsCalls)
	}
}

func TestSearchFirewallRuleGroupsFQLError(t *testing.T) {
	t.Parallel()

	badReq := &firewall_management.QueryRuleGroupsBadRequest{Payload: &models.FwmgrMsaspecResponseFields{
		Errors: []*models.FwmgrMsaspecError{{Code: i32(400), Message: str("bad group filter")}},
	}}
	f := &fakeFirewall{queryGroupsErr: badReq}
	m := newModule(f)

	_, out, err := m.searchFirewallRuleGroups(context.Background(), nil, SearchRuleGroupsInput{Filter: "bogus"})
	if err != nil {
		t.Fatalf("expected FQL error to be formatted, not returned: %v", err)
	}
	if len(out.Errors) != 1 || out.Errors[0].Message != "bad group filter" {
		t.Fatalf("expected FQL error detail, got %+v", out.Errors)
	}
}

func TestSearchFirewallRuleGroupsDetailFetchError(t *testing.T) {
	t.Parallel()

	f := &fakeFirewall{
		queryGroupsResp: &firewall_management.QueryRuleGroupsOK{Payload: &models.FwmgrAPIQueryResponse{
			Resources: []string{"g1"},
		}},
		getGroupsErr: errors.New("detail boom"),
	}
	m := newModule(f)

	_, _, err := m.searchFirewallRuleGroups(context.Background(), nil, SearchRuleGroupsInput{Filter: "platform:'windows'"})
	if err == nil {
		t.Fatalf("expected detail-fetch error to be returned")
	}
	if f.getGroupsCalls != 1 {
		t.Fatalf("expected detail fetch to be attempted once, got %d", f.getGroupsCalls)
	}
}

// --- search_firewall_policy_rules ---

func TestSearchFirewallPolicyRulesSuccess(t *testing.T) {
	t.Parallel()

	f := &fakeFirewall{
		queryPolicyResp: &firewall_management.QueryPolicyRulesOK{Payload: &models.FwmgrAPIQueryResponse{
			Resources: []string{"r1"},
			Meta:      &models.FwmgrAPIMetaInfo{},
		}},
		getRulesResp: &firewall_management.GetRulesOK{Payload: &models.FwmgrAPIRulesResponse{
			Resources: []*models.FwmgrFirewallRuleV1{{ID: str("r1")}},
		}},
	}
	m := newModule(f)

	_, out, err := m.searchFirewallPolicyRules(context.Background(), nil, SearchPolicyRulesInput{PolicyID: "p1"})
	if err != nil {
		t.Fatalf("searchFirewallPolicyRules: %v", err)
	}
	if len(out.Resources) != 1 {
		t.Fatalf("unexpected result: %+v", out)
	}
	if f.lastQueryPolicy.ID == nil || *f.lastQueryPolicy.ID != "p1" {
		t.Fatalf("expected policy id p1, got %v", f.lastQueryPolicy.ID)
	}
	if f.getRulesCalls != 1 {
		t.Fatalf("expected rule detail fetch via GetRules, got %d", f.getRulesCalls)
	}
	if out.Meta != any(f.queryPolicyResp.Payload.Meta) {
		t.Fatalf("expected verbatim meta passthrough, got %+v", out.Meta)
	}
}

func TestSearchFirewallPolicyRulesRequiresPolicyID(t *testing.T) {
	t.Parallel()

	m := newModule(&fakeFirewall{})
	_, _, err := m.searchFirewallPolicyRules(context.Background(), nil, SearchPolicyRulesInput{})
	if !errors.Is(err, errInvalidInput) {
		t.Fatalf("expected errInvalidInput for missing policy_id, got %v", err)
	}
}

func TestSearchFirewallPolicyRulesFQLError(t *testing.T) {
	t.Parallel()

	badReq := &firewall_management.QueryPolicyRulesBadRequest{Payload: &models.FwmgrMsaspecResponseFields{
		Errors: []*models.FwmgrMsaspecError{{Code: i32(400), Message: str("bad policy filter")}},
	}}
	f := &fakeFirewall{queryPolicyErr: badReq}
	m := newModule(f)

	_, out, err := m.searchFirewallPolicyRules(context.Background(), nil, SearchPolicyRulesInput{PolicyID: "p1", Filter: "bogus"})
	if err != nil {
		t.Fatalf("expected FQL error to be formatted, not returned: %v", err)
	}
	if len(out.Errors) != 1 || out.Errors[0].Message != "bad policy filter" {
		t.Fatalf("expected FQL error detail, got %+v", out.Errors)
	}
}

// --- create_firewall_rule_group ---

func TestCreateFirewallRuleGroupValidation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		in      CreateInput
		wantErr bool
	}{
		{"missing name and platform", CreateInput{Rules: []*models.FwmgrAPIRuleCreateRequestV1{{}}}, true},
		{"missing platform", CreateInput{Name: "grp", Rules: []*models.FwmgrAPIRuleCreateRequestV1{{}}}, true},
		{"missing name", CreateInput{Platform: "windows", Rules: []*models.FwmgrAPIRuleCreateRequestV1{{}}}, true},
		{"missing rules and clone_id", CreateInput{Name: "grp", Platform: "windows"}, true},
		{"valid with rules", CreateInput{Name: "grp", Platform: "windows", Rules: []*models.FwmgrAPIRuleCreateRequestV1{{Name: str("r")}}}, false},
		{"valid with clone_id", CreateInput{Name: "grp", Platform: "windows", CloneID: "src"}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := &fakeFirewall{createResp: &firewall_management.CreateRuleGroupCreated{Payload: &models.FwmgrAPIQueryResponse{}}}
			m := newModule(f)
			_, _, err := m.createFirewallRuleGroup(context.Background(), nil, tc.in)
			if tc.wantErr && !errors.Is(err, errInvalidInput) {
				t.Fatalf("expected errInvalidInput, got %v", err)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestCreateFirewallRuleGroupBody(t *testing.T) {
	t.Parallel()

	f := &fakeFirewall{createResp: &firewall_management.CreateRuleGroupCreated{Payload: &models.FwmgrAPIQueryResponse{
		Resources: []string{"new-group"},
		Meta:      &models.FwmgrAPIMetaInfo{},
	}}}
	m := newModule(f)

	_, out, err := m.createFirewallRuleGroup(context.Background(), nil, CreateInput{
		Name:        "Prod Outbound",
		Platform:    "windows",
		Description: "prod",
		Rules:       []*models.FwmgrAPIRuleCreateRequestV1{{Name: str("r1")}},
		Comment:     "audit",
	})
	if err != nil {
		t.Fatalf("createFirewallRuleGroup: %v", err)
	}
	if out.Total != 1 || out.Resources[0] != "new-group" {
		t.Fatalf("expected created id returned, got %+v", out)
	}
	if out.Meta != any(f.createResp.Payload.Meta) {
		t.Fatalf("expected verbatim meta passthrough, got %+v", out.Meta)
	}
	body := f.lastCreateParams.Body
	if body.Name == nil || *body.Name != "Prod Outbound" {
		t.Errorf("name = %v, want Prod Outbound", body.Name)
	}
	if body.Platform == nil || *body.Platform != "windows" {
		t.Errorf("platform = %v, want windows", body.Platform)
	}
	if body.Enabled == nil || !*body.Enabled {
		t.Errorf("enabled = %v, want default true", body.Enabled)
	}
	if body.Description == nil || *body.Description != "prod" {
		t.Errorf("description = %v, want prod", body.Description)
	}
	if len(body.Rules) != 1 {
		t.Errorf("rules len = %d, want 1", len(body.Rules))
	}
	if f.lastCreateParams.Comment == nil || *f.lastCreateParams.Comment != "audit" {
		t.Errorf("comment = %v, want audit", f.lastCreateParams.Comment)
	}
}

func TestCreateFirewallRuleGroupEnabledFalse(t *testing.T) {
	t.Parallel()

	f := &fakeFirewall{createResp: &firewall_management.CreateRuleGroupCreated{Payload: &models.FwmgrAPIQueryResponse{}}}
	m := newModule(f)
	disabled := false

	_, _, err := m.createFirewallRuleGroup(context.Background(), nil, CreateInput{
		Name:     "grp",
		Platform: "windows",
		Rules:    []*models.FwmgrAPIRuleCreateRequestV1{{Name: str("r1")}},
		Enabled:  &disabled,
	})
	if err != nil {
		t.Fatalf("createFirewallRuleGroup: %v", err)
	}
	if body := f.lastCreateParams.Body; body.Enabled == nil || *body.Enabled {
		t.Fatalf("expected enabled=false to be honored, got %v", body.Enabled)
	}
}

func TestCreateFirewallRuleGroupCloneSetsLibrary(t *testing.T) {
	t.Parallel()

	f := &fakeFirewall{createResp: &firewall_management.CreateRuleGroupCreated{Payload: &models.FwmgrAPIQueryResponse{}}}
	m := newModule(f)

	_, _, err := m.createFirewallRuleGroup(context.Background(), nil, CreateInput{
		Name:     "grp",
		Platform: "windows",
		CloneID:  "src-group",
		Library:  true,
	})
	if err != nil {
		t.Fatalf("createFirewallRuleGroup: %v", err)
	}
	p := f.lastCreateParams
	if p.CloneID == nil || *p.CloneID != "src-group" {
		t.Errorf("clone_id = %v, want src-group", p.CloneID)
	}
	if p.Library == nil || *p.Library != "true" {
		t.Errorf("library = %v, want \"true\"", p.Library)
	}
}

// --- delete_firewall_rule_groups ---

func TestDeleteFirewallRuleGroupsValidation(t *testing.T) {
	t.Parallel()

	m := newModule(&fakeFirewall{})
	_, _, err := m.deleteFirewallRuleGroups(context.Background(), nil, DeleteInput{})
	if !errors.Is(err, errInvalidInput) {
		t.Fatalf("expected errInvalidInput for empty ids, got %v", err)
	}
}

func TestDeleteFirewallRuleGroupsSuccess(t *testing.T) {
	t.Parallel()

	f := &fakeFirewall{deleteResp: &firewall_management.DeleteRuleGroupsOK{Payload: &models.FwmgrAPIQueryResponse{
		Resources: []string{"g1", "g2"},
		Meta:      &models.FwmgrAPIMetaInfo{},
	}}}
	m := newModule(f)

	_, out, err := m.deleteFirewallRuleGroups(context.Background(), nil, DeleteInput{IDs: []string{"g1", "g2"}, Comment: "cleanup"})
	if err != nil {
		t.Fatalf("deleteFirewallRuleGroups: %v", err)
	}
	if out.Total != 2 {
		t.Fatalf("expected 2 deleted ids, got %+v", out)
	}
	if out.Meta != any(f.deleteResp.Payload.Meta) {
		t.Fatalf("expected verbatim meta passthrough, got %+v", out.Meta)
	}
	if len(f.lastDeleteParams.Ids) != 2 {
		t.Fatalf("expected 2 ids passed, got %v", f.lastDeleteParams.Ids)
	}
	if f.lastDeleteParams.Comment == nil || *f.lastDeleteParams.Comment != "cleanup" {
		t.Fatalf("expected comment passed through, got %v", f.lastDeleteParams.Comment)
	}
}

func TestDeleteFirewallRuleGroupsAPIError(t *testing.T) {
	t.Parallel()

	f := &fakeFirewall{deleteErr: errors.New("boom")}
	m := newModule(f)

	_, _, err := m.deleteFirewallRuleGroups(context.Background(), nil, DeleteInput{IDs: []string{"g1"}})
	if err == nil {
		t.Fatalf("expected API error to be returned")
	}
}

// --- resource + annotation registration ---

// TestRegisterResourcesServesFQLGuide verifies the firewall module publishes its
// FQL guide as the falcon://firewall/rules/fql-guide resource, with the
// Python-matching name, and that reading it returns the embedded guide text.
func TestRegisterResourcesServesFQLGuide(t *testing.T) {
	t.Parallel()

	srv := mcp.NewServer(&mcp.Implementation{Name: "test", Version: "test"}, nil)
	newModule(&fakeFirewall{}).RegisterResources(srv)

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
	if len(list.Resources) != 1 {
		t.Fatalf("expected 1 resource, got %d", len(list.Resources))
	}
	if got := list.Resources[0]; got.Name != "falcon_search_firewall_rules_fql_guide" || got.URI != fqlGuideURI {
		t.Fatalf("resource = {name:%q uri:%q}, want falcon_search_firewall_rules_fql_guide / %s", got.Name, got.URI, fqlGuideURI)
	}

	read, err := cs.ReadResource(ctx, &mcp.ReadResourceParams{URI: fqlGuideURI})
	if err != nil {
		t.Fatalf("ReadResource: %v", err)
	}
	if len(read.Contents) != 1 || read.Contents[0].Text != fqlGuide {
		t.Fatalf("read content does not match embedded guide")
	}
}

// TestRegisterToolsAnnotations verifies each tool advertises the correct
// annotations: the three searches read-only, create mutating, delete
// destructive.
func TestRegisterToolsAnnotations(t *testing.T) {
	t.Parallel()

	var entries []base.ToolEntry
	reg := captureRegistrar(func(e base.ToolEntry) { entries = append(entries, e) })
	newModule(&fakeFirewall{}).RegisterTools(reg)

	byName := map[string]*mcp.Tool{}
	for _, e := range entries {
		byName[e.Tool.Name] = e.Tool
	}

	for _, name := range []string{
		"falcon_search_firewall_rules",
		"falcon_search_firewall_rule_groups",
		"falcon_search_firewall_policy_rules",
	} {
		tool := byName[name]
		if tool == nil {
			t.Fatalf("missing %s", name)
		}
		assertReadOnlyAnnotations(t, name, tool.Annotations)
	}

	create := byName["falcon_create_firewall_rule_group"]
	if create == nil {
		t.Fatal("missing falcon_create_firewall_rule_group")
	}
	assertMutatingAnnotations(t, "falcon_create_firewall_rule_group", create.Annotations)

	del := byName["falcon_delete_firewall_rule_groups"]
	if del == nil {
		t.Fatal("missing falcon_delete_firewall_rule_groups")
	}
	assertDestructiveAnnotations(t, "falcon_delete_firewall_rule_groups", del.Annotations, true)
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

func assertMutatingAnnotations(t *testing.T, name string, a *mcp.ToolAnnotations) {
	t.Helper()
	if a == nil {
		t.Fatalf("%s: annotations nil", name)
	}
	if a.ReadOnlyHint {
		t.Errorf("%s: ReadOnlyHint = true, want false", name)
	}
	if a.IdempotentHint {
		t.Errorf("%s: IdempotentHint = true, want false", name)
	}
	if a.DestructiveHint == nil || *a.DestructiveHint {
		t.Errorf("%s: DestructiveHint = %v, want non-nil false (MCP defaults omitted to true)", name, a.DestructiveHint)
	}
	if a.OpenWorldHint == nil || !*a.OpenWorldHint {
		t.Errorf("%s: OpenWorldHint = %v, want non-nil true", name, a.OpenWorldHint)
	}
}

func assertDestructiveAnnotations(t *testing.T, name string, a *mcp.ToolAnnotations, idempotent bool) {
	t.Helper()
	if a == nil {
		t.Fatalf("%s: annotations nil", name)
	}
	if a.ReadOnlyHint {
		t.Errorf("%s: ReadOnlyHint = true, want false", name)
	}
	if a.IdempotentHint != idempotent {
		t.Errorf("%s: IdempotentHint = %v, want %v", name, a.IdempotentHint, idempotent)
	}
	if a.DestructiveHint == nil || !*a.DestructiveHint {
		t.Errorf("%s: DestructiveHint = %v, want non-nil true", name, a.DestructiveHint)
	}
	if a.OpenWorldHint == nil || !*a.OpenWorldHint {
		t.Errorf("%s: OpenWorldHint = %v, want non-nil true", name, a.OpenWorldHint)
	}
}
