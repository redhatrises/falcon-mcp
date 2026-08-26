package correlation_rules

import (
	"context"
	"errors"
	"testing"

	"github.com/crowdstrike/gofalcon/falcon/client/correlation_rules"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/go-openapi/runtime"

	"github.com/crowdstrike/falcon-mcp/internal/modules/base"
	"github.com/crowdstrike/falcon-mcp/internal/testutil"
)

// metaQueryTime is a non-zero query_time for test fakes, so a handler's
// normalized meta is a populated value rather than nil.
var metaQueryTime = 0.02

var testLogger = testutil.DiscardLogger()

// fakeAPI is a configurable test double for the correlationRulesAPI interface.
type fakeAPI struct {
	searchResp *correlation_rules.CombinedRulesGetV2OK
	searchErr  error
	createResp *correlation_rules.EntitiesRulesPostV1OK
	createErr  error
	patchResp  *correlation_rules.EntitiesRulesPatchV1OK
	patchErr   error
	deleteResp *correlation_rules.EntitiesRulesDeleteV1OK
	deleteErr  error

	lastSearch   *correlation_rules.CombinedRulesGetV2Params
	lastCreate   *models.CorrelationrulesapiRuleCreateRequestV1
	lastPatchReq any // the wire body the patch ClientOption serialized
	lastDelete   []string
}

func (f *fakeAPI) CombinedRulesGetV2(p *correlation_rules.CombinedRulesGetV2Params, _ ...correlation_rules.ClientOption) (*correlation_rules.CombinedRulesGetV2OK, error) {
	f.lastSearch = p
	return f.searchResp, f.searchErr
}

func (f *fakeAPI) EntitiesRulesPostV1(p *correlation_rules.EntitiesRulesPostV1Params, _ ...correlation_rules.ClientOption) (*correlation_rules.EntitiesRulesPostV1OK, error) {
	f.lastCreate = p.Body
	return f.createResp, f.createErr
}

// EntitiesRulesPatchV1 captures the wire body the module's ClientOption produces
// by replaying the opts against a runtime.TestClientRequest, since the module
// serializes the patch through a request-writer override rather than params.Body.
func (f *fakeAPI) EntitiesRulesPatchV1(p *correlation_rules.EntitiesRulesPatchV1Params, opts ...correlation_rules.ClientOption) (*correlation_rules.EntitiesRulesPatchV1OK, error) {
	op := &runtime.ClientOperation{Params: p}
	for _, opt := range opts {
		opt(op)
	}
	if op.Params != nil {
		req := &runtime.TestClientRequest{}
		if err := op.Params.WriteToRequest(req, nil); err == nil {
			f.lastPatchReq = req.Body
		}
	}
	return f.patchResp, f.patchErr
}

func (f *fakeAPI) EntitiesRulesDeleteV1(p *correlation_rules.EntitiesRulesDeleteV1Params, _ ...correlation_rules.ClientOption) (*correlation_rules.EntitiesRulesDeleteV1OK, error) {
	f.lastDelete = p.Ids
	return f.deleteResp, f.deleteErr
}

// --- search ---

func TestSearchSuccess(t *testing.T) {
	t.Parallel()

	f := &fakeAPI{searchResp: &correlation_rules.CombinedRulesGetV2OK{Payload: &models.CorrelationrulesapiGetEntitiesRulesResponseV1{
		Resources: []*models.CorrelationrulesapiRuleV1{{ID: new("r1"), Name: new("Rule One")}},
		Meta:      &models.MsaMetaInfo{QueryTime: &metaQueryTime},
	}}}
	m := &Module{API: f, Logger: testLogger}

	_, out, err := m.searchCorrelationRules(context.Background(), nil, SearchInput{Filter: "status:'active'"})
	if err != nil {
		t.Fatalf("searchCorrelationRules: %v", err)
	}
	if len(out.Resources) != 1 || out.FilterUsed != "status:'active'" {
		t.Fatalf("unexpected result: %+v", out)
	}
	if f.lastSearch.Filter == nil || *f.lastSearch.Filter != "status:'active'" {
		t.Fatalf("filter not passed through: %+v", f.lastSearch.Filter)
	}
	if f.lastSearch.Limit == nil || *f.lastSearch.Limit != defaultLimit {
		t.Fatalf("expected default limit %d, got %v", defaultLimit, f.lastSearch.Limit)
	}
	testutil.AssertNormalizedMeta(t, out.Meta, f.searchResp.Payload.Meta)
}

func TestSearchAppliesParams(t *testing.T) {
	t.Parallel()

	f := &fakeAPI{searchResp: &correlation_rules.CombinedRulesGetV2OK{Payload: &models.CorrelationrulesapiGetEntitiesRulesResponseV1{
		Resources: []*models.CorrelationrulesapiRuleV1{},
	}}}
	m := &Module{API: f, Logger: testLogger}

	_, _, err := m.searchCorrelationRules(context.Background(), nil, SearchInput{Limit: 50, Offset: 10, Sort: "last_updated_on.desc"})
	if err != nil {
		t.Fatalf("searchCorrelationRules: %v", err)
	}
	if f.lastSearch.Limit == nil || *f.lastSearch.Limit != 50 {
		t.Fatalf("expected limit 50, got %v", f.lastSearch.Limit)
	}
	if f.lastSearch.Offset == nil || *f.lastSearch.Offset != 10 {
		t.Fatalf("expected offset 10, got %v", f.lastSearch.Offset)
	}
	if f.lastSearch.Sort == nil || *f.lastSearch.Sort != "last_updated_on.desc" {
		t.Fatalf("expected sort passed through, got %v", f.lastSearch.Sort)
	}
}

func TestSearchEmpty(t *testing.T) {
	t.Parallel()

	f := &fakeAPI{searchResp: &correlation_rules.CombinedRulesGetV2OK{Payload: &models.CorrelationrulesapiGetEntitiesRulesResponseV1{
		Resources: []*models.CorrelationrulesapiRuleV1{},
	}}}
	m := &Module{API: f, Logger: testLogger}

	_, out, err := m.searchCorrelationRules(context.Background(), nil, SearchInput{})
	if err != nil {
		t.Fatalf("searchCorrelationRules: %v", err)
	}
	if len(out.Resources) != 0 || out.Resources == nil {
		t.Fatalf("expected non-nil empty slice, got %+v", out)
	}
}

func TestSearchFQLError(t *testing.T) {
	t.Parallel()

	badReq := &correlation_rules.CombinedRulesGetV2BadRequest{Payload: &models.CorrelationrulesapiGetEntitiesRulesResponseV1{
		Errors: []*models.MsaAPIError{{Code: new(int32(400)), Message: new("invalid filter")}},
	}}
	f := &fakeAPI{searchErr: badReq}
	m := &Module{API: f, Logger: testLogger}

	_, out, err := m.searchCorrelationRules(context.Background(), nil, SearchInput{Filter: "bogus::"})
	if err != nil {
		t.Fatalf("expected FQL error to be formatted, not returned: %v", err)
	}
	if len(out.Errors) != 1 || out.Errors[0].Message != "invalid filter" {
		t.Fatalf("expected FQL error detail, got %+v", out.Errors)
	}
	if out.FQLGuide == "" || out.Hint == "" {
		t.Fatalf("expected fql_guide and hint to be populated")
	}
}

func TestSearchAPIError(t *testing.T) {
	t.Parallel()

	f := &fakeAPI{searchErr: errors.New("boom")}
	m := &Module{API: f, Logger: testLogger}

	_, _, err := m.searchCorrelationRules(context.Background(), nil, SearchInput{})
	if err == nil {
		t.Fatalf("expected non-FQL error to be returned")
	}
}

// --- create ---

func TestCreateValidation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		in      CreateInput
		wantErr bool
	}{
		{"missing all", CreateInput{}, true},
		{"missing name", CreateInput{CustomerID: "cid", SearchFilter: "q", Severity: 50}, true},
		{"missing customer_id", CreateInput{Name: "n", SearchFilter: "q", Severity: 50}, true},
		{"missing search_filter", CreateInput{CustomerID: "cid", Name: "n", Severity: 50}, true},
		{"missing severity", CreateInput{CustomerID: "cid", Name: "n", SearchFilter: "q"}, true},
		{"invalid severity", CreateInput{CustomerID: "cid", Name: "n", SearchFilter: "q", Severity: 42}, true},
		{"valid", CreateInput{CustomerID: "cid", Name: "n", SearchFilter: "q", Severity: 50}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := &fakeAPI{createResp: &correlation_rules.EntitiesRulesPostV1OK{Payload: &models.CorrelationrulesapiGetEntitiesRulesResponseV1{}}}
			m := &Module{API: f, Logger: testLogger}
			_, _, err := m.createCorrelationRule(context.Background(), nil, tc.in)
			if tc.wantErr && !errors.Is(err, base.ErrInvalidInput) {
				t.Fatalf("expected base.ErrInvalidInput, got %v", err)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestCreateBodyDefaults(t *testing.T) {
	t.Parallel()

	f := &fakeAPI{createResp: &correlation_rules.EntitiesRulesPostV1OK{Payload: &models.CorrelationrulesapiGetEntitiesRulesResponseV1{
		Resources: []*models.CorrelationrulesapiRuleV1{{ID: new("new"), RuleID: "rule-new"}},
		Meta:      &models.MsaMetaInfo{QueryTime: &metaQueryTime},
	}}}
	m := &Module{API: f, Logger: testLogger}

	_, out, err := m.createCorrelationRule(context.Background(), nil, CreateInput{
		CustomerID:   "cid",
		Name:         "My Rule",
		SearchFilter: "#event_simpleName=ProcessRollup2",
		Severity:     70,
	})
	if err != nil {
		t.Fatalf("createCorrelationRule: %v", err)
	}
	if out.Total != 1 {
		t.Fatalf("expected created record returned, got %+v", out)
	}
	testutil.AssertNormalizedMeta(t, out.Meta, f.createResp.Payload.Meta)
	body := f.lastCreate
	if body == nil {
		t.Fatal("expected create body to be sent")
	}
	if body.CustomerID == nil || *body.CustomerID != "cid" {
		t.Errorf("customer_id = %v, want cid", body.CustomerID)
	}
	if body.Name == nil || *body.Name != "My Rule" {
		t.Errorf("name = %v, want My Rule", body.Name)
	}
	if body.Severity == nil || *body.Severity != 70 {
		t.Errorf("severity = %v, want 70", body.Severity)
	}
	if body.Status == nil || *body.Status != defaultStatus {
		t.Errorf("status = %v, want %s", body.Status, defaultStatus)
	}
	if body.Search == nil {
		t.Fatal("expected search sub-object")
	}
	if body.Search.Filter == nil || *body.Search.Filter != "#event_simpleName=ProcessRollup2" {
		t.Errorf("search.filter = %v", body.Search.Filter)
	}
	if body.Search.Outcome == nil || *body.Search.Outcome != defaultSearchOutcome {
		t.Errorf("search.outcome = %v, want %s", body.Search.Outcome, defaultSearchOutcome)
	}
	if body.Search.Lookback == nil || *body.Search.Lookback != defaultLookback {
		t.Errorf("search.lookback = %v, want %s", body.Search.Lookback, defaultLookback)
	}
	if body.Search.TriggerMode == nil || *body.Search.TriggerMode != defaultTriggerMode {
		t.Errorf("search.trigger_mode = %v, want %s", body.Search.TriggerMode, defaultTriggerMode)
	}
	if body.Operation == nil || body.Operation.Schedule == nil || body.Operation.Schedule.Definition == nil ||
		*body.Operation.Schedule.Definition != defaultSchedule {
		t.Errorf("operation.schedule.definition not set to default %s", defaultSchedule)
	}
}

func TestCreateBodyWithOptionalFields(t *testing.T) {
	t.Parallel()

	f := &fakeAPI{createResp: &correlation_rules.EntitiesRulesPostV1OK{Payload: &models.CorrelationrulesapiGetEntitiesRulesResponseV1{}}}
	m := &Module{API: f, Logger: testLogger}

	_, _, err := m.createCorrelationRule(context.Background(), nil, CreateInput{
		CustomerID:    "cid",
		Name:          "n",
		SearchFilter:  "q",
		Severity:      90,
		SearchOutcome: "case",
		Lookback:      "24h0m",
		Schedule:      "@every 24h0m",
		Status:        "inactive",
		TriggerMode:   "verbose",
		UseIngestTime: true,
		Description:   "desc",
		Comment:       "audit",
		MitreAttack:   []MitreAttackMapping{{TacticID: "TA0002", TechniqueID: "T1059"}},
	})
	if err != nil {
		t.Fatalf("createCorrelationRule: %v", err)
	}
	body := f.lastCreate
	if body.Description != "desc" || body.Comment != "audit" {
		t.Errorf("description/comment not set: %+v", body)
	}
	if body.Status == nil || *body.Status != "inactive" {
		t.Errorf("status override not applied: %v", body.Status)
	}
	if *body.Search.Outcome != "case" || *body.Search.Lookback != "24h0m" || !body.Search.UseIngestTime {
		t.Errorf("search overrides not applied: %+v", body.Search)
	}
	if body.Search.TriggerMode == nil || *body.Search.TriggerMode != "verbose" {
		t.Errorf("trigger_mode override not applied: %v", body.Search.TriggerMode)
	}
	if *body.Operation.Schedule.Definition != "@every 24h0m" {
		t.Errorf("schedule override not applied: %v", body.Operation.Schedule.Definition)
	}
	if len(body.MitreAttack) != 1 || body.MitreAttack[0].TacticID == nil || *body.MitreAttack[0].TacticID != "TA0002" ||
		body.MitreAttack[0].TechniqueID != "T1059" {
		t.Errorf("mitre_attack not mapped: %+v", body.MitreAttack)
	}
}

func TestCreateAPIError(t *testing.T) {
	t.Parallel()

	f := &fakeAPI{createErr: errors.New("boom")}
	m := &Module{API: f, Logger: testLogger}

	_, _, err := m.createCorrelationRule(context.Background(), nil, CreateInput{
		CustomerID: "cid", Name: "n", SearchFilter: "q", Severity: 50,
	})
	if err == nil {
		t.Fatalf("expected API error to be returned")
	}
}

// --- update ---

func TestUpdateValidation(t *testing.T) {
	t.Parallel()

	m := &Module{API: &fakeAPI{}, Logger: testLogger}
	_, _, err := m.updateCorrelationRule(context.Background(), nil, UpdateInput{})
	if !errors.Is(err, base.ErrInvalidInput) {
		t.Fatalf("expected base.ErrInvalidInput for missing rule_id, got %v", err)
	}

	_, _, err = m.updateCorrelationRule(context.Background(), nil, UpdateInput{RuleID: "r1", Severity: 42})
	if !errors.Is(err, base.ErrInvalidInput) {
		t.Fatalf("expected base.ErrInvalidInput for invalid severity, got %v", err)
	}
}

func TestUpdateBodyPartial(t *testing.T) {
	t.Parallel()

	f := &fakeAPI{patchResp: &correlation_rules.EntitiesRulesPatchV1OK{Payload: &models.CorrelationrulesapiGetEntitiesRulesResponseV1{
		Resources: []*models.CorrelationrulesapiRuleV1{{ID: new("r1")}},
		Meta:      &models.MsaMetaInfo{QueryTime: &metaQueryTime},
	}}}
	m := &Module{API: f, Logger: testLogger}

	_, out, err := m.updateCorrelationRule(context.Background(), nil, UpdateInput{
		RuleID: "rule-1",
		Status: "inactive",
	})
	if err != nil {
		t.Fatalf("updateCorrelationRule: %v", err)
	}
	if out.Total != 1 {
		t.Fatalf("expected updated record returned, got %+v", out)
	}
	testutil.AssertNormalizedMeta(t, out.Meta, f.patchResp.Payload.Meta)
	// The wire body is a single-element list of patch maps.
	body, ok := f.lastPatchReq.([]map[string]any)
	if !ok || len(body) != 1 {
		t.Fatalf("expected patch body to be a single-element []map, got %#v", f.lastPatchReq)
	}
	patch := body[0]
	if patch["id"] != "rule-1" {
		t.Errorf("id = %v, want rule-1", patch["id"])
	}
	if patch["status"] != "inactive" {
		t.Errorf("status = %v, want inactive", patch["status"])
	}
	// Only provided keys should be present. In particular the gofalcon PATCH
	// model lacks omitempty on mitre_attack/notifications/guardrail_notifications,
	// so the map-body path must NOT emit those keys (else it would send explicit
	// null and risk clearing existing values). search stays absent too.
	for _, absent := range []string{"mitre_attack", "notifications", "guardrail_notifications", "search", "name", "severity", "comment", "description"} {
		if _, present := patch[absent]; present {
			t.Errorf("expected key %q to be absent when not provided, got %v", absent, patch[absent])
		}
	}
}

func TestUpdateBodySearchFields(t *testing.T) {
	t.Parallel()

	f := &fakeAPI{patchResp: &correlation_rules.EntitiesRulesPatchV1OK{Payload: &models.CorrelationrulesapiGetEntitiesRulesResponseV1{}}}
	m := &Module{API: f, Logger: testLogger}

	ingest := true
	_, _, err := m.updateCorrelationRule(context.Background(), nil, UpdateInput{
		RuleID:        "rule-1",
		Name:          "New Name",
		Description:   "new desc",
		Status:        "active",
		Severity:      90,
		SearchFilter:  "#event_simpleName=Foo",
		Lookback:      "2h0m",
		TriggerMode:   "verbose",
		UseIngestTime: &ingest,
		MitreAttack:   []MitreAttackMapping{{TacticID: "TA0008", TechniqueID: "T1021"}},
		Comment:       "why",
	})
	if err != nil {
		t.Fatalf("updateCorrelationRule: %v", err)
	}
	body, ok := f.lastPatchReq.([]map[string]any)
	if !ok || len(body) != 1 {
		t.Fatalf("expected patch body to be a single-element []map, got %#v", f.lastPatchReq)
	}
	patch := body[0]
	if patch["name"] != "New Name" || patch["severity"] != 90 || patch["comment"] != "why" ||
		patch["description"] != "new desc" || patch["status"] != "active" {
		t.Errorf("scalar fields not set: %+v", patch)
	}
	search, ok := patch["search"].(map[string]any)
	if !ok {
		t.Fatalf("expected search sub-object, got %#v", patch["search"])
	}
	if search["filter"] != "#event_simpleName=Foo" || search["lookback"] != "2h0m" ||
		search["trigger_mode"] != "verbose" || search["use_ingest_time"] != true {
		t.Errorf("search fields not set: %+v", search)
	}
	mitre, ok := patch["mitre_attack"].([]map[string]any)
	if !ok || len(mitre) != 1 || mitre[0]["tactic_id"] != "TA0008" || mitre[0]["technique_id"] != "T1021" {
		t.Errorf("mitre_attack not mapped: %#v", patch["mitre_attack"])
	}
}

// TestUpdatePatchBodyOmitsUnsetKeys is the regression guard for the PATCH-null
// defect: a patch that changes only status must not carry mitre_attack,
// notifications, or guardrail_notifications keys (the gofalcon typed model would
// serialize them as explicit null, potentially clearing existing values).
func TestUpdatePatchBodyOmitsUnsetKeys(t *testing.T) {
	t.Parallel()

	patch := UpdateInput{RuleID: "rule-1", Status: "inactive"}.patchBody()
	want := map[string]any{"id": "rule-1", "status": "inactive"}
	if len(patch) != len(want) {
		t.Fatalf("patch body has unexpected keys: %#v", patch)
	}
	for k, v := range want {
		if patch[k] != v {
			t.Errorf("patch[%q] = %v, want %v", k, patch[k], v)
		}
	}
}

// TestUpdatePatchBodyMitreOmitsEmptyTechnique verifies that a mapping with an
// empty TechniqueID omits the technique_id key entirely (rather than sending an
// empty string), mirroring the Python reference which only forwards provided
// subfields.
func TestUpdatePatchBodyMitreOmitsEmptyTechnique(t *testing.T) {
	t.Parallel()

	patch := UpdateInput{RuleID: "rule-1", MitreAttack: []MitreAttackMapping{{TacticID: "TA0008"}}}.patchBody()
	mitre, ok := patch["mitre_attack"].([]map[string]any)
	if !ok || len(mitre) != 1 {
		t.Fatalf("expected one mitre mapping, got %#v", patch["mitre_attack"])
	}
	if mitre[0]["tactic_id"] != "TA0008" {
		t.Errorf("tactic_id = %v, want TA0008", mitre[0]["tactic_id"])
	}
	if _, present := mitre[0]["technique_id"]; present {
		t.Errorf("technique_id should be absent when empty, got %v", mitre[0]["technique_id"])
	}
}

func TestUpdateAPIError(t *testing.T) {
	t.Parallel()

	f := &fakeAPI{patchErr: errors.New("boom")}
	m := &Module{API: f, Logger: testLogger}

	_, _, err := m.updateCorrelationRule(context.Background(), nil, UpdateInput{RuleID: "r1", Status: "active"})
	if err == nil {
		t.Fatalf("expected API error to be returned")
	}
}

// --- delete ---

func TestDeleteValidation(t *testing.T) {
	t.Parallel()

	m := &Module{API: &fakeAPI{}, Logger: testLogger}
	_, _, err := m.deleteCorrelationRules(context.Background(), nil, DeleteInput{})
	if !errors.Is(err, base.ErrInvalidInput) {
		t.Fatalf("expected base.ErrInvalidInput for empty ids, got %v", err)
	}
}

func TestDeleteSuccess(t *testing.T) {
	t.Parallel()

	f := &fakeAPI{deleteResp: &correlation_rules.EntitiesRulesDeleteV1OK{Payload: &models.MsaspecQueryResponse{
		Resources: []string{"r1", "r2"},
		Meta:      &models.MsaMetaInfo{QueryTime: &metaQueryTime},
	}}}
	m := &Module{API: f, Logger: testLogger}

	_, out, err := m.deleteCorrelationRules(context.Background(), nil, DeleteInput{IDs: []string{"r1", "r2"}})
	if err != nil {
		t.Fatalf("deleteCorrelationRules: %v", err)
	}
	if out.Total != 2 || len(out.Resources) != 2 {
		t.Fatalf("expected 2 deleted ids, got %+v", out)
	}
	if len(f.lastDelete) != 2 {
		t.Fatalf("expected 2 ids passed, got %v", f.lastDelete)
	}
	testutil.AssertNormalizedMeta(t, out.Meta, f.deleteResp.Payload.Meta)
}

func TestDeleteAPIError(t *testing.T) {
	t.Parallel()

	f := &fakeAPI{deleteErr: errors.New("boom")}
	m := &Module{API: f, Logger: testLogger}

	_, _, err := m.deleteCorrelationRules(context.Background(), nil, DeleteInput{IDs: []string{"r1"}})
	if err == nil {
		t.Fatalf("expected API error to be returned")
	}
}

// --- resources & annotations ---

// TestRegisterResourcesServesFQLGuide verifies the module publishes its FQL
// guide as the falcon://correlation-rules/search/fql-guide resource, with the
// Python-matching name, and that reading it returns the embedded guide text.
func TestRegisterResourcesServesFQLGuide(t *testing.T) {
	t.Parallel()
	testutil.AssertServesFQLGuide(context.Background(), t, (&Module{API: &fakeAPI{}, Logger: testLogger}).RegisterResources, testutil.FQLGuideExpectation{
		Name: "falcon_search_correlation_rules_fql_guide",
		URI:  fqlGuideURI,
		Body: fqlGuide,
	})
}

// TestRegisterToolsAnnotations verifies each tool advertises the correct
// annotations: search read-only, create mutating (non-idempotent), update
// mutating (idempotent, non-destructive), delete destructive (idempotent).
func TestRegisterToolsAnnotations(t *testing.T) {
	t.Parallel()

	m := &Module{API: &fakeAPI{}, Logger: testLogger}
	byName := testutil.CollectTools(m)

	search := byName["falcon_search_correlation_rules"]
	if search == nil {
		t.Fatal("missing falcon_search_correlation_rules")
	}
	testutil.AssertReadOnlyAnnotations(t, "falcon_search_correlation_rules", search.Annotations)

	create := byName["falcon_create_correlation_rule"]
	if create == nil {
		t.Fatal("missing falcon_create_correlation_rule")
	}
	testutil.AssertMutatingAnnotations(t, "falcon_create_correlation_rule", create.Annotations, false)

	update := byName["falcon_update_correlation_rule"]
	if update == nil {
		t.Fatal("missing falcon_update_correlation_rule")
	}
	testutil.AssertMutatingAnnotations(t, "falcon_update_correlation_rule", update.Annotations, true)

	del := byName["falcon_delete_correlation_rules"]
	if del == nil {
		t.Fatal("missing falcon_delete_correlation_rules")
	}
	testutil.AssertDestructiveAnnotations(t, "falcon_delete_correlation_rules", del.Annotations, true)
}
