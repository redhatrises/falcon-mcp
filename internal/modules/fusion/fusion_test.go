package fusion

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/crowdstrike/gofalcon/falcon/client/workflows"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/crowdstrike/falcon-mcp/internal/modules/base"
	"github.com/crowdstrike/falcon-mcp/internal/testutil"
)

var testLogger = testutil.DiscardLogger()

// fakeFusion is a configurable test double for the fusionAPI interface. It
// records the last params each operation received so tests can assert forwarding.
type fakeFusion struct {
	defsResp    *workflows.WorkflowDefinitionsCombinedOK
	defsErr     error
	execsResp   *workflows.WorkflowExecutionsCombinedOK
	execsErr    error
	resultsResp *workflows.ExecutionResultsOK
	resultsErr  error
	executeResp *workflows.ExecuteOK
	executeErr  error

	lastDefsParams    *workflows.WorkflowDefinitionsCombinedParams
	lastExecsParams   *workflows.WorkflowExecutionsCombinedParams
	lastResultsParams *workflows.ExecutionResultsParams
	lastExecuteParams *workflows.ExecuteParams
}

func (f *fakeFusion) WorkflowDefinitionsCombined(p *workflows.WorkflowDefinitionsCombinedParams, _ ...workflows.ClientOption) (*workflows.WorkflowDefinitionsCombinedOK, error) {
	f.lastDefsParams = p
	return f.defsResp, f.defsErr
}

func (f *fakeFusion) WorkflowExecutionsCombined(p *workflows.WorkflowExecutionsCombinedParams, _ ...workflows.ClientOption) (*workflows.WorkflowExecutionsCombinedOK, error) {
	f.lastExecsParams = p
	return f.execsResp, f.execsErr
}

func (f *fakeFusion) ExecutionResults(p *workflows.ExecutionResultsParams, _ ...workflows.ClientOption) (*workflows.ExecutionResultsOK, error) {
	f.lastResultsParams = p
	return f.resultsResp, f.resultsErr
}

func (f *fakeFusion) Execute(p *workflows.ExecuteParams, _ ...workflows.ClientOption) (*workflows.ExecuteOK, error) {
	f.lastExecuteParams = p
	return f.executeResp, f.executeErr
}

func defsOK(defs ...*models.DefinitionsDefinitionExt) *workflows.WorkflowDefinitionsCombinedOK {
	return &workflows.WorkflowDefinitionsCombinedOK{
		Payload: &models.DefinitionsDefinitionExternalResponse{Resources: defs},
	}
}

func execsOK(execs ...*models.ExecutionsExecutionResult) *workflows.WorkflowExecutionsCombinedOK {
	return &workflows.WorkflowExecutionsCombinedOK{
		Payload: &models.APIExecutionResultsResponse{Resources: execs},
	}
}

// TestSearchWorkflowDefinitionsSuccess verifies a successful search returns the
// records, echoes the filter, and passes the response meta through verbatim.
func TestSearchWorkflowDefinitionsSuccess(t *testing.T) {
	t.Parallel()

	f := &fakeFusion{defsResp: defsOK(&models.DefinitionsDefinitionExt{ID: new("def-1")})}
	f.defsResp.Payload.Meta = &models.MsaMetaInfo{
		Pagination: &models.MsaPaging{Total: new(int64(7))},
		QueryTime:  new(0.01),
		TraceID:    new("trace-defs"),
	}
	m := &Module{API: f, Logger: testLogger}

	_, out, err := m.searchWorkflowDefinitions(context.Background(), nil, SearchInput{Filter: "enabled:true"})
	if err != nil {
		t.Fatalf("searchWorkflowDefinitions: %v", err)
	}
	if len(out.Resources) != 1 || out.FilterUsed != "enabled:true" {
		t.Fatalf("unexpected result: %+v", out)
	}
	if *out.Resources[0].ID != "def-1" {
		t.Fatalf("unexpected resource: %+v", out.Resources[0])
	}
	if !reflect.DeepEqual(out.Meta, base.NormalizedMeta(f.defsResp.Payload.Meta)) {
		t.Fatalf("Meta = %+v, want verbatim passthrough of the response meta", out.Meta)
	}
}

// TestSearchWorkflowDefinitionsDefaults verifies the handler defaults the limit
// and sort and forwards the offset as a string only when non-zero.
func TestSearchWorkflowDefinitionsDefaults(t *testing.T) {
	t.Parallel()

	f := &fakeFusion{defsResp: defsOK()}
	m := &Module{API: f, Logger: testLogger}

	_, _, err := m.searchWorkflowDefinitions(context.Background(), nil, SearchInput{})
	if err != nil {
		t.Fatalf("searchWorkflowDefinitions: %v", err)
	}
	p := f.lastDefsParams
	if p.Limit == nil || *p.Limit != defaultSearchLimit {
		t.Errorf("limit = %v, want default %d", p.Limit, defaultSearchLimit)
	}
	if p.Sort == nil || *p.Sort != definitionsDefaultSort {
		t.Errorf("sort = %v, want default %q", p.Sort, definitionsDefaultSort)
	}
	if p.Offset != nil {
		t.Errorf("offset = %v, want unset when zero", *p.Offset)
	}
}

// TestSearchWorkflowDefinitionsOffset verifies a non-zero offset is forwarded as
// its decimal string, and an explicit limit/sort override the defaults.
func TestSearchWorkflowDefinitionsOffset(t *testing.T) {
	t.Parallel()

	f := &fakeFusion{defsResp: defsOK()}
	m := &Module{API: f, Logger: testLogger}

	_, _, err := m.searchWorkflowDefinitions(context.Background(), nil, SearchInput{
		Limit:  25,
		Offset: 50,
		Sort:   "name.asc",
	})
	if err != nil {
		t.Fatalf("searchWorkflowDefinitions: %v", err)
	}
	p := f.lastDefsParams
	if p.Limit == nil || *p.Limit != 25 {
		t.Errorf("limit = %v, want 25", p.Limit)
	}
	if p.Sort == nil || *p.Sort != "name.asc" {
		t.Errorf("sort = %v, want name.asc", p.Sort)
	}
	if p.Offset == nil || *p.Offset != "50" {
		t.Errorf("offset = %v, want \"50\"", p.Offset)
	}
}

// TestSearchWorkflowDefinitionsEmpty verifies an empty result is a non-nil empty
// slice and no meta is attached when the response carries none.
func TestSearchWorkflowDefinitionsEmpty(t *testing.T) {
	t.Parallel()

	f := &fakeFusion{defsResp: defsOK()}
	m := &Module{API: f, Logger: testLogger}

	_, out, err := m.searchWorkflowDefinitions(context.Background(), nil, SearchInput{})
	if err != nil {
		t.Fatalf("searchWorkflowDefinitions: %v", err)
	}
	if out.Resources == nil || len(out.Resources) != 0 {
		t.Fatalf("expected empty non-nil resources, got %+v", out)
	}
	if out.Meta != nil {
		t.Fatalf("Meta = %+v, want nil when the response carries no meta", out.Meta)
	}
}

// TestSearchWorkflowDefinitionsFQLError verifies a 400 whose message names FQL
// becomes a soft SearchResult error, not a Go error.
func TestSearchWorkflowDefinitionsFQLError(t *testing.T) {
	t.Parallel()

	badReq := &workflows.WorkflowDefinitionsCombinedBadRequest{
		Payload: &models.DefinitionsDefinitionExternalResponse{
			Errors: []*models.MsaAPIError{{Code: new(int32(400)), Message: new("invalid FQL expression")}},
		},
	}
	f := &fakeFusion{defsErr: badReq}
	m := &Module{API: f, Logger: testLogger}

	_, out, err := m.searchWorkflowDefinitions(context.Background(), nil, SearchInput{Filter: "bogus::"})
	if err != nil {
		t.Fatalf("expected soft FQL error result, got Go error: %v", err)
	}
	if len(out.Errors) != 1 || out.Errors[0].Message != "invalid FQL expression" {
		t.Fatalf("expected FQL error detail, got %+v", out.Errors)
	}
	if out.FQLGuide == "" {
		t.Fatalf("expected FQL guide in error result")
	}
	if out.FilterUsed != "bogus::" {
		t.Fatalf("expected filter echoed, got %q", out.FilterUsed)
	}
}

// TestSearchWorkflowDefinitionsFilterWordFQLError verifies a 400 whose message
// blames the filter without naming FQL still becomes a soft SearchResult error,
// matching the house convention of classifying on "filter" as well as "fql".
func TestSearchWorkflowDefinitionsFilterWordFQLError(t *testing.T) {
	t.Parallel()

	badReq := &workflows.WorkflowDefinitionsCombinedBadRequest{
		Payload: &models.DefinitionsDefinitionExternalResponse{
			Errors: []*models.MsaAPIError{{Code: new(int32(400)), Message: new("invalid filter expression")}},
		},
	}
	f := &fakeFusion{defsErr: badReq}
	m := &Module{API: f, Logger: testLogger}

	_, out, err := m.searchWorkflowDefinitions(context.Background(), nil, SearchInput{Filter: "bogus::"})
	if err != nil {
		t.Fatalf("expected soft FQL error result, got Go error: %v", err)
	}
	if len(out.Errors) != 1 || out.Errors[0].Message != "invalid filter expression" {
		t.Fatalf("expected FQL error detail, got %+v", out.Errors)
	}
	if out.FQLGuide == "" {
		t.Fatalf("expected FQL guide in error result")
	}
}

// TestSearchWorkflowDefinitionsNonFQLBadRequest verifies a 400 whose message does
// not name FQL is surfaced as a Go error rather than a soft FQL result, since a
// rejected sort or oversized limit also returns 400 here.
func TestSearchWorkflowDefinitionsNonFQLBadRequest(t *testing.T) {
	t.Parallel()

	badReq := &workflows.WorkflowDefinitionsCombinedBadRequest{
		Payload: &models.DefinitionsDefinitionExternalResponse{
			Errors: []*models.MsaAPIError{{Code: new(int32(400)), Message: new("sort field not sortable")}},
		},
	}
	f := &fakeFusion{defsErr: badReq}
	m := &Module{API: f, Logger: testLogger}

	_, out, err := m.searchWorkflowDefinitions(context.Background(), nil, SearchInput{Filter: "enabled:true"})
	if err == nil {
		t.Fatalf("expected Go error for non-FQL 400, got soft result: %+v", out)
	}
	if len(out.Errors) != 0 {
		t.Fatalf("expected no soft FQL errors, got %+v", out.Errors)
	}
}

// TestSearchWorkflowDefinitionsFilterlessErrorNotClassified verifies the FQL gate
// never fires without a filter: a bare 400 with no filter is a Go error.
func TestSearchWorkflowDefinitionsFilterlessErrorNotClassified(t *testing.T) {
	t.Parallel()

	badReq := &workflows.WorkflowDefinitionsCombinedBadRequest{
		Payload: &models.DefinitionsDefinitionExternalResponse{
			Errors: []*models.MsaAPIError{{Code: new(int32(400)), Message: new("invalid FQL expression")}},
		},
	}
	f := &fakeFusion{defsErr: badReq}
	m := &Module{API: f, Logger: testLogger}

	_, _, err := m.searchWorkflowDefinitions(context.Background(), nil, SearchInput{})
	if err == nil {
		t.Fatalf("expected Go error when no filter was supplied")
	}
}

// TestSearchWorkflowExecutionsSuccess verifies a successful executions search
// returns the records and passes meta through.
func TestSearchWorkflowExecutionsSuccess(t *testing.T) {
	t.Parallel()

	f := &fakeFusion{execsResp: execsOK(&models.ExecutionsExecutionResult{ExecutionID: new("exec-1")})}
	f.execsResp.Payload.Meta = &models.MsaMetaInfo{
		Pagination: &models.MsaPaging{Total: new(int64(3))},
		QueryTime:  new(0.02),
		TraceID:    new("trace-execs"),
	}
	m := &Module{API: f, Logger: testLogger}

	_, out, err := m.searchWorkflowExecutions(context.Background(), nil, SearchInput{Filter: "ui_status:'Completed'"})
	if err != nil {
		t.Fatalf("searchWorkflowExecutions: %v", err)
	}
	if len(out.Resources) != 1 || *out.Resources[0].ExecutionID != "exec-1" {
		t.Fatalf("unexpected result: %+v", out)
	}
	if !reflect.DeepEqual(out.Meta, base.NormalizedMeta(f.execsResp.Payload.Meta)) {
		t.Fatalf("Meta = %+v, want verbatim passthrough of the response meta", out.Meta)
	}
}

// TestSearchWorkflowExecutionsDefaults verifies the executions handler defaults
// the limit and sort.
func TestSearchWorkflowExecutionsDefaults(t *testing.T) {
	t.Parallel()

	f := &fakeFusion{execsResp: execsOK()}
	m := &Module{API: f, Logger: testLogger}

	_, _, err := m.searchWorkflowExecutions(context.Background(), nil, SearchInput{})
	if err != nil {
		t.Fatalf("searchWorkflowExecutions: %v", err)
	}
	p := f.lastExecsParams
	if p.Limit == nil || *p.Limit != defaultSearchLimit {
		t.Errorf("limit = %v, want default %d", p.Limit, defaultSearchLimit)
	}
	if p.Sort == nil || *p.Sort != executionsDefaultSort {
		t.Errorf("sort = %v, want default %q", p.Sort, executionsDefaultSort)
	}
}

// TestSearchWorkflowExecutionsFQLError verifies an FQL-named 400 is a soft result.
func TestSearchWorkflowExecutionsFQLError(t *testing.T) {
	t.Parallel()

	badReq := &workflows.WorkflowExecutionsCombinedBadRequest{
		Payload: &models.APIExecutionResultsResponse{
			Errors: []*models.MsaAPIError{{Code: new(int32(400)), Message: new("unknown fql field")}},
		},
	}
	f := &fakeFusion{execsErr: badReq}
	m := &Module{API: f, Logger: testLogger}

	_, out, err := m.searchWorkflowExecutions(context.Background(), nil, SearchInput{Filter: "status:'Completed'"})
	if err != nil {
		t.Fatalf("expected soft FQL error result, got Go error: %v", err)
	}
	if len(out.Errors) != 1 || out.FQLGuide == "" {
		t.Fatalf("expected FQL error detail and guide, got %+v", out)
	}
}

// TestGetWorkflowExecutionResultsEmptyShortCircuits verifies an empty IDs input
// returns an empty entity set without calling the API.
func TestGetWorkflowExecutionResultsEmptyShortCircuits(t *testing.T) {
	t.Parallel()

	f := &fakeFusion{}
	m := &Module{API: f, Logger: testLogger}

	_, out, err := m.getWorkflowExecutionResults(context.Background(), nil, ExecutionResultsInput{})
	if err != nil {
		t.Fatalf("getWorkflowExecutionResults: %v", err)
	}
	if out.Resources == nil || len(out.Resources) != 0 {
		t.Fatalf("expected empty non-nil resources, got %+v", out)
	}
	if f.lastResultsParams != nil {
		t.Fatalf("expected no API call for empty IDs, got params %+v", f.lastResultsParams)
	}
}

// TestGetWorkflowExecutionResultsSuccess verifies IDs and skip_fields are
// forwarded and the records are returned with meta.
func TestGetWorkflowExecutionResultsSuccess(t *testing.T) {
	t.Parallel()

	f := &fakeFusion{resultsResp: &workflows.ExecutionResultsOK{
		Payload: &models.APIExecutionResultsResponse{
			Resources: []*models.ExecutionsExecutionResult{{ExecutionID: new("exec-1")}},
			Meta:      &models.MsaMetaInfo{QueryTime: new(0.03), TraceID: new("trace-results")},
		},
	}}
	m := &Module{API: f, Logger: testLogger}

	_, out, err := m.getWorkflowExecutionResults(context.Background(), nil, ExecutionResultsInput{
		IDs:        []string{"exec-1", "exec-2"},
		SkipFields: []string{"trigger"},
	})
	if err != nil {
		t.Fatalf("getWorkflowExecutionResults: %v", err)
	}
	if len(out.Resources) != 1 || out.Total != 1 {
		t.Fatalf("unexpected result: %+v", out)
	}
	p := f.lastResultsParams
	if !reflect.DeepEqual(p.Ids, []string{"exec-1", "exec-2"}) {
		t.Errorf("ids = %v", p.Ids)
	}
	if !reflect.DeepEqual(p.SkipFields, []string{"trigger"}) {
		t.Errorf("skip_fields = %v", p.SkipFields)
	}
	if !reflect.DeepEqual(out.Meta, base.NormalizedMeta(f.resultsResp.Payload.Meta)) {
		t.Fatalf("Meta = %+v, want verbatim passthrough", out.Meta)
	}
}

// TestExecuteWorkflowValidation verifies the exactly-one-of guard rejects both
// definition_id and name being set, or neither, with errInvalidArgs.
func TestExecuteWorkflowValidation(t *testing.T) {
	t.Parallel()

	cases := map[string]ExecuteInput{
		"neither": {},
		"both":    {DefinitionID: "def-1", Name: "wf"},
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			f := &fakeFusion{}
			m := &Module{API: f, Logger: testLogger}

			_, _, err := m.executeWorkflow(context.Background(), nil, in)
			if !errors.Is(err, errInvalidArgs) {
				t.Fatalf("err = %v, want errInvalidArgs", err)
			}
			if f.lastExecuteParams != nil {
				t.Fatalf("expected no API call on validation failure, got %+v", f.lastExecuteParams)
			}
		})
	}
}

// TestExecuteWorkflowSuccess verifies a definition-ID execution forwards the
// params and labels each returned execution ID.
func TestExecuteWorkflowSuccess(t *testing.T) {
	t.Parallel()

	f := &fakeFusion{executeResp: &workflows.ExecuteOK{
		Payload: &models.APIResourceIDsResponse{
			Resources: []string{"exec-1", "exec-2"},
			Meta:      &models.MsaMetaInfo{QueryTime: new(0.04), TraceID: new("trace-exec")},
		},
	}}
	m := &Module{API: f, Logger: testLogger}

	depth := 2
	_, out, err := m.executeWorkflow(context.Background(), nil, ExecuteInput{
		DefinitionID:   "def-1",
		Parameters:     map[string]any{"host_id": "abc"},
		Key:            "idem-1",
		Depth:          &depth,
		SourceEventURL: "https://example.test/e",
	})
	if err != nil {
		t.Fatalf("executeWorkflow: %v", err)
	}
	want := []executionRef{{ExecutionID: "exec-1"}, {ExecutionID: "exec-2"}}
	if !reflect.DeepEqual(out.Resources, want) {
		t.Fatalf("resources = %+v, want %+v", out.Resources, want)
	}

	p := f.lastExecuteParams
	if !reflect.DeepEqual(p.DefinitionID, []string{"def-1"}) {
		t.Errorf("definition_id = %v", p.DefinitionID)
	}
	if p.Name != nil {
		t.Errorf("name = %v, want unset", *p.Name)
	}
	if p.Key == nil || *p.Key != "idem-1" {
		t.Errorf("key = %v", p.Key)
	}
	if p.Depth == nil || *p.Depth != 2 {
		t.Errorf("depth = %v, want 2", p.Depth)
	}
	if p.SourceEventURL == nil || *p.SourceEventURL != "https://example.test/e" {
		t.Errorf("source_event_url = %v", p.SourceEventURL)
	}
	body, ok := p.Body.(map[string]any)
	if !ok || !reflect.DeepEqual(body, map[string]any{"host_id": "abc"}) {
		t.Errorf("body = %v, want the parameters verbatim", p.Body)
	}
	if !reflect.DeepEqual(out.Meta, base.NormalizedMeta(f.executeResp.Payload.Meta)) {
		t.Fatalf("Meta = %+v, want verbatim passthrough", out.Meta)
	}
}

// TestExecuteWorkflowEmptyBody verifies a workflow with no parameters still sends
// an explicit empty body, since the endpoint requires the body to be present.
func TestExecuteWorkflowEmptyBody(t *testing.T) {
	t.Parallel()

	f := &fakeFusion{executeResp: &workflows.ExecuteOK{
		Payload: &models.APIResourceIDsResponse{Resources: []string{"exec-1"}},
	}}
	m := &Module{API: f, Logger: testLogger}

	_, _, err := m.executeWorkflow(context.Background(), nil, ExecuteInput{Name: "notify-team"})
	if err != nil {
		t.Fatalf("executeWorkflow: %v", err)
	}
	p := f.lastExecuteParams
	if p.Body == nil {
		t.Fatalf("body = nil, want an explicit empty map")
	}
	body, ok := p.Body.(map[string]any)
	if !ok {
		t.Fatalf("body = %T, want map[string]any", p.Body)
	}
	if len(body) != 0 {
		t.Errorf("body = %v, want empty", body)
	}
	if p.Name == nil || *p.Name != "notify-team" {
		t.Errorf("name = %v, want notify-team", p.Name)
	}
	if len(p.DefinitionID) != 0 {
		t.Errorf("definition_id = %v, want unset", p.DefinitionID)
	}
}

// TestRegisterToolsAnnotations verifies the read-only search/read tools default
// to read-only annotations and execute_workflow carries destructive, non-
// idempotent mutator annotations (base.DestructiveAnnotations(false)).
func TestRegisterToolsAnnotations(t *testing.T) {
	t.Parallel()
	var entries []base.ToolEntry
	reg := testutil.CaptureRegistrar(func(e base.ToolEntry) { entries = append(entries, e) })
	m := &Module{Logger: testLogger}
	m.RegisterTools(reg)

	byName := map[string]*mcp.Tool{}
	for _, e := range entries {
		byName[e.Tool.Name] = e.Tool
	}

	readOnly := []string{
		"falcon_search_workflow_definitions",
		"falcon_search_workflow_executions",
		"falcon_get_workflow_execution_results",
	}
	for _, name := range readOnly {
		tool := byName[name]
		if tool == nil {
			t.Fatalf("missing tool %s", name)
		}
		if tool.Annotations == nil || !tool.Annotations.ReadOnlyHint {
			t.Errorf("%s: expected ReadOnlyHint true", name)
		}
	}

	exec := byName["falcon_execute_workflow"]
	if exec == nil {
		t.Fatal("missing falcon_execute_workflow")
	}
	a := exec.Annotations
	if a == nil {
		t.Fatal("falcon_execute_workflow: annotations nil")
	}
	if a.ReadOnlyHint {
		t.Error("falcon_execute_workflow: ReadOnlyHint = true, want false")
	}
	if a.DestructiveHint == nil || !*a.DestructiveHint {
		t.Errorf("falcon_execute_workflow: DestructiveHint = %v, want non-nil true", a.DestructiveHint)
	}
	if a.IdempotentHint {
		t.Error("falcon_execute_workflow: IdempotentHint = true, want false")
	}
	if a.OpenWorldHint == nil || !*a.OpenWorldHint {
		t.Errorf("falcon_execute_workflow: OpenWorldHint = %v, want non-nil true", a.OpenWorldHint)
	}
}
