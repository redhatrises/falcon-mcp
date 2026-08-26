package agentworks

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/crowdstrike/gofalcon/falcon/client/agent_invocation"
	"github.com/crowdstrike/gofalcon/falcon/client/agent_versions"
	"github.com/crowdstrike/gofalcon/falcon/client/agents"
	"github.com/crowdstrike/gofalcon/falcon/client/spans"
	"github.com/crowdstrike/gofalcon/falcon/models"

	"github.com/crowdstrike/falcon-mcp/internal/modules/base"
	"github.com/crowdstrike/falcon-mcp/internal/testutil"
)

var testLogger = testutil.DiscardLogger()

func strptr(s string) *string   { return &s }
func f64ptr(v float64) *float64 { return &v }

// fakeAPI stands in for all four gofalcon sub-clients the module spans. One
// struct implements every consumed method so a single value can be wired into
// all four Module fields; captured inputs and canned outputs drive assertions.
type fakeAPI struct {
	// agents two-step.
	queryAgentsResp *agents.QueryAgentsV2OK
	queryAgentsErr  error
	getAgentsResp   *agents.GetAgentsV2OK
	lastAgentsQuery *agents.QueryAgentsV2Params
	getAgentsCalls  int

	// agent-versions two-step.
	queryVersionsResp *agent_versions.QueryAgentVersionsV1OK
	queryVersionsErr  error
	getVersionsResp   *agent_versions.GetAgentVersionsV1OK

	// spans two-step.
	queriesSpansResp  *spans.QueriesSpansV1OK
	queriesSpansErr   error
	entitiesSpansResp *spans.EntitiesSpansV1OK

	// invocation lookup + poll.
	getInvocationResp   *agent_invocation.GetAgentInvocationV3OK
	getInvocationErr    error
	getInvocationStatus []string // successive statuses returned by poll, if set
	getInvocationCalls  int
	lastInvocationID    string

	// invoke dispatch.
	invokePublishedResp  *agent_invocation.InvokePublishedAgentExternalV1OK
	invokePublishedErr   error
	invokePublishedCalls int
	lastPublishedBody    *models.APIInvokePublishedAgentExternalRequest

	invokeVersionResp  *agent_invocation.InvokeAgentVersionExternalV1OK
	invokeVersionErr   error
	invokeVersionCalls int
	lastVersionBody    *models.APIInvokeAgentVersionExternalRequest
}

func (f *fakeAPI) QueryAgentsV2(p *agents.QueryAgentsV2Params, _ ...agents.ClientOption) (*agents.QueryAgentsV2OK, error) {
	f.lastAgentsQuery = p
	return f.queryAgentsResp, f.queryAgentsErr
}

func (f *fakeAPI) GetAgentsV2(_ *agents.GetAgentsV2Params, _ ...agents.ClientOption) (*agents.GetAgentsV2OK, error) {
	f.getAgentsCalls++
	return f.getAgentsResp, nil
}

func (f *fakeAPI) QueryAgentVersionsV1(_ *agent_versions.QueryAgentVersionsV1Params, _ ...agent_versions.ClientOption) (*agent_versions.QueryAgentVersionsV1OK, error) {
	return f.queryVersionsResp, f.queryVersionsErr
}

func (f *fakeAPI) GetAgentVersionsV1(_ *agent_versions.GetAgentVersionsV1Params, _ ...agent_versions.ClientOption) (*agent_versions.GetAgentVersionsV1OK, error) {
	return f.getVersionsResp, nil
}

func (f *fakeAPI) QueriesSpansV1(_ *spans.QueriesSpansV1Params, _ ...spans.ClientOption) (*spans.QueriesSpansV1OK, error) {
	return f.queriesSpansResp, f.queriesSpansErr
}

func (f *fakeAPI) EntitiesSpansV1(_ *spans.EntitiesSpansV1Params, _ ...spans.ClientOption) (*spans.EntitiesSpansV1OK, error) {
	return f.entitiesSpansResp, nil
}

func (f *fakeAPI) GetAgentInvocationV3(p *agent_invocation.GetAgentInvocationV3Params, _ ...agent_invocation.ClientOption) (*agent_invocation.GetAgentInvocationV3OK, error) {
	f.getInvocationCalls++
	f.lastInvocationID = p.ID
	if f.getInvocationErr != nil {
		return nil, f.getInvocationErr
	}
	if len(f.getInvocationStatus) > 0 {
		idx := f.getInvocationCalls - 1
		if idx >= len(f.getInvocationStatus) {
			idx = len(f.getInvocationStatus) - 1
		}
		return &agent_invocation.GetAgentInvocationV3OK{Payload: &models.APIInvokeAgentResponse{
			Resources: []*models.APIAgentInvocationResponseResource{{ID: p.ID, Status: f.getInvocationStatus[idx]}},
		}}, nil
	}
	return f.getInvocationResp, nil
}

func (f *fakeAPI) InvokePublishedAgentExternalV1(p *agent_invocation.InvokePublishedAgentExternalV1Params, _ ...agent_invocation.ClientOption) (*agent_invocation.InvokePublishedAgentExternalV1OK, error) {
	f.invokePublishedCalls++
	f.lastPublishedBody = p.Body
	return f.invokePublishedResp, f.invokePublishedErr
}

func (f *fakeAPI) InvokeAgentVersionExternalV1(p *agent_invocation.InvokeAgentVersionExternalV1Params, _ ...agent_invocation.ClientOption) (*agent_invocation.InvokeAgentVersionExternalV1OK, error) {
	f.invokeVersionCalls++
	f.lastVersionBody = p.Body
	return f.invokeVersionResp, f.invokeVersionErr
}

// newModule builds a Module wired to f with a tiny poll interval so block-poll
// tests finish fast.
func newModule(f *fakeAPI) *Module {
	return &Module{
		Agents:          f,
		AgentVersions:   f,
		Spans:           f,
		AgentInvocation: f,
		Concurrency:     4,
		PollInterval:    time.Millisecond,
		Timeout:         50 * time.Millisecond,
		Logger:          testLogger,
	}
}

// fakeStatusErr implements runtime.ClientResponseStatus for a chosen HTTP code,
// standing in for the untyped 400 the query operations return for a bad filter.
type fakeStatusErr struct{ code int }

func (e fakeStatusErr) Error() string       { return "status error" }
func (e fakeStatusErr) IsSuccess() bool     { return e.code >= 200 && e.code < 300 }
func (e fakeStatusErr) IsRedirect() bool    { return e.code >= 300 && e.code < 400 }
func (e fakeStatusErr) IsClientError() bool { return e.code >= 400 && e.code < 500 }
func (e fakeStatusErr) IsServerError() bool { return e.code >= 500 }
func (e fakeStatusErr) IsCode(c int) bool   { return e.code == c }

func TestSearchAgentsEmptyReturnsList(t *testing.T) {
	t.Parallel()
	f := &fakeAPI{queryAgentsResp: &agents.QueryAgentsV2OK{Payload: &models.APIQueryResponse{
		Resources: []string{},
		Meta:      &models.MsaMetaInfo{QueryTime: f64ptr(0.1)},
	}}}
	m := newModule(f)
	_, out, err := m.searchAgents(context.Background(), nil, SearchAgentsInput{})
	if err != nil {
		t.Fatalf("searchAgents: %v", err)
	}
	if out.Resources == nil || len(out.Resources) != 0 {
		t.Fatalf("expected empty non-nil resources, got %+v", out.Resources)
	}
	if f.getAgentsCalls != 0 {
		t.Fatalf("expected no detail fetch on empty result, got %d", f.getAgentsCalls)
	}
	if out.Meta == nil {
		t.Fatal("expected meta carried on empty result")
	}
}

func TestSearchAgentsFetchesDetailsRestoresOrder(t *testing.T) {
	t.Parallel()
	// Query returns IDs in one order; the details step returns them scrambled.
	// FetchDetails must reorder the entities back to the query order via keyFn.
	f := &fakeAPI{
		queryAgentsResp: &agents.QueryAgentsV2OK{Payload: &models.APIQueryResponse{
			Resources: []string{"a", "b", "c"},
			Meta:      &models.MsaMetaInfo{},
		}},
		getAgentsResp: &agents.GetAgentsV2OK{Payload: &models.APIAgentResponse{
			Resources: []*models.APIAgent{
				{ID: strptr("c")}, {ID: strptr("a")}, {ID: strptr("b")},
			},
		}},
	}
	m := newModule(f)
	_, out, err := m.searchAgents(context.Background(), nil, SearchAgentsInput{})
	if err != nil {
		t.Fatalf("searchAgents: %v", err)
	}
	got := make([]string, 0, len(out.Resources))
	for _, a := range out.Resources {
		got = append(got, *a.ID)
	}
	if !reflect.DeepEqual(got, []string{"a", "b", "c"}) {
		t.Fatalf("order not restored: got %v, want [a b c]", got)
	}
}

func TestSearchAgentsOptionalFilter(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		filter     string
		wantFilter *string
	}{
		{"omitted", "", nil},
		{"set", "template_id:'general'", strptr("template_id:'general'")},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := &fakeAPI{queryAgentsResp: &agents.QueryAgentsV2OK{Payload: &models.APIQueryResponse{Resources: []string{}}}}
			m := newModule(f)
			if _, _, err := m.searchAgents(context.Background(), nil, SearchAgentsInput{Filter: tc.filter}); err != nil {
				t.Fatalf("searchAgents: %v", err)
			}
			got := f.lastAgentsQuery.Filter
			if !reflect.DeepEqual(got, tc.wantFilter) {
				t.Fatalf("Filter param = %v, want %v", got, tc.wantFilter)
			}
		})
	}
}

func TestSearchAgentsFQLErrorReturnsGuide(t *testing.T) {
	t.Parallel()
	badReq := &agents.QueryAgentsV2BadRequest{Payload: &models.APIErrorResponse{
		Errors: []*models.MsaAPIError{{Code: new(int32(400)), Message: new("invalid FQL expression")}},
	}}
	f := &fakeAPI{queryAgentsErr: badReq}
	m := newModule(f)
	_, out, err := m.searchAgents(context.Background(), nil, SearchAgentsInput{Filter: "bogus:'x'"})
	if err != nil {
		t.Fatalf("expected data result on 400 with filter, got Go error: %v", err)
	}
	if out.FQLGuide == "" {
		t.Fatal("expected FQL guide populated on rejected filter")
	}
	if len(out.Errors) != 1 || out.Errors[0].Message != "invalid FQL expression" {
		t.Fatalf("expected API FQL error detail surfaced, got %+v", out.Errors)
	}
	if len(out.Resources) != 0 {
		t.Fatalf("expected no resources on FQL error, got %d", len(out.Resources))
	}
}

func TestSearchAgentsNonFQLBadRequestSurfacesError(t *testing.T) {
	t.Parallel()
	// A 400 whose message blames the sort (not the filter) is not a filter-syntax
	// problem; surface it as a Go error rather than misrouting to the filter guide.
	badReq := &agents.QueryAgentsV2BadRequest{Payload: &models.APIErrorResponse{
		Errors: []*models.MsaAPIError{{Code: new(int32(400)), Message: new("sort field not sortable")}},
	}}
	f := &fakeAPI{queryAgentsErr: badReq}
	m := newModule(f)
	if _, _, err := m.searchAgents(context.Background(), nil, SearchAgentsInput{Filter: "template_id:'x'", Sort: "bogus|desc"}); err == nil {
		t.Fatal("expected Go error for a non-FQL 400, got nil")
	}
}

func TestSearchAgentsBadRequestNoFilterSurfacesError(t *testing.T) {
	t.Parallel()
	// A 400 with no filter is not a filter-syntax problem; surface it as a Go error.
	f := &fakeAPI{queryAgentsErr: fakeStatusErr{code: 400}}
	m := newModule(f)
	if _, _, err := m.searchAgents(context.Background(), nil, SearchAgentsInput{}); err == nil {
		t.Fatal("expected Go error for a 400 with no filter, got nil")
	}
}

func TestSearchAgentVersionsFetchesDetailsRestoresOrder(t *testing.T) {
	t.Parallel()
	// Query returns IDs in one order; the details step returns them scrambled.
	// FetchDetails must reorder the entities back to the query order via keyFn.
	f := &fakeAPI{
		queryVersionsResp: &agent_versions.QueryAgentVersionsV1OK{Payload: &models.APIQueryResponse{
			Resources: []string{"v1", "v2", "v3"},
			Meta:      &models.MsaMetaInfo{},
		}},
		getVersionsResp: &agent_versions.GetAgentVersionsV1OK{Payload: &models.APIAgentVersionResponse{
			Resources: []*models.APIAgentVersion{
				{ID: strptr("v3")}, {ID: strptr("v1")}, {ID: strptr("v2")},
			},
		}},
	}
	m := newModule(f)
	_, out, err := m.searchAgentVersions(context.Background(), nil, SearchAgentVersionsInput{})
	if err != nil {
		t.Fatalf("searchAgentVersions: %v", err)
	}
	got := make([]string, 0, len(out.Resources))
	for _, v := range out.Resources {
		got = append(got, *v.ID)
	}
	if !reflect.DeepEqual(got, []string{"v1", "v2", "v3"}) {
		t.Fatalf("order not restored: got %v, want [v1 v2 v3]", got)
	}
}

func TestSearchAgentVersionsFQLErrorReturnsGuide(t *testing.T) {
	t.Parallel()
	badReq := &agent_versions.QueryAgentVersionsV1BadRequest{Payload: &models.APIErrorResponse{
		Errors: []*models.MsaAPIError{{Code: new(int32(400)), Message: new("invalid filter expression")}},
	}}
	f := &fakeAPI{queryVersionsErr: badReq}
	m := newModule(f)
	_, out, err := m.searchAgentVersions(context.Background(), nil, SearchAgentVersionsInput{Filter: "bogus:'x'"})
	if err != nil {
		t.Fatalf("expected data result on 400 with filter, got Go error: %v", err)
	}
	if out.FQLGuide == "" {
		t.Fatal("expected FQL guide populated on rejected filter")
	}
	if len(out.Errors) != 1 || out.Errors[0].Message != "invalid filter expression" {
		t.Fatalf("expected API FQL error detail surfaced, got %+v", out.Errors)
	}
	if len(out.Resources) != 0 {
		t.Fatalf("expected no resources on FQL error, got %d", len(out.Resources))
	}
}

func TestSearchSpansFQLErrorReturnsGuide(t *testing.T) {
	t.Parallel()
	badReq := &spans.QueriesSpansV1BadRequest{Payload: &models.APIErrorResponse{
		Errors: []*models.MsaAPIError{{Code: new(int32(400)), Message: new("unknown fql field")}},
	}}
	f := &fakeAPI{queriesSpansErr: badReq}
	m := newModule(f)
	_, out, err := m.searchSpans(context.Background(), nil, SearchSpansInput{Filter: "bad:'x'"})
	if err != nil {
		t.Fatalf("expected data result on 400 with filter, got Go error: %v", err)
	}
	if out.FQLGuide == "" {
		t.Fatal("expected spans FQL guide populated on rejected filter")
	}
	if len(out.Errors) != 1 || out.Errors[0].Message != "unknown fql field" {
		t.Fatalf("expected API FQL error detail surfaced, got %+v", out.Errors)
	}
}

func TestSearchSpansFetchesDetails(t *testing.T) {
	t.Parallel()
	f := &fakeAPI{
		queriesSpansResp: &spans.QueriesSpansV1OK{Payload: &models.MsaspecQueryResponse{
			Resources: []string{"s1", "s2"},
		}},
		entitiesSpansResp: &spans.EntitiesSpansV1OK{Payload: &models.DomainEntitiesSpansResponse{
			Resources: []*models.DomainSpan{{ID: strptr("s2")}, {ID: strptr("s1")}},
		}},
	}
	m := newModule(f)
	_, out, err := m.searchSpans(context.Background(), nil, SearchSpansInput{Filter: "trace_id:'abc'"})
	if err != nil {
		t.Fatalf("searchSpans: %v", err)
	}
	got := []string{*out.Resources[0].ID, *out.Resources[1].ID}
	if !reflect.DeepEqual(got, []string{"s1", "s2"}) {
		t.Fatalf("span order not restored: got %v, want [s1 s2]", got)
	}
}

func TestGetInvocationEmptyIDErrors(t *testing.T) {
	t.Parallel()
	f := &fakeAPI{}
	m := newModule(f)
	_, _, err := m.getInvocation(context.Background(), nil, GetInvocationInput{ID: ""})
	if !errors.Is(err, errInvalidInput) {
		t.Fatalf("expected errInvalidInput for empty id, got %v", err)
	}
	if f.getInvocationCalls != 0 {
		t.Fatalf("expected no API call for empty id, got %d", f.getInvocationCalls)
	}
}

func TestGetInvocationReturnsResource(t *testing.T) {
	t.Parallel()
	f := &fakeAPI{getInvocationResp: &agent_invocation.GetAgentInvocationV3OK{Payload: &models.APIInvokeAgentResponse{
		Resources: []*models.APIAgentInvocationResponseResource{{ID: "inv1", Status: "completed"}},
	}}}
	m := newModule(f)
	_, out, err := m.getInvocation(context.Background(), nil, GetInvocationInput{ID: "inv1"})
	if err != nil {
		t.Fatalf("getInvocation: %v", err)
	}
	if len(out.Resources) != 1 || out.Resources[0].ID != "inv1" {
		t.Fatalf("unexpected resources: %+v", out.Resources)
	}
	if f.lastInvocationID != "inv1" {
		t.Fatalf("path id = %q, want inv1", f.lastInvocationID)
	}
}

func TestInvokeDeadlineBelowMinRejected(t *testing.T) {
	t.Parallel()
	f := &fakeAPI{}
	m := newModule(f)
	_, _, err := m.invokeAgent(context.Background(), nil, InvokeInput{
		Prompt: "hi", AgentID: "ag1", DeadlineSeconds: 30,
	})
	if !errors.Is(err, errInvalidInput) {
		t.Fatalf("expected errInvalidInput for deadline < %d, got %v", minDeadlineSeconds, err)
	}
	if f.invokePublishedCalls != 0 || f.invokeVersionCalls != 0 {
		t.Fatal("expected no invoke call when deadline is rejected")
	}
}

func TestInvokeRequiredArgsRejected(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		in   InvokeInput
	}{
		{"empty prompt", InvokeInput{AgentID: "ag1"}},
		{"empty agent_id", InvokeInput{Prompt: "hi"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := &fakeAPI{}
			m := newModule(f)
			if _, _, err := m.invokeAgent(context.Background(), nil, tc.in); !errors.Is(err, errInvalidInput) {
				t.Fatalf("expected errInvalidInput, got %v", err)
			}
			if f.invokePublishedCalls != 0 || f.invokeVersionCalls != 0 {
				t.Fatal("expected no invoke call on invalid input")
			}
		})
	}
}

func TestInvokeDispatchPublished(t *testing.T) {
	t.Parallel()
	f := &fakeAPI{
		invokePublishedResp: &agent_invocation.InvokePublishedAgentExternalV1OK{Payload: &models.APIInvokeAgentResponse{
			Resources: []*models.APIAgentInvocationResponseResource{{ID: "inv1", AiTraceID: "trace1", Status: "processing"}},
		}},
		getInvocationStatus: []string{statusCompleted},
	}
	m := newModule(f)
	_, out, err := m.invokeAgent(context.Background(), nil, InvokeInput{Prompt: "hello", AgentID: "ag1"})
	if err != nil {
		t.Fatalf("invokeAgent: %v", err)
	}
	if f.invokePublishedCalls != 1 {
		t.Fatalf("expected published invoke, got %d published / %d version", f.invokePublishedCalls, f.invokeVersionCalls)
	}
	if f.invokeVersionCalls != 0 {
		t.Fatalf("expected no version invoke, got %d", f.invokeVersionCalls)
	}
	if f.lastPublishedBody.ID == nil || *f.lastPublishedBody.ID != "ag1" {
		t.Fatalf("published body ID = %v, want ag1", f.lastPublishedBody.ID)
	}
	if len(f.lastPublishedBody.Messages) != 1 {
		t.Fatalf("expected one message, got %d", len(f.lastPublishedBody.Messages))
	}
	msg := f.lastPublishedBody.Messages[0]
	if msg.Role == nil || *msg.Role != roleUser {
		t.Errorf("message role = %v, want %q", msg.Role, roleUser)
	}
	if msg.Content == nil || *msg.Content != "hello" {
		t.Errorf("message content = %v, want hello", msg.Content)
	}
	if out.Status != statusCompleted {
		t.Errorf("status = %q, want %q", out.Status, statusCompleted)
	}
	if out.AiTraceID != "trace1" {
		t.Errorf("ai_trace_id = %q, want trace1 (captured from initial invoke)", out.AiTraceID)
	}
	if out.ID != "inv1" {
		t.Errorf("id = %q, want inv1", out.ID)
	}
}

func TestInvokeDispatchVersion(t *testing.T) {
	t.Parallel()
	f := &fakeAPI{
		invokeVersionResp: &agent_invocation.InvokeAgentVersionExternalV1OK{Payload: &models.APIInvokeAgentResponse{
			Resources: []*models.APIAgentInvocationResponseResource{{ID: "inv2", AiTraceID: "trace2", Status: "processing"}},
		}},
		getInvocationStatus: []string{statusFailed},
	}
	m := newModule(f)
	_, out, err := m.invokeAgent(context.Background(), nil, InvokeInput{
		Prompt: "hi", AgentID: "ag1", VersionID: "v9",
	})
	if err != nil {
		t.Fatalf("invokeAgent: %v", err)
	}
	if f.invokeVersionCalls != 1 || f.invokePublishedCalls != 0 {
		t.Fatalf("expected version invoke, got %d version / %d published", f.invokeVersionCalls, f.invokePublishedCalls)
	}
	if f.lastVersionBody.VersionID == nil || *f.lastVersionBody.VersionID != "v9" {
		t.Fatalf("version body VersionID = %v, want v9", f.lastVersionBody.VersionID)
	}
	if f.lastVersionBody.ID == nil || *f.lastVersionBody.ID != "ag1" {
		t.Fatalf("version body ID = %v, want ag1", f.lastVersionBody.ID)
	}
	if out.Status != statusFailed {
		t.Errorf("status = %q, want %q", out.Status, statusFailed)
	}
}

func TestInvokeCapsSentWhenNonZero(t *testing.T) {
	t.Parallel()
	f := &fakeAPI{
		invokePublishedResp: &agent_invocation.InvokePublishedAgentExternalV1OK{Payload: &models.APIInvokeAgentResponse{
			Resources: []*models.APIAgentInvocationResponseResource{{ID: "inv1", Status: "processing"}},
		}},
		getInvocationStatus: []string{statusCompleted},
	}
	m := newModule(f)
	_, _, err := m.invokeAgent(context.Background(), nil, InvokeInput{
		Prompt: "hi", AgentID: "ag1", DeadlineSeconds: 120, CreditCentsLimit: 5,
	})
	if err != nil {
		t.Fatalf("invokeAgent: %v", err)
	}
	if f.lastPublishedBody.DeadlineSeconds != 120 {
		t.Errorf("DeadlineSeconds = %d, want 120", f.lastPublishedBody.DeadlineSeconds)
	}
	if f.lastPublishedBody.CreditCentsLimit != 5 {
		t.Errorf("CreditCentsLimit = %d, want 5", f.lastPublishedBody.CreditCentsLimit)
	}
}

func TestInvokeWaitingForToolApproval(t *testing.T) {
	t.Parallel()
	f := &fakeAPI{
		invokePublishedResp: &agent_invocation.InvokePublishedAgentExternalV1OK{Payload: &models.APIInvokeAgentResponse{
			Resources: []*models.APIAgentInvocationResponseResource{{ID: "inv1", AiTraceID: "trace1", Status: "processing"}},
		}},
		getInvocationStatus: []string{statusWaitingToolApproval},
	}
	m := newModule(f)
	_, out, err := m.invokeAgent(context.Background(), nil, InvokeInput{Prompt: "hi", AgentID: "ag1"})
	if err != nil {
		t.Fatalf("invokeAgent: %v", err)
	}
	if out.Status != statusWaitingToolApproval {
		t.Errorf("status = %q, want %q", out.Status, statusWaitingToolApproval)
	}
	if out.Note == "" {
		t.Error("expected a note explaining tool-approval pause")
	}
}

func TestInvokeTimeoutReturnsResumeHint(t *testing.T) {
	t.Parallel()
	// The run never reaches a terminal status, so the block-poll must time out
	// and return the id/status so the caller can resume server-side.
	f := &fakeAPI{
		invokePublishedResp: &agent_invocation.InvokePublishedAgentExternalV1OK{Payload: &models.APIInvokeAgentResponse{
			Resources: []*models.APIAgentInvocationResponseResource{{ID: "inv1", AiTraceID: "trace1", Status: "processing"}},
		}},
		getInvocationStatus: []string{"processing"},
	}
	m := newModule(f)
	m.Timeout = 10 * time.Millisecond
	_, out, err := m.invokeAgent(context.Background(), nil, InvokeInput{Prompt: "hi", AgentID: "ag1"})
	if err != nil {
		t.Fatalf("invokeAgent: %v", err)
	}
	if out.ID != "inv1" {
		t.Errorf("id = %q, want inv1", out.ID)
	}
	// TimeoutSeconds is whole-second truncation of m.Timeout; a sub-second test
	// timeout legitimately truncates to 0, so assert the resume contract instead.
	if out.Note == "" {
		t.Error("expected a resume note on timeout")
	}
}

func TestInvokePollGenuineErrorReturnsErrorStatus(t *testing.T) {
	t.Parallel()
	// The invoke succeeds, but the first poll fails with a non-context transport
	// error. The block-poll must surface that as an "error" status with a note,
	// not as a timeout or a Go error.
	f := &fakeAPI{
		invokePublishedResp: &agent_invocation.InvokePublishedAgentExternalV1OK{Payload: &models.APIInvokeAgentResponse{
			Resources: []*models.APIAgentInvocationResponseResource{{ID: "inv1", AiTraceID: "trace1", Status: "processing"}},
		}},
		getInvocationErr: errors.New("upstream boom"),
	}
	m := newModule(f)
	_, out, err := m.invokeAgent(context.Background(), nil, InvokeInput{Prompt: "hi", AgentID: "ag1"})
	if err != nil {
		t.Fatalf("invokeAgent: %v", err)
	}
	if out.Status != "error" {
		t.Errorf("status = %q, want error", out.Status)
	}
	if out.Note == "" {
		t.Error("expected a note carrying the poll failure detail")
	}
	if out.ID != "inv1" {
		t.Errorf("id = %q, want inv1", out.ID)
	}
	if out.AiTraceID != "trace1" {
		t.Errorf("ai_trace_id = %q, want trace1", out.AiTraceID)
	}
}

func TestRegisterToolsAnnotations(t *testing.T) {
	t.Parallel()
	var entries []base.ToolEntry
	reg := testutil.CaptureRegistrar(func(e base.ToolEntry) { entries = append(entries, e) })
	m := &Module{Logger: testLogger}
	m.RegisterTools(reg)

	byName := map[string]base.ToolEntry{}
	for _, e := range entries {
		byName[e.Tool.Name] = e
	}

	readOnly := []string{
		"falcon_search_agentworks_agents",
		"falcon_search_agentworks_agent_versions",
		"falcon_search_agentworks_spans",
		"falcon_get_agentworks_agent_invocation",
	}
	for _, name := range readOnly {
		e, ok := byName[name]
		if !ok {
			t.Fatalf("missing tool %s", name)
		}
		testutil.AssertReadOnlyAnnotations(t, name, e.Tool.Annotations)
	}

	inv, ok := byName["falcon_invoke_agentworks_agent"]
	if !ok {
		t.Fatal("missing falcon_invoke_agentworks_agent")
	}
	testutil.AssertMutatingAnnotations(t, "falcon_invoke_agentworks_agent", inv.Tool.Annotations, false)
}
