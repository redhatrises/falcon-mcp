package rtr

import (
	"context"
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/crowdstrike/gofalcon/falcon/client/real_time_response"
	"github.com/crowdstrike/gofalcon/falcon/client/real_time_response_audit"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/crowdstrike/falcon-mcp/internal/modules/base"
)

// testLogger discards output; modules require a non-nil logger.
var testLogger = slog.New(slog.DiscardHandler)

func str(s string) *string { return &s }
func i32(v int32) *int32   { return &v }
func b(v bool) *bool       { return &v }

// fakeRTR is a configurable test double for the rtrAPI interface. Each field
// pairs a canned response with an error; call counters and captured params
// support assertions.
type fakeRTR struct {
	listAllResp *real_time_response.RTRListAllSessionsOK
	listAllErr  error

	listResp  *real_time_response.RTRListSessionsOK
	listErr   error
	listCalls int
	lastIDs   []string

	aggResp *real_time_response.RTRAggregateSessionsOK
	aggErr  error
	lastAgg []*models.MsaAggregateQueryRequest

	initResp *real_time_response.RTRInitSessionCreated
	initErr  error
	lastInit *models.DomainInitRequest

	pulseResp *real_time_response.RTRPulseSessionCreated
	pulseErr  error

	execResp  *real_time_response.RTRExecuteCommandCreated
	execErr   error
	execCalls int
	lastExec  *models.DomainCommandExecuteRequest

	statusResps []*real_time_response.RTRCheckCommandStatusOK
	statusErr   error
	statusCalls int
	lastSeqIDs  []int64

	filesResp *real_time_response.RTRListFilesV2OK
	filesErr  error

	deleteResp   *real_time_response.RTRDeleteSessionNoContent
	deleteErr    error
	lastDeleteID string
}

func (f *fakeRTR) RTRListAllSessions(*real_time_response.RTRListAllSessionsParams, ...real_time_response.ClientOption) (*real_time_response.RTRListAllSessionsOK, error) {
	return f.listAllResp, f.listAllErr
}

func (f *fakeRTR) RTRListSessions(p *real_time_response.RTRListSessionsParams, _ ...real_time_response.ClientOption) (*real_time_response.RTRListSessionsOK, error) {
	f.listCalls++
	if p.Body != nil {
		f.lastIDs = p.Body.Ids
	}
	return f.listResp, f.listErr
}

func (f *fakeRTR) RTRAggregateSessions(p *real_time_response.RTRAggregateSessionsParams, _ ...real_time_response.ClientOption) (*real_time_response.RTRAggregateSessionsOK, error) {
	f.lastAgg = p.Body
	return f.aggResp, f.aggErr
}

func (f *fakeRTR) RTRInitSession(p *real_time_response.RTRInitSessionParams, _ ...real_time_response.ClientOption) (*real_time_response.RTRInitSessionCreated, error) {
	f.lastInit = p.Body
	return f.initResp, f.initErr
}

func (f *fakeRTR) RTRPulseSession(p *real_time_response.RTRPulseSessionParams, _ ...real_time_response.ClientOption) (*real_time_response.RTRPulseSessionCreated, error) {
	return f.pulseResp, f.pulseErr
}

func (f *fakeRTR) RTRExecuteCommand(p *real_time_response.RTRExecuteCommandParams, _ ...real_time_response.ClientOption) (*real_time_response.RTRExecuteCommandCreated, error) {
	f.execCalls++
	f.lastExec = p.Body
	return f.execResp, f.execErr
}

func (f *fakeRTR) RTRCheckCommandStatus(p *real_time_response.RTRCheckCommandStatusParams, _ ...real_time_response.ClientOption) (*real_time_response.RTRCheckCommandStatusOK, error) {
	f.lastSeqIDs = append(f.lastSeqIDs, p.SequenceID)
	i := f.statusCalls
	f.statusCalls++
	if f.statusErr != nil {
		return nil, f.statusErr
	}
	if i < len(f.statusResps) {
		return f.statusResps[i], nil
	}
	if len(f.statusResps) > 0 {
		return f.statusResps[len(f.statusResps)-1], nil
	}
	return &real_time_response.RTRCheckCommandStatusOK{Payload: &models.DomainStatusResponseWrapper{}}, nil
}

func (f *fakeRTR) RTRListFilesV2(*real_time_response.RTRListFilesV2Params, ...real_time_response.ClientOption) (*real_time_response.RTRListFilesV2OK, error) {
	return f.filesResp, f.filesErr
}

func (f *fakeRTR) RTRDeleteSession(p *real_time_response.RTRDeleteSessionParams, _ ...real_time_response.ClientOption) (*real_time_response.RTRDeleteSessionNoContent, error) {
	f.lastDeleteID = p.SessionID
	if f.deleteResp == nil {
		f.deleteResp = &real_time_response.RTRDeleteSessionNoContent{Payload: &models.MsaReplyMetaOnly{}}
	}
	return f.deleteResp, f.deleteErr
}

// fakeAudit is a test double for the rtrAuditAPI interface.
type fakeAudit struct {
	resp *real_time_response_audit.RTRAuditSessionsOK
	err  error
}

func (f *fakeAudit) RTRAuditSessions(*real_time_response_audit.RTRAuditSessionsParams, ...real_time_response_audit.ClientOption) (*real_time_response_audit.RTRAuditSessionsOK, error) {
	return f.resp, f.err
}

func newModule(f *fakeRTR, a *fakeAudit) *Module {
	if a == nil {
		a = &fakeAudit{}
	}
	return &Module{API: f, Audit: a, Concurrency: 4, Logger: testLogger}
}

// --- search_rtr_sessions -----------------------------------------------------

func TestSearchSessionsTwoStep(t *testing.T) {
	t.Parallel()
	f := &fakeRTR{
		listAllResp: &real_time_response.RTRListAllSessionsOK{Payload: &models.DomainListSessionsResponseMsa{
			Resources: []string{"s1", "s2"},
			Meta:      &models.MsaMetaInfo{},
		}},
		listResp: &real_time_response.RTRListSessionsOK{Payload: &models.DomainSessionResponseWrapper{
			Resources: []*models.DomainSession{{ID: str("s1"), Hostname: str("H1")}, {ID: str("s2"), Hostname: str("H2")}},
		}},
	}
	m := newModule(f, nil)

	_, out, err := m.searchSessions(context.Background(), nil, SearchSessionsInput{Filter: "hostname:'H*'"})
	if err != nil {
		t.Fatalf("searchSessions: %v", err)
	}
	if len(out.Resources) != 2 || out.FilterUsed != "hostname:'H*'" {
		t.Fatalf("unexpected result: %+v", out)
	}
	if f.listCalls != 1 {
		t.Fatalf("expected one details call, got %d", f.listCalls)
	}
	if len(f.lastIDs) != 2 || f.lastIDs[0] != "s1" {
		t.Fatalf("expected ids threaded to details call, got %v", f.lastIDs)
	}
	if out.Meta != any(f.listAllResp.Payload.Meta) {
		t.Fatalf("expected verbatim meta passthrough, got %+v", out.Meta)
	}
}

func TestSearchSessionsReordersByQueryOrder(t *testing.T) {
	t.Parallel()
	// Details endpoint returns sessions out of query order; KeyFn must restore it.
	f := &fakeRTR{
		listAllResp: &real_time_response.RTRListAllSessionsOK{Payload: &models.DomainListSessionsResponseMsa{
			Resources: []string{"s1", "s2"},
		}},
		listResp: &real_time_response.RTRListSessionsOK{Payload: &models.DomainSessionResponseWrapper{
			Resources: []*models.DomainSession{{ID: str("s2")}, {ID: str("s1")}},
		}},
	}
	m := newModule(f, nil)
	_, out, err := m.searchSessions(context.Background(), nil, SearchSessionsInput{})
	if err != nil {
		t.Fatalf("searchSessions: %v", err)
	}
	if *out.Resources[0].ID != "s1" || *out.Resources[1].ID != "s2" {
		t.Fatalf("expected query order s1,s2, got %v,%v", *out.Resources[0].ID, *out.Resources[1].ID)
	}
}

func TestSearchSessionsEmpty(t *testing.T) {
	t.Parallel()
	f := &fakeRTR{listAllResp: &real_time_response.RTRListAllSessionsOK{Payload: &models.DomainListSessionsResponseMsa{
		Resources: []string{},
	}}}
	m := newModule(f, nil)

	_, out, err := m.searchSessions(context.Background(), nil, SearchSessionsInput{})
	if err != nil {
		t.Fatalf("searchSessions: %v", err)
	}
	if len(out.Resources) != 0 || out.Resources == nil {
		t.Fatalf("expected non-nil empty slice, got %+v", out)
	}
	if f.listCalls != 0 {
		t.Fatalf("expected no detail fetch on empty result, got %d", f.listCalls)
	}
}

func TestSearchSessionsFQLError(t *testing.T) {
	t.Parallel()
	// RTRListAllSessions returns a typed 400 with a DomainAPIError payload.
	badReq := &real_time_response.RTRListAllSessionsBadRequest{Payload: &models.DomainAPIError{
		Code: i32(400), Message: str("invalid filter"),
	}}
	f := &fakeRTR{listAllErr: badReq}
	m := newModule(f, nil)

	_, out, err := m.searchSessions(context.Background(), nil, SearchSessionsInput{Filter: "bogus:'x'"})
	if err != nil {
		t.Fatalf("expected FQL error formatted as data, not returned: %v", err)
	}
	if len(out.Errors) != 1 || out.Errors[0].Message != "invalid filter" || out.Errors[0].Code != 400 {
		t.Fatalf("expected FQL error detail, got %+v", out.Errors)
	}
	if out.FQLGuide == "" || out.Hint == "" {
		t.Fatalf("expected fql_guide and hint populated")
	}
	if f.listCalls != 0 {
		t.Fatalf("expected no detail fetch after FQL error")
	}
}

func TestSearchSessionsAPIError(t *testing.T) {
	t.Parallel()
	f := &fakeRTR{listAllErr: errors.New("boom")}
	m := newModule(f, nil)
	_, _, err := m.searchSessions(context.Background(), nil, SearchSessionsInput{})
	if err == nil {
		t.Fatalf("expected non-FQL error to be returned")
	}
}

// --- search_rtr_audit_sessions ----------------------------------------------

func TestSearchAuditSessions(t *testing.T) {
	t.Parallel()
	f := &fakeAudit{resp: &real_time_response_audit.RTRAuditSessionsOK{Payload: &models.DomainSessionResponseWrapper{
		Resources: []*models.DomainSession{{ID: str("a1")}},
		Meta:      &models.MsaMetaInfo{},
	}}}
	m := newModule(&fakeRTR{}, f)

	_, out, err := m.searchAuditSessions(context.Background(), nil, SearchAuditSessionsInput{Filter: "created_at:>'now-7d'"})
	if err != nil {
		t.Fatalf("searchAuditSessions: %v", err)
	}
	if len(out.Resources) != 1 || out.FilterUsed != "created_at:>'now-7d'" {
		t.Fatalf("unexpected result: %+v", out)
	}
	if out.Meta != any(f.resp.Payload.Meta) {
		t.Fatalf("expected verbatim meta passthrough, got %+v", out.Meta)
	}
}

func TestSearchAuditSessionsFQLError(t *testing.T) {
	t.Parallel()
	badReq := &real_time_response_audit.RTRAuditSessionsBadRequest{Payload: &models.DomainAPIError{
		Code: i32(400), Message: str("bad audit filter"),
	}}
	m := newModule(&fakeRTR{}, &fakeAudit{err: badReq})

	_, out, err := m.searchAuditSessions(context.Background(), nil, SearchAuditSessionsInput{Filter: "nope:'x'"})
	if err != nil {
		t.Fatalf("expected FQL error formatted as data: %v", err)
	}
	if len(out.Errors) != 1 || out.Errors[0].Message != "bad audit filter" {
		t.Fatalf("expected FQL error detail, got %+v", out.Errors)
	}
}

// --- aggregate_rtr_sessions --------------------------------------------------

func TestAggregateSessions(t *testing.T) {
	t.Parallel()
	f := &fakeRTR{aggResp: &real_time_response.RTRAggregateSessionsOK{Payload: &models.MsaAggregatesResponse{
		Resources: []*models.MsaAggregationResult{{Name: str("rtr_session_aggregation")}},
		Meta:      &models.MsaMetaInfo{},
	}}}
	m := newModule(f, nil)

	_, out, err := m.aggregateSessions(context.Background(), nil, AggregateInput{
		Field:         "created_at",
		AggregateType: "date_range",
		DateRanges:    []map[string]string{{"from": "now-7d", "to": "now"}},
	})
	if err != nil {
		t.Fatalf("aggregateSessions: %v", err)
	}
	if out.Total != 1 {
		t.Fatalf("expected one aggregation result, got %+v", out)
	}
	if out.Meta != any(f.aggResp.Payload.Meta) {
		t.Fatalf("expected verbatim meta passthrough, got %+v", out.Meta)
	}
	if len(f.lastAgg) != 1 {
		t.Fatalf("expected one aggregate query in body")
	}
	got := f.lastAgg[0]
	if got.Field == nil || *got.Field != "created_at" || got.Type == nil || *got.Type != "date_range" {
		t.Fatalf("unexpected aggregate body: %+v", got)
	}
	if len(got.DateRanges) != 1 || got.DateRanges[0].From == nil || *got.DateRanges[0].From != "now-7d" {
		t.Fatalf("expected date range folded into body, got %+v", got.DateRanges)
	}
	if got.Name == nil || *got.Name != "rtr_session_aggregation" {
		t.Fatalf("expected default name, got %+v", got.Name)
	}
}

func TestAggregateSessionsRequiresField(t *testing.T) {
	t.Parallel()
	m := newModule(&fakeRTR{}, nil)
	_, _, err := m.aggregateSessions(context.Background(), nil, AggregateInput{})
	if !errors.Is(err, errInvalidInput) {
		t.Fatalf("expected errInvalidInput, got %v", err)
	}
}

func TestAggregateSessionsRejectsBadType(t *testing.T) {
	t.Parallel()
	m := newModule(&fakeRTR{}, nil)
	_, _, err := m.aggregateSessions(context.Background(), nil, AggregateInput{Field: "hostname", AggregateType: "term"})
	if !errors.Is(err, errInvalidInput) {
		t.Fatalf("expected errInvalidInput for bad aggregate_type, got %v", err)
	}
}

// --- get_rtr_session_details -------------------------------------------------

func TestGetSessionDetailsEmpty(t *testing.T) {
	t.Parallel()
	f := &fakeRTR{}
	m := newModule(f, nil)
	_, out, err := m.getSessionDetails(context.Background(), nil, GetSessionDetailsInput{})
	if err != nil {
		t.Fatalf("getSessionDetails: %v", err)
	}
	if out.Resources == nil || out.Total != 0 {
		t.Fatalf("expected non-nil empty slice, got %+v", out)
	}
	if f.listCalls != 0 {
		t.Fatalf("expected no details call for empty ids")
	}
}

func TestGetSessionDetails(t *testing.T) {
	t.Parallel()
	f := &fakeRTR{listResp: &real_time_response.RTRListSessionsOK{Payload: &models.DomainSessionResponseWrapper{
		Resources: []*models.DomainSession{{ID: str("s1")}},
	}}}
	m := newModule(f, nil)
	_, out, err := m.getSessionDetails(context.Background(), nil, GetSessionDetailsInput{IDs: []string{"s1"}})
	if err != nil {
		t.Fatalf("getSessionDetails: %v", err)
	}
	if out.Total != 1 {
		t.Fatalf("expected one session, got %+v", out)
	}
}

// --- list_rtr_session_files --------------------------------------------------

func TestListSessionFiles(t *testing.T) {
	t.Parallel()

	t.Run("requires session_id", func(t *testing.T) {
		t.Parallel()
		m := newModule(&fakeRTR{}, nil)
		_, _, err := m.listSessionFiles(context.Background(), nil, ListFilesInput{})
		if !errors.Is(err, errInvalidInput) {
			t.Fatalf("expected errInvalidInput, got %v", err)
		}
	})

	t.Run("success", func(t *testing.T) {
		t.Parallel()
		f := &fakeRTR{filesResp: &real_time_response.RTRListFilesV2OK{Payload: &models.DomainListFilesV2ResponseWrapper{
			Resources: []*models.DomainFileV2{{ID: str("f1")}},
			Meta:      &models.MsaMetaInfo{},
		}}}
		m := newModule(f, nil)
		_, out, err := m.listSessionFiles(context.Background(), nil, ListFilesInput{SessionID: "s1"})
		if err != nil {
			t.Fatalf("listSessionFiles: %v", err)
		}
		if out.Total != 1 {
			t.Fatalf("expected one file, got %+v", out)
		}
		if out.Meta != any(f.filesResp.Payload.Meta) {
			t.Fatalf("expected verbatim meta passthrough, got %+v", out.Meta)
		}
	})
}

// --- init / pulse / delete ---------------------------------------------------

func TestInitSession(t *testing.T) {
	t.Parallel()

	t.Run("requires device_id", func(t *testing.T) {
		t.Parallel()
		m := newModule(&fakeRTR{}, nil)
		_, _, err := m.initSession(context.Background(), nil, InitInput{})
		if !errors.Is(err, errInvalidInput) {
			t.Fatalf("expected errInvalidInput, got %v", err)
		}
	})

	t.Run("defaults origin and sends body", func(t *testing.T) {
		t.Parallel()
		f := &fakeRTR{initResp: &real_time_response.RTRInitSessionCreated{Payload: &models.DomainInitResponseWrapper{
			Resources: []*models.DomainInitResponse{{SessionID: str("s1")}},
			Meta:      &models.MsaMetaInfo{},
		}}}
		m := newModule(f, nil)
		_, out, err := m.initSession(context.Background(), nil, InitInput{DeviceID: "aid1"})
		if err != nil {
			t.Fatalf("initSession: %v", err)
		}
		if out.Total != 1 {
			t.Fatalf("expected one session record, got %+v", out)
		}
		if f.lastInit.DeviceID == nil || *f.lastInit.DeviceID != "aid1" {
			t.Fatalf("expected device_id sent, got %+v", f.lastInit.DeviceID)
		}
		if f.lastInit.Origin == nil || *f.lastInit.Origin != defaultOrigin {
			t.Fatalf("expected default origin, got %+v", f.lastInit.Origin)
		}
		if out.Meta != any(f.initResp.Payload.Meta) {
			t.Fatalf("expected verbatim meta passthrough, got %+v", out.Meta)
		}
	})
}

func TestPulseSession(t *testing.T) {
	t.Parallel()
	f := &fakeRTR{pulseResp: &real_time_response.RTRPulseSessionCreated{Payload: &models.DomainInitResponseWrapper{
		Resources: []*models.DomainInitResponse{{SessionID: str("s1")}},
		Meta:      &models.MsaMetaInfo{},
	}}}
	m := newModule(f, nil)
	_, out, err := m.pulseSession(context.Background(), nil, PulseInput{DeviceID: "aid1"})
	if err != nil {
		t.Fatalf("pulseSession: %v", err)
	}
	if out.Total != 1 {
		t.Fatalf("expected one session record, got %+v", out)
	}
	if out.Meta != any(f.pulseResp.Payload.Meta) {
		t.Fatalf("expected verbatim meta passthrough, got %+v", out.Meta)
	}
}

func TestDeleteSession(t *testing.T) {
	t.Parallel()

	t.Run("requires session_id", func(t *testing.T) {
		t.Parallel()
		m := newModule(&fakeRTR{}, nil)
		_, _, err := m.deleteSession(context.Background(), nil, DeleteInput{})
		if !errors.Is(err, errInvalidInput) {
			t.Fatalf("expected errInvalidInput, got %v", err)
		}
	})

	t.Run("success returns ActionResult", func(t *testing.T) {
		t.Parallel()
		f := &fakeRTR{deleteResp: &real_time_response.RTRDeleteSessionNoContent{Payload: &models.MsaReplyMetaOnly{
			Meta: &models.MsaMetaInfo{},
		}}}
		m := newModule(f, nil)
		_, out, err := m.deleteSession(context.Background(), nil, DeleteInput{SessionID: "s1"})
		if err != nil {
			t.Fatalf("deleteSession: %v", err)
		}
		if !out.Ok {
			t.Fatalf("expected Ok, got %+v", out)
		}
		if f.lastDeleteID != "s1" {
			t.Fatalf("expected session id passed, got %q", f.lastDeleteID)
		}
		if out.Meta != any(f.deleteResp.Payload.Meta) {
			t.Fatalf("expected verbatim meta passthrough, got %+v", out.Meta)
		}
	})
}

// --- execute / check ---------------------------------------------------------

func TestExecuteReadOnlyCommand(t *testing.T) {
	t.Parallel()

	t.Run("validation", func(t *testing.T) {
		t.Parallel()
		for _, in := range []ExecuteInput{
			{BaseCommand: "ls"}, // missing session
			{SessionID: "s1"},   // missing base_command
		} {
			m := newModule(&fakeRTR{}, nil)
			_, _, err := m.executeReadOnlyCommand(context.Background(), nil, in)
			if !errors.Is(err, errInvalidInput) {
				t.Fatalf("expected errInvalidInput for %+v, got %v", in, err)
			}
		}
	})

	t.Run("sends body and returns records", func(t *testing.T) {
		t.Parallel()
		f := &fakeRTR{execResp: &real_time_response.RTRExecuteCommandCreated{Payload: &models.DomainCommandExecuteResponseWrapper{
			Resources: []*models.DomainCommandExecuteResponse{{CloudRequestID: str("crid1")}},
			Meta:      &models.MsaMetaInfo{},
		}}}
		m := newModule(f, nil)
		_, out, err := m.executeReadOnlyCommand(context.Background(), nil, ExecuteInput{SessionID: "s1", BaseCommand: "ls", CommandString: "ls C:\\", Persist: true})
		if err != nil {
			t.Fatalf("executeReadOnlyCommand: %v", err)
		}
		if out.Total != 1 {
			t.Fatalf("expected one command record, got %+v", out)
		}
		got := f.lastExec
		if got.SessionID == nil || *got.SessionID != "s1" || got.BaseCommand == nil || *got.BaseCommand != "ls" {
			t.Fatalf("unexpected exec body: %+v", got)
		}
		if got.CommandString == nil || *got.CommandString != "ls C:\\" {
			t.Fatalf("expected command_string sent, got %+v", got.CommandString)
		}
		if out.Meta != any(f.execResp.Payload.Meta) {
			t.Fatalf("expected verbatim meta passthrough, got %+v", out.Meta)
		}
	})
}

func TestCheckCommandStatus(t *testing.T) {
	t.Parallel()

	t.Run("requires cloud_request_id", func(t *testing.T) {
		t.Parallel()
		m := newModule(&fakeRTR{}, nil)
		_, _, err := m.checkCommandStatus(context.Background(), nil, CheckStatusInput{})
		if !errors.Is(err, errInvalidInput) {
			t.Fatalf("expected errInvalidInput, got %v", err)
		}
	})

	t.Run("success", func(t *testing.T) {
		t.Parallel()
		f := &fakeRTR{statusResps: []*real_time_response.RTRCheckCommandStatusOK{
			{Payload: &models.DomainStatusResponseWrapper{Resources: []*models.DomainStatusResponse{{Complete: b(true), Stdout: str("out")}}, Meta: &models.MsaMetaInfo{}}},
		}}
		m := newModule(f, nil)
		_, out, err := m.checkCommandStatus(context.Background(), nil, CheckStatusInput{CloudRequestID: "crid1", SequenceID: 2})
		if err != nil {
			t.Fatalf("checkCommandStatus: %v", err)
		}
		if out.Total != 1 {
			t.Fatalf("expected one status record, got %+v", out)
		}
		if len(f.lastSeqIDs) != 1 || f.lastSeqIDs[0] != 2 {
			t.Fatalf("expected sequence_id 2 passed, got %v", f.lastSeqIDs)
		}
		if out.Meta != any(f.statusResps[0].Payload.Meta) {
			t.Fatalf("expected verbatim meta passthrough, got %+v", out.Meta)
		}
	})
}

// --- run_rtr_read_only_command_and_wait --------------------------------------

func execOK() *real_time_response.RTRExecuteCommandCreated {
	return &real_time_response.RTRExecuteCommandCreated{Payload: &models.DomainCommandExecuteResponseWrapper{
		Resources: []*models.DomainCommandExecuteResponse{{CloudRequestID: str("crid1")}},
	}}
}

func TestWaitCompletesFirstPoll(t *testing.T) {
	t.Parallel()
	f := &fakeRTR{
		execResp: execOK(),
		statusResps: []*real_time_response.RTRCheckCommandStatusOK{
			{Payload: &models.DomainStatusResponseWrapper{Resources: []*models.DomainStatusResponse{
				{Complete: b(true), Stdout: str("hello"), Stderr: str("")},
			}}},
		},
	}
	m := newModule(f, nil)
	_, out, err := m.runReadOnlyCommandAndWait(context.Background(), nil, WaitInput{SessionID: "s1", BaseCommand: "ps"})
	if err != nil {
		t.Fatalf("wait: %v", err)
	}
	if !out.Complete || out.TimedOut {
		t.Fatalf("expected complete, got %+v", out)
	}
	if out.CloudRequestID != "crid1" || out.Stdout != "hello" {
		t.Fatalf("unexpected result: %+v", out)
	}
	if f.statusCalls != 1 {
		t.Fatalf("expected one status poll, got %d", f.statusCalls)
	}
}

func TestWaitAggregatesChunksAcrossPolls(t *testing.T) {
	t.Parallel()
	// First chunk carries a non-zero SequenceID so the second poll's captured
	// sequence_id (42) is provably derived from the first response's advancement,
	// not from the loop's zero-value default.
	f := &fakeRTR{
		execResp: execOK(),
		statusResps: []*real_time_response.RTRCheckCommandStatusOK{
			{Payload: &models.DomainStatusResponseWrapper{Resources: []*models.DomainStatusResponse{
				{Complete: b(false), Stdout: str("part1"), SequenceID: 42},
			}}},
			{Payload: &models.DomainStatusResponseWrapper{Resources: []*models.DomainStatusResponse{
				{Complete: b(true), Stdout: str("part2"), SequenceID: 43},
			}}},
		},
	}
	m := newModule(f, nil)
	_, out, err := m.runReadOnlyCommandAndWait(context.Background(), nil, WaitInput{
		SessionID: "s1", BaseCommand: "cat", PollIntervalSeconds: 0.5,
	})
	if err != nil {
		t.Fatalf("wait: %v", err)
	}
	if !out.Complete {
		t.Fatalf("expected complete, got %+v", out)
	}
	if out.Stdout != "part1part2" {
		t.Fatalf("expected aggregated stdout, got %q", out.Stdout)
	}
	if len(out.Status) != 2 {
		t.Fatalf("expected 2 status chunks, got %d", len(out.Status))
	}
	// First poll must start at 0; second must advance to the first chunk's
	// SequenceID (42), proving the advancement logic ran.
	if len(f.lastSeqIDs) != 2 || f.lastSeqIDs[0] != 0 || f.lastSeqIDs[1] != 42 {
		t.Fatalf("expected sequence advance [0 42], got %v", f.lastSeqIDs)
	}
}

func TestWaitPropagatesMidPollError(t *testing.T) {
	t.Parallel()
	// A genuine API error mid-poll (not a deadline) must surface as a hard error,
	// not be swallowed as a timeout. There is time left on the deadline.
	f := &fakeRTR{
		execResp:  execOK(),
		statusErr: errors.New("boom"),
	}
	m := newModule(f, nil)
	_, _, err := m.runReadOnlyCommandAndWait(context.Background(), nil, WaitInput{
		SessionID: "s1", BaseCommand: "ps", TimeoutSeconds: 600, PollIntervalSeconds: 0.5,
	})
	if err == nil {
		t.Fatalf("expected mid-poll API error to propagate as a hard error")
	}
}

func TestWaitTimesOut(t *testing.T) {
	t.Parallel()
	// Never-complete status; a 1s timeout with fast polling exercises the timeout
	// branch without a long test.
	f := &fakeRTR{
		execResp: execOK(),
		statusResps: []*real_time_response.RTRCheckCommandStatusOK{
			{Payload: &models.DomainStatusResponseWrapper{Resources: []*models.DomainStatusResponse{
				{Complete: b(false), Stdout: str("waiting")},
			}}},
		},
	}
	m := newModule(f, nil)
	_, out, err := m.runReadOnlyCommandAndWait(context.Background(), nil, WaitInput{
		SessionID: "s1", BaseCommand: "ps", TimeoutSeconds: 1, PollIntervalSeconds: 0.5,
	})
	if err != nil {
		t.Fatalf("wait: %v", err)
	}
	if out.Complete || !out.TimedOut {
		t.Fatalf("expected timed out, got %+v", out)
	}
	if out.Warning == "" {
		t.Fatalf("expected timeout warning")
	}
}

func TestWaitRespectsContextCancel(t *testing.T) {
	t.Parallel()
	f := &fakeRTR{
		execResp: execOK(),
		statusResps: []*real_time_response.RTRCheckCommandStatusOK{
			{Payload: &models.DomainStatusResponseWrapper{Resources: []*models.DomainStatusResponse{
				{Complete: b(false)},
			}}},
		},
	}
	m := newModule(f, nil)
	ctx, cancel := context.WithCancel(context.Background())
	// Cancel shortly after start; the loop must return a timed-out result promptly.
	go func() { time.Sleep(50 * time.Millisecond); cancel() }()
	_, out, err := m.runReadOnlyCommandAndWait(ctx, nil, WaitInput{
		SessionID: "s1", BaseCommand: "ps", TimeoutSeconds: 600, PollIntervalSeconds: 10,
	})
	if err != nil {
		t.Fatalf("wait: %v", err)
	}
	if !out.TimedOut {
		t.Fatalf("expected timed out on cancel, got %+v", out)
	}
}

func TestWaitExecuteError(t *testing.T) {
	t.Parallel()
	f := &fakeRTR{execErr: errors.New("boom")}
	m := newModule(f, nil)
	_, _, err := m.runReadOnlyCommandAndWait(context.Background(), nil, WaitInput{SessionID: "s1", BaseCommand: "ps"})
	if err == nil {
		t.Fatalf("expected execute error propagated")
	}
	if f.statusCalls != 0 {
		t.Fatalf("expected no polling after execute error")
	}
}

func TestWaitMissingCloudRequestID(t *testing.T) {
	t.Parallel()
	f := &fakeRTR{execResp: &real_time_response.RTRExecuteCommandCreated{Payload: &models.DomainCommandExecuteResponseWrapper{
		Resources: []*models.DomainCommandExecuteResponse{{CloudRequestID: nil}},
	}}}
	m := newModule(f, nil)
	_, _, err := m.runReadOnlyCommandAndWait(context.Background(), nil, WaitInput{SessionID: "s1", BaseCommand: "ps"})
	if !errors.Is(err, errInvalidInput) {
		t.Fatalf("expected errInvalidInput for missing cloud_request_id, got %v", err)
	}
}

// --- registration ------------------------------------------------------------

// captureRegistrar adapts a func to base.Registrar for registration tests.
type captureRegistrar func(base.ToolEntry)

func (f captureRegistrar) Add(e base.ToolEntry) { f(e) }

func TestRegisterToolsAnnotations(t *testing.T) {
	t.Parallel()
	var entries []base.ToolEntry
	reg := captureRegistrar(func(e base.ToolEntry) { entries = append(entries, e) })
	newModule(&fakeRTR{}, nil).RegisterTools(reg)

	byName := map[string]*mcp.Tool{}
	for _, e := range entries {
		byName[e.Tool.Name] = e.Tool
	}

	if len(entries) != 11 {
		t.Fatalf("expected 11 tools registered, got %d", len(entries))
	}

	// Mutating (non-destructive) tools.
	for _, name := range []string{
		"falcon_init_rtr_session",
		"falcon_pulse_rtr_session",
		"falcon_execute_rtr_read_only_command",
		"falcon_run_rtr_read_only_command_and_wait",
	} {
		tool := byName[name]
		if tool == nil {
			t.Fatalf("missing tool %s", name)
		}
		assertMutatingAnnotations(t, name, tool.Annotations)
	}

	// Destructive delete.
	del := byName["falcon_delete_rtr_session"]
	if del == nil {
		t.Fatal("missing falcon_delete_rtr_session")
	}
	assertDestructiveAnnotations(t, "falcon_delete_rtr_session", del.Annotations, true)

	// Read-only tools keep default read-only annotations.
	for _, name := range []string{
		"falcon_search_rtr_sessions",
		"falcon_search_rtr_audit_sessions",
		"falcon_aggregate_rtr_sessions",
		"falcon_get_rtr_session_details",
		"falcon_check_rtr_command_status",
		"falcon_list_rtr_session_files",
	} {
		tool := byName[name]
		if tool == nil {
			t.Fatalf("missing tool %s", name)
		}
		if tool.Annotations == nil || !tool.Annotations.ReadOnlyHint {
			t.Errorf("%s: expected ReadOnlyHint true, got %+v", name, tool.Annotations)
		}
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
		t.Errorf("%s: DestructiveHint = %v, want non-nil false", name, a.DestructiveHint)
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
}

// TestRegisterResourcesServesGuides verifies the module publishes its four RTR
// resources with the Python-matching URIs and names.
func TestRegisterResourcesServesGuides(t *testing.T) {
	t.Parallel()

	srv := mcp.NewServer(&mcp.Implementation{Name: "test", Version: "test"}, nil)
	newModule(&fakeRTR{}, nil).RegisterResources(srv)

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
	want := map[string]string{
		"falcon://rtr/sessions/search/fql-guide":       "falcon_search_rtr_sessions_fql_guide",
		"falcon://rtr/audit/sessions/search/fql-guide": "falcon_search_rtr_audit_sessions_fql_guide",
		"falcon://rtr/sessions/aggregate-guide":        "falcon_aggregate_rtr_sessions_guide",
		"falcon://rtr/workflows/investigation-guide":   "falcon_rtr_read_only_investigation_guide",
	}
	if len(list.Resources) != len(want) {
		t.Fatalf("expected %d resources, got %d", len(want), len(list.Resources))
	}
	for _, r := range list.Resources {
		if name, ok := want[r.URI]; !ok || r.Name != name {
			t.Errorf("resource {uri:%q name:%q} not in expected set", r.URI, r.Name)
		}
	}
}
