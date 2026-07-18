package base

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/crowdstrike/gofalcon/falcon/models"
)

// fakeStatusErr implements runtime.ClientResponseStatus for a chosen HTTP code,
// standing in for a gofalcon per-operation transport error.
type fakeStatusErr struct {
	code int
	msg  string
}

func (e fakeStatusErr) Error() string       { return e.msg }
func (e fakeStatusErr) IsSuccess() bool     { return e.code >= 200 && e.code < 300 }
func (e fakeStatusErr) IsRedirect() bool    { return e.code >= 300 && e.code < 400 }
func (e fakeStatusErr) IsClientError() bool { return e.code >= 400 && e.code < 500 }
func (e fakeStatusErr) IsServerError() bool { return e.code >= 500 }
func (e fakeStatusErr) IsCode(c int) bool   { return e.code == c }

// fakeOKPayload mirrors a gofalcon *OK payload: a struct carrying Errors.
type fakeOKPayload struct {
	Errors    []*models.MsaAPIError
	Resources []string
}

// fakeOK mirrors a gofalcon *OK response: a pointer to a payload.
type fakeOK struct {
	Payload *fakeOKPayload
}

func TestAPIError_SuccessReturnsNil(t *testing.T) {
	t.Parallel()
	resp := &fakeOK{Payload: &fakeOKPayload{Resources: []string{"a", "b"}}}
	if e := APIError(nil, resp, Scope{Name: "Hosts", Read: true}); e != nil {
		t.Fatalf("APIError on clean success = %+v, want nil", e)
	}
}

func TestAPIError_403AttachesScopes(t *testing.T) {
	t.Parallel()
	transportErr := fakeStatusErr{code: 403, msg: "forbidden"}
	e := APIError(transportErr, nil, Scope{Name: "Hosts", Read: true})
	if e == nil {
		t.Fatal("APIError on 403 = nil, want *Error")
	}
	if e.StatusCode != 403 {
		t.Fatalf("StatusCode = %d, want 403", e.StatusCode)
	}
	if len(e.RequiredScopes) != 1 || e.RequiredScopes[0] != "Hosts:read" {
		t.Fatalf("RequiredScopes = %v, want [Hosts:read]", e.RequiredScopes)
	}
	if e.Resolution == "" {
		t.Fatal("Resolution empty on 403, want scope-grant hint")
	}
}

func TestAPIError_Non403NoScopes(t *testing.T) {
	t.Parallel()
	e := APIError(fakeStatusErr{code: 400, msg: "bad request"}, nil, Scope{Name: "Hosts", Read: true})
	if e == nil {
		t.Fatal("APIError on 400 = nil, want *Error")
	}
	if e.StatusCode != 400 {
		t.Fatalf("StatusCode = %d, want 400", e.StatusCode)
	}
	if len(e.RequiredScopes) != 0 || e.Resolution != "" {
		t.Fatalf("400 should not attach scopes/resolution, got %+v", e)
	}
}

func TestAPIError_PayloadErrors(t *testing.T) {
	t.Parallel()
	code := int32(500)
	msg := "internal boom"
	resp := &fakeOK{Payload: &fakeOKPayload{Errors: []*models.MsaAPIError{{Code: &code, Message: &msg}}}}
	e := APIError(nil, resp, Scope{Name: "Hosts", Read: true})
	if e == nil {
		t.Fatal("APIError with payload errors = nil, want *Error")
	}
	if e.Message == "" {
		t.Fatal("Message empty, want payload error text")
	}
}

// respErrOK and policyErrOK mirror gofalcon *OK payloads whose Errors slices use
// error element types other than MsaAPIError (ResponsesError for the
// data_protection query responses, PolicymanagerError for its entity-get
// responses). They guard the generalized payloadErrors path: a hardcoded
// []*models.MsaAPIError assertion silently dropped these.
type respErrPayload struct {
	Errors    []*models.ResponsesError
	Resources []string
}
type respErrOK struct{ Payload *respErrPayload }

type policyErrPayload struct {
	Errors    []*models.PolicymanagerError
	Resources []string
}
type policyErrOK struct{ Payload *policyErrPayload }

func TestAPIError_PayloadErrors_NonMsaTypes(t *testing.T) {
	t.Parallel()
	code := int32(500)
	msg := "partial fetch failed"

	respErr := &respErrOK{Payload: &respErrPayload{Errors: []*models.ResponsesError{{Code: &code, Message: &msg}}}}
	if e := APIError(nil, respErr, Scope{Name: "Data Protection", Read: true}); e == nil {
		t.Fatal("APIError with ResponsesError payload = nil, want the embedded error surfaced")
	}

	polErr := &policyErrOK{Payload: &policyErrPayload{Errors: []*models.PolicymanagerError{{Code: &code, Message: &msg}}}}
	if e := APIError(nil, polErr, Scope{Name: "Data Protection", Read: true}); e == nil {
		t.Fatal("APIError with PolicymanagerError payload = nil, want the embedded error surfaced")
	}

	// A populated-but-empty-message error slice still counts as an error; an
	// empty slice is clean success.
	clean := &respErrOK{Payload: &respErrPayload{Resources: []string{"a"}}}
	if e := APIError(nil, clean, Scope{Name: "Data Protection", Read: true}); e != nil {
		t.Fatalf("APIError with no embedded errors = %+v, want nil", e)
	}
}

// valErrPayload mirrors a gofalcon error type whose Code/Message are plain
// value fields (not pointers), e.g. models.AccessscopemanagerV1Error. The
// generalized path must read these without panicking.
type valErr struct {
	Code    int32
	Message string
}
type valErrPayload struct {
	Errors    []valErr
	Resources []string
}
type valErrOK struct{ Payload *valErrPayload }

func TestAPIError_PayloadErrors_NonPointerAndNilFields(t *testing.T) {
	t.Parallel()

	// Non-pointer Code/Message fields must not panic and must surface the error.
	valResp := &valErrOK{Payload: &valErrPayload{Errors: []valErr{{Code: 500, Message: "value-typed boom"}}}}
	if e := APIError(nil, valResp, Scope{Name: "Data Protection", Read: true}); e == nil {
		t.Fatal("APIError with value-typed Code/Message = nil, want the embedded error surfaced")
	}

	// A pointer-shaped error with a nil Message must not panic (gofalcon's
	// AssertNoError dereferences Message unconditionally).
	code := int32(500)
	nilMsg := &respErrOK{Payload: &respErrPayload{Errors: []*models.ResponsesError{{Code: &code}}}}
	e := APIError(nil, nilMsg, Scope{Name: "Data Protection", Read: true})
	if e == nil {
		t.Fatal("APIError with nil Message pointer = nil, want the embedded error surfaced")
	}
}

func TestAPIError_ReflectiveNilGuards(t *testing.T) {
	t.Parallel()
	// nil response, no transport error: nothing to report.
	if e := APIError(nil, nil, Scope{Name: "Hosts", Read: true}); e != nil {
		t.Fatalf("APIError(nil, nil) = %+v, want nil", e)
	}
	// response with nil Payload pointer must not panic and must return nil.
	if e := APIError(nil, &fakeOK{Payload: nil}, Scope{Name: "Hosts", Read: true}); e != nil {
		t.Fatalf("APIError with nil Payload = %+v, want nil", e)
	}
	// a response type with no Payload field at all must not panic.
	type noPayload struct{ X int }
	if e := APIError(nil, &noPayload{X: 1}, Scope{Name: "Hosts", Read: true}); e != nil {
		t.Fatalf("APIError with no Payload field = %+v, want nil", e)
	}
}

func TestError_JSONEnvelope(t *testing.T) {
	t.Parallel()
	e := &Error{Message: "boom", StatusCode: 403, RequiredScopes: []string{"Hosts:read"}, Resolution: "grant it"}
	b, err := json.Marshal(e)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if m["error"] != "boom" {
		t.Fatalf(`json["error"] = %v, want "boom"`, m["error"])
	}
	if _, ok := m["status_code"]; ok {
		t.Fatal("status_code must not be serialized (json:\"-\")")
	}
	if m["required_scopes"] == nil {
		t.Fatal("required_scopes missing from envelope")
	}
	if m["resolution"] != "grant it" {
		t.Fatalf(`json["resolution"] = %v`, m["resolution"])
	}
}

func TestError_OmitsEmptyOptionalFields(t *testing.T) {
	t.Parallel()
	b, _ := json.Marshal(&Error{Message: "boom"})
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	if _, ok := m["required_scopes"]; ok {
		t.Fatal("required_scopes should be omitted when empty")
	}
	if _, ok := m["resolution"]; ok {
		t.Fatal("resolution should be omitted when empty")
	}
}

// TestStatusOf_Wrapped verifies statusOf recovers the code via the interface
// even when the error is wrapped.
func TestStatusOf_Wrapped(t *testing.T) {
	t.Parallel()
	wrapped := errors.Join(errors.New("context"), fakeStatusErr{code: 429, msg: "rate limited"})
	if got := statusOf(wrapped); got != 429 {
		t.Fatalf("statusOf(wrapped 429) = %d, want 429", got)
	}
}
