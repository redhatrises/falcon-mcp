package base

import (
	"errors"
	"fmt"
	"reflect"
	"strings"

	"github.com/crowdstrike/gofalcon/falcon"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/go-openapi/runtime"
)

// Error is the normalized error shape returned to tools. It marshals to the
// same JSON envelope the Python server produced: {"error", "required_scopes",
// "resolution"}. StatusCode is internal only (json:"-").
type Error struct {
	Message        string   `json:"error"`
	StatusCode     int      `json:"-"`
	RequiredScopes []string `json:"required_scopes,omitempty"`
	Resolution     string   `json:"resolution,omitempty"`
}

// Error implements the error interface.
func (e *Error) Error() string { return e.Message }

// ErrInvalidInput is the shared sentinel for caller-side argument validation
// failures (empty required field, out-of-range value, mutually exclusive flags).
// Modules wrap it with InvalidInput and callers classify with
// errors.Is(err, base.ErrInvalidInput).
var ErrInvalidInput = errors.New("invalid input")

// InvalidInput builds an ErrInvalidInput-wrapped error for op with detail,
// formatted as "op: invalid input: detail". op names the operation, so the
// message needs no package prefix.
func InvalidInput(op, detail string) error {
	return fmt.Errorf("%s: %w: %s", op, ErrInvalidInput, detail)
}

// APIError converts a gofalcon transport error plus a gofalcon *OK response
// into a single *Error, or nil on success. scopes are the API scopes the
// operation requires; on a 403 they are attached so the caller learns exactly
// which permissions to grant. resp may be any gofalcon *OK value; its
// Payload.Errors are extracted reflectively so one funnel serves every
// operation without per-operation helpers.
func APIError(transportErr error, resp any, scopes ...Scope) *Error {
	if transportErr != nil {
		code := statusOf(transportErr)
		e := &Error{Message: falcon.ErrorExplain(transportErr), StatusCode: code}
		if code == 403 {
			if required := scopeStrings(scopes); len(required) > 0 {
				e.RequiredScopes = required
				e.Resolution = resolutionHint(required)
			}
		}
		return e
	}
	if err := falcon.AssertNoError(payloadErrors(resp)); err != nil {
		return &Error{Message: err.Error()}
	}
	return nil
}

// checkedStatusCodes are the HTTP statuses statusOf reports explicitly, in
// precedence order. It is a package-level array so statusOf allocates nothing
// on the error path.
var checkedStatusCodes = [...]int{400, 401, 403, 404, 409, 429, 500, 503}

// statusOf extracts the HTTP status from any gofalcon error generically, via
// the go-openapi runtime.ClientResponseStatus interface, so no per-operation
// type switch is needed. It returns 0 when the status is not recoverable.
func statusOf(err error) int {
	var st runtime.ClientResponseStatus
	if errors.As(err, &st) {
		for _, c := range checkedStatusCodes {
			if st.IsCode(c) {
				return c
			}
		}
		switch {
		case st.IsClientError():
			return 400
		case st.IsServerError():
			return 500
		}
	}
	return 0
}

// IsBadRequest reports whether err carries an HTTP 400 status. Search tools
// whose gofalcon client exposes no typed BadRequest to match on use this to
// classify a rejected filter and return the FQL guide instead of a raw error.
func IsBadRequest(err error) bool { return err != nil && statusOf(err) == 400 }

// scopeStrings flattens the console permission strings for the given scopes.
func scopeStrings(scopes []Scope) []string {
	var out []string
	for _, s := range scopes {
		out = append(out, s.Strings()...)
	}
	return out
}

// resolutionHint renders the 403 resolution message listing the required API
// scopes, so the caller learns exactly which permissions to grant.
func resolutionHint(required []string) string {
	return fmt.Sprintf(
		"This operation requires the following API scopes: %s. "+
			"Please ensure your API client has been granted these scopes in the "+
			"CrowdStrike Falcon console.", strings.Join(required, ", "))
}

// payloadErrors reflectively reads resp.Payload.Errors from any gofalcon *OK
// response and normalizes it to []*models.MsaAPIError for AssertNoError. Every
// generated *OK type has a Payload pointer whose target carries an Errors slice,
// but the element type varies per operation (models.MsaAPIError,
// models.ResponsesError, models.PolicymanagerError, ...) with no shared
// interface. They share the Code (*int32) and Message (*string) fields, so the
// elements are read reflectively rather than type-asserted against a single
// concrete type — a hardcoded assertion silently dropped errors on any operation
// whose payload used a different error type. It returns nil safely when the
// field or payload is absent.
func payloadErrors(resp any) []*models.MsaAPIError {
	if resp == nil {
		return nil
	}
	v := reflect.ValueOf(resp)
	for v.Kind() == reflect.Pointer {
		if v.IsNil() {
			return nil
		}
		v = v.Elem()
	}
	if v.Kind() != reflect.Struct {
		return nil
	}
	payload := v.FieldByName("Payload")
	if !payload.IsValid() {
		return nil
	}
	for payload.Kind() == reflect.Pointer {
		if payload.IsNil() {
			return nil
		}
		payload = payload.Elem()
	}
	if payload.Kind() != reflect.Struct {
		return nil
	}
	errsField := payload.FieldByName("Errors")
	if !errsField.IsValid() || errsField.Kind() != reflect.Slice {
		return nil
	}
	// Fast path: the error slice is already the type AssertNoError expects.
	if errs, ok := errsField.Interface().([]*models.MsaAPIError); ok {
		return errs
	}
	// General path: read Code/Message off each element regardless of its concrete
	// type, so operations whose payloads use ResponsesError/PolicymanagerError/etc.
	// are surfaced too. Message is always non-nil: gofalcon's AssertNoError
	// dereferences it unconditionally, so a nil here would panic the tool call.
	out := make([]*models.MsaAPIError, 0, errsField.Len())
	for i := 0; i < errsField.Len(); i++ {
		elem := errsField.Index(i)
		for elem.Kind() == reflect.Pointer {
			if elem.IsNil() {
				elem = reflect.Value{}
				break
			}
			elem = elem.Elem()
		}
		if !elem.IsValid() || elem.Kind() != reflect.Struct {
			continue
		}
		msg := stringField(elem, "Message")
		out = append(out, &models.MsaAPIError{
			Code:    int32Field(elem, "Code"),
			Message: &msg,
		})
	}
	return out
}

// int32Field returns the int32 value of the named field on struct value v as a
// pointer, or nil when the field is absent or not int32-shaped. It accepts both
// pointer (*int32) and value (int32) fields, since gofalcon error types vary.
func int32Field(v reflect.Value, name string) *int32 {
	f := v.FieldByName(name)
	if !f.IsValid() {
		return nil
	}
	if f.Kind() == reflect.Pointer {
		if f.IsNil() {
			return nil
		}
		f = f.Elem()
	}
	if code, ok := f.Interface().(int32); ok {
		return &code
	}
	return nil
}

// stringField returns the string value of the named field on struct value v, or
// "" when the field is absent, nil, or not string-shaped. It accepts both
// pointer (*string) and value (string) fields, since gofalcon error types vary.
// It never returns a form that would make a downstream *Message deref panic.
func stringField(v reflect.Value, name string) string {
	f := v.FieldByName(name)
	if !f.IsValid() {
		return ""
	}
	if f.Kind() == reflect.Pointer {
		if f.IsNil() {
			return ""
		}
		f = f.Elem()
	}
	if s, ok := f.Interface().(string); ok {
		return s
	}
	return ""
}
