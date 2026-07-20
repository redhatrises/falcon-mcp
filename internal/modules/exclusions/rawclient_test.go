package exclusions

import (
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/crowdstrike/gofalcon/falcon/client/ml_exclusions"
	"github.com/go-openapi/runtime"
)

// stubClientResponse is a minimal runtime.ClientResponse for reader tests.
type stubClientResponse struct {
	code int
	body string
}

func (s stubClientResponse) Code() int                  { return s.code }
func (s stubClientResponse) Message() string            { return http.StatusText(s.code) }
func (s stubClientResponse) GetHeader(string) string    { return "" }
func (s stubClientResponse) GetHeaders(string) []string { return nil }
func (s stubClientResponse) Body() io.ReadCloser        { return io.NopCloser(strings.NewReader(s.body)) }

// stubReader is the wrapped reader capture delegates to for non-2xx responses.
type stubReader struct{ called bool }

func (r *stubReader) ReadResponse(runtime.ClientResponse, runtime.Consumer) (any, error) {
	r.called = true
	return nil, errors.New("delegated")
}

// TestRawCaptureReader2xx verifies that a 2xx response body is captured and a
// placeholder OK is returned so the generated method's type assertion succeeds.
func TestRawCaptureReader2xx(t *testing.T) {
	t.Parallel()
	for _, code := range []int{200, 201} {
		r := &rawCaptureReader{mk: func() any { return ml_exclusions.NewExclusionsGetV2OK() }}
		got, err := r.ReadResponse(stubClientResponse{code: code, body: `{"resources":[{"id":"a"}]}`}, nil)
		if err != nil {
			t.Fatalf("code %d: unexpected error %v", code, err)
		}
		if _, ok := got.(*ml_exclusions.ExclusionsGetV2OK); !ok {
			t.Fatalf("code %d: expected placeholder OK, got %T", code, got)
		}
		if string(r.body) != `{"resources":[{"id":"a"}]}` {
			t.Fatalf("code %d: body not captured, got %q", code, r.body)
		}
	}
}

// TestRawCaptureReaderNon2xxDelegates verifies non-2xx responses fall through to
// the wrapped reader, preserving gofalcon's typed error path.
func TestRawCaptureReaderNon2xxDelegates(t *testing.T) {
	t.Parallel()
	orig := &stubReader{}
	r := &rawCaptureReader{orig: orig, mk: func() any { return ml_exclusions.NewExclusionsGetV2OK() }}
	_, err := r.ReadResponse(stubClientResponse{code: 400, body: `{"errors":[]}`}, nil)
	if !orig.called {
		t.Fatalf("expected delegation to wrapped reader on 400")
	}
	if err == nil {
		t.Fatalf("expected wrapped reader error to surface")
	}
}
