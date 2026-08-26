package testutil

import (
	"fmt"
	"log/slog"
	"reflect"
	"testing"

	"github.com/crowdstrike/falcon-mcp/internal/modules/base"
	"github.com/go-openapi/runtime"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// CaptureRegistrar is a base.Registrar that forwards each registered
// base.ToolEntry to the wrapped function, letting tests capture the tools a
// module registers.
type CaptureRegistrar func(base.ToolEntry)

// Add forwards e to the wrapped function, satisfying base.Registrar.
func (f CaptureRegistrar) Add(e base.ToolEntry) { f(e) }

// statusErr implements runtime.ClientResponseStatus for a chosen HTTP code,
// standing in for the untyped status errors gofalcon query operations return
// when no typed error type is generated for the operation.
type statusErr struct{ code int }

func (e statusErr) Error() string       { return fmt.Sprintf("status %d", e.code) }
func (e statusErr) IsSuccess() bool     { return e.code >= 200 && e.code < 300 }
func (e statusErr) IsRedirect() bool    { return e.code >= 300 && e.code < 400 }
func (e statusErr) IsClientError() bool { return e.code >= 400 && e.code < 500 }
func (e statusErr) IsServerError() bool { return e.code >= 500 }
func (e statusErr) IsCode(c int) bool   { return e.code == c }

var _ runtime.ClientResponseStatus = statusErr{}

// StatusErr returns an error reporting the given HTTP status via the go-openapi
// runtime.ClientResponseStatus interface, letting tests exercise status-based
// error classification without a live API call.
func StatusErr(code int) error { return statusErr{code: code} }

// CollectTools registers m's tools through a CaptureRegistrar and returns them
// keyed by their (already "falcon_"-prefixed) name, so tests can assert on
// individual tools without re-implementing the registrar plumbing.
func CollectTools(m base.Module) map[string]*mcp.Tool {
	tools := map[string]*mcp.Tool{}
	m.RegisterTools(CaptureRegistrar(func(e base.ToolEntry) {
		tools[e.Tool.Name] = e.Tool
	}))
	return tools
}

// DiscardLogger returns a logger that discards all output. Modules require a
// non-nil logger, so tests pass this when the log output itself is not under
// test.
func DiscardLogger() *slog.Logger {
	return slog.New(slog.DiscardHandler)
}

// AssertNormalizedMeta fails the test unless got equals base.NormalizedMeta(raw),
// i.e. the handler passed the API response's meta through the normalizer verbatim.
// raw is the value the handler received (typically a *models.MsaMetaInfo).
func AssertNormalizedMeta(t *testing.T, got *base.Meta, raw any) {
	t.Helper()
	if want := base.NormalizedMeta(raw); !reflect.DeepEqual(got, want) {
		t.Fatalf("Meta = %+v, want normalized passthrough %+v", got, want)
	}
}

// AssertReadOnlyAnnotations asserts that a carries read-only tool annotations:
// ReadOnlyHint is true and DestructiveHint is a non-nil false. name identifies
// the tool in failure messages.
func AssertReadOnlyAnnotations(t *testing.T, name string, a *mcp.ToolAnnotations) {
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

// AssertMutatingAnnotations asserts that a carries non-destructive mutating tool
// annotations: not read-only, DestructiveHint non-nil false, OpenWorldHint
// non-nil true, and IdempotentHint equal to idempotent. Callers pass idempotent
// true for PUT-like tools whose repeated application has no additional effect
// and false otherwise. name identifies the tool in failure messages.
func AssertMutatingAnnotations(t *testing.T, name string, a *mcp.ToolAnnotations, idempotent bool) {
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
	if a.DestructiveHint == nil || *a.DestructiveHint {
		t.Errorf("%s: DestructiveHint = %v, want non-nil false (MCP defaults omitted to true)", name, a.DestructiveHint)
	}
	if a.OpenWorldHint == nil || !*a.OpenWorldHint {
		t.Errorf("%s: OpenWorldHint = %v, want non-nil true", name, a.OpenWorldHint)
	}
}

// AssertDestructiveAnnotations asserts that a carries destructive tool
// annotations: not read-only, DestructiveHint non-nil true, OpenWorldHint
// non-nil true, and IdempotentHint equal to idempotent. name identifies the tool
// in failure messages.
func AssertDestructiveAnnotations(t *testing.T, name string, a *mcp.ToolAnnotations, idempotent bool) {
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
