package testutil

import (
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

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
