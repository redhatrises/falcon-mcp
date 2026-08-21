package testutil

import (
	"context"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// waitTimeout bounds how long teardown waits for a server session to end before
// the test fails, so a stuck session reports a failure instead of hanging the
// test binary until the package-level timeout.
const waitTimeout = 5 * time.Second

// NewClientSession connects an in-memory MCP client to srv and returns the ready
// client session. It connects the server transport before the client (the SDK
// requires server-first because the client drives initialization) and registers
// t.Cleanup for both sides so the session is torn down when the test ends.
func NewClientSession(ctx context.Context, t *testing.T, srv *mcp.Server) *mcp.ClientSession {
	t.Helper()

	clientT, serverT := mcp.NewInMemoryTransports()
	ss, err := srv.Connect(ctx, serverT, nil)
	if err != nil {
		t.Fatalf("server connect: %v", err)
	}
	// Cleanup runs LIFO: the client (registered below) closes first, then the
	// server session drains. Bound the drain and surface any server-side error
	// rather than discarding it.
	t.Cleanup(func() {
		done := make(chan error, 1)
		go func() { done <- ss.Wait() }()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("server session wait: %v", err)
			}
		case <-time.After(waitTimeout):
			t.Errorf("server session did not end within %s", waitTimeout)
		}
	})

	cs, err := mcp.NewClient(&mcp.Implementation{Name: "c", Version: "test"}, nil).Connect(ctx, clientT, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	t.Cleanup(func() { _ = cs.Close() })

	return cs
}

// FQLGuideExpectation describes one FQL-guide resource a module serves: the
// expected resource Name, its URI, and the full guide text (Body).
type FQLGuideExpectation struct {
	Name string
	URI  string
	Body string
}

// AssertServesFQLGuide asserts that the resources applied by register expose
// exactly the resources described by want — no more, no fewer — each matching
// its Name and serving Body as its content. It stands up a server, opens an
// in-memory session, then lists and reads the resources over the real MCP
// protocol. It handles a single guide or several (e.g. intel and recon).
func AssertServesFQLGuide(ctx context.Context, t *testing.T, register func(*mcp.Server), want ...FQLGuideExpectation) {
	t.Helper()

	srv := mcp.NewServer(&mcp.Implementation{Name: "test", Version: "test"}, nil)
	register(srv)
	cs := NewClientSession(ctx, t, srv)

	list, err := cs.ListResources(ctx, nil)
	if err != nil {
		t.Fatalf("ListResources: %v", err)
	}
	if len(list.Resources) != len(want) {
		t.Fatalf("resource count = %d, want %d", len(list.Resources), len(want))
	}
	gotName := make(map[string]string, len(list.Resources))
	for _, r := range list.Resources {
		gotName[r.URI] = r.Name
	}

	for _, w := range want {
		name, ok := gotName[w.URI]
		if !ok {
			t.Errorf("resource %s not served", w.URI)
			continue
		}
		if name != w.Name {
			t.Errorf("resource %s name = %q, want %q", w.URI, name, w.Name)
		}

		read, err := cs.ReadResource(ctx, &mcp.ReadResourceParams{URI: w.URI})
		if err != nil {
			t.Errorf("ReadResource %s: %v", w.URI, err)
			continue
		}
		if len(read.Contents) != 1 {
			t.Errorf("resource %s: content count = %d, want 1", w.URI, len(read.Contents))
			continue
		}
		if got := read.Contents[0].Text; got != w.Body {
			t.Errorf("resource %s body mismatch: got %d bytes, want %d bytes\n--- got (first 200) ---\n%.200s\n--- want (first 200) ---\n%.200s",
				w.URI, len(got), len(w.Body), got, w.Body)
		}
	}
}
