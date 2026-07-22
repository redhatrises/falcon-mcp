package mcpserver

import (
	"context"
	"testing"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/crowdstrike/falcon-mcp/internal/config"
)

// listTools connects an in-memory client to srv and returns the registered tools.
func listTools(t *testing.T, srv *Server) []*mcp.Tool {
	t.Helper()
	clientT, serverT := mcp.NewInMemoryTransports()
	ctx := context.Background()
	ss, err := srv.MCP().Connect(ctx, serverT, nil)
	if err != nil {
		t.Fatalf("server connect: %v", err)
	}
	t.Cleanup(func() { _ = ss.Wait() })

	cs, err := mcp.NewClient(&mcp.Implementation{Name: "c", Version: "test"}, nil).Connect(ctx, clientT, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	t.Cleanup(func() { _ = cs.Close() })

	tools, err := cs.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}
	return tools.Tools
}

// listToolNames connects an in-memory client to srv and returns the registered
// tool names.
func listToolNames(t *testing.T, srv *Server) map[string]bool {
	t.Helper()
	names := map[string]bool{}
	for _, tool := range listTools(t, srv) {
		names[tool.Name] = true
	}
	return names
}

// metaToolNames are the three meta-tools exposed only in dynamic mode.
var metaToolNames = []string{"falcon_search_tools", "falcon_execute_tool", "falcon_list_enabled_modules"}

// TestDynamicModeExposesOnlyMetaTools verifies that with Dynamic=true the server
// exposes exactly the three meta-tools and none of the real tools.
func TestDynamicModeExposesOnlyMetaTools(t *testing.T) {
	t.Parallel()
	srv, err := New(&config.Config{Dynamic: true}, &client.CrowdStrikeAPISpecification{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	names := listToolNames(t, srv)

	if len(names) != len(metaToolNames) {
		t.Errorf("tool count = %d %v, want %d meta-tools", len(names), keys(names), len(metaToolNames))
	}
	for _, want := range metaToolNames {
		if !names[want] {
			t.Errorf("meta-tool %q not registered", want)
		}
	}
	// A representative real tool must NOT be present.
	if names["falcon_search_hosts"] {
		t.Error("real tool falcon_search_hosts leaked in dynamic mode")
	}
}

// TestNormalModeExposesRealToolsNotMeta verifies the default mode exposes the
// real tools and none of the meta-tools.
func TestNormalModeExposesRealToolsNotMeta(t *testing.T) {
	t.Parallel()
	srv, err := New(&config.Config{}, &client.CrowdStrikeAPISpecification{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	names := listToolNames(t, srv)

	if !names["falcon_search_hosts"] {
		t.Error("real tool falcon_search_hosts missing in normal mode")
	}
	for _, meta := range metaToolNames {
		if names[meta] {
			t.Errorf("meta-tool %q leaked in normal mode", meta)
		}
	}
}

// TestDynamicMetaToolAnnotations verifies annotation posture for the three
// dynamic-mode meta-tools. falcon_search_tools and falcon_list_enabled_modules
// are read-only discovery helpers; falcon_execute_tool is a general dispatcher
// that can invoke mutating tools, so it must NOT advertise readOnlyHint
// (it uses MutatingAnnotations so base.AddTool does not apply the default
// read-only set). See docs/usage/dynamic-mode.md.
func TestDynamicMetaToolAnnotations(t *testing.T) {
	t.Parallel()
	srv, err := New(&config.Config{Dynamic: true}, &client.CrowdStrikeAPISpecification{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	byName := map[string]*mcp.Tool{}
	for _, tool := range listTools(t, srv) {
		byName[tool.Name] = tool
	}

	for _, name := range []string{"falcon_search_tools", "falcon_list_enabled_modules"} {
		tool, ok := byName[name]
		if !ok {
			t.Fatalf("%s not registered", name)
		}
		ann := tool.Annotations
		if ann == nil {
			t.Fatalf("%s: annotations nil, want read-only", name)
		}
		if !ann.ReadOnlyHint {
			t.Errorf("%s: ReadOnlyHint = false, want true", name)
		}
		if ann.DestructiveHint != nil && *ann.DestructiveHint {
			t.Errorf("%s: DestructiveHint = true, want false", name)
		}
	}

	exec, ok := byName["falcon_execute_tool"]
	if !ok {
		t.Fatal("falcon_execute_tool not registered")
	}
	ann := exec.Annotations
	if ann == nil {
		// Nil would also be non-read-only under MCP defaults, but Go always
		// materializes annotations via base.AddTool — require explicit non-readonly.
		t.Fatal("falcon_execute_tool: annotations nil; want explicit non-read-only annotations")
	}
	if ann.ReadOnlyHint {
		t.Errorf("falcon_execute_tool: ReadOnlyHint = true, want false (dispatcher can mutate)")
	}
	if ann.DestructiveHint == nil {
		t.Error("falcon_execute_tool: DestructiveHint nil; want explicit false (MCP defaults true when omitted)")
	} else if *ann.DestructiveHint {
		t.Errorf("falcon_execute_tool: DestructiveHint = true, want false")
	}
	if ann.OpenWorldHint == nil || !*ann.OpenWorldHint {
		t.Errorf("falcon_execute_tool: OpenWorldHint = %v, want true", ann.OpenWorldHint)
	}
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
