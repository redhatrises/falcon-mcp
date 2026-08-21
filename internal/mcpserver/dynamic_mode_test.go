package mcpserver

import (
	"context"
	"testing"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/crowdstrike/falcon-mcp/internal/config"
	"github.com/crowdstrike/falcon-mcp/internal/testutil"
)

// listToolNames connects an in-memory client to srv and returns the registered
// tool names.
func listToolNames(t *testing.T, srv *Server) map[string]bool {
	t.Helper()
	ctx := context.Background()
	cs := testutil.NewClientSession(ctx, t, srv.MCP())

	tools, err := cs.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}
	names := map[string]bool{}
	for _, tool := range tools.Tools {
		names[tool.Name] = true
	}
	return names
}

// dynamicModeToolNames are the three tools exposed in dynamic mode (meta-tools
// plus always-on list_enabled_modules).
var dynamicModeToolNames = []string{"falcon_search_tools", "falcon_execute_tool", "falcon_list_enabled_modules"}

// normalModeCoreToolNames are the three core tools registered in
// normal mode (not the dynamic search/execute meta-tools).
var normalModeCoreToolNames = []string{"falcon_check_connectivity", "falcon_list_modules", "falcon_list_enabled_modules"}

// TestDynamicModeExposesOnlyMetaTools verifies that with Dynamic=true the server
// exposes exactly the three dynamic tools and none of the real tools or
// normal-only core tools.
func TestDynamicModeExposesOnlyMetaTools(t *testing.T) {
	t.Parallel()
	srv, err := New(&config.Config{Dynamic: true}, &client.CrowdStrikeAPISpecification{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	names := listToolNames(t, srv)

	if len(names) != len(dynamicModeToolNames) {
		t.Errorf("tool count = %d %v, want %d dynamic tools", len(names), keys(names), len(dynamicModeToolNames))
	}
	for _, want := range dynamicModeToolNames {
		if !names[want] {
			t.Errorf("dynamic tool %q not registered", want)
		}
	}
	// A representative real tool must NOT be present.
	if names["falcon_search_hosts"] {
		t.Error("real tool falcon_search_hosts leaked in dynamic mode")
	}
	// Normal-only core tools must NOT be present in dynamic mode.
	if names["falcon_check_connectivity"] {
		t.Error("falcon_check_connectivity leaked in dynamic mode")
	}
	if names["falcon_list_modules"] {
		t.Error("falcon_list_modules leaked in dynamic mode")
	}
}

// TestNormalModeExposesRealToolsAndCore verifies the default mode exposes real
// module tools plus the three core tools, and not the dynamic search/execute
// meta-tools.
func TestNormalModeExposesRealToolsAndCore(t *testing.T) {
	t.Parallel()
	srv, err := New(&config.Config{}, &client.CrowdStrikeAPISpecification{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	names := listToolNames(t, srv)

	if !names["falcon_search_hosts"] {
		t.Error("real tool falcon_search_hosts missing in normal mode")
	}
	for _, core := range normalModeCoreToolNames {
		if !names[core] {
			t.Errorf("core tool %q missing in normal mode", core)
		}
	}
	// Dynamic-only meta-tools must not leak into normal mode.
	for _, meta := range []string{"falcon_search_tools", "falcon_execute_tool"} {
		if names[meta] {
			t.Errorf("dynamic meta-tool %q leaked in normal mode", meta)
		}
	}
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// TestDynamicMetaToolAnnotations verifies annotation posture for the
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
	ctx := context.Background()
	cs := testutil.NewClientSession(ctx, t, srv.MCP())
	tools, err := cs.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}
	byName := map[string]*mcp.Tool{}
	for _, tool := range tools.Tools {
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
