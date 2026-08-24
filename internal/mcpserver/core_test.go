package mcpserver

import (
	"context"
	"encoding/json"
	"slices"
	"testing"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/crowdstrike/falcon-mcp/internal/config"
	"github.com/crowdstrike/falcon-mcp/internal/modules/base"
	"github.com/crowdstrike/falcon-mcp/internal/testutil"
)

func TestCheckConnectivityTrue(t *testing.T) {
	t.Parallel()
	c := &coreTools{check: func(context.Context) bool { return true }}
	_, out, err := c.checkConnectivity(context.Background(), nil, struct{}{})
	if err != nil {
		t.Fatalf("checkConnectivity: %v", err)
	}
	if !out.Connected {
		t.Fatal("Connected = false, want true")
	}
}

func TestCheckConnectivityFalse(t *testing.T) {
	t.Parallel()
	c := &coreTools{check: func(context.Context) bool { return false }}
	_, out, err := c.checkConnectivity(context.Background(), nil, struct{}{})
	if err != nil {
		t.Fatalf("checkConnectivity: %v", err)
	}
	if out.Connected {
		t.Fatal("Connected = true, want false")
	}
}

func TestCheckConnectivityNilChecker(t *testing.T) {
	t.Parallel()
	c := &coreTools{}
	_, out, err := c.checkConnectivity(context.Background(), nil, struct{}{})
	if err != nil {
		t.Fatalf("checkConnectivity: %v", err)
	}
	if out.Connected {
		t.Fatal("nil checker should report Connected=false")
	}
}

func TestListEnabledToolsReportsKept(t *testing.T) {
	t.Parallel()
	reg := newRegistration()
	reg.kept["hosts"] = []string{"falcon_search_hosts", "falcon_get_host_details"}
	reg.kept["detections"] = []string{"falcon_search_detections"}
	c := &coreTools{reg: reg, policy: newToolPolicy(&config.Config{})}

	_, out, err := c.listEnabledTools(context.Background(), nil, struct{}{})
	if err != nil {
		t.Fatalf("listEnabledTools: %v", err)
	}
	if out.Total != 3 {
		t.Fatalf("Total = %d, want 3", out.Total)
	}
	assertSameSet(t, out.Tools, []string{"falcon_search_hosts", "falcon_get_host_details", "falcon_search_detections"})
	assertSameSet(t, out.ByModule["hosts"], []string{"falcon_search_hosts", "falcon_get_host_details"})
	// No deliberate filter is active, so the summary field stays empty.
	if out.FiltersActive != "" {
		t.Errorf("FiltersActive = %q, want empty (no filter active)", out.FiltersActive)
	}
}

func TestListEnabledToolsReportsActiveFilters(t *testing.T) {
	t.Parallel()
	reg := newRegistration()
	reg.kept["hosts"] = []string{"falcon_search_hosts"}
	c := &coreTools{reg: reg, policy: newToolPolicy(&config.Config{ReadOnly: true})}

	_, out, err := c.listEnabledTools(context.Background(), nil, struct{}{})
	if err != nil {
		t.Fatalf("listEnabledTools: %v", err)
	}
	if out.FiltersActive != "read-only" {
		t.Errorf("FiltersActive = %q, want %q", out.FiltersActive, "read-only")
	}
}

func TestListEnabledModulesSubset(t *testing.T) {
	t.Parallel()
	c := &coreTools{
		enabled: []base.Module{
			fakeToolModule{name: "detections"},
			fakeToolModule{name: "cloud"},
		},
	}
	_, out, err := c.listEnabledModules(context.Background(), nil, struct{}{})
	if err != nil {
		t.Fatalf("listEnabledModules: %v", err)
	}
	names := make([]string, len(out.Modules))
	for i, info := range out.Modules {
		names[i] = info.Name
	}
	assertSameSet(t, names, []string{"detections", "cloud"})
	if out.Total != 2 {
		t.Errorf("Total = %d, want 2", out.Total)
	}
}

// TestNormalModeCoreToolsCallable drives the core tools end-to-end over an
// in-memory MCP session against a real Server in normal mode.
func TestNormalModeCoreToolsCallable(t *testing.T) {
	t.Parallel()
	srv, err := New(
		&config.Config{Modules: []string{"hosts"}},
		&client.CrowdStrikeAPISpecification{},
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = srv.Close() })

	ctx := context.Background()
	cs := testutil.NewClientSession(ctx, t, srv.MCP())

	// list_enabled_modules: only hosts (from --modules allowlist).
	res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "falcon_list_enabled_modules"})
	if err != nil {
		t.Fatalf("list_enabled_modules: %v", err)
	}
	if res.IsError {
		t.Fatalf("list_enabled_modules error: %v", res.Content)
	}
	var enabled EnabledModulesResult
	if err := decodeStructured(t, res.StructuredContent, &enabled); err != nil {
		t.Fatalf("decode enabled: %v", err)
	}
	if enabled.Total != 1 || len(enabled.Modules) != 1 || enabled.Modules[0].Name != "hosts" {
		t.Fatalf("enabled = %+v, want single hosts module", enabled)
	}

	// list_enabled_tools: the hosts module's tools survived the (empty) policy.
	res, err = cs.CallTool(ctx, &mcp.CallToolParams{Name: "falcon_list_enabled_tools"})
	if err != nil {
		t.Fatalf("list_enabled_tools: %v", err)
	}
	if res.IsError {
		t.Fatalf("list_enabled_tools error: %v", res.Content)
	}
	var tools EnabledToolsResult
	if err := decodeStructured(t, res.StructuredContent, &tools); err != nil {
		t.Fatalf("decode tools: %v", err)
	}
	if tools.Total == 0 {
		t.Fatalf("list_enabled_tools returned no tools")
	}
	if !slices.Contains(tools.Tools, "falcon_search_hosts") {
		t.Fatalf("list_enabled_tools missing falcon_search_hosts: %v", tools.Tools)
	}
	// The core and meta tools are not module tools, so they must not appear.
	for _, n := range tools.Tools {
		if n == "falcon_list_enabled_tools" || n == "falcon_check_connectivity" || n == "falcon_list_enabled_modules" {
			t.Errorf("list_enabled_tools should not list core tool %q", n)
		}
	}

	// check_connectivity: with empty credentials the probe fails closed.
	res, err = cs.CallTool(ctx, &mcp.CallToolParams{Name: "falcon_check_connectivity"})
	if err != nil {
		t.Fatalf("check_connectivity: %v", err)
	}
	if res.IsError {
		t.Fatalf("check_connectivity error: %v", res.Content)
	}
	var conn ConnectivityResult
	if err := decodeStructured(t, res.StructuredContent, &conn); err != nil {
		// Some SDK paths put JSON in TextContent only; fall back.
		if len(res.Content) > 0 {
			if tc, ok := res.Content[0].(*mcp.TextContent); ok {
				if json.Unmarshal([]byte(tc.Text), &conn) == nil {
					goto checked
				}
			}
		}
		t.Fatalf("decode connectivity: %v (sc=%T)", err, res.StructuredContent)
	}
checked:
	// Empty/invalid credentials must not report connected.
	if conn.Connected {
		t.Error("check_connectivity Connected=true with empty credentials")
	}
}

// TestDynamicModeMetaToolSurface pins the dynamic-mode core/meta surface: the
// always-on falcon_list_enabled_tools is present, while the normal-only
// falcon_check_connectivity and falcon_list_enabled_modules are absent (dynamic
// mode keeps the client's context window down to the meta-tools).
func TestDynamicModeMetaToolSurface(t *testing.T) {
	t.Parallel()
	srv, err := New(
		&config.Config{Dynamic: true, Modules: []string{"hosts", "detections"}},
		&client.CrowdStrikeAPISpecification{},
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = srv.Close() })

	ctx := context.Background()
	cs := testutil.NewClientSession(ctx, t, srv.MCP())

	tools, err := cs.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}
	got := map[string]bool{}
	for _, tool := range tools.Tools {
		got[tool.Name] = true
	}
	for _, present := range []string{"falcon_list_enabled_tools", "falcon_search_tools", "falcon_execute_tool"} {
		if !got[present] {
			t.Errorf("dynamic mode missing meta-tool %q", present)
		}
	}
	for _, absent := range []string{"falcon_check_connectivity", "falcon_list_enabled_modules", "falcon_list_modules"} {
		if got[absent] {
			t.Errorf("dynamic mode advertised %q, want absent", absent)
		}
	}
	// The real module tools must not be advertised directly in dynamic mode.
	if got["falcon_search_hosts"] {
		t.Errorf("dynamic mode advertised module tool falcon_search_hosts directly, want absent")
	}

	// falcon_list_enabled_tools still reports the module tools behind the catalog.
	res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "falcon_list_enabled_tools"})
	if err != nil {
		t.Fatalf("list_enabled_tools: %v", err)
	}
	if res.IsError {
		t.Fatalf("list_enabled_tools error: %v", res.Content)
	}
	var enabledTools EnabledToolsResult
	if err := decodeStructured(t, res.StructuredContent, &enabledTools); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if enabledTools.Total == 0 {
		t.Fatalf("list_enabled_tools returned no tools in dynamic mode")
	}
}
