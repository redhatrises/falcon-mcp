package mcpserver

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/crowdstrike/falcon-mcp/internal/config"
	"github.com/crowdstrike/falcon-mcp/internal/modules/base"
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

func TestListModulesReturnsAvailable(t *testing.T) {
	t.Parallel()
	c := &coreTools{available: []string{"hosts", "detections", "cloud"}}
	_, out, err := c.listModules(context.Background(), nil, struct{}{})
	if err != nil {
		t.Fatalf("listModules: %v", err)
	}
	if len(out.Modules) != 3 {
		t.Fatalf("modules = %v, want 3", out.Modules)
	}
	// Defensive copy: mutating the result must not affect the core slice.
	out.Modules[0] = "mutated"
	if c.available[0] != "hosts" {
		t.Fatal("listModules mutated shared available slice")
	}
}

func TestListModulesIgnoresEnabledFilter(t *testing.T) {
	t.Parallel()
	// available is the full registry; enabled is a subset — list_modules always
	// reports the full set.
	c := &coreTools{
		available: []string{"hosts", "detections", "cloud", "intel"},
		enabled:   []base.Module{fakeToolModule{name: "hosts"}},
	}
	_, out, err := c.listModules(context.Background(), nil, struct{}{})
	if err != nil {
		t.Fatalf("listModules: %v", err)
	}
	assertSameSet(t, out.Modules, []string{"hosts", "detections", "cloud", "intel"})
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

// TestNormalModeCoreToolsCallable drives the three core tools end-to-end over
// an in-memory MCP session against a real Server in normal mode.
func TestNormalModeCoreToolsCallable(t *testing.T) {
	t.Parallel()
	// Override New's probe by constructing via registerModules path with a stub.
	// Using New with empty cfg would still register tools; the probe would hit
	// the network with empty credentials and return false — which is fine for
	// list_modules / list_enabled_modules, but we assert check_connectivity
	// structure either way.
	srv, err := New(Options{
		Config: &config.Config{Modules: []string{"hosts"}},
		API:    &client.CrowdStrikeAPISpecification{},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = srv.Close() })

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

	// list_modules: full registry, not just enabled.
	res, err = cs.CallTool(ctx, &mcp.CallToolParams{Name: "falcon_list_modules"})
	if err != nil {
		t.Fatalf("list_modules: %v", err)
	}
	if res.IsError {
		t.Fatalf("list_modules error: %v", res.Content)
	}
	var all ListModulesResult
	if err := decodeStructured(t, res.StructuredContent, &all); err != nil {
		t.Fatalf("decode all: %v", err)
	}
	if len(all.Modules) < 2 {
		t.Fatalf("list_modules returned %d modules, want full registry", len(all.Modules))
	}
	foundHosts := false
	for _, n := range all.Modules {
		if n == "hosts" {
			foundHosts = true
			break
		}
	}
	if !foundHosts {
		t.Fatalf("list_modules missing hosts: %v", all.Modules)
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

// TestDynamicModeStillHasListEnabledModules ensures list_enabled_modules stays
// available when Dynamic=true (moved off MetaModule onto always-on core).
func TestDynamicModeStillHasListEnabledModules(t *testing.T) {
	t.Parallel()
	srv, err := New(Options{
		Config: &config.Config{Dynamic: true, Modules: []string{"hosts", "detections"}},
		API:    &client.CrowdStrikeAPISpecification{},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = srv.Close() })

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

	res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "falcon_list_enabled_modules"})
	if err != nil {
		t.Fatalf("list_enabled_modules: %v", err)
	}
	if res.IsError {
		t.Fatalf("list_enabled_modules error: %v", res.Content)
	}
	var enabled EnabledModulesResult
	if err := decodeStructured(t, res.StructuredContent, &enabled); err != nil {
		t.Fatalf("decode: %v", err)
	}
	names := make([]string, len(enabled.Modules))
	for i, m := range enabled.Modules {
		names[i] = m.Name
	}
	assertSameSet(t, names, []string{"hosts", "detections"})
}
