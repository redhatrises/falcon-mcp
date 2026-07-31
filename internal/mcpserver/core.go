package mcpserver

import (
	"context"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/crowdstrike/falcon-mcp/internal/modules/base"
)

// ConnectivityChecker probes live Falcon API authentication. It must not
// disturb the shared client's cached token state (it uses a fresh token
// exchange). Unit tests inject a stub; production uses falconapi.CheckConnectivity.
type ConnectivityChecker func(ctx context.Context) bool

// ConnectivityResult is the falcon_check_connectivity output envelope.
type ConnectivityResult struct {
	Connected bool `json:"connected"`
}

// ListModulesResult is the falcon_list_modules output envelope (all available
// modules, regardless of --modules).
type ListModulesResult struct {
	Modules []string `json:"modules"`
}

// coreTools owns the three core tools. list_enabled_modules is
// registered in both modes; check_connectivity and list_modules only in normal
// mode (dynamic mode keeps the context window to the three meta-tools).
type coreTools struct {
	enabled   []base.Module
	available []string
	check     ConnectivityChecker
}

// registerAlwaysOn registers falcon_list_enabled_modules, which is present in
// both normal and dynamic mode: MetaModule.noMatchHint names it as the recovery
// step for a search that matched nothing, so it must be callable in dynamic mode.
func (c *coreTools) registerAlwaysOn(r base.Registrar) {
	base.AddTool(r, &mcp.Tool{
		Name: "list_enabled_modules",
		Description: "List the Falcon modules enabled on this server, each with its " +
			"name and description. Use this to learn which capability areas this " +
			"server exposes before searching for a tool.",
	}, c.listEnabledModules)
}

// registerNormalOnly registers falcon_check_connectivity and falcon_list_modules,
// which are exposed only outside dynamic mode.
func (c *coreTools) registerNormalOnly(r base.Registrar) {
	base.AddTool(r, &mcp.Tool{
		Name:        "check_connectivity",
		Description: "Check connectivity to the Falcon API.",
	}, c.checkConnectivity)

	base.AddTool(r, &mcp.Tool{
		Name:        "list_modules",
		Description: "List all available modules in the falcon-mcp server.",
	}, c.listModules)
}

func (c *coreTools) checkConnectivity(ctx context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, ConnectivityResult, error) {
	connected := false
	if c.check != nil {
		connected = c.check(ctx)
	}
	return nil, ConnectivityResult{Connected: connected}, nil
}

func (c *coreTools) listModules(_ context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, ListModulesResult, error) {
	// Copy so callers cannot mutate the shared available slice.
	mods := make([]string, len(c.available))
	copy(mods, c.available)
	return nil, ListModulesResult{Modules: mods}, nil
}

// listEnabledModules implements falcon_list_enabled_modules. It reports the
// enabled modules (honoring --modules), each with its name and description.
// The shape matches the dynamic-mode envelope (name + description + total).
func (c *coreTools) listEnabledModules(_ context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, EnabledModulesResult, error) {
	mods := make([]ModuleInfo, len(c.enabled))
	for i, mod := range c.enabled {
		mods[i] = ModuleInfo{Name: mod.Name(), Description: mod.Description()}
	}
	return nil, EnabledModulesResult{Modules: mods, Total: len(mods)}, nil
}
