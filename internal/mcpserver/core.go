package mcpserver

import (
	"context"
	"sort"

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

// EnabledToolsResult is the falcon_list_enabled_tools output envelope. It lists
// the module tools that survived the tool policy (sorted names, and grouped by
// module), plus a human-readable summary of which filters are active. It does
// not list the core or meta tools.
type EnabledToolsResult struct {
	Tools         []string            `json:"tools"`
	Total         int                 `json:"total"`
	ByModule      map[string][]string `json:"by_module"`
	FiltersActive string              `json:"filters_active,omitempty"`
}

// coreTools owns the core (non-module) tools. list_enabled_tools is registered
// in both modes; check_connectivity and list_enabled_modules only in normal
// mode (dynamic mode keeps the context window to the three meta-tools).
type coreTools struct {
	enabled []base.Module
	check   ConnectivityChecker
	reg     *registration
	policy  toolPolicy
}

// registerAlwaysOn registers falcon_list_enabled_tools, which is present in both
// normal and dynamic mode so a client can always see which tools survived the
// policy without loading their schemas.
func (c *coreTools) registerAlwaysOn(r base.Registrar) {
	base.AddTool(r, &mcp.Tool{
		Name:        "list_enabled_tools",
		Description: "List the Falcon tools enabled on this server, grouped by module, with a summary of any active tool filters.",
	}, c.listEnabledTools)
}

// registerNormalOnly registers falcon_check_connectivity and
// falcon_list_enabled_modules, which are exposed only outside dynamic mode.
func (c *coreTools) registerNormalOnly(r base.Registrar) {
	base.AddTool(r, &mcp.Tool{
		Name:        "check_connectivity",
		Description: "Check connectivity to the Falcon API.",
	}, c.checkConnectivity)

	base.AddTool(r, &mcp.Tool{
		Name:        "list_enabled_modules",
		Description: "List the Falcon modules enabled on this server.",
	}, c.listEnabledModules)
}

func (c *coreTools) checkConnectivity(ctx context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, ConnectivityResult, error) {
	connected := false
	if c.check != nil {
		connected = c.check(ctx)
	}
	return nil, ConnectivityResult{Connected: connected}, nil
}

// listEnabledTools implements falcon_list_enabled_tools. It reports the module
// tools that survived the policy — a flat sorted list and a per-module grouping
// — plus a description of any active filters. It reads the registration lazily,
// which is fully populated by the time any request arrives.
func (c *coreTools) listEnabledTools(_ context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, EnabledToolsResult, error) {
	byModule := make(map[string][]string, len(c.reg.kept))
	var all []string
	for mod, names := range c.reg.kept {
		sorted := make([]string, len(names))
		copy(sorted, names)
		sort.Strings(sorted)
		byModule[mod] = sorted
		all = append(all, names...)
	}
	sort.Strings(all)

	res := EnabledToolsResult{Tools: all, Total: len(all), ByModule: byModule}
	if c.policy.active() {
		res.FiltersActive = c.policy.describe()
	}
	return nil, res, nil
}

// listEnabledModules implements falcon_list_enabled_modules. It reports the
// enabled modules (honoring --modules), each with its name and description. The
// shape matches the dynamic-mode envelope (name + description + total).
func (c *coreTools) listEnabledModules(_ context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, EnabledModulesResult, error) {
	mods := make([]ModuleInfo, len(c.enabled))
	for i, mod := range c.enabled {
		mods[i] = ModuleInfo{Name: mod.Name(), Description: mod.Description()}
	}
	return nil, EnabledModulesResult{Modules: mods, Total: len(mods)}, nil
}
