// Package mcpserver assembles the falcon-mcp MCP server: it builds the server,
// registers the enabled tool modules, and exposes Run over a transport.
package mcpserver

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/crowdstrike/falcon-mcp/internal/config"
	falconapi "github.com/crowdstrike/falcon-mcp/internal/falcon"
	"github.com/crowdstrike/falcon-mcp/internal/modules/base"
	"github.com/crowdstrike/falcon-mcp/internal/modules/registry"
	"github.com/crowdstrike/falcon-mcp/internal/version"
)

// ErrUnknownModule classifies a --modules allowlist entry that names no
// registered module. Callers can branch with errors.Is.
var ErrUnknownModule = errors.New("mcpserver: unknown module")

// serverInstructions is returned to clients in the initialize response's
// instructions field as a usage hint for the LLM.
const serverInstructions = "Connects AI agents to the CrowdStrike Falcon platform, exposing detections, threat intelligence, host management, and more as MCP tools."

// serverTitle is the human-readable display name reported to clients.
const serverTitle = "The CrowdStrike Falcon MCP Server"

// Server wraps the assembled MCP server and its registered modules. In dynamic
// mode it also owns the tool catalog's in-process session, torn down by Close.
type Server struct {
	mcp     *mcp.Server
	modules []base.Module
	catalog *Catalog // non-nil only in dynamic mode
}

// New builds a Server from cfg and the shared Falcon client. It constructs all
// registered modules (via the generated factory list), filters them against
// cfg.Modules (empty enables all), and registers the selected modules.
// It returns ErrUnknownModule (wrapped) when the allowlist names a module that
// does not exist. In dynamic mode it wires the catalog's in-process session;
// call Close to release it.
func New(cfg *config.Config, api *client.CrowdStrikeAPISpecification) (*Server, error) {
	s := mcp.NewServer(&mcp.Implementation{Name: "falcon-mcp", Title: serverTitle, Version: version.Version}, &mcp.ServerOptions{
		Instructions: serverInstructions,
		// KeepAlive pings idle sessions to detect dead peers and hold long-lived
		// http/sse connections open. Zero disables it (the SDK default), so stdio
		// and unconfigured deployments are unaffected.
		KeepAlive: cfg.KeepAlive,
	})

	// The process logger's level was already set by the CLI (preRunE) before we
	// are called; injecting it here keeps handlers free of the slog global.
	logger := slog.Default()
	allModules := registry.Build(registry.Deps{
		API:         api,
		Concurrency: cfg.DetailFetchConcurrency,
		Logger:      logger,
	}, moduleFactories())

	enabled, err := selectModules(allModules, cfg.Modules)
	if err != nil {
		return nil, err
	}

	// Probe uses cfg credentials for an OAuth token exchange so
	// falcon_check_connectivity does not disturb the shared gofalcon client's
	// cached token. Capture cfg by value into the closure.
	probeCfg := cfg
	check := func(ctx context.Context) bool {
		return falconapi.CheckConnectivity(ctx, probeCfg)
	}

	cat, err := registerModules(s, enabled, allModules, check, cfg.Dynamic)
	if err != nil {
		return nil, err
	}
	slog.Info("modules enabled", "modules", moduleNames(enabled), "dynamic", cfg.Dynamic)

	return &Server{mcp: s, modules: enabled, catalog: cat}, nil
}

// registerModules registers core tools and the enabled modules on s.
//
// Always (both modes): falcon_list_enabled_modules.
// Normal mode: also falcon_check_connectivity, falcon_list_modules, and each
// module's tools directly on s; the returned catalog is nil.
// Dynamic mode: real tools go on the catalog's internal server and only the
// meta-tools (search_tools, execute_tool) plus list_enabled_modules are on s;
// the returned catalog owns the in-process session and must be closed by the
// caller. Module resources (FQL guides) and prompts are exposed on s in both
// modes.
func registerModules(s *mcp.Server, enabled, all []base.Module, check ConnectivityChecker, dynamicMode bool) (*Catalog, error) {
	core := &coreTools{
		enabled:   enabled,
		available: moduleNames(all),
		check:     check,
	}
	reg := base.ServerRegistrar(s)
	// falcon_list_enabled_modules is always registered — dynamic mode's
	// no-results hint references it by name, and it's useful in both modes.
	core.registerAlwaysOn(reg)

	if !dynamicMode {
		core.registerNormalOnly(reg)
		for _, m := range enabled {
			m.RegisterTools(reg)
			m.RegisterResources(s)
			m.RegisterPrompts(s)
		}
		return nil, nil
	}

	cat := NewCatalog()
	for _, m := range enabled {
		m.RegisterTools(cat.ForModule(m.Name()))
		m.RegisterResources(s)
		m.RegisterPrompts(s)
	}
	// Connect the in-process session before serving so falcon_execute_tool can
	// dispatch. context.Background is right here: the session lives for the
	// server's lifetime, not a single request, and is closed via Server.Close.
	if err := cat.Connect(context.Background()); err != nil {
		return nil, err
	}
	// Meta-tools only: list_enabled_modules is already on the served server.
	NewMetaModule(cat, enabled).RegisterTools(reg)
	return cat, nil
}

// moduleNames returns the Name() of each module, in order. It is the single
// source for the enabled-modules log line and the "known" list in selection
// errors, so the module set is never enumerated by hand.
func moduleNames(modules []base.Module) []string {
	names := make([]string, len(modules))
	for i, m := range modules {
		names[i] = m.Name()
	}
	return names
}

// selectModules returns the subset of all whose Name() appears in want,
// preserving all's order. An empty want selects everything. Names in want that
// match no module yield a wrapped ErrUnknownModule; duplicates in want collapse.
func selectModules(all []base.Module, want []string) ([]base.Module, error) {
	if len(want) == 0 {
		return all, nil
	}

	known := moduleNames(all)
	var unknown []string
	for _, name := range want {
		if !slices.Contains(known, name) {
			unknown = append(unknown, name)
		}
	}
	if len(unknown) > 0 {
		return nil, fmt.Errorf("%w: %v (known: %v)", ErrUnknownModule, unknown, known)
	}

	var enabled []base.Module
	for _, m := range all {
		if slices.Contains(want, m.Name()) {
			enabled = append(enabled, m)
		}
	}
	return enabled, nil
}

// MCP returns the underlying MCP server, for wiring HTTP/SSE handlers that
// need a *mcp.Server per request.
func (s *Server) MCP() *mcp.Server { return s.mcp }

// Close releases resources held by the server. In dynamic mode it tears down
// the catalog's in-process session; in normal mode it is a no-op. It is safe to
// call more than once.
func (s *Server) Close() error {
	if s.catalog != nil {
		return s.catalog.Close()
	}
	return nil
}

// Run serves the MCP protocol over t until ctx is cancelled or the session
// ends, then releases server resources.
func (s *Server) Run(ctx context.Context, t mcp.Transport) error {
	defer func() { _ = s.Close() }()
	if err := s.mcp.Run(ctx, t); err != nil {
		return fmt.Errorf("mcpserver: run: %w", err)
	}
	return nil
}
