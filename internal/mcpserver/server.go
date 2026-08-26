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

// baseInstructions is returned to clients in the initialize response's
// instructions field as a usage hint for the LLM. Both transport modes inherit
// it; it carries the cross-cutting filter and state-change guidance no single
// tool description owns.
const baseInstructions = "This server provides access to CrowdStrike Falcon capabilities.\n\n" +
	"Composing filters: " + fqlFilterHintSuffix + " When a tool's filter parameter names " +
	"a falcon:// guide resource, read it before composing a filter: it lists the fields " +
	"and operators that endpoint actually accepts, and an unsupported field returns an " +
	"empty result rather than an error, which is indistinguishable from a genuine " +
	"no-match.\n\n" +
	"Changing state: readOnlyHint=false marks a tool that changes tenant state, and " +
	"destructiveHint=true marks one whose effect cannot be undone. Confirm the user's " +
	"intent before calling either."

// dynamicInstructions is appended to baseInstructions when the server runs in
// dynamic mode, describing the search/execute loop that reaches an unregistered
// tool.
const dynamicInstructions = "This server is running in dynamic mode: the " +
	"Falcon tools are not individually registered, and are reached through " +
	"three tools instead — falcon_search_tools and falcon_execute_tool for " +
	"discovery, plus the always-on falcon_list_enabled_tools inventory.\n\n" +
	"1. falcon_search_tools with a keyword query, or a module name, lists " +
	"candidate tools ordered by likely relevance. These entries carry each " +
	"tool's name, description, and read_only / destructive flags, but no " +
	"parameters. The order is a keyword match, not a judgement of intent, so " +
	"read the descriptions and flags and pick the tool that fits.\n" +
	"2. falcon_search_tools again with tool_names=[chosen name] returns the " +
	"full parameter schema for those tools, including filter syntax hints. " +
	"Name more than one to compare candidates.\n" +
	"3. falcon_execute_tool runs the tool with those parameters.\n\n" +
	"falcon_list_enabled_tools gives the full inventory of Falcon tools " +
	"available here, grouped by the module each belongs to. A capability " +
	"absent from that list is not available on this server, whether because " +
	"its module is off or a filter withholds it — report that rather than " +
	"searching repeatedly."

// serverInstructions returns the instructions string for the initialize
// response. Dynamic mode appends the search/execute loop guidance to the base
// instructions both modes share.
func serverInstructions(dynamic bool) string {
	if !dynamic {
		return baseInstructions
	}
	return baseInstructions + "\n\n" + dynamicInstructions
}

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
// registered modules (via the generated factory list) and registers them under
// the tool policy derived from cfg (--modules, --tools, --exclude-tools,
// --read-only). It returns ErrUnknownModule (wrapped) when --modules names a
// module that does not exist, or ErrUnknownToolName (wrapped) when an
// allow/deny-list entry names no registered tool. In dynamic mode it wires the
// catalog's in-process session; call Close to release it.
func New(cfg *config.Config, api *client.CrowdStrikeAPISpecification) (*Server, error) {
	s := mcp.NewServer(&mcp.Implementation{Name: "falcon-mcp", Title: serverTitle, Version: version.Version}, &mcp.ServerOptions{
		Instructions: serverInstructions(cfg.Dynamic),
		// KeepAlive pings idle sessions to detect dead peers and hold long-lived
		// http/sse connections open. Zero disables it (the SDK default), so stdio
		// and unconfigured deployments are unaffected.
		KeepAlive: cfg.KeepAlive,
	})

	// The process logger's level was already set by the CLI (preRunE) before we
	// are called; injecting it here keeps handlers free of the slog global.
	logger := slog.Default()
	allModules := registry.Build(registry.Deps{
		API:                    api,
		Concurrency:            cfg.DetailFetchConcurrency,
		Logger:                 logger,
		NgsiemPollInterval:     cfg.NgsiemPollInterval,
		NgsiemTimeout:          cfg.NgsiemTimeout,
		AgentworksPollInterval: cfg.AgentworksPollInterval,
		AgentworksTimeout:      cfg.AgentworksTimeout,
	}, moduleFactories())

	reported, err := selectModules(allModules, cfg.Modules)
	if err != nil {
		return nil, err
	}
	// Allow-list-only mode (--tools without --modules): no module is enabled
	// wholesale, so none are reported as enabled (only the named tools load).
	if len(cfg.Modules) == 0 && len(cfg.Tools) > 0 {
		reported = nil
	}

	// Probe uses cfg credentials for an OAuth token exchange so
	// falcon_check_connectivity does not disturb the shared gofalcon client's
	// cached token. Capture cfg by value into the closure.
	probeCfg := cfg
	check := func(ctx context.Context) bool {
		return falconapi.CheckConnectivity(ctx, probeCfg)
	}

	policy := newToolPolicy(cfg)
	cat, err := registerModules(registerParams{
		server:   s,
		all:      allModules,
		reported: reported,
		policy:   policy,
		check:    check,
		dynamic:  cfg.Dynamic,
	})
	if err != nil {
		return nil, err
	}
	slog.Info("modules enabled", "modules", moduleNames(reported), "dynamic", cfg.Dynamic, "tool_filters", policy.describe())

	return &Server{mcp: s, modules: reported, catalog: cat}, nil
}

// registerParams groups the inputs to registerModules.
type registerParams struct {
	server   *mcp.Server
	all      []base.Module
	reported []base.Module
	policy   toolPolicy
	check    ConnectivityChecker
	dynamic  bool
}

// registerModules registers the core tools and every module tool that survives
// the tool policy on the server.
//
// Always (both modes): falcon_list_enabled_tools.
// Normal mode: also falcon_check_connectivity and falcon_list_enabled_modules,
// plus each surviving module tool directly on the server; the returned catalog
// is nil.
// Dynamic mode: surviving module tools go on the catalog's internal server and
// only the meta-tools (search_tools, execute_tool) reach the served server; the
// returned catalog owns the in-process session and must be closed by the caller.
// A module's resources and prompts are registered only when at least one of its
// tools survived the policy.
//
// Every module is iterated through a per-module policyRegistrar so the recorded
// tool-name set is complete: this both lets an allow-listed tool from a module
// outside --modules still register, and lets allow/deny-list names be validated
// against the full module tool surface.
func registerModules(p registerParams) (*Catalog, error) {
	reg := newRegistration()
	core := &coreTools{enabled: p.reported, check: p.check, reg: reg, policy: p.policy}
	served := base.ServerRegistrar(p.server)
	core.registerAlwaysOn(served)

	var cat *Catalog
	next := func(base.Module) base.Registrar { return served }
	if p.dynamic {
		cat = NewCatalog()
		next = func(m base.Module) base.Registrar { return cat.ForModule(m.Name()) }
	} else {
		core.registerNormalOnly(served)
	}

	for _, m := range p.all {
		preg := &policyRegistrar{module: m.Name(), policy: p.policy, next: next(m), reg: reg}
		m.RegisterTools(preg)
		if len(reg.kept[m.Name()]) > 0 {
			m.RegisterResources(p.server)
			m.RegisterPrompts(p.server)
		}
	}

	if err := p.policy.validateToolNames(reg.seen); err != nil {
		return nil, err
	}

	if !p.dynamic {
		return nil, nil
	}
	// The policy and the full seen-name set let the meta-tools explain, in
	// search and execute results, why a named tool the client asked for is
	// absent — withheld by a filter versus never existed.
	cat.policy = p.policy
	cat.seen = reg.seen
	// Connect the in-process session before serving so falcon_execute_tool can
	// dispatch. context.Background is right here: the session lives for the
	// server's lifetime, not a single request, and is closed via Server.Close.
	if err := cat.Connect(context.Background()); err != nil {
		return nil, err
	}
	NewMetaModule(cat, p.reported).RegisterTools(served)
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
