package mcpserver

// Dynamic mode: instead of registering every module's tools on the served MCP
// server (each carrying a full schema that costs the client context-window
// tokens), it registers three fixed meta-tools — falcon_search_tools,
// falcon_execute_tool, and falcon_list_enabled_tools — backed by an in-process
// Catalog of the real tools. Clients discover tools on demand via search and
// invoke them by name via execute, paying each tool's schema cost only when they
// use it.
//
// The real tools are registered on a separate internal *mcp.Server that is
// never served to the client. falcon_execute_tool dispatches to them over an
// in-process client session wired to that internal server with
// mcp.NewInMemoryTransports, so the SDK owns all argument validation and result
// packing — there is no hand-maintained copy of the SDK's tool erasure to drift
// on an SDK upgrade.
//
// This is a faithful port of the upstream Python crowdstrike/falcon-mcp dynamic
// mode. It does NOT use the MCP notifications/tools/list_changed mechanism: the
// three meta-tools are the served server's entire tool surface for the process
// lifetime.

import (
	"context"
	"fmt"
	"sort"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/crowdstrike/falcon-mcp/internal/modules/base"
)

// Catalog holds the real tools captured in dynamic mode. Tools are registered
// on an internal *mcp.Server at startup; after Connect wires an in-process
// client session to that server, the catalog is read-only and its meta-tool
// handlers only read it, so it needs no mutex.
type Catalog struct {
	internal *mcp.Server
	entries  []catalogEntry
	byName   map[string]catalogEntry // "falcon_"-prefixed name -> entry
	modules  []string                // contributing module names, in registration order

	// policy is the tool filter that shaped which entries were registered. It
	// is read to explain, in search and execute results, why a named tool the
	// client asked for is absent. The zero value is inert (no filter).
	policy toolPolicy
	// seen maps every module tool name (prefixed) across all modules to its
	// owning module, before the policy dropped any. It distinguishes a tool the
	// policy withheld (in seen, not in byName) from one that never existed, and
	// the module value lets withholdingRule attribute a drop to the module gate
	// rather than the active filter.
	seen map[string]string

	// session is the in-process client connected to internal, established by
	// Connect and used by falcon_execute_tool to dispatch by name. It is nil
	// until Connect succeeds.
	session *mcp.ClientSession
	ss      *mcp.ServerSession
}

// catalogEntry is one real tool captured for dynamic dispatch: its SDK
// descriptor (already "falcon_"-prefixed), owning module, the lowercased search
// corpus, and the parameter summary derived from its inferred input schema. The
// remaining fields are precomputed by deriveRanking for search scoring.
type catalogEntry struct {
	tool   *mcp.Tool
	module string
	corpus string
	params []paramSummary

	unprefixedName string              // tool name with the "falcon_" prefix removed
	nameWords      map[string]struct{} // alphanumeric words of the unprefixed name
	nameKey        map[string]struct{} // normalized exact-name keys (prefixed and bare)
	moduleWords    map[string]struct{} // alphanumeric words of the module name
	moduleKey      string              // normalized module identifier
}

// NewCatalog returns an empty Catalog with a fresh internal server for the real
// tools.
func NewCatalog() *Catalog {
	return &Catalog{
		internal: mcp.NewServer(&mcp.Implementation{Name: "falcon-mcp-internal", Version: "internal"}, nil),
		byName:   map[string]catalogEntry{},
	}
}

// ForModule returns a base.Registrar that registers each tool the named module
// registers onto the internal server (via the SDK's mcp.AddTool) and records a
// catalog entry (stamping the module name). The recorded entry carries the
// tool's inferred input schema, which the search corpus and parameter summaries
// read.
func (c *Catalog) ForModule(name string) base.Registrar {
	c.modules = append(c.modules, name)
	return &catalogRegistrar{cat: c, module: name}
}

// Connect wires an in-process client session to the internal server so
// falcon_execute_tool can dispatch tools by name. It must be called once, after
// all modules have registered and before the meta-tools are invoked. The
// session lives until Close; ctx governs only the connection handshake.
func (c *Catalog) Connect(ctx context.Context) error {
	clientT, serverT := mcp.NewInMemoryTransports()
	ss, err := c.internal.Connect(ctx, serverT, nil)
	if err != nil {
		return fmt.Errorf("dynamic: connect internal server: %w", err)
	}
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "falcon-mcp-dynamic", Version: "internal"}, nil).Connect(ctx, clientT, nil)
	if err != nil {
		_ = ss.Close()
		return fmt.Errorf("dynamic: connect internal client: %w", err)
	}
	c.ss = ss
	c.session = cs
	return nil
}

// Close tears down the in-process session established by Connect. It is safe to
// call on a catalog that was never connected.
func (c *Catalog) Close() error {
	if c.session != nil {
		_ = c.session.Close()
	}
	if c.ss != nil {
		_ = c.ss.Wait()
	}
	return nil
}

// Modules returns the contributing module names in registration order.
func (c *Catalog) Modules() []string {
	out := make([]string, len(c.modules))
	copy(out, c.modules)
	return out
}

// lookup returns the entry for name, accepting either the exact "falcon_"-
// prefixed name or the bare name.
func (c *Catalog) lookup(name string) (catalogEntry, bool) {
	if e, ok := c.byName[name]; ok {
		return e, true
	}
	e, ok := c.byName[toolNamePrefix+name]
	return e, ok
}

// catalogRegistrar is the per-module sink returned by ForModule. It implements
// base.Registrar.
type catalogRegistrar struct {
	cat    *Catalog
	module string
}

func (r *catalogRegistrar) Add(e base.ToolEntry) {
	e.Module = r.module
	// Register the real tool on the internal server; the SDK owns its erasure.
	e.Register(r.cat.internal)

	ce := catalogEntry{
		tool:   e.Tool,
		module: r.module,
		params: paramSummaries(e.InputSchema),
	}
	ce.corpus = searchCorpus(e.Tool, r.module, ce.params)
	ce.deriveRanking()

	r.cat.entries = append(r.cat.entries, ce)
	r.cat.byName[e.Tool.Name] = ce
}

// entriesRemain reports whether the catalog exposes any tool after policy
// filtering.
func (c *Catalog) entriesRemain() bool { return len(c.entries) > 0 }

// describePolicy returns the human-readable summary of the active tool filter,
// or "none".
func (c *Catalog) describePolicy() string { return c.policy.describe() }

// policyActive reports whether a tool filter (read-only, allow-list, or
// deny-list) is in effect.
func (c *Catalog) policyActive() bool { return c.policy.active() }

// hasWithheld reports whether the policy dropped at least one tool that would
// otherwise be in the catalog.
func (c *Catalog) hasWithheld() bool {
	return c.policyActive() && len(c.seen) > len(c.entries)
}

// withholdingRule reports whether name refers to a tool the active policy
// withheld — a tool that exists in some module but was filtered out. It returns
// a reason and true only when a filter is active, name is not in the catalog,
// and name was seen during registration. A tool whose module is not enabled is
// attributed to the module gate; otherwise the reason is the filter
// description. name is accepted with or without the "falcon_" prefix.
func (c *Catalog) withholdingRule(name string) (string, bool) {
	if !c.policyActive() {
		return "", false
	}
	if _, ok := c.byName[name]; ok {
		return "", false
	}
	if _, ok := c.byName[toolNamePrefix+name]; ok {
		return "", false
	}
	module, ok := c.seen[name]
	if !ok {
		if module, ok = c.seen[toolNamePrefix+name]; !ok {
			return "", false
		}
	}
	if !c.policy.moduleEnabled(module) {
		return "module not enabled", true
	}
	return c.policy.describe(), true
}

// matchSet returns the catalog entries that match query, optionally restricted
// to a single module, along with whether the match was relaxed. It mirrors
// upstream's two-tier logic: an empty query returns every candidate; otherwise
// it first tries a strict match (every query token appears in an entry's corpus,
// or the query names the tool exactly) and, only if that yields nothing, falls
// back to a relaxed match (any token appears). The bool is true when the relaxed
// tier produced the result.
func (c *Catalog) matchSet(query, module string) ([]catalogEntry, bool) {
	candidates := c.entries
	if module != "" {
		key := normalizeIdentifier(module)
		filtered := candidates[:0:0]
		for _, e := range candidates {
			if e.moduleKey == key {
				filtered = append(filtered, e)
			}
		}
		candidates = filtered
	}

	tokens := wordsList(query)
	if len(tokens) == 0 {
		out := make([]catalogEntry, len(candidates))
		copy(out, candidates)
		return out, false
	}
	queryKey := normalizeIdentifier(query)

	var strict []catalogEntry
	for _, e := range candidates {
		if containsAll(e.corpus, tokens) || setHas(e.nameKey, queryKey) {
			strict = append(strict, e)
		}
	}
	if len(strict) > 0 {
		return strict, false
	}

	var relaxed []catalogEntry
	for _, e := range candidates {
		if containsAny(e.corpus, tokens) || setHas(e.nameKey, queryKey) {
			relaxed = append(relaxed, e)
		}
	}
	return relaxed, true
}

// matches returns the matching catalog entries ranked by relevance to query,
// and whether the match was relaxed. An empty query returns every candidate
// ordered by tool name; otherwise entries are ordered by the ranking score.
func (c *Catalog) matches(query, module string) ([]catalogEntry, bool) {
	set, relaxed := c.matchSet(query, module)
	tokens := wordsList(query)
	queryKey := normalizeIdentifier(query)

	// An empty query cannot rank by relevance — every entry scores zero — so it
	// gets its own by-name ordering, matching upstream's dedicated empty-query
	// branch. Without this the general comparator would order a no-query listing
	// by name-word-count then read-only-first, which then changes which tools
	// survive the result limit.
	if len(tokens) == 0 && queryKey == "" {
		out := make([]catalogEntry, len(set))
		copy(out, set)
		sort.SliceStable(out, func(i, j int) bool {
			return out[i].tool.Name < out[j].tool.Name
		})
		return out, relaxed
	}

	ranked := make([]rankedEntry, len(set))
	for i, e := range set {
		matched, strength := e.score(tokens, queryKey)
		ranked[i] = rankedEntry{entry: e, matched: matched, strength: strength}
	}
	sort.SliceStable(ranked, func(i, j int) bool {
		return ranked[i].less(ranked[j])
	})

	out := make([]catalogEntry, len(ranked))
	for i, r := range ranked {
		out[i] = r.entry
	}
	return out, relaxed
}

// rankedEntry pairs a catalog entry with its score against the current query,
// for sorting.
type rankedEntry struct {
	entry    catalogEntry
	matched  int
	strength int
}

// less reports whether re should sort before o. The order is: more matched
// tokens first, then higher strength, then a shorter name, then read-only
// before mutating, then tool name ascending — a total order, so the sort is
// deterministic.
func (re rankedEntry) less(o rankedEntry) bool {
	if re.matched != o.matched {
		return re.matched > o.matched
	}
	if re.strength != o.strength {
		return re.strength > o.strength
	}
	if ln, lo := len(re.entry.nameWords), len(o.entry.nameWords); ln != lo {
		return ln < lo
	}
	if ri, oi := readOnly(re.entry), readOnly(o.entry); ri != oi {
		return ri // read-only (true) sorts before mutating (false)
	}
	return re.entry.tool.Name < o.entry.tool.Name
}

// readOnly reports whether the entry's tool is annotated read-only.
func readOnly(e catalogEntry) bool {
	return e.tool.Annotations != nil && e.tool.Annotations.ReadOnlyHint
}
