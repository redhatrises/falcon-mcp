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
	"strings"

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

// matchSet splits the catalog entries matching query — optionally restricted to a
// single module — into a full-coverage block and a lower-ranked partial block,
// mirroring upstream's two-block model. An empty query returns every candidate as
// full. Naming a tool exactly returns only that tool. Generic stopwords are dropped
// before the every-token conjunction so an incidental word cannot veto the right
// tool; when the full-coverage block is too thin to answer with, entries carrying at
// least half the gate tokens — or any one of them in their own name — join it as the
// partial block, and a still-thin result drops to any single gate token. A query
// whose conjunction already works keeps its narrow set and pays nothing for the
// wider one.
func (c *Catalog) matchSet(query, module string) (full, partial []catalogEntry) {
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

	if query == "" {
		out := make([]catalogEntry, len(candidates))
		copy(out, candidates)
		return out, nil
	}

	tokens := wordsList(query)
	queryKey := normalizeIdentifier(query)

	// Naming a tool is a request for that tool, not a keyword search, so every other
	// entry sharing a token is noise. Membership, not substring, so a short query is
	// not absorbed into an unrelated collapsed name; this mirrors score()'s exact-name
	// short-circuit and reaches the glued "searchhosts" form that tokenizing misses.
	if queryKey != "" {
		var exact []catalogEntry
		for _, e := range candidates {
			if setHas(e.nameKey, queryKey) {
				exact = append(exact, e)
			}
		}
		if len(exact) > 0 {
			return exact, nil
		}
	}

	if len(tokens) == 0 {
		// Punctuation only: nothing to match on, and an empty gate would otherwise
		// make the conjunction vacuously true for every entry.
		return nil, nil
	}

	// Drop generic words before the conjunction so they cannot veto; ranking still
	// sees every token. When every token is generic, fall back to the raw words but
	// report them as partial by construction: these tools carry the words
	// incidentally, which is the whole reason the words do not gate.
	gate := make([]string, 0, len(tokens))
	for _, t := range tokens {
		if !setHas(stopwords, t) {
			gate = append(gate, t)
		}
	}
	if len(gate) == 0 {
		for _, e := range candidates {
			if containsAll(e.corpus, tokens) {
				partial = append(partial, e)
			}
		}
		return nil, partial
	}

	// At least half the gate tokens, rounding up: enough to demote a near miss
	// rather than drop it, without admitting every tool that shares one word.
	threshold := (len(gate) + 1) / 2
	for _, e := range candidates {
		hits := 0
		for _, t := range gate {
			if strings.Contains(e.corpus, t) {
				hits++
			}
		}
		switch {
		case hits == len(gate):
			full = append(full, e)
		case hits >= threshold || e.namesAny(gate):
			partial = append(partial, e)
		}
	}

	if len(full) >= tierRescueBelow {
		// A full-coverage block this size is already an answer, so a precise query
		// pays nothing for the wider set.
		return full, nil
	}
	if len(full)+len(partial) >= tierRescueBelow {
		return full, partial
	}

	// Still too thin. Drop to any single gate token so a match the threshold excluded
	// is demoted rather than lost — otherwise a near miss by one tool would suppress
	// the rescue for all of them. Generic tokens stay out even here: the shortest of
	// them are substrings of every corpus.
	covered := make(map[string]struct{}, len(full))
	for _, e := range full {
		covered[e.tool.Name] = struct{}{}
	}
	var rescue []catalogEntry
	for _, e := range candidates {
		if _, ok := covered[e.tool.Name]; ok {
			continue
		}
		if containsAny(e.corpus, gate) {
			rescue = append(rescue, e)
		}
	}
	return full, rescue
}

// matches returns the matching catalog entries ranked by relevance to query, and the
// count of full-coverage matches (entries covering every gate token, which sort
// first and which the search hint reports). An empty query returns every candidate
// ordered by tool name; otherwise entries are ordered by the ranking score, with the
// full-coverage block always above the partial one.
func (c *Catalog) matches(query, module string) ([]catalogEntry, int) {
	full, partial := c.matchSet(query, module)
	tokens := wordsList(query)
	queryKey := normalizeIdentifier(query)

	// An empty query cannot rank by relevance — every entry scores zero — so it gets
	// its own by-name ordering, matching upstream's dedicated empty-query branch.
	// Without this the general comparator would order a no-query listing by
	// name-word-count then read-only-first, which then changes which tools survive
	// the result limit.
	if len(tokens) == 0 && queryKey == "" {
		out := make([]catalogEntry, len(full))
		copy(out, full)
		sort.SliceStable(out, func(i, j int) bool {
			return out[i].tool.Name < out[j].tool.Name
		})
		return out, len(out)
	}

	ranked := make([]rankedEntry, 0, len(full)+len(partial))
	for _, e := range full {
		matched, strength := e.score(tokens, queryKey)
		ranked = append(ranked, rankedEntry{entry: e, block: 0, matched: matched, strength: strength})
	}
	for _, e := range partial {
		matched, strength := e.score(tokens, queryKey)
		ranked = append(ranked, rankedEntry{entry: e, block: 1, matched: matched, strength: strength})
	}
	sort.SliceStable(ranked, func(i, j int) bool {
		return ranked[i].less(ranked[j])
	})

	out := make([]catalogEntry, len(ranked))
	for i, r := range ranked {
		out[i] = r.entry
	}
	return out, len(full)
}

// rankedEntry pairs a catalog entry with its coverage block and its score against
// the current query, for sorting.
type rankedEntry struct {
	entry    catalogEntry
	block    int // 0 = full coverage, 1 = partial
	matched  int
	strength int
}

// less reports whether re should sort before o. The order is: full-coverage block
// before partial, then more matched tokens, then higher strength, then a shorter
// name, then read-only before mutating, then tool name ascending — a total order, so
// the sort is deterministic.
func (re rankedEntry) less(o rankedEntry) bool {
	if re.block != o.block {
		return re.block < o.block
	}
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
