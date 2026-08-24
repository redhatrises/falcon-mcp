package mcpserver

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/crowdstrike/falcon-mcp/internal/config"
	"github.com/crowdstrike/falcon-mcp/internal/modules/base"
)

// ErrUnknownToolName classifies an allow/deny-list entry that names no
// registered module tool. Callers can branch with errors.Is.
var ErrUnknownToolName = errors.New("mcpserver: unknown tool name")

// toolPolicy decides, per tool, whether it is served. It combines the read-only
// switch, an allow-list and deny-list of "falcon_"-prefixed tool names, and the
// module gate (which modules are enabled). Precedence: a tool must first be in
// scope (its module enabled or its name allow-listed), then it survives unless
// it is deny-listed or, under read-only, mutating. Read-only therefore
// overrides the allow-list: an allow-listed mutating tool is still dropped.
type toolPolicy struct {
	readOnly          bool
	allowed           map[string]struct{}
	excluded          map[string]struct{}
	enabledModules    map[string]struct{}
	allModulesEnabled bool
}

// newToolPolicy derives a toolPolicy from cfg. The module gate is: the named
// modules when Modules is set; the empty set when only Tools is set (so nothing
// loads by module and only allow-listed tools survive); all modules when
// neither is set.
func newToolPolicy(cfg *config.Config) toolPolicy {
	p := toolPolicy{
		readOnly: cfg.ReadOnly,
		allowed:  toSet(cfg.Tools),
		excluded: toSet(cfg.ExcludeTools),
	}
	switch {
	case len(cfg.Modules) > 0:
		p.enabledModules = toSet(cfg.Modules)
	case len(cfg.Tools) > 0:
		p.enabledModules = map[string]struct{}{}
	default:
		p.allModulesEnabled = true
	}
	return p
}

// moduleEnabled reports whether the named module's tools are in scope by the
// module gate.
func (p toolPolicy) moduleEnabled(module string) bool {
	if p.allModulesEnabled {
		return true
	}
	_, ok := p.enabledModules[module]
	return ok
}

// keeps reports whether the tool is served. name is the "falcon_"-prefixed tool
// name; readOnlyHint is the tool's own annotation (true when it declares no side
// effects).
func (p toolPolicy) keeps(name, module string, readOnlyHint bool) bool {
	_, allow := p.allowed[name]
	if !allow && !p.moduleEnabled(module) {
		return false
	}
	if _, deny := p.excluded[name]; deny {
		return false
	}
	if p.readOnly && !readOnlyHint {
		return false
	}
	return true
}

// active reports whether any deliberate filter is in effect (read-only, or a
// non-empty allow/deny list). The module gate alone is not counted as a filter.
func (p toolPolicy) active() bool {
	return p.readOnly || len(p.allowed) > 0 || len(p.excluded) > 0
}

// describe summarizes the active filters for the falcon_list_enabled_tools
// envelope and the startup log. It returns "none" when no deliberate filter
// applies.
func (p toolPolicy) describe() string {
	var parts []string
	if p.readOnly {
		parts = append(parts, "read-only")
	}
	if n := len(p.allowed); n > 0 {
		parts = append(parts, fmt.Sprintf("allow-list (%d named)", n))
	}
	if n := len(p.excluded); n > 0 {
		parts = append(parts, fmt.Sprintf("deny-list (%d named)", n))
	}
	if len(parts) == 0 {
		return "none"
	}
	return strings.Join(parts, ", ")
}

// validateToolNames reports the allow/deny-list names absent from seen. seen
// maps each examined tool name to its module; only the key set is consulted
// here. Names must be "falcon_"-prefixed and match a registered module tool
// exactly. The error lists the offending names sorted, wrapping
// ErrUnknownToolName.
func (p toolPolicy) validateToolNames(seen map[string]string) error {
	unknown := map[string]struct{}{}
	for _, set := range []map[string]struct{}{p.allowed, p.excluded} {
		for name := range set {
			if _, ok := seen[name]; !ok {
				unknown[name] = struct{}{}
			}
		}
	}
	if len(unknown) == 0 {
		return nil
	}
	names := make([]string, 0, len(unknown))
	for n := range unknown {
		names = append(names, n)
	}
	sort.Strings(names)
	return fmt.Errorf("%w: %v (names must be falcon_-prefixed, e.g. falcon_search_hosts)", ErrUnknownToolName, names)
}

// registration accumulates the module tools that survived the policy, keyed by
// module (kept), and every module tool name the policy examined mapped to its
// owning module (seen). kept backs falcon_list_enabled_tools; seen backs
// allow/deny-list validation and lets dynamic mode attribute a withheld tool to
// its module gate. Both hold "falcon_"-prefixed names.
type registration struct {
	kept map[string][]string
	seen map[string]string
}

// newRegistration returns an empty registration.
func newRegistration() *registration {
	return &registration{kept: map[string][]string{}, seen: map[string]string{}}
}

// policyRegistrar wraps a base.Registrar, admitting only the tools the policy
// keeps and recording the outcome in reg. Kept tools are forwarded to next (the
// served server in normal mode, or the catalog's per-module sink in dynamic
// mode); every examined tool is recorded in reg.seen so allow/deny-list names
// can be validated against the full module tool surface.
type policyRegistrar struct {
	module string
	policy toolPolicy
	next   base.Registrar
	reg    *registration
}

// Add records the tool in seen, then forwards it to next only when the policy
// keeps it, recording kept module tools for falcon_list_enabled_tools.
func (r *policyRegistrar) Add(e base.ToolEntry) {
	name := e.Tool.Name
	r.reg.seen[name] = r.module

	ann := e.Tool.Annotations
	readOnlyHint := ann == nil || ann.ReadOnlyHint
	if !r.policy.keeps(name, r.module, readOnlyHint) {
		return
	}
	r.next.Add(e)
	r.reg.kept[r.module] = append(r.reg.kept[r.module], name)
}

// toSet returns names as a set for O(1) membership tests. A nil or empty slice
// yields an empty (non-nil) set.
func toSet(names []string) map[string]struct{} {
	s := make(map[string]struct{}, len(names))
	for _, n := range names {
		s[n] = struct{}{}
	}
	return s
}
