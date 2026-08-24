package mcpserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/crowdstrike/falcon-mcp/internal/modules/base"
)

// defaultSearchLimit and the clamp bounds mirror upstream falcon-mcp.
const (
	defaultSearchLimit = 50
	minSearchLimit     = 1
	maxSearchLimit     = 500
)

// ErrUnknownTool classifies a falcon_execute_tool call naming a tool that is
// not in the catalog. It is surfaced as a tool-error result (not a protocol
// error), matching the server's data-not-protocol-error contract.
var ErrUnknownTool = errors.New("dynamic: unknown tool")

// MetaModule is the base.Module that exposes the dynamic-mode discovery/
// execution meta-tools (falcon_search_tools, falcon_execute_tool) over a
// pre-built Catalog. The always-on falcon_list_enabled_tools is registered
// separately by registerModules so it is present in both modes. MetaModule
// registers no resources of its own.
type MetaModule struct {
	catalog *Catalog
	modules []base.Module // retained for catalog context; not listed here
}

// NewMetaModule returns a MetaModule over cat. modules is the set of enabled
// modules that contributed tools to the catalog (kept for future use).
func NewMetaModule(cat *Catalog, modules []base.Module) *MetaModule {
	return &MetaModule{catalog: cat, modules: modules}
}

// Name reports the module name.
func (m *MetaModule) Name() string { return "dynamic" }

// Description reports a one-line summary of the module.
func (m *MetaModule) Description() string {
	return "Meta-tools to discover and execute Falcon tools on demand (dynamic mode)"
}

// RegisterResources is a no-op: the meta-module owns no resources. Real modules
// still register their FQL guides separately in dynamic mode.
func (m *MetaModule) RegisterResources(_ *mcp.Server) {}

// RegisterPrompts is a no-op: the meta-module owns no prompts.
func (m *MetaModule) RegisterPrompts(_ *mcp.Server) {}

// searchToolsSchema is the input schema for falcon_search_tools. It is inferred
// from SearchToolsInput's struct tags, then a mutate func adds the limit
// bounds/default the tag syntax cannot express, reusing the clamp constants.
var searchToolsSchema = base.SchemaFor[SearchToolsInput](func(s *jsonschema.Schema) {
	s.Properties["limit"].Minimum = jsonschema.Ptr(float64(minSearchLimit))
	s.Properties["limit"].Maximum = jsonschema.Ptr(float64(maxSearchLimit))
	s.Properties["limit"].Default = json.RawMessage(strconv.Itoa(defaultSearchLimit))
})

// RegisterTools registers the dynamic-mode discovery/execution meta-tools into
// r (the live server). They flow through base.AddTool so they get the "falcon_"
// prefix. search_tools keeps the default read-only annotations; execute_tool is
// a general dispatcher that can invoke mutating tools, so it must not advertise
// readOnlyHint (see docs/usage/dynamic-mode.md). The always-on
// falcon_list_enabled_tools is registered by coreTools.registerAlwaysOn, not
// here.
func (m *MetaModule) RegisterTools(r base.Registrar) {
	base.AddTool(r, &mcp.Tool{
		Name:        "search_tools",
		Description: "Discover Falcon tools in two steps. First search by keyword query or module to get candidate tools (name, description, read_only/destructive flags, but no parameters), ordered by likely relevance. Then call again with tool_names=[chosen name] to get the full parameter schema, before running one with falcon_execute_tool.",
		InputSchema: searchToolsSchema,
	}, m.searchTools)

	base.AddTool(r, &mcp.Tool{
		Name:        "execute_tool",
		Description: "Execute a Falcon tool by name with the given parameters. Use falcon_search_tools to discover tool names and parameters first.",
		// Not read-only: this meta-tool can dispatch to mutating/destructive
		// tools. Agents must use falcon_search_tools' read_only/destructive
		// fields to assess risk per target tool.
		Annotations: base.MutatingAnnotations(false),
	}, m.executeTool)
}

// SearchToolsInput is the input for falcon_search_tools.
type SearchToolsInput struct {
	Query     string   `json:"query,omitempty" jsonschema:"Keywords to search across tool names, descriptions, module names, and parameter names."`
	Module    string   `json:"module,omitempty" jsonschema:"Restrict results to one module (e.g. 'hosts', 'detections'). Case and separators are ignored, so 'Host_Groups' and 'hostgroups' both work. Call falcon_list_enabled_tools for the module names this server accepts. Pass it with no query to browse every tool that module contributes here, which may be a subset of the module's full surface."`
	Limit     int      `json:"limit,omitempty" jsonschema:"Maximum number of results to return (default: 50, max: 500). Ignored when tool_names is given."`
	ToolNames []string `json:"tool_names,omitempty" jsonschema:"Exact tool names to return full parameter schemas for. Use this after a keyword search has told you which tool you want; pass two or more names to compare candidates in one call. Overrides query, module, and limit."`
}

// ToolSummary is one falcon_search_tools result. Field order mirrors upstream's
// entry shape (name, module, description, flags, then parameters). Parameters is
// a pointer so a lean discovery result omits the key entirely — its absence is
// the signal that a second, tool_names call is needed before executing — while a
// named-tool result can still carry an explicit empty list.
type ToolSummary struct {
	Name        string          `json:"name"`
	Module      string          `json:"module"`
	Description string          `json:"description"`
	ReadOnly    bool            `json:"read_only"`
	Destructive bool            `json:"destructive"`
	Parameters  *[]paramSummary `json:"parameters,omitempty"`
}

// SearchToolsResult is the falcon_search_tools output envelope. Total is the
// full match count ignoring the limit; Truncated reports whether the limit
// capped the results; Hint carries relevance and next-step guidance.
type SearchToolsResult struct {
	Results   []ToolSummary `json:"results"`
	Total     int           `json:"total"`
	Truncated bool          `json:"truncated"`
	Hint      string        `json:"hint,omitempty"`
}

// searchTools implements falcon_search_tools' two-step discovery. With tool_names
// set it returns the full parameter schema for each named tool (a schema lookup).
// Otherwise it ranks the catalog against the query — optionally scoped to a
// module — and returns up to Limit lean entries (no parameters), with a hint
// steering the caller to name a tool for its schema before executing.
func (m *MetaModule) searchTools(_ context.Context, _ *mcp.CallToolRequest, in SearchToolsInput) (*mcp.CallToolResult, SearchToolsResult, error) {
	if len(in.ToolNames) > 0 {
		return nil, m.describeNamed(in.ToolNames), nil
	}

	limit := clampLimit(in.Limit)
	ranked, relaxed := m.catalog.matches(in.Query, in.Module)
	total := len(ranked)

	shown := ranked
	if len(shown) > limit {
		shown = shown[:limit]
	}
	truncated := total > len(shown)

	if len(shown) == 0 {
		return nil, SearchToolsResult{
			Results:   []ToolSummary{},
			Total:     0,
			Truncated: false,
			Hint:      m.emptyHint(in.Query, in.Module),
		}, nil
	}

	results := make([]ToolSummary, len(shown))
	for i, ce := range shown {
		results[i] = leanSummary(ce)
	}
	return nil, SearchToolsResult{
		Results:   results,
		Total:     total,
		Truncated: truncated,
		Hint:      searchHint(searchHintInput{shown: len(results), total: total, truncated: truncated, relaxed: relaxed}),
	}, nil
}
func clampLimit(limit int) int {
	switch {
	case limit == 0:
		return defaultSearchLimit
	case limit < minSearchLimit:
		return minSearchLimit
	case limit > maxSearchLimit:
		return maxSearchLimit
	default:
		return limit
	}
}

// emptyHint explains a search that matched nothing, distinguishing a server with
// no tools at all, one where a filter withheld tools, and one where the
// capability was simply never enabled.
func (m *MetaModule) emptyHint(query, module string) string {
	var criteria []string
	if query != "" {
		criteria = append(criteria, fmt.Sprintf("matching '%s'", query))
	}
	if module != "" {
		criteria = append(criteria, fmt.Sprintf("in module '%s'", module))
	}
	subject := "No tool is"
	if len(criteria) > 0 {
		subject = "No tool " + strings.Join(criteria, " ") + " is"
	}

	switch {
	case !m.catalog.entriesRemain():
		return fmt.Sprintf(
			"This server has no Falcon tools available: its configuration (%s) "+
				"withholds all of them. Tell the user the server is configured with no "+
				"tools available rather than searching again.",
			m.catalog.describePolicy())
	case m.catalog.hasWithheld():
		return fmt.Sprintf(
			"%s available on this server, which is running with a tool filter (%s). "+
				"Call falcon_list_enabled_tools for what is available. The capability may "+
				"exist but be withheld by configuration — tell the user that rather than "+
				"trying more searches.",
			subject, m.catalog.describePolicy())
	default:
		return fmt.Sprintf(
			"%s available on this server. Call falcon_list_enabled_tools for the full "+
				"inventory. If the capability you need is genuinely absent, it was not "+
				"enabled on this server — tell the user rather than trying more searches.",
			subject)
	}
}

// searchHintInput carries the result counts and match-mode flags that shape the
// guidance searchHint appends to a non-empty tool search.
type searchHintInput struct {
	shown, total       int
	truncated, relaxed bool
}

// searchHint builds the guidance appended to a non-empty search: a relaxed-match
// note when the fallback ran, a truncation note when the limit capped results,
// and always, last, the reminder that lean results carry no parameters.
func searchHint(in searchHintInput) string {
	var hints []string
	if in.relaxed {
		hints = append(hints,
			"No tool matched every word, so these match at least one of them, ordered "+
				"by likely relevance. Read the descriptions and pick the one that fits "+
				"rather than assuming the capability is missing.")
	}
	if in.truncated {
		hints = append(hints, fmt.Sprintf(
			"Showing %d of %d. Call falcon_list_enabled_tools for all names, or narrow "+
				"with query.", in.shown, in.total))
	}
	hints = append(hints,
		"These results carry no parameters. Pick the tool you want, then call "+
			"falcon_search_tools again with tool_names=[its name] to get the parameters "+
			"before calling falcon_execute_tool.")
	return strings.Join(hints, " ")
}

// describeNamed returns full schemas for the named tools, reporting any this
// server lacks. Names are deduped preserving order; a repeated name yields one
// entry. Total counts what came back, since no query ran.
func (m *MetaModule) describeNamed(names []string) SearchToolsResult {
	results := make([]ToolSummary, 0, len(names))
	found := map[string]struct{}{}
	var missing []string
	seenReq := map[string]struct{}{}
	for _, name := range names {
		if _, dup := seenReq[name]; dup {
			continue
		}
		seenReq[name] = struct{}{}

		ce, ok := m.catalog.lookup(name)
		if !ok {
			missing = append(missing, name)
			continue
		}
		if _, dup := found[ce.tool.Name]; dup {
			continue
		}
		found[ce.tool.Name] = struct{}{}
		results = append(results, fullSummary(ce))
	}

	res := SearchToolsResult{Results: results, Total: len(results), Truncated: false}
	if len(missing) > 0 {
		res.Hint = m.missingNamesHint(missing)
	}
	return res
}

// missingNamesHint distinguishes names a filter withheld from names that never
// existed, wording each differently, since a single call can name both.
func (m *MetaModule) missingNamesHint(missing []string) string {
	var withheld []string
	var unknown []string
	for _, name := range missing {
		if rule, ok := m.catalog.withholdingRule(name); ok {
			withheld = append(withheld, fmt.Sprintf("%s (%s)", name, rule))
		} else {
			unknown = append(unknown, name)
		}
	}

	var hints []string
	if len(withheld) > 0 {
		hints = append(hints, fmt.Sprintf(
			"Withheld by this server's configuration: %s. The capability is not missing "+
				"— tell the user it is disabled by configuration rather than searching "+
				"again.", strings.Join(withheld, ", ")))
	}
	if len(unknown) > 0 {
		hints = append(hints, fmt.Sprintf(
			"Not available on this server: %s. Search by keyword for the right name, or "+
				"call falcon_list_enabled_tools for the full inventory.",
			strings.Join(unknown, ", ")))
	}
	return strings.Join(hints, " ")
}

// leanSummary builds a discovery result without the parameter schema, deriving
// the read-only and destructive flags from the tool's annotations.
func leanSummary(ce catalogEntry) ToolSummary {
	return baseSummary(ce)
}

// fullSummary builds a named-tool result including the parameter schema with
// filter-syntax hints applied. A tool with no parameters carries an explicit
// empty list, so the key is present (distinct from a lean entry's omission).
func fullSummary(ce catalogEntry) ToolSummary {
	s := baseSummary(ce)
	params := enrichFilterHints(ce.tool.Name, ce.params)
	if params == nil {
		params = []paramSummary{}
	}
	s.Parameters = &params
	return s
}

// baseSummary fills the fields every result carries, with or without parameters.
func baseSummary(ce catalogEntry) ToolSummary {
	ann := ce.tool.Annotations
	readOnly := ann == nil || ann.ReadOnlyHint
	destructive := ann != nil && ann.DestructiveHint != nil && *ann.DestructiveHint
	return ToolSummary{
		Name:        ce.tool.Name,
		Module:      ce.module,
		Description: ce.tool.Description,
		ReadOnly:    readOnly,
		Destructive: destructive,
	}
}

// enrichFilterHints returns params with the tool's curated FQL field hint (when
// one exists) and the universal FQL syntax suffix appended to the "filter"
// parameter's description, mirroring upstream falcon-mcp's dynamic.py. Tools
// without a filter parameter are returned unchanged. The input slice is copied
// before mutation so the shared catalog entry stays pristine across repeated
// searches (otherwise the hint would compound on every call).
func enrichFilterHints(toolName string, params []paramSummary) []paramSummary {
	idx := -1
	for i, p := range params {
		if p.Name == "filter" {
			idx = i
			break
		}
	}
	if idx == -1 {
		return params
	}

	out := make([]paramSummary, len(params))
	copy(out, params)

	desc := out[idx].Description
	if hint := filterHints[toolName]; hint != "" {
		desc = appendHint(desc, hint)
	}
	desc = appendHint(desc, fqlFilterHintSuffix)
	out[idx].Description = desc
	return out
}

// appendHint joins desc and hint with the same separator upstream falcon-mcp
// uses: a single space when desc already ends with a period, otherwise ". ".
func appendHint(desc, hint string) string {
	sep := ". "
	if strings.HasSuffix(desc, ".") {
		sep = " "
	}
	return desc + sep + hint
}

// ExecuteToolInput is the input for falcon_execute_tool. Parameters is a JSON
// object so its inferred schema is "object" (a json.RawMessage would infer as
// a byte array and reject object arguments at the meta-tool's own validation).
type ExecuteToolInput struct {
	ToolName   string         `json:"tool_name" jsonschema:"exact tool name to execute (from falcon_search_tools results)"`
	Parameters map[string]any `json:"parameters,omitempty" jsonschema:"tool parameters as a JSON object"`
}

// executeTool implements falcon_execute_tool. It looks up the named tool in the
// catalog and dispatches to it over the catalog's in-process client session, so
// the internal server (and the SDK) performs argument validation and result
// packing. An unknown tool yields a tool-error result carrying a discovery
// hint; parameter validation failures surface as the tool's own error result,
// enriched with the expected parameters.
func (m *MetaModule) executeTool(ctx context.Context, _ *mcp.CallToolRequest, in ExecuteToolInput) (*mcp.CallToolResult, any, error) {
	ce, ok := m.catalog.lookup(in.ToolName)
	if !ok {
		var res mcp.CallToolResult
		// A tool the policy withheld is absent from the catalog exactly like one
		// that never existed. Name which it is, or the model reports an operator's
		// configuration choice to the user as a missing product capability.
		if rule, withheld := m.catalog.withholdingRule(in.ToolName); withheld {
			remainder := "This server currently has no Falcon tools available at all, " +
				"so do not look for an alternative."
			if m.catalog.entriesRemain() {
				remainder = "Do not try to achieve the same effect through a different " +
					"tool, though other tools remain available for other work."
			}
			res.SetError(fmt.Errorf(
				"%q exists on this server but its configuration withholds it (%s). The "+
					"capability is not missing — tell the user it is disabled by this "+
					"server's configuration. %s", in.ToolName, rule, remainder))
			return &res, nil, nil
		}
		res.SetError(fmt.Errorf("%w: %q; call falcon_search_tools to discover available tools", ErrUnknownTool, in.ToolName))
		return &res, nil, nil
	}

	// Parameters is an object (map) already; the SDK marshals it over the
	// in-process transport. A nil map is sent as an empty object.
	args := any(in.Parameters)
	if in.Parameters == nil {
		args = map[string]any{}
	}

	res, err := m.catalog.session.CallTool(ctx, &mcp.CallToolParams{
		Name:      ce.tool.Name,
		Arguments: args,
	})
	if err != nil {
		return nil, nil, err
	}
	if res != nil && res.IsError {
		enrichValidationError(res, ce)
	}
	// Return the underlying tool's result verbatim: nil Out leaves res's own
	// StructuredContent/Content (set by the internal server) untouched.
	return res, nil, nil
}

// enrichValidationError appends the tool's expected parameters to an error
// result's text, matching upstream's parameter-validation guidance.
func enrichValidationError(res *mcp.CallToolResult, ce catalogEntry) {
	if len(ce.params) == 0 {
		return
	}
	names := make([]string, len(ce.params))
	for i, p := range ce.params {
		names[i] = p.Name
	}
	hint := fmt.Sprintf(" (expected parameters: %s)", strings.Join(names, ", "))
	if len(res.Content) > 0 {
		if tc, ok := res.Content[0].(*mcp.TextContent); ok {
			tc.Text += hint
		}
	}
}

// ModuleInfo describes one enabled module in a falcon_list_enabled_modules
// result.
type ModuleInfo struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

// EnabledModulesResult is the falcon_list_enabled_modules output envelope.
type EnabledModulesResult struct {
	Modules []ModuleInfo `json:"modules"`
	Total   int          `json:"total"`
}
