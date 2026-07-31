package mcpserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/crowdstrike/falcon-mcp/internal/modules/base"
)

// defaultSearchLimit and the clamp bounds mirror upstream falcon-mcp.
const (
	defaultSearchLimit = 20
	minSearchLimit     = 1
	maxSearchLimit     = 100
)

// ErrUnknownTool classifies a falcon_execute_tool call naming a tool that is
// not in the catalog. It is surfaced as a tool-error result (not a protocol
// error), matching the server's data-not-protocol-error contract.
var ErrUnknownTool = errors.New("dynamic: unknown tool")

// MetaModule is the base.Module that exposes the dynamic-mode discovery/
// execution meta-tools (falcon_search_tools, falcon_execute_tool) over a
// pre-built Catalog. falcon_list_enabled_modules is registered separately by
// registerModules so it is present in both modes. MetaModule registers no
// resources of its own.
type MetaModule struct {
	catalog *Catalog
}

// NewMetaModule returns a MetaModule over cat. The enabled modules that
// contributed tools are reachable through cat.Modules().
func NewMetaModule(cat *Catalog) *MetaModule {
	return &MetaModule{catalog: cat}
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
// readOnlyHint (see docs/usage/dynamic-mode.md). falcon_list_enabled_modules is
// registered by coreTools.registerAlwaysOn, not here.
func (m *MetaModule) RegisterTools(r base.Registrar) {
	base.AddTool(r, &mcp.Tool{
		Name: "search_tools",
		Description: "Discover available Falcon tools by keyword search. Keywords are " +
			"matched against tool names, descriptions, module names, and parameter " +
			"names; pass module to restrict results to one module. Each match reports " +
			"its parameters plus read_only and destructive flags. Consult this before " +
			"calling falcon_execute_tool to understand a tool's parameters and " +
			"mutation risk.",
		InputSchema: searchToolsSchema,
	}, m.searchTools)

	base.AddTool(r, &mcp.Tool{
		Name: "execute_tool",
		Description: "Execute a Falcon tool by name with the given parameters. " +
			"Use falcon_search_tools to discover tool names and parameters first, " +
			"and to check each tool's read_only and destructive flags — do not " +
			"execute destructive tools without confirming the user's intent. " +
			"Results are returned in full: use the target tool's own limit " +
			"parameter to control response volume.",
		// Not read-only: this meta-tool can dispatch to mutating/destructive
		// tools. Agents must use falcon_search_tools' read_only/destructive
		// fields to assess risk per target tool.
		Annotations: base.MutatingAnnotations(),
	}, m.executeTool)
}

// SearchToolsInput is the input for falcon_search_tools.
type SearchToolsInput struct {
	Query  string `json:"query,omitempty" jsonschema:"keywords to match across tool names, descriptions, module names, and parameter names"`
	Module string `json:"module,omitempty" jsonschema:"filter results to a specific module (e.g. 'hosts', 'detections')"`
	Limit  int    `json:"limit,omitempty" jsonschema:"maximum results to return"`
}

// ToolSummary is one falcon_search_tools result.
type ToolSummary struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	Module      string         `json:"module"`
	Parameters  []paramSummary `json:"parameters"`
	ReadOnly    bool           `json:"read_only"`
	Destructive bool           `json:"destructive"`
}

// SearchToolsResult is the falcon_search_tools output envelope. Hint is set only
// when Tools is empty, carrying recovery guidance; it is omitted otherwise so a
// successful search keeps the same shape minus the noise.
type SearchToolsResult struct {
	Tools []ToolSummary `json:"tools"`
	Total int           `json:"total"`
	Hint  string        `json:"hint,omitempty"`
}

// searchTools implements falcon_search_tools. It filters the catalog by exact
// module (when given), then keeps entries whose search corpus contains every
// lowercased query token (AND substring match), and returns the first Limit
// results — matching upstream falcon-mcp's algorithm.
func (m *MetaModule) searchTools(_ context.Context, _ *mcp.CallToolRequest, in SearchToolsInput) (*mcp.CallToolResult, SearchToolsResult, error) {
	limit := in.Limit
	switch {
	case limit == 0:
		limit = defaultSearchLimit
	case limit < minSearchLimit:
		limit = minSearchLimit
	case limit > maxSearchLimit:
		limit = maxSearchLimit
	}

	tokens := strings.Fields(strings.ToLower(in.Query))

	tools := make([]ToolSummary, 0, limit)
	for _, ce := range m.catalog.entries {
		if in.Module != "" && ce.module != in.Module {
			continue
		}
		if !matchesAll(ce.corpus, tokens) {
			continue
		}
		tools = append(tools, summarize(ce))
		if len(tools) == limit {
			break
		}
	}
	res := SearchToolsResult{Tools: tools, Total: len(tools)}
	if len(tools) == 0 {
		res.Hint = m.noMatchHint()
	}
	return nil, res, nil
}

// noMatchHint returns the recovery guidance attached to an empty
// falcon_search_tools result: the modules this server actually exposes (sorted
// for a stable message) plus the next things to try. Without it a search for a
// module the deployment does not enable is indistinguishable from a typo.
func (m *MetaModule) noMatchHint() string {
	mods := m.catalog.Modules()
	slices.Sort(mods)
	return fmt.Sprintf(
		"No tools matched. Available modules: %s. Try a broader query, drop the module filter, or call falcon_list_enabled_modules.",
		strings.Join(mods, ", "),
	)
}

// matchesAll reports whether corpus contains every token (AND substring).
// An empty token set matches everything.
func matchesAll(corpus string, tokens []string) bool {
	for _, t := range tokens {
		if !strings.Contains(corpus, t) {
			return false
		}
	}
	return true
}

// summarize builds a ToolSummary from a catalog entry, deriving the read-only
// and destructive flags from the tool's annotations.
func summarize(ce catalogEntry) ToolSummary {
	ann := ce.tool.Annotations
	readOnly := ann == nil || ann.ReadOnlyHint
	destructive := ann != nil && ann.DestructiveHint != nil && *ann.DestructiveHint
	return ToolSummary{
		Name:        ce.tool.Name,
		Description: ce.tool.Description,
		Module:      ce.module,
		Parameters:  enrichFilterHints(ce.tool.Name, ce.params),
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
