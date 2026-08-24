// Package ioc implements the three custom-IOC tools over the gofalcon ioc
// client: searching indicators, creating them, and deleting them. It registers
// the IOC search FQL guide resource.
//
// Unlike falcon-mcp's Python module, search is a single combined call
// (IndicatorCombinedV1) rather than a query-then-get-by-ids round trip, so the
// module does no bulk detail fetch and ignores Deps.Concurrency.
package ioc

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"

	"github.com/crowdstrike/gofalcon/falcon/client/ioc"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/crowdstrike/falcon-mcp/internal/modules/base"
	"github.com/crowdstrike/falcon-mcp/internal/modules/registry"
)

// Factory builds the IOC module from shared deps. The generated aggregator
// (internal/mcpserver) collects it, so the module needs no init side effect.
// This module does no bulk detail fetch, so it ignores Deps.Concurrency.
var Factory registry.Factory = func(d registry.Deps) base.Module {
	return &Module{API: d.API.Ioc, Logger: d.Logger}
}

// defaultLimit is the search page size applied when the caller omits limit.
const defaultLimit = 10

// errInvalidInput classifies client-side validation failures in the mutating
// tools.
var errInvalidInput = errors.New("ioc: invalid input")

// CrowdStrike API scopes required by this module's operations. Surfaced on a
// 403 via base.APIError, referenced directly at each call site.
var (
	scopeIOCRead  = base.Scope{Name: "IOC Management", Read: true}
	scopeIOCWrite = base.Scope{Name: "IOC Management", Write: true}
)

// iocAPI is the minimal slice of the gofalcon ioc client this module consumes,
// declared next to its consumer so handlers can be tested against a tiny fake
// rather than all of gofalcon.
type iocAPI interface {
	IndicatorCombinedV1(params *ioc.IndicatorCombinedV1Params, opts ...ioc.ClientOption) (*ioc.IndicatorCombinedV1OK, error)
	IndicatorCreateV1(params *ioc.IndicatorCreateV1Params, opts ...ioc.ClientOption) (*ioc.IndicatorCreateV1Created, error)
	IndicatorDeleteV1(params *ioc.IndicatorDeleteV1Params, opts ...ioc.ClientOption) (*ioc.IndicatorDeleteV1OK, error)
}

// Module registers the IOC tools. It holds only the shared, concurrency-safe
// Falcon client and configuration; handlers are stateless and reentrant.
// Logger must be non-nil.
type Module struct {
	API    iocAPI
	Logger *slog.Logger
}

// Name reports the module name.
func (m *Module) Name() string { return "ioc" }

// Description reports a one-line summary of the module.
func (m *Module) Description() string {
	return "Search, create, and delete custom Falcon IOCs (indicators of compromise)"
}

// searchIOCsSchema is the input schema for falcon_search_iocs. It is inferred
// from SearchInput's struct tags, then a mutate func adds the limit
// bounds/default the tag syntax cannot express.
var searchIOCsSchema = base.SchemaFor[SearchInput](func(s *jsonschema.Schema) {
	s.Properties["limit"].Minimum = jsonschema.Ptr(1.0)
	s.Properties["limit"].Maximum = jsonschema.Ptr(500.0)
	s.Properties["limit"].Default = json.RawMessage(`10`)
})

// RegisterTools registers the three IOC tools into r.
func (m *Module) RegisterTools(r base.Registrar) {
	base.AddTool(r, &mcp.Tool{
		Name: "search_iocs",
		Description: "Search custom IOCs in CrowdStrike Falcon using IOC FQL (fields: type, value, action, source, severity_number, expiration, expired, applied_globally, metadata.filename.raw). Consult falcon://ioc/search/fql-guide before constructing filter expressions. Returns full indicator records.\n" +
			"Responses include `pagination.total` (the total number of records matching the filter, " +
			"or null when the API does not report a count) — use it to answer \"how many\" questions. " +
			"For cursor-based paging, use `pagination.next` as the `after` parameter on the next call.",
		InputSchema: searchIOCsSchema,
	}, m.searchIOCs)

	base.AddTool(r, &mcp.Tool{
		Name:        "add_ioc",
		Description: "Create one or more custom IOCs. Provide type/value (plus optional action, severity, expiration, etc.) for a single IOC, or a bulk indicators array. Returns the created indicator records.",
		Annotations: base.MutatingAnnotations(false),
	}, m.addIOC)

	base.AddTool(r, &mcp.Tool{
		Name:        "remove_iocs",
		Description: "Delete custom IOCs by IDs or FQL filter. If both are given, filter takes precedence. Returns the deleted IOC IDs. Idempotent.",
		Annotations: base.DestructiveAnnotations(true),
	}, m.removeIOCs)
}

// RegisterResources publishes the IOC search FQL guide as an MCP resource,
// mirroring falcon-mcp's falcon://ioc/search/fql-guide resource.
func (m *Module) RegisterResources(s *mcp.Server) {
	base.TextResource(s,
		fqlGuideURI,
		"search_iocs_fql_guide",
		"Contains the guide for the `filter` param of the `falcon_search_iocs` tool.",
		"text/markdown",
		fqlGuide,
	)
}

// RegisterPrompts is a no-op: the IOC module exposes no prompts.
func (m *Module) RegisterPrompts(_ *mcp.Server) {}

// SearchInput is the input for falcon_search_iocs.
//
// Pagination is cursor-only: pass pagination.next from the previous response as
// after. The endpoint documents offset and after as mutually exclusive, and
// reaching beyond 10,000 indicators requires the cursor.
type SearchInput struct {
	Filter     string `json:"filter,omitempty" jsonschema:"IOC FQL filter (e.g. type:'domain'+expired:false, source:'mcp'). See falcon://ioc/search/fql-guide for syntax."`
	Limit      int    `json:"limit,omitempty" jsonschema:"maximum results to return"`
	Sort       string `json:"sort,omitempty" jsonschema:"IOC FQL sort (e.g. modified_on.desc, severity_number.desc)"`
	After      string `json:"after,omitempty" jsonschema:"Pagination token for large result sets. Use the pagination.next value returned by the previous search call."`
	FromParent *bool  `json:"from_parent,omitempty" jsonschema:"return indicators from the MSSP parent when applicable"`
}

func (m *Module) searchIOCs(ctx context.Context, _ *mcp.CallToolRequest, in SearchInput) (*mcp.CallToolResult, base.SearchResult[*models.APIIndicatorV1], error) {
	var zero base.SearchResult[*models.APIIndicatorV1]
	limit := int64(in.Limit)
	if limit == 0 {
		limit = defaultLimit
	}
	m.Logger.Debug("search_iocs", "filter", in.Filter, "limit", limit, "sort", in.Sort, "after", in.After)

	params := ioc.NewIndicatorCombinedV1ParamsWithContext(ctx)
	params.Limit = &limit
	if in.Filter != "" {
		params.Filter = &in.Filter
	}
	if in.Sort != "" {
		params.Sort = &in.Sort
	}
	if in.After != "" {
		params.After = &in.After
	}
	if in.FromParent != nil {
		params.FromParent = in.FromParent
	}

	resp, err := m.API.IndicatorCombinedV1(params)
	if err != nil {
		if details, ok := fqlBadRequest(err); ok {
			return nil, base.FQLError[*models.APIIndicatorV1](details, in.Filter, fqlGuide), nil
		}
	}
	if e := base.APIError(err, resp, scopeIOCRead); e != nil {
		return nil, zero, e
	}

	indicators := resp.Payload.Resources
	m.Logger.Debug("search_iocs query complete", "matched", len(indicators))
	return nil, base.Found(indicators, in.Filter).WithMeta(resp.Payload.Meta), nil
}

// fqlBadRequest reports whether err is a 400-class IOC query error and, if so,
// extracts the API error details for an FQL-error response. gofalcon surfaces
// 400s as a typed *ioc.IndicatorCombinedV1BadRequest whose payload carries the
// errors; classify with errors.As rather than string matching.
func fqlBadRequest(err error) ([]base.FQLErrorDetail, bool) {
	var badReq *ioc.IndicatorCombinedV1BadRequest
	if !errors.As(err, &badReq) || badReq.Payload == nil {
		return nil, false
	}
	return base.FQLErrorDetails(badReq.Payload.Errors), true
}
