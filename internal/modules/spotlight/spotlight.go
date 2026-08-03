// Package spotlight implements the falcon_search_vulnerabilities tool over the
// gofalcon spotlight_vulnerabilities client, and registers the vulnerabilities
// FQL guide resource.
//
// search_vulnerabilities is a single-step typed gofalcon call
// (CombinedQueryVulnerabilities) that returns full vulnerability entities
// directly, so this module does no bulk detail fetch and ignores
// Deps.Concurrency. The tool is read-only.
package spotlight

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"

	"github.com/crowdstrike/gofalcon/falcon/client/spotlight_vulnerabilities"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/crowdstrike/falcon-mcp/internal/modules/base"
	"github.com/crowdstrike/falcon-mcp/internal/modules/registry"
)

// defaultLimit is the search page size applied when the caller omits limit.
const defaultLimit = 10

// fqlGuideURI is the MCP resource URI serving the vulnerabilities FQL filter
// guide, mirroring falcon-mcp's falcon://spotlight/vulnerabilities/fql-guide.
const fqlGuideURI = "falcon://spotlight/vulnerabilities/fql-guide"

// scopeVulnerabilitiesRead is the CrowdStrike API scope required by this
// module's operations. Surfaced on a 403 via base.APIError.
var scopeVulnerabilitiesRead = base.Scope{Name: "Vulnerabilities", Read: true}

// Factory builds the spotlight module from shared deps. The generated
// aggregator (internal/mcpserver) collects it, so the module needs no init side
// effect. The single tool is a one-call query, so the module ignores
// Deps.Concurrency.
var Factory registry.Factory = func(d registry.Deps) base.Module {
	return &Module{API: d.API.SpotlightVulnerabilities, Logger: d.Logger}
}

// spotlightAPI is the minimal slice of the gofalcon spotlight vulnerabilities
// client this module consumes, declared next to its consumer for testability.
type spotlightAPI interface {
	CombinedQueryVulnerabilities(params *spotlight_vulnerabilities.CombinedQueryVulnerabilitiesParams, opts ...spotlight_vulnerabilities.ClientOption) (*spotlight_vulnerabilities.CombinedQueryVulnerabilitiesOK, error)
}

// Module registers the spotlight tools. It holds only the shared,
// concurrency-safe Falcon client and configuration; handlers are stateless and
// reentrant. Logger must be non-nil.
type Module struct {
	API    spotlightAPI
	Logger *slog.Logger
}

// Name reports the module name.
func (m *Module) Name() string { return "spotlight" }

// Description reports a one-line summary of the module.
func (m *Module) Description() string {
	return "Search CrowdStrike Falcon Spotlight vulnerabilities"
}

// Tool and parameter descriptions, mirroring the Python falcon-mcp spotlight
// module (the facet description omits Python's scalar form, which the []string
// schema cannot accept). filterParamDescription carries backticks and
// sort/facet carry multi-line content that cannot live in a jsonschema struct
// tag, so they are consts applied to searchVulnerabilitiesSchema by its mutate
// func below.
const (
	searchVulnerabilitiesDescription = `Search for vulnerabilities in your CrowdStrike environment.

Use this to find vulnerabilities by CVE severity, status, host, or remediation
state. Consult falcon://spotlight/vulnerabilities/fql-guide before constructing
filter expressions. Returns vulnerability details including CVE info, host context,
and remediation guidance (based on facet selection).
Responses include ` + "`pagination.total`" + ` (the total number of records matching the filter, or null when the API does not report a count) — use it to answer "how many" questions. For cursor-based paging, use ` + "`pagination.next`" + ` as the ` + "`after`" + ` parameter on the next call.`

	filterParamDescription = "FQL filter expression. See `falcon://spotlight/vulnerabilities/fql-guide` for syntax."

	sortParamDescription = `Sort vulnerabilities using FQL syntax.

Supported sorting fields:
• created_timestamp: When the vulnerability was found
• closed_timestamp: When the vulnerability was closed
• updated_timestamp: When the vulnerability was last updated

Sort either asc (ascending) or desc (descending).
Format: 'field|direction'

Examples: 'created_timestamp|desc', 'updated_timestamp|desc', 'closed_timestamp|asc'`

	facetParamDescription = `Select one or more detail blocks to be returned for each vulnerability.

Provide a list of values (e.g. ['cve'] or ['cve', 'host_info', 'remediation'])
to retrieve one or more detail blocks in a single request.

Supported values:
• host_info: Include host/asset information and context
• remediation: Include remediation and fix information
• cve: Include CVE details, scoring, and metadata
• evaluation_logic: Include vulnerability assessment methodology

Use host_info when you need asset context, remediation for fix information,
cve for detailed vulnerability scoring, and evaluation_logic for assessment details.`

	afterParamDescription = "A pagination token used with the limit parameter to manage pagination of results. On your first request, don't provide an after token. On subsequent requests, provide the after token from the previous response to continue from that place in the results."
)

// searchVulnerabilitiesSchema is the input schema for
// falcon_search_vulnerabilities. It is inferred from SearchInput's struct tags,
// then a mutate func adds the limit bounds and default the tag syntax cannot
// express, plus the backtick-bearing filter and multi-line sort/facet
// descriptions that cannot live in a struct tag.
var searchVulnerabilitiesSchema = base.SchemaFor[SearchInput](func(s *jsonschema.Schema) {
	s.Properties["filter"].Description = filterParamDescription
	s.Properties["sort"].Description = sortParamDescription
	s.Properties["facet"].Description = facetParamDescription
	s.Properties["after"].Description = afterParamDescription
	s.Properties["limit"].Minimum = jsonschema.Ptr(1.0)
	s.Properties["limit"].Maximum = jsonschema.Ptr(5000.0)
	s.Properties["limit"].Default = json.RawMessage(`10`)
})

// RegisterTools registers the spotlight tools into r.
func (m *Module) RegisterTools(r base.Registrar) {
	searchTool := &mcp.Tool{
		Name:        "search_vulnerabilities",
		Description: searchVulnerabilitiesDescription,
		InputSchema: searchVulnerabilitiesSchema,
	}
	base.AddTool(r, searchTool, m.searchVulnerabilities)
}

// RegisterResources publishes the vulnerabilities FQL guide as an MCP resource,
// mirroring falcon-mcp's falcon://spotlight/vulnerabilities/fql-guide resource.
func (m *Module) RegisterResources(s *mcp.Server) {
	base.TextResource(s,
		fqlGuideURI,
		"search_vulnerabilities_fql_guide",
		"Contains the guide for the `filter` param of the `falcon_search_vulnerabilities` tool.",
		"text/markdown",
		fqlGuide,
	)
}

// RegisterPrompts is a no-op: the spotlight module exposes no prompts.
func (m *Module) RegisterPrompts(_ *mcp.Server) {}

// SearchInput is the input for falcon_search_vulnerabilities. The json tags
// drive the SDK's unmarshal into this struct; the served schema
// (searchVulnerabilitiesSchema) is inferred from these jsonschema tags, then
// augmented with the limit bounds and the backtick-bearing filter/sort/facet
// descriptions.
//
// Pagination here is token-based (after), matching the combined
// vulnerabilities endpoint, which does not accept an offset parameter.
type SearchInput struct {
	Filter string   `json:"filter,omitempty" jsonschema:"FQL filter (e.g. status:'open', cve.severity:'HIGH')"`
	Limit  int      `json:"limit,omitempty" jsonschema:"maximum records to return"`
	Sort   string   `json:"sort,omitempty" jsonschema:"FQL sort (e.g. created_timestamp|desc)"`
	After  string   `json:"after,omitempty" jsonschema:"pagination token from a previous response"`
	Facet  []string `json:"facet,omitempty" jsonschema:"detail blocks to return (host_info, remediation, cve, evaluation_logic)"`
}

func (m *Module) searchVulnerabilities(ctx context.Context, _ *mcp.CallToolRequest, in SearchInput) (*mcp.CallToolResult, base.SearchResult[*models.DomainBaseAPIVulnerabilityV2], error) {
	var zero base.SearchResult[*models.DomainBaseAPIVulnerabilityV2]
	limit := int64(in.Limit)
	if limit == 0 {
		limit = defaultLimit
	}
	m.Logger.Debug("search_vulnerabilities", "filter", in.Filter, "limit", limit, "sort", in.Sort, "after", in.After, "facet", in.Facet)

	params := spotlight_vulnerabilities.NewCombinedQueryVulnerabilitiesParamsWithContext(ctx)
	params.Limit = &limit
	if in.Filter != "" {
		params.Filter = in.Filter
	}
	if in.Sort != "" {
		params.Sort = &in.Sort
	}
	if in.After != "" {
		params.After = &in.After
	}
	if len(in.Facet) > 0 {
		params.Facet = in.Facet
	}

	resp, err := m.API.CombinedQueryVulnerabilities(params)
	if err != nil {
		if details, ok := fqlBadRequest(err); ok {
			return nil, base.FQLError[*models.DomainBaseAPIVulnerabilityV2](details, in.Filter, fqlGuide), nil
		}
	}
	if e := base.APIError(err, resp, scopeVulnerabilitiesRead); e != nil {
		return nil, zero, e
	}

	vulnerabilities := resp.Payload.Resources
	m.Logger.Debug("search_vulnerabilities query complete", "matched", len(vulnerabilities))
	return nil, base.Found(vulnerabilities, in.Filter).WithMeta(resp.Payload.Meta), nil
}

// fqlBadRequest reports whether err is a 400-class combined vulnerabilities
// query error and, if so, extracts the API error details for an FQL-error
// response. gofalcon surfaces 400s as a typed
// *spotlight_vulnerabilities.CombinedQueryVulnerabilitiesBadRequest whose
// payload carries the errors; classify with errors.As rather than string
// matching.
func fqlBadRequest(err error) ([]base.FQLErrorDetail, bool) {
	var badReq *spotlight_vulnerabilities.CombinedQueryVulnerabilitiesBadRequest
	if !errors.As(err, &badReq) || badReq.Payload == nil {
		return nil, false
	}
	return base.FQLErrorDetails(badReq.Payload.Errors), true
}
