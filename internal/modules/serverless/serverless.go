// Package serverless implements the falcon_search_serverless_vulnerabilities tool
// over the gofalcon serverless_vulnerabilities client, and registers the
// serverless vulnerabilities FQL guide resource.
//
// search_serverless_vulnerabilities is a single-step combined query
// (GetCombinedVulnerabilitiesSARIF) that returns vulnerability data in SARIF
// format, so this module does no bulk detail fetch and ignores Deps.Concurrency.
// The handler returns the SARIF "runs" array, mirroring the Python falcon-mcp
// module's response["runs"]. The tool is read-only.
package serverless

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"

	"github.com/crowdstrike/gofalcon/falcon/client/serverless_vulnerabilities"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/crowdstrike/falcon-mcp/internal/modules/base"
	"github.com/crowdstrike/falcon-mcp/internal/modules/registry"
)

// defaultLimit is the search page size applied when the caller omits limit,
// mirroring the Python falcon-mcp serverless module's default of 10.
const defaultLimit = 10

// fqlGuideURI is the MCP resource URI serving the serverless vulnerabilities FQL
// filter guide, mirroring falcon-mcp's
// falcon://serverless/vulnerabilities/fql-guide.
const fqlGuideURI = "falcon://serverless/vulnerabilities/fql-guide"

// scopeContainerImageRead is the CrowdStrike API scope required by this module's
// operation ("Falcon Container Image:read"). Surfaced on a 403 via base.APIError.
var scopeContainerImageRead = base.Scope{Name: "Falcon Container Image", Read: true}

// Factory builds the serverless module from shared deps. The generated
// aggregator (internal/mcpserver) collects the Factory, so the module needs no
// init side effect. The single tool is a one-call query, so the module ignores
// Deps.Concurrency.
var Factory registry.Factory = func(d registry.Deps) base.Module {
	return &Module{API: d.API.ServerlessVulnerabilities, Logger: d.Logger}
}

// serverlessAPI is the minimal slice of the serverless vulnerabilities client
// this module consumes, declared next to its consumer for testability. gofalcon's
// serverless_vulnerabilities.ClientService satisfies it directly.
type serverlessAPI interface {
	GetCombinedVulnerabilitiesSARIF(params *serverless_vulnerabilities.GetCombinedVulnerabilitiesSARIFParams, opts ...serverless_vulnerabilities.ClientOption) (*serverless_vulnerabilities.GetCombinedVulnerabilitiesSARIFOK, error)
}

// Module registers the serverless tools. It holds only the shared,
// concurrency-safe Falcon client and configuration; handlers are stateless and
// reentrant. Logger must be non-nil.
type Module struct {
	API    serverlessAPI
	Logger *slog.Logger
}

// Name reports the module name.
func (m *Module) Name() string { return "serverless" }

// Description reports a one-line summary of the module.
func (m *Module) Description() string {
	return "Search CrowdStrike Falcon serverless (Lambda/Cloud Functions/Azure Functions) vulnerabilities"
}

// Tool and parameter descriptions, mirroring the Python falcon-mcp serverless
// module. filterParamDescription carries backticks and sortParamDescription
// carries multi-line content that cannot live in a jsonschema struct tag, so
// they are consts applied to searchSchema by its mutate func below.
const (
	searchDescription = `Search for vulnerabilities in serverless functions across all cloud providers.

Use this to find CVEs in Lambda/Cloud Functions/Azure Functions by severity,
provider, or runtime. Consult falcon://serverless/vulnerabilities/fql-guide before
constructing filter expressions. Returns vulnerability data in SARIF format
including CVE IDs, severity levels, and descriptions.`

	filterParamDescription = "FQL filter expression (required). See `falcon://serverless/vulnerabilities/fql-guide` for syntax."

	sortParamDescription = `Sort serverless vulnerabilities using FQL syntax.

Supported sorting fields:
• application_name: Name of the application
• application_name_version: Version of the application
• cid: Customer ID
• cloud_account_id: Cloud account ID
• cloud_account_name: Cloud account name
• cloud_provider: Cloud provider
• cve_id: CVE ID
• cvss_base_score: CVSS base score
• exprt_rating: ExPRT rating
• first_seen_timestamp: When the vulnerability was first seen
• function_resource_id: Function resource ID
• is_supported: Whether the function is supported
• layer: Layer where the vulnerability was found
• region: Cloud region
• runtime: Runtime environment
• severity: Severity level
• timestamp: When the vulnerability was last updated
• type: Type of vulnerability

Format: 'field'

Examples: 'severity', 'cloud_provider', 'first_seen_timestamp'`
)

// searchSchema is the input schema for falcon_search_serverless_vulnerabilities.
// It is inferred from SearchInput's struct tags, then a mutate func adds the
// limit bounds and default the tag syntax cannot express, plus the
// backtick-bearing filter and multi-line sort descriptions that cannot live in a
// struct tag.
var searchSchema = base.SchemaFor[SearchInput](func(s *jsonschema.Schema) {
	s.Properties["filter"].Description = filterParamDescription
	s.Properties["sort"].Description = sortParamDescription
	s.Properties["limit"].Minimum = jsonschema.Ptr(1.0)
	s.Properties["limit"].Default = json.RawMessage(`10`)
	s.Properties["offset"].Minimum = jsonschema.Ptr(0.0)
})

// RegisterTools registers the serverless tools into r.
func (m *Module) RegisterTools(r base.Registrar) {
	searchTool := &mcp.Tool{
		Name:        "search_serverless_vulnerabilities",
		Description: searchDescription,
		InputSchema: searchSchema,
	}
	base.AddTool(r, searchTool, m.searchServerlessVulnerabilities)
}

// RegisterResources publishes the serverless vulnerabilities FQL guide as an MCP
// resource, mirroring falcon-mcp's
// falcon://serverless/vulnerabilities/fql-guide resource.
func (m *Module) RegisterResources(s *mcp.Server) {
	base.TextResource(s,
		fqlGuideURI,
		"serverless_vulnerabilities_fql_guide",
		"Contains the guide for the `filter` param of the `falcon_search_serverless_vulnerabilities` tool.",
		"text/markdown",
		fqlGuide,
	)
}

// RegisterPrompts is a no-op: the serverless module exposes no prompts.
func (m *Module) RegisterPrompts(_ *mcp.Server) {}

// SearchInput is the input for falcon_search_serverless_vulnerabilities. The
// json tags drive the SDK's unmarshal into this struct; the served schema
// (searchSchema) is inferred from these jsonschema tags, then augmented with the
// limit bounds and the backtick-bearing filter/sort descriptions.
//
// Filter has no omitempty because the Python tool requires it; the handler
// validates it and returns a soft input error when empty.
type SearchInput struct {
	Filter string `json:"filter" jsonschema:"FQL filter (e.g. cloud_provider:'aws', severity:'HIGH')"`
	Limit  int    `json:"limit,omitempty" jsonschema:"maximum records to return"`
	Offset int    `json:"offset,omitempty" jsonschema:"pagination offset"`
	Sort   string `json:"sort,omitempty" jsonschema:"FQL sort (e.g. severity, cloud_provider)"`
}

func (m *Module) searchServerlessVulnerabilities(ctx context.Context, _ *mcp.CallToolRequest, in SearchInput) (*mcp.CallToolResult, base.SearchResult[*models.ModelsRun], error) {
	var zero base.SearchResult[*models.ModelsRun]
	if in.Filter == "" {
		return nil, zero, base.ErrInvalidInput
	}
	limit := int64(in.Limit)
	if limit == 0 {
		limit = defaultLimit
	}
	m.Logger.Debug("search_serverless_vulnerabilities", "filter", in.Filter, "limit", limit, "offset", in.Offset, "sort", in.Sort)

	params := serverless_vulnerabilities.NewGetCombinedVulnerabilitiesSARIFParamsWithContext(ctx)
	params.Filter = &in.Filter
	params.Limit = &limit
	if in.Offset != 0 {
		params.Offset = new(int64(in.Offset))
	}
	if in.Sort != "" {
		params.Sort = &in.Sort
	}

	resp, err := m.API.GetCombinedVulnerabilitiesSARIF(params)
	if details, ok := fqlBadRequest(err); ok {
		return nil, base.FQLError[*models.ModelsRun](details, in.Filter, fqlGuide), nil
	}
	if e := base.APIError(err, resp, scopeContainerImageRead); e != nil {
		return nil, zero, e
	}

	runs, meta := sarifRuns(resp)
	m.Logger.Debug("search_serverless_vulnerabilities query complete", "runs", len(runs))
	// The endpoint carries no pagination cursor, but meta still reports the query
	// duration and the trace ID quoted in support requests.
	return nil, base.Found(runs, in.Filter).WithMeta(meta), nil
}

// sarifRuns extracts the SARIF "runs" array and the response metadata from a
// combined-SARIF response, mirroring the Python module's response["runs"]. A nil
// response or one with no SARIF document yields an empty slice, not an error;
// metadata is returned whenever present, so query_time and trace_id survive a
// result-less response.
func sarifRuns(resp *serverless_vulnerabilities.GetCombinedVulnerabilitiesSARIFOK) ([]*models.ModelsRun, *models.MsaMetaInfo) {
	if resp == nil || resp.Payload == nil {
		return nil, nil
	}
	if resp.Payload.Resources == nil {
		return nil, resp.Payload.Meta
	}
	return resp.Payload.Resources.Runs, resp.Payload.Meta
}

// fqlBadRequest reports whether err is a 400-class combined SARIF query error
// and, if so, extracts the API error details for an FQL-error response. gofalcon
// surfaces 400s as a typed
// *serverless_vulnerabilities.GetCombinedVulnerabilitiesSARIFBadRequest whose
// payload carries the errors; classify with errors.As rather than string
// matching.
func fqlBadRequest(err error) ([]base.FQLErrorDetail, bool) {
	var badReq *serverless_vulnerabilities.GetCombinedVulnerabilitiesSARIFBadRequest
	if !errors.As(err, &badReq) || badReq.Payload == nil {
		return nil, false
	}
	return base.FQLErrorDetails(badReq.Payload.Errors), true
}
