// Package serverless implements the falcon_search_serverless_vulnerabilities tool
// over the gofalcon serverless_vulnerabilities client, and registers the
// serverless vulnerabilities FQL guide resource.
//
// search_serverless_vulnerabilities is a single-step combined query
// (GetCombinedVulnerabilitiesSARIF) that returns vulnerability data in SARIF
// format, so this module does no bulk detail fetch and ignores Deps.Concurrency.
// The tool is read-only.
//
// The gofalcon typed response cannot be used directly: its generated model
// declares the "resources" field as an array of SARIF documents, but the live
// API returns a single SARIF object ({$schema, version, runs}). Decoding a real
// response through the typed method therefore fails with a JSON unmarshal error.
// This module wraps the gofalcon client with serverlessClient, which captures
// the raw 200 body and lets the handler decode the actual shape and return the
// SARIF "runs" array — matching the Python falcon-mcp module, which returns
// response["runs"].
package serverless

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"

	"github.com/crowdstrike/gofalcon/falcon/client/serverless_vulnerabilities"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/go-openapi/runtime"
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

// Factory builds the serverless module from shared deps. The gofalcon client is
// wrapped by serverlessClient so the handler can recover the raw SARIF body the
// generated reader cannot decode. The generated aggregator (internal/mcpserver)
// collects the Factory, so the module needs no init side effect. The single tool
// is a one-call query, so the module ignores Deps.Concurrency.
var Factory registry.Factory = func(d registry.Deps) base.Module {
	return &Module{API: serverlessClient{ClientService: d.API.ServerlessVulnerabilities}, Logger: d.Logger}
}

// serverlessAPI is the minimal slice of the serverless vulnerabilities client
// this module consumes, declared next to its consumer for testability. The
// GetCombinedVulnerabilitiesSARIF here returns the raw 200 body as an any
// ([]byte) rather than the gofalcon typed OK, because the typed model cannot
// decode the live response (see the package doc and serverlessClient).
type serverlessAPI interface {
	GetCombinedVulnerabilitiesSARIF(params *serverless_vulnerabilities.GetCombinedVulnerabilitiesSARIFParams, opts ...serverless_vulnerabilities.ClientOption) (any, error)
}

// serverlessClient adapts the gofalcon serverless_vulnerabilities.ClientService,
// overriding GetCombinedVulnerabilitiesSARIF to recover the raw 200 body. The
// generated method decodes "resources" as an array and so fails on the live
// response (a single SARIF object); worse, it panics if the transport returns
// any non-*GetCombinedVulnerabilitiesSARIFOK value, so a Reader override cannot
// simply return the raw bytes in its place. Instead the override captures the
// 200 body into a field on a custom reader while still returning a valid
// *GetCombinedVulnerabilitiesSARIFOK to satisfy the method's type assertion;
// this adapter then hands the captured bytes back as the any result. Non-200
// responses (including the FQL 400) fall through to the generated typed errors.
type serverlessClient struct {
	serverless_vulnerabilities.ClientService
}

// GetCombinedVulnerabilitiesSARIF fetches the combined SARIF response, recovering
// the 200 body the generated reader cannot decode. It returns the raw body as an
// any ([]byte) on success, or the generated typed error on a non-200 response.
func (c serverlessClient) GetCombinedVulnerabilitiesSARIF(params *serverless_vulnerabilities.GetCombinedVulnerabilitiesSARIFParams, opts ...serverless_vulnerabilities.ClientOption) (any, error) {
	capture := &sarifReader{}
	override := func(op *runtime.ClientOperation) {
		capture.orig = op.Reader
		op.Reader = capture
	}
	_, err := c.ClientService.GetCombinedVulnerabilitiesSARIF(params, append([]serverless_vulnerabilities.ClientOption{override}, opts...)...)
	if err != nil {
		return nil, err
	}
	return capture.body, nil
}

// sarifReader wraps the generated reader to capture the 200 response body, which
// the generated reader cannot decode into its array-typed model (see
// serverlessClient). On non-200 responses it delegates to the original reader so
// 400/403/429/500 still surface as gofalcon's typed errors.
type sarifReader struct {
	orig runtime.ClientResponseReader
	body []byte
}

// ReadResponse captures the 200 body into r.body and returns a valid
// *GetCombinedVulnerabilitiesSARIFOK so the generated method's type assertion
// succeeds; other status codes delegate to the wrapped reader.
func (r *sarifReader) ReadResponse(resp runtime.ClientResponse, c runtime.Consumer) (any, error) {
	if resp.Code() == 200 {
		b, err := io.ReadAll(resp.Body())
		if err != nil {
			return nil, fmt.Errorf("read serverless SARIF body: %w", err)
		}
		r.body = b
		return serverless_vulnerabilities.NewGetCombinedVulnerabilitiesSARIFOK(), nil
	}
	return r.orig.ReadResponse(resp, c)
}

// sarifResponse is the on-the-wire shape of the combined SARIF response. Unlike
// the gofalcon model, resources is a single SARIF document, not an array — this
// is why the typed method cannot decode a real response. Meta is the standard
// sibling of resources and carries query_time and trace_id.
type sarifResponse struct {
	Meta      *models.MsaMetaInfo              `json:"meta"`
	Resources *models.ModelsVulnerabilitySARIF `json:"resources"`
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

	raw, err := m.API.GetCombinedVulnerabilitiesSARIF(params)
	if err != nil {
		if details, ok := fqlBadRequest(err); ok {
			return nil, base.FQLError[*models.ModelsRun](details, in.Filter, fqlGuide), nil
		}
		if e := base.APIError(err, nil, scopeContainerImageRead); e != nil {
			return nil, zero, e
		}
	}

	body, _ := raw.([]byte)
	runs, meta, err := decodeSARIF(body)
	if err != nil {
		return nil, zero, err
	}
	m.Logger.Debug("search_serverless_vulnerabilities query complete", "runs", len(runs))
	// The endpoint carries no pagination cursor, but meta still reports the query
	// duration and the trace ID quoted in support requests.
	return nil, base.Found(runs, in.Filter).WithMeta(meta), nil
}

// decodeSARIF extracts the SARIF "runs" array and the response metadata from a
// raw combined-SARIF response body, mirroring the Python module's
// response["runs"]. An empty body or a response with no resources yields an
// empty slice, not an error; metadata is returned whenever the body decodes, so
// query_time and trace_id survive a result-less response.
func decodeSARIF(body []byte) ([]*models.ModelsRun, *models.MsaMetaInfo, error) {
	if len(body) == 0 {
		return nil, nil, nil
	}
	var resp sarifResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, nil, fmt.Errorf("decode serverless SARIF response: %w", err)
	}
	if resp.Resources == nil {
		return nil, resp.Meta, nil
	}
	return resp.Resources.Runs, resp.Meta, nil
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
