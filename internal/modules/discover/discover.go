// Package discover implements the falcon_search_applications and
// falcon_search_unmanaged_assets tools over the gofalcon discover client, and
// registers their FQL guide resources.
//
// Both tools are single-step typed gofalcon calls (CombinedApplications and
// CombinedHosts) that return full entities directly, so this module does no
// bulk detail fetch and ignores Deps.Concurrency. Both tools are read-only.
package discover

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"

	"github.com/crowdstrike/gofalcon/falcon/client/discover"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/crowdstrike/falcon-mcp/internal/modules/base"
	"github.com/crowdstrike/falcon-mcp/internal/modules/registry"
)

// defaultLimit is the search page size applied when the caller omits limit,
// matching the Python discover module's default.
const defaultLimit = 100

// maxLimit is the largest page size the combined endpoints accept. Both
// CombinedApplications and CombinedHosts reject limit > 1000 with a 400
// (verified live), so the schema caps the input here.
const maxLimit = 1000

// unmanagedFilter is prepended to every unmanaged-asset query so the tool only
// ever returns hosts without a Falcon sensor, mirroring the Python module.
const unmanagedFilter = "entity_type:'unmanaged'"

// scopeAssetsRead is the CrowdStrike API scope required by this module's
// discover operations (console permission "Assets"). Surfaced on a 403 via
// base.APIError.
var scopeAssetsRead = base.Scope{Name: "Assets", Read: true}

// Factory builds the discover module from shared deps. The generated aggregator
// (internal/mcpserver) collects it, so the module needs no init side effect.
// Both tools are one-call queries, so the module ignores Deps.Concurrency.
var Factory registry.Factory = func(d registry.Deps) base.Module {
	return &Module{API: d.API.Discover, Logger: d.Logger}
}

// discoverAPI is the minimal slice of the gofalcon discover client this module
// consumes, declared next to its consumer so handlers can be tested against a
// tiny fake rather than all of gofalcon.
type discoverAPI interface {
	CombinedApplications(params *discover.CombinedApplicationsParams, opts ...discover.ClientOption) (*discover.CombinedApplicationsOK, error)
	CombinedHosts(params *discover.CombinedHostsParams, opts ...discover.ClientOption) (*discover.CombinedHostsOK, error)
}

// Module registers the discover tools. It holds only the shared,
// concurrency-safe Falcon client and configuration; handlers are stateless and
// reentrant. Logger must be non-nil.
type Module struct {
	API    discoverAPI
	Logger *slog.Logger
}

// Name reports the module name.
func (m *Module) Name() string { return "discover" }

// Description reports a one-line summary of the module.
func (m *Module) Description() string {
	return "Search Falcon Discover applications and unmanaged assets"
}

// Tool and parameter descriptions, kept 1:1 with the Python falcon-mcp discover
// module. The filter/facet/sort descriptions carry backticks or multi-line
// content that cannot live in a jsonschema struct tag, so they are consts
// applied to the schemas by their mutate funcs below.
const (
	searchApplicationsDescription = `Search for applications discovered in your CrowdStrike environment.

Use this to find applications by name, vendor, or installation details. Consult
falcon://discover/applications/fql-guide before constructing filter expressions.
Returns application entities with optional host info and usage data (based on facet).`

	searchUnmanagedAssetsDescription = `Search for unmanaged assets (hosts without Falcon sensor) in your environment.

Finds systems discovered by Falcon-managed hosts that lack a sensor themselves.
Consult falcon://discover/hosts/fql-guide before constructing filter expressions.
The tool automatically adds entity_type:'unmanaged' to all queries. Returns full
asset details including platform, network, and criticality information.`

	applicationsFilterDescription = "FQL filter expression (required). See `falcon://discover/applications/fql-guide` for syntax."

	applicationsFacetDescription = `Type of data to be returned for each application entity. The facet filter allows you to limit the response to just the information you want.

Possible values:
• browser_extension
• host_info
• install_usage

Note: Requests that do not include the host_info or browser_extension facets still return host.ID, browser_extension.ID, and browser_extension.enabled in the response.`

	applicationsSortDescription = "Property used to sort the results. All properties can be used to sort unless otherwise noted in their property descriptions."

	unmanagedFilterDescription = "FQL filter expression. See `falcon://discover/hosts/fql-guide` for syntax. Note: entity_type:'unmanaged' is automatically applied."

	unmanagedSortDescription = `Sort unmanaged assets using these options:

hostname: Host name/computer name
last_seen_timestamp: Timestamp when the asset was last seen
first_seen_timestamp: Timestamp when the asset was first seen
platform_name: Operating system platform
os_version: Operating system version
external_ip: External IP address
country: Country location
criticality: Criticality level

Sort either asc (ascending) or desc (descending).
Both formats are supported: 'hostname.desc' or 'hostname|desc'

Examples: 'hostname.asc', 'last_seen_timestamp.desc', 'criticality.desc'`
)

// searchApplicationsSchema is the input schema for falcon_search_applications.
// It is inferred from ApplicationsInput's struct tags, then a mutate func adds
// the limit bounds/default the tag syntax cannot express, plus the
// backtick-bearing filter and multi-line facet/sort descriptions.
var searchApplicationsSchema = base.SchemaFor[ApplicationsInput](func(s *jsonschema.Schema) {
	s.Properties["filter"].Description = applicationsFilterDescription
	s.Properties["facet"].Description = applicationsFacetDescription
	s.Properties["sort"].Description = applicationsSortDescription
	s.Properties["limit"].Minimum = jsonschema.Ptr(1.0)
	s.Properties["limit"].Maximum = jsonschema.Ptr(float64(maxLimit))
	s.Properties["limit"].Default = json.RawMessage(`100`)
})

// searchUnmanagedAssetsSchema is the input schema for
// falcon_search_unmanaged_assets. It is inferred from UnmanagedAssetsInput's
// struct tags, then a mutate func adds the limit bounds/default the tag syntax
// cannot express, plus the backtick-bearing filter and multi-line sort
// descriptions.
var searchUnmanagedAssetsSchema = base.SchemaFor[UnmanagedAssetsInput](func(s *jsonschema.Schema) {
	s.Properties["filter"].Description = unmanagedFilterDescription
	s.Properties["sort"].Description = unmanagedSortDescription
	s.Properties["limit"].Minimum = jsonschema.Ptr(1.0)
	s.Properties["limit"].Maximum = jsonschema.Ptr(float64(maxLimit))
	s.Properties["limit"].Default = json.RawMessage(`100`)
})

// RegisterTools registers the discover tools into r.
func (m *Module) RegisterTools(r base.Registrar) {
	base.AddTool(r, &mcp.Tool{
		Name:        "search_applications",
		Description: searchApplicationsDescription,
		InputSchema: searchApplicationsSchema,
	}, m.searchApplications)

	base.AddTool(r, &mcp.Tool{
		Name:        "search_unmanaged_assets",
		Description: searchUnmanagedAssetsDescription,
		InputSchema: searchUnmanagedAssetsSchema,
	}, m.searchUnmanagedAssets)
}

// RegisterResources publishes the discover FQL guides as MCP resources,
// mirroring falcon-mcp's falcon://discover/applications/fql-guide and
// falcon://discover/hosts/fql-guide resources.
func (m *Module) RegisterResources(s *mcp.Server) {
	base.TextResource(s,
		applicationsFQLGuideURI,
		"search_applications_fql_guide",
		"Contains the guide for the `filter` param of the `falcon_search_applications` tool.",
		"text/markdown",
		applicationsFQLGuide,
	)
	base.TextResource(s,
		unmanagedAssetsFQLGuideURI,
		"search_unmanaged_assets_fql_guide",
		"Contains the guide for the `filter` param of the `falcon_search_unmanaged_assets` tool.",
		"text/markdown",
		unmanagedAssetsFQLGuide,
	)
}

// RegisterPrompts is a no-op: the discover module exposes no prompts.
func (m *Module) RegisterPrompts(_ *mcp.Server) {}

// ApplicationsInput is the input for falcon_search_applications. The json tags
// drive the SDK's unmarshal into this struct; the served schema
// (searchApplicationsSchema) is inferred from these jsonschema tags, then
// augmented with the limit bounds and the backtick/multi-line descriptions.
//
// filter is required: the combined applications endpoint rejects a request with
// no filter (400 "a filter parameter is required", verified live), so it has no
// omitempty and schema inference marks it required.
type ApplicationsInput struct {
	Filter string `json:"filter" jsonschema:"FQL filter (e.g. name:'Chrome', vendor:'Microsoft Corporation')"`
	Facet  string `json:"facet,omitempty" jsonschema:"detail block to return (browser_extension, host_info, install_usage)"`
	Limit  int    `json:"limit,omitempty" jsonschema:"maximum records to return"`
	Sort   string `json:"sort,omitempty" jsonschema:"FQL sort (e.g. name.asc, last_updated_timestamp.desc)"`
}

func (m *Module) searchApplications(ctx context.Context, _ *mcp.CallToolRequest, in ApplicationsInput) (*mcp.CallToolResult, base.SearchResult[*models.DomainDiscoverAPIApplication], error) {
	var zero base.SearchResult[*models.DomainDiscoverAPIApplication]
	limit := int64(in.Limit)
	if limit == 0 {
		limit = defaultLimit
	}
	m.Logger.Debug("search_applications", "filter", in.Filter, "facet", in.Facet, "limit", limit, "sort", in.Sort)

	params := discover.NewCombinedApplicationsParamsWithContext(ctx)
	params.Limit = &limit
	params.Filter = in.Filter
	if in.Facet != "" {
		params.Facet = []string{in.Facet}
	}
	if in.Sort != "" {
		params.Sort = &in.Sort
	}

	resp, err := m.API.CombinedApplications(params)
	if err != nil {
		if details, ok := applicationsFQLBadRequest(err); ok {
			return nil, base.FQLError[*models.DomainDiscoverAPIApplication](details, in.Filter, applicationsFQLGuide), nil
		}
	}
	if e := base.APIError(err, resp, scopeAssetsRead); e != nil {
		return nil, zero, e
	}

	applications := resp.Payload.Resources
	m.Logger.Debug("search_applications query complete", "matched", len(applications))
	return nil, base.Found(applications, in.Filter), nil
}

// UnmanagedAssetsInput is the input for falcon_search_unmanaged_assets. The json
// tags drive the SDK's unmarshal into this struct; the served schema
// (searchUnmanagedAssetsSchema) is inferred from these jsonschema tags, then
// augmented with the limit bounds and the backtick/multi-line descriptions.
//
// The combined hosts endpoint paginates by token (after), not offset, so this
// tool exposes no offset parameter (the Python offset had no gofalcon
// equivalent).
type UnmanagedAssetsInput struct {
	Filter string `json:"filter,omitempty" jsonschema:"FQL filter (e.g. platform_name:'Windows', criticality:'Critical')"`
	Limit  int    `json:"limit,omitempty" jsonschema:"maximum records to return"`
	Sort   string `json:"sort,omitempty" jsonschema:"FQL sort (e.g. hostname.asc, last_seen_timestamp.desc)"`
}

func (m *Module) searchUnmanagedAssets(ctx context.Context, _ *mcp.CallToolRequest, in UnmanagedAssetsInput) (*mcp.CallToolResult, base.SearchResult[*models.DomainDiscoverAPIHost], error) {
	var zero base.SearchResult[*models.DomainDiscoverAPIHost]
	limit := int64(in.Limit)
	if limit == 0 {
		limit = defaultLimit
	}

	// Always constrain to unmanaged assets, combining with any user filter via
	// the FQL AND operator (+).
	filter := unmanagedFilter
	if in.Filter != "" {
		filter = unmanagedFilter + "+" + in.Filter
	}
	m.Logger.Debug("search_unmanaged_assets", "filter", filter, "limit", limit, "sort", in.Sort)

	params := discover.NewCombinedHostsParamsWithContext(ctx)
	params.Limit = &limit
	params.Filter = filter
	if in.Sort != "" {
		params.Sort = &in.Sort
	}

	resp, err := m.API.CombinedHosts(params)
	if err != nil {
		if details, ok := hostsFQLBadRequest(err); ok {
			return nil, base.FQLError[*models.DomainDiscoverAPIHost](details, filter, unmanagedAssetsFQLGuide), nil
		}
	}
	if e := base.APIError(err, resp, scopeAssetsRead); e != nil {
		return nil, zero, e
	}

	assets := resp.Payload.Resources
	m.Logger.Debug("search_unmanaged_assets query complete", "matched", len(assets))
	return nil, base.Found(assets, filter), nil
}

// applicationsFQLBadRequest reports whether err is a 400-class combined
// applications error and, if so, extracts the API error details for an FQL-error
// response. gofalcon surfaces 400s as a typed
// *discover.CombinedApplicationsBadRequest whose payload carries the errors;
// classify with errors.As rather than string matching.
func applicationsFQLBadRequest(err error) ([]base.FQLErrorDetail, bool) {
	var badReq *discover.CombinedApplicationsBadRequest
	if !errors.As(err, &badReq) || badReq.Payload == nil {
		return nil, false
	}
	return base.FQLErrorDetails(badReq.Payload.Errors), true
}

// hostsFQLBadRequest reports whether err is a 400-class combined hosts error
// and, if so, extracts the API error details for an FQL-error response.
func hostsFQLBadRequest(err error) ([]base.FQLErrorDetail, bool) {
	var badReq *discover.CombinedHostsBadRequest
	if !errors.As(err, &badReq) || badReq.Payload == nil {
		return nil, false
	}
	return base.FQLErrorDetails(badReq.Payload.Errors), true
}
