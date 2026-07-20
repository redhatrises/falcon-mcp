// Package data_protection implements the falcon_search_data_protection_classifications,
// falcon_search_data_protection_policies, and
// falcon_search_data_protection_content_patterns tools over the gofalcon
// data_protection_configuration client, and registers their FQL guide resources.
//
// The module provides read-only access to Data Protection configuration data —
// classification rules, policies, and content patterns — so an LLM can reason
// about why a Data Protection detection fired. Each tool follows the two-step
// search pattern (query IDs, then fetch full entity details).
package data_protection

import (
	"context"
	"encoding/json"
	"log/slog"

	dp "github.com/crowdstrike/gofalcon/falcon/client/data_protection_configuration"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/crowdstrike/falcon-mcp/internal/modules/base"
	"github.com/crowdstrike/falcon-mcp/internal/modules/registry"
)

// detailBatchSize is the maximum number of IDs fetched per details call. The
// data-protection get endpoints take IDs as query parameters, so this stays
// conservative to keep request URLs within limits.
const detailBatchSize = 100

// defaultLimit is the search page size applied when the caller omits limit.
const defaultLimit = 100

// FQL guide resource URIs, mirroring the Python falcon-mcp module.
const (
	classificationsFQLGuideURI = "falcon://data-protection/classifications/fql-guide"
	policiesFQLGuideURI        = "falcon://data-protection/policies/fql-guide"
	contentPatternsFQLGuideURI = "falcon://data-protection/content-patterns/fql-guide"
)

// scopeDataProtectionRead is the CrowdStrike API scope required by this module's
// operations. Surfaced on a 403 via base.APIError.
var scopeDataProtectionRead = base.Scope{Name: "Data Protection", Read: true}

// Factory builds the data_protection module from shared deps. The generated
// aggregator (internal/mcpserver) collects it, so the module needs no init side
// effect.
var Factory registry.Factory = func(d registry.Deps) base.Module {
	return &Module{API: d.API.DataProtectionConfiguration, Concurrency: d.Concurrency, Logger: d.Logger}
}

// dataProtectionAPI is the minimal slice of the gofalcon
// data_protection_configuration client this module consumes, declared next to
// its consumer for testability.
type dataProtectionAPI interface {
	QueriesClassificationGetV2(params *dp.QueriesClassificationGetV2Params, opts ...dp.ClientOption) (*dp.QueriesClassificationGetV2OK, error)
	EntitiesClassificationGetV2(params *dp.EntitiesClassificationGetV2Params, opts ...dp.ClientOption) (*dp.EntitiesClassificationGetV2OK, error)
	QueriesPolicyGetV2(params *dp.QueriesPolicyGetV2Params, opts ...dp.ClientOption) (*dp.QueriesPolicyGetV2OK, error)
	EntitiesPolicyGetV2(params *dp.EntitiesPolicyGetV2Params, opts ...dp.ClientOption) (*dp.EntitiesPolicyGetV2OK, error)
	QueriesContentPatternGetV2(params *dp.QueriesContentPatternGetV2Params, opts ...dp.ClientOption) (*dp.QueriesContentPatternGetV2OK, error)
	EntitiesContentPatternGet(params *dp.EntitiesContentPatternGetParams, opts ...dp.ClientOption) (*dp.EntitiesContentPatternGetOK, error)
}

// Module registers the data_protection tools. It holds only the shared,
// concurrency-safe Falcon client and configuration; handlers are stateless and
// reentrant. Logger must be non-nil.
type Module struct {
	API         dataProtectionAPI
	Concurrency int // bounds concurrent detail fetches
	Logger      *slog.Logger
}

// Name reports the module name.
func (m *Module) Name() string { return "data_protection" }

// Description reports a one-line summary of the module.
func (m *Module) Description() string {
	return "Search Falcon Data Protection classifications, policies, and content patterns"
}

// Tool and parameter descriptions, kept 1:1 with the Python falcon-mcp
// data_protection module. The filter descriptions carry backticks that cannot
// live in a jsonschema struct tag, so they are consts applied to the schemas by
// their mutate funcs below.
const (
	searchClassificationsDescription = `Search for Data Protection classifications in your CrowdStrike environment.

Use this to find classification rules that define what sensitive data patterns
to detect. Consult falcon://data-protection/classifications/fql-guide before
constructing filter expressions. Returns full classification details including
content pattern references and rule configuration.`

	searchPoliciesDescription = `Search for Data Protection policies in your CrowdStrike environment.

Use this to find data protection policies by platform, enablement status, or
precedence. Requires a platform_name ('win' or 'mac'). Consult
falcon://data-protection/policies/fql-guide before constructing filter
expressions. Returns full policy details including host groups and
classification assignments.`

	searchContentPatternsDescription = `Search for Data Protection content patterns in your CrowdStrike environment.

Use this to find regex-based content detection patterns by type, category, or
region. Consult falcon://data-protection/content-patterns/fql-guide before
constructing filter expressions. Returns full pattern details including regex
definitions and match thresholds.`

	classificationsFilterDescription = "FQL filter expression. See `falcon://data-protection/classifications/fql-guide` for syntax."
	policiesFilterDescription        = "FQL filter expression. See `falcon://data-protection/policies/fql-guide` for syntax."
	contentPatternsFilterDescription = "FQL filter expression. See `falcon://data-protection/content-patterns/fql-guide` for syntax."

	platformNameDescription = "Required. Platform to query: 'win' or 'mac'."
)

// limitBounds applies the shared limit/offset constraints and default that the
// jsonschema struct-tag syntax cannot express, matching the Python module's
// ge=1, le=500, default=100 on limit and ge=0 on offset.
func limitBounds(s *jsonschema.Schema) {
	s.Properties["limit"].Minimum = jsonschema.Ptr(1.0)
	s.Properties["limit"].Maximum = jsonschema.Ptr(500.0)
	s.Properties["limit"].Default = json.RawMessage(`100`)
	s.Properties["offset"].Minimum = jsonschema.Ptr(0.0)
}

var searchClassificationsSchema = base.SchemaFor[SearchInput](func(s *jsonschema.Schema) {
	s.Properties["filter"].Description = classificationsFilterDescription
	limitBounds(s)
})

var searchPoliciesSchema = base.SchemaFor[SearchPoliciesInput](func(s *jsonschema.Schema) {
	s.Properties["filter"].Description = policiesFilterDescription
	s.Properties["platform_name"].Description = platformNameDescription
	limitBounds(s)
})

var searchContentPatternsSchema = base.SchemaFor[SearchInput](func(s *jsonschema.Schema) {
	s.Properties["filter"].Description = contentPatternsFilterDescription
	limitBounds(s)
})

// RegisterTools registers the data_protection tools into r.
func (m *Module) RegisterTools(r base.Registrar) {
	base.AddTool(r, &mcp.Tool{
		Name:        "search_data_protection_classifications",
		Description: searchClassificationsDescription,
		InputSchema: searchClassificationsSchema,
	}, m.searchClassifications)

	base.AddTool(r, &mcp.Tool{
		Name:        "search_data_protection_policies",
		Description: searchPoliciesDescription,
		InputSchema: searchPoliciesSchema,
	}, m.searchPolicies)

	base.AddTool(r, &mcp.Tool{
		Name:        "search_data_protection_content_patterns",
		Description: searchContentPatternsDescription,
		InputSchema: searchContentPatternsSchema,
	}, m.searchContentPatterns)
}

// RegisterResources publishes the three FQL guides as MCP resources, mirroring
// the Python falcon-mcp data-protection resources.
func (m *Module) RegisterResources(s *mcp.Server) {
	base.TextResource(s, classificationsFQLGuideURI,
		"search_data_protection_classifications_fql_guide",
		"Contains the guide for the `filter` param of the `falcon_search_data_protection_classifications` tool.",
		"text/markdown", classificationsFQLGuide)
	base.TextResource(s, policiesFQLGuideURI,
		"search_data_protection_policies_fql_guide",
		"Contains the guide for the `filter` param of the `falcon_search_data_protection_policies` tool.",
		"text/markdown", policiesFQLGuide)
	base.TextResource(s, contentPatternsFQLGuideURI,
		"search_data_protection_content_patterns_fql_guide",
		"Contains the guide for the `filter` param of the `falcon_search_data_protection_content_patterns` tool.",
		"text/markdown", contentPatternsFQLGuide)
}

// RegisterPrompts is a no-op: the data_protection module exposes no prompts.
func (m *Module) RegisterPrompts(_ *mcp.Server) {}

// SearchInput is the input for the classifications and content-patterns search
// tools, which take the same filter/limit/offset/sort parameters. The json tags
// drive the SDK's unmarshal; the served schema is inferred from these jsonschema
// tags, then augmented with the limit/offset bounds and backtick-bearing filter
// description.
type SearchInput struct {
	Filter string `json:"filter,omitempty" jsonschema:"FQL filter. See the tool's fql-guide resource for syntax."`
	Limit  int    `json:"limit,omitempty" jsonschema:"maximum number of records to return"`
	Offset int    `json:"offset,omitempty" jsonschema:"pagination offset"`
	Sort   string `json:"sort,omitempty" jsonschema:"FQL sort (e.g. name.asc, created_at.desc, modified_at.desc)"`
}

// SearchPoliciesInput is the input for the policies search tool, which requires
// a platform_name in addition to the shared search parameters.
type SearchPoliciesInput struct {
	PlatformName string `json:"platform_name" jsonschema:"Required. Platform to query: 'win' or 'mac'."`
	Filter       string `json:"filter,omitempty" jsonschema:"FQL filter. See the tool's fql-guide resource for syntax."`
	Limit        int    `json:"limit,omitempty" jsonschema:"maximum number of records to return"`
	Offset       int    `json:"offset,omitempty" jsonschema:"pagination offset"`
	Sort         string `json:"sort,omitempty" jsonschema:"FQL sort (e.g. name.asc, precedence.asc, created_at.desc)"`
}

func (m *Module) searchClassifications(ctx context.Context, req *mcp.CallToolRequest, in SearchInput) (*mcp.CallToolResult, base.SearchResult[*models.PolicymanagerExternalClassification], error) {
	var zero base.SearchResult[*models.PolicymanagerExternalClassification]
	m.Logger.Debug("search_data_protection_classifications", "filter", in.Filter, "limit", in.Limit, "offset", in.Offset, "sort", in.Sort)

	params := dp.NewQueriesClassificationGetV2ParamsWithContext(ctx)
	limit := limitOrDefault(in.Limit)
	params.Limit = &limit
	if in.Filter != "" {
		params.Filter = &in.Filter
	}
	if in.Sort != "" {
		params.Sort = &in.Sort
	}
	if in.Offset != 0 {
		offset := int64(in.Offset)
		params.Offset = &offset
	}

	qresp, err := m.API.QueriesClassificationGetV2(params)
	if details, ok := classificationFQLBadRequest(err); ok {
		return nil, base.FQLError[*models.PolicymanagerExternalClassification](details, in.Filter, classificationsFQLGuide), nil
	}
	if e := base.APIError(err, qresp, scopeDataProtectionRead); e != nil {
		return nil, zero, e
	}

	ids := qresp.Payload.Resources
	if len(ids) == 0 {
		return nil, base.Found([]*models.PolicymanagerExternalClassification{}, in.Filter).WithMeta(qresp.Payload.Meta), nil
	}

	got, err := base.FetchDetails(ctx, base.FetchDetailsParams[*models.PolicymanagerExternalClassification]{
		IDs:         ids,
		ChunkSize:   detailBatchSize,
		Concurrency: m.Concurrency,
		Progress:    base.ProgressFunc(ctx, req),
		Fetch: func(ctx context.Context, chunk []string) ([]*models.PolicymanagerExternalClassification, error) {
			p := dp.NewEntitiesClassificationGetV2ParamsWithContext(ctx)
			p.Ids = chunk
			resp, err := m.API.EntitiesClassificationGetV2(p)
			if e := base.APIError(err, resp, scopeDataProtectionRead); e != nil {
				return nil, e
			}
			return resp.Payload.Resources, nil
		},
		// The get endpoint may reorder results; restore the query step's sort.
		// Field verified against the live API: id.
		KeyFn: func(c *models.PolicymanagerExternalClassification) string {
			if c == nil || c.ID == nil {
				return ""
			}
			return *c.ID
		},
	})
	if err != nil {
		return nil, zero, err
	}
	return nil, base.Found(got, in.Filter).WithMeta(qresp.Payload.Meta), nil
}

func (m *Module) searchPolicies(ctx context.Context, req *mcp.CallToolRequest, in SearchPoliciesInput) (*mcp.CallToolResult, base.SearchResult[*models.PolicymanagerExternalPolicy], error) {
	var zero base.SearchResult[*models.PolicymanagerExternalPolicy]
	m.Logger.Debug("search_data_protection_policies", "platform_name", in.PlatformName, "filter", in.Filter, "limit", in.Limit, "offset", in.Offset, "sort", in.Sort)

	params := dp.NewQueriesPolicyGetV2ParamsWithContext(ctx)
	params.PlatformName = in.PlatformName
	limit := limitOrDefault(in.Limit)
	params.Limit = &limit
	if in.Filter != "" {
		params.Filter = &in.Filter
	}
	if in.Sort != "" {
		params.Sort = &in.Sort
	}
	if in.Offset != 0 {
		offset := int64(in.Offset)
		params.Offset = &offset
	}

	qresp, err := m.API.QueriesPolicyGetV2(params)
	if details, ok := policyFQLBadRequest(err); ok {
		return nil, base.FQLError[*models.PolicymanagerExternalPolicy](details, in.Filter, policiesFQLGuide), nil
	}
	if e := base.APIError(err, qresp, scopeDataProtectionRead); e != nil {
		return nil, zero, e
	}

	ids := qresp.Payload.Resources
	if len(ids) == 0 {
		return nil, base.Found([]*models.PolicymanagerExternalPolicy{}, in.Filter).WithMeta(qresp.Payload.Meta), nil
	}

	got, err := base.FetchDetails(ctx, base.FetchDetailsParams[*models.PolicymanagerExternalPolicy]{
		IDs:         ids,
		ChunkSize:   detailBatchSize,
		Concurrency: m.Concurrency,
		Progress:    base.ProgressFunc(ctx, req),
		Fetch: func(ctx context.Context, chunk []string) ([]*models.PolicymanagerExternalPolicy, error) {
			p := dp.NewEntitiesPolicyGetV2ParamsWithContext(ctx)
			p.Ids = chunk
			resp, err := m.API.EntitiesPolicyGetV2(p)
			if e := base.APIError(err, resp, scopeDataProtectionRead); e != nil {
				return nil, e
			}
			return resp.Payload.Resources, nil
		},
		KeyFn: func(p *models.PolicymanagerExternalPolicy) string {
			if p == nil || p.ID == nil {
				return ""
			}
			return *p.ID
		},
	})
	if err != nil {
		return nil, zero, err
	}
	return nil, base.Found(got, in.Filter).WithMeta(qresp.Payload.Meta), nil
}

func (m *Module) searchContentPatterns(ctx context.Context, req *mcp.CallToolRequest, in SearchInput) (*mcp.CallToolResult, base.SearchResult[*models.APIContentPatternV1], error) {
	var zero base.SearchResult[*models.APIContentPatternV1]
	m.Logger.Debug("search_data_protection_content_patterns", "filter", in.Filter, "limit", in.Limit, "offset", in.Offset, "sort", in.Sort)

	params := dp.NewQueriesContentPatternGetV2ParamsWithContext(ctx)
	limit := limitOrDefault(in.Limit)
	params.Limit = &limit
	if in.Filter != "" {
		params.Filter = &in.Filter
	}
	if in.Sort != "" {
		params.Sort = &in.Sort
	}
	if in.Offset != 0 {
		offset := int64(in.Offset)
		params.Offset = &offset
	}

	qresp, err := m.API.QueriesContentPatternGetV2(params)
	if details, ok := contentPatternFQLBadRequest(err); ok {
		return nil, base.FQLError[*models.APIContentPatternV1](details, in.Filter, contentPatternsFQLGuide), nil
	}
	if e := base.APIError(err, qresp, scopeDataProtectionRead); e != nil {
		return nil, zero, e
	}

	ids := qresp.Payload.Resources
	if len(ids) == 0 {
		return nil, base.Found([]*models.APIContentPatternV1{}, in.Filter).WithMeta(qresp.Payload.Meta), nil
	}

	got, err := base.FetchDetails(ctx, base.FetchDetailsParams[*models.APIContentPatternV1]{
		IDs:         ids,
		ChunkSize:   detailBatchSize,
		Concurrency: m.Concurrency,
		Progress:    base.ProgressFunc(ctx, req),
		Fetch: func(ctx context.Context, chunk []string) ([]*models.APIContentPatternV1, error) {
			p := dp.NewEntitiesContentPatternGetParamsWithContext(ctx)
			p.Ids = chunk
			resp, err := m.API.EntitiesContentPatternGet(p)
			if e := base.APIError(err, resp, scopeDataProtectionRead); e != nil {
				return nil, e
			}
			return resp.Payload.Resources, nil
		},
		KeyFn: func(p *models.APIContentPatternV1) string {
			if p == nil || p.ID == nil {
				return ""
			}
			return *p.ID
		},
	})
	if err != nil {
		return nil, zero, err
	}
	return nil, base.Found(got, in.Filter).WithMeta(qresp.Payload.Meta), nil
}

// limitOrDefault returns the caller's limit or defaultLimit when unset.
func limitOrDefault(limit int) int64 {
	if limit == 0 {
		return defaultLimit
	}
	return int64(limit)
}
