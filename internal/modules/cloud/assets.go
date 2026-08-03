package cloud

import (
	"context"
	"encoding/json"

	"github.com/crowdstrike/gofalcon/falcon/client/cloud_security_assets"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/crowdstrike/falcon-mcp/internal/modules/base"
)

// assetsAPI is the slice of the gofalcon cloud_security_assets client this
// module consumes.
type assetsAPI interface {
	CloudSecurityAssetsQueries(*cloud_security_assets.CloudSecurityAssetsQueriesParams, ...cloud_security_assets.ClientOption) (*cloud_security_assets.CloudSecurityAssetsQueriesOK, error)
	CloudSecurityAssetsEntitiesGet(*cloud_security_assets.CloudSecurityAssetsEntitiesGetParams, ...cloud_security_assets.ClientOption) (*cloud_security_assets.CloudSecurityAssetsEntitiesGetOK, error)
}

// SearchCSPMAssetsInput is the input for falcon_search_cspm_assets.
//
// Pagination is cursor-only: pass pagination.next from the previous response as
// after. The endpoint documents offset and after as mutually exclusive, and
// offset as usable only below 10,000, so traversing a large result set has to go
// through the cursor.
type SearchCSPMAssetsInput struct {
	Filter string `json:"filter,omitempty" jsonschema:"FQL filter. See the fql-guide resource for syntax."`
	Limit  int    `json:"limit,omitempty" jsonschema:"maximum number of assets to return"`
	After  string `json:"after,omitempty" jsonschema:"pagination token from a previous response; use with limit to page results"`
	Sort   string `json:"sort,omitempty" jsonschema:"FQL sort (e.g. updated_at.desc, resource_type.asc)"`
}

var searchCSPMAssetsSchema = base.SchemaFor[SearchCSPMAssetsInput](func(s *jsonschema.Schema) {
	s.Properties["filter"].Description = cspmAssetsFilterDescription
	s.Properties["sort"].Description = cspmAssetsSortDescription
	s.Properties["after"].Description = cspmAssetsAfterDescription
	limitBounds(1000, 100)(s)
})

// searchCSPMAssets queries CSPM asset IDs, then fetches full asset entities and
// slims each record to actionable fields. Raw CSPM asset records can be 100+ KB
// each due to compliance benchmark details and raw configuration blobs; slimming
// keeps security posture context while dropping verbose internal data (matching
// the Python module). The query endpoint validates FQL fields server-side and
// returns a typed 400 for an unknown field.
func (m *Module) searchCSPMAssets(ctx context.Context, req *mcp.CallToolRequest, in SearchCSPMAssetsInput) (*mcp.CallToolResult, base.SearchResult[map[string]any], error) {
	var zero base.SearchResult[map[string]any]
	m.Logger.Debug("search_cspm_assets", "filter", in.Filter, "limit", in.Limit, "after", in.After, "sort", in.Sort)

	params := cloud_security_assets.NewCloudSecurityAssetsQueriesParamsWithContext(ctx)
	limit := int64(in.Limit)
	if limit == 0 {
		limit = 100
	}
	params.Limit = &limit
	if in.Filter != "" {
		params.Filter = &in.Filter
	}
	if in.After != "" {
		params.After = &in.After
	}
	if in.Sort != "" {
		params.Sort = &in.Sort
	}

	qresp, err := m.Assets.CloudSecurityAssetsQueries(params)
	if details, ok := assetsFQLBadRequest(err); ok {
		return nil, base.FQLError[map[string]any](details, in.Filter, cspmAssetsFQLGuide), nil
	}
	if e := base.APIError(err, qresp, scopeAssetsRead); e != nil {
		return nil, zero, e
	}

	ids := qresp.Payload.Resources
	if len(ids) == 0 {
		return nil, base.Found([]map[string]any{}, in.Filter).WithMeta(qresp.Payload.Meta), nil
	}

	got, err := base.FetchDetails(ctx, base.FetchDetailsParams[*models.ResourcesCloudResource]{
		IDs:         ids,
		ChunkSize:   detailBatchSize,
		Concurrency: m.Concurrency,
		Progress:    base.ProgressFunc(ctx, req),
		Fetch: func(ctx context.Context, chunk []string) ([]*models.ResourcesCloudResource, error) {
			p := cloud_security_assets.NewCloudSecurityAssetsEntitiesGetParamsWithContext(ctx)
			p.Ids = chunk
			resp, err := m.Assets.CloudSecurityAssetsEntitiesGet(p)
			if e := base.APIError(err, resp, scopeAssetsRead); e != nil {
				return nil, e
			}
			return resp.Payload.Resources, nil
		},
		// The get endpoint may reorder results; restore the query step's sort.
		// Field verified against the live API: id.
		KeyFn: func(a *models.ResourcesCloudResource) string {
			if a == nil {
				return ""
			}
			return a.ID
		},
	})
	if err != nil {
		return nil, zero, err
	}

	slimmed := make([]map[string]any, 0, len(got))
	for _, asset := range got {
		if s := slimCSPMAsset(asset); s != nil {
			slimmed = append(slimmed, s)
		}
	}
	return nil, base.Found(slimmed, in.Filter).WithMeta(qresp.Payload.Meta), nil
}

// keepTopLevel is the set of CSPM asset top-level fields retained by slimCSPMAsset.
var keepTopLevel = map[string]struct{}{
	"id": {}, "arn": {}, "resource_id": {}, "resource_name": {},
	"resource_type": {}, "resource_type_name": {}, "account_id": {},
	"account_name": {}, "region": {}, "zone": {}, "cloud_provider": {},
	"service": {}, "service_category": {}, "active": {}, "first_seen": {},
	"updated_at": {}, "creation_time": {}, "tags": {}, "resource_url": {},
	"relationships": {},
}

// cloudContextScalars is the set of cloud_context scalar fields retained.
var cloudContextScalars = []string{
	"cspm_license", "publicly_exposed", "managed_by", "has_tags",
	"instance_id", "instance_state", "open_cloud_risks", "scan_type",
	"data_classifications",
}

// detectionsKeep is the set of cloud_context.detections fields retained.
var detectionsKeep = []string{
	"iom_counts", "ioa_counts", "severities", "highest_severity", "resource_url",
}

// slimCSPMAsset strips bloated fields from a CSPM asset record to reduce response
// size, mirroring the Python module. It marshals the typed model to a generic map
// (so the polymorphic AdditionalProperties fields flatten out), then keeps only
// the actionable top-level fields plus a trimmed cloud_context. Returns nil only
// when the asset cannot be represented as an object.
func slimCSPMAsset(asset *models.ResourcesCloudResource) map[string]any {
	if asset == nil {
		return nil
	}
	b, err := json.Marshal(asset)
	if err != nil {
		return nil
	}
	var full map[string]any
	if err := json.Unmarshal(b, &full); err != nil {
		return nil
	}

	slimmed := make(map[string]any, len(keepTopLevel)+1)
	for k, v := range full {
		if _, ok := keepTopLevel[k]; ok {
			slimmed[k] = v
		}
	}
	if ctx, ok := full["cloud_context"].(map[string]any); ok {
		slimmed["cloud_context"] = slimCloudContext(ctx)
	}
	return slimmed
}

// slimCloudContext keeps the security-relevant summary from cloud_context and
// strips benchmark bloat, mirroring the Python module.
func slimCloudContext(ctx map[string]any) map[string]any {
	slimmed := make(map[string]any)
	for _, key := range cloudContextScalars {
		if v, ok := ctx[key]; ok {
			slimmed[key] = v
		}
	}
	// Host info (platform, OS, state) — small and useful.
	if host, ok := ctx["host"]; ok {
		slimmed["host"] = host
	}
	// Detections — keep counts/severity, strip rule IDs and benchmark objects.
	if detections, ok := ctx["detections"].(map[string]any); ok {
		trimmed := make(map[string]any)
		for _, k := range detectionsKeep {
			if v, ok := detections[k]; ok {
				trimmed[k] = v
			}
		}
		slimmed["detections"] = trimmed
	}
	// Insights — keep external boolean flags, drop verbose details.
	if insights, ok := ctx["insights"].(map[string]any); ok {
		if external, ok := insights["external"]; ok && external != nil {
			slimmed["insights"] = map[string]any{"external": external}
		}
	}
	return slimmed
}
