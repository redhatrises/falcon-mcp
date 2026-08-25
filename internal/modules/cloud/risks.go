package cloud

import (
	"context"
	"strconv"

	"github.com/crowdstrike/gofalcon/falcon/client/cloud_security"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/crowdstrike/falcon-mcp/internal/modules/base"
)

// cloudSecAPI is the slice of the gofalcon cloud_security client this module
// consumes (combined cloud risks and cloud groups).
type cloudSecAPI interface {
	CombinedCloudRisks(*cloud_security.CombinedCloudRisksParams, ...cloud_security.ClientOption) (*cloud_security.CombinedCloudRisksOK, error)
	ListCloudGroupsExternal(*cloud_security.ListCloudGroupsExternalParams, ...cloud_security.ClientOption) (*cloud_security.ListCloudGroupsExternalOK, error)
	ListCloudGroupsByIDExternal(*cloud_security.ListCloudGroupsByIDExternalParams, ...cloud_security.ClientOption) (*cloud_security.ListCloudGroupsByIDExternalOK, error)
}

// --- Cloud risks ---

// SearchCloudRisksInput is the input for falcon_search_cloud_risks.
type SearchCloudRisksInput struct {
	Filter string `json:"filter,omitempty" jsonschema:"FQL filter. See the fql-guide resource for syntax."`
	Limit  int    `json:"limit,omitempty" jsonschema:"maximum number of risks to return"`
	Offset int    `json:"offset,omitempty" jsonschema:"starting index of overall result set from which to return results"`
	Sort   string `json:"sort,omitempty" jsonschema:"FQL sort (e.g. severity.desc, first_seen.desc)"`
}

var searchCloudRisksSchema = base.SchemaFor[SearchCloudRisksInput](func(s *jsonschema.Schema) {
	s.Properties["filter"].Description = cloudRisksFilterDescription
	s.Properties["sort"].Description = cloudRisksSortDescription
	limitBounds(1000, 100)(s)
})

// searchCloudRisks queries the combined cloud risks endpoint, which returns full
// risk records in a single call (no two-step detail fetch). The endpoint
// validates FQL fields server-side and returns a typed 400 for an unknown field.
func (m *Module) searchCloudRisks(ctx context.Context, _ *mcp.CallToolRequest, in SearchCloudRisksInput) (*mcp.CallToolResult, base.SearchResult[*models.RisksUnionCloudRisk], error) {
	var zero base.SearchResult[*models.RisksUnionCloudRisk]
	m.Logger.Debug("search_cloud_risks", "filter", in.Filter, "limit", in.Limit, "offset", in.Offset, "sort", in.Sort)

	params := cloud_security.NewCombinedCloudRisksParamsWithContext(ctx)
	limit := int64(in.Limit)
	if limit == 0 {
		limit = 100
	}
	params.Limit = &limit
	if in.Filter != "" {
		params.Filter = &in.Filter
	}
	if in.Offset != 0 {
		params.Offset = new(int64(in.Offset))
	}
	if in.Sort != "" {
		params.Sort = &in.Sort
	}

	resp, err := m.CloudSec.CombinedCloudRisks(params)
	if details, ok := risksFQLBadRequest(err); ok {
		return nil, base.FQLError[*models.RisksUnionCloudRisk](details, in.Filter, cloudRisksFQLGuide), nil
	}
	if e := base.APIError(err, resp, scopeRisksRead); e != nil {
		return nil, zero, e
	}
	return nil, base.Found(resp.Payload.Resources, in.Filter).WithMeta(resp.Payload.Meta), nil
}

// --- Cloud groups ---

// SearchCloudGroupsInput is the input for falcon_search_cloud_groups.
type SearchCloudGroupsInput struct {
	Filter string `json:"filter,omitempty" jsonschema:"FQL filter. See the tool description for supported fields."`
	Limit  int    `json:"limit,omitempty" jsonschema:"maximum number of cloud groups to return"`
	Offset int    `json:"offset,omitempty" jsonschema:"starting index of overall result set from which to return results"`
	Sort   string `json:"sort,omitempty" jsonschema:"sort groups (e.g. name.asc, created_at.desc)"`
}

var searchCloudGroupsSchema = base.SchemaFor[SearchCloudGroupsInput](func(s *jsonschema.Schema) {
	s.Properties["filter"].Description = cloudGroupsFilterDescription
	s.Properties["sort"].Description = cloudGroupsSortDescription
	limitBounds(500, 100)(s)
})

// searchCloudGroups lists cloud groups, returning full group records in a single
// call. The ListCloudGroupsExternal endpoint takes limit/offset as string query
// params (a gofalcon quirk for this operation), so they are converted here.
func (m *Module) searchCloudGroups(ctx context.Context, _ *mcp.CallToolRequest, in SearchCloudGroupsInput) (*mcp.CallToolResult, base.SearchResult[*models.AssetgroupmanagerV1CloudGroup], error) {
	var zero base.SearchResult[*models.AssetgroupmanagerV1CloudGroup]
	m.Logger.Debug("search_cloud_groups", "filter", in.Filter, "limit", in.Limit, "offset", in.Offset, "sort", in.Sort)

	params := cloud_security.NewListCloudGroupsExternalParamsWithContext(ctx)
	limit := in.Limit
	if limit == 0 {
		limit = 100
	}
	params.Limit = new(strconv.Itoa(limit))
	if in.Filter != "" {
		params.Filter = &in.Filter
	}
	if in.Offset != 0 {
		params.Offset = new(strconv.Itoa(in.Offset))
	}
	if in.Sort != "" {
		params.Sort = &in.Sort
	}

	resp, err := m.CloudSec.ListCloudGroupsExternal(params)
	if e := base.APIError(err, resp, scopeGroupsRead); e != nil {
		return nil, zero, e
	}
	return nil, base.Found(resp.Payload.Resources, in.Filter).WithMeta(resp.Payload.Meta), nil
}

// GetCloudGroupsInput is the input for falcon_get_cloud_groups.
type GetCloudGroupsInput struct {
	IDs []string `json:"ids" jsonschema:"One or more cloud group IDs to retrieve. Find IDs with falcon_search_cloud_groups."`
}

// getCloudGroups fetches full cloud group records by ID. The endpoint takes IDs
// as query parameters.
func (m *Module) getCloudGroups(ctx context.Context, _ *mcp.CallToolRequest, in GetCloudGroupsInput) (*mcp.CallToolResult, base.EntitiesResult[*models.AssetgroupmanagerV1CloudGroup], error) {
	var zero base.EntitiesResult[*models.AssetgroupmanagerV1CloudGroup]
	m.Logger.Debug("get_cloud_groups", "ids", len(in.IDs))
	if len(in.IDs) == 0 {
		return nil, base.Entities([]*models.AssetgroupmanagerV1CloudGroup{}), nil
	}

	params := cloud_security.NewListCloudGroupsByIDExternalParamsWithContext(ctx)
	params.Ids = in.IDs
	resp, err := m.CloudSec.ListCloudGroupsByIDExternal(params)
	if e := base.APIError(err, resp, scopeGroupsRead); e != nil {
		return nil, zero, e
	}
	return nil, base.Entities(resp.Payload.Resources).WithMeta(resp.Payload.Meta), nil
}
