package cloud

import (
	"context"

	"github.com/crowdstrike/gofalcon/falcon/client/container_vulnerabilities"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/crowdstrike/falcon-mcp/internal/modules/base"
)

// vulnsAPI is the slice of the gofalcon container_vulnerabilities client this
// module consumes.
type vulnsAPI interface {
	ReadCombinedVulnerabilities(*container_vulnerabilities.ReadCombinedVulnerabilitiesParams, ...container_vulnerabilities.ClientOption) (*container_vulnerabilities.ReadCombinedVulnerabilitiesOK, error)
}

// SearchVulnerabilitiesInput is the input for falcon_search_images_vulnerabilities.
type SearchVulnerabilitiesInput struct {
	Filter string `json:"filter,omitempty" jsonschema:"FQL filter. See the fql-guide resource for syntax."`
	Limit  int    `json:"limit,omitempty" jsonschema:"maximum number of vulnerabilities to return"`
	Offset int    `json:"offset,omitempty" jsonschema:"starting index of overall result set from which to return results"`
	Sort   string `json:"sort,omitempty" jsonschema:"FQL sort (e.g. cvss_score.desc, cps_current_rating.asc)"`
}

var searchImagesVulnerabilitiesSchema = base.SchemaFor[SearchVulnerabilitiesInput](func(s *jsonschema.Schema) {
	s.Properties["filter"].Description = imagesVulnerabilitiesFilterDescription
	s.Properties["sort"].Description = imagesVulnerabilitiesSortDescription
	limitBounds(9999, 10)(s)
})

// searchImagesVulnerabilities queries the container image vulnerabilities
// combined endpoint, which returns full vulnerability records in a single call
// (no two-step detail fetch). This endpoint does not validate FQL filter fields
// server-side (no typed 400), so an unsupported field silently returns empty.
func (m *Module) searchImagesVulnerabilities(ctx context.Context, _ *mcp.CallToolRequest, in SearchVulnerabilitiesInput) (*mcp.CallToolResult, base.SearchResult[*models.ModelsAPIVulnerabilityCombined], error) {
	var zero base.SearchResult[*models.ModelsAPIVulnerabilityCombined]
	m.Logger.Debug("search_images_vulnerabilities", "filter", in.Filter, "limit", in.Limit, "offset", in.Offset, "sort", in.Sort)

	params := container_vulnerabilities.NewReadCombinedVulnerabilitiesParamsWithContext(ctx)
	limit := int64(in.Limit)
	if limit == 0 {
		limit = 10
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

	resp, err := m.Vulns.ReadCombinedVulnerabilities(params)
	if e := base.APIError(err, resp, scopeContainerImageRead); e != nil {
		return nil, zero, e
	}
	return nil, base.Found(resp.Payload.Resources, in.Filter).WithMeta(resp.Payload.Meta), nil
}
