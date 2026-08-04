package cloud

import (
	"context"

	"github.com/crowdstrike/gofalcon/falcon/client/cloud_security_detections"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/crowdstrike/falcon-mcp/internal/modules/base"
)

// detectionsAPI is the slice of the gofalcon cloud_security_detections client
// this module consumes (CSPM IOM findings).
type detectionsAPI interface {
	CspmEvaluationsIomQueries(*cloud_security_detections.CspmEvaluationsIomQueriesParams, ...cloud_security_detections.ClientOption) (*cloud_security_detections.CspmEvaluationsIomQueriesOK, error)
	CspmEvaluationsIomEntities(*cloud_security_detections.CspmEvaluationsIomEntitiesParams, ...cloud_security_detections.ClientOption) (*cloud_security_detections.CspmEvaluationsIomEntitiesOK, error)
}

// SearchIOMFindingsInput is the input for falcon_search_iom_findings.
type SearchIOMFindingsInput struct {
	Filter string `json:"filter,omitempty" jsonschema:"FQL filter. See the fql-guide resource for syntax."`
	Limit  int    `json:"limit,omitempty" jsonschema:"maximum number of IOM findings to return"`
	Offset int    `json:"offset,omitempty" jsonschema:"starting index of overall result set from which to return findings"`
	Sort   string `json:"sort,omitempty" jsonschema:"FQL sort (e.g. severity|desc, last_detected|desc)"`
}

var searchIOMFindingsSchema = base.SchemaFor[SearchIOMFindingsInput](func(s *jsonschema.Schema) {
	s.Properties["filter"].Description = iomFindingsFilterDescription
	s.Properties["sort"].Description = iomFindingsSortDescription
	limitBounds(1000, 100)(s)
})

// searchIOMFindings queries IOM finding IDs, then fetches full IOM entity
// details (GET with query params, batched). The query endpoint validates FQL
// fields server-side and returns a typed 400 for an unknown field.
func (m *Module) searchIOMFindings(ctx context.Context, req *mcp.CallToolRequest, in SearchIOMFindingsInput) (*mcp.CallToolResult, base.SearchResult[*models.EvaluationsEvaluation], error) {
	var zero base.SearchResult[*models.EvaluationsEvaluation]
	m.Logger.Debug("search_iom_findings", "filter", in.Filter, "limit", in.Limit, "offset", in.Offset, "sort", in.Sort)

	params := cloud_security_detections.NewCspmEvaluationsIomQueriesParamsWithContext(ctx)
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

	qresp, err := m.Detections.CspmEvaluationsIomQueries(params)
	if details, ok := iomFQLBadRequest(err); ok {
		return nil, base.FQLError[*models.EvaluationsEvaluation](details, in.Filter, cspmIOMFindingsFQLGuide), nil
	}
	if e := base.APIError(err, qresp, scopeDetectionsRead); e != nil {
		return nil, zero, e
	}

	ids := qresp.Payload.Resources
	if len(ids) == 0 {
		return nil, base.Found([]*models.EvaluationsEvaluation{}, in.Filter).WithMeta(qresp.Payload.Meta), nil
	}

	got, err := base.FetchDetails(ctx, base.FetchDetailsParams[*models.EvaluationsEvaluation]{
		IDs:         ids,
		ChunkSize:   detailBatchSize,
		Concurrency: m.Concurrency,
		Progress:    base.ProgressFunc(ctx, req),
		Fetch: func(ctx context.Context, chunk []string) ([]*models.EvaluationsEvaluation, error) {
			p := cloud_security_detections.NewCspmEvaluationsIomEntitiesParamsWithContext(ctx)
			p.Ids = chunk
			resp, err := m.Detections.CspmEvaluationsIomEntities(p)
			if e := base.APIError(err, resp, scopeDetectionsRead); e != nil {
				return nil, e
			}
			return resp.Payload.Resources, nil
		},
		// The get endpoint may reorder results; restore the query step's sort.
		// Field verified against the live API: id.
		KeyFn: func(e *models.EvaluationsEvaluation) string {
			if e == nil {
				return ""
			}
			return e.ID
		},
	})
	if err != nil {
		return nil, zero, err
	}
	return nil, base.Found(got, in.Filter).WithMeta(qresp.Payload.Meta), nil
}
