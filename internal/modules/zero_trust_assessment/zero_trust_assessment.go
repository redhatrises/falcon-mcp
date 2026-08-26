// Package zerotrustassessment implements the Zero Trust Assessment tools over
// the gofalcon zero_trust_assessment client: search assessments by posture
// score, fetch assessment details by agent ID, and read the tenant-wide audit
// summary.
package zerotrustassessment

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"

	"github.com/crowdstrike/gofalcon/falcon/client/zero_trust_assessment"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/crowdstrike/falcon-mcp/internal/modules/base"
	"github.com/crowdstrike/falcon-mcp/internal/modules/registry"
)

// detailBatchSize is the maximum number of agent IDs fetched per details call.
// GetAssessmentV1 takes IDs as query parameters, so the batch is kept small to
// bound the request URL length.
const detailBatchSize = 100

// defaultLimit is the query page size applied when the caller omits limit. It
// backs both the advertised schema default and the handler fallback so the two
// cannot drift.
const defaultLimit = 100

// sortOrders are the accepted sort_order values for search_zta_assessments. The
// endpoint sorts on score; asc lists the weakest hosts first, desc the
// strongest.
var sortOrders = []string{"asc", "desc"}

// errInvalidInput classifies a caller-side argument error that never reaches the
// Falcon API. It is wrapped with %w so callers and tests can match it.
var errInvalidInput = errors.New("zero trust assessment: invalid input")

// scopeZTARead is the CrowdStrike API scope required by this module's
// operations. Surfaced on a 403 via base.APIError.
var scopeZTARead = base.Scope{Name: "Zero Trust Assessment", Read: true}

// Factory builds the zero trust assessment module from shared deps.
var Factory registry.Factory = func(d registry.Deps) base.Module {
	return &Module{API: d.API.ZeroTrustAssessment, Concurrency: d.Concurrency, Logger: d.Logger}
}

// ztaAPI is the minimal slice of the gofalcon zero_trust_assessment client this
// module consumes, declared next to its consumer for testability.
type ztaAPI interface {
	GetAssessmentsByScoreV1(params *zero_trust_assessment.GetAssessmentsByScoreV1Params, opts ...zero_trust_assessment.ClientOption) (*zero_trust_assessment.GetAssessmentsByScoreV1OK, error)
	GetAssessmentV1(params *zero_trust_assessment.GetAssessmentV1Params, opts ...zero_trust_assessment.ClientOption) (*zero_trust_assessment.GetAssessmentV1OK, error)
	GetAuditV1(params *zero_trust_assessment.GetAuditV1Params, opts ...zero_trust_assessment.ClientOption) (*zero_trust_assessment.GetAuditV1OK, error)
}

// Module registers the Zero Trust Assessment tools. It holds only the shared
// Falcon client and configuration; handlers are stateless and reentrant. Logger
// must be non-nil.
type Module struct {
	API         ztaAPI
	Concurrency int // bounds concurrent detail fetches
	Logger      *slog.Logger
}

// Name reports the module name.
func (m *Module) Name() string { return "zerotrustassessment" }

// Description reports a one-line summary of the module.
func (m *Module) Description() string {
	return "Retrieve Zero Trust Assessment posture scores and hardening signals for hosts"
}

// Tool and parameter descriptions, kept 1:1 with the Python falcon-mcp
// zero_trust_assessment module. Those carrying backticks live as consts applied
// via the schema mutate func, since a jsonschema struct tag cannot hold them.
const (
	searchDescription = `Search Zero Trust Assessment scores and return full assessment details.

Use this to rank hosts by security posture: pass ` + "`max_score`" + ` to list the weakest
hosts, ` + "`min_score`" + ` to list the strongest. Score is the only attribute this tool can
select on, so start from ` + "`falcon_get_zta_assessments`" + ` when you already have an agent
ID (AID) and from ` + "`falcon_search_hosts`" + ` when you have a hostname.
Returns each host's Zero Trust score with its full sensor and OS hardening signals,
in the standard pagination envelope; feed ` + "`pagination.next`" + ` back as ` + "`after`" + `.

Results name hosts only by AID, so pair this with ` + "`falcon_search_hosts`" + ` to report
hostnames. Each record carries a long signal list, so raise ` + "`limit`" + ` deliberately.`

	getDescription = `Get Zero Trust Assessment details for specific hosts by agent ID (AID).

Use this when you already hold an AID: a detection reports one as its ` + "`device_id`" + `, and
` + "`falcon_search_hosts`" + ` resolves a hostname to one. No Zero Trust tool accepts a
hostname, so resolve the name with ` + "`falcon_search_hosts`" + ` first.
Returns ` + "`resources`" + ` holding one record per assessed host — the Zero Trust score plus the
full sensor and OS hardening signals — and ` + "`not_found`" + ` listing the AIDs with no
assessment.

` + "`not_found`" + ` is always present, even when empty, because the API reports an unknown or
never-assessed AID by omitting its record from an otherwise successful response.`

	auditDescription = `Get the tenant-wide Zero Trust Assessment summary.

Use this to answer how the whole tenant scores, rather than which hosts score badly —
it is a single CID-level rollup and carries no per-host data, so reach for
` + "`falcon_search_zta_assessments`" + ` when you need individual hosts.
Returns one record with the assessed host count and average Zero Trust score for the
tenant, broken down by platform.`

	minScoreDescription = "Lowest Zero Trust score to include (0-100). Omit for no lower bound."

	maxScoreDescription = "Highest Zero Trust score to include (0-100). Combine with `min_score` " +
		"to select a range."

	afterDescription = "Pagination token from a previous response's `pagination.next`."

	idsDescription = "One or more agent IDs (AIDs), 1-1000. Lowercase hex, case-sensitive."
)

// searchSchema is the input schema for falcon_search_zta_assessments. It is
// inferred from SearchInput's tags, then a mutate func adds the score bounds,
// the limit bound and default, the sort_order enum, and the backtick-bearing
// descriptions the struct tags cannot express.
var searchSchema = base.SchemaFor[SearchInput](func(s *jsonschema.Schema) {
	s.Properties["min_score"].Description = minScoreDescription
	s.Properties["min_score"].Minimum = jsonschema.Ptr(0.0)
	s.Properties["min_score"].Maximum = jsonschema.Ptr(100.0)
	s.Properties["max_score"].Description = maxScoreDescription
	s.Properties["max_score"].Minimum = jsonschema.Ptr(0.0)
	s.Properties["max_score"].Maximum = jsonschema.Ptr(100.0)
	s.Properties["limit"].Minimum = jsonschema.Ptr(1.0)
	s.Properties["limit"].Maximum = jsonschema.Ptr(1000.0)
	s.Properties["limit"].Default = json.RawMessage(strconv.Itoa(defaultLimit))
	s.Properties["after"].Description = afterDescription
	base.Enum(s, "sort_order", sortOrders, "asc")
})

// getSchema is the input schema for falcon_get_zta_assessments, adding the 1-1000
// length bound the tag syntax cannot express.
var getSchema = base.SchemaFor[GetInput](func(s *jsonschema.Schema) {
	s.Properties["ids"].Description = idsDescription
	s.Properties["ids"].MinItems = jsonschema.Ptr(1)
	s.Properties["ids"].MaxItems = jsonschema.Ptr(1000)
})

// RegisterTools registers the Zero Trust Assessment tools into r.
func (m *Module) RegisterTools(r base.Registrar) {
	base.AddTool(r, &mcp.Tool{
		Name:        "search_zta_assessments",
		Description: searchDescription,
		InputSchema: searchSchema,
	}, m.searchAssessments)

	base.AddTool(r, &mcp.Tool{
		Name:        "get_zta_assessments",
		Description: getDescription,
		InputSchema: getSchema,
	}, m.getAssessments)

	base.AddTool(r, &mcp.Tool{
		Name:        "get_zta_audit",
		Description: auditDescription,
	}, m.getAudit)
}

// RegisterResources is a no-op: search_zta_assessments selects on a numeric
// score range rather than a free-text FQL filter, so there is no filter guide
// to publish.
func (m *Module) RegisterResources(_ *mcp.Server) {}

// RegisterPrompts is a no-op: the module exposes no prompts.
func (m *Module) RegisterPrompts(_ *mcp.Server) {}

// SearchInput is the input for falcon_search_zta_assessments. min_score and
// max_score are pointers so an unset bound is distinguishable from an explicit
// 0, which is a valid (weakest) score.
type SearchInput struct {
	MinScore  *int   `json:"min_score,omitempty" jsonschema:"lowest Zero Trust score to include (0-100)"`
	MaxScore  *int   `json:"max_score,omitempty" jsonschema:"highest Zero Trust score to include (0-100)"`
	Limit     int    `json:"limit,omitempty" jsonschema:"maximum number of hosts to return (max 1000)"`
	After     string `json:"after,omitempty" jsonschema:"pagination token from a previous response"`
	SortOrder string `json:"sort_order,omitempty" jsonschema:"'asc' for weakest first, 'desc' for strongest first"`
}

// GetInput is the input for falcon_get_zta_assessments. ids has no omitempty, so
// schema inference marks it required.
type GetInput struct {
	IDs []string `json:"ids" jsonschema:"one or more agent IDs (AIDs), 1-1000"`
}

// searchResult is the search envelope. It extends the standard search envelope
// with not_found, the AIDs whose assessment vanished between the score query and
// the detail fetch. not_found is omitted when empty, matching the Python module.
type searchResult struct {
	base.SearchResult[*models.DomainSignalProperties]
	NotFound []string `json:"not_found,omitempty"`
}

// getResult is the get-by-IDs envelope. not_found is always present — even
// empty — because the API reports an unknown or never-assessed AID by omitting
// its record rather than erroring.
type getResult struct {
	base.EntitiesResult[*models.DomainSignalProperties]
	NotFound []string `json:"not_found"`
}

func (m *Module) searchAssessments(ctx context.Context, req *mcp.CallToolRequest, in SearchInput) (*mcp.CallToolResult, searchResult, error) {
	var zero searchResult

	order := in.SortOrder
	if order == "" {
		order = "asc"
	}
	if order != "asc" && order != "desc" {
		return nil, zero, fmt.Errorf("%w: invalid sort_order %q: valid values are %s", errInvalidInput, order, strings.Join(sortOrders, ", "))
	}
	if in.MinScore != nil && in.MaxScore != nil && *in.MinScore > *in.MaxScore {
		return nil, zero, fmt.Errorf("%w: min_score (%d) is greater than max_score (%d), so no host can match", errInvalidInput, *in.MinScore, *in.MaxScore)
	}

	limit := int64(in.Limit)
	if limit == 0 {
		limit = defaultLimit
	}
	fql := buildScoreFilter(in.MinScore, in.MaxScore)
	sort := "score|" + order
	m.Logger.Debug("search_zta_assessments", "filter", fql, "limit", limit, "sort", sort, "has_after", in.After != "")

	params := zero_trust_assessment.NewGetAssessmentsByScoreV1ParamsWithContext(ctx)
	params.Filter = fql
	params.Limit = &limit
	params.Sort = &sort
	if in.After != "" {
		params.After = &in.After
	}

	scoreResp, err := m.API.GetAssessmentsByScoreV1(params)
	if e := base.APIError(err, scoreResp, scopeZTARead); e != nil {
		return nil, zero, e
	}

	// The query returns {aid, score} pairs; keep the AIDs in the sorted order.
	aids := make([]string, 0, len(scoreResp.Payload.Resources))
	for _, r := range scoreResp.Payload.Resources {
		if r != nil && r.Aid != nil && *r.Aid != "" {
			aids = append(aids, *r.Aid)
		}
	}
	if len(aids) == 0 {
		return nil, searchResult{SearchResult: base.Found([]*models.DomainSignalProperties{}, fql).WithMeta(scoreResp.Payload.Meta)}, nil
	}

	details, err := m.fetchDetails(ctx, req, aids)
	if err != nil {
		return nil, zero, err
	}

	// A miss here means the host stopped being assessed between the two calls.
	result := searchResult{SearchResult: base.Found(details, fql).WithMeta(scoreResp.Payload.Meta)}
	if missing := missingAIDs(aids, details); len(missing) > 0 {
		result.NotFound = missing
	}
	return nil, result, nil
}

func (m *Module) getAssessments(ctx context.Context, req *mcp.CallToolRequest, in GetInput) (*mcp.CallToolResult, getResult, error) {
	m.Logger.Debug("get_zta_assessments", "ids", len(in.IDs))
	if len(in.IDs) == 0 {
		return nil, getResult{EntitiesResult: base.Entities([]*models.DomainSignalProperties{}), NotFound: []string{}}, nil
	}
	details, err := m.fetchDetails(ctx, req, in.IDs)
	if err != nil {
		return nil, getResult{}, err
	}
	return nil, getResult{
		EntitiesResult: base.Entities(details),
		NotFound:       missingAIDs(in.IDs, details),
	}, nil
}

func (m *Module) getAudit(ctx context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, base.EntitiesResult[*models.CommonCIDAuditResult], error) {
	m.Logger.Debug("get_zta_audit")
	params := zero_trust_assessment.NewGetAuditV1ParamsWithContext(ctx)
	resp, err := m.API.GetAuditV1(params)
	if e := base.APIError(err, resp, scopeZTARead); e != nil {
		return nil, base.EntitiesResult[*models.CommonCIDAuditResult]{}, e
	}
	return nil, base.Entities(resp.Payload.Resources).WithMeta(resp.Payload.Meta), nil
}

// fetchDetails fetches full assessment records for the given AIDs, chunking and
// fetching concurrently when the set exceeds a single details call's capacity,
// and reordering results back into the requested AID order.
func (m *Module) fetchDetails(ctx context.Context, req *mcp.CallToolRequest, aids []string) ([]*models.DomainSignalProperties, error) {
	return base.FetchDetails(ctx, base.FetchDetailsParams[*models.DomainSignalProperties]{
		IDs:         aids,
		ChunkSize:   detailBatchSize,
		Concurrency: m.Concurrency,
		Progress:    base.ProgressFunc(ctx, req),
		Fetch: func(ctx context.Context, chunk []string) ([]*models.DomainSignalProperties, error) {
			params := zero_trust_assessment.NewGetAssessmentV1ParamsWithContext(ctx)
			params.Ids = chunk
			resp, err := m.API.GetAssessmentV1(params)
			if e := base.APIError(err, resp, scopeZTARead); e != nil {
				return nil, e
			}
			return resp.Payload.Resources, nil
		},
		KeyFn: func(a *models.DomainSignalProperties) string {
			if a == nil || a.Aid == nil {
				return ""
			}
			return *a.Aid
		},
	})
}

// buildScoreFilter renders the FQL the query endpoint requires from typed score
// bounds. The endpoint rejects a missing filter, and score:>=0 matches every
// assessed host, so an unbounded search falls back to that.
func buildScoreFilter(minScore, maxScore *int) string {
	parts := make([]string, 0, 2)
	if minScore != nil {
		parts = append(parts, "score:>="+strconv.Itoa(*minScore))
	}
	if maxScore != nil {
		parts = append(parts, "score:<="+strconv.Itoa(*maxScore))
	}
	if len(parts) == 0 {
		return "score:>=0"
	}
	return strings.Join(parts, "+")
}

// missingAIDs returns the requested AIDs that came back with no assessment,
// preserving request order. It always returns a non-nil slice.
func missingAIDs(requested []string, records []*models.DomainSignalProperties) []string {
	found := make(map[string]struct{}, len(records))
	for _, r := range records {
		if r != nil && r.Aid != nil {
			found[*r.Aid] = struct{}{}
		}
	}
	missing := make([]string, 0)
	for _, aid := range requested {
		if _, ok := found[aid]; !ok {
			missing = append(missing, aid)
		}
	}
	return missing
}
