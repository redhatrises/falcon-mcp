// Package quarantine implements the quarantine investigation and remediation
// tools over the gofalcon quarantine client: searching quarantined files,
// previewing action counts, and applying reversible (release/unrelease) or
// destructive (delete) quarantine actions.
//
// Search is a two-step round trip (QueryQuarantineFiles for IDs, then
// GetQuarantineFiles for full records), mirroring the falcon-mcp Python module.
// This is the first ported module to carry mutating actions, so it exercises
// the registry's tool-annotation emission for both non-destructive and
// destructive tools.
package quarantine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"

	"github.com/crowdstrike/gofalcon/falcon/client/quarantine"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/crowdstrike/falcon-mcp/internal/modules/base"
	"github.com/crowdstrike/falcon-mcp/internal/modules/registry"
)

// Factory builds the quarantine module from shared deps. The generated
// aggregator (internal/mcpserver) collects it, so the module needs no init side
// effect.
var Factory registry.Factory = func(d registry.Deps) base.Module {
	return &Module{API: d.API.Quarantine, Concurrency: d.Concurrency, Logger: d.Logger}
}

// defaultLimit is the search page size applied when the caller omits limit.
const defaultLimit = 10

// quarantineBatchSize bounds the number of IDs sent to GetQuarantineFiles per
// detail call, matching the conservative page sizes used by sibling modules.
const quarantineBatchSize = 500

// validRestoreActions are the reversible action values accepted by
// falcon_update_quarantined_files.
var validRestoreActions = map[string]bool{"release": true, "unrelease": true}

// errInvalidInput classifies client-side validation failures in the tools.
var errInvalidInput = errors.New("quarantine: invalid input")

// CrowdStrike API scopes required by this module's operations. Surfaced on a
// 403 via base.APIError, referenced directly at each call site.
var (
	scopeQuarantineRead  = base.Scope{Name: "Quarantined Files", Read: true}
	scopeQuarantineWrite = base.Scope{Name: "Quarantined Files", Write: true}
)

// quarantineAPI is the minimal slice of the gofalcon quarantine client this
// module consumes, declared next to its consumer so handlers can be tested
// against a small fake rather than all of gofalcon.
type quarantineAPI interface {
	QueryQuarantineFiles(params *quarantine.QueryQuarantineFilesParams, opts ...quarantine.ClientOption) (*quarantine.QueryQuarantineFilesOK, error)
	GetQuarantineFiles(params *quarantine.GetQuarantineFilesParams, opts ...quarantine.ClientOption) (*quarantine.GetQuarantineFilesOK, error)
	ActionUpdateCount(params *quarantine.ActionUpdateCountParams, opts ...quarantine.ClientOption) (*quarantine.ActionUpdateCountOK, error)
	UpdateQuarantinedDetectsByIds(params *quarantine.UpdateQuarantinedDetectsByIdsParams, opts ...quarantine.ClientOption) (*quarantine.UpdateQuarantinedDetectsByIdsOK, error)
	UpdateQfByQuery(params *quarantine.UpdateQfByQueryParams, opts ...quarantine.ClientOption) (*quarantine.UpdateQfByQueryOK, error)
}

// Module registers the quarantine tools. It holds only the shared,
// concurrency-safe Falcon client and configuration; handlers are stateless and
// reentrant. Logger must be non-nil.
type Module struct {
	API         quarantineAPI
	Concurrency int
	Logger      *slog.Logger
}

// Name reports the module name.
func (m *Module) Name() string { return "quarantine" }

// Description reports a one-line summary of the module.
func (m *Module) Description() string {
	return "Search quarantine records, preview action counts, and release, unrelease, or delete quarantined files"
}

// searchQuarantinedFilesSchema is the input schema for
// falcon_search_quarantined_files. It is inferred from SearchInput's struct
// tags, then a mutate func adds the limit bounds/default the tag syntax cannot
// express.
var searchQuarantinedFilesSchema = base.SchemaFor[SearchInput](func(s *jsonschema.Schema) {
	s.Properties["limit"].Minimum = jsonschema.Ptr(1.0)
	s.Properties["limit"].Maximum = jsonschema.Ptr(500.0)
	s.Properties["limit"].Default = json.RawMessage(`10`)
	s.Properties["offset"].Minimum = jsonschema.Ptr(0.0)
})

// RegisterTools registers the four quarantine tools into r.
func (m *Module) RegisterTools(r base.Registrar) {
	base.AddTool(r, &mcp.Tool{
		Name: "search_quarantined_files",
		Description: "Search quarantined files in your CrowdStrike environment by host, hash, " +
			"user, or quarantine state, and return full quarantine metadata. Consult " +
			"falcon://quarantine/files/search/fql-guide before constructing filter expressions. " +
			"Returns full quarantine details including hostname, sha256, paths, state, and " +
			"associated alert and detection IDs." +
			" Responses include `pagination.total` (the total number of records matching the filter, " +
			"or null when the API does not report a count) — use it to answer \"how many\" questions.",
		InputSchema: searchQuarantinedFilesSchema,
	}, m.searchQuarantinedFiles)

	base.AddTool(r, &mcp.Tool{
		Name: "preview_quarantine_actions",
		Description: "Estimate how many quarantine records each action would affect for a given " +
			"FQL filter. Use this read-only tool before calling a mutating quarantine action to " +
			"understand the blast radius of a release, unrelease, or delete request. Consult " +
			"falcon://quarantine/files/search/fql-guide before constructing filter expressions. " +
			"Returns a list of action counts keyed by action name.",
	}, m.previewQuarantineActions)

	base.AddTool(r, &mcp.Tool{
		Name: "update_quarantined_files",
		Description: "Apply a reversible quarantine action (release or unrelease) to records " +
			"selected by IDs or filter. Provide `ids` for specific records, or `filter` to select " +
			"by query. Consult falcon://quarantine/files/search/fql-guide before constructing " +
			"filter expressions. Returns success with no records.",
		Annotations: base.MutatingAnnotations(false),
	}, m.updateQuarantinedFiles)

	base.AddTool(r, &mcp.Tool{
		Name: "delete_quarantined_files",
		Description: "Delete quarantine records selected by IDs or filter. This tool is " +
			"destructive and should be used only when quarantine records should be removed rather " +
			"than released. Provide `ids` for specific records, or `filter` to select by query. " +
			"Consult falcon://quarantine/files/search/fql-guide before constructing filter " +
			"expressions. Returns success with no records.",
		Annotations: base.DestructiveAnnotations(true),
	}, m.deleteQuarantinedFiles)
}

// RegisterResources publishes the quarantine search FQL guide as an MCP
// resource, mirroring falcon-mcp's falcon://quarantine/files/search/fql-guide.
func (m *Module) RegisterResources(s *mcp.Server) {
	base.TextResource(s,
		fqlGuideURI,
		"search_quarantined_files_fql_guide",
		"Contains the guide for the `filter` param of quarantine search and filter-based action tools.",
		"text/markdown",
		fqlGuide,
	)
}

// RegisterPrompts is a no-op: the quarantine module exposes no prompts.
func (m *Module) RegisterPrompts(_ *mcp.Server) {}

// SearchInput is the input for falcon_search_quarantined_files.
type SearchInput struct {
	Filter string `json:"filter,omitempty" jsonschema:"FQL filter expression. See falcon://quarantine/files/search/fql-guide for syntax."`
	Limit  int    `json:"limit,omitempty" jsonschema:"maximum number of quarantine file IDs to return (max 500)"`
	Offset int    `json:"offset,omitempty" jsonschema:"starting index of the overall result set from which to return IDs"`
	Sort   string `json:"sort,omitempty" jsonschema:"FQL sort such as date_updated|desc or hostname|asc"`
}

func (m *Module) searchQuarantinedFiles(ctx context.Context, req *mcp.CallToolRequest, in SearchInput) (*mcp.CallToolResult, base.SearchResult[*models.QuarantineQuarantinedFile], error) {
	var zero base.SearchResult[*models.QuarantineQuarantinedFile]
	limit := int64(in.Limit)
	if limit == 0 {
		limit = defaultLimit
	}
	m.Logger.Debug("search_quarantined_files", "filter", in.Filter, "limit", limit, "offset", in.Offset, "sort", in.Sort)

	params := quarantine.NewQueryQuarantineFilesParamsWithContext(ctx)
	params.Limit = &limit
	if in.Filter != "" {
		params.Filter = &in.Filter
	}
	// This endpoint types its offset query param as a string while reporting a
	// numeric offset back in meta.pagination, so the numeric input is formatted
	// here rather than exposing the string form to callers.
	if in.Offset != 0 {
		params.Offset = new(strconv.Itoa(in.Offset))
	}
	if in.Sort != "" {
		params.Sort = &in.Sort
	}

	queryResp, err := m.API.QueryQuarantineFiles(params)
	if e := base.APIError(err, queryResp, scopeQuarantineRead); e != nil {
		return nil, zero, e
	}

	ids := queryResp.Payload.Resources
	m.Logger.Debug("search_quarantined_files query complete", "matched_ids", len(ids))
	if len(ids) == 0 {
		return nil, base.Found([]*models.QuarantineQuarantinedFile{}, in.Filter).WithMeta(queryResp.Payload.Meta), nil
	}

	files, err := m.fetchDetails(ctx, req, ids)
	if err != nil {
		return nil, zero, err
	}
	return nil, base.Found(files, in.Filter).WithMeta(queryResp.Payload.Meta), nil
}

// fetchDetails fetches full quarantine records for the given IDs, chunking and
// fetching concurrently when the set exceeds a single detail call's capacity. It
// emits per-chunk progress notifications when req carries a progress token.
func (m *Module) fetchDetails(ctx context.Context, req *mcp.CallToolRequest, ids []string) ([]*models.QuarantineQuarantinedFile, error) {
	return base.FetchDetails(ctx, base.FetchDetailsParams[*models.QuarantineQuarantinedFile]{
		IDs:         ids,
		ChunkSize:   quarantineBatchSize,
		Concurrency: m.Concurrency,
		Progress:    base.ProgressFunc(ctx, req),
		Fetch: func(ctx context.Context, chunk []string) ([]*models.QuarantineQuarantinedFile, error) {
			params := quarantine.NewGetQuarantineFilesParamsWithContext(ctx)
			params.Body = &models.MsaIdsRequest{Ids: chunk}
			resp, err := m.API.GetQuarantineFiles(params)
			if e := base.APIError(err, resp, scopeQuarantineRead); e != nil {
				return nil, e
			}
			return resp.Payload.Resources, nil
		},
		// GetQuarantineFiles may reorder records; reorder to the query step's
		// sort by the record id field.
		KeyFn: func(f *models.QuarantineQuarantinedFile) string {
			if f == nil {
				return ""
			}
			return f.ID
		},
	})
}

// previewQuarantineActions counts how many records each quarantine action would
// affect for the given filter.
func (m *Module) previewQuarantineActions(ctx context.Context, _ *mcp.CallToolRequest, in PreviewInput) (*mcp.CallToolResult, base.EntitiesResult[*models.MsaAggregationResult], error) {
	var zero base.EntitiesResult[*models.MsaAggregationResult]
	if in.Filter == "" {
		return nil, zero, wrapInvalid("preview quarantine actions", "filter must not be empty")
	}
	m.Logger.Debug("preview_quarantine_actions", "filter", in.Filter)

	params := quarantine.NewActionUpdateCountParamsWithContext(ctx)
	params.Filter = in.Filter

	resp, err := m.API.ActionUpdateCount(params)
	if e := base.APIError(err, resp, scopeQuarantineRead); e != nil {
		return nil, zero, e
	}
	return nil, base.Entities(resp.Payload.Resources).WithMeta(resp.Payload.Meta), nil
}

// PreviewInput is the input for falcon_preview_quarantine_actions.
type PreviewInput struct {
	Filter string `json:"filter" jsonschema:"FQL filter expression. See falcon://quarantine/files/search/fql-guide for syntax."`
}

// normalizeRestoreAction validates and normalizes a reversible quarantine
// action name to lowercase, matching the Python module's semantics.
func normalizeRestoreAction(action string) (string, error) {
	lowered := strings.ToLower(strings.TrimSpace(action))
	if !validRestoreActions[lowered] {
		return "", wrapInvalid("update quarantined files", fmt.Sprintf("unsupported action %q (want release or unrelease)", action))
	}
	return lowered, nil
}

// wrapInvalid builds an errInvalidInput-wrapped error for op with detail.
func wrapInvalid(op, detail string) error {
	return fmt.Errorf("%s: %w: %s", op, errInvalidInput, detail)
}
