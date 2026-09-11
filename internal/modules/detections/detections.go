// MIT License
//
// Copyright (c) 2026 CrowdStrike
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

// Package detections implements the falcon_search_detections,
// falcon_get_detection_details, and falcon_update_detections tools over the
// gofalcon alerts client. It covers EPP, IDP, XDR, OverWatch, and NG-SIEM
// alerts.
package detections

import (
	"context"
	"errors"
	"log/slog"

	"github.com/crowdstrike/gofalcon/falcon/client/alerts"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/crowdstrike/falcon-mcp/internal/modules/base"
	"github.com/crowdstrike/falcon-mcp/internal/modules/registry"
)

// Factory builds the detections module from shared deps. The generated
// aggregator (internal/mcpserver) collects it, so the module needs no init
// side effect.
var Factory registry.Factory = func(d registry.Deps) base.Module {
	return &Module{API: d.API.Alerts, Concurrency: d.Concurrency, Logger: d.Logger}
}

// alertBatchSize is the maximum number of composite IDs fetched per GetV2 call.
const alertBatchSize = 1000

// alertsAPI is the minimal slice of the gofalcon alerts client this module
// consumes, declared next to its consumer so handlers can be tested against a
// tiny fake rather than all of gofalcon.
type alertsAPI interface {
	QueryV2(params *alerts.QueryV2Params, opts ...alerts.ClientOption) (*alerts.QueryV2OK, error)
	GetV2(params *alerts.GetV2Params, opts ...alerts.ClientOption) (*alerts.GetV2OK, error)
	GetAggregateV2(params *alerts.GetAggregateV2Params, opts ...alerts.ClientOption) (*alerts.GetAggregateV2OK, error)
	UpdateV3(params *alerts.UpdateV3Params, opts ...alerts.ClientOption) (*alerts.UpdateV3OK, error)
}

// CrowdStrike API scopes required by this module's alerts operations. Surfaced
// on a 403 via base.APIError, referenced directly at each call site.
var (
	scopeAlertsRead  = base.Scope{Name: "Alerts", Read: true}
	scopeAlertsWrite = base.Scope{Name: "Alerts", Write: true}
)

// Module registers the detections tools. It holds only the shared, concurrency-
// safe Falcon client and configuration; handlers are stateless and reentrant.
// Logger must be non-nil.
type Module struct {
	API         alertsAPI
	Concurrency int // bounds detail-fetch fan-out
	Logger      *slog.Logger
}

// Name reports the module name.
func (m *Module) Name() string { return "detections" }

// Description reports a one-line summary of the module.
func (m *Module) Description() string {
	return "Search, retrieve, and triage Falcon detections/alerts (EPP, IDP, XDR, OverWatch, NG-SIEM)"
}

// searchDetectionsSchema is the input schema for falcon_search_detections. It is
// inferred from SearchInput's struct tags, then a mutate func adds the limit
// bounds/default and offset minimum the tag syntax cannot express.
var searchDetectionsSchema = base.SearchSchema[SearchInput](base.SearchSchemaOpts{
	MaxLimit:     9999,
	DefaultLimit: 10,
})

// RegisterTools registers the three detection tools into r.
func (m *Module) RegisterTools(r base.Registrar) {
	base.AddTool(r, &mcp.Tool{
		Name: "search_detections",
		Description: "Search for detections/alerts in CrowdStrike Falcon using FQL. " +
			"Use this to discover detections by severity, status, hostname, time range, or other attributes — the general tool for alert and detection queries. " +
			"Covers alerts across all Falcon products: endpoint (EPP), identity (IDP), XDR, OverWatch, and NG-SIEM. " +
			"Consult falcon://detections/search/fql-guide before constructing filter expressions. " +
			"Returns full alert records including process context, device info, tactic/technique details, and threat classification. " +
			"Responses include `pagination.total` (the total number of records matching the filter, " +
			"or null when the API does not report a count) — use it to answer \"how many\" questions.",
		InputSchema: searchDetectionsSchema,
	}, m.searchDetections)

	base.AddTool(r, &mcp.Tool{
		Name: "get_detection_details",
		Description: "Retrieve full details for detection/alert composite IDs you already have. " +
			"Use when you have specific composite ID(s); for discovering detections by criteria (severity, status, hostname, etc.) use falcon_search_detections instead. " +
			"Returns full detection records; alerts hidden from the Falcon UI are omitted when include_hidden is false.",
	}, m.getDetectionDetails)

	base.AddTool(r, &mcp.Tool{
		Name: "aggregate_detections",
		Description: "Count and summarize detections (also called alerts) without retrieving each record. " +
			"Use this for \"how many\" and \"top N\" questions — alerts per severity, status, tactic, or host, distinct host counts, and alert volume over time — instead of paging through falcon_search_detections. Consult falcon://detections/search/fql-guide before constructing filter expressions. " +
			"Returns one aggregation per request holding `buckets`, which key on `label` with a `count`; single-value aggregations (`cardinality`, `max`, `min`, `avg`, `sum`) report their answer as `value` instead.",
		InputSchema: aggregateDetectionsSchema,
	}, m.aggregateDetections)

	base.AddTool(r, &mcp.Tool{
		Name: "update_detections",
		Description: "Update the status, assignment, UI visibility, comments, and tags of one or more detections/alerts. " +
			"Change status (new, in_progress, reopened, closed); assign by UUID, user id, or full name, or unassign; append a comment; show or hide in the UI; or add/remove tags. " +
			"Resolution is tag-based — the conventional tags true_positive, false_positive, or ignored populate the console's Resolution view, so closing without one returns a hint. " +
			"At least one update field beyond ids is required. Requests over 1000 detection IDs are chunked automatically; if a later chunk fails after earlier ones applied, the result carries a partial_success block listing the updated and failed/remaining ids so only the remainder need be retried.",
		Annotations: base.MutatingAnnotations(false),
	}, m.updateDetections)
}

// RegisterResources publishes the detections FQL guide as an MCP resource,
// mirroring falcon-mcp's falcon://detections/search/fql-guide resource.
func (m *Module) RegisterResources(s *mcp.Server) {
	base.TextResource(s,
		fqlGuideURI,
		"search_detections_fql_guide",
		"Contains the guide for the `filter` param of the `falcon_search_detections` tool.",
		"text/markdown",
		fqlGuide,
	)
}

// SearchInput is the input for falcon_search_detections.
type SearchInput struct {
	Filter        string `json:"filter,omitempty" jsonschema:"FQL filter (e.g. severity.desc, status:'new'). See falcon://detections/search/fql-guide for syntax."`
	Limit         int    `json:"limit,omitempty" jsonschema:"maximum results to return"`
	Offset        int    `json:"offset,omitempty" jsonschema:"pagination offset"`
	Q             string `json:"q,omitempty" jsonschema:"free-text metadata search"`
	Sort          string `json:"sort,omitempty" jsonschema:"FQL sort (e.g. timestamp.desc)"`
	IncludeHidden *bool  `json:"include_hidden,omitempty" jsonschema:"include hidden alerts (default true)"`
}

func (m *Module) searchDetections(ctx context.Context, req *mcp.CallToolRequest, in SearchInput) (*mcp.CallToolResult, base.SearchResult[*models.DetectsAlert], error) {
	var zero base.SearchResult[*models.DetectsAlert]
	limit := int64(in.Limit)
	if limit == 0 {
		limit = 10
	}
	m.Logger.Debug("search_detections", "filter", in.Filter, "limit", limit, "offset", in.Offset, "q", in.Q, "sort", in.Sort)
	params := alerts.NewQueryV2ParamsWithContext(ctx)
	params.Limit = &limit
	if in.Filter != "" {
		params.Filter = &in.Filter
	}
	if in.Offset != 0 {
		params.Offset = new(int64(in.Offset))
	}
	if in.Q != "" {
		params.Q = &in.Q
	}
	if in.Sort != "" {
		params.Sort = &in.Sort
	}
	if in.IncludeHidden != nil {
		params.IncludeHidden = in.IncludeHidden
	}

	queryResp, err := m.API.QueryV2(params)
	if err != nil {
		if details, ok := fqlBadRequest(err); ok {
			return nil, base.FQLError[*models.DetectsAlert](details, in.Filter, fqlGuide), nil
		}
	}
	if e := base.APIError(err, queryResp, scopeAlertsRead); e != nil {
		return nil, zero, e
	}

	ids := queryResp.Payload.Resources
	m.Logger.Debug("search_detections query complete", "matched_ids", len(ids))
	if len(ids) == 0 {
		return nil, base.Found([]*models.DetectsAlert{}, in.Filter).WithMeta(queryResp.Payload.Meta), nil
	}

	alertsResult, err := m.fetchDetails(ctx, req, ids, in.IncludeHidden)
	if err != nil {
		return nil, zero, err
	}
	return nil, base.Found(alertsResult, in.Filter).WithMeta(queryResp.Payload.Meta), nil
}

// DetailsInput is the input for falcon_get_detection_details.
type DetailsInput struct {
	IDs           []string `json:"ids" jsonschema:"composite IDs of the detections to retrieve"`
	IncludeHidden *bool    `json:"include_hidden,omitempty" jsonschema:"include hidden alerts (default true)"`
}

func (m *Module) getDetectionDetails(ctx context.Context, req *mcp.CallToolRequest, in DetailsInput) (*mcp.CallToolResult, base.EntitiesResult[*models.DetectsAlert], error) {
	m.Logger.Debug("get_detection_details", "ids", len(in.IDs))
	if len(in.IDs) == 0 {
		return nil, base.Entities([]*models.DetectsAlert{}), nil
	}
	alertsResult, err := m.fetchDetails(ctx, req, in.IDs, in.IncludeHidden)
	if err != nil {
		return nil, base.EntitiesResult[*models.DetectsAlert]{}, err
	}
	return nil, base.Entities(alertsResult), nil
}

// fetchDetails fetches full alert records for the given composite IDs, chunking and
// fetching concurrently when the set exceeds a single GetV2 call's capacity. It
// emits per-chunk progress notifications when req carries a progress token.
func (m *Module) fetchDetails(ctx context.Context, req *mcp.CallToolRequest, ids []string, includeHidden *bool) ([]*models.DetectsAlert, error) {
	return base.FetchDetails(ctx, base.FetchDetailsParams[*models.DetectsAlert]{
		IDs:         ids,
		ChunkSize:   alertBatchSize,
		Concurrency: m.Concurrency,
		Progress:    base.ProgressFunc(ctx, req),
		Fetch: func(ctx context.Context, chunk []string) ([]*models.DetectsAlert, error) {
			params := alerts.NewGetV2ParamsWithContext(ctx)
			params.Body = &models.DetectsapiPostEntitiesAlertsV2Request{CompositeIds: chunk}
			if includeHidden != nil {
				params.IncludeHidden = includeHidden
			}
			resp, err := m.API.GetV2(params)
			if e := base.APIError(err, resp, scopeAlertsRead); e != nil {
				return nil, e
			}
			return resp.Payload.Resources, nil
		},
		// GetV2 returns alerts in arbitrary order; reorder to the query step's
		// sort. Field verified against the live API: composite_id.
		KeyFn: func(a *models.DetectsAlert) string { return base.Deref(a.CompositeID) },
	})
}

// fqlBadRequest reports whether err is a 400-class alerts query error and, if
// so, extracts the API error details for an FQL-error response. gofalcon
// surfaces 400s as a typed *alerts.QueryV2BadRequest whose payload carries the
// errors; classify with errors.As rather than string matching.
func fqlBadRequest(err error) ([]base.FQLErrorDetail, bool) {
	var badReq *alerts.QueryV2BadRequest
	if !errors.As(err, &badReq) || badReq.Payload == nil {
		return nil, false
	}
	return apiErrorDetails(badReq.Payload.Errors), true
}

// apiErrorDetails flattens gofalcon MsaAPIError values into base.FQLErrorDetail.
func apiErrorDetails(errs []*models.MsaAPIError) []base.FQLErrorDetail {
	details := make([]base.FQLErrorDetail, 0, len(errs))
	for _, e := range errs {
		if e == nil {
			continue
		}
		var code int32
		if e.Code != nil {
			code = *e.Code
		}
		var msg string
		if e.Message != nil {
			msg = *e.Message
		}
		details = append(details, base.FQLErrorDetail{Code: code, Message: msg})
	}
	return details
}
