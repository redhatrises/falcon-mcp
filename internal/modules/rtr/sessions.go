package rtr

import (
	"context"
	"errors"
	"fmt"
	"strconv"

	"github.com/crowdstrike/gofalcon/falcon/client/real_time_response"
	"github.com/crowdstrike/gofalcon/falcon/client/real_time_response_audit"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/crowdstrike/falcon-mcp/internal/modules/base"
)

// validAggregateTypes are the accepted aggregate_type values, mirroring the
// Python module's Literal["terms", "date_range"] constraint.
var validAggregateTypes = map[string]bool{"terms": true, "date_range": true}

// defaultSearchLimit is the session-search page size applied when the caller
// omits limit, matching the Python module's default of 10.
const defaultSearchLimit = 10

// defaultAggregateSize is the terms-aggregation bucket count applied when the
// caller omits size.
const defaultAggregateSize = 10

// SearchSessionsInput is the input for falcon_search_rtr_sessions.
type SearchSessionsInput struct {
	Filter string `json:"filter,omitempty" jsonschema:"FQL filter. See falcon://rtr/sessions/search/fql-guide for syntax (e.g. hostname:'BRR-WB-LIB-22', aid:'2c5c...')."`
	Limit  int    `json:"limit,omitempty" jsonschema:"maximum number of RTR session IDs to return (max 5000)"`
	Offset int    `json:"offset,omitempty" jsonschema:"starting index of overall result set from which to return IDs"`
	Sort   string `json:"sort,omitempty" jsonschema:"RTR session FQL sort using dot syntax (e.g. created_at.desc, hostname.asc)"`
}

func (m *Module) searchSessions(ctx context.Context, req *mcp.CallToolRequest, in SearchSessionsInput) (*mcp.CallToolResult, base.SearchResult[*models.DomainSession], error) {
	var zero base.SearchResult[*models.DomainSession]
	limit := int64(in.Limit)
	if limit == 0 {
		limit = defaultSearchLimit
	}
	m.Logger.Debug("search_rtr_sessions", "filter", in.Filter, "limit", limit, "offset", in.Offset, "sort", in.Sort)

	params := real_time_response.NewRTRListAllSessionsParamsWithContext(ctx)
	params.Limit = &limit
	if in.Filter != "" {
		params.Filter = &in.Filter
	}
	if in.Offset != 0 {
		// RTRListAllSessions types offset as an opaque *string token, not an int.
		offset := strconv.Itoa(in.Offset)
		params.Offset = &offset
	}
	if in.Sort != "" {
		params.Sort = &in.Sort
	}

	queryResp, err := m.API.RTRListAllSessions(params)
	if err != nil {
		if details, ok := listAllSessionsFQLBadRequest(err); ok {
			return nil, base.FQLError[*models.DomainSession](details, in.Filter, sessionsFQLGuide), nil
		}
	}
	if e := base.APIError(err, queryResp, scopeRTRRead); e != nil {
		return nil, zero, e
	}

	ids := queryResp.Payload.Resources
	m.Logger.Debug("search_rtr_sessions query complete", "matched_ids", len(ids))
	if len(ids) == 0 {
		return nil, base.Found([]*models.DomainSession{}, in.Filter), nil
	}
	sessions, err := m.fetchSessionDetails(ctx, req, ids)
	if err != nil {
		return nil, zero, err
	}
	return nil, base.Found(sessions, in.Filter), nil
}

// SearchAuditSessionsInput is the input for falcon_search_rtr_audit_sessions.
type SearchAuditSessionsInput struct {
	Filter          string `json:"filter,omitempty" jsonschema:"FQL filter. See falcon://rtr/audit/sessions/search/fql-guide for syntax (e.g. created_at:>'now-7d')."`
	Limit           int    `json:"limit,omitempty" jsonschema:"maximum number of RTR audit session records to return (max 1000)"`
	Offset          int    `json:"offset,omitempty" jsonschema:"starting index of the audit result set"`
	Sort            string `json:"sort,omitempty" jsonschema:"RTR audit sort using pipe syntax (e.g. created_at|desc, updated_at|asc)"`
	WithCommandInfo bool   `json:"with_command_info,omitempty" jsonschema:"include command IDs and command log fields in the audit response"`
}

func (m *Module) searchAuditSessions(ctx context.Context, _ *mcp.CallToolRequest, in SearchAuditSessionsInput) (*mcp.CallToolResult, base.SearchResult[*models.DomainSession], error) {
	var zero base.SearchResult[*models.DomainSession]
	limit := in.Limit
	if limit == 0 {
		limit = defaultSearchLimit
	}
	m.Logger.Debug("search_rtr_audit_sessions", "filter", in.Filter, "limit", limit, "offset", in.Offset, "sort", in.Sort, "with_command_info", in.WithCommandInfo)

	params := real_time_response_audit.NewRTRAuditSessionsParamsWithContext(ctx)
	// RTRAuditSessions types both limit and offset as opaque *string, not int.
	limitStr := strconv.Itoa(limit)
	params.Limit = &limitStr
	if in.Filter != "" {
		params.Filter = &in.Filter
	}
	if in.Offset != 0 {
		offset := strconv.Itoa(in.Offset)
		params.Offset = &offset
	}
	if in.Sort != "" {
		params.Sort = &in.Sort
	}
	if in.WithCommandInfo {
		params.WithCommandInfo = &in.WithCommandInfo
	}

	resp, err := m.Audit.RTRAuditSessions(params)
	if err != nil {
		if details, ok := auditSessionsFQLBadRequest(err); ok {
			return nil, base.FQLError[*models.DomainSession](details, in.Filter, auditFQLGuide), nil
		}
	}
	if e := base.APIError(err, resp, scopeRTRAudit); e != nil {
		return nil, zero, e
	}

	sessions := resp.Payload.Resources
	m.Logger.Debug("search_rtr_audit_sessions query complete", "matched", len(sessions))
	return nil, base.Found(sessions, in.Filter), nil
}

// AggregateInput is the input for falcon_aggregate_rtr_sessions.
type AggregateInput struct {
	Field         string              `json:"field" jsonschema:"RTR session field to aggregate (e.g. hostname, user_id, origin, base_command, created_at)"`
	AggregateType string              `json:"aggregate_type,omitempty" jsonschema:"aggregation type: terms for top values or date_range for time buckets (default terms)"`
	Name          string              `json:"name,omitempty" jsonschema:"friendly name for the aggregation returned by Falcon (default rtr_session_aggregation)"`
	Filter        string              `json:"filter,omitempty" jsonschema:"FQL filter to scope the aggregation (e.g. created_at:>'now-7d')"`
	Size          int                 `json:"size,omitempty" jsonschema:"maximum buckets to return for terms aggregations (max 1000)"`
	Interval      string              `json:"interval,omitempty" jsonschema:"interval for date_range aggregations (e.g. day, hour)"`
	DateRanges    []map[string]string `json:"date_ranges,omitempty" jsonschema:"date ranges for date_range aggregations (e.g. [{\"from\":\"now-7d\",\"to\":\"now\"}])"`
}

func (m *Module) aggregateSessions(ctx context.Context, _ *mcp.CallToolRequest, in AggregateInput) (*mcp.CallToolResult, base.EntitiesResult[*models.MsaAggregationResult], error) {
	var zero base.EntitiesResult[*models.MsaAggregationResult]
	if in.Field == "" {
		return nil, zero, wrapInvalid("aggregate rtr sessions", "field must not be empty")
	}
	aggType := in.AggregateType
	if aggType == "" {
		aggType = "terms"
	}
	if !validAggregateTypes[aggType] {
		return nil, zero, wrapInvalid("aggregate rtr sessions", fmt.Sprintf("invalid aggregate_type %q (want terms or date_range)", aggType))
	}
	name := in.Name
	if name == "" {
		name = "rtr_session_aggregation"
	}
	size := int32(defaultAggregateSize)
	if in.Size > 0 {
		// The schema bounds size to 1..1000; clamp defensively so the int->int32
		// conversion cannot overflow regardless of client input.
		if in.Size > 1000 {
			size = 1000
		} else {
			size = int32(in.Size)
		}
	}
	m.Logger.Debug("aggregate_rtr_sessions", "field", in.Field, "type", aggType, "filter", in.Filter, "size", size)

	req := &models.MsaAggregateQueryRequest{
		Field: &in.Field,
		Type:  &aggType,
		Name:  &name,
		Size:  &size,
	}
	if in.Filter != "" {
		req.Filter = &in.Filter
	}
	if in.Interval != "" {
		req.Interval = &in.Interval
	}
	for _, dr := range in.DateRanges {
		from, to := dr["from"], dr["to"]
		req.DateRanges = append(req.DateRanges, &models.MsaDateRangeSpec{From: &from, To: &to})
	}

	params := real_time_response.NewRTRAggregateSessionsParamsWithContext(ctx)
	params.Body = []*models.MsaAggregateQueryRequest{req}

	resp, err := m.API.RTRAggregateSessions(params)
	if e := base.APIError(err, resp, scopeRTRRead); e != nil {
		return nil, zero, e
	}
	return nil, base.Entities(resp.Payload.Resources), nil
}

// GetSessionDetailsInput is the input for falcon_get_rtr_session_details.
type GetSessionDetailsInput struct {
	IDs []string `json:"ids" jsonschema:"RTR session IDs to retrieve details for"`
}

func (m *Module) getSessionDetails(ctx context.Context, req *mcp.CallToolRequest, in GetSessionDetailsInput) (*mcp.CallToolResult, base.EntitiesResult[*models.DomainSession], error) {
	m.Logger.Debug("get_rtr_session_details", "ids", len(in.IDs))
	if len(in.IDs) == 0 {
		return nil, base.Entities([]*models.DomainSession{}), nil
	}
	sessions, err := m.fetchSessionDetails(ctx, req, in.IDs)
	if err != nil {
		return nil, base.EntitiesResult[*models.DomainSession]{}, err
	}
	return nil, base.Entities(sessions), nil
}

// ListFilesInput is the input for falcon_list_rtr_session_files.
type ListFilesInput struct {
	SessionID string `json:"session_id" jsonschema:"RTR session ID to retrieve extracted session files for (required)"`
}

func (m *Module) listSessionFiles(ctx context.Context, _ *mcp.CallToolRequest, in ListFilesInput) (*mcp.CallToolResult, base.EntitiesResult[*models.DomainFileV2], error) {
	var zero base.EntitiesResult[*models.DomainFileV2]
	if in.SessionID == "" {
		return nil, zero, wrapInvalid("list rtr session files", "session_id must not be empty")
	}
	m.Logger.Debug("list_rtr_session_files", "session_id", in.SessionID)

	params := real_time_response.NewRTRListFilesV2ParamsWithContext(ctx)
	params.SessionID = in.SessionID

	resp, err := m.API.RTRListFilesV2(params)
	if e := base.APIError(err, resp, scopeRTRWrite); e != nil {
		return nil, zero, e
	}
	return nil, base.Entities(resp.Payload.Resources), nil
}

// fetchSessionDetails fetches full session records for the given session IDs,
// chunking and fetching concurrently when the set exceeds a single
// RTRListSessions call's capacity. It emits per-chunk progress notifications
// when req carries a progress token, and restores the query step's sort order
// (RTRListSessions may reorder results) via KeyFn on DomainSession.ID.
func (m *Module) fetchSessionDetails(ctx context.Context, req *mcp.CallToolRequest, ids []string) ([]*models.DomainSession, error) {
	return base.FetchDetails(ctx, base.FetchDetailsParams[*models.DomainSession]{
		IDs:         ids,
		ChunkSize:   sessionBatchSize,
		Concurrency: m.Concurrency,
		Progress:    base.ProgressFunc(ctx, req),
		Fetch: func(ctx context.Context, chunk []string) ([]*models.DomainSession, error) {
			params := real_time_response.NewRTRListSessionsParamsWithContext(ctx)
			params.Body = &models.MsaIdsRequest{Ids: chunk}
			resp, err := m.API.RTRListSessions(params)
			if e := base.APIError(err, resp, scopeRTRRead); e != nil {
				return nil, e
			}
			return resp.Payload.Resources, nil
		},
		// RTRListSessions may reorder sessions; reorder to the query step's sort.
		// Field verified against the live API: id.
		KeyFn: func(s *models.DomainSession) string {
			if s == nil || s.ID == nil {
				return ""
			}
			return *s.ID
		},
	})
}

// listAllSessionsFQLBadRequest reports whether err is a 400-class
// RTRListAllSessions error and, if so, extracts the API error details for an
// FQL-error response. RTRListAllSessions validates filters server-side and
// returns a typed 400 (verified live), so this path fires on a bad filter.
//
// Unlike most gofalcon operations, the BadRequest payload is a single
// *models.DomainAPIError (flat Code/Message), not a wrapper carrying an Errors
// slice, so it is adapted through domainAPIErrToDetails rather than
// base.FQLErrorDetails.
func listAllSessionsFQLBadRequest(err error) ([]base.FQLErrorDetail, bool) {
	var badReq *real_time_response.RTRListAllSessionsBadRequest
	if !errors.As(err, &badReq) {
		return nil, false
	}
	return domainAPIErrToDetails(badReq.Payload), true
}

// auditSessionsFQLBadRequest is the audit-search counterpart of
// listAllSessionsFQLBadRequest.
func auditSessionsFQLBadRequest(err error) ([]base.FQLErrorDetail, bool) {
	var badReq *real_time_response_audit.RTRAuditSessionsBadRequest
	if !errors.As(err, &badReq) {
		return nil, false
	}
	return domainAPIErrToDetails(badReq.Payload), true
}

// domainAPIErrToDetails flattens a gofalcon *models.DomainAPIError into the
// base.FQLErrorDetail slice an FQL-error SearchResult carries. DomainAPIError
// carries a single flat Code/Message pair (no Errors slice), so this yields one
// detail — or none when the payload or its fields are absent.
func domainAPIErrToDetails(e *models.DomainAPIError) []base.FQLErrorDetail {
	if e == nil {
		return nil
	}
	var code int32
	if e.Code != nil {
		code = *e.Code
	}
	var msg string
	if e.Message != nil {
		msg = *e.Message
	}
	return []base.FQLErrorDetail{{Code: code, Message: msg}}
}
