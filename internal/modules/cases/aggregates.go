package cases

import (
	"context"
	"errors"
	"strings"

	"github.com/crowdstrike/gofalcon/falcon/client/case_files"
	"github.com/crowdstrike/gofalcon/falcon/client/case_management"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/crowdstrike/falcon-mcp/internal/modules/base"
)

// AggregateInput is the input for the four case-configuration aggregate
// tools (SLAs, templates, access tags, notification groups). They share one
// request shape; only the aggregated field set differs, expressed through the
// per-tool schema description rather than a distinct struct.
type AggregateInput struct {
	Field   string `json:"field" jsonschema:"Field to aggregate on. Supported: name, id, cid, created_by_name, updated_by_name, created_timestamp, updated_timestamp."`
	AggType string `json:"agg_type,omitempty" jsonschema:"Aggregation type. 'terms' counts records per distinct value; 'date_range' counts records per date_ranges bucket."`
	Filter  string `json:"filter,omitempty" jsonschema:"FQL filter expression. See falcon://cases/aggregates/fql-guide for syntax."`
	Size    int32  `json:"size,omitempty" jsonschema:"Maximum number of buckets to return. Omit for all buckets."`
	// The from_ wire name (trailing underscore) mirrors the Python module, which
	// exposes from_ with no Pydantic alias; keep it 1:1 so existing clients work.
	From       int32                     `json:"from_,omitempty" jsonschema:"Bucket offset, for paging through a large bucket list."`
	DateRanges []base.AggregateDateRange `json:"date_ranges,omitempty" jsonschema:"Date buckets for agg_type='date_range', each {'from': ISO8601, 'to': ISO8601}."`
	Name       string                    `json:"name,omitempty" jsonschema:"Label echoed back on the result to identify this aggregation."`
}

// toAggregateInput maps the tool input onto the transport-agnostic
// base.AggregateInput consumed by the request builders. The case-configuration
// endpoints accept only the terms/date_range dialect, so the histogram/metric
// fields are not collected.
func (in AggregateInput) toAggregateInput() base.AggregateInput {
	return base.AggregateInput{
		Type:       in.AggType,
		Field:      in.Field,
		Filter:     in.Filter,
		Name:       in.Name,
		Size:       in.Size,
		From:       in.From,
		DateRanges: in.DateRanges,
	}
}

// FileAggregateInput is the input for falcon_aggregate_case_file_details. It
// adds case_ids, which the handler folds into a case_id:[...] filter clause to
// restrict the aggregation to specific cases.
type FileAggregateInput struct {
	Field   string   `json:"field" jsonschema:"Field to aggregate on. Supported: name, case_id, id, cid, file_size (a human-readable string such as '114.8 KB')."`
	AggType string   `json:"agg_type,omitempty" jsonschema:"Aggregation type. 'terms' counts files per distinct value; 'date_range' counts files per date_ranges bucket."`
	CaseIDs []string `json:"case_ids,omitempty" jsonschema:"Case ID(s) to restrict the aggregation to. Omit to aggregate files across all cases."`
	Filter  string   `json:"filter,omitempty" jsonschema:"FQL filter expression. See falcon://cases/file-aggregates/fql-guide for syntax."`
	Size    int32    `json:"size,omitempty" jsonschema:"Maximum number of buckets to return. Omit for all buckets."`
	// The from_ wire name (trailing underscore) mirrors the Python module, which
	// exposes from_ with no Pydantic alias; keep it 1:1 so existing clients work.
	From       int32                     `json:"from_,omitempty" jsonschema:"Bucket offset, for paging through a large bucket list."`
	DateRanges []base.AggregateDateRange `json:"date_ranges,omitempty" jsonschema:"Date buckets for agg_type='date_range', each {'from': ISO8601, 'to': ISO8601}."`
	Name       string                    `json:"name,omitempty" jsonschema:"Label echoed back on the result to identify this aggregation."`
}

// toAggregateInput maps the file-aggregate tool input onto base.AggregateInput.
// case_ids is applied separately by the handler, not here.
func (in FileAggregateInput) toAggregateInput() base.AggregateInput {
	return base.AggregateInput{
		Type:       in.AggType,
		Field:      in.Field,
		Filter:     in.Filter,
		Name:       in.Name,
		Size:       in.Size,
		From:       in.From,
		DateRanges: in.DateRanges,
	}
}

// caseAggregateSchema is the input schema for the SLA, template, and
// notification-group aggregate tools. It is inferred from AggregateInput,
// then a mutate func applies the agg_type enum and the size/from bounds the
// struct tags cannot express.
var caseAggregateSchema = base.SchemaFor[AggregateInput](func(s *jsonschema.Schema) {
	base.Enum(s, "agg_type", base.CaseAggregateTypes, base.AggregateTypeDefault)
	s.Properties["size"].Minimum = jsonschema.Ptr(1.0)
	s.Properties["from_"].Minimum = jsonschema.Ptr(0.0)
})

// caseAccessTagsAggregateSchema is the input schema for
// falcon_aggregate_case_access_tags. Access tags accept a narrower field set
// than the other case-configuration aggregates, so the field description is
// overridden accordingly.
var caseAccessTagsAggregateSchema = base.SchemaFor[AggregateInput](func(s *jsonschema.Schema) {
	base.Enum(s, "agg_type", base.CaseAggregateTypes, base.AggregateTypeDefault)
	s.Properties["size"].Minimum = jsonschema.Ptr(1.0)
	s.Properties["from_"].Minimum = jsonschema.Ptr(0.0)
	s.Properties["field"].Description = "Field to aggregate on. Access tags support only: key, id, cid."
})

// caseFileAggregateSchema is the input schema for
// falcon_aggregate_case_file_details.
var caseFileAggregateSchema = base.SchemaFor[FileAggregateInput](func(s *jsonschema.Schema) {
	base.Enum(s, "agg_type", base.CaseAggregateTypes, base.AggregateTypeDefault)
	s.Properties["size"].Minimum = jsonschema.Ptr(1.0)
	s.Properties["from_"].Minimum = jsonschema.Ptr(0.0)
})

// caseConfigAggregateFn runs one /casemgmt/aggregates/* op with the given body.
// It returns the raw *OK response (passed to base.APIError so payload-level
// errors surface reflectively), the response's aggregates payload (for the
// buckets and meta), and any transport error.
type caseConfigAggregateFn func(ctx context.Context, body []*models.APIMSAAggregateQueryRequest) (resp any, payload *models.APIMSAAggregatesResponse, err error)

// aggregateCaseConfig drives the four case-configuration aggregate tools. They
// differ only in the op invoked, supplied as call; the request build, companion
// validation, FQL-error classification, and result packing are shared. All four
// require the Case Templates:read scope.
func (m *Module) aggregateCaseConfig(ctx context.Context, tool string, in AggregateInput, call caseConfigAggregateFn) (*mcp.CallToolResult, base.AggregateResult[*models.MsaAggregationResult], error) {
	var zero base.AggregateResult[*models.MsaAggregationResult]
	agg := in.toAggregateInput()
	if agg.Type == "" {
		agg.Type = base.AggregateTypeDefault
	}
	m.Logger.Debug(tool, "field", agg.Field, "type", agg.Type, "filter", agg.Filter)

	if hint := base.AggregateCompanionHint(agg); hint != "" {
		return nil, base.AggregateHint[*models.MsaAggregationResult](hint), nil
	}

	body := []*models.APIMSAAggregateQueryRequest{base.BuildCaseAggregate(agg)}
	resp, payload, err := call(ctx, body)
	if err != nil {
		if details, ok := caseConfigAggregateFQLBadRequest(err); ok {
			return nil, base.AggregateFQLError[*models.MsaAggregationResult](details, aggregatesFQLGuide), nil
		}
	}
	if e := base.APIError(err, resp, scopeCaseTemplatesRead); e != nil {
		return nil, zero, e
	}
	return nil, base.Aggregated(payload.Resources).WithMeta(payload.Meta), nil
}

func (m *Module) aggregateCaseSlas(ctx context.Context, _ *mcp.CallToolRequest, in AggregateInput) (*mcp.CallToolResult, base.AggregateResult[*models.MsaAggregationResult], error) {
	return m.aggregateCaseConfig(ctx, "aggregate_case_slas", in, func(ctx context.Context, body []*models.APIMSAAggregateQueryRequest) (any, *models.APIMSAAggregatesResponse, error) {
		params := case_management.NewAggregatesSlasPostV1ParamsWithContext(ctx)
		params.Body = body
		ok, err := m.Templates.AggregatesSlasPostV1(params)
		if ok == nil {
			return ok, nil, err
		}
		return ok, ok.Payload, err
	})
}

func (m *Module) aggregateCaseTemplates(ctx context.Context, _ *mcp.CallToolRequest, in AggregateInput) (*mcp.CallToolResult, base.AggregateResult[*models.MsaAggregationResult], error) {
	return m.aggregateCaseConfig(ctx, "aggregate_case_templates", in, func(ctx context.Context, body []*models.APIMSAAggregateQueryRequest) (any, *models.APIMSAAggregatesResponse, error) {
		params := case_management.NewAggregatesTemplatesPostV1ParamsWithContext(ctx)
		params.Body = body
		ok, err := m.Templates.AggregatesTemplatesPostV1(params)
		if ok == nil {
			return ok, nil, err
		}
		return ok, ok.Payload, err
	})
}

func (m *Module) aggregateCaseAccessTags(ctx context.Context, _ *mcp.CallToolRequest, in AggregateInput) (*mcp.CallToolResult, base.AggregateResult[*models.MsaAggregationResult], error) {
	return m.aggregateCaseConfig(ctx, "aggregate_case_access_tags", in, func(ctx context.Context, body []*models.APIMSAAggregateQueryRequest) (any, *models.APIMSAAggregatesResponse, error) {
		params := case_management.NewAggregatesAccessTagsPostV1ParamsWithContext(ctx)
		params.Body = body
		ok, err := m.Templates.AggregatesAccessTagsPostV1(params)
		if ok == nil {
			return ok, nil, err
		}
		return ok, ok.Payload, err
	})
}

func (m *Module) aggregateCaseNotificationGroups(ctx context.Context, _ *mcp.CallToolRequest, in AggregateInput) (*mcp.CallToolResult, base.AggregateResult[*models.MsaAggregationResult], error) {
	return m.aggregateCaseConfig(ctx, "aggregate_case_notification_groups", in, func(ctx context.Context, body []*models.APIMSAAggregateQueryRequest) (any, *models.APIMSAAggregatesResponse, error) {
		params := case_management.NewAggregatesNotificationGroupsPostV2ParamsWithContext(ctx)
		params.Body = body
		ok, err := m.Templates.AggregatesNotificationGroupsPostV2(params)
		if ok == nil {
			return ok, nil, err
		}
		return ok, ok.Payload, err
	})
}

// aggregateCaseFileDetails counts the files attached to cases, grouped by a
// field. When case_ids are given they are folded into a case_id:[...] filter
// clause and also set on the request's Ids param, matching the Python module.
func (m *Module) aggregateCaseFileDetails(ctx context.Context, _ *mcp.CallToolRequest, in FileAggregateInput) (*mcp.CallToolResult, base.AggregateResult[*models.MsaAggregationResult], error) {
	var zero base.AggregateResult[*models.MsaAggregationResult]
	agg := in.toAggregateInput()
	if agg.Type == "" {
		agg.Type = base.AggregateTypeDefault
	}
	if len(in.CaseIDs) > 0 {
		// A caller filter that cannot be safely wrapped in the case_id scope is
		// reported as a soft FQL result, so the caller receives the guide and can
		// self-correct exactly as it would from an API-rejected filter.
		scoped, err := base.ScopeFilter(caseIDScope(in.CaseIDs), agg.Filter)
		if err != nil {
			m.Logger.Warn("aggregate_case_file_details rejected malformed filter", "filter", agg.Filter, "err", err)
			details := []base.FQLErrorDetail{{Code: 400, Message: err.Error()}}
			return nil, base.AggregateFQLError[*models.MsaAggregationResult](details, fileAggregatesFQLGuide), nil
		}
		agg.Filter = scoped
	}
	m.Logger.Debug("aggregate_case_file_details", "field", agg.Field, "type", agg.Type, "filter", agg.Filter, "case_ids", len(in.CaseIDs))

	if hint := base.AggregateCompanionHint(agg); hint != "" {
		return nil, base.AggregateHint[*models.MsaAggregationResult](hint), nil
	}

	params := case_files.NewAggregatesFileDetailsPostV1ParamsWithContext(ctx)
	params.Body = []models.MsaAggregateQueryRequest{base.BuildFileAggregate(agg)}
	if len(in.CaseIDs) > 0 {
		params.Ids = in.CaseIDs
	}

	resp, err := m.CaseFiles.AggregatesFileDetailsPostV1(params)
	if err != nil {
		if details, ok := caseFileAggregateFQLBadRequest(err); ok {
			return nil, base.AggregateFQLError[*models.MsaAggregationResult](details, fileAggregatesFQLGuide), nil
		}
	}
	if e := base.APIError(err, resp, scopeCasesRead); e != nil {
		return nil, zero, e
	}
	return nil, base.Aggregated(resp.Payload.Resources).WithMeta(resp.Payload.Meta), nil
}

// caseIDScope builds the case_id:[...] FQL clause that restricts a file
// aggregation to the given cases, quoting each id as an FQL literal so an
// embedded quote cannot break out of the clause.
func caseIDScope(ids []string) string {
	quoted := make([]string, len(ids))
	for i, id := range ids {
		quoted[i] = base.QuoteFQLValue(id)
	}
	return "case_id:[" + strings.Join(quoted, ",") + "]"
}

// caseConfigAggregateFQLBadRequest reports whether err is a 400-class error from
// any of the four case-configuration aggregate ops that blames the FQL filter
// and, if so, extracts the API error details for an FQL-error response. Each op
// has its own typed BadRequest, all carrying []*models.MsaAPIError; classify
// with errors.As rather than string matching. A 400 whose messages do not
// mention the filter (an unsupported field or aggregation type) is not
// classified here so it surfaces raw through base.APIError.
func caseConfigAggregateFQLBadRequest(err error) ([]base.FQLErrorDetail, bool) {
	var slas *case_management.AggregatesSlasPostV1BadRequest
	if errors.As(err, &slas) && slas.Payload != nil {
		return filterErrorDetails(slas.Payload.Errors)
	}
	var tmpl *case_management.AggregatesTemplatesPostV1BadRequest
	if errors.As(err, &tmpl) && tmpl.Payload != nil {
		return filterErrorDetails(tmpl.Payload.Errors)
	}
	var tags *case_management.AggregatesAccessTagsPostV1BadRequest
	if errors.As(err, &tags) && tags.Payload != nil {
		return filterErrorDetails(tags.Payload.Errors)
	}
	var groups *case_management.AggregatesNotificationGroupsPostV2BadRequest
	if errors.As(err, &groups) && groups.Payload != nil {
		return filterErrorDetails(groups.Payload.Errors)
	}
	return nil, false
}

// caseFileAggregateFQLBadRequest reports whether err is a 400-class case-file
// aggregate error that blames the FQL filter and, if so, extracts the API error
// details. A 400 whose messages do not mention the filter passes through raw.
func caseFileAggregateFQLBadRequest(err error) ([]base.FQLErrorDetail, bool) {
	var badReq *case_files.AggregatesFileDetailsPostV1BadRequest
	if !errors.As(err, &badReq) || badReq.Payload == nil {
		return nil, false
	}
	return filterErrorDetails(badReq.Payload.Errors)
}

// filterErrorDetails flattens the API errors and returns them with true only
// when at least one message mentions the filter. This mirrors upstream
// _is_filter_error, which attaches the FQL guide only for filter-specific 400s
// and lets other 400s (unsupported field or aggregation type) surface raw.
func filterErrorDetails(errs []*models.MsaAPIError) ([]base.FQLErrorDetail, bool) {
	details := base.FQLErrorDetails(errs)
	for _, d := range details {
		if strings.Contains(strings.ToLower(d.Message), "filter") {
			return details, true
		}
	}
	return nil, false
}
