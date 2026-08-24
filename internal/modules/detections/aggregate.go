package detections

import (
	"context"
	"encoding/json"
	"errors"
	"strings"

	"github.com/crowdstrike/gofalcon/falcon/client/alerts"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/crowdstrike/falcon-mcp/internal/modules/base"
)

// aggregateIntervals is the set of bucket widths a date_histogram accepts.
var aggregateIntervals = []string{"hour", "day", "week", "month", "quarter", "year"}

// aggregateDetectionsSchema is the input schema for falcon_aggregate_detections.
// It is inferred from AggregateInput, then a mutate func applies the enum
// constraints and size bounds/default the struct tags cannot express.
var aggregateDetectionsSchema = base.SchemaFor[AggregateInput](func(s *jsonschema.Schema) {
	base.Enum(s, "type", base.AggregateTypes, base.AggregateTypeDefault)
	base.Enum(s, "interval", aggregateIntervals, "")
	s.Properties["size"].Minimum = jsonschema.Ptr(1.0)
	s.Properties["size"].Maximum = jsonschema.Ptr(1000.0)
	s.Properties["size"].Default = json.RawMessage(`10`)
})

// AggregateInput is the input for falcon_aggregate_detections. It collects the
// aggregate parameters the alerts endpoint accepts; the handler maps it onto a
// base.AggregateInput. Field and Type are the only required fields.
type AggregateInput struct {
	Field         string                    `json:"field" jsonschema:"Alert field to aggregate on, such as severity_name, status, tactic, technique, product, device.hostname, or timestamp. See falcon://detections/search/fql-guide for the aggregatable fields."`
	Type          string                    `json:"type,omitempty" jsonschema:"Aggregation to run. Use terms to count alerts per distinct value, date_histogram for a time series, date_range or range for explicit buckets, and cardinality for a distinct-value count."`
	Filter        string                    `json:"filter,omitempty" jsonschema:"FQL filter expression narrowing which alerts are counted. See falcon://detections/search/fql-guide for syntax."`
	Size          int32                     `json:"size,omitempty" jsonschema:"Maximum number of buckets to return for terms aggregations."`
	Sort          string                    `json:"sort,omitempty" jsonschema:"Bucket ordering, using the pipe form only: _count|desc (most alerts first), _count|asc, _key|asc, or _key|desc. The dot form accepted by search sorts is rejected here."`
	Interval      string                    `json:"interval,omitempty" jsonschema:"Bucket width for date_histogram aggregations. Required whenever type is date_histogram."`
	DateRanges    []base.AggregateDateRange `json:"date_ranges,omitempty" jsonschema:"Explicit time buckets for date_range aggregations, for example [{'from': 'now-7d', 'to': 'now'}]. Required whenever type is date_range."`
	Ranges        []base.AggregateRange     `json:"ranges,omitempty" jsonschema:"Numeric buckets for range aggregations, for example [{'From': 0, 'To': 50}]. Required whenever type is range."`
	Percents      []float64                 `json:"percents,omitempty" jsonschema:"Ignored: the alerts aggregate endpoint has no percents parameter, so a percentiles aggregation always uses the API's default percentiles."`
	Missing       string                    `json:"missing,omitempty" jsonschema:"Label used for alerts that have no value for field, so they are counted instead of dropped."`
	Include       string                    `json:"include,omitempty" jsonschema:"Keep only buckets whose key matches this regular expression, e.g. High|Critical."`
	Name          string                    `json:"name,omitempty" jsonschema:"Label echoed back on the returned aggregation."`
	TimeZone      string                    `json:"time_zone,omitempty" jsonschema:"UTC offset applied to date buckets, e.g. +00:00."`
	SubAggregates []SubAggregate            `json:"sub_aggregates,omitempty" jsonschema:"Nested aggregations applied within each bucket, each shaped like a top-level spec, e.g. [{'type': 'terms', 'field': 'status'}]."`
	IncludeHidden *bool                     `json:"include_hidden,omitempty" jsonschema:"Whether to count hidden alerts (default true). Set false to match the alert totals shown in the Falcon console."`
}

// SubAggregate is one nested aggregation within a bucket. It carries the same
// parameters as the top-level input minus the transport-only fields
// (include_hidden) and further nesting, matching the realistic single level of
// nesting the alerts endpoint is driven with.
type SubAggregate struct {
	Field      string                    `json:"field" jsonschema:"Alert field to aggregate on within each parent bucket."`
	Type       string                    `json:"type,omitempty" jsonschema:"Aggregation to run within each parent bucket."`
	Filter     string                    `json:"filter,omitempty" jsonschema:"FQL filter narrowing the nested aggregation."`
	Size       int32                     `json:"size,omitempty" jsonschema:"Maximum number of buckets for a nested terms aggregation."`
	Sort       string                    `json:"sort,omitempty" jsonschema:"Bucket ordering for the nested aggregation, pipe form only."`
	Interval   string                    `json:"interval,omitempty" jsonschema:"Bucket width for a nested date_histogram."`
	DateRanges []base.AggregateDateRange `json:"date_ranges,omitempty" jsonschema:"Explicit time buckets for a nested date_range."`
	Ranges     []base.AggregateRange     `json:"ranges,omitempty" jsonschema:"Numeric buckets for a nested range."`
	Percents   []float64                 `json:"percents,omitempty" jsonschema:"Ignored: the alerts aggregate endpoint has no percents parameter, so a nested percentiles aggregation always uses the API's default percentiles."`
	Missing    string                    `json:"missing,omitempty" jsonschema:"Label for documents missing field in the nested aggregation."`
	Include    string                    `json:"include,omitempty" jsonschema:"Nested bucket-key include pattern."`
	Name       string                    `json:"name,omitempty" jsonschema:"Label echoed back on the nested aggregation."`
	TimeZone   string                    `json:"time_zone,omitempty" jsonschema:"UTC offset applied to nested date buckets."`
}

// toAggregateInput maps the tool input onto the transport-agnostic
// base.AggregateInput consumed by the request builders.
func (in AggregateInput) toAggregateInput() base.AggregateInput {
	agg := base.AggregateInput{
		Type:       in.Type,
		Field:      in.Field,
		Filter:     in.Filter,
		Name:       in.Name,
		Size:       in.Size,
		Sort:       in.Sort,
		Interval:   in.Interval,
		TimeZone:   in.TimeZone,
		Missing:    in.Missing,
		Include:    in.Include,
		DateRanges: in.DateRanges,
		Ranges:     in.Ranges,
		Percents:   in.Percents,
	}
	for _, sub := range in.SubAggregates {
		agg.SubAggregates = append(agg.SubAggregates, sub.toAggregateInput())
	}
	return agg
}

// toAggregateInput maps a nested sub-aggregation onto base.AggregateInput.
func (in SubAggregate) toAggregateInput() base.AggregateInput {
	return base.AggregateInput{
		Type:       in.Type,
		Field:      in.Field,
		Filter:     in.Filter,
		Name:       in.Name,
		Size:       in.Size,
		Sort:       in.Sort,
		Interval:   in.Interval,
		TimeZone:   in.TimeZone,
		Missing:    in.Missing,
		Include:    in.Include,
		DateRanges: in.DateRanges,
		Ranges:     in.Ranges,
		Percents:   in.Percents,
	}
}

// aggregateDetections counts and summarizes alerts without retrieving each
// record, answering "how many" and "top N" questions in one call.
func (m *Module) aggregateDetections(ctx context.Context, _ *mcp.CallToolRequest, in AggregateInput) (*mcp.CallToolResult, base.AggregateResult[*models.DetectsapiAggregationResult], error) {
	var zero base.AggregateResult[*models.DetectsapiAggregationResult]
	agg := in.toAggregateInput()
	if agg.Type == "" {
		agg.Type = base.AggregateTypeDefault
	}
	// The alerts endpoint applies its own bucket cap when size is omitted, so a
	// raw or dynamic-mode caller that bypasses the JSON-schema default would get
	// a different count than a schema-aware one. Apply the same default here so
	// the bucket count is consistent regardless of how the tool is invoked.
	if agg.Size == 0 {
		agg.Size = 10
	}

	m.Logger.Debug("aggregate_detections", "field", agg.Field, "type", agg.Type, "filter", agg.Filter)

	if hint := base.AggregateCompanionHint(agg); hint != "" {
		return nil, base.AggregateHint[*models.DetectsapiAggregationResult](hint), nil
	}

	params := alerts.NewGetAggregateV2ParamsWithContext(ctx)
	params.Body = []*models.DetectsapiAggregateAlertQueryRequest{base.BuildAlertAggregate(agg)}
	// Match the Falcon console's default of counting hidden alerts unless the
	// caller opts out.
	includeHidden := true
	if in.IncludeHidden != nil {
		includeHidden = *in.IncludeHidden
	}
	params.IncludeHidden = &includeHidden

	resp, err := m.API.GetAggregateV2(params)
	if err != nil {
		if details, ok := aggregateFQLBadRequest(err); ok {
			return nil, base.AggregateFQLError[*models.DetectsapiAggregationResult](details, fqlGuide), nil
		}
	}
	if e := base.APIError(err, resp, scopeAlertsRead); e != nil {
		return nil, zero, e
	}

	return nil, base.Aggregated(resp.Payload.Resources).WithMeta(resp.Payload.Meta), nil
}

// aggregateFQLBadRequest reports whether err is a 400-class aggregate error that
// blames the FQL filter and, if so, extracts the API error details for an
// FQL-error response. A 400 whose messages do not mention the filter (a bad
// sort, an unaggregatable field, or an invalid interval) is not classified here
// so it surfaces raw through base.APIError, mirroring upstream _is_filter_error.
func aggregateFQLBadRequest(err error) ([]base.FQLErrorDetail, bool) {
	var badReq *alerts.GetAggregateV2BadRequest
	if !errors.As(err, &badReq) || badReq.Payload == nil {
		return nil, false
	}
	details := apiErrorDetails(badReq.Payload.Errors)
	for _, d := range details {
		if strings.Contains(strings.ToLower(d.Message), "filter") {
			return details, true
		}
	}
	return nil, false
}
