package recon

import (
	"context"
	"encoding/json"
	"errors"
	"strings"

	"github.com/crowdstrike/gofalcon/falcon/client/recon"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/crowdstrike/falcon-mcp/internal/modules/base"
)

// reconAggregateIntervals is the set of bucket widths a date_histogram accepts.
var reconAggregateIntervals = []string{"hour", "day", "week", "month", "quarter", "year"}

// reconLookbackDays are the accepted lookback windows (in days) for
// preview_recon_rule, matching the fixed set the Recon preview endpoint allows.
var reconLookbackDays = []float64{7, 30, 180, 365}

// reconPreviewTopics are the accepted monitoring-rule topics for
// preview_recon_rule. SA_TYPOSQUATTING is intentionally excluded: the preview
// endpoint rejects it, so it is not offered.
var reconPreviewTopics = []string{
	"SA_DOMAIN", "SA_EMAIL", "SA_IP", "SA_AUTHOR", "SA_BRAND_PRODUCT",
	"SA_THIRD_PARTY", "SA_CUSTOM", "SA_VIP", "SA_CVE", "SA_ALIAS",
}

// Aggregate tool and parameter descriptions, kept 1:1 with the Python falcon-mcp
// recon module. Those carrying backticks or multi-line content live as consts
// applied via each schema's mutate func, since a jsonschema struct tag cannot
// hold them.
const (
	aggregateNotificationsDescription = `Count and summarize Falcon Intelligence Recon notifications without retrieving each record.

Use this for "how many" and "top N" questions over recon notifications — counts per status,
rule priority, or topic, and notification volume over time — instead of paging through
` + "`falcon_search_recon_notifications`" + `. Consult
` + "`falcon://recon/notifications/search/fql-guide`" + ` before constructing filter expressions.
Returns aggregation buckets keyed by ` + "`label`" + ` with a ` + "`count`" + `.`

	aggregateExposedDataRecordsDescription = `Count and summarize Falcon Intelligence Recon exposed-data records without retrieving each record.

Use this for "how many" and "top N" questions over leaked credential and PII rows — counts
per credential status, site, source category, or rule topic — instead of paging through
` + "`falcon_search_recon_exposed_data_records`" + `. Consult
` + "`falcon://recon/exposed-data-records/search/fql-guide`" + ` before constructing filter expressions.
Returns aggregation buckets keyed by ` + "`label`" + ` with a ` + "`count`" + `.`

	previewRuleDescription = `Preview how many Falcon Intelligence Recon notifications a monitoring rule would have generated.

Use this to size a candidate rule before creating it: it evaluates the rule's ` + "`filter`" + `
against historical data for the chosen ` + "`topic`" + ` and reports the match volume, so you can
tune the filter without generating live notifications. Returns aggregation buckets describing
the historical match counts.`

	aggregateNotificationsFieldDescription = "Notification field to aggregate on, such as status, rule_priority, rule_topic, or created_date. See `falcon://recon/notifications/search/fql-guide` for the aggregatable fields."

	aggregateExposedDataRecordsFieldDescription = "Exposed-data record field to aggregate on. Supported: cid, notification_id, notification_group_id, created_date, rule.id, rule.name, rule.topic, source_category, site, author, file.name, credential_status, bot.operating_system.hardware_id, bot.bot_id."

	aggregateTypeDescription = "Aggregation to run. Use terms to count records per distinct value, date_histogram for a time series, date_range or range for explicit buckets, cardinality for a distinct-value count, and max or min for a numeric extreme. The recon endpoint rejects sum, avg, and percentiles."

	aggregateNotificationsFilterDescription      = "FQL filter expression narrowing which notifications are counted. See `falcon://recon/notifications/search/fql-guide` for syntax."
	aggregateExposedDataRecordsFilterDescription = "FQL filter expression narrowing which exposed-data records are counted. See `falcon://recon/exposed-data-records/search/fql-guide` for syntax."

	aggregateIntervalDescription   = "Bucket width for date_histogram aggregations. Required whenever type is date_histogram."
	aggregateDateRangesDescription = "Explicit time buckets for date_range aggregations, for example [{'from': 'now-7d', 'to': 'now'}]. Required whenever type is date_range."
	aggregateRangesDescription     = "Numeric buckets for range aggregations, for example [{'From': 0, 'To': 50}]. Required whenever type is range."
	aggregateSizeDescription       = "Maximum number of buckets to return for terms aggregations."
	aggregateSortDescription       = "Bucket ordering, e.g. _count|desc (most records first), _count|asc, _key|asc, or _key|desc."
	aggregateMissingDescription    = "Label used for records that have no value for field, so they are counted instead of dropped."
	aggregateIncludeDescription    = "Keep only buckets whose key matches this regular expression."
	aggregateNameDescription       = "Label echoed back on the returned aggregation."
	aggregateTimeZoneDescription   = "UTC offset applied to date buckets, e.g. +00:00."

	previewFilterDescription   = "FQL filter defining the candidate rule's match criteria. Required."
	previewTopicDescription    = "Monitoring-rule topic the filter is evaluated against. Required."
	previewLookbackDescription = "How many days of history to evaluate the rule against. One of 7, 30, 180, or 365."
)

// aggregateSchema builds an aggregate input schema, applying the recon
// aggregation-type enum, the date_histogram interval enum, the size bounds, and
// the backtick-bearing field/filter descriptions the struct tags cannot express.
func aggregateSchema[In any](fieldDesc, filterDesc string) *jsonschema.Schema {
	return base.SchemaFor[In](func(s *jsonschema.Schema) {
		s.Properties["field"].Description = fieldDesc
		s.Properties["filter"].Description = filterDesc
		s.Properties["type"].Description = aggregateTypeDescription
		s.Properties["interval"].Description = aggregateIntervalDescription
		s.Properties["date_ranges"].Description = aggregateDateRangesDescription
		s.Properties["ranges"].Description = aggregateRangesDescription
		s.Properties["size"].Description = aggregateSizeDescription
		s.Properties["sort"].Description = aggregateSortDescription
		s.Properties["missing"].Description = aggregateMissingDescription
		s.Properties["include"].Description = aggregateIncludeDescription
		s.Properties["name"].Description = aggregateNameDescription
		s.Properties["time_zone"].Description = aggregateTimeZoneDescription
		base.Enum(s, "type", base.ReconAggregateTypes, base.AggregateTypeDefault)
		base.Enum(s, "interval", reconAggregateIntervals, "")
		s.Properties["size"].Minimum = jsonschema.Ptr(1.0)
		s.Properties["size"].Maximum = jsonschema.Ptr(1000.0)
		s.Properties["size"].Default = json.RawMessage(`10`)
	})
}

var (
	aggregateNotificationsSchema      = aggregateSchema[AggregateInput](aggregateNotificationsFieldDescription, aggregateNotificationsFilterDescription)
	aggregateExposedDataRecordsSchema = aggregateSchema[AggregateInput](aggregateExposedDataRecordsFieldDescription, aggregateExposedDataRecordsFilterDescription)

	previewRuleSchema = base.SchemaFor[PreviewInput](func(s *jsonschema.Schema) {
		s.Properties["filter"].Description = previewFilterDescription
		s.Properties["topic"].Description = previewTopicDescription
		s.Properties["lookback_days"].Description = previewLookbackDescription
		base.Enum(s, "topic", reconPreviewTopics, "")
		s.Properties["lookback_days"].Enum = enumValues(reconLookbackDays)
	})
)

// enumValues renders a numeric enum's allowed values as JSON for a schema's Enum
// slot, since base.Enum only handles string enums.
func enumValues(vals []float64) []any {
	out := make([]any, len(vals))
	for i, v := range vals {
		out[i] = v
	}
	return out
}

// AggregateInput is the input shared by both recon aggregate tools. It collects
// the aggregate parameters the recon endpoints accept; the handler maps it onto
// a base.AggregateInput. Field is the only required field.
type AggregateInput struct {
	Field      string                    `json:"field" jsonschema:"field to aggregate on"`
	Type       string                    `json:"type,omitempty" jsonschema:"aggregation to run"`
	Filter     string                    `json:"filter,omitempty" jsonschema:"FQL filter narrowing which records are counted"`
	Size       int32                     `json:"size,omitempty" jsonschema:"maximum number of buckets for terms aggregations"`
	Sort       string                    `json:"sort,omitempty" jsonschema:"bucket ordering, e.g. _count|desc"`
	Interval   string                    `json:"interval,omitempty" jsonschema:"bucket width for date_histogram aggregations"`
	DateRanges []base.AggregateDateRange `json:"date_ranges,omitempty" jsonschema:"explicit time buckets for date_range aggregations"`
	Ranges     []base.AggregateRange     `json:"ranges,omitempty" jsonschema:"numeric buckets for range aggregations"`
	Missing    string                    `json:"missing,omitempty" jsonschema:"label for records missing field"`
	Include    string                    `json:"include,omitempty" jsonschema:"keep only buckets whose key matches this regex"`
	Name       string                    `json:"name,omitempty" jsonschema:"label echoed back on the aggregation"`
	TimeZone   string                    `json:"time_zone,omitempty" jsonschema:"UTC offset applied to date buckets"`
}

// toAggregateInput maps the tool input onto the transport-agnostic
// base.AggregateInput consumed by the request builder.
func (in AggregateInput) toAggregateInput() base.AggregateInput {
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
	}
}

// PreviewInput is the input for falcon_preview_recon_rule. Filter and Topic are
// required (no omitempty), so schema inference marks them required.
type PreviewInput struct {
	Filter       string `json:"filter" jsonschema:"FQL filter defining the candidate rule's match criteria"`
	Topic        string `json:"topic" jsonschema:"monitoring-rule topic the filter is evaluated against"`
	LookbackDays int32  `json:"lookback_days,omitempty" jsonschema:"how many days of history to evaluate against"`
}

// aggregateNotifications counts and summarizes recon notifications without
// retrieving each record.
func (m *Module) aggregateNotifications(ctx context.Context, _ *mcp.CallToolRequest, in AggregateInput) (*mcp.CallToolResult, base.AggregateResult[*models.DomainAggregationResult], error) {
	agg := in.toAggregateInput()
	if hint, ok := reconAggregateGuard(&agg); ok {
		return nil, hint, nil
	}
	m.Logger.Debug("aggregate_recon_notifications", "field", agg.Field, "type", agg.Type, "filter", agg.Filter)

	params := recon.NewAggregateNotificationsV1ParamsWithContext(ctx)
	body := base.BuildFileAggregate(agg)
	params.Body = []*models.MsaAggregateQueryRequest{&body}

	resp, err := m.API.AggregateNotificationsV1(params)
	if err != nil {
		if details, ok := aggregateFQLBadRequest(err); ok {
			return nil, base.AggregateFQLError[*models.DomainAggregationResult](details, notificationsFQLGuide), nil
		}
	}
	if e := base.APIError(err, resp, scopeMonitoringRules); e != nil {
		return nil, base.AggregateResult[*models.DomainAggregationResult]{}, e
	}
	return nil, base.Aggregated(resp.Payload.Resources).WithMeta(resp.Payload.Meta), nil
}

// aggregateExposedDataRecords counts and summarizes recon exposed-data records
// without retrieving each record.
func (m *Module) aggregateExposedDataRecords(ctx context.Context, _ *mcp.CallToolRequest, in AggregateInput) (*mcp.CallToolResult, base.AggregateResult[*models.DomainAggregationResult], error) {
	agg := in.toAggregateInput()
	if hint, ok := reconAggregateGuard(&agg); ok {
		return nil, hint, nil
	}
	m.Logger.Debug("aggregate_recon_exposed_data_records", "field", agg.Field, "type", agg.Type, "filter", agg.Filter)

	params := recon.NewAggregateNotificationsExposedDataRecordsV1ParamsWithContext(ctx)
	body := base.BuildFileAggregate(agg)
	params.Body = []*models.MsaAggregateQueryRequest{&body}

	resp, err := m.API.AggregateNotificationsExposedDataRecordsV1(params)
	if err != nil {
		if details, ok := aggregateFQLBadRequest(err); ok {
			return nil, base.AggregateFQLError[*models.DomainAggregationResult](details, exposedDataRecordsFQLGuide), nil
		}
	}
	if e := base.APIError(err, resp, scopeMonitoringRules); e != nil {
		return nil, base.AggregateResult[*models.DomainAggregationResult]{}, e
	}
	return nil, base.Aggregated(resp.Payload.Resources).WithMeta(resp.Payload.Meta), nil
}

// previewRule previews how many notifications a candidate monitoring rule would
// have generated over the chosen lookback window.
func (m *Module) previewRule(ctx context.Context, _ *mcp.CallToolRequest, in PreviewInput) (*mcp.CallToolResult, base.AggregateResult[*models.DomainAggregationResult], error) {
	m.Logger.Debug("preview_recon_rule", "topic", in.Topic, "filter", in.Filter, "lookback_days", in.LookbackDays)

	params := recon.NewPreviewRuleV1ParamsWithContext(ctx)
	body := &models.DomainRulePreviewRequest{
		Filter: &in.Filter,
		Topic:  &in.Topic,
	}
	if in.LookbackDays != 0 {
		body.LookbackDays = in.LookbackDays
	}
	params.Body = body

	resp, err := m.API.PreviewRuleV1(params)
	if err != nil {
		if details, ok := previewFQLBadRequest(err); ok {
			return nil, base.AggregateFQLError[*models.DomainAggregationResult](details, previewRuleFQLGuide), nil
		}
	}
	if e := base.APIError(err, resp, scopeMonitoringRules); e != nil {
		return nil, base.AggregateResult[*models.DomainAggregationResult]{}, e
	}
	return nil, base.Aggregated(resp.Payload.Resources).WithMeta(resp.Payload.Meta), nil
}

// reconAggregateGuard defaults the aggregate type in place the same way a
// schema-aware caller would and reports a companion hint (as a data result) when
// the aggregation type is missing its required companion field. It returns the
// hint envelope and true when the caller must be told, or the zero value and
// false when the request is well-formed.
func reconAggregateGuard(agg *base.AggregateInput) (base.AggregateResult[*models.DomainAggregationResult], bool) {
	if agg.Type == "" {
		agg.Type = base.AggregateTypeDefault
	}
	if hint := base.AggregateCompanionHint(*agg); hint != "" {
		return base.AggregateHint[*models.DomainAggregationResult](hint), true
	}
	return base.AggregateResult[*models.DomainAggregationResult]{}, false
}

// aggregateFQLBadRequest reports whether err is a 400-class recon aggregate error
// that blames the FQL filter and, if so, extracts the API error details for an
// FQL-error response. A 400 whose messages do not mention the filter surfaces raw
// through base.APIError, mirroring the detections aggregate classifier.
func aggregateFQLBadRequest(err error) ([]base.FQLErrorDetail, bool) {
	var notifBad *recon.AggregateNotificationsV1BadRequest
	if errors.As(err, &notifBad) && notifBad.Payload != nil {
		return filterErrorDetails(reconErrorDetails(notifBad.Payload.Errors))
	}
	var edrBad *recon.AggregateNotificationsExposedDataRecordsV1BadRequest
	if errors.As(err, &edrBad) && edrBad.Payload != nil {
		return filterErrorDetails(reconErrorDetails(edrBad.Payload.Errors))
	}
	return nil, false
}

// previewFQLBadRequest reports whether err is a 400-class preview error that
// blames the FQL filter and, if so, extracts the API error details.
func previewFQLBadRequest(err error) ([]base.FQLErrorDetail, bool) {
	var badReq *recon.PreviewRuleV1BadRequest
	if !errors.As(err, &badReq) || badReq.Payload == nil {
		return nil, false
	}
	return filterErrorDetails(reconErrorDetails(badReq.Payload.Errors))
}

// filterErrorDetails keeps the given details only when at least one message
// blames the filter, so a 400 about a bad sort, an unaggregatable field, or an
// invalid interval surfaces raw rather than as a soft FQL error.
func filterErrorDetails(details []base.FQLErrorDetail) ([]base.FQLErrorDetail, bool) {
	for _, d := range details {
		if strings.Contains(strings.ToLower(d.Message), "filter") {
			return details, true
		}
	}
	return nil, false
}
