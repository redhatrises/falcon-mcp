package base

import (
	"fmt"

	"github.com/crowdstrike/gofalcon/falcon/models"
)

// AggregateTypeDefault is the aggregation applied when a tool leaves Type unset.
const AggregateTypeDefault = "terms"

// AggregateTypes is the full set of aggregation types the alert and case-file
// aggregate endpoints accept. Tools pass it to Enum so the served schema and the
// value the handler forwards cannot drift.
var AggregateTypes = []string{
	"terms",
	"date_histogram",
	"date_range",
	"range",
	"cardinality",
	"max",
	"min",
	"avg",
	"sum",
	"percentiles",
}

// CaseAggregateTypes is the reduced set the /casemgmt/aggregates/* endpoints
// accept: they count records per distinct value (terms) or per explicit date
// bucket (date_range) and reject the histogram/metric types.
var CaseAggregateTypes = []string{"terms", "date_range"}

// ReconAggregateTypes is the set the /recon/aggregates/* endpoints accept. They
// support the bucketing and single-value metric types but reject the
// distribution metrics sum, avg, and percentiles.
var ReconAggregateTypes = []string{
	"terms",
	"date_histogram",
	"date_range",
	"range",
	"cardinality",
	"max",
	"min",
}

// aggregateRequiredCompanions maps an aggregation type to the field it cannot be
// evaluated without. The Falcon aggregate endpoints answer a spec missing its
// companion with an opaque 500 rather than a validation error, so tools reject
// the combination client-side via MissingAggregateCompanion.
var aggregateRequiredCompanions = map[string]string{
	"date_histogram": "interval",
	"date_range":     "date_ranges",
	"range":          "ranges",
}

// AggregateDateRange is one explicit time bucket for a date_range aggregation.
// Both bounds are FQL date expressions ("now-7d", ISO 8601); an empty bound is
// omitted from the request.
type AggregateDateRange struct {
	From string `json:"from,omitempty"`
	To   string `json:"to,omitempty"`
}

// AggregateRange is one explicit numeric bucket for a range aggregation. The
// wire keys are capitalized ("From"/"To") to match the Falcon API.
type AggregateRange struct {
	From float64 `json:"From"`
	To   float64 `json:"To"`
}

// AggregateInput is the transport-agnostic superset of aggregate parameters the
// detections and cases tools collect. Each per-target builder maps the subset
// its endpoint accepts and omits the rest, so a tool only populates the fields
// its dialect supports. Zero-valued scalars are treated as unset and omitted.
type AggregateInput struct {
	// Type is the aggregation to run (see AggregateTypes), sent as the wire key
	// "type".
	Type string
	// Field is the document field to aggregate on.
	Field string
	// Filter is an FQL expression narrowing the aggregated documents.
	Filter string
	// Name is the label echoed back on the result, identifying it within a
	// multi-aggregation response.
	Name string
	// Size caps the number of buckets returned by a terms aggregation. Zero is
	// unset (endpoint default).
	Size int32
	// From is the bucket offset for paging a large bucket list. Zero is unset.
	From int32
	// Sort orders buckets using the pipe form, e.g. "_count|desc".
	Sort string
	// Interval is the bucket width for a date_histogram, as a bare unit name
	// ("hour", "day", "week", "month", "quarter", "year").
	Interval string
	// TimeZone is the UTC offset applied to date buckets, e.g. "+00:00".
	TimeZone string
	// Missing is the label substituted for documents with no value for Field, so
	// they are counted rather than dropped.
	Missing string
	// Include keeps only buckets whose key matches this regular expression.
	Include string
	// Exclude drops buckets whose key matches this regular expression.
	Exclude string
	// DateRanges are the explicit time buckets for a date_range aggregation.
	DateRanges []AggregateDateRange
	// Ranges are the explicit numeric buckets for a range aggregation.
	Ranges []AggregateRange
	// Percents are the percentiles to compute for a percentiles aggregation.
	Percents []float64
	// SubAggregates are nested aggregations applied within each bucket, each
	// shaped like a top-level input.
	SubAggregates []AggregateInput
}

// MissingAggregateCompanion reports the first aggregation type in in (or nested
// in its SubAggregates) that is missing the companion field it cannot be
// evaluated without. It returns the offending type and the name of the missing
// companion; both are empty when every aggregation is complete. Tools call this
// before dispatch and surface the result as a soft error rather than let the
// endpoint answer with an opaque 500.
func MissingAggregateCompanion(in AggregateInput) (aggType, companion string) {
	switch aggregateRequiredCompanions[in.Type] {
	case "interval":
		if in.Interval == "" {
			return in.Type, "interval"
		}
	case "date_ranges":
		if len(in.DateRanges) == 0 {
			return in.Type, "date_ranges"
		}
	case "ranges":
		if len(in.Ranges) == 0 {
			return in.Type, "ranges"
		}
	}
	for _, sub := range in.SubAggregates {
		if t, c := MissingAggregateCompanion(sub); t != "" {
			return t, c
		}
	}
	return "", ""
}

// AggregateCompanionHint returns the soft-error message for an aggregation input
// missing a required companion field, or "" when the input is complete. The
// message names both the missing companion and the type that requires it.
func AggregateCompanionHint(in AggregateInput) string {
	if t, c := MissingAggregateCompanion(in); t != "" {
		return fmt.Sprintf("`%s` is required when type is `%s`", c, t)
	}
	return ""
}

// BuildAlertAggregate maps in onto the alerts aggregate body. The alerts
// endpoint has no percents field, so Percents is not forwarded; a percentiles
// aggregation falls back to the API's default percentiles.
func BuildAlertAggregate(in AggregateInput) *models.DetectsapiAggregateAlertQueryRequest {
	r := &models.DetectsapiAggregateAlertQueryRequest{
		Type:  &in.Type,
		Field: &in.Field,
	}
	r.Filter = PtrIfSet(in.Filter)
	r.Name = PtrIfSet(in.Name)
	r.Size = PtrIfSet(in.Size)
	r.From = PtrIfSet(in.From)
	r.Sort = PtrIfSet(in.Sort)
	r.Interval = PtrIfSet(in.Interval)
	r.TimeZone = PtrIfSet(in.TimeZone)
	r.Missing = PtrIfSet(in.Missing)
	r.Include = PtrIfSet(in.Include)
	r.Exclude = PtrIfSet(in.Exclude)
	r.DateRanges = dateRangeSpecs(in.DateRanges)
	r.Ranges = rangeSpecs(in.Ranges)
	for _, sub := range in.SubAggregates {
		r.SubAggregates = append(r.SubAggregates, BuildAlertAggregate(sub))
	}
	return r
}

// BuildCaseAggregate maps in onto the reduced /casemgmt/aggregates/* body, which
// accepts only the terms/date_range dialect fields. Fields outside that dialect
// (interval, ranges, percents, sub-aggregates, ...) are dropped.
func BuildCaseAggregate(in AggregateInput) *models.APIMSAAggregateQueryRequest {
	return &models.APIMSAAggregateQueryRequest{
		Type:       &in.Type,
		Field:      &in.Field,
		Filter:     PtrIfSet(in.Filter),
		Name:       PtrIfSet(in.Name),
		Size:       PtrIfSet(in.Size),
		From:       PtrIfSet(in.From),
		Sort:       PtrIfSet(in.Sort),
		DateRanges: dateRangeSpecs(in.DateRanges),
	}
}

// BuildFileAggregate maps in onto the case-files aggregate body, the full
// dialect including percents. It returns a value (not a pointer) because that
// endpoint's request body is a slice of values.
func BuildFileAggregate(in AggregateInput) models.MsaAggregateQueryRequest {
	r := models.MsaAggregateQueryRequest{
		Type:     &in.Type,
		Field:    &in.Field,
		Percents: in.Percents,
	}
	r.Filter = PtrIfSet(in.Filter)
	r.Name = PtrIfSet(in.Name)
	r.Size = PtrIfSet(in.Size)
	r.From = PtrIfSet(in.From)
	r.Sort = PtrIfSet(in.Sort)
	r.Interval = PtrIfSet(in.Interval)
	r.TimeZone = PtrIfSet(in.TimeZone)
	r.Missing = PtrIfSet(in.Missing)
	r.Include = PtrIfSet(in.Include)
	r.Exclude = PtrIfSet(in.Exclude)
	r.DateRanges = dateRangeSpecs(in.DateRanges)
	r.Ranges = rangeSpecs(in.Ranges)
	for _, sub := range in.SubAggregates {
		s := BuildFileAggregate(sub)
		r.SubAggregates = append(r.SubAggregates, &s)
	}
	return r
}

// dateRangeSpecs maps the input date buckets onto the gofalcon spec, omitting
// empty bounds. It returns nil for an empty input so the field is omitted.
func dateRangeSpecs(ranges []AggregateDateRange) []*models.MsaDateRangeSpec {
	if len(ranges) == 0 {
		return nil
	}
	out := make([]*models.MsaDateRangeSpec, 0, len(ranges))
	for _, r := range ranges {
		out = append(out, &models.MsaDateRangeSpec{
			From: PtrIfSet(r.From),
			To:   PtrIfSet(r.To),
		})
	}
	return out
}

// rangeSpecs maps the input numeric buckets onto the gofalcon spec. Both bounds
// are always sent because zero is a meaningful range bound. It returns nil for
// an empty input so the field is omitted.
func rangeSpecs(ranges []AggregateRange) []*models.MsaRangeSpec {
	if len(ranges) == 0 {
		return nil
	}
	out := make([]*models.MsaRangeSpec, 0, len(ranges))
	for _, r := range ranges {
		out = append(out, &models.MsaRangeSpec{From: &r.From, To: &r.To})
	}
	return out
}

// PtrIfSet returns a pointer to v, or nil when v is the zero value, so an unset
// field carries no meaningful value into the request. The gofalcon aggregate
// specs tag these optional fields without omitempty, so a nil pointer is
// marshaled as an explicit JSON null (present with a null value) rather than
// omitted; the aggregate endpoints treat a null spec field as absent.
func PtrIfSet[T comparable](v T) *T {
	var zero T
	if v == zero {
		return nil
	}
	return new(v)
}

// AggregateResult is the structured output envelope for the aggregate tools. It
// mirrors SearchResult: Resources holds one entry per aggregation (each an
// opaque record of the aggregation name and its buckets), and the same
// soft-error fields surface an invalid FQL filter or a missing companion field.
// The buckets are opaque records, consistent with inferOutputSchema treating
// resource records as opaque objects.
type AggregateResult[T any] struct {
	Resources []T              `json:"resources"`
	Errors    []FQLErrorDetail `json:"errors,omitempty"`
	FQLGuide  string           `json:"fql_guide,omitempty"`
	Hint      string           `json:"hint,omitempty"`
	Meta      *Meta            `json:"meta,omitempty"`
}

// Aggregated builds a success (or empty) AggregateResult, normalizing a nil
// slice to an empty slice so the output is always a JSON array.
func Aggregated[T any](resources []T) AggregateResult[T] {
	if resources == nil {
		resources = []T{}
	}
	return AggregateResult[T]{Resources: resources}
}

// AggregateHint builds an empty AggregateResult carrying an advisory message,
// used for client-side validation failures such as a missing companion field.
func AggregateHint[T any](hint string) AggregateResult[T] {
	return AggregateResult[T]{Resources: []T{}, Hint: hint}
}

// AggregateFQLError builds an AggregateResult describing an invalid FQL filter,
// carrying the API error details and the module's FQL guide text. Resources is
// empty.
func AggregateFQLError[T any](details []FQLErrorDetail, fqlGuide string) AggregateResult[T] {
	return AggregateResult[T]{
		Resources: []T{},
		Errors:    details,
		FQLGuide:  fqlGuide,
		Hint:      "The provided FQL filter appears to be invalid. Review the fql_guide for correct syntax.",
	}
}

// WithMeta returns r with the API's response metadata attached, normalized to the
// fixed Meta shape. A nil or nil-pointer meta, or one carrying nothing reportable,
// leaves the field unset. See normalizeMeta.
func (r AggregateResult[T]) WithMeta(meta any) AggregateResult[T] {
	r.Meta = normalizeMeta(meta)
	return r
}
