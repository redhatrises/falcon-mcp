package base

import (
	"encoding/json"
	"testing"

	"github.com/crowdstrike/gofalcon/falcon/models"
)

// TestBuildAlertAggregateMapsAndOmits verifies the alerts builder forwards set
// fields, omits zero-valued ones, always sends the required type/field, and
// drops percents (the alerts body has no such field).
func TestBuildAlertAggregateMapsAndOmits(t *testing.T) {
	t.Parallel()

	got := BuildAlertAggregate(AggregateInput{
		Type:       "terms",
		Field:      "severity_name",
		Size:       10,
		Percents:   []float64{50, 95},
		DateRanges: []AggregateDateRange{{From: "now-7d", To: "now"}},
		SubAggregates: []AggregateInput{
			{Type: "terms", Field: "status"},
		},
	})

	if got.Type == nil || *got.Type != "terms" {
		t.Fatalf("Type = %v, want terms", got.Type)
	}
	if got.Field == nil || *got.Field != "severity_name" {
		t.Fatalf("Field = %v, want severity_name", got.Field)
	}
	if got.Size == nil || *got.Size != 10 {
		t.Fatalf("Size = %v, want 10", got.Size)
	}
	// From/Sort/Filter were unset — they must be omitted (nil), not zero values.
	if got.From != nil || got.Sort != nil || got.Filter != nil {
		t.Errorf("unset fields not omitted: from=%v sort=%v filter=%v", got.From, got.Sort, got.Filter)
	}
	if len(got.DateRanges) != 1 || got.DateRanges[0].From == nil || *got.DateRanges[0].From != "now-7d" {
		t.Errorf("DateRanges not mapped: %+v", got.DateRanges)
	}
	if len(got.SubAggregates) != 1 || got.SubAggregates[0].Field == nil || *got.SubAggregates[0].Field != "status" {
		t.Errorf("SubAggregates not mapped: %+v", got.SubAggregates)
	}
	// The alerts body carries no percents field; the builder cannot forward it.
	// Marshaling must not surface a "percents" key.
	raw, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if _, ok := m["percents"]; ok {
		t.Error("alerts body must not carry a percents key")
	}
}

// TestBuildCaseAggregateReducedDialect verifies the case-config builder maps the
// narrow field set and drops fields outside its dialect.
func TestBuildCaseAggregateReducedDialect(t *testing.T) {
	t.Parallel()

	got := BuildCaseAggregate(AggregateInput{
		Type:       "date_range",
		Field:      "created_timestamp",
		Filter:     "name:*'*Corp*'",
		From:       5,
		DateRanges: []AggregateDateRange{{From: "2024-01-01", To: "2024-02-01"}},
		// Fields outside the reduced dialect — must not appear.
		Interval: "day",
		Percents: []float64{50},
	})

	if got.Type == nil || *got.Type != "date_range" {
		t.Fatalf("Type = %v, want date_range", got.Type)
	}
	if got.Field == nil || *got.Field != "created_timestamp" {
		t.Fatalf("Field = %v, want created_timestamp", got.Field)
	}
	if got.Filter == nil || *got.Filter != "name:*'*Corp*'" {
		t.Errorf("Filter = %v", got.Filter)
	}
	if got.From == nil || *got.From != 5 {
		t.Errorf("From = %v, want 5", got.From)
	}
	if len(got.DateRanges) != 1 {
		t.Errorf("DateRanges = %+v, want one bucket", got.DateRanges)
	}
	// APIMSAAggregateQueryRequest has no Interval/Percents fields at all, so the
	// reduced dialect is enforced by the type. This asserts the mapped fields are
	// correct; the absence of the others is a compile-time guarantee.
}

// TestBuildFileAggregateForwardsPercents verifies the case-files builder returns
// a value, forwards percents, and nests sub-aggregates as pointers.
func TestBuildFileAggregateForwardsPercents(t *testing.T) {
	t.Parallel()

	got := BuildFileAggregate(AggregateInput{
		Type:     "percentiles",
		Field:    "size",
		Percents: []float64{50, 95},
		SubAggregates: []AggregateInput{
			{Type: "terms", Field: "type"},
		},
	})

	if got.Type == nil || *got.Type != "percentiles" {
		t.Fatalf("Type = %v, want percentiles", got.Type)
	}
	if len(got.Percents) != 2 || got.Percents[1] != 95 {
		t.Errorf("Percents = %v, want [50 95]", got.Percents)
	}
	if len(got.SubAggregates) != 1 || got.SubAggregates[0] == nil || *got.SubAggregates[0].Field != "type" {
		t.Errorf("SubAggregates not nested as pointers: %+v", got.SubAggregates)
	}
}

// TestRangeSpecsAlwaysSendsBothBounds verifies numeric range bounds are sent
// even when zero, since zero is a meaningful bound.
func TestRangeSpecsAlwaysSendsBothBounds(t *testing.T) {
	t.Parallel()

	got := BuildAlertAggregate(AggregateInput{
		Type:   "range",
		Field:  "score",
		Ranges: []AggregateRange{{From: 0, To: 50}},
	})
	if len(got.Ranges) != 1 {
		t.Fatalf("Ranges = %+v, want one", got.Ranges)
	}
	if got.Ranges[0].From == nil || *got.Ranges[0].From != 0 {
		t.Errorf("range From = %v, want 0 (sent, not omitted)", got.Ranges[0].From)
	}
	if got.Ranges[0].To == nil || *got.Ranges[0].To != 50 {
		t.Errorf("range To = %v, want 50", got.Ranges[0].To)
	}
}

// TestMissingAggregateCompanion covers the required-companion validation,
// including recursion into sub-aggregates.
func TestMissingAggregateCompanion(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		in            AggregateInput
		wantType      string
		wantCompanion string
	}{
		{
			name: "terms needs nothing",
			in:   AggregateInput{Type: "terms", Field: "status"},
		},
		{
			name:          "date_histogram without interval",
			in:            AggregateInput{Type: "date_histogram", Field: "timestamp"},
			wantType:      "date_histogram",
			wantCompanion: "interval",
		},
		{
			name: "date_histogram with interval",
			in:   AggregateInput{Type: "date_histogram", Field: "timestamp", Interval: "day"},
		},
		{
			name:          "date_range without date_ranges",
			in:            AggregateInput{Type: "date_range", Field: "timestamp"},
			wantType:      "date_range",
			wantCompanion: "date_ranges",
		},
		{
			name:          "range without ranges",
			in:            AggregateInput{Type: "range", Field: "score"},
			wantType:      "range",
			wantCompanion: "ranges",
		},
		{
			name: "range with ranges",
			in:   AggregateInput{Type: "range", Field: "score", Ranges: []AggregateRange{{From: 0, To: 1}}},
		},
		{
			name: "incomplete sub-aggregate",
			in: AggregateInput{
				Type:  "terms",
				Field: "status",
				SubAggregates: []AggregateInput{
					{Type: "date_range", Field: "timestamp"},
				},
			},
			wantType:      "date_range",
			wantCompanion: "date_ranges",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			gotType, gotCompanion := MissingAggregateCompanion(tt.in)
			if gotType != tt.wantType || gotCompanion != tt.wantCompanion {
				t.Errorf("MissingAggregateCompanion = (%q, %q), want (%q, %q)", gotType, gotCompanion, tt.wantType, tt.wantCompanion)
			}
			hint := AggregateCompanionHint(tt.in)
			if (hint == "") == (tt.wantType != "") {
				t.Errorf("AggregateCompanionHint = %q, want non-empty=%v", hint, tt.wantType != "")
			}
		})
	}
}

// TestAggregatedNormalizesNilSlice verifies the success constructor never leaves
// Resources nil, so the output is always a JSON array.
func TestAggregatedNormalizesNilSlice(t *testing.T) {
	t.Parallel()

	got := Aggregated[*models.MsaAggregationResult](nil)
	if got.Resources == nil {
		t.Fatal("Resources = nil, want empty slice")
	}
	if len(got.Resources) != 0 {
		t.Fatalf("Resources len = %d, want 0", len(got.Resources))
	}
}

// TestAggregateResultWithMeta verifies meta passthrough: a populated meta is
// normalized and attached; an empty/typed-nil meta leaves the key out of JSON.
func TestAggregateResultWithMeta(t *testing.T) {
	t.Parallel()

	total := int64(7)
	populated := &models.MsaMetaInfo{Pagination: &models.MsaPaging{Total: &total}}
	got := Aggregated([]string{"a"}).WithMeta(populated)
	if got.Meta == nil || got.Meta.Pagination == nil || *got.Meta.Pagination.Total != 7 {
		t.Fatalf("Meta = %+v, want pagination.total 7", got.Meta)
	}

	var typedNil *models.MsaMetaInfo
	empty := Aggregated([]string{"a"}).WithMeta(typedNil)
	raw, err := json.Marshal(empty)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if _, ok := m["meta"]; ok {
		t.Error("typed-nil meta must be omitted from AggregateResult JSON")
	}
}

// TestAggregateFQLErrorShape verifies the FQL soft-error constructor sets the
// guide, error details, and advisory hint with an empty resource list.
func TestAggregateFQLErrorShape(t *testing.T) {
	t.Parallel()

	details := []FQLErrorDetail{{Code: 400, Message: "bad field"}}
	got := AggregateFQLError[string](details, "guide-text")
	if len(got.Resources) != 0 {
		t.Errorf("Resources = %v, want empty", got.Resources)
	}
	if got.FQLGuide != "guide-text" {
		t.Errorf("FQLGuide = %q", got.FQLGuide)
	}
	if len(got.Errors) != 1 || got.Errors[0].Message != "bad field" {
		t.Errorf("Errors = %+v", got.Errors)
	}
	if got.Hint == "" {
		t.Error("Hint should advise reviewing the guide")
	}
}
