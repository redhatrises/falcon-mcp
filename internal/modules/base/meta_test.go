package base

import (
	"encoding/json"
	"testing"

	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/google/jsonschema-go/jsonschema"
)

// metaJSON normalizes v and marshals the result, returning "" when normalizeMeta
// drops the meta entirely.
func metaJSON(t *testing.T, v any) string {
	t.Helper()
	m := normalizeMeta(v)
	if m == nil {
		return ""
	}
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("marshal normalized meta: %v", err)
	}
	return string(raw)
}

// TestNormalizeMetaRealTypes pins the normalized JSON for one representative of
// every meta shape the Falcon APIs return, exercised through the real gofalcon
// models rather than hand-built JSON. Each row proves a specific divergence is
// reconciled: the cursor spelling, the query_time casing, pointer versus value
// scalars, and the numeric-versus-opaque offset.
func TestNormalizeMetaRealTypes(t *testing.T) {
	t.Parallel()

	var (
		total   = int64(120)
		limit32 = int32(50)
		limit64 = int64(50)
		qt      = 0.02
		trace   = "trace-xyz"
		offset  = int32(10)
		quota   = int32(9)
		opaque  = "opaque-token"

		// The Recon rule quota's live shape, including a genuine zero for pending.
		quotaTotal   = int32(500)
		quotaActive  = int32(371)
		quotaPending = int32(0)
	)

	tests := []struct {
		name string
		meta any
		want string
	}{{
		name: "MsaMetaInfo drops powered_by and writes",
		meta: &models.MsaMetaInfo{
			Pagination: &models.MsaPaging{Total: &total, Limit: &limit32, Offset: &offset},
			QueryTime:  &qt,
			TraceID:    &trace,
			PoweredBy:  "crowdstrike-api",
			Writes:     &models.MsaResources{},
		},
		want: `{"pagination":{"total":120,"limit":50,"offset":10},"query_time":0.02,"trace_id":"trace-xyz"}`,
	}, {
		name: "DomainMsaMetaInfo carries only pagination",
		meta: &models.DomainMsaMetaInfo{
			Pagination: &models.MsaPaging{Total: &total},
		},
		want: `{"pagination":{"total":120}}`,
	}, {
		name: "AssetgroupmanagerV1Meta non-pointer scalars and numeric offset",
		meta: &models.AssetgroupmanagerV1Meta{
			Pagination: &models.AssetgroupmanagerV1Pagination{Total: 120, Limit: 50, Offset: 10},
			QueryTime:  0.02,
			TraceID:    trace,
			PoweredBy:  "crowdstrike-api",
		},
		want: `{"pagination":{"total":120,"limit":50,"offset":10},"query_time":0.02,"trace_id":"trace-xyz"}`,
	}, {
		name: "APIIndicatorsQueryMeta after becomes next",
		meta: &models.APIIndicatorsQueryMeta{
			Pagination: &models.APIIndicatorsQueryPaging{Total: &total, Limit: &limit32, Offset: 10, After: "cursor-A"},
		},
		want: `{"pagination":{"total":120,"limit":50,"offset":10,"next":"cursor-A"}}`,
	}, {
		// gofalcon types this offset as an interface{} holding a string. No tool
		// reaches IocapiResponseMeta, so this is a forward-compat guard: a
		// non-numeric offset is dropped and every other field survives.
		name: "IocapiResponseMeta string offset is dropped, rest survives",
		meta: &models.IocapiResponseMeta{
			Pagination: &models.IocapiPaginationMeta{Total: 120, Limit: 50, Offset: "opaque-token", NextPage: "cursor-I"},
		},
		want: `{"pagination":{"total":120,"limit":50,"next":"cursor-I"}}`,
	}, {
		name: "DomainSPAPIQueryMeta keeps quota",
		meta: &models.DomainSPAPIQueryMeta{
			Pagination: &models.DomainSPAPIQueryPaging{Total: &total, Limit: &limit32, After: new("cursor-S")},
			QueryTime:  &qt,
			TraceID:    &trace,
			Quota:      &models.DomainQuota{Total: &quota, Used: &quota},
		},
		want: `{"pagination":{"total":120,"limit":50,"next":"cursor-S"},"query_time":0.02,"trace_id":"trace-xyz","quota":{"total":9,"used":9}}`,
	}, {
		name: "MetaGetSecurityChecks next wins and previous is dropped",
		meta: &models.MetaGetSecurityChecks{
			Pagination: &models.PaginationMetaGetSecurityChecks{
				Limit: &limit64, Offset: &total, Next: new("cursor-N"), Previous: new("cursor-P"),
			},
		},
		want: `{"pagination":{"total":null,"limit":50,"offset":120,"next":"cursor-N"}}`,
	}, {
		// Another forward-compat guard: gofalcon types this offset as *string, and
		// no tool calls the combined or scroll device operations behind it. It is one
		// of several string-typed offset shapes, none reachable from a wired-up tool.
		name: "DeviceapiMetaInfo string offset is dropped, rest survives",
		meta: &models.DeviceapiMetaInfo{
			Pagination: &models.DeviceapiDevicePagingV2{Offset: &opaque, Limit: 50, Next: "cursor-D"},
			QueryTime:  &qt,
			TraceID:    &trace,
		},
		want: `{"pagination":{"total":null,"limit":50,"next":"cursor-D"},"query_time":0.02,"trace_id":"trace-xyz"}`,
	}, {
		name: "FwmgrAPIMetaInfo after becomes next",
		meta: &models.FwmgrAPIMetaInfo{
			Pagination: &models.FwmgrAPIQueryPaging{Total: &total, Limit: &limit32, Offset: 10, After: "cursor-F"},
			QueryTime:  &qt,
			TraceID:    &trace,
		},
		want: `{"pagination":{"total":120,"limit":50,"offset":10,"next":"cursor-F"},"query_time":0.02,"trace_id":"trace-xyz"}`,
	}, {
		name: "DomainDiscoverAPIMetaInfo after becomes next",
		meta: &models.DomainDiscoverAPIMetaInfo{
			Pagination: &models.DomainDiscoverAPIPaging{Total: &total, Limit: &limit32, After: new("cursor-G")},
			QueryTime:  &qt,
			TraceID:    &trace,
		},
		want: `{"pagination":{"total":120,"limit":50,"next":"cursor-G"},"query_time":0.02,"trace_id":"trace-xyz"}`,
	}, {
		name: "mutation meta carries only query_time and trace_id",
		meta: &models.MsaMetaInfo{
			QueryTime: &qt,
			TraceID:   &trace,
			Writes:    &models.MsaResources{},
		},
		want: `{"query_time":0.02,"trace_id":"trace-xyz"}`,
	}, {
		// CSPM assets and IOM report the cursor as a sibling of pagination rather
		// than inside it, and their nested paging block has no cursor field at all.
		name: "RestCursorAndLimitMetaInfo sibling next folds into pagination",
		meta: &models.RestCursorAndLimitMetaInfo{
			Next:       "cursor-C",
			Pagination: &models.RestPaging{Total: &total, Limit: &limit64, Offset: 10},
			QueryTime:  &qt,
			TraceID:    &trace,
			PoweredBy:  "crowdstrike-api",
		},
		want: `{"pagination":{"total":120,"limit":50,"offset":10,"next":"cursor-C"},"query_time":0.02,"trace_id":"trace-xyz"}`,
	}, {
		// The backward cursor is not carried, matching the nested-paging types.
		name: "RestCursorAndLimitMetaInfo sibling prev is not a forward cursor",
		meta: &models.RestCursorAndLimitMetaInfo{
			Prev:       "cursor-P",
			Pagination: &models.RestPaging{Total: &total, Limit: &limit64},
			QueryTime:  &qt,
			TraceID:    &trace,
		},
		want: `{"pagination":{"total":120,"limit":50},"query_time":0.02,"trace_id":"trace-xyz"}`,
	}, {
		// These endpoints report a sibling cursor with no pagination block at all,
		// so the cursor has to be carried in a synthesized one.
		name: "RestCursorMetaInfo sibling next with no pagination block",
		meta: &models.RestCursorMetaInfo{
			Next:      "cursor-R",
			QueryTime: &qt,
			TraceID:   &trace,
			PoweredBy: "crowdstrike-api",
		},
		want: `{"pagination":{"total":null,"next":"cursor-R"},"query_time":0.02,"trace_id":"trace-xyz"}`,
	}, {
		name: "APICursorMetaInfo sibling next with no pagination block",
		meta: &models.APICursorMetaInfo{
			Next:      "cursor-A2",
			QueryTime: &qt,
			TraceID:   &trace,
		},
		want: `{"pagination":{"total":null,"next":"cursor-A2"},"query_time":0.02,"trace_id":"trace-xyz"}`,
	}, {
		// Recon reports its monitoring-rule allowance as total/active/pending
		// rather than the total/used the Spotlight endpoints report. All three are
		// actionable: active and pending are what consume the allowance, and
		// pending is legitimately zero here.
		name: "DomainRuleMetaInfo keeps the rule quota's active and pending",
		meta: &models.DomainRuleMetaInfo{
			Pagination: &models.MsaPaging{Total: &total, Limit: &limit32, Offset: &offset},
			QueryTime:  &qt,
			TraceID:    &trace,
			Quota:      &models.DomainRuleQuota{Total: &quotaTotal, Active: &quotaActive, Pending: &quotaPending},
			PoweredBy:  "crowdstrike-api",
		},
		want: `{"pagination":{"total":120,"limit":50,"offset":10},"query_time":0.02,"trace_id":"trace-xyz","quota":{"total":500,"active":371,"pending":0}}`,
	}}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := metaJSON(t, tt.meta); got != tt.want {
				t.Errorf("normalized meta mismatch\n got: %s\nwant: %s", got, tt.want)
			}
		})
	}
}

// TestNormalizeMetaCursorPrecedence covers the cursor collapse in isolation: each
// spelling the APIs use lands in next, snake_case after wins when a payload
// carries several, and an all-empty pagination leaves next absent. The cursor may
// also arrive as a sibling of pagination rather than inside it, at lowest
// precedence; a sibling-only payload gets a synthesized pagination to carry it.
func TestNormalizeMetaCursorPrecedence(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		raw  string
		want string
	}{
		{"after", `{"pagination":{"total":1,"after":"c"}}`, "c"},
		{"next", `{"pagination":{"total":1,"next":"c"}}`, "c"},
		{"next_page", `{"pagination":{"total":1,"next_page":"c"}}`, "c"},
		{"after wins over next", `{"pagination":{"total":1,"after":"c","next":"other"}}`, "c"},
		{"next wins over next_page", `{"pagination":{"total":1,"next":"c","next_page":"other"}}`, "c"},
		{"previous is not a forward cursor", `{"pagination":{"total":1,"previous":"c"}}`, ""},
		{"no cursor", `{"pagination":{"total":1}}`, ""},
		{"sibling next folds in", `{"next":"c","pagination":{"total":1}}`, "c"},
		{"sibling next with no pagination block", `{"next":"c"}`, "c"},
		{"nested after wins over sibling next", `{"next":"other","pagination":{"total":1,"after":"c"}}`, "c"},
		{"nested next wins over sibling next", `{"next":"other","pagination":{"total":1,"next":"c"}}`, "c"},
		{"sibling prev is not a forward cursor", `{"prev":"c","pagination":{"total":1}}`, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var m Meta
			if err := json.Unmarshal([]byte(tt.raw), &m); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if m.Pagination == nil {
				t.Fatal("pagination must be present")
			}
			if m.Pagination.Next != tt.want {
				t.Errorf("next = %q, want %q", m.Pagination.Next, tt.want)
			}
		})
	}
}

// TestPagingOffsetDecode covers the offset contract a paging caller depends on: a
// numeric offset round-trips as a number, so an integer-typed offset input accepts it
// without conversion, and a real zero is reported rather than conflated with an
// absent value. A non-numeric offset leaves the field absent instead of failing the
// decode, so the rest of the block survives.
func TestPagingOffsetDecode(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		raw  string
		want string
	}{
		// Numeric offsets, the only form any endpoint wired up today reports.
		{"number", `{"offset":10}`, `{"total":null,"offset":10}`},
		{"real zero is reported", `{"offset":0}`, `{"total":null,"offset":0}`},
		{"negative", `{"offset":-5}`, `{"total":null,"offset":-5}`},
		// Absent and null are the same thing: no offset to report.
		{"absent", `{}`, `{"total":null}`},
		{"null", `{"offset":null}`, `{"total":null}`},
		// A non-numeric offset is dropped, and total survives alongside it. Several
		// gofalcon paging models type the field this way, none reachable from a tool.
		{"string is dropped, total kept", `{"offset":"opaque-token","total":120}`, `{"total":120}`},
		{"digit string is dropped", `{"offset":"12345"}`, `{"total":null}`},
		{"object is dropped", `{"offset":{"k":"v"}}`, `{"total":null}`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var p Paging
			if err := json.Unmarshal([]byte(tt.raw), &p); err != nil {
				t.Fatalf("unmarshal %s: %v", tt.raw, err)
			}
			got, err := json.Marshal(p)
			if err != nil {
				t.Fatalf("marshal %+v: %v", p, err)
			}
			if string(got) != tt.want {
				t.Errorf("%s marshaled to %s, want %s", tt.raw, got, tt.want)
			}
		})
	}
}

// TestNormalizeMetaQueryTimeCasing covers the Recon endpoints' camelCase spelling
// and the precedence when a payload carries both forms.
func TestNormalizeMetaQueryTimeCasing(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		raw  string
		want float64
	}{
		{"snake_case", `{"query_time":0.5}`, 0.5},
		{"camelCase", `{"queryTime":0.5}`, 0.5},
		{"snake_case wins", `{"query_time":0.5,"queryTime":9}`, 0.5},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var m Meta
			if err := json.Unmarshal([]byte(tt.raw), &m); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if m.QueryTime == nil {
				t.Fatal("query_time must be populated")
			}
			if *m.QueryTime != tt.want {
				t.Errorf("query_time = %v, want %v", *m.QueryTime, tt.want)
			}
		})
	}
}

// TestNormalizeMetaNullTotal proves an absent match count survives as a JSON null
// rather than being dropped or coerced to zero, so a caller can tell "the API
// reported no count" from "the count is zero" and knows to keep paging.
func TestNormalizeMetaNullTotal(t *testing.T) {
	t.Parallel()

	m := normalizeMeta(&models.MsaMetaInfo{Pagination: &models.MsaPaging{Total: nil}})
	if m == nil {
		t.Fatal("a populated pagination block must not be dropped")
	}
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if got, want := string(raw), `{"pagination":{"total":null}}`; got != want {
		t.Fatalf("meta = %s, want %s", got, want)
	}

	var probe struct {
		Pagination map[string]json.RawMessage `json:"pagination"`
	}
	if err := json.Unmarshal(raw, &probe); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	total, ok := probe.Pagination["total"]
	if !ok {
		t.Fatal("total key must be present even when null")
	}
	if string(total) != "null" {
		t.Fatalf("total = %s, want null", total)
	}

	zero := int64(0)
	m = normalizeMeta(&models.MsaMetaInfo{Pagination: &models.MsaPaging{Total: &zero}})
	raw, err = json.Marshal(m)
	if err != nil {
		t.Fatalf("marshal zero total: %v", err)
	}
	if got, want := string(raw), `{"pagination":{"total":0}}`; got != want {
		t.Fatalf("zero total = %s, want %s", got, want)
	}
}

// TestNormalizeMetaDropsNothingReportable covers the inputs that must leave the
// meta field absent: an untyped nil, a typed nil pointer (an interface holding one
// is itself non-nil, so omitempty alone would emit "null"), and a meta whose only
// fields are ones we do not carry.
func TestNormalizeMetaDropsNothingReportable(t *testing.T) {
	t.Parallel()

	var typedNil *models.MsaMetaInfo
	tests := []struct {
		name string
		meta any
	}{
		{"untyped nil", nil},
		{"typed nil pointer", typedNil},
		{"empty struct", &models.MsaMetaInfo{}},
		{"only dropped fields", &models.MsaMetaInfo{PoweredBy: "crowdstrike-api", Writes: &models.MsaResources{}}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := normalizeMeta(tt.meta); got != nil {
				raw, _ := json.Marshal(got)
				t.Errorf("normalizeMeta = %s, want nil", raw)
			}
		})
	}
}

// TestNormalizeMetaUnconvertibleDegrades proves meta conversion never fails a tool
// call. The resources the caller asked for are already in hand, so a value that
// cannot be marshaled (a channel) or whose JSON does not fit the Meta shape (a
// bare array) yields no meta rather than an error.
func TestNormalizeMetaUnconvertibleDegrades(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		meta any
	}{
		{"unmarshalable value", struct{ Ch chan int }{Ch: make(chan int)}},
		{"json is not an object", []string{"a", "b"}},
		{"json is a scalar", 42},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := normalizeMeta(tt.meta); got != nil {
				t.Errorf("normalizeMeta = %+v, want nil", got)
			}
		})
	}
}

// TestWithMetaOmitsAbsentMeta covers the three envelopes together: a populated
// meta is attached and normalized, and an empty one leaves the key out of the JSON
// rather than emitting "meta":null.
func TestWithMetaOmitsAbsentMeta(t *testing.T) {
	t.Parallel()

	total := int64(3)
	populated := &models.MsaMetaInfo{Pagination: &models.MsaPaging{Total: &total}}
	var typedNil *models.MsaMetaInfo

	hasMetaKey := func(t *testing.T, v any) bool {
		t.Helper()
		raw, err := json.Marshal(v)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		var m map[string]json.RawMessage
		if err := json.Unmarshal(raw, &m); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		_, ok := m["meta"]
		return ok
	}

	t.Run("SearchResult", func(t *testing.T) {
		t.Parallel()
		got := Found([]string{"a"}, "").WithMeta(populated)
		if got.Meta == nil || got.Meta.Pagination == nil || *got.Meta.Pagination.Total != 3 {
			t.Fatalf("Meta = %+v, want pagination.total 3", got.Meta)
		}
		if hasMetaKey(t, Found([]string{"a"}, "").WithMeta(typedNil)) {
			t.Error("typed-nil meta must be omitted from SearchResult JSON")
		}
	})
	t.Run("EntitiesResult", func(t *testing.T) {
		t.Parallel()
		got := Entities([]string{"a"}).WithMeta(populated)
		if got.Meta == nil || got.Meta.Pagination == nil || *got.Meta.Pagination.Total != 3 {
			t.Fatalf("Meta = %+v, want pagination.total 3", got.Meta)
		}
		if hasMetaKey(t, Entities([]string{"a"}).WithMeta(typedNil)) {
			t.Error("typed-nil meta must be omitted from EntitiesResult JSON")
		}
	})
	t.Run("ActionResult", func(t *testing.T) {
		t.Parallel()
		got := ActionResult{Ok: true}.WithMeta(populated)
		if got.Meta == nil || got.Meta.Pagination == nil || *got.Meta.Pagination.Total != 3 {
			t.Fatalf("Meta = %+v, want pagination.total 3", got.Meta)
		}
		if hasMetaKey(t, ActionResult{Ok: true}.WithMeta(typedNil)) {
			t.Error("typed-nil meta must be omitted from ActionResult JSON")
		}
	})
}

// TestMetaSchemaIsDescriptive proves the trimmed Meta advertises a real schema
// rather than the accept-anything object an any-typed field would produce, so a
// client can discover the pagination contract from tools/list.
func TestMetaSchemaIsDescriptive(t *testing.T) {
	t.Parallel()

	schema := inferOutputSchema[SearchResult[policyDates]]()
	if schema == nil {
		t.Fatal("inferOutputSchema returned nil for SearchResult")
	}
	for _, path := range [][]string{
		{"meta", "pagination", "total"},
		{"meta", "pagination", "limit"},
		{"meta", "pagination", "offset"},
		{"meta", "pagination", "next"},
		{"meta", "query_time"},
		{"meta", "trace_id"},
		{"meta", "quota", "total"},
		{"meta", "quota", "used"},
	} {
		if got := findProp(t, schema, path...); got == nil {
			t.Errorf("schema is missing %v", path)
		}
	}
	if got := schemaType(findProp(t, schema, "meta", "pagination", "next")); got != "string" {
		t.Errorf("pagination.next type = %q, want string", got)
	}
	// The output-side counterpart to TestOffsetInputsAreIntegers: the reported offset
	// must be the same JSON type every tool's offset input accepts, so a caller can
	// feed it back without a type conversion. How far to advance it is endpoint-specific.
	if got := schemaType(findProp(t, schema, "meta", "pagination", "offset")); got != "integer" {
		t.Errorf("pagination.offset type = %q, want integer", got)
	}
}

// TestMetaValidatesAgainstSchema is the end-to-end guard that every normalized
// shape validates against the resolved output schema over the SDK path. A typed
// Meta constrains the payload, so a mapping that produced an unexpected JSON type
// (e.g. an offset left as a number) would be caught here rather than by a client.
func TestMetaValidatesAgainstSchema(t *testing.T) {
	t.Parallel()

	schema := inferOutputSchema[SearchResult[policyDates]]()
	resolved, err := schema.Resolve(&jsonschema.ResolveOptions{ValidateDefaults: true})
	if err != nil {
		t.Fatalf("resolve schema: %v", err)
	}

	var (
		total   = int64(120)
		limit32 = int32(50)
		qt      = 0.02
		trace   = "trace-xyz"
		quota   = int32(9)
		opaque  = "opaque-token"
	)
	metas := []any{
		&models.MsaMetaInfo{Pagination: &models.MsaPaging{Total: &total, Limit: &limit32}, QueryTime: &qt, TraceID: &trace},
		&models.APIIndicatorsQueryMeta{Pagination: &models.APIIndicatorsQueryPaging{Total: &total, Offset: 10, After: "c"}},
		&models.IocapiResponseMeta{Pagination: &models.IocapiPaginationMeta{Total: 120, Offset: "tok", NextPage: "c"}},
		&models.DeviceapiMetaInfo{Pagination: &models.DeviceapiDevicePagingV2{Offset: &opaque, Next: "c"}},
		&models.AssetgroupmanagerV1Meta{Pagination: &models.AssetgroupmanagerV1Pagination{Total: 120, Offset: 10}, QueryTime: 0.02, TraceID: trace},
		&models.DomainSPAPIQueryMeta{QueryTime: &qt, TraceID: &trace, Quota: &models.DomainQuota{Total: &quota, Used: &quota}},
		&models.MsaMetaInfo{Pagination: &models.MsaPaging{Total: nil}},
		&models.MsaMetaInfo{QueryTime: &qt, TraceID: &trace},
	}

	for _, meta := range metas {
		result := Found([]policyDates{}, "status:'open'").WithMeta(meta)
		raw, err := json.Marshal(result)
		if err != nil {
			t.Fatalf("marshal result: %v", err)
		}
		var instance any
		if err := json.Unmarshal(raw, &instance); err != nil {
			t.Fatalf("unmarshal result: %v", err)
		}
		if err := resolved.Validate(instance); err != nil {
			t.Errorf("%T must validate against the output schema: %v\n  payload: %s", meta, err, raw)
		}
	}
}

// TestNormalizeMetaDropsUnusedFields pins the allowlist: fields the API returns
// that a caller cannot act on are absent from the output, keeping the envelope
// small and its shape identical across endpoints.
func TestNormalizeMetaDropsUnusedFields(t *testing.T) {
	t.Parallel()

	affected := int32(3)
	total := int64(1)
	qt := 0.02
	raw, err := json.Marshal(normalizeMeta(&models.MsaMetaInfo{
		Pagination: &models.MsaPaging{Total: &total},
		QueryTime:  &qt,
		PoweredBy:  "crowdstrike-api",
		Writes:     &models.MsaResources{ResourcesAffected: &affected},
	}))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var got map[string]json.RawMessage
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, key := range []string{"powered_by", "writes", "errors", "previous", "next_page", "after"} {
		if _, ok := got[key]; ok {
			t.Errorf("meta must not carry %q, got %s", key, raw)
		}
	}
	if _, ok := got["pagination"]; !ok {
		t.Errorf("meta must carry pagination, got %s", raw)
	}
}
