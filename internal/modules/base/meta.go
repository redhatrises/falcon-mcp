package base

import (
	"encoding/json"
	"log/slog"
	"reflect"
	"strconv"
)

// Paging is the normalized pagination block. It reconciles the several shapes the
// Falcon APIs use into one: Next carries whichever cursor field the endpoint
// populated, and Offset is always a number, so it is the same JSON type every tool's
// integer-typed offset input accepts. Offset's meaning is endpoint-specific — some
// APIs report the offset the request was served at, others the offset of the next
// page — so it is advisory, not a portable "add the page size to advance" rule.
// Prefer Next for forward paging wherever the endpoint populates it.
//
// Total deliberately has no omitempty. Some endpoints report no match count at
// all, and a JSON null distinguishes "the API gave no count" from a real zero;
// dropping the key would conflate the two. A caller that sees a null total must
// keep paging until resources comes back empty rather than trusting the count.
//
// One case defeats that distinction, and it is a gofalcon defect rather than a
// choice made here: where gofalcon types a paging field as a non-pointer numeric
// with omitempty, its own marshal drops a genuine zero before normalizeMeta runs,
// so a real total of 0 arrives indistinguishable from an absent one and is
// reported as null. AssetgroupmanagerV1Pagination is the reachable instance
// (search_cloud_groups). Following the null-total advice there means one extra
// page fetch that returns nothing, which is the same outcome the advice already
// prescribes. The fix belongs upstream, not in a local workaround.
type Paging struct {
	Total  *int64 `json:"total"`
	Limit  *int64 `json:"limit,omitempty"`
	Offset *int64 `json:"offset,omitempty"`
	Next   string `json:"next,omitempty"`
}

// UnmarshalJSON decodes any of the API's pagination shapes into p, collapsing the
// endpoint-specific cursor spellings into Next. Falcon names the forward cursor
// "after" (intel, spotlight, firewall, discover, IOC) or "next" (device, Shield);
// the first non-empty one wins. "next_page" is also decoded, but only a gofalcon
// paging shape no wired-up tool reaches carries it, so it is a forward-compat guard.
// The backward cursor ("previous", Shield only) is not carried.
//
// Offset is decoded through a raw message and parsed, so a value that is not a JSON
// number leaves it absent instead of failing the decode. Meta.UnmarshalJSON
// propagates an error from here and normalizeMeta degrades a failed decode to no
// meta at all, so a strict field would discard total and trace_id over an offset the
// caller cannot act on anyway. No endpoint wired up today reports a non-numeric
// offset; gofalcon types the field as a string on several paging models (the device,
// threatgraph, detects-query, assessment, and IOC shapes among them), none of which
// a tool reaches.
func (p *Paging) UnmarshalJSON(b []byte) error {
	var raw struct {
		Total    *int64          `json:"total"`
		Limit    *int64          `json:"limit"`
		Offset   json.RawMessage `json:"offset"`
		After    string          `json:"after"`
		Next     string          `json:"next"`
		NextPage string          `json:"next_page"`
	}
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	p.Total, p.Limit = raw.Total, raw.Limit
	if offset, err := strconv.ParseInt(string(raw.Offset), 10, 64); err == nil {
		p.Offset = &offset
	}
	for _, cursor := range []string{raw.After, raw.Next, raw.NextPage} {
		if cursor != "" {
			p.Next = cursor
			break
		}
	}
	return nil
}

// Quota is the API allowance an endpoint reports. The Spotlight endpoints report
// a request budget as total/used; the Recon rules endpoint reports its
// monitoring-rule budget as total/active/pending, where active and pending are
// what consume the allowance. A caller approaching Total has nearly exhausted its
// allowance. Every field is a pointer with omitempty, so a field an endpoint's own
// shape does not carry is absent rather than reported as a zero it never sent.
// Unlike Paging.Total, these fields are pointers in gofalcon too, so a real zero
// survives the conversion.
type Quota struct {
	Total   *int64 `json:"total,omitempty"`
	Used    *int64 `json:"used,omitempty"`
	Active  *int64 `json:"active,omitempty"`
	Pending *int64 `json:"pending,omitempty"`
}

// Meta is the response metadata attached to every tool result envelope. It is a
// fixed shape holding the fields a client can act on — the pagination cursor and
// count, the server-side query duration, the trace ID to quote in a support
// request, and the Spotlight request quota — rather than whatever the endpoint
// happened to return.
type Meta struct {
	Pagination *Paging  `json:"pagination,omitempty"`
	QueryTime  *float64 `json:"query_time,omitempty"`
	TraceID    string   `json:"trace_id,omitempty"`
	Quota      *Quota   `json:"quota,omitempty"`
}

// UnmarshalJSON decodes an API meta object into m, accepting both spellings of
// the query duration. The endpoints themselves report query_time; the camelCase
// arm exists because this decodes gofalcon's re-marshaled struct rather than the
// wire bytes, and DomainMsaMetaInfo — the Recon notifications and
// exposed-data-records shape — tags the field queryTime. snake_case wins when a
// payload carries both.
//
// The forward cursor may also arrive as a sibling of pagination rather than
// inside it: the CSPM assets and IOM endpoints report it as a top-level "next",
// and their nested paging block carries no cursor field at all. Fold that sibling
// into Paging.Next at lowest precedence, so a nested cursor always wins, and
// synthesize a Paging when the response carries no nested block to hold it. The
// sibling backward cursor ("prev") is not carried, matching Paging.
func (m *Meta) UnmarshalJSON(b []byte) error {
	var raw struct {
		Pagination     *Paging  `json:"pagination"`
		QueryTime      *float64 `json:"query_time"`
		QueryTimeCamel *float64 `json:"queryTime"`
		TraceID        string   `json:"trace_id"`
		Quota          *Quota   `json:"quota"`
		Next           string   `json:"next"`
	}
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	m.Pagination, m.TraceID, m.Quota = raw.Pagination, raw.TraceID, raw.Quota
	if m.QueryTime = raw.QueryTime; m.QueryTime == nil {
		m.QueryTime = raw.QueryTimeCamel
	}
	if raw.Next != "" {
		if m.Pagination == nil {
			m.Pagination = &Paging{}
		}
		if m.Pagination.Next == "" {
			m.Pagination.Next = raw.Next
		}
	}
	return nil
}

// isEmpty reports whether m carries nothing worth sending, so the caller can
// omit the field entirely rather than emit an empty object.
func (m *Meta) isEmpty() bool {
	return m.Pagination == nil && m.QueryTime == nil && m.TraceID == "" && m.Quota == nil
}

// NormalizedMeta converts a gofalcon response meta object into the Meta shape a
// tool result carries, for use in module tests. A handler's result meta should
// equal NormalizedMeta of the meta its fake API returned; comparing against the
// raw gofalcon struct would instead assert the passthrough that WithMeta
// deliberately no longer performs.
func NormalizedMeta(v any) *Meta {
	return normalizeMeta(v)
}

// normalizeMeta converts a gofalcon response meta object into the fixed Meta
// shape, returning nil when there is nothing to report so a meta,omitempty field
// is omitted rather than serialized as an empty object or a JSON null. A nil or
// nil-pointer input yields nil: an interface holding a typed nil pointer is
// itself non-nil, so omitempty alone would emit "null" without this guard.
//
// The conversion is a JSON round-trip rather than a type switch. Around two dozen
// distinct gofalcon meta types reach this function and most of the Shield ones are
// structurally identical but nominally distinct, so a switch would need an arm per
// type and a new arm on every SDK bump. Marshaling reuses gofalcon's own struct
// tags as the field mapping, which keeps the mapping correct by construction.
//
// Meta is advisory, so a conversion failure degrades to no meta rather than
// failing the tool call: the resources the caller asked for are already in hand.
func normalizeMeta(v any) *Meta {
	if v == nil {
		return nil
	}
	if rv := reflect.ValueOf(v); rv.Kind() == reflect.Pointer && rv.IsNil() {
		return nil
	}

	raw, err := json.Marshal(v)
	if err != nil {
		slog.Default().Warn("dropping unmarshalable response meta", "type", reflect.TypeOf(v).String(), "error", err)
		return nil
	}
	var m Meta
	if err := json.Unmarshal(raw, &m); err != nil {
		slog.Default().Warn("dropping undecodable response meta", "type", reflect.TypeOf(v).String(), "error", err)
		return nil
	}
	if m.isEmpty() {
		return nil
	}
	return &m
}
