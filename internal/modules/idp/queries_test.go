package idp

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/crowdstrike/gofalcon/falcon/client/identity_protection"
)

// These tests lock down how caller-controlled values enter the GraphQL queries.
// The builders embed values in two distinct contexts, each with its own rule:
//
//   - String context (entity IDs, start/end times): JSON-encoded, so quotes,
//     backslashes, and control characters cannot terminate the literal early.
//   - Enum context (timeline categories): GraphQL enums are bare identifiers
//     and cannot be quoted, so only known-good values are allowed through.
//
// The assertions below check those properties structurally rather than by
// matching rendered substrings, so they keep holding if field order or
// formatting in the query text changes.

// jsonStringLiteral matches a JSON string literal: a quote, then any run of
// escapes or non-quote, non-backslash characters, then the closing quote.
var jsonStringLiteral = regexp.MustCompile(`"(?:[^"\\]|\\.)*"`)

// graphQLStrings extracts every double-quoted JSON string literal from a query,
// returning the decoded values. Anything a builder embedded correctly appears
// here as a single element; a value that escaped its literal would instead show
// up as query structure and be absent.
func graphQLStrings(t *testing.T, query string) []string {
	t.Helper()
	matches := jsonStringLiteral.FindAllString(query, -1)
	out := make([]string, 0, len(matches))
	for _, m := range matches {
		var s string
		if err := json.Unmarshal([]byte(m), &s); err != nil {
			t.Fatalf("query contains a malformed string literal %s: %v\nquery:\n%s", m, err, query)
		}
		out = append(out, s)
	}
	return out
}

// assertContained verifies that value appears in the query only as the decoded
// content of a single JSON string literal. This is the property that makes
// injection impossible: the payload is data, never structure.
func assertContained(t *testing.T, query, value string) {
	t.Helper()
	if slices.Contains(graphQLStrings(t, query), value) {
		return
	}
	t.Fatalf("value %q did not survive as a single JSON string literal (it broke out of string context)\nquery:\n%s", value, query)
}

// stripStrings removes every JSON string literal from a query, leaving only the
// GraphQL structure. Assertions about structure run against this so a payload
// quoted safely inside a literal can never satisfy them. Literals are removed
// entirely rather than replaced with an empty pair of quotes, so the result
// contains no literal for a second pass to match.
func stripStrings(t *testing.T, query string) string {
	t.Helper()
	return jsonStringLiteral.ReplaceAllString(query, "")
}

// injectionPayloads are breakout attempts shaped for the contexts the builders
// interpolate into: closing a string, a list, and an argument list, then opening
// sibling structure.
//
// sanitized is what sanitizeInput must produce for each payload, written out by
// hand rather than computed: a test that derived it by calling sanitizeInput
// would keep passing if sanitizeInput stopped stripping anything at all.
var injectionPayloads = []struct {
	name      string
	payload   string
	sanitized string
}{
	{
		name:      "close string and add argument",
		payload:   `e1", first: 999`,
		sanitized: `e1, first: 999`,
	},
	{
		name:      "close list and add sibling field",
		payload:   `e1"], first: 999) { nodes { entityId } } } } #`,
		sanitized: `e1], first: 999) { nodes { entityId } } } } #`,
	},
	{
		name:      "backslash before quote",
		payload:   `e1\", first: 999`,
		sanitized: `e1, first: 999`,
	},
	{
		name:      "embedded newline and quote",
		payload:   "e1\"\n, first: 999",
		sanitized: `e1, first: 999`,
	},
	{
		name:      "wildcard with breakout",
		payload:   `*"], first: 1000) { nodes { entityId } `,
		sanitized: `*], first: 1000) { nodes { entityId } `,
	},
}

func TestBuildTimelineQueryEncodesEntityID(t *testing.T) {
	t.Parallel()
	for _, tc := range injectionPayloads {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			q := buildTimelineQuery(tc.payload, "", "", nil, 10)

			assertContained(t, q, tc.payload)

			// The only integer argument in the structure must be the real limit.
			if got := structuralFirstArgs(t, q); len(got) != 1 || got[0] != "10" {
				t.Fatalf("expected exactly one first: argument (the real limit 10), got %v\nquery:\n%s", got, q)
			}
		})
	}
}

func TestBuildTimelineQueryEncodesTimes(t *testing.T) {
	t.Parallel()
	start := `2024-01-01T00:00:00Z", categories: [ACTIVITY`
	end := `2024-12-31T23:59:59Z"} #`

	q := buildTimelineQuery("entity-safe", start, end, nil, 5)

	assertContained(t, q, start)
	assertContained(t, q, end)

	// No categories filter was requested, so the injected one must not appear as
	// structure.
	if strings.Contains(stripStrings(t, q), "categories:") {
		t.Fatalf("injected categories argument leaked into query structure:\n%s", q)
	}
	if got := structuralFirstArgs(t, q); len(got) != 1 || got[0] != "5" {
		t.Fatalf("expected only the real limit 5, got %v\nquery:\n%s", got, q)
	}
}

// structuralFirstArgs returns every `first: N` argument value that appears in
// the query's structure (outside any string literal).
func structuralFirstArgs(t *testing.T, query string) []string {
	t.Helper()
	re := regexp.MustCompile(`first:\s*(\d+)`)
	var out []string
	for _, m := range re.FindAllStringSubmatch(stripStrings(t, query), -1) {
		out = append(out, m[1])
	}
	return out
}

func TestBuildTimelineQueryAllowlistsCategories(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name  string
		types []string
		want  string // expected rendered categories argument; "" means omitted
	}{
		{
			name:  "all valid preserved in order",
			types: []string{"ACTIVITY", "THREAT", "SYSTEM"},
			want:  "categories: [ACTIVITY, THREAT, SYSTEM]",
		},
		{
			name:  "every documented enum accepted",
			types: []string{"ACTIVITY", "NOTIFICATION", "THREAT", "ENTITY", "AUDIT", "POLICY", "SYSTEM"},
			want:  "categories: [ACTIVITY, NOTIFICATION, THREAT, ENTITY, AUDIT, POLICY, SYSTEM]",
		},
		{
			name:  "unknown value dropped",
			types: []string{"ACTIVITY", "BOGUS", "AUDIT"},
			want:  "categories: [ACTIVITY, AUDIT]",
		},
		{
			name:  "injection-shaped value dropped",
			types: []string{"ACTIVITY", `THREAT] , first: 1) { __typename } #`, "AUDIT"},
			want:  "categories: [ACTIVITY, AUDIT]",
		},
		{
			name:  "case variant rejected as enums are case-sensitive",
			types: []string{"activity", "Threat"},
			want:  "",
		},
		{
			name:  "whitespace-padded value rejected",
			types: []string{" ACTIVITY ", "AUDIT"},
			want:  "categories: [AUDIT]",
		},
		{
			name:  "empty string dropped",
			types: []string{"", "POLICY"},
			want:  "categories: [POLICY]",
		},
		{
			name:  "all invalid omits the filter entirely",
			types: []string{`ACTIVITY]`, "not-an-enum", ""},
			want:  "",
		},
		{
			name:  "no types omits the filter",
			types: nil,
			want:  "",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			q := buildTimelineQuery("e1", "", "", tc.types, 10)
			structure := stripStrings(t, q)

			if tc.want == "" {
				if strings.Contains(structure, "categories:") {
					t.Fatalf("expected no categories filter, got:\n%s", q)
				}
				return
			}
			if !strings.Contains(structure, tc.want) {
				t.Fatalf("expected %q in query, got:\n%s", tc.want, q)
			}
			// A dropped value must not appear anywhere, in any context.
			if strings.Contains(q, "__typename") || strings.Contains(q, "BOGUS") {
				t.Fatalf("a rejected category leaked into the query:\n%s", q)
			}
		})
	}
}

func TestBuildRelationshipQueryEncodesEntityID(t *testing.T) {
	t.Parallel()
	for _, tc := range injectionPayloads {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			q := buildRelationshipQuery(tc.payload, 1, false, 10)

			assertContained(t, q, tc.payload)

			if got := structuralFirstArgs(t, q); len(got) != 1 || got[0] != "10" {
				t.Fatalf("expected exactly one first: argument (the real limit 10), got %v\nquery:\n%s", got, q)
			}
		})
	}
}

func TestBatchBuildersEncodeEntityIDs(t *testing.T) {
	t.Parallel()
	// buildEntityDetailsQuery and buildRiskAssessmentQuery already encoded their
	// IDs; these guard against a regression that reintroduces raw interpolation.
	malicious := `x"], first: 1) { nodes { entityId } } } #`
	ids := []string{malicious, "safe-id"}

	for name, q := range map[string]string{
		"entity details":  buildEntityDetailsQuery(ids, false, false, false, false),
		"risk assessment": buildRiskAssessmentQuery(ids, false),
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			assertContained(t, q, malicious)
			assertContained(t, q, "safe-id")
		})
	}
}

func TestBuildersRenderValidQueriesForSafeInput(t *testing.T) {
	t.Parallel()
	// The encoding must not disturb the happy path: legitimate values render as
	// ordinary arguments.
	timeline := buildTimelineQuery("entity-001", "2024-01-01T00:00:00Z", "2024-01-31T23:59:59Z",
		[]string{"ACTIVITY", "THREAT"}, 25)

	for _, want := range []string{
		`sourceEntityQuery: {entityIds: ["entity-001"]}`,
		`startTime: "2024-01-01T00:00:00Z"`,
		`endTime: "2024-01-31T23:59:59Z"`,
		"categories: [ACTIVITY, THREAT]",
		"first: 25",
	} {
		if !strings.Contains(timeline, want) {
			t.Fatalf("timeline query missing %q:\n%s", want, timeline)
		}
	}

	relationship := buildRelationshipQuery("entity-abc", 2, true, 15)
	for _, want := range []string{
		`entityIds: ["entity-abc"]`,
		"first: 15",
		"riskScore",
		"associations",
	} {
		if !strings.Contains(relationship, want) {
			t.Fatalf("relationship query missing %q:\n%s", want, relationship)
		}
	}
}

func TestFilterTimelineCategories(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name         string
		in           []string
		want         []string
		wantRejected []string
	}{
		{name: "nil yields nothing", in: nil},
		{name: "empty yields nothing", in: []string{}},
		{name: "all rejected yields nothing", in: []string{"nope", "ACTIVITY]"}, wantRejected: []string{"nope", "ACTIVITY]"}},
		{name: "order preserved", in: []string{"SYSTEM", "ACTIVITY"}, want: []string{"SYSTEM", "ACTIVITY"}},
		{name: "mixed filters to valid", in: []string{"ACTIVITY", "nope", "SYSTEM"}, want: []string{"ACTIVITY", "SYSTEM"}, wantRejected: []string{"nope"}},
		{name: "duplicates passed through", in: []string{"AUDIT", "AUDIT"}, want: []string{"AUDIT", "AUDIT"}},
		{name: "case variant rejected", in: []string{"activity"}, wantRejected: []string{"activity"}},
		{name: "whitespace-padded rejected", in: []string{" ACTIVITY "}, wantRejected: []string{" ACTIVITY "}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, rejected := filterTimelineCategories(tc.in)
			if !slices.Equal(got, tc.want) {
				t.Fatalf("kept %q, want %q", got, tc.want)
			}
			// The rejected values are reported verbatim so the warning names what
			// the caller got wrong.
			if !slices.Equal(rejected, tc.wantRejected) {
				t.Fatalf("rejected %q, want %q", rejected, tc.wantRejected)
			}
		})
	}
}

func TestJSONHelpersEscapeSpecials(t *testing.T) {
	t.Parallel()
	// Documents the encoding contract the builders rely on.
	for _, tc := range []struct {
		name string
		got  string
		want string
	}{
		{"string with quote and backslash", jsonString(`a"b\c`), `"a\"b\\c"`},
		{"string with newline", jsonString("a\nb"), `"a\nb"`},
		{"empty string", jsonString(""), `""`},
		{"list escapes elements", jsonList([]string{`x"y`, "z"}), `["x\"y","z"]`},
		{"nil list renders as empty array not null", jsonList(nil), `[]`},
		{"empty list renders as empty array", jsonList([]string{}), `[]`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if tc.got != tc.want {
				t.Fatalf("got %s, want %s", tc.got, tc.want)
			}
		})
	}
}

// TestEntityIDsNeutralizedEndToEnd is the defense-in-depth guard for the whole
// path a caller-supplied entity ID travels: investigateEntity -> resolveEntities
// -> the timeline and relationship builders -> the submitted GraphQL.
//
// Two independent layers apply. resolveEntities sanitizes direct entity IDs like
// every other identifier, stripping the quotes and backslashes a breakout needs;
// the builders then JSON-encode at the point of embedding. Either alone is
// sufficient, so this asserts the outcome both produce: whatever reaches the wire
// is string data, never query structure.
func TestEntityIDsNeutralizedEndToEnd(t *testing.T) {
	t.Parallel()
	for _, tc := range injectionPayloads {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			// Both investigation types run per entity, so two queries are submitted.
			f := &fakeIDP{resps: []*identity_protection.APIPreemptProxyPostGraphqlOK{
				okResp(map[string]any{"timeline": map[string]any{"nodes": []any{}}}),
				okResp(entitiesData(map[string]any{"entityId": tc.payload})),
			}}
			m := newModule(f)

			_, _, apiErr := m.investigateEntity(context.Background(), nil, InvestigateInput{
				EntityIDs:          []string{tc.payload},
				InvestigationTypes: []string{investigationTimeline, investigationRelationships},
				TimelineEventTypes: []string{"ACTIVITY", `THREAT] , first: 1) { __typename } #`},
			})
			if apiErr != nil {
				t.Fatalf("unexpected API error: %v", apiErr)
			}

			if len(f.queries) != 2 {
				t.Fatalf("expected 2 submitted queries (timeline, relationship), got %d", len(f.queries))
			}

			for i, q := range f.queries {
				// The ID reached the wire only as string data, in its sanitized form.
				assertContained(t, q, tc.sanitized)

				// The injected limit never became a real argument.
				if got := structuralFirstArgs(t, q); len(got) != 1 || got[0] != "10" {
					t.Fatalf("query %d: expected only the real limit 10, got %v\nquery:\n%s", i, got, q)
				}

				// The injected enum was dropped; only the valid one survived.
				structure := stripStrings(t, q)
				if strings.Contains(structure, "__typename") {
					t.Fatalf("query %d: injected enum leaked into structure:\n%s", i, q)
				}
				if strings.Contains(structure, "categories:") &&
					!strings.Contains(structure, "categories: [ACTIVITY]") {
					t.Fatalf("query %d: expected only the allowlisted category:\n%s", i, q)
				}
			}
		})
	}
}

// TestTimelinesBatchWarnsOnRejectedCategories asserts the operator-facing half of
// the allowlist: a rejected event type is reported by name, so a caller who
// misspells one can tell why their timeline came back narrower than they asked
// for. Naming the values is the point — a bare count would not be actionable.
func TestTimelinesBatchWarnsOnRejectedCategories(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	m := newModule(&fakeIDP{
		resps: []*identity_protection.APIPreemptProxyPostGraphqlOK{
			okResp(map[string]any{"timeline": map[string]any{"nodes": []any{}}}),
			okResp(map[string]any{"timeline": map[string]any{"nodes": []any{}}}),
		},
	})
	m.Logger = slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn}))

	_, apiErr := m.timelinesBatch(context.Background(), []string{"e1", "e2"}, investigationParams{
		timelineEventTypes: []string{"ACTIVITY", "activity", "BOGUS"},
		limit:              10,
	})
	if apiErr != nil {
		t.Fatalf("unexpected API error: %v", apiErr)
	}

	logged := buf.String()
	for _, want := range []string{"activity", "BOGUS"} {
		if !strings.Contains(logged, want) {
			t.Fatalf("warning did not name the rejected value %q:\n%s", want, logged)
		}
	}

	// One warning for the batch, not one per entity.
	if got := strings.Count(logged, "Ignoring unrecognized timeline event types"); got != 1 {
		t.Fatalf("expected exactly 1 warning for the batch, got %d:\n%s", got, logged)
	}
}

// TestTimelinesBatchSilentWhenAllCategoriesValid guards against a warning that
// fires on the happy path, which would train operators to ignore it.
func TestTimelinesBatchSilentWhenAllCategoriesValid(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	m := newModule(&fakeIDP{
		resps: []*identity_protection.APIPreemptProxyPostGraphqlOK{
			okResp(map[string]any{"timeline": map[string]any{"nodes": []any{}}}),
		},
	})
	m.Logger = slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn}))

	if _, apiErr := m.timelinesBatch(context.Background(), []string{"e1"}, investigationParams{
		timelineEventTypes: []string{"ACTIVITY", "THREAT"},
		limit:              10,
	}); apiErr != nil {
		t.Fatalf("unexpected API error: %v", apiErr)
	}

	if buf.Len() != 0 {
		t.Fatalf("expected no warning for all-valid categories, got:\n%s", buf.String())
	}
}

// entity IDs go through sanitizeInput like every other identifier, so the
// invariant "all caller input is sanitized before reaching a builder" holds even
// for a future builder that forgets to encode.
func TestResolveEntitiesSanitizesDirectIDs(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		ids  []string
		want []string
	}{
		{
			name: "quotes stripped from a breakout attempt",
			ids:  []string{`e1", first: 999`},
			want: []string{"e1, first: 999"},
		},
		{
			name: "backslash stripped",
			ids:  []string{`e1\"x`},
			want: []string{"e1x"},
		},
		{
			name: "capped at 255 runes, not bytes",
			ids:  []string{strings.Repeat("é", 300)},
			want: []string{strings.Repeat("é", 255)},
		},
		{
			name: "a legitimate ID is untouched",
			ids:  []string{"entity-001"},
			want: []string{"entity-001"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			m := newModule(&fakeIDP{})

			// No query filters are supplied, so resolveEntities returns the direct IDs
			// without an API call.
			got, apiErr := m.resolveEntities(context.Background(), SearchCriteria{
				EntityIDs: tc.ids,
			}, 10)
			if apiErr != nil {
				t.Fatalf("unexpected API error: %v", apiErr)
			}
			if !slices.Equal(got, tc.want) {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}
