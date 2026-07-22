package idp

import (
	"strings"
	"testing"
)

// These tests lock down GraphQL string embedding: user-controlled values must
// not break out of string/enum context. Before the fix, entity IDs and times
// were interpolated as ["%s"] / "%s" and event types as raw unquoted tokens.

func TestBuildTimelineQueryEscapesEntityID(t *testing.T) {
	t.Parallel()
	// Classic string breakout: close the array/string and inject another field.
	malicious := `e1"], first: 999) { nodes { entityId } } } } #`
	q := buildTimelineQuery(malicious, "", "", nil, 10)

	// The malicious payload must appear only as a JSON-escaped string element,
	// not as raw GraphQL structure.
	if strings.Contains(q, `entityIds: ["e1"]`) {
		t.Fatalf("entity ID must not be raw-quoted; injection would succeed:\n%s", q)
	}
	// json.Marshal escapes quotes and backslashes inside the string value.
	if !strings.Contains(q, `sourceEntityQuery: {entityIds: ["e1\"], first: 999) { nodes { entityId } } } } #"]}`) &&
		!strings.Contains(q, `"e1\"], first: 999`) {
		// Prefer checking that the breakout sequence is inside a JSON string
		// (escaped quote before the injected structure).
		if !strings.Contains(q, `\"], first: 999`) {
			t.Fatalf("expected JSON-escaped breakout payload in entityIds, got:\n%s", q)
		}
	}
	// Injected structure must not appear outside of a string literal as a
	// sibling field of sourceEntityQuery.
	if strings.Contains(q, `entityIds: ["e1"], first: 999`) {
		t.Fatalf("breakout produced a second first: argument outside string context:\n%s", q)
	}
}

func TestBuildTimelineQueryEscapesTimes(t *testing.T) {
	t.Parallel()
	start := `2024-01-01T00:00:00Z", categories: [ACTIVITY`
	end := `2024-12-31T23:59:59Z"} #`
	q := buildTimelineQuery("entity-safe", start, end, nil, 5)

	// Times must be JSON string literals (escaped), not raw "..." embedding.
	if strings.Contains(q, `startTime: "2024-01-01T00:00:00Z", categories: [ACTIVITY`) {
		t.Fatalf("startTime breakout not escaped:\n%s", q)
	}
	if !strings.Contains(q, `startTime: "2024-01-01T00:00:00Z\", categories: [ACTIVITY"`) {
		t.Fatalf("expected JSON-escaped startTime, got:\n%s", q)
	}
	if !strings.Contains(q, `endTime: "2024-12-31T23:59:59Z\"} #"`) {
		t.Fatalf("expected JSON-escaped endTime, got:\n%s", q)
	}
	// Valid limit still present as integer argument.
	if !strings.Contains(q, "first: 5") {
		t.Fatalf("expected first: 5 in query:\n%s", q)
	}
}

func TestBuildTimelineQueryAllowlistsEventTypes(t *testing.T) {
	t.Parallel()
	// Injection via unquoted enum: close list and inject another argument.
	injection := []string{
		"ACTIVITY",
		`THREAT] , first: 1) { __typename } #`,
		"BOGUS",
		"AUDIT",
	}
	q := buildTimelineQuery("e1", "", "", injection, 10)

	if !strings.Contains(q, "categories: [ACTIVITY, AUDIT]") {
		t.Fatalf("expected only allowlisted categories ACTIVITY, AUDIT; got:\n%s", q)
	}
	if strings.Contains(q, "__typename") || strings.Contains(q, "BOGUS") || strings.Contains(q, "THREAT]") {
		t.Fatalf("injected/unknown event types must be dropped:\n%s", q)
	}
}

func TestBuildTimelineQueryDropsAllInvalidEventTypes(t *testing.T) {
	t.Parallel()
	q := buildTimelineQuery("e1", "", "", []string{`ACTIVITY]`, "not-an-enum", ""}, 10)
	if strings.Contains(q, "categories:") {
		t.Fatalf("categories filter must be omitted when nothing is allowlisted:\n%s", q)
	}
}

func TestBuildTimelineQuerySafeHappyPath(t *testing.T) {
	t.Parallel()
	q := buildTimelineQuery(
		"entity-001",
		"2024-01-01T00:00:00Z",
		"2024-01-31T23:59:59Z",
		[]string{"ACTIVITY", "THREAT"},
		25,
	)
	if !strings.Contains(q, `sourceEntityQuery: {entityIds: ["entity-001"]}`) {
		t.Fatalf("expected safe entityIds list, got:\n%s", q)
	}
	if !strings.Contains(q, `startTime: "2024-01-01T00:00:00Z"`) {
		t.Fatalf("expected JSON startTime, got:\n%s", q)
	}
	if !strings.Contains(q, `endTime: "2024-01-31T23:59:59Z"`) {
		t.Fatalf("expected JSON endTime, got:\n%s", q)
	}
	if !strings.Contains(q, "categories: [ACTIVITY, THREAT]") {
		t.Fatalf("expected categories list, got:\n%s", q)
	}
	if !strings.Contains(q, "first: 25") {
		t.Fatalf("expected first: 25, got:\n%s", q)
	}
}

func TestBuildRelationshipQueryEscapesEntityID(t *testing.T) {
	t.Parallel()
	malicious := `e1"], first: 1) { nodes { entityId } } } #`
	q := buildRelationshipQuery(malicious, 1, false, 10)

	if strings.Contains(q, `entityIds: ["e1"], first: 1)`) {
		t.Fatalf("relationship entity ID breakout not escaped:\n%s", q)
	}
	// Escaped quote must appear inside the JSON string element.
	if !strings.Contains(q, `"e1\"], first: 1) { nodes { entityId } } } #"`) {
		t.Fatalf("expected JSON-escaped entity ID in relationship query:\n%s", q)
	}
	// The legitimate first: limit remains the integer argument.
	if !strings.Contains(q, ", first: 10)") {
		t.Fatalf("expected first: 10 as the real limit:\n%s", q)
	}
}

func TestBuildRelationshipQuerySafeHappyPath(t *testing.T) {
	t.Parallel()
	q := buildRelationshipQuery("entity-abc", 2, true, 15)
	if !strings.Contains(q, `entityIds: ["entity-abc"]`) {
		t.Fatalf("expected JSON entityIds, got:\n%s", q)
	}
	if !strings.Contains(q, "riskScore") {
		t.Fatalf("expected risk fields when includeRiskContext:\n%s", q)
	}
	if !strings.Contains(q, "associations") {
		t.Fatalf("expected associations at depth 2:\n%s", q)
	}
}

func TestBuildEntityDetailsAndRiskUseJSONList(t *testing.T) {
	t.Parallel()
	// Batch builders already used jsonList; confirm injection-shaped IDs stay in strings.
	ids := []string{`x"], first: 1) {`, "safe-id"}
	details := buildEntityDetailsQuery(ids, false, false, false, false)
	risk := buildRiskAssessmentQuery(ids, false)

	for name, q := range map[string]string{"details": details, "risk": risk} {
		if !strings.Contains(q, `"x\"], first: 1) {"`) {
			t.Fatalf("%s: expected JSON-escaped malicious id, got:\n%s", name, q)
		}
		if !strings.Contains(q, `"safe-id"`) {
			t.Fatalf("%s: expected safe-id present, got:\n%s", name, q)
		}
	}
}

func TestFilterTimelineCategories(t *testing.T) {
	t.Parallel()
	got := filterTimelineCategories([]string{"ACTIVITY", "nope", "SYSTEM", "ACTIVITY]inject"})
	if len(got) != 2 || got[0] != "ACTIVITY" || got[1] != "SYSTEM" {
		t.Fatalf("unexpected filter result: %v", got)
	}
	if filterTimelineCategories(nil) != nil {
		t.Fatalf("nil input should yield nil")
	}
	if out := filterTimelineCategories([]string{}); out != nil {
		t.Fatalf("empty input should yield nil, got %v", out)
	}
}

func TestJSONStringEscapesSpecials(t *testing.T) {
	t.Parallel()
	// Document the encoding contract used by query builders.
	if got := jsonString(`a"b\c`); got != `"a\"b\\c"` {
		t.Fatalf("jsonString specials: got %s", got)
	}
	if got := jsonList([]string{`x"y`, "z"}); got != `["x\"y","z"]` {
		t.Fatalf("jsonList specials: got %s", got)
	}
}
