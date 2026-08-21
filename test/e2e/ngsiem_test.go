package e2e

import (
	"context"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// The ngsiem specs exercise falcon_search_ngsiem against the live tenant. Unlike
// the FQL search modules, this tool drives NGSIEM's asynchronous job-based CQL
// search: it starts a query job, polls to completion, and returns the matching
// event records. The specs are read-only, cap results with a `| head(...)` in
// the CQL, and tolerate an empty tenant. Events are arbitrary JSON objects with
// no fixed ID field, so there is no search->get-by-id chain to exercise.
//
// The default 60s spec timeout can be tight for a job-based search that has to
// start, run, and be polled; each spec extends its own context so a slow-but-real
// search still completes. Label("ngsiem") allows selecting just this module with
// --label-filter="ngsiem"; Label("integration") marks the live tier.
var _ = Describe("ngsiem module", Label("integration", "ngsiem"), func() {
	var ctx context.Context

	BeforeEach(func() {
		// Give the job-based search room beyond the default per-spec deadline.
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(context.Background(), 2*time.Minute)
		DeferCleanup(cancel)
	})

	itAdvertisesTools("falcon_search_ngsiem")

	It("runs a CQL query and returns event records", func() {
		res := callOK(ctx, "falcon_search_ngsiem", map[string]any{
			"query_string": "#event_simpleName=ProcessRollup2 | head(5)",
			"start":        startISO(24 * time.Hour),
			"repository":   "search-all",
		})
		skipIfEmpty(res, "tenant returned no ProcessRollup2 events in the last 24h")
		// Events are free-form JSON objects; assert each returned resource is an
		// object (not a bare id), which confirms the poll loop surfaced full event
		// records rather than identifiers.
		for i, r := range resources(res) {
			_, ok := r.(map[string]any)
			Expect(ok).To(BeTrue(), "event[%d] should be a JSON object, got %T", i, r)
		}
	})

	It("accepts an explicit end time", func() {
		res := callOK(ctx, "falcon_search_ngsiem", map[string]any{
			"query_string": "#event_simpleName=ProcessRollup2 | head(1)",
			"start":        startISO(24 * time.Hour),
			"end":          startISO(0),
		})
		// An empty window is a valid outcome; the point is that supplying end does
		// not error. resources() still asserts the envelope shape.
		_ = resources(res)
	})
})

// startISO returns an RFC 3339 UTC timestamp `ago` before now, formatted the way
// falcon_search_ngsiem expects its start/end inputs (an ISO 8601 timestamp,
// which the tool converts to epoch milliseconds). ago==0 yields the current
// time, used as an explicit end bound.
func startISO(ago time.Duration) string {
	return time.Now().Add(-ago).UTC().Format(time.RFC3339)
}
