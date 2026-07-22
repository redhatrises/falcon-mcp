package e2e

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// The quarantine specs exercise falcon_search_quarantined_files and
// falcon_preview_quarantine_actions against the live tenant. They are read-only
// (preview does not mutate state), use a small limit, and tolerate an empty
// tenant. Label("quarantine") allows selecting just this module with
// --label-filter="quarantine"; Label("integration") marks the live tier.
var _ = Describe("quarantine module", Label("integration", "quarantine"), func() {
	var ctx context.Context

	BeforeEach(func() {
		ctx = newSpecContext()
	})

	It("advertises its read tools with the falcon_ prefix", func() {
		cs := newSession(ctx)
		names := toolNames(ctx, cs)
		Expect(names).To(ContainElements(
			"falcon_search_quarantined_files",
			"falcon_preview_quarantine_actions",
		))
	})

	It("searches quarantined files and returns full records", func() {
		cs := newSession(ctx)
		res := callTool(ctx, cs, "falcon_search_quarantined_files", map[string]any{"limit": 3})
		expectNoToolError(res)
		skipIfEmpty(res, "tenant has no quarantined files to validate details against")
		expectSearchReturnsDetails(res, "id")
	})

	It("searches quarantined files sorted by date_updated", func() {
		cs := newSession(ctx)
		res := callTool(ctx, cs, "falcon_search_quarantined_files", map[string]any{
			"sort":  "date_updated|desc",
			"limit": 3,
		})
		expectNoToolError(res)
		skipIfEmpty(res, "tenant has no quarantined files to sort")
		expectSearchReturnsDetails(res, "id")
	})

	It("previews quarantine actions for a filter", func() {
		cs := newSession(ctx)
		// preview_quarantine_actions is a read-only aggregation over a filter; an
		// empty tenant yields an empty resources array, which is a valid outcome.
		res := callTool(ctx, cs, "falcon_preview_quarantine_actions", map[string]any{
			"filter": "state:'quarantined'",
		})
		expectNoToolError(res)
		// No details assertion: the aggregation payload shape is not a two-step
		// entity search, so only the protocol/tool success is asserted here.
		_ = resources(res)
	})
})
