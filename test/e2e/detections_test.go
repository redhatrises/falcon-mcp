package e2e

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// The detections specs exercise falcon_search_detections against the live
// tenant. They are read-only, use a small limit, and tolerate an empty tenant.
// Label("detections") allows selecting just this module with
// --label-filter="detections"; Label("integration") marks the live tier.
var _ = Describe("detections module", Label("integration", "detections"), func() {
	var ctx context.Context

	BeforeEach(func() {
		ctx = newSpecContext()
	})

	It("advertises its tools with the falcon_ prefix", func() {
		cs := newSession(ctx)
		Expect(toolNames(ctx, cs)).To(ContainElement("falcon_search_detections"))
	})

	It("searches detections and returns full alert records", func() {
		cs := newSession(ctx)
		res := callTool(ctx, cs, "falcon_search_detections", map[string]any{"limit": 3})
		expectNoToolError(res)
		skipIfEmpty(res, "tenant has no detections to validate details against")
		// composite_id is the field the module keys detail results on, so its
		// presence confirms the two-step query->details fetch returned full
		// records rather than bare IDs.
		expectSearchReturnsDetails(res, "composite_id")
	})

	It("searches detections with an FQL filter", func() {
		cs := newSession(ctx)
		res := callTool(ctx, cs, "falcon_search_detections", map[string]any{
			"filter": "status:'new'",
			"limit":  3,
		})
		expectNoToolError(res)
		skipIfEmpty(res, "no new detections in tenant")
		expectSearchReturnsDetails(res, "composite_id", "severity", "status")
	})

	It("searches detections sorted by severity", func() {
		cs := newSession(ctx)
		res := callTool(ctx, cs, "falcon_search_detections", map[string]any{
			"sort":  "severity.desc",
			"limit": 3,
		})
		expectNoToolError(res)
		skipIfEmpty(res, "tenant has no detections to sort")
		expectSearchReturnsDetails(res, "composite_id", "severity", "status")
	})
})
