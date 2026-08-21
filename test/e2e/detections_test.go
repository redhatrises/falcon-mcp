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

	itAdvertisesTools(
		"falcon_search_detections",
		"falcon_get_detection_details",
		"falcon_update_detections",
	)

	It("searches detections and returns full alert records", func() {
		res := callOK(ctx, "falcon_search_detections", map[string]any{"limit": 3})
		skipIfEmpty(res, "tenant has no detections to validate details against")
		// composite_id is the field the module keys detail results on, so its
		// presence confirms the two-step query->details fetch returned full
		// records rather than bare IDs.
		expectSearchReturnsDetails(res, "composite_id")
	})

	It("searches detections with an FQL filter", func() {
		res := callOK(ctx, "falcon_search_detections", map[string]any{
			"filter": "status:'new'",
			"limit":  3,
		})
		skipIfEmpty(res, "no new detections in tenant")
		expectSearchReturnsDetails(res, "composite_id", "severity", "status")
	})

	It("searches detections sorted by severity", func() {
		res := callOK(ctx, "falcon_search_detections", map[string]any{
			"sort":  "severity.desc",
			"limit": 3,
		})
		skipIfEmpty(res, "tenant has no detections to sort")
		expectSearchReturnsDetails(res, "composite_id", "severity", "status")
	})

	It("gets detection details for an id found by search", func() {
		cs := newSession(ctx)
		search := callTool(ctx, cs, "falcon_search_detections", map[string]any{"limit": 1})
		expectNoToolError(search)
		id := firstResourceID(search, "composite_id") // skips when the tenant is empty

		details := callTool(ctx, cs, "falcon_get_detection_details", map[string]any{
			"ids": []string{id},
		})
		expectNoToolError(details)
		got := resources(details)
		Expect(got).To(HaveLen(1), "expected exactly one detection for one id")
		obj, ok := got[0].(map[string]any)
		Expect(ok).To(BeTrue(), "detection detail should be an object, got %T", got[0])
		Expect(obj).To(HaveKeyWithValue("composite_id", id))
	})

	It("adds and removes a tag on a detection found by search", Label("mutating"), func() {
		cs := newSession(ctx)
		search := callTool(ctx, cs, "falcon_search_detections", map[string]any{"limit": 1})
		expectNoToolError(search)
		id := firstResourceID(search, "composite_id") // skips when the tenant is empty
		tag := uniqueTestName("tag")

		add := callTool(ctx, cs, "falcon_update_detections", map[string]any{
			"ids":      []string{id},
			"add_tags": []any{tag},
		})
		skipIfToolError(add, "update detection (Alerts write scope required)")
		Expect(structured(add)).To(HaveKeyWithValue("ok", true))

		// Remove the tag regardless of later assertions, restoring the original
		// state.
		deferToolCleanup("falcon_update_detections", map[string]any{
			"ids":         []string{id},
			"remove_tags": []any{tag},
		})

		// Read back: the tag must be present on the detection. The update index
		// is eventually consistent, so poll rather than reading once.
		Eventually(func() []string {
			details := callTool(ctx, cs, "falcon_get_detection_details", map[string]any{
				"ids": []string{id},
			})
			expectNoToolError(details)
			got := resources(details)
			Expect(got).To(HaveLen(1))
			obj, ok := got[0].(map[string]any)
			Expect(ok).To(BeTrue(), "detection detail should be an object, got %T", got[0])
			return tagsOf(obj)
		}).Should(ContainElement(tag), "added tag not present after update")
	})
})
