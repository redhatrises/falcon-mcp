package e2e

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// The exclusions specs exercise falcon_search_exclusions across all four
// exclusion types (ioa, ml, sensor_visibility, certificate) against the live
// tenant. They are read-only, use a small limit, and tolerate an empty tenant.
// The mutating tools (create/update/delete) are intentionally not exercised here
// to avoid changing tenant state. Label("exclusions") selects just this module.
//
// The ml search doubly validates the raw-capture detail path: the gofalcon ML
// get model types groups as objects while the live API returns []string, so a
// typed get would hard-fail — a passing ml search here confirms the workaround.
var _ = Describe("exclusions module", Label("integration", "exclusions"), func() {
	var ctx context.Context

	BeforeEach(func() {
		ctx = newSpecContext()
	})

	It("advertises its tools with the falcon_ prefix", func() {
		cs := newSession(ctx)
		names := toolNames(ctx, cs)
		Expect(names).To(ContainElements(
			"falcon_search_exclusions",
			"falcon_create_exclusion",
			"falcon_update_exclusion",
			"falcon_delete_exclusions",
			"falcon_get_certificate_details",
		))
	})

	It("searches IOA exclusions and returns full records", func() {
		cs := newSession(ctx)
		res := callTool(ctx, cs, "falcon_search_exclusions", map[string]any{
			"exclusion_type": "ioa",
			"limit":          3,
		})
		expectNoToolError(res)
		skipIfEmpty(res, "tenant has no IOA exclusions")
		expectSearchReturnsDetails(res, "id")
	})

	It("searches ML exclusions and returns full records via the raw-capture path", func() {
		cs := newSession(ctx)
		res := callTool(ctx, cs, "falcon_search_exclusions", map[string]any{
			"exclusion_type": "ml",
			"limit":          3,
		})
		expectNoToolError(res)
		skipIfEmpty(res, "tenant has no ML exclusions")
		// value is present on every ML exclusion record; its presence confirms the
		// detail fetch returned full objects despite the gofalcon groups model bug.
		expectSearchReturnsDetails(res, "id", "value")
	})

	It("searches sensor visibility exclusions and returns full records", func() {
		cs := newSession(ctx)
		res := callTool(ctx, cs, "falcon_search_exclusions", map[string]any{
			"exclusion_type": "sensor_visibility",
			"limit":          3,
		})
		expectNoToolError(res)
		skipIfEmpty(res, "tenant has no sensor visibility exclusions")
		expectSearchReturnsDetails(res, "id", "value")
	})

	It("searches certificate-based exclusions and returns full records", func() {
		cs := newSession(ctx)
		res := callTool(ctx, cs, "falcon_search_exclusions", map[string]any{
			"exclusion_type": "certificate",
			"limit":          3,
		})
		expectNoToolError(res)
		skipIfEmpty(res, "tenant has no certificate-based exclusions")
		expectSearchReturnsDetails(res, "id")
	})

	It("applies a boolean FQL filter supported by every type", func() {
		cs := newSession(ctx)
		res := callTool(ctx, cs, "falcon_search_exclusions", map[string]any{
			"exclusion_type": "ml",
			"filter":         "applied_globally:true",
			"limit":          3,
		})
		expectNoToolError(res)
		skipIfEmpty(res, "no globally-applied ML exclusions in tenant")
		expectSearchReturnsDetails(res, "id", "value")
	})

	It("sorts IOA exclusions by last_modified without the created_on sort trap", func() {
		// IOA rejects sort=created_on.desc with a 400; last_modified.desc is the
		// correct field. A passing call confirms the tool built a valid sort.
		cs := newSession(ctx)
		res := callTool(ctx, cs, "falcon_search_exclusions", map[string]any{
			"exclusion_type": "ioa",
			"sort":           "last_modified.desc",
			"limit":          3,
		})
		expectNoToolError(res)
		skipIfEmpty(res, "tenant has no IOA exclusions to sort")
		expectSearchReturnsDetails(res, "id")
	})

	It("rejects an invalid exclusion_type with a tool error", func() {
		cs := newSession(ctx)
		res := callTool(ctx, cs, "falcon_search_exclusions", map[string]any{
			"exclusion_type": "bogus",
			"limit":          3,
		})
		Expect(res.IsError).To(BeTrue(), "expected an invalid exclusion_type to be a tool error")
	})
})
