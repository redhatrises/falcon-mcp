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
// The ml search validates the typed detail path: gofalcon types the ML get
// response groups field as []string (PR #683), so a real ML record with host
// groups decodes cleanly through the typed model + modelsToMaps round-trip. A
// passing ml search here confirms that path with no raw-capture workaround.
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

	It("searches ML exclusions and returns full records via the typed path", func() {
		cs := newSession(ctx)
		res := callTool(ctx, cs, "falcon_search_exclusions", map[string]any{
			"exclusion_type": "ml",
			"limit":          3,
		})
		expectNoToolError(res)
		skipIfEmpty(res, "tenant has no ML exclusions")
		// value is present on every ML exclusion record; its presence confirms the
		// detail fetch returned full objects decoded through the typed groups model.
		expectSearchReturnsDetails(res, "id", "value")
	})

	It("surfaces the raw API meta object on a populated search", func() {
		cs := newSession(ctx)
		res := callTool(ctx, cs, "falcon_search_exclusions", map[string]any{
			"exclusion_type": "ml",
			"limit":          3,
		})
		expectNoToolError(res)
		skipIfEmpty(res, "tenant has no ML exclusions")
		// The pagination passthrough attaches the query-step meta verbatim; a
		// populated search must carry a meta object (e.g. pagination/query_time).
		obj := structured(res)
		meta, ok := obj["meta"].(map[string]any)
		Expect(ok).To(BeTrue(), "expected a meta object on a populated search, got %v", obj["meta"])
		Expect(meta).NotTo(BeEmpty(), "meta object should carry at least one field")
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

	It("preserves applied_globally on IOA records (nullable-field fidelity)", func() {
		// gofalcon PR #686 retyped IOA/CB applied_globally as *bool so a present
		// false round-trips instead of being dropped by omitempty — the fix that
		// let the module drop its raw-capture reader. Assert at least one IOA
		// record carries the applied_globally key (present, regardless of value).
		cs := newSession(ctx)
		res := callTool(ctx, cs, "falcon_search_exclusions", map[string]any{
			"exclusion_type": "ioa",
			"limit":          10,
		})
		expectNoToolError(res)
		skipIfEmpty(res, "tenant has no IOA exclusions")
		found := false
		for _, r := range resources(res) {
			obj, ok := r.(map[string]any)
			Expect(ok).To(BeTrue(), "IOA resource should be a full object, got %T", r)
			if _, present := obj["applied_globally"]; present {
				found = true
				break
			}
		}
		Expect(found).To(BeTrue(),
			"expected at least one IOA record to carry applied_globally; the nullable-field fix should surface it verbatim")
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
