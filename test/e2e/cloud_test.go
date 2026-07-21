package e2e

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// The cloud specs exercise the read-only cloud tools against the live tenant.
// They use small limits and tolerate an empty tenant. Label("cloud") allows
// selecting just this module. The mutating suppression-rule tools
// (create/delete) are intentionally not exercised here to avoid altering tenant
// state.
var _ = Describe("cloud module", Label("integration", "cloud"), func() {
	var ctx context.Context

	BeforeEach(func() {
		ctx = newSpecContext()
	})

	It("searches kubernetes containers and returns full records", func() {
		cs := newSession(ctx)
		res := callTool(ctx, cs, "falcon_search_kubernetes_containers", map[string]any{"limit": 3})
		expectNoToolError(res)
		skipIfEmpty(res, "tenant has no kubernetes containers")
		expectSearchReturnsDetails(res, "container_id")
	})

	It("counts kubernetes containers", func() {
		cs := newSession(ctx)
		res := callTool(ctx, cs, "falcon_count_kubernetes_containers", map[string]any{})
		expectNoToolError(res)
		obj := structured(res)
		Expect(obj).To(HaveKey("count"), "count result should carry a count field")
	})

	It("searches image vulnerabilities and returns full records", func() {
		cs := newSession(ctx)
		res := callTool(ctx, cs, "falcon_search_images_vulnerabilities", map[string]any{"limit": 3})
		expectNoToolError(res)
		skipIfEmpty(res, "tenant has no image vulnerabilities")
		expectSearchReturnsDetails(res, "cve_id")
	})

	It("searches CSPM assets and returns slimmed records with an id", func() {
		cs := newSession(ctx)
		res := callTool(ctx, cs, "falcon_search_cspm_assets", map[string]any{"limit": 3})
		expectNoToolError(res)
		skipIfEmpty(res, "tenant has no CSPM assets")
		expectSearchReturnsDetails(res, "id")
	})

	It("searches IOM findings and returns full records", func() {
		cs := newSession(ctx)
		res := callTool(ctx, cs, "falcon_search_iom_findings", map[string]any{"limit": 3})
		expectNoToolError(res)
		skipIfEmpty(res, "tenant has no IOM findings")
		expectSearchReturnsDetails(res, "id")
	})

	It("searches cloud risks and returns full records", func() {
		cs := newSession(ctx)
		res := callTool(ctx, cs, "falcon_search_cloud_risks", map[string]any{"limit": 3})
		expectNoToolError(res)
		skipIfEmpty(res, "tenant has no cloud risks")
		expectSearchReturnsDetails(res, "id")
	})

	It("searches cloud groups and returns full records", func() {
		cs := newSession(ctx)
		res := callTool(ctx, cs, "falcon_search_cloud_groups", map[string]any{"limit": 3})
		expectNoToolError(res)
		skipIfEmpty(res, "tenant has no cloud groups")
		expectSearchReturnsDetails(res, "id")
	})

	It("gets cloud groups by id found from search", func() {
		cs := newSession(ctx)
		search := callTool(ctx, cs, "falcon_search_cloud_groups", map[string]any{"limit": 1})
		expectNoToolError(search)
		id := firstResourceID(search, "id") // skips when the tenant has no groups

		details := callTool(ctx, cs, "falcon_get_cloud_groups", map[string]any{"ids": []string{id}})
		expectNoToolError(details)
		got := resources(details)
		Expect(got).To(HaveLen(1), "expected exactly one group for one id")
		obj, ok := got[0].(map[string]any)
		Expect(ok).To(BeTrue(), "group detail should be an object, got %T", got[0])
		Expect(obj).To(HaveKeyWithValue("id", id))
	})

	It("searches CSPM suppression rules", func() {
		cs := newSession(ctx)
		res := callTool(ctx, cs, "falcon_search_cspm_suppression_rules", map[string]any{"limit": 3})
		expectNoToolError(res)
		// Returns an empty list when no rules exist; nothing to assert on shape.
	})

	It("returns an FQL error result for an invalid cloud risks filter", func() {
		cs := newSession(ctx)
		res := callTool(ctx, cs, "falcon_search_cloud_risks", map[string]any{
			"filter": "definitely_not_a_field:'x'",
			"limit":  3,
		})
		// Invalid FQL is a data result, not a protocol/tool error.
		expectNoToolError(res)
		obj := structured(res)
		Expect(obj).To(HaveKey("errors"), "expected FQL error details in the result")
	})
})
