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
		res := callOK(ctx, "falcon_search_kubernetes_containers", map[string]any{"limit": 3})
		skipIfEmpty(res, "tenant has no kubernetes containers")
		expectSearchReturnsDetails(res, "container_id")
	})

	It("counts kubernetes containers", func() {
		res := callOK(ctx, "falcon_count_kubernetes_containers", map[string]any{})
		obj := structured(res)
		Expect(obj).To(HaveKey("count"), "count result should carry a count field")
	})

	It("counts kubernetes containers with a filter", func() {
		res := callOK(ctx, "falcon_count_kubernetes_containers", map[string]any{
			"filter": "running_status:true",
		})
		Expect(structured(res)).To(HaveKey("count"))
	})

	It("searches kubernetes containers sorted by last_seen", func() {
		res := callOK(ctx, "falcon_search_kubernetes_containers", map[string]any{
			"sort":  "last_seen.desc",
			"limit": 3,
		})
		skipIfEmpty(res, "tenant has no kubernetes containers to sort")
		expectSearchReturnsDetails(res, "container_id")
	})

	It("searches image vulnerabilities and returns full records", func() {
		res := callOK(ctx, "falcon_search_images_vulnerabilities", map[string]any{"limit": 3})
		skipIfEmpty(res, "tenant has no image vulnerabilities")
		expectSearchReturnsDetails(res, "cve_id")
	})

	It("searches CSPM assets and returns slimmed records with an id", func() {
		res := callOK(ctx, "falcon_search_cspm_assets", map[string]any{"limit": 3})
		skipIfEmpty(res, "tenant has no CSPM assets")
		expectSearchReturnsDetails(res, "id")
	})

	It("searches CSPM assets sorted by updated_at", func() {
		res := callOK(ctx, "falcon_search_cspm_assets", map[string]any{
			"sort":  "updated_at.desc",
			"limit": 3,
		})
		skipIfEmpty(res, "tenant has no CSPM assets to sort")
		expectSearchReturnsDetails(res, "id")
	})

	It("searches IOM findings and returns full records", func() {
		res := callOK(ctx, "falcon_search_iom_findings", map[string]any{"limit": 3})
		skipIfEmpty(res, "tenant has no IOM findings")
		expectSearchReturnsDetails(res, "id")
	})

	It("searches IOM findings sorted by severity", func() {
		res := callOK(ctx, "falcon_search_iom_findings", map[string]any{
			"sort":  "severity|desc",
			"limit": 3,
		})
		skipIfEmpty(res, "tenant has no IOM findings to sort")
		expectSearchReturnsDetails(res, "id")
	})

	It("searches cloud risks and returns full records", func() {
		res := callOK(ctx, "falcon_search_cloud_risks", map[string]any{"limit": 3})
		skipIfEmpty(res, "tenant has no cloud risks")
		expectSearchReturnsDetails(res, "id")
	})

	It("searches cloud groups and returns full records", func() {
		res := callOK(ctx, "falcon_search_cloud_groups", map[string]any{"limit": 3})
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
		// Returns an empty list when no rules exist; nothing to assert on shape.
		callOK(ctx, "falcon_search_cspm_suppression_rules", map[string]any{"limit": 3})
	})

	It("returns an FQL error result for an invalid cloud risks filter", func() {
		res := callOK(ctx, "falcon_search_cloud_risks", map[string]any{
			"filter": "definitely_not_a_field:'x'",
			"limit":  3,
		})
		// Invalid FQL is a data result, not a protocol/tool error.
		obj := structured(res)
		Expect(obj).To(HaveKey("errors"), "expected FQL error details in the result")
	})

	It("creates, finds, and deletes a CSPM suppression rule", Label("mutating"), func() {
		cs := newSession(ctx)
		name := uniqueTestName("suppression")

		create := callTool(ctx, cs, "falcon_create_cspm_suppression_rule", map[string]any{
			"name":               name,
			"suppression_reason": "false-positive",
			// Scope by a severity that need not match any live finding; the rule
			// is created regardless and cleaned up below.
			"rule_severities": []any{"informational"},
		})
		skipIfToolError(create, "create suppression rule (CSPM write scope required)")
		_, id := createdObject(create, "id")

		deferToolCleanup("falcon_delete_cspm_suppression_rules", map[string]any{
			"ids": []string{id},
		})

		// Round-trip: the created rule must appear in the suppression-rule list.
		// The list endpoint has no name/id filter, so scan the first 500; a tenant
		// with more than 500 suppression rules could hide the new one. Poll
		// because the list is eventually consistent after a create.
		Eventually(func() []string {
			found := callTool(ctx, cs, "falcon_search_cspm_suppression_rules", map[string]any{"limit": 500})
			expectNoToolError(found)
			return idsOf(found, "id")
		}).Should(ContainElement(id), "created suppression rule not found in search")
	})
})
