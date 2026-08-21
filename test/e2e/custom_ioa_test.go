package e2e

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// The custom_ioa specs exercise the read-only Custom IOA tools against the live
// tenant: searching rule groups (with their rules), discovering platforms, and
// listing rule types. They use small limits and tolerate an empty tenant. The
// mutating tools (create/update/delete rule groups and rules) are not exercised
// here to avoid altering tenant state. Label("customioa") selects just this
// module.
var _ = Describe("customioa module", Label("integration", "customioa"), func() {
	var ctx context.Context

	BeforeEach(func() {
		ctx = newSpecContext()
	})

	itAdvertisesTools(
		"falcon_search_ioa_rule_groups",
		"falcon_get_ioa_platforms",
		"falcon_get_ioa_rule_types",
		"falcon_create_ioa_rule_group",
		"falcon_update_ioa_rule_group",
		"falcon_delete_ioa_rule_groups",
		"falcon_create_ioa_rule",
		"falcon_update_ioa_rule",
		"falcon_delete_ioa_rules",
	)

	It("searches IOA rule groups and returns full records", func() {
		res := callOK(ctx, "falcon_search_ioa_rule_groups", map[string]any{"limit": 3})
		skipIfEmpty(res, "tenant has no Custom IOA rule groups")
		// id/name/platform confirm QueryRuleGroupsFull returned full group
		// records, not bare IDs.
		expectSearchReturnsDetails(res, "id", "name", "platform")
	})

	It("searches IOA rule groups with an FQL filter", func() {
		res := callOK(ctx, "falcon_search_ioa_rule_groups", map[string]any{
			"filter": "platform:'windows'",
			"limit":  3,
		})
		skipIfEmpty(res, "no Windows Custom IOA rule groups in tenant")
		expectSearchReturnsDetails(res, "id", "name", "platform")
	})

	It("pages rule groups and rule types by advancing the reported offset", func() {
		cs := newSession(ctx)
		expectOffsetPaginates(ctx, cs, "falcon_search_ioa_rule_groups", map[string]any{"limit": 2})
		expectOffsetPaginates(ctx, cs, "falcon_get_ioa_rule_types", map[string]any{"limit": 2})
	})

	It("gets the available IOA platforms", func() {
		res := callOK(ctx, "falcon_get_ioa_platforms", map[string]any{})
		// Platforms are a fixed set on any tenant; the result must be non-empty
		// and each entry is an object carrying the platform id.
		got := resources(res)
		Expect(got).NotTo(BeEmpty(), "expected platform identifiers")
		ids := make([]string, 0, len(got))
		for _, r := range got {
			obj, ok := r.(map[string]any)
			Expect(ok).To(BeTrue(), "platform should be an object, got %T", r)
			id, ok := obj["id"].(string)
			Expect(ok).To(BeTrue(), "platform id should be a string")
			ids = append(ids, id)
		}
		Expect(ids).To(ContainElement("windows"))
	})

	It("lists IOA rule types and returns full records", func() {
		res := callOK(ctx, "falcon_get_ioa_rule_types", map[string]any{"limit": 5})
		skipIfEmpty(res, "tenant exposes no Custom IOA rule types")
		// id/platform confirm the two-step query->GetRuleTypes fetch returned
		// full rule-type records, not bare IDs.
		expectSearchReturnsDetails(res, "id", "platform")
	})

	It("creates, finds, and deletes an IOA rule group", Label("mutating"), func() {
		cs := newSession(ctx)
		name := uniqueTestName("ioagroup")

		create := callTool(ctx, cs, "falcon_create_ioa_rule_group", map[string]any{
			"name":        name,
			"platform":    "windows",
			"description": "disposable rule group created by falcon-mcp e2e",
		})
		skipIfToolError(create, "create IOA rule group (Custom IOA write scope required)")
		obj, id := createdObject(create, "id")

		deferToolCleanup("falcon_delete_ioa_rule_groups", map[string]any{
			"ids": []string{id},
		})

		Expect(obj).To(HaveKeyWithValue("name", name))

		// Round-trip: the created group must be findable by name. The rule-group
		// index is eventually consistent, so poll rather than searching once.
		Eventually(func() []string {
			found := callTool(ctx, cs, "falcon_search_ioa_rule_groups", map[string]any{
				"filter": "name:'" + name + "'",
				"limit":  5,
			})
			expectNoToolError(found)
			return idsOf(found, "id")
		}).Should(ContainElement(id), "created rule group not found in search")
	})
})
