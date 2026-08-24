package e2e

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// The cases specs exercise the case-management tools against the live tenant.
// They are read-only (create/update/evidence/tag tools mutate and are not driven
// here to avoid side effects) and tolerate an empty tenant. The search and list
// tools follow the two-step query->get chain and return entities with a flat
// "id" field, so the presence of "id" confirms the detail fetch ran rather than
// returning bare identifiers. Label("cases") selects just this module with
// --label-filter="cases"; Label("integration") marks the live tier.
var _ = Describe("cases module", Label("integration", "cases"), func() {
	var ctx context.Context

	BeforeEach(func() {
		ctx = newSpecContext()
	})

	itAdvertisesTools(
		"falcon_search_cases",
		"falcon_get_cases",
		"falcon_create_case",
		"falcon_update_case",
		"falcon_add_case_alert_evidence",
		"falcon_add_case_event_evidence",
		"falcon_manage_case_tags",
		"falcon_list_case_templates",
	)

	It("searches cases and returns full entity details", func() {
		res := callOK(ctx, "falcon_search_cases", map[string]any{
			"limit": 5,
		})
		skipIfEmpty(res, "tenant has no cases to validate against")
		// id and status are entity fields, so their presence confirms the
		// two-step query->get-by-id chain returned full records rather than IDs.
		expectSearchReturnsDetails(res, "id", "status")
	})

	It("searches cases filtered by severity and returns details", func() {
		res := callOK(ctx, "falcon_search_cases", map[string]any{
			"filter": "severity:>0",
			"limit":  3,
		})
		skipIfEmpty(res, "tenant has no cases matching severity:>0")
		expectSearchReturnsDetails(res, "id", "severity")
	})

	It("gets a case by ID discovered from search", func() {
		cs := newSession(ctx)
		found := callTool(ctx, cs, "falcon_search_cases", map[string]any{"limit": 1})
		expectNoToolError(found)
		skipIfEmpty(found, "tenant has no cases to get by ID")

		id := firstResourceID(found, "id")
		Expect(id).NotTo(BeEmpty())
		res := callTool(ctx, cs, "falcon_get_cases", map[string]any{
			"ids": []string{id},
		})
		expectNoToolError(res)
		expectSearchReturnsDetails(res, "id")
	})

	It("lists case templates and returns full template details", func() {
		res := callOK(ctx, "falcon_list_case_templates", map[string]any{
			"limit": 5,
		})
		skipIfEmpty(res, "tenant has no case templates to validate against")
		// id and name are template entity fields, confirming the detail fetch ran.
		expectSearchReturnsDetails(res, "id", "name")
	})
})
