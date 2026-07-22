package e2e

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// The correlation_rules specs exercise falcon_search_correlation_rules against
// the live tenant. They are read-only (create/update/delete are mutating and are
// not driven here), use a small limit, and tolerate an empty tenant.
// Label("correlation_rules") allows selecting just this module.
var _ = Describe("correlation_rules module", Label("integration", "correlation_rules"), func() {
	var ctx context.Context

	BeforeEach(func() {
		ctx = newSpecContext()
	})

	It("advertises the correlation-rules tools with the falcon_ prefix", func() {
		cs := newSession(ctx)
		names := toolNames(ctx, cs)
		Expect(names).To(ContainElements(
			"falcon_search_correlation_rules",
			"falcon_create_correlation_rule",
			"falcon_update_correlation_rule",
			"falcon_delete_correlation_rules",
		))
	})

	It("searches correlation rules and returns full rule records", func() {
		cs := newSession(ctx)
		res := callTool(ctx, cs, "falcon_search_correlation_rules", map[string]any{"limit": 3})
		expectNoToolError(res)
		skipIfEmpty(res, "tenant has no correlation rules to validate details against")
		// CombinedRulesGetV2 returns full rule objects in one call; rule_id is the
		// field the tool documents for chaining into update/delete, so its presence
		// confirms full records (not bare IDs) came back.
		expectSearchReturnsDetails(res, "rule_id", "name")
	})

	It("searches published correlation rules with an FQL filter", func() {
		cs := newSession(ctx)
		res := callTool(ctx, cs, "falcon_search_correlation_rules", map[string]any{
			"filter": "state:'published'",
			"limit":  3,
		})
		expectNoToolError(res)
		skipIfEmpty(res, "no published correlation rules in tenant")
		expectSearchReturnsDetails(res, "rule_id", "name", "status")
	})

	It("searches correlation rules sorted by last_updated_on", func() {
		cs := newSession(ctx)
		res := callTool(ctx, cs, "falcon_search_correlation_rules", map[string]any{
			"sort":  "last_updated_on.desc",
			"limit": 3,
		})
		expectNoToolError(res)
		skipIfEmpty(res, "tenant has no correlation rules to sort")
		expectSearchReturnsDetails(res, "rule_id")
	})

	It("creates, finds, and deletes a correlation rule", Label("mutating"), func() {
		cs := newSession(ctx)
		// The create endpoint requires the tenant CID; derive it from an existing
		// rule (skips when the tenant has none), matching how a real caller scopes
		// the create to their own CID.
		search := callTool(ctx, cs, "falcon_search_correlation_rules", map[string]any{"limit": 1})
		expectNoToolError(search)
		customerID := firstResourceID(search, "customer_id") // skips when empty
		name := uniqueTestName("corrrule")

		create := callTool(ctx, cs, "falcon_create_correlation_rule", map[string]any{
			"customer_id":   customerID,
			"name":          name,
			"search_filter": "#event_simpleName=ProcessRollup2 | CommandLine=*falcon-mcp-e2e*",
			"severity":      10,
			"description":   "disposable rule created by falcon-mcp e2e",
			"status":        "inactive",
		})
		skipIfToolError(create, "create correlation rule (Correlation Rules write scope required)")
		obj, ruleID := createdObject(create, "rule_id")

		deferToolCleanup("falcon_delete_correlation_rules", map[string]any{
			"ids":     []string{ruleID},
			"comment": "falcon-mcp e2e cleanup",
		})

		Expect(obj).To(HaveKeyWithValue("name", name))

		// Round-trip: the created rule must be findable by name. The rule index is
		// eventually consistent, so poll rather than searching once.
		Eventually(func() []string {
			found := callTool(ctx, cs, "falcon_search_correlation_rules", map[string]any{
				"filter": "name:'" + name + "'",
				"limit":  5,
			})
			expectNoToolError(found)
			return idsOf(found, "rule_id")
		}).Should(ContainElement(ruleID), "created rule not found in search")
	})
})
