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
})
