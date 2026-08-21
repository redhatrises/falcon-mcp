package e2e

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// The shield specs exercise the Falcon Shield (SaaS Security) tools against the
// live tenant. They are read-only and tolerate an empty tenant, except the
// dismiss spec, which only exercises input validation (it never dismisses a real
// check, to avoid mutating live posture state). Label("shield") selects just
// this module. Shield read ops are single-call (no two-step fetch), so the
// resources are asserted to be full objects directly.
var _ = Describe("shield module", Label("integration", "shield"), func() {
	var ctx context.Context

	BeforeEach(func() {
		ctx = newSpecContext()
	})

	It("lists integrations and returns full records", func() {
		res := callOK(ctx, "falcon_get_shield_integrations", map[string]any{})
		skipIfEmpty(res, "tenant has no Shield integrations")
		expectSearchReturnsDetails(res, "id")
	})

	It("searches posture checks and returns full records", func() {
		res := callOK(ctx, "falcon_search_shield_checks", map[string]any{"limit": 3})
		skipIfEmpty(res, "tenant has no Shield posture checks")
		expectSearchReturnsDetails(res, "id", "status")
	})

	It("searches posture checks filtered by impact (title-case normalized)", func() {
		// "high" must be normalized to "High" for the endpoint to match; a
		// wrong-case value silently returns empty rather than erroring.
		res := callOK(ctx, "falcon_search_shield_checks", map[string]any{
			"impact": "high",
			"limit":  3,
		})
		skipIfEmpty(res, "tenant has no high-impact Shield checks")
		expectSearchReturnsDetails(res, "id", "impact")
	})

	It("gets aggregated posture metrics", func() {
		callOK(ctx, "falcon_get_shield_posture_metrics", map[string]any{"limit": 3})
	})

	It("searches apps and returns full records with object scopes", func() {
		res := callOK(ctx, "falcon_search_shield_apps", map[string]any{"limit": 3})
		skipIfEmpty(res, "tenant has no Shield apps")
		// item_id is required to chain into get_shield_app_users; its presence
		// confirms the app records decoded (the scopes array-of-object fix).
		expectSearchReturnsDetails(res, "item_id")
	})

	It("searches devices and returns full records", func() {
		res := callOK(ctx, "falcon_search_shield_devices", map[string]any{"limit": 3})
		skipIfEmpty(res, "tenant has no Shield devices")
		expectSearchReturnsDetails(res, "id")
	})

	It("searches users and returns full records", func() {
		res := callOK(ctx, "falcon_search_shield_users", map[string]any{"limit": 3})
		skipIfEmpty(res, "tenant has no Shield users")
		expectSearchReturnsDetails(res, "email")
	})

	It("searches data shares and returns full records", func() {
		callOK(ctx, "falcon_search_shield_data_shares", map[string]any{"limit": 3})
	})

	It("searches alerts and returns full records", func() {
		callOK(ctx, "falcon_search_shield_alerts", map[string]any{"limit": 3})
	})

	It("gets activity monitor events", func() {
		callOK(ctx, "falcon_get_shield_activity_monitor", map[string]any{"limit": 3})
	})

	It("lists system users", func() {
		callOK(ctx, "falcon_get_shield_system_users", map[string]any{})
	})

	It("lists supported SaaS platforms", func() {
		res := callOK(ctx, "falcon_get_shield_supported_saas", map[string]any{})
		skipIfEmpty(res, "no supported SaaS platforms returned")
		expectSearchReturnsDetails(res, "id", "name")
	})

	It("gets system logs", func() {
		callOK(ctx, "falcon_get_shield_system_logs", map[string]any{"limit": 3})
	})

	It("gets affected entities for a check found by search", func() {
		cs := newSession(ctx)
		search := callTool(ctx, cs, "falcon_search_shield_checks", map[string]any{"limit": 1})
		expectNoToolError(search)
		id := firstResourceID(search, "id") // skips when the tenant has no checks

		res := callTool(ctx, cs, "falcon_get_shield_check_affected_entities", map[string]any{
			"id":    id,
			"limit": 3,
		})
		expectNoToolError(res)
	})

	It("gets compliance mappings for a check found by search", func() {
		cs := newSession(ctx)
		search := callTool(ctx, cs, "falcon_search_shield_checks", map[string]any{"limit": 1})
		expectNoToolError(search)
		id := firstResourceID(search, "id")

		res := callTool(ctx, cs, "falcon_get_shield_check_compliance", map[string]any{"id": id})
		expectNoToolError(res)
	})

	It("gets app users for an app found by search", func() {
		cs := newSession(ctx)
		search := callTool(ctx, cs, "falcon_search_shield_apps", map[string]any{"limit": 1})
		expectNoToolError(search)
		itemID := firstResourceID(search, "item_id")

		res := callTool(ctx, cs, "falcon_get_shield_app_users", map[string]any{"item_id": itemID})
		expectNoToolError(res)
	})

	// dismiss_shield_check is a permanent, irreversible mutation. To avoid
	// altering live posture state, only its input validation is exercised: an
	// empty reason must be rejected before any API call is made.
	It("rejects a dismiss with a missing reason", func() {
		cs := newSession(ctx)
		res := callTool(ctx, cs, "falcon_dismiss_shield_check", map[string]any{
			"id":     "does-not-matter",
			"reason": "",
		})
		Expect(res.IsError).To(BeTrue(), "empty reason should be rejected as an input error")
	})
})
