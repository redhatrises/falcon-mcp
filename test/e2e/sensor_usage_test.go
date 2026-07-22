package e2e

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// The sensor_usage specs exercise falcon_search_sensor_usage against the live
// tenant. Unlike the entity-search modules, this tool returns weekly usage
// rollups (date plus per-category counts), not entities with an id, so the
// specs assert on the usage fields rather than using expectSearchReturnsDetails.
// They are read-only and tolerate an empty response. Label("sensor_usage")
// allows selecting just this module; Label("integration") marks the live tier.
var _ = Describe("sensor_usage module", Label("integration", "sensor_usage"), func() {
	var ctx context.Context

	BeforeEach(func() {
		ctx = newSpecContext()
	})

	It("advertises its tool with the falcon_ prefix", func() {
		cs := newSession(ctx)
		Expect(toolNames(ctx, cs)).To(ContainElement("falcon_search_sensor_usage"))
	})

	It("searches sensor usage and returns weekly rollups", func() {
		cs := newSession(ctx)
		res := callTool(ctx, cs, "falcon_search_sensor_usage", map[string]any{})
		expectNoToolError(res)
		skipIfEmpty(res, "tenant returned no sensor usage data")
		// Each rollup carries a date and per-category counts; date confirms the
		// records are full usage objects rather than bare values.
		for i, r := range resources(res) {
			obj, ok := r.(map[string]any)
			Expect(ok).To(BeTrue(), "usage[%d] should be an object, got %T", i, r)
			Expect(obj).To(HaveKey("date"))
		}
	})

	It("searches sensor usage with an FQL filter", func() {
		cs := newSession(ctx)
		res := callTool(ctx, cs, "falcon_search_sensor_usage", map[string]any{
			"filter": "period:'30'",
		})
		expectNoToolError(res)
		skipIfEmpty(res, "tenant returned no sensor usage data for the period")
		for i, r := range resources(res) {
			obj, ok := r.(map[string]any)
			Expect(ok).To(BeTrue(), "usage[%d] should be an object, got %T", i, r)
			Expect(obj).To(HaveKey("date"))
		}
	})
})
