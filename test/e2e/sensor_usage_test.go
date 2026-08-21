package e2e

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
)

// The sensor_usage specs exercise falcon_search_sensor_usage against the live
// tenant. Unlike the entity-search modules, this tool returns weekly usage
// rollups (date plus per-category counts), not entities with an id, so the
// specs assert on the date field rather than an id. They are read-only and
// tolerate an empty response. Label("sensorusage") allows selecting just this
// module; Label("integration") marks the live tier.
var _ = Describe("sensorusage module", Label("integration", "sensorusage"), func() {
	var ctx context.Context

	BeforeEach(func() {
		ctx = newSpecContext()
	})

	itAdvertisesTools("falcon_search_sensor_usage")

	It("searches sensor usage and returns weekly rollups", func() {
		res := callOK(ctx, "falcon_search_sensor_usage", map[string]any{})
		skipIfEmpty(res, "tenant returned no sensor usage data")
		// Each rollup carries a date and per-category counts; date confirms the
		// records are full usage objects rather than bare values.
		expectSearchReturnsDetails(res, "date")
	})

	It("searches sensor usage with an FQL filter", func() {
		res := callOK(ctx, "falcon_search_sensor_usage", map[string]any{
			"filter": "period:'30'",
		})
		skipIfEmpty(res, "tenant returned no sensor usage data for the period")
		expectSearchReturnsDetails(res, "date")
	})
})
