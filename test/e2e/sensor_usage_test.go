// MIT License
//
// Copyright (c) 2026 CrowdStrike
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

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
