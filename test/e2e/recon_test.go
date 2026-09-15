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

// The recon specs exercise the Falcon Intelligence Recon search and aggregate
// tools (falcon_search_recon_notifications, falcon_search_recon_rules,
// falcon_search_recon_exposed_data_records, falcon_aggregate_recon_notifications,
// falcon_aggregate_recon_exposed_data_records) against the live tenant. They are
// read-only, use a small limit, and tolerate an empty tenant.
// Label("recon") allows selecting just this module with --label-filter="recon";
// Label("integration") marks the live tier.
var _ = Describe("recon module", Label("integration", "recon"), func() {
	var ctx context.Context

	BeforeEach(func() {
		ctx = newSpecContext()
	})

	itAdvertisesTools(
		"falcon_search_recon_notifications",
		"falcon_search_recon_rules",
		"falcon_search_recon_exposed_data_records",
		"falcon_aggregate_recon_notifications",
		"falcon_aggregate_recon_exposed_data_records",
	)

	It("searches recon notifications and returns full records", func() {
		res := callOK(ctx, "falcon_search_recon_notifications", map[string]any{"limit": 3})
		skipIfEmpty(res, "tenant has no recon notifications to validate details against")
		expectSearchReturnsDetails(res, "id")
	})

	It("searches recon notifications with an FQL filter", func() {
		res := callOK(ctx, "falcon_search_recon_notifications", map[string]any{
			"filter": "status:'new'",
			"limit":  3,
		})
		skipIfEmpty(res, "no new recon notifications in tenant")
		expectSearchReturnsDetails(res, "id")
	})

	It("searches recon rules and returns full records", func() {
		res := callOK(ctx, "falcon_search_recon_rules", map[string]any{"limit": 3})
		skipIfEmpty(res, "tenant has no recon monitoring rules")
		expectSearchReturnsDetails(res, "id", "name")
	})

	It("searches recon rules sorted by created_timestamp", func() {
		res := callOK(ctx, "falcon_search_recon_rules", map[string]any{
			"sort":  "created_timestamp|desc",
			"limit": 3,
		})
		skipIfEmpty(res, "tenant has no recon rules to sort")
		expectSearchReturnsDetails(res, "id")
	})

	It("searches recon exposed data records and returns full records", func() {
		res := callOK(ctx, "falcon_search_recon_exposed_data_records", map[string]any{"limit": 3})
		skipIfEmpty(res, "tenant has no exposed data records")
		expectSearchReturnsDetails(res, "id")
	})

	It("aggregates recon notifications by status", func() {
		res := callOK(ctx, "falcon_aggregate_recon_notifications", map[string]any{
			"type":   "terms",
			"field":  "status",
			"filter": "created_date:>'now-30d'",
			"size":   5,
		})
		// Aggregation returns bucket results; an empty tenant yields an empty set.
		_ = resources(res)
	})

	It("aggregates recon notifications into explicit date buckets", func() {
		res := callOK(ctx, "falcon_aggregate_recon_notifications", map[string]any{
			"type":        "date_range",
			"field":       "created_date",
			"date_ranges": []map[string]any{{"from": "now-7d", "to": "now"}},
		})
		_ = resources(res)
	})

	It("aggregates recon exposed data records by credential_status", func() {
		res := callOK(ctx, "falcon_aggregate_recon_exposed_data_records", map[string]any{
			"type":   "terms",
			"field":  "credential_status",
			"filter": "created_date:>'now-30d'",
			"size":   5,
		})
		_ = resources(res)
	})

	// A date_histogram with no interval is a caller mistake, not a transport
	// failure: the guard answers with the aggregation hint as a data result, so
	// the tool must not report an error.
	It("hints instead of failing when a date_histogram omits its interval", func() {
		res := callOK(ctx, "falcon_aggregate_recon_notifications", map[string]any{
			"type":  "date_histogram",
			"field": "created_date",
		})
		expectNoToolError(res)
	})
})
