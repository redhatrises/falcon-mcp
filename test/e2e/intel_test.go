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
	. "github.com/onsi/gomega"
)

// The intel specs exercise the threat-intelligence search tools
// (falcon_search_actors, falcon_search_indicators, falcon_search_reports) and
// falcon_get_mitre_report against the live tenant. They are read-only, use a
// small limit, and tolerate an empty tenant. Label("intel") allows selecting
// just this module with --label-filter="intel"; Label("integration") marks the
// live tier.
var _ = Describe("intel module", Label("integration", "intel"), func() {
	var ctx context.Context

	BeforeEach(func() {
		ctx = newSpecContext()
	})

	itAdvertisesTools(
		"falcon_search_actors",
		"falcon_search_indicators",
		"falcon_search_reports",
		"falcon_get_mitre_report",
	)

	It("searches actors and returns full records", func() {
		res := callOK(ctx, "falcon_search_actors", map[string]any{"limit": 3})
		skipIfEmpty(res, "tenant has no intel actors to validate details against")
		expectSearchReturnsDetails(res, "id")
	})

	It("searches actors with a free-text query", func() {
		res := callOK(ctx, "falcon_search_actors", map[string]any{
			"q":     "panda",
			"limit": 3,
		})
		skipIfEmpty(res, "no actors matched the free-text query")
		expectSearchReturnsDetails(res, "id")
	})

	It("searches indicators and returns full records", func() {
		res := callOK(ctx, "falcon_search_indicators", map[string]any{
			"filter": "type:'domain'",
			"limit":  3,
		})
		skipIfEmpty(res, "tenant has no domain indicators")
		// indicator is the value field; its presence confirms full records
		// rather than bare IDs.
		expectSearchReturnsDetails(res, "id", "indicator", "type")
	})

	It("searches reports and returns full records", func() {
		res := callOK(ctx, "falcon_search_reports", map[string]any{"limit": 3})
		skipIfEmpty(res, "tenant has no intel reports")
		expectSearchReturnsDetails(res, "id", "name")
	})

	// get_mitre_report resolves an actor and returns a MitreResult envelope
	// rather than a search "resources" array: a json request populates report,
	// a csv request populates raw. WARP PANDA is a long-standing tracked actor
	// used as a stable lookup; a tenant without Intelligence entitlement returns
	// an error field, which is a valid live outcome and skips.
	DescribeTable("gets a MITRE report for a known actor",
		func(format, populatedField string) {
			res := callOK(ctx, "falcon_get_mitre_report", map[string]any{
				"actor":  "WARP PANDA",
				"format": format,
			})
			obj := structured(res)
			if _, hasErr := obj["error"]; hasErr {
				Skip("intel/MITRE not available for this tenant or actor")
			}
			Expect(obj).To(HaveKeyWithValue("format", format))
			Expect(obj).To(HaveKey(populatedField))
			Expect(obj[populatedField]).NotTo(BeEmpty(), "expected %q to be populated for %q format", populatedField, format)
		},
		Entry("json format", "json", "report"),
		Entry("csv format", "csv", "raw"),
	)
})
