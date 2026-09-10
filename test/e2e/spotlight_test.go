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

// The spotlight specs exercise falcon_search_vulnerabilities against the live
// tenant. They are read-only, use a small limit, and tolerate an empty tenant.
// Label("spotlight") allows selecting just this module with
// --label-filter="spotlight"; Label("integration") marks the live tier.
var _ = Describe("spotlight module", Label("integration", "spotlight"), func() {
	var ctx context.Context

	BeforeEach(func() {
		ctx = newSpecContext()
	})

	itAdvertisesTools("falcon_search_vulnerabilities")

	It("searches vulnerabilities and returns full records", func() {
		res := callOK(ctx, "falcon_search_vulnerabilities", map[string]any{
			"facet": []any{"cve"},
			"limit": 3,
		})
		skipIfEmpty(res, "tenant has no vulnerabilities to validate details against")
		// cve is populated only when the cve facet is requested; its presence
		// confirms the facet was applied and full records returned.
		expectSearchReturnsDetails(res, "id", "cve")
	})

	It("searches vulnerabilities with an FQL filter", func() {
		res := callOK(ctx, "falcon_search_vulnerabilities", map[string]any{
			"filter": "status:'open'",
			"facet":  []any{"cve"},
			"limit":  3,
		})
		skipIfEmpty(res, "no open vulnerabilities in tenant")
		expectSearchReturnsDetails(res, "id", "cve")
	})

	It("searches vulnerabilities sorted by created_timestamp", func() {
		res := callOK(ctx, "falcon_search_vulnerabilities", map[string]any{
			"sort":  "created_timestamp|desc",
			"limit": 3,
		})
		skipIfEmpty(res, "tenant has no vulnerabilities to sort")
		expectSearchReturnsDetails(res, "id")
	})

	DescribeTable("returns the requested facet detail blocks",
		func(facets []any) {
			res := callOK(ctx, "falcon_search_vulnerabilities", map[string]any{
				"facet": facets,
				"limit": 3,
			})
			skipIfEmpty(res, "tenant has no vulnerabilities for facet validation")
			expectSearchReturnsDetails(res, "id")
		},
		Entry("single facet", []any{"cve"}),
		Entry("multiple facets", []any{"cve", "host_info", "remediation"}),
	)
})
