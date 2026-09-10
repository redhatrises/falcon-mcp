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

// The serverless specs exercise falcon_search_serverless_vulnerabilities against
// the live tenant. They are read-only, use a small limit, and tolerate an empty
// tenant. The endpoint requires a filter, so every call supplies one. Results
// are SARIF "run" objects (each carrying "tool" and "results"), not entities
// with a flat ID field, so there is no search->get-by-id chain to exercise.
// Label("serverless") allows selecting just this module with
// --label-filter="serverless"; Label("integration") marks the live tier.
var _ = Describe("serverless module", Label("integration", "serverless"), func() {
	var ctx context.Context

	BeforeEach(func() {
		ctx = newSpecContext()
	})

	itAdvertisesTools("falcon_search_serverless_vulnerabilities")

	It("searches serverless vulnerabilities and returns SARIF runs", func() {
		res := callOK(ctx, "falcon_search_serverless_vulnerabilities", map[string]any{
			"filter": "cloud_provider:'aws'",
			"limit":  5,
		})
		skipIfEmpty(res, "tenant has no AWS serverless vulnerabilities to validate against")
		// tool and results are the SARIF run fields, so their presence confirms
		// the combined query returned full SARIF runs rather than bare
		// identifiers.
		expectSearchReturnsDetails(res, "tool", "results")
	})

	It("searches serverless vulnerabilities with a severity filter", func() {
		res := callOK(ctx, "falcon_search_serverless_vulnerabilities", map[string]any{
			"filter": "severity:'HIGH'",
			"limit":  3,
		})
		skipIfEmpty(res, "no HIGH severity serverless vulnerabilities in tenant")
		expectSearchReturnsDetails(res, "tool", "results")
	})

	It("searches serverless vulnerabilities sorted by severity", func() {
		res := callOK(ctx, "falcon_search_serverless_vulnerabilities", map[string]any{
			"filter": "cloud_provider:'aws'",
			"sort":   "severity",
			"limit":  3,
		})
		skipIfEmpty(res, "tenant has no AWS serverless vulnerabilities to sort")
		expectSearchReturnsDetails(res, "tool", "results")
	})
})
