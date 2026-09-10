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

// The data_protection specs exercise the Data Protection search tools
// (classifications, policies, content patterns) against the live tenant. This
// is a distinct module from shield (SaaS Security). The specs are read-only,
// use a small limit, and tolerate an empty tenant. Label("dataprotection")
// allows selecting just this module; Label("integration") marks the live tier.
var _ = Describe("dataprotection module", Label("integration", "dataprotection"), func() {
	var ctx context.Context

	BeforeEach(func() {
		ctx = newSpecContext()
	})

	itAdvertisesTools(
		"falcon_search_data_protection_classifications",
		"falcon_search_data_protection_policies",
		"falcon_search_data_protection_content_patterns",
	)

	It("searches classifications and returns full records", func() {
		res := callOK(ctx, "falcon_search_data_protection_classifications", map[string]any{"limit": 3})
		skipIfEmpty(res, "tenant has no data protection classifications")
		expectSearchReturnsDetails(res, "id", "name")
	})

	It("searches classifications sorted by name", func() {
		res := callOK(ctx, "falcon_search_data_protection_classifications", map[string]any{
			"sort":  "name.asc",
			"limit": 3,
		})
		skipIfEmpty(res, "tenant has no classifications to sort")
		expectSearchReturnsDetails(res, "id", "name")
	})

	DescribeTable("searches policies for each platform and returns full records",
		func(platform string) {
			res := callOK(ctx, "falcon_search_data_protection_policies", map[string]any{
				"platform_name": platform,
				"limit":         3,
			})
			skipIfEmpty(res, "tenant has no "+platform+" data protection policies")
			expectSearchReturnsDetails(res, "id", "name")
		},
		Entry("windows", "win"),
		Entry("mac", "mac"),
	)

	It("searches content patterns and returns full records", func() {
		res := callOK(ctx, "falcon_search_data_protection_content_patterns", map[string]any{"limit": 3})
		skipIfEmpty(res, "tenant has no data protection content patterns")
		expectSearchReturnsDetails(res, "id", "name", "type")
	})

	It("searches content patterns filtered by type", func() {
		res := callOK(ctx, "falcon_search_data_protection_content_patterns", map[string]any{
			"filter": "type:'predefined'",
			"limit":  3,
		})
		skipIfEmpty(res, "no predefined content patterns in tenant")
		expectSearchReturnsDetails(res, "id", "type")
	})
})
