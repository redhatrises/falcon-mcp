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

// The discover specs exercise falcon_search_applications and
// falcon_search_unmanaged_assets against the live tenant, mirroring the Python
// tests/integration/test_discover.py suite. They validate the gofalcon
// operation names (CombinedApplications, CombinedHosts) resolve, that the
// combined endpoints return full entity details rather than bare IDs, and that
// the unmanaged-asset tool applies entity_type:'unmanaged' automatically. They
// are read-only, use a small limit, and tolerate an empty tenant.
// Label("discover") allows selecting just this module with
// --label-filter="discover"; Label("integration") marks the live tier.
var _ = Describe("discover module", Label("integration", "discover"), func() {
	var ctx context.Context

	BeforeEach(func() {
		ctx = newSpecContext()
	})

	itAdvertisesTools(
		"falcon_search_applications",
		"falcon_search_unmanaged_assets",
	)

	It("searches applications and returns full application records", func() {
		// A filter is required for the combined applications endpoint; name:*'*'
		// matches everything so the spec works against any tenant.
		res := callOK(ctx, "falcon_search_applications", map[string]any{
			"filter": "name:*'*'",
			"limit":  5,
		})
		skipIfEmpty(res, "tenant has no applications to validate details against")
		// id and name confirm the combined query returned full records, not bare IDs.
		expectSearchReturnsDetails(res, "id", "name")
	})

	It("searches applications with an FQL filter", func() {
		res := callOK(ctx, "falcon_search_applications", map[string]any{
			"filter": "vendor:'Microsoft Corporation'",
			"limit":  3,
		})
		skipIfEmpty(res, "no Microsoft applications in tenant")
		expectSearchReturnsDetails(res, "id", "name")
	})

	It("searches applications with a facet", func() {
		res := callOK(ctx, "falcon_search_applications", map[string]any{
			"filter": "name:*'*'",
			"facet":  "host_info",
			"limit":  3,
		})
		skipIfEmpty(res, "tenant has no applications to validate facet against")
		expectSearchReturnsDetails(res, "id", "name")
	})

	It("searches unmanaged assets and returns full asset records", func() {
		res := callOK(ctx, "falcon_search_unmanaged_assets", map[string]any{"limit": 5})
		skipIfEmpty(res, "tenant has no unmanaged assets to validate details against")
		// id confirms the combined hosts query returned full records, not bare IDs.
		expectSearchReturnsDetails(res, "id")
	})

	It("searches unmanaged assets with an additional FQL filter", func() {
		res := callOK(ctx, "falcon_search_unmanaged_assets", map[string]any{
			"filter": "platform_name:'Windows'",
			"limit":  3,
		})
		skipIfEmpty(res, "no Windows unmanaged assets in tenant")
		expectSearchReturnsDetails(res, "id")
	})

	It("searches unmanaged assets sorted by last_seen_timestamp", func() {
		res := callOK(ctx, "falcon_search_unmanaged_assets", map[string]any{
			"sort":  "last_seen_timestamp.desc",
			"limit": 3,
		})
		skipIfEmpty(res, "tenant has no unmanaged assets to sort")
		expectSearchReturnsDetails(res, "id")
	})
})
