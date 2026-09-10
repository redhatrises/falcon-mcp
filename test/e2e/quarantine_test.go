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

// The quarantine specs exercise falcon_search_quarantined_files and
// falcon_preview_quarantine_actions against the live tenant. They are read-only
// (preview does not mutate state), use a small limit, and tolerate an empty
// tenant. Label("quarantine") allows selecting just this module with
// --label-filter="quarantine"; Label("integration") marks the live tier.
var _ = Describe("quarantine module", Label("integration", "quarantine"), func() {
	var ctx context.Context

	BeforeEach(func() {
		ctx = newSpecContext()
	})

	itAdvertisesTools(
		"falcon_search_quarantined_files",
		"falcon_preview_quarantine_actions",
	)

	It("searches quarantined files and returns full records", func() {
		res := callOK(ctx, "falcon_search_quarantined_files", map[string]any{"limit": 3})
		skipIfEmpty(res, "tenant has no quarantined files to validate details against")
		expectSearchReturnsDetails(res, "id")
	})

	It("searches quarantined files sorted by date_updated", func() {
		res := callOK(ctx, "falcon_search_quarantined_files", map[string]any{
			"sort":  "date_updated|desc",
			"limit": 3,
		})
		skipIfEmpty(res, "tenant has no quarantined files to sort")
		expectSearchReturnsDetails(res, "id")
	})

	It("pages quarantined files by advancing the reported offset", func() {
		cs := newSession(ctx)
		expectOffsetPaginates(ctx, cs, "falcon_search_quarantined_files", map[string]any{"limit": 2})
	})

	It("previews quarantine actions for a filter", func() {
		// preview_quarantine_actions is a read-only aggregation over a filter; an
		// empty tenant yields an empty resources array, which is a valid outcome.
		res := callOK(ctx, "falcon_preview_quarantine_actions", map[string]any{
			"filter": "state:'quarantined'",
		})
		// No details assertion: the aggregation payload shape is not a two-step
		// entity search, so only the protocol/tool success is asserted here.
		_ = resources(res)
	})
})
