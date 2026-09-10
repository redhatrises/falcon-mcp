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

// The hosts specs exercise falcon_search_hosts and falcon_get_host_details
// against the live tenant. They are read-only, use a small limit, and tolerate
// an empty tenant. Label("hosts") allows selecting just this module.
var _ = Describe("hosts module", Label("integration", "hosts"), func() {
	var ctx context.Context

	BeforeEach(func() {
		ctx = newSpecContext()
	})

	It("searches hosts and returns full device records", func() {
		res := callOK(ctx, "falcon_search_hosts", map[string]any{"limit": 3})
		skipIfEmpty(res, "tenant has no hosts to validate details against")
		// device_id is the field the module keys detail results on, confirming
		// the two-step query->details fetch returned full records, not bare IDs.
		expectSearchReturnsDetails(res, "device_id")
	})

	It("searches hosts with an FQL filter", func() {
		res := callOK(ctx, "falcon_search_hosts", map[string]any{
			"filter": "platform_name:'Windows'",
			"limit":  3,
		})
		skipIfEmpty(res, "no Windows hosts in tenant")
		expectSearchReturnsDetails(res, "device_id", "hostname", "platform_name")
	})

	It("searches hosts sorted by last_seen", func() {
		res := callOK(ctx, "falcon_search_hosts", map[string]any{
			"sort":  "last_seen.desc",
			"limit": 3,
		})
		skipIfEmpty(res, "tenant has no hosts to sort")
		expectSearchReturnsDetails(res, "device_id", "hostname")
	})

	It("gets host details for an id found by search", func() {
		cs := newSession(ctx)
		search := callTool(ctx, cs, "falcon_search_hosts", map[string]any{"limit": 1})
		expectNoToolError(search)
		id := firstResourceID(search, "device_id") // skips when the tenant is empty

		details := callTool(ctx, cs, "falcon_get_host_details", map[string]any{"ids": []string{id}})
		expectNoToolError(details)
		got := resources(details)
		Expect(got).To(HaveLen(1), "expected exactly one device for one id")
		obj, ok := got[0].(map[string]any)
		Expect(ok).To(BeTrue(), "device detail should be an object, got %T", got[0])
		Expect(obj).To(HaveKeyWithValue("device_id", id))
	})
})
