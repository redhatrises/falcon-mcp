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
	"os"
	"strconv"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// The agentworks specs exercise the Charlotte AI tools against the live tenant.
// The three searches and get-by-id are read-only, use a small limit, and
// tolerate an empty tenant. falcon_invoke_agentworks_agent spends real Charlotte
// AI credits, so it is opt-in (RUN_AGENTWORKS_INVOKE) and bounded by a tiny
// credit_cents_limit; it stays skipped by default.
var _ = Describe("agentworks module", Label("integration", "agentworks"), func() {
	var ctx context.Context

	BeforeEach(func() {
		ctx = newSpecContext()
	})

	It("searches agents and returns full agent records", func() {
		res := callOK(ctx, "falcon_search_agentworks_agents", map[string]any{"limit": 3})
		skipIfEmpty(res, "tenant has no AgentWorks agents to validate details against")
		// id is the field the module keys detail results on, confirming the
		// two-step query->details fetch returned full records, not bare IDs.
		expectSearchReturnsDetails(res, "id")
	})

	It("searches agent versions and returns full version records", func() {
		res := callOK(ctx, "falcon_search_agentworks_agent_versions", map[string]any{"limit": 3})
		skipIfEmpty(res, "tenant has no AgentWorks agent versions")
		expectSearchReturnsDetails(res, "id", "agent_id")
	})

	It("searches agent versions scoped to an agent found by search", func() {
		cs := newSession(ctx)
		agents := callTool(ctx, cs, "falcon_search_agentworks_agents", map[string]any{"limit": 1})
		expectNoToolError(agents)
		agentID := firstResourceID(agents, "id") // skips when the tenant is empty

		versions := callTool(ctx, cs, "falcon_search_agentworks_agent_versions", map[string]any{
			"filter": "agent_id:'" + agentID + "'",
			"limit":  3,
		})
		expectNoToolError(versions)
		skipIfEmpty(versions, "agent has no versions")
		expectSearchReturnsDetails(versions, "id", "agent_id")
	})

	It("searches spans (empty without a live trace is tolerated)", func() {
		// Spans are scoped by trace_id in practice; with no known trace this may
		// legitimately return nothing. The check is that the tool runs cleanly.
		res := callOK(ctx, "falcon_search_agentworks_spans", map[string]any{"limit": 3})
		skipIfEmpty(res, "no AgentWorks spans in tenant without a known trace_id")
		expectSearchReturnsDetails(res, "id")
	})

	It("invokes an agent and blocks for the result", func() {
		if !invokeEnabled() {
			Skip("set RUN_AGENTWORKS_INVOKE=1 to run the credit-spending invoke spec")
		}
		cs := newSession(ctx)
		agents := callTool(ctx, cs, "falcon_search_agentworks_agents", map[string]any{"limit": 1})
		expectNoToolError(agents)
		agentID := firstResourceID(agents, "id")

		res := callTool(ctx, cs, "falcon_invoke_agentworks_agent", map[string]any{
			"prompt":             "Reply with the single word: ok.",
			"agent_id":           agentID,
			"credit_cents_limit": 1,
		})
		expectNoToolError(res)
		obj := structured(res)
		// The block-poll always emits an id and a status, whether the run
		// finished, is waiting, or timed out server-side.
		Expect(obj).To(HaveKey("id"))
		Expect(obj).To(HaveKey("status"))
	})
})

// invokeEnabled reports whether the credit-spending invoke spec should run. It
// is off by default and enabled by setting RUN_AGENTWORKS_INVOKE to a truthy
// value (1, true, yes, on).
func invokeEnabled() bool {
	enabled, err := strconv.ParseBool(os.Getenv("RUN_AGENTWORKS_INVOKE"))
	return err == nil && enabled
}
