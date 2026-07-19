package e2e

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// The RTR specs exercise the read-only RTR tools against the live tenant:
// searching sessions (two-step), audit sessions, aggregation, and get-by-id.
// They deliberately avoid init/pulse/execute/delete, which mutate RTR session
// state on real hosts. They tolerate an empty tenant. Label("rtr") allows
// selecting just this module.
var _ = Describe("rtr module", Label("integration", "rtr"), func() {
	var ctx context.Context

	BeforeEach(func() {
		ctx = newSpecContext()
	})

	It("advertises the RTR tools with the falcon_ prefix", func() {
		cs := newSession(ctx)
		names := toolNames(ctx, cs)
		for _, want := range []string{
			"falcon_search_rtr_sessions",
			"falcon_search_rtr_audit_sessions",
			"falcon_aggregate_rtr_sessions",
			"falcon_get_rtr_session_details",
			"falcon_check_rtr_command_status",
			"falcon_list_rtr_session_files",
			"falcon_init_rtr_session",
			"falcon_pulse_rtr_session",
			"falcon_execute_rtr_read_only_command",
			"falcon_run_rtr_read_only_command_and_wait",
			"falcon_delete_rtr_session",
		} {
			Expect(names).To(ContainElement(want), "missing RTR tool %s", want)
		}
	})

	It("searches RTR sessions and returns full session records", func() {
		cs := newSession(ctx)
		res := callTool(ctx, cs, "falcon_search_rtr_sessions", map[string]any{"limit": 3})
		expectNoToolError(res)
		skipIfEmpty(res, "tenant has no RTR sessions to validate details against")
		// id is the field the module keys detail results on, confirming the
		// two-step query->details fetch returned full records, not bare IDs.
		expectSearchReturnsDetails(res, "id")
	})

	It("searches RTR sessions with a time-bound FQL filter", func() {
		cs := newSession(ctx)
		res := callTool(ctx, cs, "falcon_search_rtr_sessions", map[string]any{
			"filter": "created_at:>'now-3650d'",
			"limit":  3,
		})
		expectNoToolError(res)
		skipIfEmpty(res, "no RTR sessions in the last decade")
		expectSearchReturnsDetails(res, "id")
	})

	It("returns an FQL error result for an invalid filter, not a protocol error", func() {
		cs := newSession(ctx)
		res := callTool(ctx, cs, "falcon_search_rtr_sessions", map[string]any{
			"filter": "not_a_real_field:'x'",
			"limit":  3,
		})
		// RTRListAllSessions validates filter keys and returns a typed 400; the
		// module surfaces it as an FQL data result (errors + fql_guide populated),
		// not an in-band tool error.
		expectNoToolError(res)
		obj := structured(res)
		Expect(obj).To(HaveKey("errors"), "expected FQL errors surfaced in result")
		Expect(obj["fql_guide"]).NotTo(BeEmpty(), "expected fql_guide echoed for correction")
	})

	It("searches RTR audit sessions", func() {
		cs := newSession(ctx)
		res := callTool(ctx, cs, "falcon_search_rtr_audit_sessions", map[string]any{
			"filter": "created_at:>'now-3650d'",
			"limit":  3,
		})
		expectNoToolError(res)
		// Audit search is a single call; records carry an id when present.
		skipIfEmpty(res, "tenant has no RTR audit sessions")
		expectSearchReturnsDetails(res, "id")
	})

	It("aggregates RTR sessions by base_command", func() {
		cs := newSession(ctx)
		res := callTool(ctx, cs, "falcon_aggregate_rtr_sessions", map[string]any{
			"field":  "base_command",
			"filter": "created_at:>'now-3650d'",
			"size":   5,
		})
		expectNoToolError(res)
		// Aggregation returns bucket results; an empty tenant yields an empty set.
		_ = resources(res)
	})

	It("gets RTR session details for an id found by search", func() {
		cs := newSession(ctx)
		search := callTool(ctx, cs, "falcon_search_rtr_sessions", map[string]any{"limit": 1})
		expectNoToolError(search)
		id := firstResourceID(search, "id") // skips when the tenant is empty

		details := callTool(ctx, cs, "falcon_get_rtr_session_details", map[string]any{"ids": []string{id}})
		expectNoToolError(details)
		got := resources(details)
		Expect(got).To(HaveLen(1), "expected exactly one session for one id")
		obj, ok := got[0].(map[string]any)
		Expect(ok).To(BeTrue(), "session detail should be an object, got %T", got[0])
		Expect(obj).To(HaveKeyWithValue("id", id))
	})
})
