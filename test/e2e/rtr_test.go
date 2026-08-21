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

	itAdvertisesTools(
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
	)

	It("searches RTR sessions and returns full session records", func() {
		res := callOK(ctx, "falcon_search_rtr_sessions", map[string]any{"limit": 3})
		skipIfEmpty(res, "tenant has no RTR sessions to validate details against")
		// id is the field the module keys detail results on, confirming the
		// two-step query->details fetch returned full records, not bare IDs.
		expectSearchReturnsDetails(res, "id")
	})

	It("searches RTR sessions with a time-bound FQL filter", func() {
		res := callOK(ctx, "falcon_search_rtr_sessions", map[string]any{
			"filter": "created_at:>'now-3650d'",
			"limit":  3,
		})
		skipIfEmpty(res, "no RTR sessions in the last decade")
		expectSearchReturnsDetails(res, "id")
	})

	It("returns an FQL error result for an invalid filter, not a protocol error", func() {
		// RTRListAllSessions validates filter keys and returns a typed 400; the
		// module surfaces it as an FQL data result (errors + fql_guide populated),
		// not an in-band tool error.
		res := callOK(ctx, "falcon_search_rtr_sessions", map[string]any{
			"filter": "not_a_real_field:'x'",
			"limit":  3,
		})
		obj := structured(res)
		Expect(obj).To(HaveKey("errors"), "expected FQL errors surfaced in result")
		Expect(obj["fql_guide"]).NotTo(BeEmpty(), "expected fql_guide echoed for correction")
	})

	It("searches RTR audit sessions", func() {
		res := callOK(ctx, "falcon_search_rtr_audit_sessions", map[string]any{
			"filter": "created_at:>'now-3650d'",
			"limit":  3,
		})
		// Audit search is a single call; records carry an id when present.
		skipIfEmpty(res, "tenant has no RTR audit sessions")
		expectSearchReturnsDetails(res, "id")
	})

	It("aggregates RTR sessions by base_command", func() {
		res := callOK(ctx, "falcon_aggregate_rtr_sessions", map[string]any{
			"field":  "base_command",
			"filter": "created_at:>'now-3650d'",
			"size":   5,
		})
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

	// The FQL-field matrix asserts each documented filter field is accepted by
	// the API rather than rejected as an unknown key. A rejected field surfaces
	// as an FQL data result (errors + fql_guide populated); an accepted field
	// with no matching data simply returns an empty resources array. So
	// "accepted" is the absence of the errors key. Values are chosen not to
	// match real data (a nonexistent string, a far-future timestamp) so the
	// check is about field acceptance, not data presence.
	DescribeTable("accepts documented FQL filter fields",
		func(filter string) {
			res := callOK(ctx, "falcon_search_rtr_sessions", map[string]any{
				"filter": filter,
				"limit":  1,
			})
			Expect(structured(res)).NotTo(HaveKey("errors"), "FQL field rejected: %s", filter)
		},
		Entry("string field id", "id:'NONEXISTENT_VALUE_XYZZY12345'"),
		Entry("string field aid", "aid:'NONEXISTENT_VALUE_XYZZY12345'"),
		Entry("string field hostname", "hostname:'NONEXISTENT_VALUE_XYZZY12345'"),
		Entry("string field user_id", "user_id:'NONEXISTENT_VALUE_XYZZY12345'"),
		Entry("string field origin", "origin:'NONEXISTENT_VALUE_XYZZY12345'"),
		Entry("string field cloud_request_id", "cloud_request_id:'NONEXISTENT_VALUE_XYZZY12345'"),
		Entry("string field command_string", "command_string:'NONEXISTENT_VALUE_XYZZY12345'"),
		Entry("string field base_command", "base_command:'NONEXISTENT_VALUE_XYZZY12345'"),
		Entry("boolean field offline_queued", "offline_queued:true"),
		Entry("boolean field commands_queued", "commands_queued:true"),
		Entry("timestamp field created_at", "created_at:>'2099-01-01T00:00:00Z'"),
		Entry("timestamp field updated_at", "updated_at:>'2099-01-01T00:00:00Z'"),
		Entry("timestamp field deleted_at", "deleted_at:>'2099-01-01T00:00:00Z'"),
		Entry("user_id @me special token", "user_id:'@me'"),
		Entry("compound AND filter with wildcard", "offline_queued:true+hostname:'NONEXISTENT_XYZZY12345*'"),
	)
})
