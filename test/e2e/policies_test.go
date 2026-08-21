package e2e

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// The policies specs exercise falcon_search_policies and falcon_search_policy_members
// across all six policy types (prevention, sensor_update, firewall, device_control,
// response, content_update) against the live tenant. They are read-only, use a small
// limit, and tolerate an empty tenant. The mutating tools (create/update/delete/action/
// precedence) are intentionally not exercised here to avoid changing tenant state.
// Label("policies") selects just this module.
//
// The device_control search doubly validates the two-step query->get detail path:
// its combined query op has no V2 variant, so search queries for IDs then fetches
// full records via GetDeviceControlPolicies — a passing search here confirms the
// tool returns full policy objects, not bare IDs.
var _ = Describe("policies module", Label("integration", "policies"), func() {
	var ctx context.Context

	BeforeEach(func() {
		ctx = newSpecContext()
	})

	itAdvertisesTools(
		"falcon_search_policies",
		"falcon_search_policy_members",
		"falcon_create_policy",
		"falcon_update_policy",
		"falcon_delete_policies",
		"falcon_perform_policy_action",
		"falcon_set_policy_precedence",
	)

	// Every policy type of each tenant has at least a Default policy, so these
	// searches should return full records including the id field.
	DescribeTable("searches each policy type and returns full records",
		func(policyType string) {
			res := callOK(ctx, "falcon_search_policies", map[string]any{
				"policy_type": policyType,
				"limit":       3,
			})
			skipIfEmpty(res, "tenant has no "+policyType+" policies")
			expectSearchReturnsDetails(res, "id", "name")
		},
		Entry("prevention", "prevention"),
		Entry("sensor_update", "sensor_update"),
		Entry("firewall", "firewall"),
		Entry("device_control", "device_control"),
		Entry("response", "response"),
		Entry("content_update", "content_update"),
	)

	It("applies the enabled boolean FQL filter", func() {
		res := callOK(ctx, "falcon_search_policies", map[string]any{
			"policy_type": "prevention",
			"filter":      "enabled:true",
			"limit":       3,
		})
		skipIfEmpty(res, "no enabled prevention policies in tenant")
		expectSearchReturnsDetails(res, "id", "name")
	})

	It("matches a policy name with the contains operator", func() {
		// name:~'value' is the correct operator for prevention; a glob returns
		// nothing. 'default' matches the built-in Default policy on most tenants.
		res := callOK(ctx, "falcon_search_policies", map[string]any{
			"policy_type": "prevention",
			"filter":      "name:~'default'",
			"limit":       3,
		})
		skipIfEmpty(res, "no prevention policy name contains 'default'")
		expectSearchReturnsDetails(res, "id", "name")
	})

	It("surfaces the raw API meta object on a populated search", func() {
		res := callOK(ctx, "falcon_search_policies", map[string]any{
			"policy_type": "prevention",
			"limit":       3,
		})
		skipIfEmpty(res, "tenant has no prevention policies")
		obj := structured(res)
		meta, ok := obj["meta"].(map[string]any)
		Expect(ok).To(BeTrue(), "expected a meta object on a populated search, got %v", obj["meta"])
		Expect(meta).NotTo(BeEmpty(), "meta object should carry at least one field")
	})

	It("sorts by modified_timestamp without the platform_name sort trap", func() {
		// Sorting by platform_name returns HTTP 500; modified_timestamp is a safe
		// sort field. A passing call confirms the tool built a valid sort.
		res := callOK(ctx, "falcon_search_policies", map[string]any{
			"policy_type": "prevention",
			"sort":        "modified_timestamp.desc",
			"limit":       3,
		})
		skipIfEmpty(res, "tenant has no prevention policies to sort")
		expectSearchReturnsDetails(res, "id")
	})

	It("rejects a platform_name sort as a tool error", func() {
		// The module rejects platform_name sorts client-side (the API 500s).
		cs := newSession(ctx)
		res := callTool(ctx, cs, "falcon_search_policies", map[string]any{
			"policy_type": "prevention",
			"sort":        "platform_name.asc",
			"limit":       3,
		})
		Expect(res.IsError).To(BeTrue(), "expected a platform_name sort to be a tool error")
	})

	It("rejects an invalid policy_type with a tool error", func() {
		cs := newSession(ctx)
		res := callTool(ctx, cs, "falcon_search_policies", map[string]any{
			"policy_type": "bogus",
			"limit":       3,
		})
		Expect(res.IsError).To(BeTrue(), "expected an invalid policy_type to be a tool error")
	})

	It("lists the host members of a policy found by search", func() {
		cs := newSession(ctx)
		search := callTool(ctx, cs, "falcon_search_policies", map[string]any{
			"policy_type": "prevention",
			"limit":       1,
		})
		expectNoToolError(search)
		id := firstResourceID(search, "id") // skips when the tenant is empty

		members := callTool(ctx, cs, "falcon_search_policy_members", map[string]any{
			"policy_type": "prevention",
			"id":          id,
			"limit":       3,
		})
		expectNoToolError(members)
		// Members may be empty (a policy can govern no hosts); when present they
		// must be full device records keyed on device_id, not bare IDs.
		skipIfEmpty(members, "prevention policy governs no hosts")
		expectSearchReturnsDetails(members, "device_id")
	})
})
