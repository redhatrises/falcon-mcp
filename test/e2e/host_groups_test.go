package e2e

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// The host_groups specs exercise the host group tools against the live tenant.
// The read specs (search groups, search members) are always safe. The mutation
// spec creates a disposable static group, confirms it via search, and deletes
// it, cleaning up with DeferCleanup even if an assertion fails; it carries
// Label("mutating") so it can be excluded with --label-filter="!mutating" and
// skips when the write scope is absent. Label("hostgroups") selects just this
// module; Label("integration") marks the live tier.
var _ = Describe("hostgroups module", Label("integration", "hostgroups"), func() {
	var ctx context.Context

	BeforeEach(func() {
		ctx = newSpecContext()
	})

	itAdvertisesTools(
		"falcon_search_host_groups",
		"falcon_search_host_group_members",
		"falcon_create_host_group",
		"falcon_delete_host_groups",
	)

	It("searches host groups and returns full records", func() {
		res := callOK(ctx, "falcon_search_host_groups", map[string]any{"limit": 3})
		skipIfEmpty(res, "tenant has no host groups to validate details against")
		expectSearchReturnsDetails(res, "id", "name")
	})

	It("searches host groups with an FQL filter", func() {
		res := callOK(ctx, "falcon_search_host_groups", map[string]any{
			"filter": "group_type:'static'",
			"limit":  3,
		})
		skipIfEmpty(res, "no static host groups in tenant")
		expectSearchReturnsDetails(res, "id", "name", "group_type")
	})

	It("lists members of a host group found by search", func() {
		cs := newSession(ctx)
		search := callTool(ctx, cs, "falcon_search_host_groups", map[string]any{"limit": 1})
		expectNoToolError(search)
		id := firstResourceID(search, "id") // skips when the tenant has no groups

		members := callTool(ctx, cs, "falcon_search_host_group_members", map[string]any{
			"id":    id,
			"limit": 3,
		})
		expectNoToolError(members)
		// Members are full device records; an empty group is a valid outcome, so
		// only assert the two-step detail shape when members are present.
		skipIfEmpty(members, "host group has no members")
		expectSearchReturnsDetails(members, "device_id")
	})

	It("creates, finds, and deletes a static host group", Label("mutating"), func() {
		cs := newSession(ctx)
		name := uniqueTestName("hostgroup")

		create := callTool(ctx, cs, "falcon_create_host_group", map[string]any{
			"name":        name,
			"group_type":  "static",
			"description": "disposable group created by falcon-mcp e2e",
		})
		skipIfToolError(create, "create host group (Host Group write scope required)")
		obj, id := createdObject(create, "id")

		// Register cleanup immediately so the group is removed even if a later
		// assertion fails.
		deferToolCleanup("falcon_delete_host_groups", map[string]any{
			"ids": []string{id},
		})

		Expect(obj).To(HaveKeyWithValue("name", name))

		// Round-trip: the created group must be findable by name. The group index
		// is eventually consistent, so poll rather than searching once.
		Eventually(func() []string {
			found := callTool(ctx, cs, "falcon_search_host_groups", map[string]any{
				"filter": "name:'" + name + "'",
				"limit":  5,
			})
			expectNoToolError(found)
			return idsOf(found, "id")
		}).Should(ContainElement(id), "created group not found in search")
	})
})
