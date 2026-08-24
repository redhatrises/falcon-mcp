package e2e

import (
	"context"

	. "github.com/onsi/ginkgo/v2"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// The firewall specs exercise the three read-only firewall search tools against
// the live tenant: falcon_search_firewall_rules, falcon_search_firewall_rule_groups,
// and falcon_search_firewall_policy_rules. They validate that the gofalcon
// operation names (QueryRules/GetRules, QueryRuleGroups/GetRuleGroups,
// QueryPolicyRules) resolve and that each two-step query->get search returns full
// entity records rather than bare IDs. The policy-rule search derives its
// required policy_id from a rule-group's policy_ids so it works against any
// tenant. They are read-only, use a small limit, and tolerate an empty tenant.
//
// The mutating tools (falcon_create_firewall_rule_group,
// falcon_delete_firewall_rule_groups) are intentionally not exercised here: they
// alter live tenant state, and the read-only e2e tier mirrors the other module
// specs (hosts, detections, discover, serverless), which never mutate.
//
// Label("firewall") allows selecting just this module with
// --label-filter="firewall"; Label("integration") marks the live tier.
var _ = Describe("firewall module", Label("integration", "firewall"), func() {
	var ctx context.Context

	BeforeEach(func() {
		ctx = newSpecContext()
	})

	itAdvertisesTools(
		"falcon_search_firewall_rules",
		"falcon_search_firewall_rule_groups",
		"falcon_search_firewall_policy_rules",
		"falcon_create_firewall_rule_group",
		"falcon_delete_firewall_rule_groups",
	)

	It("searches firewall rules and returns full rule records", func() {
		res := callOK(ctx, "falcon_search_firewall_rules", map[string]any{"limit": 3})
		skipIfEmpty(res, "tenant has no firewall rules to validate details against")
		// id is the field the module keys detail results on, confirming the
		// two-step query->details fetch returned full records, not bare IDs.
		expectSearchReturnsDetails(res, "id", "name")
	})

	It("searches firewall rule groups and returns full rule group records", func() {
		res := callOK(ctx, "falcon_search_firewall_rule_groups", map[string]any{"limit": 3})
		skipIfEmpty(res, "tenant has no firewall rule groups to validate details against")
		expectSearchReturnsDetails(res, "id", "name")
	})

	It("searches firewall rule groups with an FQL filter", func() {
		res := callOK(ctx, "falcon_search_firewall_rule_groups", map[string]any{
			"filter": "enabled:true",
			"limit":  3,
		})
		skipIfEmpty(res, "tenant has no enabled firewall rule groups")
		expectSearchReturnsDetails(res, "id", "enabled")
	})

	It("searches firewall policy rules for a policy discovered from a rule group", func() {
		// Rule groups carry the policy_ids they belong to; use one to scope the
		// policy-rule search so this works against any tenant without a hardcoded
		// policy id.
		groups := callOK(ctx, "falcon_search_firewall_rule_groups", map[string]any{"limit": 10})
		policyID := firstPolicyID(groups)

		res := callOK(ctx, "falcon_search_firewall_policy_rules", map[string]any{
			"policy_id": policyID,
			"limit":     3,
		})
		skipIfEmpty(res, "policy container has no rules to validate details against")
		expectSearchReturnsDetails(res, "id", "name")
	})
})

// firstPolicyID returns a policy container ID drawn from the policy_ids of the
// first rule group that has one, or skips the spec when none is available. The
// firewall rule-group record exposes the policy containers it belongs to via a
// policy_ids string array.
func firstPolicyID(res *mcp.CallToolResult) string {
	GinkgoHelper()
	for _, r := range resources(res) {
		obj, ok := r.(map[string]any)
		if !ok {
			continue
		}
		ids, ok := obj["policy_ids"].([]any)
		if !ok {
			continue
		}
		for _, id := range ids {
			if s, ok := id.(string); ok && s != "" {
				return s
			}
		}
	}
	Skip("no rule group with a policy_id to scope a policy-rule search")
	return ""
}
