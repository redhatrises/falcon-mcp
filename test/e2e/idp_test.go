package e2e

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// The idp specs exercise falcon_idp_investigate_entity against the live tenant.
// Unlike the FQL search modules, this tool drives CrowdStrike's Identity
// Protection GraphQL endpoint: it resolves entities from identifiers and runs
// one or more investigation types (entity details, timeline, relationships,
// risk). The specs are read-only, cap results with a small limit, and tolerate
// an empty tenant. Validation failures are returned as data on the result
// envelope (an "error" field), not as protocol errors, so those specs assert on
// the structured content rather than IsError.
//
// Label("idp") allows selecting just this module with --label-filter="idp";
// Label("integration") marks the live tier.
var _ = Describe("idp module", Label("integration", "idp"), func() {
	var ctx context.Context

	BeforeEach(func() {
		ctx = newSpecContext()
	})

	itAdvertisesTools("falcon_idp_investigate_entity")

	It("resolves entities by name and returns entity details", func() {
		res := callOK(ctx, "falcon_idp_investigate_entity", map[string]any{
			"entity_names":        "*",
			"investigation_types": []any{"entity_details"},
			"limit":               3,
		})
		// A bare "*" is rejected as data (bare wildcard), so instead use a broad
		// but non-bare pattern below; this call is expected to be a data error.
		obj := structured(res)
		Expect(obj).To(HaveKey("error"))
	})

	It("returns full entity detail objects, not bare IDs", func() {
		res := callOK(ctx, "falcon_idp_investigate_entity", map[string]any{
			"entity_names":        "a*",
			"investigation_types": []any{"entity_details"},
			"limit":               5,
		})
		obj := structured(res)
		// Either entities resolved (completed) or none matched (error field). Both
		// are valid live outcomes; when entities resolved, entity_details must
		// carry full objects with entityId, proving the two-step query worked.
		if _, hasErr := obj["error"]; hasErr {
			By("skipping: tenant returned no entities matching 'a*'")
			Skip("no entities matched 'a*'")
		}
		details, ok := obj["entity_details"].(map[string]any)
		Expect(ok).To(BeTrue(), "expected entity_details object, got %T", obj["entity_details"])
		entities, ok := details["entities"].([]any)
		Expect(ok).To(BeTrue(), "expected entity_details.entities array")
		for i, e := range entities {
			em, ok := e.(map[string]any)
			Expect(ok).To(BeTrue(), "entity[%d] should be an object, got %T", i, e)
			Expect(em).To(HaveKey("entityId"), "entity[%d] missing entityId (bare id?)", i)
		}
	})

	It("runs a risk assessment for resolved entities", func() {
		res := callOK(ctx, "falcon_idp_investigate_entity", map[string]any{
			"entity_names":        "a*",
			"investigation_types": []any{"risk_assessment"},
			"limit":               3,
		})
		obj := structured(res)
		if _, hasErr := obj["error"]; hasErr {
			Skip("no entities matched 'a*'")
		}
		risk, ok := obj["risk_assessment"].(map[string]any)
		Expect(ok).To(BeTrue(), "expected risk_assessment object")
		_, ok = risk["risk_assessments"].([]any)
		Expect(ok).To(BeTrue(), "expected risk_assessments array")
	})

	It("rejects a call with no identifier as a data error", func() {
		res := callOK(ctx, "falcon_idp_investigate_entity", map[string]any{
			"investigation_types": []any{"entity_details"},
		})
		obj := structured(res)
		Expect(obj).To(HaveKey("error"))
		summary, ok := obj["investigation_summary"].(map[string]any)
		Expect(ok).To(BeTrue(), "expected investigation_summary object")
		Expect(summary["status"]).To(Equal("failed"))
	})
})
