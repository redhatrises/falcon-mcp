package e2e

import (
	"context"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// bogusAID is a well-formed but unassigned agent ID. The assessment API reports
// an unknown or never-assessed AID by omitting its record from an otherwise
// successful response, so this drives the not_found path without an error.
const bogusAID = "00000000000000000000000000000000"

// The zero_trust_assessment specs exercise the ZTA posture tools against the
// live tenant. All three are read-only, use a small limit, and tolerate a tenant
// with no assessed hosts.
var _ = Describe("zero_trust_assessment module", Label("integration", "zero_trust_assessment"), func() {
	var ctx context.Context

	BeforeEach(func() {
		ctx = newSpecContext()
	})

	itAdvertisesTools(
		"falcon_search_zta_assessments",
		"falcon_get_zta_assessments",
		"falcon_get_zta_audit",
	)

	Describe("search_zta_assessments", func() {
		It("returns the standard search envelope for a score bound", func() {
			// max_score alone lists the weakest hosts; the call must succeed and
			// carry the resources array whether or not the tenant has matches.
			res := callOK(ctx, "falcon_search_zta_assessments", map[string]any{"max_score": 50})
			Expect(structured(res)).To(HaveKey("resources"))
			// Counts ride on meta (meta.pagination.total) rather than a top-level
			// total; meta is omitempty, so assert its shape only when present.
			if m, ok := structured(res)["meta"]; ok {
				Expect(m).To(BeAssignableToTypeOf(map[string]any{}))
			}
		})

		It("returns full assessment records, not bare AIDs", func() {
			res := callOK(ctx, "falcon_search_zta_assessments", map[string]any{"max_score": 100, "limit": 5})
			skipIfEmpty(res, "tenant has no assessed hosts to validate details against")
			// assessment and assessment_items are the hardening-signal blocks; their
			// presence proves the score query was expanded into full detail records.
			expectSearchReturnsDetails(res, "aid", "cid", "assessment", "assessment_items")
		})

		It("rejects inverted score bounds before calling the API", func() {
			// min above max can match no host; the module fails this locally rather
			// than issuing a query that would silently return nothing.
			cs := newSession(ctx)
			res := callTool(ctx, cs, "falcon_search_zta_assessments", map[string]any{"min_score": 80, "max_score": 20})
			Expect(res.IsError).To(BeTrue(), "inverted score bounds should error: %v", res.Content)
			Expect(strings.ToLower(toolErrorText(res))).To(ContainSubstring("greater than"))
		})
	})

	Describe("get_zta_assessments", func() {
		It("reads an assessment for a host found by search", func() {
			cs := newSession(ctx)
			search := callTool(ctx, cs, "falcon_search_zta_assessments", map[string]any{"max_score": 100, "limit": 5})
			expectNoToolError(search)
			aid := firstResourceID(search, "aid") // skips when the tenant has no assessed hosts

			get := callTool(ctx, cs, "falcon_get_zta_assessments", map[string]any{"ids": []string{aid}})
			expectNoToolError(get)

			// The AID resolved from search must come back assessed, so not_found is
			// empty and the record carries a scored assessment block.
			Expect(notFound(get)).To(BeEmpty(), "an AID from search should not be reported not_found")
			recs := resources(get)
			Expect(recs).NotTo(BeEmpty())
			obj, ok := recs[0].(map[string]any)
			Expect(ok).To(BeTrue(), "assessment should be an object, got %T", recs[0])
			assessment, ok := obj["assessment"].(map[string]any)
			Expect(ok).To(BeTrue(), "record should carry an assessment object, got %T", obj["assessment"])
			Expect(assessment).To(HaveKey("overall"))
		})

		It("reports an unknown AID as not_found without erroring", func() {
			// A never-assessed AID is omitted from the response rather than erroring,
			// so the call succeeds with an empty resources set and the AID listed.
			res := callOK(ctx, "falcon_get_zta_assessments", map[string]any{"ids": []string{bogusAID}})
			Expect(resources(res)).To(BeEmpty())
			Expect(notFound(res)).To(ConsistOf(bogusAID))
		})
	})

	Describe("get_zta_audit", func() {
		It("returns the tenant-wide rollup", func() {
			res := callOK(ctx, "falcon_get_zta_audit", map[string]any{})
			skipIfEmpty(res, "tenant has no Zero Trust audit rollup (no assessed hosts)")
			// The rollup is a single CID-level record with the assessed-host count,
			// the average score, and a per-platform breakdown.
			expectSearchReturnsDetails(res, "num_aids", "average_overall_score", "platforms")
		})
	})
})

// notFound returns the not_found AID list from a ZTA result envelope, tolerating
// its absence (returns an empty slice). Both ZTA get tools carry not_found; the
// get-by-IDs envelope always includes it, while search omits it when empty.
func notFound(res *mcp.CallToolResult) []string {
	GinkgoHelper()
	raw, ok := structured(res)["not_found"]
	if !ok {
		return nil
	}
	arr, ok := raw.([]any)
	Expect(ok).To(BeTrue(), "not_found should be a JSON array, got %T", raw)
	out := make([]string, 0, len(arr))
	for _, v := range arr {
		s, ok := v.(string)
		Expect(ok).To(BeTrue(), "not_found entry should be a string, got %T", v)
		out = append(out, s)
	}
	return out
}
