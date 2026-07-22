package e2e

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// The spotlight specs exercise falcon_search_vulnerabilities against the live
// tenant. They are read-only, use a small limit, and tolerate an empty tenant.
// Label("spotlight") allows selecting just this module with
// --label-filter="spotlight"; Label("integration") marks the live tier.
var _ = Describe("spotlight module", Label("integration", "spotlight"), func() {
	var ctx context.Context

	BeforeEach(func() {
		ctx = newSpecContext()
	})

	It("advertises its tool with the falcon_ prefix", func() {
		cs := newSession(ctx)
		Expect(toolNames(ctx, cs)).To(ContainElement("falcon_search_vulnerabilities"))
	})

	It("searches vulnerabilities and returns full records", func() {
		cs := newSession(ctx)
		res := callTool(ctx, cs, "falcon_search_vulnerabilities", map[string]any{
			"facet": []any{"cve"},
			"limit": 3,
		})
		expectNoToolError(res)
		skipIfEmpty(res, "tenant has no vulnerabilities to validate details against")
		// cve is populated only when the cve facet is requested; its presence
		// confirms the facet was applied and full records returned.
		expectSearchReturnsDetails(res, "id", "cve")
	})

	It("searches vulnerabilities with an FQL filter", func() {
		cs := newSession(ctx)
		res := callTool(ctx, cs, "falcon_search_vulnerabilities", map[string]any{
			"filter": "status:'open'",
			"facet":  []any{"cve"},
			"limit":  3,
		})
		expectNoToolError(res)
		skipIfEmpty(res, "no open vulnerabilities in tenant")
		expectSearchReturnsDetails(res, "id", "cve")
	})

	It("searches vulnerabilities sorted by created_timestamp", func() {
		cs := newSession(ctx)
		res := callTool(ctx, cs, "falcon_search_vulnerabilities", map[string]any{
			"sort":  "created_timestamp|desc",
			"limit": 3,
		})
		expectNoToolError(res)
		skipIfEmpty(res, "tenant has no vulnerabilities to sort")
		expectSearchReturnsDetails(res, "id")
	})

	DescribeTable("returns the requested facet detail blocks",
		func(facets []any) {
			cs := newSession(ctx)
			res := callTool(ctx, cs, "falcon_search_vulnerabilities", map[string]any{
				"facet": facets,
				"limit": 3,
			})
			expectNoToolError(res)
			skipIfEmpty(res, "tenant has no vulnerabilities for facet validation")
			expectSearchReturnsDetails(res, "id")
		},
		Entry("single facet", []any{"cve"}),
		Entry("multiple facets", []any{"cve", "host_info", "remediation"}),
	)
})
