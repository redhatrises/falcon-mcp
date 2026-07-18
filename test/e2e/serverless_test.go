package e2e

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// The serverless specs exercise falcon_search_serverless_vulnerabilities against
// the live tenant. They are read-only, use a small limit, and tolerate an empty
// tenant. The endpoint requires a filter, so every call supplies one. Results
// are SARIF "run" objects (each carrying "tool" and "results"), not entities
// with a flat ID field, so there is no search->get-by-id chain to exercise.
// Label("serverless") allows selecting just this module with
// --label-filter="serverless"; Label("integration") marks the live tier.
var _ = Describe("serverless module", Label("integration", "serverless"), func() {
	var ctx context.Context

	BeforeEach(func() {
		ctx = newSpecContext()
	})

	It("advertises its tools with the falcon_ prefix", func() {
		cs := newSession(ctx)
		Expect(toolNames(ctx, cs)).To(ContainElement("falcon_search_serverless_vulnerabilities"))
	})

	It("searches serverless vulnerabilities and returns SARIF runs", func() {
		cs := newSession(ctx)
		res := callTool(ctx, cs, "falcon_search_serverless_vulnerabilities", map[string]any{
			"filter": "cloud_provider:'aws'",
			"limit":  5,
		})
		expectNoToolError(res)
		skipIfEmpty(res, "tenant has no AWS serverless vulnerabilities to validate against")
		// tool and results are the SARIF run fields, so their presence confirms
		// the combined query returned full SARIF runs rather than bare
		// identifiers.
		expectSearchReturnsDetails(res, "tool", "results")
	})

	It("searches serverless vulnerabilities with a severity filter", func() {
		cs := newSession(ctx)
		res := callTool(ctx, cs, "falcon_search_serverless_vulnerabilities", map[string]any{
			"filter": "severity:'HIGH'",
			"limit":  3,
		})
		expectNoToolError(res)
		skipIfEmpty(res, "no HIGH severity serverless vulnerabilities in tenant")
		expectSearchReturnsDetails(res, "tool", "results")
	})

	It("searches serverless vulnerabilities sorted by severity", func() {
		cs := newSession(ctx)
		res := callTool(ctx, cs, "falcon_search_serverless_vulnerabilities", map[string]any{
			"filter": "cloud_provider:'aws'",
			"sort":   "severity",
			"limit":  3,
		})
		expectNoToolError(res)
		skipIfEmpty(res, "tenant has no AWS serverless vulnerabilities to sort")
		expectSearchReturnsDetails(res, "tool", "results")
	})
})
