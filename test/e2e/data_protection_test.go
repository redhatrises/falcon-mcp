package e2e

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
)

// The data_protection specs exercise the Data Protection search tools
// (classifications, policies, content patterns) against the live tenant. This
// is a distinct module from shield (SaaS Security). The specs are read-only,
// use a small limit, and tolerate an empty tenant. Label("dataprotection")
// allows selecting just this module; Label("integration") marks the live tier.
var _ = Describe("dataprotection module", Label("integration", "dataprotection"), func() {
	var ctx context.Context

	BeforeEach(func() {
		ctx = newSpecContext()
	})

	itAdvertisesTools(
		"falcon_search_data_protection_classifications",
		"falcon_search_data_protection_policies",
		"falcon_search_data_protection_content_patterns",
	)

	It("searches classifications and returns full records", func() {
		res := callOK(ctx, "falcon_search_data_protection_classifications", map[string]any{"limit": 3})
		skipIfEmpty(res, "tenant has no data protection classifications")
		expectSearchReturnsDetails(res, "id", "name")
	})

	It("searches classifications sorted by name", func() {
		res := callOK(ctx, "falcon_search_data_protection_classifications", map[string]any{
			"sort":  "name.asc",
			"limit": 3,
		})
		skipIfEmpty(res, "tenant has no classifications to sort")
		expectSearchReturnsDetails(res, "id", "name")
	})

	DescribeTable("searches policies for each platform and returns full records",
		func(platform string) {
			res := callOK(ctx, "falcon_search_data_protection_policies", map[string]any{
				"platform_name": platform,
				"limit":         3,
			})
			skipIfEmpty(res, "tenant has no "+platform+" data protection policies")
			expectSearchReturnsDetails(res, "id", "name")
		},
		Entry("windows", "win"),
		Entry("mac", "mac"),
	)

	It("searches content patterns and returns full records", func() {
		res := callOK(ctx, "falcon_search_data_protection_content_patterns", map[string]any{"limit": 3})
		skipIfEmpty(res, "tenant has no data protection content patterns")
		expectSearchReturnsDetails(res, "id", "name", "type")
	})

	It("searches content patterns filtered by type", func() {
		res := callOK(ctx, "falcon_search_data_protection_content_patterns", map[string]any{
			"filter": "type:'predefined'",
			"limit":  3,
		})
		skipIfEmpty(res, "no predefined content patterns in tenant")
		expectSearchReturnsDetails(res, "id", "type")
	})
})
