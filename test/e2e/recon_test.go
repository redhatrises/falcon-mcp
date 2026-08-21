package e2e

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
)

// The recon specs exercise the Falcon Intelligence Recon search tools
// (falcon_search_recon_notifications, falcon_search_recon_rules,
// falcon_search_recon_exposed_data_records) against the live tenant. They are
// read-only, use a small limit, and tolerate an empty tenant.
// Label("recon") allows selecting just this module with --label-filter="recon";
// Label("integration") marks the live tier.
var _ = Describe("recon module", Label("integration", "recon"), func() {
	var ctx context.Context

	BeforeEach(func() {
		ctx = newSpecContext()
	})

	itAdvertisesTools(
		"falcon_search_recon_notifications",
		"falcon_search_recon_rules",
		"falcon_search_recon_exposed_data_records",
	)

	It("searches recon notifications and returns full records", func() {
		res := callOK(ctx, "falcon_search_recon_notifications", map[string]any{"limit": 3})
		skipIfEmpty(res, "tenant has no recon notifications to validate details against")
		expectSearchReturnsDetails(res, "id")
	})

	It("searches recon notifications with an FQL filter", func() {
		res := callOK(ctx, "falcon_search_recon_notifications", map[string]any{
			"filter": "status:'new'",
			"limit":  3,
		})
		skipIfEmpty(res, "no new recon notifications in tenant")
		expectSearchReturnsDetails(res, "id")
	})

	It("searches recon rules and returns full records", func() {
		res := callOK(ctx, "falcon_search_recon_rules", map[string]any{"limit": 3})
		skipIfEmpty(res, "tenant has no recon monitoring rules")
		expectSearchReturnsDetails(res, "id", "name")
	})

	It("searches recon rules sorted by created_timestamp", func() {
		res := callOK(ctx, "falcon_search_recon_rules", map[string]any{
			"sort":  "created_timestamp|desc",
			"limit": 3,
		})
		skipIfEmpty(res, "tenant has no recon rules to sort")
		expectSearchReturnsDetails(res, "id")
	})

	It("searches recon exposed data records and returns full records", func() {
		res := callOK(ctx, "falcon_search_recon_exposed_data_records", map[string]any{"limit": 3})
		skipIfEmpty(res, "tenant has no exposed data records")
		expectSearchReturnsDetails(res, "id")
	})
})
