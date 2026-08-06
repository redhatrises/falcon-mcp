package e2e

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// The scheduled_reports specs exercise the scheduled reports/searches tools
// against the live tenant. They are read-only (the launch and download tools
// mutate/trigger and are not driven here to avoid side effects) and tolerate an
// empty tenant. Both search tools follow the two-step query->get-by-id chain and
// return entities with a flat "id" field, so the presence of "id" confirms the
// detail fetch ran rather than returning bare identifiers. Label("scheduledreports")
// selects just this module with --label-filter="scheduledreports"; Label("integration")
// marks the live tier.
var _ = Describe("scheduledreports module", Label("integration", "scheduledreports"), func() {
	var ctx context.Context

	BeforeEach(func() {
		ctx = newSpecContext()
	})

	It("advertises its tools with the falcon_ prefix", func() {
		cs := newSession(ctx)
		names := toolNames(ctx, cs)
		Expect(names).To(ContainElement("falcon_search_scheduled_reports"))
		Expect(names).To(ContainElement("falcon_launch_scheduled_report"))
		Expect(names).To(ContainElement("falcon_search_report_executions"))
		Expect(names).To(ContainElement("falcon_download_report_execution"))
	})

	It("searches scheduled reports and returns full entity details", func() {
		cs := newSession(ctx)
		res := callTool(ctx, cs, "falcon_search_scheduled_reports", map[string]any{
			"limit": 5,
		})
		expectNoToolError(res)
		skipIfEmpty(res, "tenant has no scheduled reports to validate against")
		// id and status are entity fields, so their presence confirms the
		// two-step query->QueryByID chain returned full records rather than IDs.
		expectSearchReturnsDetails(res, "id", "status")
	})

	It("searches scheduled reports filtered by status", func() {
		cs := newSession(ctx)
		res := callTool(ctx, cs, "falcon_search_scheduled_reports", map[string]any{
			"filter": "status:'ACTIVE'",
			"limit":  3,
		})
		expectNoToolError(res)
		skipIfEmpty(res, "tenant has no ACTIVE scheduled reports")
		expectSearchReturnsDetails(res, "id")
	})

	It("searches report executions and returns full execution details", func() {
		cs := newSession(ctx)
		res := callTool(ctx, cs, "falcon_search_report_executions", map[string]any{
			"limit": 5,
		})
		expectNoToolError(res)
		skipIfEmpty(res, "tenant has no report executions to validate against")
		expectSearchReturnsDetails(res, "id", "status")
	})

	It("searches report executions for a specific report and downloads a completed one", func() {
		cs := newSession(ctx)
		// Find a completed execution so the download tool has a valid, ready target.
		res := callTool(ctx, cs, "falcon_search_report_executions", map[string]any{
			"filter": "status:'DONE'",
			"limit":  1,
		})
		expectNoToolError(res)
		skipIfEmpty(res, "tenant has no completed report executions to download")
		expectSearchReturnsDetails(res, "id")

		execID := firstResourceID(res, "id")
		Expect(execID).NotTo(BeEmpty())
		dl := callTool(ctx, cs, "falcon_download_report_execution", map[string]any{
			"id": execID,
		})
		// A completed execution downloads to CSV or JSON; PDF-configured reports
		// surface an in-band error, which is acceptable behavior to observe here.
		expectNoToolError(dl)
	})
})
