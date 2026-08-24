package e2e

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// The ioc specs exercise the custom IOC tools against the live tenant. The read
// specs (search) are always safe. The mutation spec creates a disposable domain
// IOC, confirms it via search, and removes it, cleaning up with DeferCleanup
// even if an assertion fails; it carries Label("mutating") so it can be excluded
// with --label-filter="!mutating" and skips when the write scope is absent.
// Label("ioc") selects just this module; Label("integration") marks the live tier.
var _ = Describe("ioc module", Label("integration", "ioc"), func() {
	var ctx context.Context

	BeforeEach(func() {
		ctx = newSpecContext()
	})

	itAdvertisesTools(
		"falcon_search_iocs",
		"falcon_add_ioc",
		"falcon_remove_iocs",
	)

	It("searches IOCs and returns full records", func() {
		res := callOK(ctx, "falcon_search_iocs", map[string]any{"limit": 3})
		skipIfEmpty(res, "tenant has no custom IOCs to validate details against")
		expectSearchReturnsDetails(res, "id", "type", "value")
	})

	It("searches IOCs with an FQL filter", func() {
		res := callOK(ctx, "falcon_search_iocs", map[string]any{
			"filter": "type:'domain'",
			"limit":  3,
		})
		skipIfEmpty(res, "no domain IOCs in tenant")
		expectSearchReturnsDetails(res, "id", "type", "value")
	})

	It("searches IOCs sorted by modified_on", func() {
		res := callOK(ctx, "falcon_search_iocs", map[string]any{
			"sort":  "modified_on.desc",
			"limit": 3,
		})
		skipIfEmpty(res, "tenant has no IOCs to sort")
		expectSearchReturnsDetails(res, "id", "value")
	})

	It("adds, finds, and removes a domain IOC", Label("mutating"), func() {
		cs := newSession(ctx)
		// .invalid is reserved (RFC 2606) so the domain can never resolve; the
		// unique suffix keeps parallel processes and reruns from colliding.
		value := uniqueTestName("ioc") + ".invalid"
		const source = "falcon-mcp-e2e"

		add := callTool(ctx, cs, "falcon_add_ioc", map[string]any{
			"type":             "domain",
			"value":            value,
			"action":           "detect",
			"severity":         "low",
			"source":           source,
			"description":      "disposable IOC created by falcon-mcp e2e",
			"platforms":        []any{"linux"},
			"applied_globally": true,
			"ignore_warnings":  true,
		})
		skipIfToolError(add, "add IOC (IOC Management write scope required)")
		obj, id := createdObject(add, "id")

		// Register cleanup immediately so the IOC is removed even if a later
		// assertion fails.
		deferToolCleanup("falcon_remove_iocs", map[string]any{
			"ids":     []string{id},
			"comment": "falcon-mcp e2e cleanup",
		})

		Expect(obj).To(HaveKeyWithValue("value", value))

		// Round-trip: the created IOC must be findable by its source and value.
		// The IOC index is eventually consistent, so poll rather than searching
		// once.
		Eventually(func() []string {
			found := callTool(ctx, cs, "falcon_search_iocs", map[string]any{
				"filter": "source:'" + source + "'+value:'" + value + "'",
				"limit":  10,
			})
			expectNoToolError(found)
			return idsOf(found, "id")
		}).Should(ContainElement(id), "created IOC not found in search")
	})
})
