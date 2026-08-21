package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"strconv"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/crowdstrike/falcon-mcp/internal/mcpserver"
)

// defaultSpecTimeout bounds a single spec's live API interaction when TIMEOUT is
// unset. Live calls can hang on a slow or unreachable tenant; without a deadline
// the call blocks until go test kills the whole binary with an unhelpful stack
// dump. This gives a spec enough room for a slow-but-real response while still
// failing fast on a hang. Override it with the TIMEOUT env var (a Go duration
// string, e.g. 90s or 2m).
const defaultSpecTimeout = 60 * time.Second

// specTimeout returns the per-spec deadline: the TIMEOUT env var parsed as a Go
// duration, or defaultSpecTimeout when TIMEOUT is unset, empty, unparseable, or
// non-positive.
func specTimeout() time.Duration {
	d, err := time.ParseDuration(os.Getenv("TIMEOUT"))
	if err != nil || d <= 0 {
		return defaultSpecTimeout
	}
	return d
}

// newSpecContext returns a context bounded by specTimeout and registers its
// cancel with DeferCleanup, so every spec's live calls honor a deadline and the
// timer is released when the spec ends. Specs use it in place of
// context.Background().
func newSpecContext() context.Context {
	GinkgoHelper()
	ctx, cancel := context.WithTimeout(context.Background(), specTimeout())
	DeferCleanup(func() { cancel() })
	return ctx
}

// newSession opens an in-memory MCP client session against the shared live
// server. It connects the server transport before the client (the SDK requires
// server-first because the client drives initialization) and registers cleanup
// so each spec's session is torn down independently. The returned session talks
// the real MCP protocol to the real server, which in turn calls the live Falcon
// API.
func newSession(ctx context.Context) *mcp.ClientSession {
	GinkgoHelper()
	Expect(srv).NotTo(BeNil(), "suite server not initialized")
	return newSessionFor(ctx, srv)
}

// newSessionFor opens an in-memory MCP client session against the given server.
// It backs newSession (shared suite server) and lets specs that build their own
// server — such as the member-scoped MSSP spec — reuse the same session wiring.
func newSessionFor(ctx context.Context, server *mcpserver.Server) *mcp.ClientSession {
	GinkgoHelper()
	Expect(server).NotTo(BeNil(), "server not initialized")

	clientT, serverT := mcp.NewInMemoryTransports()
	ss, err := server.MCP().Connect(ctx, serverT, nil)
	Expect(err).NotTo(HaveOccurred(), "server connect")
	DeferCleanup(func() { _ = ss.Wait() })

	c := mcp.NewClient(&mcp.Implementation{Name: "falcon-mcp-e2e", Version: "test"}, nil)
	cs, err := c.Connect(ctx, clientT, nil)
	Expect(err).NotTo(HaveOccurred(), "client connect")
	DeferCleanup(func() { _ = cs.Close() })

	return cs
}

// callTool invokes a tool by name and fails the spec on a protocol-level error
// (a nil result or transport failure). It does not assert on the in-band tool
// error flag; use expectNoToolError for that so callers can distinguish a
// protocol failure from a tool-reported failure.
func callTool(ctx context.Context, cs *mcp.ClientSession, name string, args map[string]any) *mcp.CallToolResult {
	GinkgoHelper()
	res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: name, Arguments: args})
	Expect(err).NotTo(HaveOccurred(), "call tool %s", name)
	Expect(res).NotTo(BeNil(), "call tool %s returned nil result", name)
	logToolResult(name, args, res)
	return res
}

// logToolResult writes a compact summary of the call to GinkgoWriter, so the
// returned records are visible in verbose runs (-ginkgo.v / -ginkgo.vv) and on
// failure. It prints the resource count and one truncated single-line JSON entry
// per resource. It is gated by logResultsEnabled (LOG_RESULTS) and never fails
// the spec: this is diagnostic output, so it falls back to the raw content when
// structured content is absent (e.g. an error result).
func logToolResult(name string, args map[string]any, res *mcp.CallToolResult) {
	if !logResultsEnabled() {
		return
	}
	obj, ok := res.StructuredContent.(map[string]any)
	if !ok {
		fmt.Fprintf(GinkgoWriter, "=== %s %v === %+v\n", name, args, res.Content)
		return
	}
	arr, _ := obj["resources"].([]any)
	fmt.Fprintf(GinkgoWriter, "=== %s %v === %d resource(s)\n", name, args, len(arr))
	for i, r := range arr {
		fmt.Fprintf(GinkgoWriter, "  [%d] %s\n", i, truncate(compactJSON(r), 200))
	}
}

// logResultsEnabled reports whether tool results should be logged. It is off by
// default and enabled by setting LOG_RESULTS to a truthy value
// (1, true, yes, on).
func logResultsEnabled() bool {
	enabled, err := strconv.ParseBool(os.Getenv("LOG_RESULTS"))
	return err == nil && enabled
}

// compactJSON renders v as single-line JSON, falling back to Go's default format
// on error. It is used only for diagnostic logging.
func compactJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return fmt.Sprintf("%+v", v)
	}
	return string(b)
}

// truncate shortens s to at most n runes, appending an ellipsis when clipped.
func truncate(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}

// expectNoToolError asserts the tool did not report an in-band error. The SDK
// surfaces tool failures via CallToolResult.IsError (with detail in Content),
// not as a Go error, so this is checked separately from the protocol error in
// callTool. It is the analog of the Python suite's assert_no_error.
func expectNoToolError(res *mcp.CallToolResult) {
	GinkgoHelper()
	Expect(res.IsError).To(BeFalse(), "tool returned an error result: %+v", res.Content)
}

// callOK opens a session, invokes the named tool, and asserts it produced
// neither a protocol error nor an in-band tool error, returning the successful
// result for further assertions. It fuses the session-open, call, and
// error-check that every single-call read spec repeats. Specs that reuse a
// session across calls — a search feeding a get-by-id, or pagination — stay on
// newSession plus callTool so the session is threaded explicitly.
func callOK(ctx context.Context, name string, args map[string]any) *mcp.CallToolResult {
	GinkgoHelper()
	cs := newSession(ctx)
	res := callTool(ctx, cs, name, args)
	expectNoToolError(res)
	return res
}

// structured returns the tool result's structured content as a JSON object. Our
// result envelopes (SearchResult, EntitiesResult) are always JSON objects, and
// the SDK delivers them to the client side as a map[string]any.
func structured(res *mcp.CallToolResult) map[string]any {
	GinkgoHelper()
	Expect(res.StructuredContent).NotTo(BeNil(), "expected structured content")
	obj, ok := res.StructuredContent.(map[string]any)
	Expect(ok).To(BeTrue(), "structured content should be a JSON object, got %T", res.StructuredContent)
	return obj
}

// resources returns the "resources" array from a search/entities result
// envelope, asserting it is present and a (possibly empty) JSON array.
func resources(res *mcp.CallToolResult) []any {
	GinkgoHelper()
	obj := structured(res)
	raw, ok := obj["resources"]
	Expect(ok).To(BeTrue(), "structured content missing resources field: %v", obj)
	// A nil resources value is a bug: the envelope normalizes to an empty slice.
	Expect(raw).NotTo(BeNil(), "resources field is null; envelope should use an empty array")
	arr, ok := raw.([]any)
	Expect(ok).To(BeTrue(), "resources should be a JSON array, got %T", raw)
	return arr
}

// expectSearchReturnsDetails asserts the search returned full resource objects
// carrying the given fields, not bare ID strings. This is the key check the
// Python suite relies on to catch a two-step search that forgets to fetch
// details: an empty tenant is tolerated (nothing to check), but any returned
// element must be an object containing every expected field. Callers assert
// expectNoToolError before reaching here (it precedes skipIfEmpty), so this
// does not re-check the error flag.
func expectSearchReturnsDetails(res *mcp.CallToolResult, fields ...string) {
	GinkgoHelper()
	for i, r := range resources(res) {
		obj, ok := r.(map[string]any)
		Expect(ok).To(BeTrue(), "resource[%d] should be a full object, got %T (bare ID?)", i, r)
		for _, f := range fields {
			Expect(obj).To(HaveKey(f), "resource[%d] missing expected field %q", i, f)
		}
	}
}

// skipIfEmpty skips the current spec, with a visible message, when the search
// returned no resources. Live tenants may legitimately have no data for a given
// query; skipping keeps the suite green rather than asserting on data that may
// not exist. It is the analog of the Python suite's skip_with_warning.
func skipIfEmpty(res *mcp.CallToolResult, reason string) {
	GinkgoHelper()
	if len(resources(res)) == 0 {
		By("skipping: " + reason)
		Skip(reason)
	}
}

// firstResourceID returns the value of idField from the first resource object,
// or skips the spec when there are no resources. It supports chained tests that
// search for an entity and then fetch it by ID.
func firstResourceID(res *mcp.CallToolResult, idField string) string {
	GinkgoHelper()
	arr := resources(res)
	if len(arr) == 0 {
		Skip("no resources returned to derive an ID from")
	}
	obj, ok := arr[0].(map[string]any)
	Expect(ok).To(BeTrue(), "first resource should be an object, got %T", arr[0])
	id, ok := obj[idField].(string)
	Expect(ok).To(BeTrue(), "first resource %q should be a string id", idField)
	Expect(id).NotTo(BeEmpty())
	return id
}

// toolNames lists the advertised tool names over the live session. It is used to
// assert a module's tools are present with the falcon_ prefix.
func toolNames(ctx context.Context, cs *mcp.ClientSession) []string {
	GinkgoHelper()
	list, err := cs.ListTools(ctx, nil)
	Expect(err).NotTo(HaveOccurred(), "list tools")
	names := make([]string, 0, len(list.Tools))
	for _, t := range list.Tools {
		names = append(names, t.Name)
	}
	return names
}

// itAdvertisesTools registers a spec asserting the module advertises every named
// tool over a live session. It replaces the near-identical tool-advertisement
// spec each module otherwise hand-writes. The spec builds its own context and
// session so it is self-contained and independent of the enclosing Describe's
// setup. Gomega's ContainElements unpacks the single slice argument.
func itAdvertisesTools(names ...string) {
	It("advertises its tools with the falcon_ prefix", func() {
		ctx := newSpecContext()
		cs := newSession(ctx)
		Expect(toolNames(ctx, cs)).To(ContainElements(names))
	})
}

// uniqueTestName builds a collision-resistant, obviously-disposable name for a
// resource a mutating spec creates. The falcon-mcp-e2e prefix makes leaked
// artifacts easy to spot and purge; the nanosecond suffix keeps parallel
// processes and reruns from colliding. It is used only by write specs.
func uniqueTestName(prefix string) string {
	return fmt.Sprintf("falcon-mcp-e2e-%s-%d", prefix, time.Now().UnixNano())
}

// skipIfToolError skips the current spec when a mutating tool reported an
// in-band error, surfacing the error text as the skip reason. A live tenant may
// lack the write scope for a create/delete flow; skipping there keeps the suite
// green rather than failing on a permission gap, mirroring how read specs
// tolerate missing data. The SDK carries a handler-returned error in Content as
// text (not StructuredContent), so the message is read from there.
func skipIfToolError(res *mcp.CallToolResult, context string) {
	GinkgoHelper()
	if !res.IsError {
		return
	}
	Skip(context + ": " + toolErrorText(res))
}

// toolErrorText extracts a human-readable message from an error result's
// Content, joining any text blocks. It is used only for skip/failure messages.
func toolErrorText(res *mcp.CallToolResult) string {
	var msg string
	for _, c := range res.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			if msg != "" {
				msg += "; "
			}
			msg += tc.Text
		}
	}
	if msg == "" {
		return "tool returned an error result"
	}
	return msg
}

// createdObject asserts a create tool returned exactly one resource and returns
// it as an object along with its idField value. It centralizes the shape checks
// every mutating create round-trip otherwise repeats.
func createdObject(res *mcp.CallToolResult, idField string) (map[string]any, string) {
	GinkgoHelper()
	created := resources(res)
	Expect(created).To(HaveLen(1), "expected exactly one created resource")
	obj, ok := created[0].(map[string]any)
	Expect(ok).To(BeTrue(), "created resource should be an object, got %T", created[0])
	id, ok := obj[idField].(string)
	Expect(ok).To(BeTrue(), "created resource should carry a string %s", idField)
	Expect(id).NotTo(BeEmpty())
	return obj, id
}

// deferToolCleanup registers DeferCleanup that invokes a teardown tool (a delete
// or a compensating update) on a fresh session and context and asserts it
// reports no error. A fresh context is used because the spec's own context may
// already be cancelled by the time cleanup runs. Registering it immediately
// after a create ensures teardown runs even if a later assertion fails.
//
// The callback builds its context and session inline rather than via
// newSpecContext/newSession because those helpers call DeferCleanup, which
// Ginkgo forbids from within a running DeferCleanup callback: the illegal call
// aborts the process before the teardown tool runs, leaking live-tenant state.
// So the context cancel and session close are deferred manually here instead.
func deferToolCleanup(tool string, args map[string]any) {
	GinkgoHelper()
	DeferCleanup(func() {
		Expect(srv).NotTo(BeNil(), "suite server not initialized")

		ctx, cancel := context.WithTimeout(context.Background(), specTimeout())
		defer cancel()

		clientT, serverT := mcp.NewInMemoryTransports()
		ss, err := srv.MCP().Connect(ctx, serverT, nil)
		Expect(err).NotTo(HaveOccurred(), "cleanup server connect")
		defer func() { _ = ss.Wait() }()

		c := mcp.NewClient(&mcp.Implementation{Name: "falcon-mcp-e2e", Version: "test"}, nil)
		cs, err := c.Connect(ctx, clientT, nil)
		Expect(err).NotTo(HaveOccurred(), "cleanup client connect")
		defer func() { _ = cs.Close() }()

		res := callTool(ctx, cs, tool, args)
		expectNoToolError(res)
	})
}

// expectOffsetPaginates drives the offset-paging contract end to end: the offset a
// tool reports in meta.pagination is the offset the caller sent, and advancing it by
// the page size returns the next, non-overlapping page. The reported offset must be
// numeric so it satisfies the tool's integer-typed offset input; a string there is
// the schema mismatch this spec exists to catch.
//
// args must carry an int "limit" — it is the page size the next offset advances by.
// A tenant holding a single page or fewer cannot exercise paging, so that case skips
// rather than asserting a vacuous truth; a missing meta, pagination block, or offset
// on a tool declared offset-paginated is the regression this exists to catch.
func expectOffsetPaginates(ctx context.Context, cs *mcp.ClientSession, name string, args map[string]any) {
	GinkgoHelper()

	limit, ok := args["limit"].(int)
	Expect(ok).To(BeTrue(), "expectOffsetPaginates requires an int limit in args, got %#v", args["limit"])

	first := callTool(ctx, cs, name, args)
	expectNoToolError(first)

	meta, ok := structured(first)["meta"].(map[string]any)
	Expect(ok).To(BeTrue(), "%s reported no meta to page from", name)
	paging, ok := meta["pagination"].(map[string]any)
	Expect(ok).To(BeTrue(), "%s reported no pagination block: %v", name, meta)
	Expect(paging).To(HaveKey("offset"), "%s is offset-paginated but reported no offset: %v", name, paging)

	// The offset must be numeric to satisfy the integer-typed offset inputs; a
	// string here is the exact mismatch this spec exists to catch.
	offset, ok := paging["offset"].(float64)
	Expect(ok).To(BeTrue(), "%s reported a non-numeric offset %#v, which its integer-typed input rejects", name, paging["offset"])

	// Paging is only observable with more than one page of results. total is the
	// API's own count, so use it to skip a tenant too small to page.
	total, ok := paging["total"].(float64)
	if !ok || total <= float64(limit) {
		Skip(fmt.Sprintf("%s tenant reports total %v for page size %d; too few to page", name, paging["total"], limit))
	}

	firstIDs := idsOf(first, "id")
	Expect(firstIDs).NotTo(BeEmpty(), "%s reported total %v but returned no page-one resources", name, total)

	// Advance by the page size and hand the offset back through the advertised input
	// schema. Copying args keeps limit/filter identical, so the offset is the only
	// difference between the two calls.
	next := make(map[string]any, len(args)+1)
	maps.Copy(next, args)
	next["offset"] = int(offset) + limit
	second := callTool(ctx, cs, name, next)
	expectNoToolError(second)

	secondIDs := idsOf(second, "id")
	Expect(secondIDs).NotTo(BeEmpty(), "%s returned no resources at offset %d despite total %v", name, int(offset)+limit, total)

	// The second page must not repeat the first: an offset advanced by the page size
	// skips exactly the resources already seen.
	firstSet := make(map[string]bool, len(firstIDs))
	for _, id := range firstIDs {
		firstSet[id] = true
	}
	for _, id := range secondIDs {
		Expect(firstSet[id]).To(BeFalse(), "%s returned ID %q on both pages; the offset did not advance", name, id)
	}
}

// idsOf collects the idField value from every resource in a search result. It
// supports round-trip assertions that a created entity appears in a search.
func idsOf(res *mcp.CallToolResult, idField string) []string {
	GinkgoHelper()
	arr := resources(res)
	ids := make([]string, 0, len(arr))
	for _, r := range arr {
		if obj, ok := r.(map[string]any); ok {
			if id, ok := obj[idField].(string); ok {
				ids = append(ids, id)
			}
		}
	}
	return ids
}

// tagsOf extracts the string tags from a detection detail object, tolerating a
// missing or differently typed tags field (returns an empty slice). It supports
// the detection update round-trip's read-back assertion.
func tagsOf(obj map[string]any) []string {
	raw, ok := obj["tags"].([]any)
	if !ok {
		return nil
	}
	tags := make([]string, 0, len(raw))
	for _, t := range raw {
		if s, ok := t.(string); ok {
			tags = append(tags, s)
		}
	}
	return tags
}
