package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/modelcontextprotocol/go-sdk/mcp"
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

	clientT, serverT := mcp.NewInMemoryTransports()
	ss, err := srv.MCP().Connect(ctx, serverT, nil)
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
