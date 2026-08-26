package e2e

import (
	"context"
	"os"
	"regexp"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// nonexistentWorkflowID is a well-formed but unassigned 32-hex ID. The workflows
// API answers an unknown definition or execution ID with a 404, which the tools
// surface as an in-band tool error, so this drives the not-found paths.
const nonexistentWorkflowID = "ffffffffffffffffffffffffffffffff"

// tokenSep splits a workflow name on whitespace, dashes, and underscores so a
// single whole token can be pulled out for a `name:~` analyzed-match filter.
var tokenSep = regexp.MustCompile(`[\s\-_]+`)

// The fusion specs exercise the Fusion SOAR workflow tools against the live
// tenant. The three search/read tools are read-only, use a small limit, and
// tolerate an empty tenant. falcon_execute_workflow starts a real workflow — it
// may contain a host, disable an identity, or notify third parties — so it is
// covered only by its error contracts here; a real run is opt-in
// (FALCON_TEST_WORKFLOW_ID) and stays skipped by default.
var _ = Describe("fusion module", Label("integration", "fusion"), func() {
	var ctx context.Context

	BeforeEach(func() {
		ctx = newSpecContext()
	})

	itAdvertisesTools(
		"falcon_search_workflow_definitions",
		"falcon_search_workflow_executions",
		"falcon_get_workflow_execution_results",
		"falcon_execute_workflow",
	)

	Describe("search_workflow_definitions", func() {
		It("returns full definition records", func() {
			res := callOK(ctx, "falcon_search_workflow_definitions", map[string]any{"limit": 3})
			skipIfEmpty(res, "tenant has no workflow definitions to validate details against")
			// trigger is the block whose parameters field is the execute input's
			// JSON Schema; asserting it confirms the search returned full records.
			expectSearchReturnsDetails(res, "id", "name", "trigger", "enabled", "version")
		})

		It("accepts the documented filter fields", func() {
			def := firstDefinition(ctx)

			name, _ := def["name"].(string)
			Expect(name).NotTo(BeEmpty(), "definition should carry a name to derive filters from")
			id, _ := def["id"].(string)
			Expect(id).NotTo(BeEmpty(), "definition should carry an id")

			// name.raw is the exact/substring field; name (analyzed) matches whole
			// tokens only. All values are derived from a real record, so each must
			// match at least the row it came from.
			expectFilterMatches(ctx, "falcon_search_workflow_definitions", "name.raw:'"+name+"'")
			expectFilterMatches(ctx, "falcon_search_workflow_definitions", "name.raw:*'*"+nameFragment(name)+"*'")
			expectFilterMatches(ctx, "falcon_search_workflow_definitions", "name:~'"+firstToken(name)+"'")
			expectFilterMatches(ctx, "falcon_search_workflow_definitions", "id:'"+id+"'")
			expectFilterMatches(ctx, "falcon_search_workflow_definitions", "enabled:"+boolValue(def["enabled"]))
			if t := triggerType(def); t != "" {
				expectFilterMatches(ctx, "falcon_search_workflow_definitions", "trigger.type:'"+t+"'")
			}
			expectFilterMatches(ctx, "falcon_search_workflow_definitions", "version:>0")
			expectFilterMatches(ctx, "falcon_search_workflow_definitions", "last_modified_timestamp:>'now-3650d'")

			// mock_activities is a documented boolean field; a clean envelope proves
			// it is accepted, but an empty match set is legitimate.
			fusionSearchClean(ctx, "falcon_search_workflow_definitions", map[string]any{"filter": "mock_activities:false", "limit": 2})
		})

		It("returns zero rows for an exact match on the analyzed name field", func() {
			def := firstDefinition(ctx)
			name, _ := def["name"].(string)
			Expect(name).NotTo(BeEmpty())
			// name is analyzed: an exact-string match against it returns nothing,
			// which is the trap name.raw exists to avoid.
			res := fusionSearchClean(ctx, "falcon_search_workflow_definitions", map[string]any{"filter": "name:'" + name + "'", "limit": 2})
			Expect(resources(res)).To(BeEmpty(), "exact match on analyzed name should return no rows")
		})

		It("reports an unknown filter field via the FQL guide", func() {
			// An unknown field is a 400 whose message blames the filter, surfaced as
			// a data result carrying fql_guide rather than an in-band error.
			res := callOK(ctx, "falcon_search_workflow_definitions", map[string]any{"filter": "not_a_real_field:'x'", "limit": 2})
			Expect(structured(res)).To(HaveKey("fql_guide"))
		})

		It("accepts dot-form sort and rejects pipe-form sort", func() {
			fusionSearchClean(ctx, "falcon_search_workflow_definitions", map[string]any{"sort": "name.asc", "limit": 2})

			cs := newSession(ctx)
			res := callTool(ctx, cs, "falcon_search_workflow_definitions", map[string]any{"sort": "name|desc", "limit": 2})
			Expect(res.IsError).To(BeTrue(), "pipe-form sort should be rejected: %v", res.Content)
		})
	})

	Describe("search_workflow_executions", func() {
		It("returns full execution records", func() {
			res := callOK(ctx, "falcon_search_workflow_executions", map[string]any{"limit": 3})
			skipIfEmpty(res, "tenant has no workflow executions to validate details against")
			// execution_id, not id, is the response name for an execution's ID.
			expectSearchReturnsDetails(res, "execution_id", "definition_id", "status")
		})

		It("accepts every documented ui_status value", func() {
			// ui_status is the field to filter run status on; status uses a separate
			// internal vocabulary. Each documented value must be accepted, though a
			// given tenant may have no runs in that state.
			for _, s := range []string{"Completed", "Failed", "In progress", "Action required"} {
				fusionSearchClean(ctx, "falcon_search_workflow_executions", map[string]any{"filter": "ui_status:'" + s + "'", "limit": 2})
			}
		})

		It("accepts the documented filter fields", func() {
			exec := firstExecution(ctx)

			id, _ := exec["execution_id"].(string)
			Expect(id).NotTo(BeEmpty(), "execution should carry an execution_id")
			defID, _ := exec["definition_id"].(string)
			Expect(defID).NotTo(BeEmpty(), "execution should carry a definition_id")

			expectFilterMatches(ctx, "falcon_search_workflow_executions", "id:'"+id+"'")
			expectFilterMatches(ctx, "falcon_search_workflow_executions", "definition_id:'"+defID+"'")
			expectFilterMatches(ctx, "falcon_search_workflow_executions", "started_timestamp:>'now-3650d'")
			expectFilterMatches(ctx, "falcon_search_workflow_executions", "definition_version:>0")

			// completed_timestamp excludes in-progress runs and the two boolean
			// fields need not match any row, so a clean envelope is the check.
			fusionSearchClean(ctx, "falcon_search_workflow_executions", map[string]any{"filter": "completed_timestamp:>'now-3650d'", "limit": 2})
			fusionSearchClean(ctx, "falcon_search_workflow_executions", map[string]any{"filter": "test_mode:false", "limit": 2})
			fusionSearchClean(ctx, "falcon_search_workflow_executions", map[string]any{"filter": "contains_mocks:false", "limit": 2})
		})

		It("returns zero rows for a ui_status value on the internal status field", func() {
			// 'Completed' is a ui_status value; the internal status field never holds
			// it, so filtering status by it is a valid field with a non-matching value.
			res := fusionSearchClean(ctx, "falcon_search_workflow_executions", map[string]any{"filter": "status:'Completed'", "limit": 2})
			Expect(resources(res)).To(BeEmpty(), "internal status never equals the ui_status value 'Completed'")
		})

		It("reports the response-only start_timestamp name via the FQL guide", func() {
			// start_timestamp is a response field name; as a filter it is unknown and
			// rejected, steering the caller to started_timestamp via the guide.
			res := callOK(ctx, "falcon_search_workflow_executions", map[string]any{"filter": "start_timestamp:>'now-3650d'", "limit": 2})
			Expect(structured(res)).To(HaveKey("fql_guide"))
		})

		It("accepts dot-form sort and rejects pipe-form sort", func() {
			fusionSearchClean(ctx, "falcon_search_workflow_executions", map[string]any{"sort": "started_timestamp.desc", "limit": 2})

			cs := newSession(ctx)
			res := callTool(ctx, cs, "falcon_search_workflow_executions", map[string]any{"sort": "started_timestamp|desc", "limit": 2})
			Expect(res.IsError).To(BeTrue(), "pipe-form sort should be rejected: %v", res.Content)
		})
	})

	Describe("get_workflow_execution_results", func() {
		It("reads results for an execution found by search", func() {
			cs := newSession(ctx)
			execs := callTool(ctx, cs, "falcon_search_workflow_executions", map[string]any{"limit": 2})
			expectNoToolError(execs)
			execID := firstResourceID(execs, "execution_id") // skips when the tenant has no executions

			res := callTool(ctx, cs, "falcon_get_workflow_execution_results", map[string]any{"ids": []string{execID}})
			expectNoToolError(res)
			// The record is keyed by the same execution_id that was requested.
			Expect(idsOf(res, "execution_id")).To(ContainElement(execID))
		})

		It("shrinks the payload when sections are skipped", func() {
			cs := newSession(ctx)
			// A Completed run embeds its triggering event under trigger, the largest
			// section, so skipping it must shrink the response.
			execs := callTool(ctx, cs, "falcon_search_workflow_executions", map[string]any{"filter": "ui_status:'Completed'", "limit": 1})
			expectNoToolError(execs)
			if len(resources(execs)) == 0 {
				Skip("tenant has no completed workflow executions to trim")
			}
			execID := firstResourceID(execs, "execution_id")

			full := callTool(ctx, cs, "falcon_get_workflow_execution_results", map[string]any{"ids": []string{execID}})
			expectNoToolError(full)
			trimmed := callTool(ctx, cs, "falcon_get_workflow_execution_results", map[string]any{
				"ids":         []string{execID},
				"skip_fields": []string{"trigger", "activities", "flows", "submodels"},
			})
			expectNoToolError(trimmed)

			Expect(len(compactJSON(structured(trimmed)))).To(BeNumerically("<", len(compactJSON(structured(full)))),
				"skip_fields should shrink the returned record")
		})

		It("errors for an unknown execution ID", func() {
			cs := newSession(ctx)
			res := callTool(ctx, cs, "falcon_get_workflow_execution_results", map[string]any{"ids": []string{nonexistentWorkflowID}})
			Expect(res.IsError).To(BeTrue(), "unknown execution ID should error: %v", res.Content)
			Expect(strings.ToLower(toolErrorText(res))).To(ContainSubstring("not found"))
		})
	})

	Describe("execute_workflow (error contracts, nothing runs)", func() {
		It("requires exactly one identifier", func() {
			cs := newSession(ctx)
			res := callTool(ctx, cs, "falcon_execute_workflow", map[string]any{})
			Expect(res.IsError).To(BeTrue(), "missing identifier should error: %v", res.Content)
			Expect(toolErrorText(res)).To(ContainSubstring("definition_id"))
		})

		It("errors for an unknown definition_id", func() {
			cs := newSession(ctx)
			res := callTool(ctx, cs, "falcon_execute_workflow", map[string]any{"definition_id": nonexistentWorkflowID})
			Expect(res.IsError).To(BeTrue(), "unknown definition_id should error: %v", res.Content)
			Expect(strings.ToLower(toolErrorText(res))).To(ContainSubstring("not found"))
		})

		It("errors for an unknown name", func() {
			cs := newSession(ctx)
			res := callTool(ctx, cs, "falcon_execute_workflow", map[string]any{"name": uniqueTestName("nonexistent-workflow")})
			Expect(res.IsError).To(BeTrue(), "unknown name should error: %v", res.Content)
			Expect(strings.ToLower(toolErrorText(res))).To(ContainSubstring("not found"))
		})

		It("refuses a disabled definition", func() {
			cs := newSession(ctx)
			defs := callTool(ctx, cs, "falcon_search_workflow_definitions", map[string]any{
				"filter": "enabled:false+trigger.type:'On demand'",
				"limit":  1,
			})
			expectNoToolError(defs)
			if len(resources(defs)) == 0 {
				Skip("no disabled on-demand workflow definition to exercise the 412 path")
			}
			id := firstResourceID(defs, "id")

			res := callTool(ctx, cs, "falcon_execute_workflow", map[string]any{"definition_id": id})
			Expect(res.IsError).To(BeTrue(), "a disabled definition should be refused: %v", res.Content)
			Expect(strings.ToLower(toolErrorText(res))).To(ContainSubstring("disabled"))
		})

		It("refuses a Signal-triggered definition", func() {
			cs := newSession(ctx)
			defs := callTool(ctx, cs, "falcon_search_workflow_definitions", map[string]any{
				"filter": "enabled:true+trigger.type:'Signal'",
				"limit":  1,
			})
			expectNoToolError(defs)
			if len(resources(defs)) == 0 {
				Skip("no enabled Signal-triggered workflow definition to exercise the 412 path")
			}
			id := firstResourceID(defs, "id")

			res := callTool(ctx, cs, "falcon_execute_workflow", map[string]any{"definition_id": id})
			Expect(res.IsError).To(BeTrue(), "a Signal-triggered definition should be refused: %v", res.Content)
			Expect(strings.ToLower(toolErrorText(res))).To(ContainSubstring("on-demand or schedule"))
		})

		It("runs a real workflow and reads its results (opt-in)", func() {
			if !workflowExecEnabled() {
				Skip("set FALCON_TEST_WORKFLOW_ID to a known-inert on-demand workflow to run the live execute spec")
			}
			cs := newSession(ctx)
			res := callTool(ctx, cs, "falcon_execute_workflow", map[string]any{
				"definition_id": os.Getenv("FALCON_TEST_WORKFLOW_ID"),
				"parameters":    map[string]any{},
			})
			expectNoToolError(res)
			execID := firstResourceID(res, "execution_id")
			Expect(execID).To(MatchRegexp("^[0-9a-f]{32}$"), "execution_id should be 32 hex characters")

			results := callTool(ctx, cs, "falcon_get_workflow_execution_results", map[string]any{"ids": []string{execID}})
			expectNoToolError(results)
			Expect(idsOf(results, "execution_id")).To(ContainElement(execID))
		})
	})
})

// fusionSearchClean runs a fusion search tool and asserts it produced neither an
// in-band tool error nor an inline FQL rejection (fql_guide), returning the clean
// result. An empty match set is tolerated. It is the Go analog of the Python
// suite's clean-envelope assertion.
func fusionSearchClean(ctx context.Context, tool string, args map[string]any) *mcp.CallToolResult {
	GinkgoHelper()
	res := callOK(ctx, tool, args)
	Expect(structured(res)).NotTo(HaveKey("fql_guide"), "filter was rejected as invalid FQL: %v", res.Content)
	return res
}

// expectFilterMatches asserts a documented filter returns at least one row. That
// is the only proof the filter construction actually selects: an unknown field
// 400s and surfaces fql_guide, but a known field with an unsupported operator
// returns an empty 200 indistinguishable from a genuine no-match. It is the
// analog of the Python suite's assert_filter_matches.
func expectFilterMatches(ctx context.Context, tool, filter string) {
	GinkgoHelper()
	res := fusionSearchClean(ctx, tool, map[string]any{"filter": filter, "limit": 2})
	Expect(resources(res)).NotTo(BeEmpty(), "documented filter returned zero rows: %s", filter)
}

// firstDefinition returns the first workflow definition object, skipping the spec
// when the tenant has none. It backs the filter-field specs, which derive their
// values from a real record.
func firstDefinition(ctx context.Context) map[string]any {
	GinkgoHelper()
	res := fusionSearchClean(ctx, "falcon_search_workflow_definitions", map[string]any{"limit": 2})
	arr := resources(res)
	if len(arr) == 0 {
		Skip("tenant has no workflow definitions to derive filter values from")
	}
	obj, ok := arr[0].(map[string]any)
	Expect(ok).To(BeTrue(), "definition should be an object, got %T", arr[0])
	return obj
}

// firstExecution returns the first workflow execution object, skipping the spec
// when the tenant has none.
func firstExecution(ctx context.Context) map[string]any {
	GinkgoHelper()
	res := fusionSearchClean(ctx, "falcon_search_workflow_executions", map[string]any{"limit": 2})
	arr := resources(res)
	if len(arr) == 0 {
		Skip("tenant has no workflow executions to derive filter values from")
	}
	obj, ok := arr[0].(map[string]any)
	Expect(ok).To(BeTrue(), "execution should be an object, got %T", arr[0])
	return obj
}

// triggerType extracts the trigger.type string from a definition record, or ""
// when the block or field is absent.
func triggerType(def map[string]any) string {
	trig, ok := def["trigger"].(map[string]any)
	if !ok {
		return ""
	}
	t, _ := trig["type"].(string)
	return t
}

// boolValue renders a JSON boolean as the "true"/"false" literal an FQL filter
// expects, defaulting to "false" for a missing or non-boolean value.
func boolValue(v any) string {
	if b, ok := v.(bool); ok && b {
		return "true"
	}
	return "false"
}

// firstToken returns the leading whitespace/dash/underscore-delimited token of a
// name, for a name:~ analyzed whole-token match.
func firstToken(name string) string {
	parts := tokenSep.Split(strings.TrimSpace(name), -1)
	return parts[0]
}

// nameFragment returns a substring of name — at least three characters, up to
// half its length — for a name.raw substring match.
func nameFragment(name string) string {
	r := []rune(name)
	n := min(max(len(r)/2, 3), len(r))
	return string(r[:n])
}

// workflowExecEnabled reports whether the live execute spec should run. It is off
// by default and enabled by setting FALCON_TEST_WORKFLOW_ID to a definition ID,
// analogous to invokeEnabled in the agentworks specs.
func workflowExecEnabled() bool {
	return os.Getenv("FALCON_TEST_WORKFLOW_ID") != ""
}
