// Package fusion implements the Fusion SOAR workflow tools over the gofalcon
// workflows client: searching workflow definitions and executions, reading
// execution results, and running a workflow. It also registers the two FQL
// guide resources for the search tools.
package fusion

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strconv"
	"strings"

	"github.com/crowdstrike/gofalcon/falcon/client/workflows"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/crowdstrike/falcon-mcp/internal/modules/base"
	"github.com/crowdstrike/falcon-mcp/internal/modules/registry"
)

// defaultSearchLimit is the page size applied when a search tool leaves limit
// unset, matching the Python falcon-mcp default.
const defaultSearchLimit = 10

// definitionsDefaultSort and executionsDefaultSort are the sort orders applied
// when a search tool leaves sort unset. Descending by the most useful timestamp
// keeps the newest records first and, for executions, avoids the ascending-order
// 404 hazard documented in the executions FQL guide.
const (
	definitionsDefaultSort = "last_modified_timestamp.desc"
	executionsDefaultSort  = "started_timestamp.desc"
)

// FQL guide resource URIs, kept 1:1 with the Python falcon-mcp fusion module.
const (
	fqlGuideDefinitionsURI = "falcon://fusion/workflow-definitions/fql-guide"
	fqlGuideExecutionsURI  = "falcon://fusion/workflow-executions/fql-guide"
)

// scopeWorkflowsRead and scopeWorkflowsWrite are the CrowdStrike API scopes the
// workflows operations require. Surfaced on a 403 via base.APIError.
var (
	scopeWorkflowsRead  = base.Scope{Name: "Workflows", Read: true}
	scopeWorkflowsWrite = base.Scope{Name: "Workflows", Write: true}
)

// Factory builds the fusion module from shared deps. The generated aggregator
// (internal/mcpserver) collects it, so the module needs no init side effect.
var Factory registry.Factory = func(d registry.Deps) base.Module {
	return &Module{API: d.API.Workflows, Logger: d.Logger}
}

// fusionAPI is the minimal slice of the gofalcon workflows client this module
// consumes, declared next to its consumer for testability.
type fusionAPI interface {
	WorkflowDefinitionsCombined(params *workflows.WorkflowDefinitionsCombinedParams, opts ...workflows.ClientOption) (*workflows.WorkflowDefinitionsCombinedOK, error)
	WorkflowExecutionsCombined(params *workflows.WorkflowExecutionsCombinedParams, opts ...workflows.ClientOption) (*workflows.WorkflowExecutionsCombinedOK, error)
	ExecutionResults(params *workflows.ExecutionResultsParams, opts ...workflows.ClientOption) (*workflows.ExecutionResultsOK, error)
	Execute(params *workflows.ExecuteParams, opts ...workflows.ClientOption) (*workflows.ExecuteOK, error)
}

// Module registers the fusion tools. It holds only the shared Falcon client and
// logger; handlers are stateless and reentrant. Logger must be non-nil.
type Module struct {
	API    fusionAPI
	Logger *slog.Logger
}

// Name reports the module name.
func (m *Module) Name() string { return "fusion" }

// Description reports a one-line summary of the module.
func (m *Module) Description() string {
	return "Search and run Fusion SOAR workflows and read their execution results"
}

// Tool and parameter descriptions, kept 1:1 with the Python falcon-mcp fusion
// module. Descriptions carrying backticks or multi-line content cannot live in a
// jsonschema struct tag, so they are consts applied by each schema's mutate func.
const (
	searchWorkflowDefinitionsDescription = `Search Fusion SOAR workflow definitions in your CrowdStrike environment.

Use this to find a workflow to run or inspect, filtering on name, enabled
state, trigger type, version, or last-modified time. Consult
falcon://fusion/workflow-definitions/fql-guide before constructing filter
expressions — matching a name needs ` + "`name.raw`" + `, because ` + "`name`" + ` is
analyzed and returns zero rows for an exact match. Returns full definition
records including ` + "`id`, `name`, `enabled`, `version`" + `, and the ` + "`trigger`" + `
block whose ` + "`parameters`" + ` field is the JSON Schema for that workflow's
execute input. Records are large (a definition embeds its whole action
configuration), so narrow the filter rather than raising the limit; one
definition can appear as several rows, one per version, so a result set may
hold more rows than the limit.
` + paginationTotalNote

	searchWorkflowExecutionsDescription = "Search Fusion SOAR workflow execution history in your CrowdStrike environment.\n" +
		"\n" +
		"Use this to see whether a workflow ran and how it finished, filtering on\n" +
		"definition, status, or start/finish time. Consult\n" +
		"falcon://fusion/workflow-executions/fql-guide before constructing filter\n" +
		"expressions — several fields are named differently in the filter than in\n" +
		"the response (`id` vs `execution_id`, `started_timestamp` vs\n" +
		"`start_timestamp`), and status must be filtered via `ui_status`, since\n" +
		"`status` uses a separate internal vocabulary. Returns full execution\n" +
		"records including `execution_id`, `definition_id`, `status`, timestamps,\n" +
		"and per-activity state. Records are large (an execution embeds the whole\n" +
		"triggering event), so narrow the filter rather than raising the limit, and\n" +
		"note `pagination.total` saturates at 10000, so exactly 10000 means \"at\n" +
		"least 10000\" rather than an exact count.\n" +
		paginationTotalNote

	getWorkflowExecutionResultsDescription = "Read what one or more Fusion SOAR workflow executions produced.\n" +
		"\n" +
		"Use this to look up executions directly by ID — up to 500 at once, with no\n" +
		"filter to construct — and to read each activity's own `result` payload:\n" +
		"ticket numbers, script output, API responses. This is the step after\n" +
		"falcon_execute_workflow, which returns only an execution ID. Returns the\n" +
		"full execution records including `status` and every activity's result;\n" +
		"`skip_fields` trims the largest sections when the records are too big. A run\n" +
		"still going reports `status` 'In progress': report that state back rather\n" +
		"than re-polling in a tight loop. 'Completed' and 'Failed' are terminal;\n" +
		"'Action required' means the run is waiting on a human, so polling will never\n" +
		"finish it."

	executeWorkflowDescription = "Start a Fusion SOAR workflow by definition ID.\n" +
		"\n" +
		"Use this to run a workflow a team has already built and reviewed — notifying\n" +
		"a channel, opening a ticket, or running a containment sequence. What this\n" +
		"tool does depends entirely on the workflow you name and cannot be known from\n" +
		"this tool's name: a workflow may contain a host, disable an identity, or\n" +
		"notify third parties. Confirm the definition with\n" +
		"falcon_search_workflow_definitions and check its `trigger.parameters`,\n" +
		"`enabled` and `version` first; prefer a `trigger.type` of 'On demand', and\n" +
		"note the API refuses a disabled definition or a 'Signal'-triggered one with\n" +
		"a 412 whose message says which. Match `parameters` to `trigger.parameters`\n" +
		"exactly — a missing required field is rejected and starts nothing, but a\n" +
		"wrong type or malformed value is accepted and starts a real run. Returns\n" +
		"`[{\"execution_id\": \"<id>\"}]`; the run is asynchronous, so read the outcome\n" +
		"with falcon_get_workflow_execution_results."

	// paginationTotalNote is the shared trailing sentence on the search tools'
	// descriptions, matching the phrasing used across the other search modules.
	paginationTotalNote = "Responses include `pagination.total` (the total number of records matching the filter, " +
		"or null when the API does not report a count) — use it to answer \"how many\" questions."
)

// Parameter descriptions carrying backticks, applied via the schema mutate funcs.
const (
	definitionsFilterDescription = "FQL filter expression. See `falcon://fusion/workflow-definitions/fql-guide` " +
		"for syntax. Match a workflow by name with `name.raw`, not `name`."

	executionsFilterDescription = "FQL filter expression. See `falcon://fusion/workflow-executions/fql-guide` " +
		"for syntax. Filter status with `ui_status`, not `status`."

	executionResultsIDsDescription = "Workflow execution IDs to read results for, up to 500. Returned by " +
		"falcon_execute_workflow as `execution_id`, or by falcon_search_workflow_executions."

	definitionsSortDescription = `Sort definitions using these options:

name: Workflow name
last_modified_timestamp: When the definition was last changed
version: Definition version
enabled: Whether the definition is enabled
id: Definition ID

Each was verified to reorder results. Sort either asc (ascending)
or desc (descending), using the dot separator ('name.desc'). The
pipe form ('name|desc') is rejected with a 400 here. A bare
property defaults to descending. Nested fields such as
trigger.type and name.raw are not sortable.

Examples: 'last_modified_timestamp.desc', 'name.asc'`

	executionsSortDescription = `Sort executions using these options:

started_timestamp: When the run started
completed_timestamp: When the run finished
definition_id: ID of the definition that ran
definition_name: Name of the definition that ran
definition_version: Version of the definition that ran
ui_status: Displayed run status
status: Internal run status
id: Execution ID

Each was verified to reorder results. Sort either asc (ascending)
or desc (descending), using the dot separator
('started_timestamp.desc'). The pipe form
('started_timestamp|desc') is rejected with a 400 here. A bare
property defaults to descending.

Prefer descending on a long history: ascending reaches the oldest
records first, and a matched execution that is no longer
retrievable fails the whole call with a 404.

Examples: 'started_timestamp.desc', 'completed_timestamp.desc'`

	skipFieldsDescription = "Sections to omit from each record to shrink the response. Any of 'trigger', " +
		"'activities', 'flows', 'submodels'. Omitting 'trigger' drops the embedded triggering event, " +
		"which is usually the largest part; do not omit 'activities' if you want the per-activity results."
)

// searchSchema builds the input schema shared by the two combined-search tools,
// applying the limit/offset bounds and the backtick-bearing filter/sort
// descriptions that a struct tag cannot express. Callers pass the per-tool
// filter and sort descriptions and the sort default.
func searchSchema[In any](filterDesc, sortDesc, sortDefault string) *jsonschema.Schema {
	return base.SchemaFor[In](func(s *jsonschema.Schema) {
		s.Properties["filter"].Description = filterDesc
		s.Properties["sort"].Description = sortDesc
		s.Properties["sort"].Default = json.RawMessage(strconv.Quote(sortDefault))
		s.Properties["limit"].Minimum = jsonschema.Ptr(1.0)
		s.Properties["limit"].Maximum = jsonschema.Ptr(500.0)
		s.Properties["limit"].Default = json.RawMessage(strconv.Itoa(defaultSearchLimit))
		s.Properties["offset"].Minimum = jsonschema.Ptr(0.0)
	})
}

// SearchInput is the input for both combined-search tools. The json tags drive
// the SDK unmarshal; the served schema is inferred from these tags then
// augmented by searchSchema.
type SearchInput struct {
	Filter string `json:"filter,omitempty" jsonschema:"FQL filter expression"`
	Limit  int    `json:"limit,omitempty" jsonschema:"The maximum records to return. [1-500]"`
	Offset int    `json:"offset,omitempty" jsonschema:"The offset to start retrieving records from."`
	Sort   string `json:"sort,omitempty" jsonschema:"FQL sort expression"`
}

// RegisterTools registers the fusion tools into r.
func (m *Module) RegisterTools(r base.Registrar) {
	base.AddTool(r, &mcp.Tool{
		Name:        "search_workflow_definitions",
		Description: searchWorkflowDefinitionsDescription,
		InputSchema: searchSchema[SearchInput](definitionsFilterDescription, definitionsSortDescription, definitionsDefaultSort),
	}, m.searchWorkflowDefinitions)

	base.AddTool(r, &mcp.Tool{
		Name:        "search_workflow_executions",
		Description: searchWorkflowExecutionsDescription,
		InputSchema: searchSchema[SearchInput](executionsFilterDescription, executionsSortDescription, executionsDefaultSort),
	}, m.searchWorkflowExecutions)

	base.AddTool(r, &mcp.Tool{
		Name:        "get_workflow_execution_results",
		Description: getWorkflowExecutionResultsDescription,
		InputSchema: executionResultsSchema,
	}, m.getWorkflowExecutionResults)

	base.AddTool(r, &mcp.Tool{
		Name:        "execute_workflow",
		Description: executeWorkflowDescription,
		InputSchema: executeSchema,
		// A workflow can delete or disable resources and notify third parties, so
		// its effects may not be reversible: destructive rather than merely mutating.
		Annotations: base.DestructiveAnnotations(false),
	}, m.executeWorkflow)
}

// RegisterResources publishes the two fusion FQL guides as MCP resources,
// mirroring the Python falcon-mcp fusion module's resources.
func (m *Module) RegisterResources(s *mcp.Server) {
	base.TextResource(s,
		fqlGuideDefinitionsURI,
		"search_workflow_definitions_fql_guide",
		"Contains the guide for the `filter` param of the `falcon_search_workflow_definitions` tool.",
		"text/markdown",
		definitionsFQLGuide,
	)
	base.TextResource(s,
		fqlGuideExecutionsURI,
		"search_workflow_executions_fql_guide",
		"Contains the guide for the `filter` param of the `falcon_search_workflow_executions` tool.",
		"text/markdown",
		executionsFQLGuide,
	)
}

// RegisterPrompts is a no-op: the fusion module exposes no prompts.
func (m *Module) RegisterPrompts(_ *mcp.Server) {}

func (m *Module) searchWorkflowDefinitions(ctx context.Context, _ *mcp.CallToolRequest, in SearchInput) (*mcp.CallToolResult, base.SearchResult[*models.DefinitionsDefinitionExt], error) {
	var zero base.SearchResult[*models.DefinitionsDefinitionExt]
	limit := int64(in.Limit)
	if limit == 0 {
		limit = defaultSearchLimit
	}
	sort := in.Sort
	if sort == "" {
		sort = definitionsDefaultSort
	}
	m.Logger.Debug("search_workflow_definitions", "filter", in.Filter, "limit", limit, "offset", in.Offset, "sort", sort)

	params := workflows.NewWorkflowDefinitionsCombinedParamsWithContext(ctx)
	params.Filter = in.Filter
	params.Limit = &limit
	params.Sort = &sort
	if in.Offset != 0 {
		o := strconv.Itoa(in.Offset)
		params.Offset = &o
	}

	resp, err := m.API.WorkflowDefinitionsCombined(params)
	if err != nil && in.Filter != "" {
		if details, ok := definitionsFQLBadRequest(err); ok {
			return nil, base.FQLError[*models.DefinitionsDefinitionExt](details, in.Filter, definitionsFQLGuide), nil
		}
	}
	if e := base.APIError(err, resp, scopeWorkflowsRead); e != nil {
		return nil, zero, e
	}
	return nil, base.Found(resp.Payload.Resources, in.Filter).WithMeta(resp.Payload.Meta), nil
}

func (m *Module) searchWorkflowExecutions(ctx context.Context, _ *mcp.CallToolRequest, in SearchInput) (*mcp.CallToolResult, base.SearchResult[*models.ExecutionsExecutionResult], error) {
	var zero base.SearchResult[*models.ExecutionsExecutionResult]
	limit := int64(in.Limit)
	if limit == 0 {
		limit = defaultSearchLimit
	}
	sort := in.Sort
	if sort == "" {
		sort = executionsDefaultSort
	}
	m.Logger.Debug("search_workflow_executions", "filter", in.Filter, "limit", limit, "offset", in.Offset, "sort", sort)

	params := workflows.NewWorkflowExecutionsCombinedParamsWithContext(ctx)
	params.Filter = in.Filter
	params.Limit = &limit
	params.Sort = &sort
	if in.Offset != 0 {
		o := strconv.Itoa(in.Offset)
		params.Offset = &o
	}

	resp, err := m.API.WorkflowExecutionsCombined(params)
	if err != nil && in.Filter != "" {
		if details, ok := executionsFQLBadRequest(err); ok {
			return nil, base.FQLError[*models.ExecutionsExecutionResult](details, in.Filter, executionsFQLGuide), nil
		}
	}
	if e := base.APIError(err, resp, scopeWorkflowsRead); e != nil {
		return nil, zero, e
	}
	return nil, base.Found(resp.Payload.Resources, in.Filter).WithMeta(resp.Payload.Meta), nil
}

// ExecutionResultsInput is the input for falcon_get_workflow_execution_results.
// ids has no omitempty, so schema inference marks it required.
type ExecutionResultsInput struct {
	IDs        []string `json:"ids" jsonschema:"execution IDs"`
	SkipFields []string `json:"skip_fields,omitempty" jsonschema:"sections to omit from each record"`
}

// executionResultsSchema is the input schema for the results tool, applying the
// backtick-bearing ids description and the skip_fields description that struct
// tags cannot carry cleanly.
var executionResultsSchema = base.SchemaFor[ExecutionResultsInput](func(s *jsonschema.Schema) {
	s.Properties["ids"].Description = executionResultsIDsDescription
	s.Properties["ids"].MaxItems = jsonschema.Ptr(500)
	s.Properties["skip_fields"].Description = skipFieldsDescription
})

func (m *Module) getWorkflowExecutionResults(ctx context.Context, _ *mcp.CallToolRequest, in ExecutionResultsInput) (*mcp.CallToolResult, base.EntitiesResult[*models.ExecutionsExecutionResult], error) {
	m.Logger.Debug("get_workflow_execution_results", "ids", len(in.IDs), "skip_fields", in.SkipFields)
	if len(in.IDs) == 0 {
		return nil, base.Entities([]*models.ExecutionsExecutionResult{}), nil
	}
	params := workflows.NewExecutionResultsParamsWithContext(ctx)
	params.Ids = in.IDs
	params.SkipFields = in.SkipFields

	resp, err := m.API.ExecutionResults(params)
	if e := base.APIError(err, resp, scopeWorkflowsRead); e != nil {
		return nil, base.EntitiesResult[*models.ExecutionsExecutionResult]{}, e
	}
	return nil, base.Entities(resp.Payload.Resources).WithMeta(resp.Payload.Meta), nil
}

// definitionsFQLBadRequest classifies err as a definitions FQL-filter error,
// returning the API error details when so. See fqlErrorDetails for why an FQL
// message is required beyond a bare 400.
func definitionsFQLBadRequest(err error) ([]base.FQLErrorDetail, bool) {
	var badReq *workflows.WorkflowDefinitionsCombinedBadRequest
	if !errors.As(err, &badReq) || badReq.Payload == nil {
		return nil, false
	}
	return fqlErrorDetails(badReq.Payload.Errors)
}

// executionsFQLBadRequest classifies err as an executions FQL-filter error.
func executionsFQLBadRequest(err error) ([]base.FQLErrorDetail, bool) {
	var badReq *workflows.WorkflowExecutionsCombinedBadRequest
	if !errors.As(err, &badReq) || badReq.Payload == nil {
		return nil, false
	}
	return fqlErrorDetails(badReq.Payload.Errors)
}

// fqlErrorDetails converts API errors to detail form and reports whether at
// least one blames the filter. The combined endpoints answer a rejected sort or
// an oversized limit with a 400 as well, so only an error whose message mentions
// the filter (or FQL) should steer the caller to the filter guide; anything else
// falls through to the generic API-error path.
func fqlErrorDetails(errs []*models.MsaAPIError) ([]base.FQLErrorDetail, bool) {
	details := base.FQLErrorDetails(errs)
	for _, d := range details {
		msg := strings.ToLower(d.Message)
		if strings.Contains(msg, "filter") || strings.Contains(msg, "fql") {
			return details, true
		}
	}
	return nil, false
}
