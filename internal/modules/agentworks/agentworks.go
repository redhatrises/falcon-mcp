// Package agentworks implements the AgentWorks (Charlotte AI) tools over the
// gofalcon agents, agent-versions, spans, and agent-invocation clients: three
// two-step searches, a single-invocation lookup, and an agent invocation. It
// also registers the three AgentWorks FQL guide resources.
package agentworks

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/crowdstrike/gofalcon/falcon/client/agent_invocation"
	"github.com/crowdstrike/gofalcon/falcon/client/agent_versions"
	"github.com/crowdstrike/gofalcon/falcon/client/agents"
	"github.com/crowdstrike/gofalcon/falcon/client/spans"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/crowdstrike/falcon-mcp/internal/modules/base"
	"github.com/crowdstrike/falcon-mcp/internal/modules/registry"
)

// detailBatchSize is the maximum number of IDs fetched per details call.
const detailBatchSize = 100

// defaultSearchLimit is the query page size applied when the caller omits limit,
// matching the Python module's default of 100 across all three searches.
const defaultSearchLimit = 100

// MCP resource URIs serving the AgentWorks FQL filter guides.
const (
	agentsFQLGuideURI        = "falcon://agentworks/agents/fql-guide"
	agentVersionsFQLGuideURI = "falcon://agentworks/agent-versions/fql-guide"
	spansFQLGuideURI         = "falcon://agentworks/spans/fql-guide"
)

// errUnexpectedResponse is returned when the invoke API succeeds but its payload
// is missing the invocation record or its id. Wrapped with %w and matched via
// errors.Is.
var errUnexpectedResponse = errors.New("agentworks: unexpected API response")

// scopeAgentworksRead is the CrowdStrike API scope required by the read tools.
// Surfaced on a 403 via base.APIError.
var scopeAgentworksRead = base.Scope{Name: "Charlotte AI Agent Definition", Read: true}

// agentsAPI is the minimal slice of the gofalcon agents client this module
// consumes, declared next to its consumer for testability.
type agentsAPI interface {
	QueryAgentsV2(params *agents.QueryAgentsV2Params, opts ...agents.ClientOption) (*agents.QueryAgentsV2OK, error)
	GetAgentsV2(params *agents.GetAgentsV2Params, opts ...agents.ClientOption) (*agents.GetAgentsV2OK, error)
}

// agentVersionsAPI is the minimal slice of the gofalcon agent-versions client.
type agentVersionsAPI interface {
	QueryAgentVersionsV1(params *agent_versions.QueryAgentVersionsV1Params, opts ...agent_versions.ClientOption) (*agent_versions.QueryAgentVersionsV1OK, error)
	GetAgentVersionsV1(params *agent_versions.GetAgentVersionsV1Params, opts ...agent_versions.ClientOption) (*agent_versions.GetAgentVersionsV1OK, error)
}

// spansAPI is the minimal slice of the gofalcon spans client.
type spansAPI interface {
	QueriesSpansV1(params *spans.QueriesSpansV1Params, opts ...spans.ClientOption) (*spans.QueriesSpansV1OK, error)
	EntitiesSpansV1(params *spans.EntitiesSpansV1Params, opts ...spans.ClientOption) (*spans.EntitiesSpansV1OK, error)
}

// agentInvocationAPI is the minimal slice of the gofalcon agent-invocation
// client: the single-invocation lookup plus the two invoke dispatch targets.
type agentInvocationAPI interface {
	GetAgentInvocationV3(params *agent_invocation.GetAgentInvocationV3Params, opts ...agent_invocation.ClientOption) (*agent_invocation.GetAgentInvocationV3OK, error)
	InvokeAgentVersionExternalV1(params *agent_invocation.InvokeAgentVersionExternalV1Params, opts ...agent_invocation.ClientOption) (*agent_invocation.InvokeAgentVersionExternalV1OK, error)
	InvokePublishedAgentExternalV1(params *agent_invocation.InvokePublishedAgentExternalV1Params, opts ...agent_invocation.ClientOption) (*agent_invocation.InvokePublishedAgentExternalV1OK, error)
}

// Module registers the AgentWorks tools. It holds the four sub-clients it spans
// plus shared configuration; handlers are stateless and reentrant. PollInterval
// and Timeout bound the invoke block-poll. Logger must be non-nil.
type Module struct {
	Agents          agentsAPI
	AgentVersions   agentVersionsAPI
	Spans           spansAPI
	AgentInvocation agentInvocationAPI
	Concurrency     int // bounds concurrent detail fetches
	PollInterval    time.Duration
	Timeout         time.Duration
	Logger          *slog.Logger
}

// Factory builds the agentworks module from shared deps. The generated
// aggregator (internal/mcpserver) collects it, so the module needs no init side
// effect. PollInterval and Timeout come from the resolved config
// (env-configurable via FALCON_MCP_AGENTWORKS_POLL_INTERVAL /
// FALCON_MCP_AGENTWORKS_TIMEOUT).
var Factory registry.Factory = func(d registry.Deps) base.Module {
	return &Module{
		Agents:          d.API.Agents,
		AgentVersions:   d.API.AgentVersions,
		Spans:           d.API.Spans,
		AgentInvocation: d.API.AgentInvocation,
		Concurrency:     d.Concurrency,
		PollInterval:    d.AgentworksPollInterval,
		Timeout:         d.AgentworksTimeout,
		Logger:          d.Logger,
	}
}

// Name reports the module name.
func (m *Module) Name() string { return "agentworks" }

// Description reports a one-line summary of the module.
func (m *Module) Description() string {
	return "Search AgentWorks (Charlotte AI) agents, versions, and spans, and invoke agents"
}

// Tool and parameter descriptions, kept 1:1 with the Python falcon-mcp
// agentworks module. Descriptions carrying backticks cannot live in a raw-string
// literal (the backtick delimits it) or a jsonschema struct tag, so they are
// consts applied to the schemas by their mutate funcs below.
const (
	searchAgentsDescription = `Search for AgentWorks (Charlotte AI) agents in your CrowdStrike environment.

Use this to list agents and find their IDs and active versions before invoking
one or inspecting its versions. Filter by template, backing model, or published
version — consult falcon://agentworks/agents/fql-guide before constructing
filter expressions. Returns full agent details including active version and
published version IDs.
` + "Responses include `pagination.total` (the total number of records matching the filter, " +
		"or null when the API does not report a count)."

	searchAgentVersionsDescription = "Search for versions of AgentWorks agents.\n\n" +
		"Use this to list an agent's versions (filter by `agent_id`) and find a specific " +
		"`version_id` — for example to invoke a non-published version by passing that " +
		"version_id to falcon_invoke_agentworks_agent. Filter by agent, name, model, or " +
		"published/enabled state — consult falcon://agentworks/agent-versions/fql-guide " +
		"before constructing filter expressions. Returns full version details.\n" +
		"Responses include `pagination.total` (the total number of records matching the filter, " +
		"or null when the API does not report a count)."

	searchSpansDescription = "Search AgentWorks execution spans (traces) for observability.\n\n" +
		"This is effectively a trace-scoped tool: spans number in the hundreds of thousands, " +
		"so ALWAYS filter — the primary use is passing an invocation's `ai_trace_id` as " +
		"`trace_id:'<value>'` to retrieve that run's spans (LLM calls, agent steps, cost, " +
		"request/response content). You can further narrow by span_type, status, name, or " +
		"duration_ms; note start_time is limited to the last 90 days. Consult " +
		"falcon://agentworks/spans/fql-guide before constructing filter expressions. " +
		"Returns full span details.\n" +
		"Responses include `pagination.total` (the total number of records matching the filter, " +
		"or null when the API does not report a count)."

	getInvocationDescription = "Get the current state of an AgentWorks agent invocation by ID.\n\n" +
		"Use this to resume or observe a run that paused (waiting_for_tool_approval) or that " +
		"timed out from falcon_invoke_agentworks_agent — poll it until `status` is terminal " +
		"(completed/failed). Returns the invocation resource including status, conversation, " +
		"ai_trace_id, and any tool approvals."

	agentsFilterDesc        = "FQL filter expression. See `falcon://agentworks/agents/fql-guide` for syntax."
	agentVersionsFilterDesc = "FQL filter expression. See `falcon://agentworks/agent-versions/fql-guide` for syntax."
	spansFilterDesc         = "FQL filter expression. See `falcon://agentworks/spans/fql-guide` for syntax. ALWAYS filter — usually by trace_id."
)

// searchAgentsSchema is the input schema for falcon_search_agentworks_agents.
// It is inferred from SearchAgentsInput, then a mutate func adds the limit
// bounds/default the tag syntax cannot express and the backtick-bearing filter
// description that cannot live in a struct tag.
var searchAgentsSchema = base.SchemaFor[SearchAgentsInput](func(s *jsonschema.Schema) {
	s.Properties["filter"].Description = agentsFilterDesc
	s.Properties["limit"].Minimum = jsonschema.Ptr(1.0)
	s.Properties["limit"].Maximum = jsonschema.Ptr(500.0)
	s.Properties["limit"].Default = json.RawMessage(`100`)
	s.Properties["offset"].Minimum = jsonschema.Ptr(0.0)
})

// searchAgentVersionsSchema is the input schema for
// falcon_search_agentworks_agent_versions.
var searchAgentVersionsSchema = base.SchemaFor[SearchAgentVersionsInput](func(s *jsonschema.Schema) {
	s.Properties["filter"].Description = agentVersionsFilterDesc
	s.Properties["limit"].Minimum = jsonschema.Ptr(1.0)
	s.Properties["limit"].Maximum = jsonschema.Ptr(500.0)
	s.Properties["limit"].Default = json.RawMessage(`100`)
	s.Properties["offset"].Minimum = jsonschema.Ptr(0.0)
})

// searchSpansSchema is the input schema for falcon_search_agentworks_spans.
var searchSpansSchema = base.SchemaFor[SearchSpansInput](func(s *jsonschema.Schema) {
	s.Properties["filter"].Description = spansFilterDesc
	s.Properties["limit"].Minimum = jsonschema.Ptr(1.0)
	s.Properties["limit"].Maximum = jsonschema.Ptr(1000.0)
	s.Properties["limit"].Default = json.RawMessage(`100`)
	s.Properties["offset"].Minimum = jsonschema.Ptr(0.0)
})

// RegisterTools registers the AgentWorks tools into r.
func (m *Module) RegisterTools(r base.Registrar) {
	base.AddTool(r, &mcp.Tool{
		Name:        "search_agentworks_agents",
		Description: searchAgentsDescription,
		InputSchema: searchAgentsSchema,
	}, m.searchAgents)

	base.AddTool(r, &mcp.Tool{
		Name:        "search_agentworks_agent_versions",
		Description: searchAgentVersionsDescription,
		InputSchema: searchAgentVersionsSchema,
	}, m.searchAgentVersions)

	base.AddTool(r, &mcp.Tool{
		Name:        "search_agentworks_spans",
		Description: searchSpansDescription,
		InputSchema: searchSpansSchema,
	}, m.searchSpans)

	base.AddTool(r, &mcp.Tool{
		Name:        "get_agentworks_agent_invocation",
		Description: getInvocationDescription,
	}, m.getInvocation)

	base.AddTool(r, &mcp.Tool{
		Name:        "invoke_agentworks_agent",
		Description: invokeDescription,
		InputSchema: invokeSchema,
		// Invoking an agent runs a workload and spends credits, but does not
		// irreversibly alter tenant data, so it is mutating rather than destructive.
		Annotations: base.MutatingAnnotations(false),
	}, m.invokeAgent)
}

// RegisterResources publishes the three AgentWorks FQL guides as MCP resources,
// mirroring falcon-mcp's falcon://agentworks/*/fql-guide resources.
func (m *Module) RegisterResources(s *mcp.Server) {
	base.TextResource(s, agentsFQLGuideURI, "search_agentworks_agents_fql_guide",
		"Contains the guide for the `filter` param of the `falcon_search_agentworks_agents` tool.",
		"text/markdown", agentsFQLGuide)
	base.TextResource(s, agentVersionsFQLGuideURI, "search_agentworks_agent_versions_fql_guide",
		"Contains the guide for the `filter` param of the `falcon_search_agentworks_agent_versions` tool.",
		"text/markdown", agentVersionsFQLGuide)
	base.TextResource(s, spansFQLGuideURI, "search_agentworks_spans_fql_guide",
		"Contains the guide for the `filter` param of the `falcon_search_agentworks_spans` tool.",
		"text/markdown", spansFQLGuide)
}

// RegisterPrompts is a no-op: the agentworks module exposes no prompts.
func (m *Module) RegisterPrompts(_ *mcp.Server) {}

// searchParams carries the pointer-shaped pagination that a query closure
// assigns onto its typed gofalcon params: an omitted filter/sort stays nil
// (never ""), and offset is sent only when non-zero.
type searchParams struct {
	Filter *string
	Limit  *int64
	Offset *int64
	Sort   *string
}

// searchOp configures one AgentWorks two-step search. runSearch drives the flow
// shared by all three tools — pagination defaulting, the empty-result envelope,
// the soft FQL error, and the concurrent detail fetch — so each tool supplies
// only its typed query and fetch closures.
type searchOp[E any] struct {
	req      *mcp.CallToolRequest
	filter   string
	limit    int
	offset   int
	sort     string
	fqlGuide string
	// query runs the Query* step. It returns non-nil fqlErr details when the API
	// rejected the FQL filter (HTTP 400 whose message blames the filter) so
	// runSearch returns a soft FQL error carrying those details rather than a Go
	// error; any other non-nil err is returned as-is.
	query func(ctx context.Context, p searchParams) (ids []string, meta *models.MsaMetaInfo, fqlErr []base.FQLErrorDetail, err error)
	fetch base.DetailFetcher[E]
	keyFn func(E) string
}

// runSearch runs a Query→Get(Entities) AgentWorks search: it builds the
// pagination params, runs the caller's query step, and — unless the filter was
// rejected or the result was empty — fetches full records for the matched IDs,
// restoring query order via keyFn. Pagination meta passes through on both the
// populated and empty paths.
func runSearch[E any](ctx context.Context, m *Module, op searchOp[E]) (base.SearchResult[E], error) {
	var zero base.SearchResult[E]
	limit := int64(op.limit)
	if limit <= 0 {
		limit = defaultSearchLimit
	}
	p := searchParams{Limit: &limit}
	if op.filter != "" {
		p.Filter = &op.filter
	}
	if op.offset != 0 {
		offset := int64(op.offset)
		p.Offset = &offset
	}
	if op.sort != "" {
		p.Sort = &op.sort
	}

	ids, meta, fqlErr, err := op.query(ctx, p)
	if err != nil {
		return zero, err
	}
	if fqlErr != nil {
		return base.FQLError[E](fqlErr, op.filter, op.fqlGuide), nil
	}
	if len(ids) == 0 {
		return base.Found([]E{}, op.filter).WithMeta(meta), nil
	}
	details, err := base.FetchDetails(ctx, base.FetchDetailsParams[E]{
		IDs:         ids,
		ChunkSize:   detailBatchSize,
		Concurrency: m.Concurrency,
		Progress:    base.ProgressFunc(ctx, op.req),
		Fetch:       op.fetch,
		KeyFn:       op.keyFn,
	})
	if err != nil {
		return zero, err
	}
	return base.Found(details, op.filter).WithMeta(meta), nil
}

// agentsFQLBadRequest classifies err as an agents FQL-filter rejection, returning
// the API error details when so. See fqlErrorDetails for why an FQL message is
// required beyond a bare 400.
func agentsFQLBadRequest(err error) ([]base.FQLErrorDetail, bool) {
	var badReq *agents.QueryAgentsV2BadRequest
	if !errors.As(err, &badReq) || badReq.Payload == nil {
		return nil, false
	}
	return fqlErrorDetails(badReq.Payload.Errors)
}

// agentVersionsFQLBadRequest classifies err as an agent-versions FQL-filter rejection.
func agentVersionsFQLBadRequest(err error) ([]base.FQLErrorDetail, bool) {
	var badReq *agent_versions.QueryAgentVersionsV1BadRequest
	if !errors.As(err, &badReq) || badReq.Payload == nil {
		return nil, false
	}
	return fqlErrorDetails(badReq.Payload.Errors)
}

// spansFQLBadRequest classifies err as a spans FQL-filter rejection.
func spansFQLBadRequest(err error) ([]base.FQLErrorDetail, bool) {
	var badReq *spans.QueriesSpansV1BadRequest
	if !errors.As(err, &badReq) || badReq.Payload == nil {
		return nil, false
	}
	return fqlErrorDetails(badReq.Payload.Errors)
}

// fqlErrorDetails converts API errors to detail form and reports whether at
// least one blames the filter. These query endpoints answer a rejected sort or
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

// SearchAgentsInput is the input for falcon_search_agentworks_agents.
type SearchAgentsInput struct {
	Filter string `json:"filter,omitempty" jsonschema:"FQL filter expression."`
	Limit  int    `json:"limit,omitempty" jsonschema:"Maximum number of agents to return (default: 100; max: 500)."`
	Offset int    `json:"offset,omitempty" jsonschema:"Starting index of overall result set from which to return agents."`
	Sort   string `json:"sort,omitempty" jsonschema:"Sort agents. Supported field: created_date. Ex: 'created_date|desc'."`
}

func (m *Module) searchAgents(ctx context.Context, req *mcp.CallToolRequest, in SearchAgentsInput) (*mcp.CallToolResult, base.SearchResult[*models.APIAgent], error) {
	m.Logger.Debug("search_agentworks_agents", "filter", in.Filter, "limit", in.Limit, "offset", in.Offset, "sort", in.Sort)
	res, err := runSearch(ctx, m, searchOp[*models.APIAgent]{
		req: req, filter: in.Filter, limit: in.Limit, offset: in.Offset, sort: in.Sort,
		fqlGuide: agentsFQLGuide,
		query: func(ctx context.Context, p searchParams) ([]string, *models.MsaMetaInfo, []base.FQLErrorDetail, error) {
			params := agents.NewQueryAgentsV2ParamsWithContext(ctx)
			params.Filter, params.Limit, params.Offset, params.Sort = p.Filter, p.Limit, p.Offset, p.Sort
			resp, qerr := m.Agents.QueryAgentsV2(params)
			if qerr != nil && in.Filter != "" {
				if details, ok := agentsFQLBadRequest(qerr); ok {
					return nil, nil, details, nil
				}
			}
			if e := base.APIError(qerr, resp, scopeAgentworksRead); e != nil {
				return nil, nil, nil, e
			}
			return resp.Payload.Resources, resp.Payload.Meta, nil, nil
		},
		fetch: func(ctx context.Context, chunk []string) ([]*models.APIAgent, error) {
			params := agents.NewGetAgentsV2ParamsWithContext(ctx)
			params.Ids = chunk
			resp, ferr := m.Agents.GetAgentsV2(params)
			if e := base.APIError(ferr, resp, scopeAgentworksRead); e != nil {
				return nil, e
			}
			return resp.Payload.Resources, nil
		},
		keyFn: func(a *models.APIAgent) string { return base.Deref(a.ID) },
	})
	return nil, res, err
}

// SearchAgentVersionsInput is the input for
// falcon_search_agentworks_agent_versions.
type SearchAgentVersionsInput struct {
	Filter string `json:"filter,omitempty" jsonschema:"FQL filter expression."`
	Limit  int    `json:"limit,omitempty" jsonschema:"Maximum number of agent versions to return (default: 100; max: 500)."`
	Offset int    `json:"offset,omitempty" jsonschema:"Starting index of overall result set from which to return versions."`
	Sort   string `json:"sort,omitempty" jsonschema:"Sort versions. Supported field: created_at. Ex: 'created_at|desc'."`
}

func (m *Module) searchAgentVersions(ctx context.Context, req *mcp.CallToolRequest, in SearchAgentVersionsInput) (*mcp.CallToolResult, base.SearchResult[*models.APIAgentVersion], error) {
	m.Logger.Debug("search_agentworks_agent_versions", "filter", in.Filter, "limit", in.Limit, "offset", in.Offset, "sort", in.Sort)
	res, err := runSearch(ctx, m, searchOp[*models.APIAgentVersion]{
		req: req, filter: in.Filter, limit: in.Limit, offset: in.Offset, sort: in.Sort,
		fqlGuide: agentVersionsFQLGuide,
		query: func(ctx context.Context, p searchParams) ([]string, *models.MsaMetaInfo, []base.FQLErrorDetail, error) {
			params := agent_versions.NewQueryAgentVersionsV1ParamsWithContext(ctx)
			params.Filter, params.Limit, params.Offset, params.Sort = p.Filter, p.Limit, p.Offset, p.Sort
			resp, qerr := m.AgentVersions.QueryAgentVersionsV1(params)
			if qerr != nil && in.Filter != "" {
				if details, ok := agentVersionsFQLBadRequest(qerr); ok {
					return nil, nil, details, nil
				}
			}
			if e := base.APIError(qerr, resp, scopeAgentworksRead); e != nil {
				return nil, nil, nil, e
			}
			return resp.Payload.Resources, resp.Payload.Meta, nil, nil
		},
		fetch: func(ctx context.Context, chunk []string) ([]*models.APIAgentVersion, error) {
			params := agent_versions.NewGetAgentVersionsV1ParamsWithContext(ctx)
			params.Ids = chunk
			resp, ferr := m.AgentVersions.GetAgentVersionsV1(params)
			if e := base.APIError(ferr, resp, scopeAgentworksRead); e != nil {
				return nil, e
			}
			return resp.Payload.Resources, nil
		},
		keyFn: func(v *models.APIAgentVersion) string { return base.Deref(v.ID) },
	})
	return nil, res, err
}

// SearchSpansInput is the input for falcon_search_agentworks_spans.
type SearchSpansInput struct {
	Filter string `json:"filter,omitempty" jsonschema:"FQL filter expression."`
	Limit  int    `json:"limit,omitempty" jsonschema:"Maximum number of spans to return (default: 100; max: 1000)."`
	Offset int    `json:"offset,omitempty" jsonschema:"Starting index of overall result set from which to return spans."`
	Sort   string `json:"sort,omitempty" jsonschema:"Sort spans. Supported field: start_time. Ex: 'start_time|desc'."`
}

func (m *Module) searchSpans(ctx context.Context, req *mcp.CallToolRequest, in SearchSpansInput) (*mcp.CallToolResult, base.SearchResult[*models.DomainSpan], error) {
	m.Logger.Debug("search_agentworks_spans", "filter", in.Filter, "limit", in.Limit, "offset", in.Offset, "sort", in.Sort)
	res, err := runSearch(ctx, m, searchOp[*models.DomainSpan]{
		req: req, filter: in.Filter, limit: in.Limit, offset: in.Offset, sort: in.Sort,
		fqlGuide: spansFQLGuide,
		query: func(ctx context.Context, p searchParams) ([]string, *models.MsaMetaInfo, []base.FQLErrorDetail, error) {
			params := spans.NewQueriesSpansV1ParamsWithContext(ctx)
			params.Filter, params.Limit, params.Offset, params.Sort = p.Filter, p.Limit, p.Offset, p.Sort
			resp, qerr := m.Spans.QueriesSpansV1(params)
			if qerr != nil && in.Filter != "" {
				if details, ok := spansFQLBadRequest(qerr); ok {
					return nil, nil, details, nil
				}
			}
			if e := base.APIError(qerr, resp, scopeAgentworksRead); e != nil {
				return nil, nil, nil, e
			}
			return resp.Payload.Resources, resp.Payload.Meta, nil, nil
		},
		fetch: func(ctx context.Context, chunk []string) ([]*models.DomainSpan, error) {
			params := spans.NewEntitiesSpansV1ParamsWithContext(ctx)
			params.Ids = chunk
			resp, ferr := m.Spans.EntitiesSpansV1(params)
			if e := base.APIError(ferr, resp, scopeAgentworksRead); e != nil {
				return nil, e
			}
			return resp.Payload.Resources, nil
		},
		keyFn: func(s *models.DomainSpan) string { return base.Deref(s.ID) },
	})
	return nil, res, err
}

// GetInvocationInput is the input for falcon_get_agentworks_agent_invocation.
type GetInvocationInput struct {
	ID string `json:"id" jsonschema:"The invocation ID to retrieve. Returned by falcon_invoke_agentworks_agent (including on timeout or a tool-approval pause)."`
}

func (m *Module) getInvocation(ctx context.Context, _ *mcp.CallToolRequest, in GetInvocationInput) (*mcp.CallToolResult, base.EntitiesResult[*models.APIAgentInvocationResponseResource], error) {
	var zero base.EntitiesResult[*models.APIAgentInvocationResponseResource]
	if in.ID == "" {
		return nil, zero, fmt.Errorf("%w: id must not be empty", base.ErrInvalidInput)
	}
	m.Logger.Debug("get_agentworks_agent_invocation", "id", in.ID)
	params := agent_invocation.NewGetAgentInvocationV3ParamsWithContext(ctx)
	params.ID = in.ID
	resp, err := m.AgentInvocation.GetAgentInvocationV3(params)
	if e := base.APIError(err, resp, scopeAgentworksRead); e != nil {
		return nil, zero, e
	}
	return nil, base.Entities(resp.Payload.Resources).WithMeta(resp.Payload.Meta), nil
}
