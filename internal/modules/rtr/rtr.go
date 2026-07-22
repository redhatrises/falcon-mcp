// Package rtr implements the eleven Real Time Response tools over the gofalcon
// real_time_response and real_time_response_audit clients: searching and
// aggregating sessions, initializing/pulsing/deleting sessions, executing
// read-only RTR commands, polling command status (including a wait-until-done
// convenience tool), and listing session files. It registers the two RTR FQL
// guides plus the aggregation and read-only investigation guides as resources.
//
// # Statelessness
//
// RTR is stateless from the server's point of view: session_id and
// cloud_request_id are opaque tokens Falcon mints and the client threads back on
// each call. The module holds no session map; every handler is a pure
// request/response passthrough, matching every other module. The one exception
// in shape — run_rtr_read_only_command_and_wait — runs an in-call poll loop
// whose state is local to the single invocation, not persisted.
//
// # Read-only enforcement is layered
//
// Safety comes from (1) endpoint selection and (2) a client-side base_command
// allowlist. This module wires only the RealTimeResponse and
// RealTimeResponseAudit sub-clients and only ever calls RTRExecuteCommand (the
// read-only command endpoint). It deliberately does NOT hold a
// RealTimeResponseAdmin field, so escalation to active-responder or admin
// endpoints is impossible without a code change that is obvious in review.
// Execute/wait tools also reject any base_command outside the Falcon read-only
// set (ls, ps, cat, filehash, reg, netstat, eventlog, …) before making a
// network call. The Falcon API additionally rejects non-read-only base commands
// on this endpoint.
package rtr

import (
	"encoding/json"
	"log/slog"

	"github.com/crowdstrike/gofalcon/falcon/client/real_time_response"
	"github.com/crowdstrike/gofalcon/falcon/client/real_time_response_audit"
	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/crowdstrike/falcon-mcp/internal/modules/base"
	"github.com/crowdstrike/falcon-mcp/internal/modules/registry"
)

// Factory builds the RTR module from shared deps. It wires only the read-only
// RealTimeResponse client and the audit client; it intentionally omits
// RealTimeResponseAdmin so the module cannot reach active-responder or admin
// command endpoints (see the package doc). The generated aggregator collects
// this Factory, so the module needs no init side effect.
var Factory registry.Factory = func(d registry.Deps) base.Module {
	return &Module{
		API:         d.API.RealTimeResponse,
		Audit:       d.API.RealTimeResponseAudit,
		Concurrency: d.Concurrency,
		Logger:      d.Logger,
	}
}

// sessionBatchSize is the maximum number of session IDs fetched per
// RTRListSessions details call in the search_rtr_sessions two-step.
const sessionBatchSize = 5000

// CrowdStrike API scopes required by this module's operations. Surfaced on a
// 403 via base.APIError, referenced directly at each call site. The read-only
// execute endpoint requires only :read even though the MCP tool is annotated
// mutating (the annotation and the API scope are orthogonal). RTRListFilesV2
// requires :write per the Falcon scope map, verified live.
var (
	scopeRTRRead  = base.Scope{Name: "Real time response", Read: true}
	scopeRTRWrite = base.Scope{Name: "Real time response", Write: true}
	scopeRTRAudit = base.Scope{Name: "real-time-response-audit", Read: true}
)

// rtrAPI is the minimal slice of the gofalcon real_time_response client this
// module consumes, declared next to its consumer so handlers can be tested
// against a small fake rather than all of gofalcon. It deliberately excludes
// every active-responder and admin operation.
type rtrAPI interface {
	RTRListAllSessions(*real_time_response.RTRListAllSessionsParams, ...real_time_response.ClientOption) (*real_time_response.RTRListAllSessionsOK, error)
	RTRListSessions(*real_time_response.RTRListSessionsParams, ...real_time_response.ClientOption) (*real_time_response.RTRListSessionsOK, error)
	RTRAggregateSessions(*real_time_response.RTRAggregateSessionsParams, ...real_time_response.ClientOption) (*real_time_response.RTRAggregateSessionsOK, error)
	RTRInitSession(*real_time_response.RTRInitSessionParams, ...real_time_response.ClientOption) (*real_time_response.RTRInitSessionCreated, error)
	RTRPulseSession(*real_time_response.RTRPulseSessionParams, ...real_time_response.ClientOption) (*real_time_response.RTRPulseSessionCreated, error)
	RTRExecuteCommand(*real_time_response.RTRExecuteCommandParams, ...real_time_response.ClientOption) (*real_time_response.RTRExecuteCommandCreated, error)
	RTRCheckCommandStatus(*real_time_response.RTRCheckCommandStatusParams, ...real_time_response.ClientOption) (*real_time_response.RTRCheckCommandStatusOK, error)
	RTRListFilesV2(*real_time_response.RTRListFilesV2Params, ...real_time_response.ClientOption) (*real_time_response.RTRListFilesV2OK, error)
	RTRDeleteSession(*real_time_response.RTRDeleteSessionParams, ...real_time_response.ClientOption) (*real_time_response.RTRDeleteSessionNoContent, error)
}

// rtrAuditAPI is the minimal slice of the gofalcon real_time_response_audit
// client this module consumes.
type rtrAuditAPI interface {
	RTRAuditSessions(*real_time_response_audit.RTRAuditSessionsParams, ...real_time_response_audit.ClientOption) (*real_time_response_audit.RTRAuditSessionsOK, error)
}

// Module registers the RTR tools. It holds only the shared, concurrency-safe
// Falcon clients and configuration; handlers are stateless and reentrant.
// Logger must be non-nil. It holds no RealTimeResponseAdmin client by design.
type Module struct {
	API         rtrAPI
	Audit       rtrAuditAPI
	Concurrency int // bounds concurrent detail fetches in search_rtr_sessions
	Logger      *slog.Logger
}

// Name reports the module name.
func (m *Module) Name() string { return "rtr" }

// Description reports a one-line summary of the module.
func (m *Module) Description() string {
	return "Audit, summarize, and run read-only RTR triage workflows"
}

// searchRTRSessionsSchema and searchRTRAuditSessionsSchema are the input schemas
// for the two RTR search tools. Each is inferred from its Input struct's tags,
// then a mutate func adds the limit bounds/default and offset minimum the tag
// syntax cannot express.
var (
	searchRTRSessionsSchema = base.SchemaFor[SearchSessionsInput](func(s *jsonschema.Schema) {
		s.Properties["limit"].Minimum = jsonschema.Ptr(1.0)
		s.Properties["limit"].Maximum = jsonschema.Ptr(5000.0)
		s.Properties["limit"].Default = json.RawMessage(`10`)
		s.Properties["offset"].Minimum = jsonschema.Ptr(0.0)
	})

	searchRTRAuditSessionsSchema = base.SchemaFor[SearchAuditSessionsInput](func(s *jsonschema.Schema) {
		s.Properties["limit"].Minimum = jsonschema.Ptr(1.0)
		s.Properties["limit"].Maximum = jsonschema.Ptr(1000.0)
		s.Properties["limit"].Default = json.RawMessage(`10`)
		s.Properties["offset"].Minimum = jsonschema.Ptr(0.0)
	})

	aggregateRTRSessionsSchema = base.SchemaFor[AggregateInput](func(s *jsonschema.Schema) {
		s.Properties["size"].Minimum = jsonschema.Ptr(1.0)
		s.Properties["size"].Maximum = jsonschema.Ptr(1000.0)
		s.Properties["size"].Default = json.RawMessage(`10`)
	})

	checkCommandStatusSchema = base.SchemaFor[CheckStatusInput](func(s *jsonschema.Schema) {
		s.Properties["sequence_id"].Minimum = jsonschema.Ptr(0.0)
	})

	initSessionSchema = base.SchemaFor[InitInput](func(s *jsonschema.Schema) {
		s.Properties["timeout"].Minimum = jsonschema.Ptr(1.0)
		s.Properties["timeout"].Maximum = jsonschema.Ptr(600.0)
	})

	waitSchema = base.SchemaFor[WaitInput](func(s *jsonschema.Schema) {
		s.Properties["timeout_seconds"].Minimum = jsonschema.Ptr(1.0)
		s.Properties["timeout_seconds"].Maximum = jsonschema.Ptr(600.0)
		s.Properties["timeout_seconds"].Default = json.RawMessage(`60`)
		s.Properties["poll_interval_seconds"].Minimum = jsonschema.Ptr(0.5)
		s.Properties["poll_interval_seconds"].Maximum = jsonschema.Ptr(30.0)
		s.Properties["poll_interval_seconds"].Default = json.RawMessage(`2`)
	})
)

// RegisterTools registers the eleven RTR tools into r. Read-only tools take the
// default annotations; init/pulse/execute/wait are mutating (they create RTR
// session/command activity); delete is destructive and idempotent.
func (m *Module) RegisterTools(r base.Registrar) {
	base.AddTool(r, &mcp.Tool{
		Name: "search_rtr_sessions",
		Description: "Search RTR sessions in your CrowdStrike environment by hostname, agent ID, user, " +
			"origin, or creation time. Consult falcon://rtr/sessions/search/fql-guide before " +
			"constructing filter expressions. Returns full session details including host info, " +
			"commands executed, and status.",
		InputSchema: searchRTRSessionsSchema,
	}, m.searchSessions)

	base.AddTool(r, &mcp.Tool{
		Name: "search_rtr_audit_sessions",
		Description: "Search RTR audit sessions for accountability and timeline evidence: who used RTR, " +
			"when, against which host, and optionally which command activity Falcon recorded. This is " +
			"read-only audit visibility; it does not open sessions or run commands. Consult " +
			"falcon://rtr/audit/sessions/search/fql-guide before constructing filter expressions.",
		InputSchema: searchRTRAuditSessionsSchema,
	}, m.searchAuditSessions)

	base.AddTool(r, &mcp.Tool{
		Name: "aggregate_rtr_sessions",
		Description: "Summarize RTR session activity with Falcon aggregation buckets. Use this before " +
			"detailed searches when the user asks which hosts, users, origins, commands, or time " +
			"windows account for RTR activity. Consult falcon://rtr/sessions/aggregate-guide. Returns " +
			"aggregation buckets, not individual session records.",
		InputSchema: aggregateRTRSessionsSchema,
	}, m.aggregateSessions)

	base.AddTool(r, &mcp.Tool{
		Name: "get_rtr_session_details",
		Description: "Retrieve full details for the given RTR session IDs. Use when you already have " +
			"session IDs from search results; to discover sessions by criteria use " +
			"falcon_search_rtr_sessions instead. Returns full session records.",
	}, m.getSessionDetails)

	base.AddTool(r, &mcp.Tool{
		Name: "init_rtr_session",
		Description: "Initialize or reuse an RTR session for a single host, opening a live connection " +
			"for executing read-only commands. Use queue_offline=true if the host may be offline. " +
			"Returns session records containing the session_id needed for subsequent commands.",
		InputSchema: initSessionSchema,
		Annotations: base.MutatingAnnotations(),
	}, m.initSession)

	base.AddTool(r, &mcp.Tool{
		Name: "pulse_rtr_session",
		Description: "Refresh an RTR session timeout for a single host, keeping an existing session " +
			"alive by resetting its inactivity timer. Use this to prevent session expiration during " +
			"long investigations.",
		Annotations: base.MutatingAnnotations(),
	}, m.pulseSession)

	base.AddTool(r, &mcp.Tool{
		Name: "execute_rtr_read_only_command",
		Description: "Execute a read-only RTR command on a single host. Client-side allowlist " +
			"enforces the Falcon read-only base_command set (ls, ps, cat, filehash, reg, netstat, " +
			"eventlog, and other read-only commands). Admin or remediation base commands are " +
			"rejected before any API call. " +
			"Returns command records containing a cloud_request_id for polling output via " +
			"falcon_check_rtr_command_status.",
		Annotations: base.MutatingAnnotations(),
	}, m.executeReadOnlyCommand)

	base.AddTool(r, &mcp.Tool{
		Name: "run_rtr_read_only_command_and_wait",
		Description: "Execute a read-only RTR command and poll until completion, accumulating output " +
			"chunks into one result. Use this for simple, focused evidence collection when you want " +
			"the command output directly and do not need to manage a cloud_request_id. Client-side " +
			"allowlist enforces Falcon read-only base commands; admin/remediation base commands are " +
			"rejected before any API call.",
		InputSchema: waitSchema,
		Annotations: base.MutatingAnnotations(),
	}, m.runReadOnlyCommandAndWait)

	base.AddTool(r, &mcp.Tool{
		Name: "check_rtr_command_status",
		Description: "Get the status and output for an RTR command execution. Poll this after " +
			"falcon_execute_rtr_read_only_command to retrieve command output; use sequence_id to " +
			"paginate through large output chunks. Returns status records with stdout, stderr, and " +
			"a complete flag.",
		InputSchema: checkCommandStatusSchema,
	}, m.checkCommandStatus)

	base.AddTool(r, &mcp.Tool{
		Name: "list_rtr_session_files",
		Description: "List files extracted during an RTR session, such as files pulled with the get " +
			"command. Returns file metadata for artifacts captured during the session.",
	}, m.listSessionFiles)

	base.AddTool(r, &mcp.Tool{
		Name: "delete_rtr_session",
		Description: "Close an RTR session and release the host connection. Use this when the " +
			"investigation is complete to free session resources. Idempotent.",
		Annotations: base.DestructiveAnnotations(true),
	}, m.deleteSession)
}

// RegisterResources publishes the two RTR FQL guides plus the aggregation and
// read-only investigation guides as MCP resources, mirroring falcon-mcp's RTR
// resource URIs 1:1.
func (m *Module) RegisterResources(s *mcp.Server) {
	base.TextResource(s,
		sessionsFQLGuideURI,
		"search_rtr_sessions_fql_guide",
		"Contains the guide for the `filter` param of the `falcon_search_rtr_sessions` tool.",
		"text/markdown",
		sessionsFQLGuide,
	)
	base.TextResource(s,
		auditFQLGuideURI,
		"search_rtr_audit_sessions_fql_guide",
		"Contains the guide for the `filter` param of the `falcon_search_rtr_audit_sessions` tool.",
		"text/markdown",
		auditFQLGuide,
	)
	base.TextResource(s,
		aggregateGuideURI,
		"aggregate_rtr_sessions_guide",
		"Explains how to summarize RTR session activity with the `falcon_aggregate_rtr_sessions` tool.",
		"text/markdown",
		aggregateGuide,
	)
	base.TextResource(s,
		investigationGuideURI,
		"rtr_read_only_investigation_guide",
		"Provides a safe read-only RTR workflow for endpoint investigation tools.",
		"text/markdown",
		investigationGuide,
	)
}

// RegisterPrompts is a no-op: the RTR module exposes no prompts.
func (m *Module) RegisterPrompts(_ *mcp.Server) {}
