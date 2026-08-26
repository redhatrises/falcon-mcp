package agentworks

import (
	"context"
	"fmt"
	"time"

	"github.com/crowdstrike/gofalcon/falcon/client/agent_invocation"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/crowdstrike/falcon-mcp/internal/modules/base"
)

// minDeadlineSeconds is the smallest server-side deadline the invoke API
// accepts; smaller values are rejected before the request is sent.
const minDeadlineSeconds = 90

// roleUser is the message role for the single prompt turn sent to an agent.
const roleUser = "user"

// Terminal invocation statuses the block-poll stops on. Any other status keeps
// polling until the deadline.
const (
	statusCompleted           = "completed"
	statusFailed              = "failed"
	statusWaitingToolApproval = "waiting_for_tool_approval"
)

// scopeAgentworksWrite is the CrowdStrike API scope required to invoke an agent.
// Surfaced on a 403 via base.APIError.
var scopeAgentworksWrite = base.Scope{Name: "Charlotte AI Agent Definition", Read: true, Write: true}

// invokeDescription is the tool description for falcon_invoke_agentworks_agent,
// kept 1:1 with the Python falcon-mcp module.
const invokeDescription = `Invoke an AgentWorks (Charlotte AI) agent and return its reply.

Use this to actually run an agent on a prompt: it invokes the agent's published version, or a specific version when you pass version_id. This is asynchronous and spends credits — it starts the run and blocks, polling until the agent finishes (timeout FALCON_MCP_AGENTWORKS_TIMEOUT, default 45s, kept under the MCP client request timeout). Returns the invocation id, status, conversation, and ai_trace_id — feed ai_trace_id to falcon_search_agentworks_spans to observe the run. If the run pauses for tool approval (approving a tool is not supported) or exceeds the timeout, it returns the id and status so you can resume or observe the run with falcon_get_agentworks_agent_invocation; the run continues server-side either way.`

// invokeSchema is the input schema for falcon_invoke_agentworks_agent. It is
// inferred from InvokeInput, then a mutate func adds the numeric bounds the tag
// syntax cannot express: deadline_seconds must be at least the API minimum, and
// credit_cents_limit must be positive to act as a cap.
var invokeSchema = base.SchemaFor[InvokeInput](func(s *jsonschema.Schema) {
	s.Properties["deadline_seconds"].Minimum = jsonschema.Ptr(float64(minDeadlineSeconds))
	s.Properties["credit_cents_limit"].Minimum = jsonschema.Ptr(1.0)
})

// InvokeInput is the input for falcon_invoke_agentworks_agent.
type InvokeInput struct {
	Prompt           string `json:"prompt" jsonschema:"The user message to send to the agent."`
	AgentID          string `json:"agent_id" jsonschema:"ID of the agent to invoke. Find IDs with falcon_search_agentworks_agents."`
	VersionID        string `json:"version_id,omitempty" jsonschema:"Optional ID of a specific agent version to invoke, for testing a version that is not published. Omit to invoke the agent's published version. Find version IDs with falcon_search_agentworks_agent_versions."`
	DeadlineSeconds  int32  `json:"deadline_seconds,omitempty" jsonschema:"Optional server-side deadline for the run, in seconds. Must be at least 90 (the API rejects smaller values)."`
	CreditCentsLimit int32  `json:"credit_cents_limit,omitempty" jsonschema:"Optional cap on credits (in cents) the run may spend."`
}

// InvokeResult is the output of falcon_invoke_agentworks_agent: the invocation
// id, its status, and the trace id are always present; the conversation and the
// status-specific hint/note/timeout fields appear only when relevant.
type InvokeResult struct {
	ID             string               `json:"id"`
	Status         string               `json:"status"`
	AiTraceID      string               `json:"ai_trace_id"`
	Conversation   []*models.APIMessage `json:"conversation,omitempty"`
	Hint           string               `json:"hint,omitempty"`
	Note           string               `json:"note,omitempty"`
	TimeoutSeconds int                  `json:"timeout_seconds,omitempty"`
}

// invokeAgent runs an agent on a prompt and blocks, polling the invocation until
// it reaches a terminal status (completed/failed/waiting_for_tool_approval), the
// configured timeout elapses, or the caller's context is cancelled. The run
// always continues server-side; the returned id lets the caller resume or
// observe it via falcon_get_agentworks_agent_invocation.
func (m *Module) invokeAgent(ctx context.Context, req *mcp.CallToolRequest, in InvokeInput) (*mcp.CallToolResult, InvokeResult, error) {
	var zero InvokeResult
	if in.Prompt == "" {
		return nil, zero, fmt.Errorf("%w: prompt must not be empty", base.ErrInvalidInput)
	}
	if in.AgentID == "" {
		return nil, zero, fmt.Errorf("%w: agent_id must not be empty", base.ErrInvalidInput)
	}
	if in.DeadlineSeconds != 0 && in.DeadlineSeconds < minDeadlineSeconds {
		return nil, zero, fmt.Errorf("%w: deadline_seconds must be at least %d", base.ErrInvalidInput, minDeadlineSeconds)
	}
	m.Logger.Debug("invoke_agentworks_agent",
		"agent_id", in.AgentID,
		"version_id", in.VersionID,
		"has_deadline", in.DeadlineSeconds != 0,
		"has_credit_limit", in.CreditCentsLimit != 0)

	// Start the run. The initial response carries the invocation id and the trace
	// id (present here while status is processing; a later poll may report it as
	// null once the run completes), so capture the trace id now and reuse it.
	resources, err := m.invoke(ctx, in)
	if err != nil {
		return nil, zero, err
	}
	if len(resources) == 0 || resources[0] == nil {
		return nil, zero, fmt.Errorf("%w: no invocation returned", errUnexpectedResponse)
	}
	invID := resources[0].ID
	if invID == "" {
		return nil, zero, fmt.Errorf("%w: invocation returned without an id", errUnexpectedResponse)
	}
	aiTraceID := resources[0].AiTraceID

	return nil, m.poll(ctx, pollState{
		invID:     invID,
		aiTraceID: aiTraceID,
		progress:  base.ProgressFunc(ctx, req),
	}), nil
}

// invoke dispatches the initial invocation: an empty version_id runs the agent's
// published version, otherwise the given version. The single prompt maps to one
// user message. Optional deadline/credit caps are sent only when set.
func (m *Module) invoke(ctx context.Context, in InvokeInput) ([]*models.APIAgentInvocationResponseResource, error) {
	messages := []*models.APIMessage{{Role: new(roleUser), Content: &in.Prompt}}

	if in.VersionID == "" {
		body := &models.APIInvokePublishedAgentExternalRequest{ID: &in.AgentID, Messages: messages}
		if in.CreditCentsLimit != 0 {
			body.CreditCentsLimit = in.CreditCentsLimit
		}
		if in.DeadlineSeconds != 0 {
			body.DeadlineSeconds = in.DeadlineSeconds
		}
		params := agent_invocation.NewInvokePublishedAgentExternalV1ParamsWithContext(ctx)
		params.Body = body
		resp, err := m.AgentInvocation.InvokePublishedAgentExternalV1(params)
		if e := base.APIError(err, resp, scopeAgentworksWrite); e != nil {
			return nil, e
		}
		return resp.Payload.Resources, nil
	}

	body := &models.APIInvokeAgentVersionExternalRequest{ID: &in.AgentID, VersionID: &in.VersionID, Messages: messages}
	if in.CreditCentsLimit != 0 {
		body.CreditCentsLimit = in.CreditCentsLimit
	}
	if in.DeadlineSeconds != 0 {
		body.DeadlineSeconds = in.DeadlineSeconds
	}
	params := agent_invocation.NewInvokeAgentVersionExternalV1ParamsWithContext(ctx)
	params.Body = body
	resp, err := m.AgentInvocation.InvokeAgentVersionExternalV1(params)
	if e := base.APIError(err, resp, scopeAgentworksWrite); e != nil {
		return nil, e
	}
	return resp.Payload.Resources, nil
}

// pollState carries the immutable identifiers and liveness callback the block-poll
// needs across iterations: the invocation id, the trace id captured at invoke
// time, and a progress callback that is nil unless the client requested progress.
type pollState struct {
	invID     string
	aiTraceID string
	progress  func(done, total int)
}

// poll blocks until the invocation reaches a terminal status, the timeout
// elapses, or the caller's context is cancelled, sleeping PollInterval between
// checks. A child context folds the timeout and caller cancellation into one
// signal. The result always reports the id, status, and captured trace id.
func (m *Module) poll(ctx context.Context, p pollState) InvokeResult {
	pollCtx, cancel := context.WithTimeout(ctx, m.Timeout)
	defer cancel()

	ticker := time.NewTicker(m.PollInterval)
	defer ticker.Stop()

	lastStatus := ""
	attempts := 0
	for {
		// Sleep before the first poll: the initial invoke already reported the
		// starting status, so an immediate re-check would be wasted.
		select {
		case <-pollCtx.Done():
			return m.timeoutResult(p, lastStatus)
		case <-ticker.C:
		}

		// Emit a liveness heartbeat before each check. Total is 0 (unknown) since a
		// block-poll has no bounded step count; the callback is a no-op unless the
		// client opted in with a progress token.
		attempts++
		if p.progress != nil {
			p.progress(attempts, 0)
		}

		resources, err := m.pollInvocation(pollCtx, p.invID)
		if err != nil {
			// A deadline/cancel mid-request surfaces as a transport error; report a
			// timeout with the last known status rather than a hard error.
			if pollCtx.Err() != nil {
				return m.timeoutResult(p, lastStatus)
			}
			return InvokeResult{ID: p.invID, Status: "error", AiTraceID: p.aiTraceID, Note: err.Error()}
		}

		status := ""
		var conversation []*models.APIMessage
		if len(resources) > 0 && resources[0] != nil {
			status = resources[0].Status
			conversation = resources[0].Conversation
		}
		lastStatus = status

		switch status {
		case statusCompleted:
			return InvokeResult{
				ID:           p.invID,
				Status:       status,
				AiTraceID:    p.aiTraceID,
				Conversation: conversation,
				Hint:         "Pass ai_trace_id as trace_id to falcon_search_agentworks_spans to see this run's spans.",
			}
		case statusFailed:
			return InvokeResult{
				ID:           p.invID,
				Status:       status,
				AiTraceID:    p.aiTraceID,
				Conversation: conversation,
			}
		case statusWaitingToolApproval:
			return InvokeResult{
				ID:        p.invID,
				Status:    status,
				AiTraceID: p.aiTraceID,
				Note:      "Invocation is paused waiting for tool approval. Approving a tool is not supported; observe the run via falcon_get_agentworks_agent_invocation.",
			}
		}
	}
}

// timeoutResult builds the InvokeResult returned when the block-poll deadline
// elapses before the run reaches a terminal status.
func (m *Module) timeoutResult(p pollState, lastStatus string) InvokeResult {
	timeoutSeconds := int(m.Timeout / time.Second)
	status := lastStatus
	if status == "" {
		status = "unknown"
	}
	return InvokeResult{
		ID:             p.invID,
		Status:         status,
		AiTraceID:      p.aiTraceID,
		TimeoutSeconds: timeoutSeconds,
		Note:           fmt.Sprintf("Invocation still running after %ds; it continues server-side. Resume/observe via falcon_get_agentworks_agent_invocation with this id.", timeoutSeconds),
	}
}

// pollInvocation fetches the current state of an invocation by id.
func (m *Module) pollInvocation(ctx context.Context, id string) ([]*models.APIAgentInvocationResponseResource, error) {
	params := agent_invocation.NewGetAgentInvocationV3ParamsWithContext(ctx)
	params.ID = id
	resp, err := m.AgentInvocation.GetAgentInvocationV3(params)
	if e := base.APIError(err, resp, scopeAgentworksRead); e != nil {
		return nil, e
	}
	return resp.Payload.Resources, nil
}
