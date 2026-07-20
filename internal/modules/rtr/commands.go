package rtr

import (
	"context"
	"strings"
	"time"

	"github.com/crowdstrike/gofalcon/falcon/client/real_time_response"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/crowdstrike/falcon-mcp/internal/modules/base"
)

// Wait-tool defaults, matching the Python module's field defaults.
const (
	defaultWaitTimeout  = 60 * time.Second
	defaultPollInterval = 2 * time.Second
)

// ExecuteInput is the input for falcon_execute_rtr_read_only_command.
type ExecuteInput struct {
	SessionID     string `json:"session_id" jsonschema:"RTR session ID from falcon_init_rtr_session or falcon_search_rtr_sessions (required)"`
	BaseCommand   string `json:"base_command" jsonschema:"read-only RTR base command such as ls, ps, cat, filehash, or reg (required)"`
	CommandString string `json:"command_string,omitempty" jsonschema:"optional full command line to execute (e.g. cat C:\\Windows\\win.ini)"`
	Persist       bool   `json:"persist,omitempty" jsonschema:"persist the read-only command in the RTR session history"`
}

func (m *Module) executeReadOnlyCommand(ctx context.Context, _ *mcp.CallToolRequest, in ExecuteInput) (*mcp.CallToolResult, base.EntitiesResult[*models.DomainCommandExecuteResponse], error) {
	var zero base.EntitiesResult[*models.DomainCommandExecuteResponse]
	if err := in.validate(); err != nil {
		return nil, zero, err
	}
	m.Logger.Debug("execute_rtr_read_only_command", "session_id", in.SessionID, "base_command", in.BaseCommand, "persist", in.Persist)

	resp, err := m.execute(ctx, in)
	if e := base.APIError(err, resp, scopeRTRRead); e != nil {
		return nil, zero, e
	}
	return nil, base.Entities(resp.Payload.Resources).WithMeta(resp.Payload.Meta), nil
}

// validate enforces the client-side constraints shared by execute and wait.
func (in ExecuteInput) validate() error {
	if in.SessionID == "" {
		return wrapInvalid("execute rtr read-only command", "session_id must not be empty")
	}
	if in.BaseCommand == "" {
		return wrapInvalid("execute rtr read-only command", "base_command must not be empty")
	}
	return nil
}

// execute issues the read-only RTRExecuteCommand request shared by the execute
// and wait tools. It returns the raw gofalcon response and error so each caller
// funnels through base.APIError with its own return shape.
func (m *Module) execute(ctx context.Context, in ExecuteInput) (*real_time_response.RTRExecuteCommandCreated, error) {
	params := real_time_response.NewRTRExecuteCommandParamsWithContext(ctx)
	body := &models.DomainCommandExecuteRequest{
		SessionID:   &in.SessionID,
		BaseCommand: &in.BaseCommand,
		Persist:     &in.Persist,
	}
	if in.CommandString != "" {
		body.CommandString = &in.CommandString
	}
	params.Body = body
	return m.API.RTRExecuteCommand(params)
}

// CheckStatusInput is the input for falcon_check_rtr_command_status.
type CheckStatusInput struct {
	CloudRequestID string `json:"cloud_request_id" jsonschema:"cloud request ID from falcon_execute_rtr_read_only_command (required)"`
	SequenceID     int    `json:"sequence_id,omitempty" jsonschema:"sequence chunk to retrieve for command output; starts at 0"`
}

func (m *Module) checkCommandStatus(ctx context.Context, _ *mcp.CallToolRequest, in CheckStatusInput) (*mcp.CallToolResult, base.EntitiesResult[*models.DomainStatusResponse], error) {
	var zero base.EntitiesResult[*models.DomainStatusResponse]
	if in.CloudRequestID == "" {
		return nil, zero, wrapInvalid("check rtr command status", "cloud_request_id must not be empty")
	}
	m.Logger.Debug("check_rtr_command_status", "cloud_request_id", in.CloudRequestID, "sequence_id", in.SequenceID)

	resp, err := m.checkStatus(ctx, in.CloudRequestID, int64(in.SequenceID))
	if e := base.APIError(err, resp, scopeRTRRead); e != nil {
		return nil, zero, e
	}
	return nil, base.Entities(resp.Payload.Resources).WithMeta(resp.Payload.Meta), nil
}

// checkStatus issues one RTRCheckCommandStatus request shared by the check and
// wait tools.
func (m *Module) checkStatus(ctx context.Context, cloudRequestID string, sequenceID int64) (*real_time_response.RTRCheckCommandStatusOK, error) {
	params := real_time_response.NewRTRCheckCommandStatusParamsWithContext(ctx)
	params.CloudRequestID = cloudRequestID
	params.SequenceID = sequenceID
	return m.API.RTRCheckCommandStatus(params)
}

// WaitInput is the input for falcon_run_rtr_read_only_command_and_wait. It
// extends ExecuteInput with poll timing controls.
type WaitInput struct {
	SessionID           string  `json:"session_id" jsonschema:"RTR session ID from falcon_init_rtr_session or falcon_search_rtr_sessions (required)"`
	BaseCommand         string  `json:"base_command" jsonschema:"read-only RTR base command such as ls, ps, cat, filehash, or reg (required)"`
	CommandString       string  `json:"command_string,omitempty" jsonschema:"optional full command line to execute (e.g. cat C:\\Windows\\win.ini)"`
	Persist             bool    `json:"persist,omitempty" jsonschema:"persist the read-only command in the RTR session history"`
	TimeoutSeconds      int     `json:"timeout_seconds,omitempty" jsonschema:"maximum time to wait for command completion in seconds (max 600, default 60)"`
	PollIntervalSeconds float64 `json:"poll_interval_seconds,omitempty" jsonschema:"seconds to wait between command status checks (0.5-30, default 2)"`
}

// WaitResult is the combined output of falcon_run_rtr_read_only_command_and_wait,
// mirroring the Python module's dict: the execution record, the accumulated
// status chunks, aggregated stdout/stderr, and completion/timeout flags.
type WaitResult struct {
	CloudRequestID string                               `json:"cloud_request_id"`
	Complete       bool                                 `json:"complete"`
	TimedOut       bool                                 `json:"timed_out"`
	Execution      *models.DomainCommandExecuteResponse `json:"execution"`
	Status         []*models.DomainStatusResponse       `json:"status"`
	Stdout         string                               `json:"stdout"`
	Stderr         string                               `json:"stderr"`
	Warning        string                               `json:"warning,omitempty"`
}

func (m *Module) runReadOnlyCommandAndWait(ctx context.Context, req *mcp.CallToolRequest, in WaitInput) (*mcp.CallToolResult, WaitResult, error) {
	var zero WaitResult
	exec := ExecuteInput{SessionID: in.SessionID, BaseCommand: in.BaseCommand, CommandString: in.CommandString, Persist: in.Persist}
	if err := exec.validate(); err != nil {
		return nil, zero, err
	}

	timeout := defaultWaitTimeout
	if in.TimeoutSeconds > 0 {
		// Guard against a non-positive value bypassing the schema's 1..600 bound,
		// which would make the deadline already-expired and maxPolls <= 0 below.
		timeout = time.Duration(in.TimeoutSeconds) * time.Second
	}
	pollInterval := defaultPollInterval
	if in.PollIntervalSeconds > 0 {
		// The schema bounds this to 0.5..30, but that is enforced only at the
		// transport boundary; guard here so a non-positive or sub-nanosecond value
		// that bypasses schema validation cannot panic time.NewTicker (d <= 0).
		if d := time.Duration(in.PollIntervalSeconds * float64(time.Second)); d > 0 {
			pollInterval = d
		}
	}
	m.Logger.Debug("run_rtr_read_only_command_and_wait", "session_id", in.SessionID, "base_command", in.BaseCommand, "timeout", timeout, "poll_interval", pollInterval)

	// Step 1: execute the read-only command, extracting the cloud_request_id.
	execResp, err := m.execute(ctx, exec)
	if e := base.APIError(err, execResp, scopeRTRRead); e != nil {
		return nil, zero, e
	}
	if len(execResp.Payload.Resources) == 0 {
		return nil, zero, wrapInvalid("run rtr read-only command and wait", "command execution did not return a command request")
	}
	execution := execResp.Payload.Resources[0]
	if execution == nil || execution.CloudRequestID == nil || *execution.CloudRequestID == "" {
		return nil, zero, wrapInvalid("run rtr read-only command and wait", "command execution did not return a cloud_request_id")
	}
	cloudRequestID := *execution.CloudRequestID

	// Step 2: poll until any chunk reports complete, the deadline passes, or the
	// caller's context is cancelled. A child context folds timeout_seconds and
	// caller cancellation into one signal so a single select handles both.
	pollCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	progress := base.ProgressFunc(ctx, req)

	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	// maxPolls estimates the worst-case poll count (deadline / interval) so
	// progress notifications carry a meaningful moving fraction rather than the
	// always-100% (n, n) a naive counter would send. It is a ceiling, at least 1.
	maxPolls := int(timeout/pollInterval) + 1

	var chunks []*models.DomainStatusResponse
	var sequenceID int64
	polls := 0

	for {
		statusResp, sErr := m.checkStatus(pollCtx, cloudRequestID, sequenceID)
		if e := base.APIError(sErr, statusResp, scopeRTRRead); e != nil {
			// A deadline/cancel mid-request surfaces as a transport error; treat it
			// as a timeout with whatever was accumulated rather than a hard error.
			if pollCtx.Err() != nil {
				return nil, timedOutResult(cloudRequestID, execution, chunks), nil
			}
			return nil, zero, e
		}
		chunks = append(chunks, statusResp.Payload.Resources...)
		polls++
		if progress != nil {
			// Clamp done to total so a longer-than-estimated wait never reports >100%.
			done := polls
			if done > maxPolls {
				done = maxPolls
			}
			progress(done, maxPolls)
		}

		if anyComplete(chunks) {
			return nil, completeResult(cloudRequestID, execution, chunks), nil
		}
		// Advance to the last chunk's sequence_id to page further output.
		if n := len(chunks); n > 0 {
			sequenceID = chunks[n-1].SequenceID
		}

		select {
		case <-pollCtx.Done():
			return nil, timedOutResult(cloudRequestID, execution, chunks), nil
		case <-ticker.C:
		}
	}
}

// anyComplete reports whether any status chunk has Complete set true.
func anyComplete(chunks []*models.DomainStatusResponse) bool {
	for _, c := range chunks {
		if c != nil && c.Complete != nil && *c.Complete {
			return true
		}
	}
	return false
}

// completeResult builds the success WaitResult from the accumulated chunks.
func completeResult(cloudRequestID string, execution *models.DomainCommandExecuteResponse, chunks []*models.DomainStatusResponse) WaitResult {
	stdout, stderr := aggregateOutput(chunks)
	return WaitResult{
		CloudRequestID: cloudRequestID,
		Complete:       true,
		TimedOut:       false,
		Execution:      execution,
		Status:         normalizeChunks(chunks),
		Stdout:         stdout,
		Stderr:         stderr,
	}
}

// timedOutResult builds the timed-out WaitResult from the accumulated chunks.
func timedOutResult(cloudRequestID string, execution *models.DomainCommandExecuteResponse, chunks []*models.DomainStatusResponse) WaitResult {
	stdout, stderr := aggregateOutput(chunks)
	return WaitResult{
		CloudRequestID: cloudRequestID,
		Complete:       false,
		TimedOut:       true,
		Execution:      execution,
		Status:         normalizeChunks(chunks),
		Stdout:         stdout,
		Stderr:         stderr,
		Warning:        "Timed out waiting for RTR command completion.",
	}
}

// aggregateOutput concatenates the stdout and stderr across all status chunks,
// matching the Python module's join semantics.
func aggregateOutput(chunks []*models.DomainStatusResponse) (string, string) {
	var stdout, stderr strings.Builder
	for _, c := range chunks {
		if c == nil {
			continue
		}
		if c.Stdout != nil {
			stdout.WriteString(*c.Stdout)
		}
		if c.Stderr != nil {
			stderr.WriteString(*c.Stderr)
		}
	}
	return stdout.String(), stderr.String()
}

// normalizeChunks returns a non-nil slice so the status field marshals as a
// JSON array even when no chunks were collected.
func normalizeChunks(chunks []*models.DomainStatusResponse) []*models.DomainStatusResponse {
	if chunks == nil {
		return []*models.DomainStatusResponse{}
	}
	return chunks
}
