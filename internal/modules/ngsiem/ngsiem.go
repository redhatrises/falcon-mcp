// Package ngsiem implements the falcon_search_ngsiem tool over the gofalcon
// ngsiem client. Unlike the FQL search modules, this tool drives CrowdStrike's
// asynchronous job-based Next-Gen SIEM search API: it starts a CQL query job
// (StartSearchV1), polls the job to completion (GetSearchStatusV1), and returns
// the matching event records. On timeout it stops the job (StopSearchV1) and
// returns an error. The tool is read-only in intent but requires both
// NGSIEM:read and NGSIEM:write because starting and stopping a query job are
// mutating verbs.
//
// The CQL query, start, and end are supplied by the caller; this tool does not
// construct queries and has no FQL guide (NGSIEM uses CQL, not FQL). The Falcon
// API expects the job's start/end times as epoch-millisecond strings, so the
// handler converts the caller's ISO 8601 timestamps before submitting.
package ngsiem

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"time"

	"github.com/crowdstrike/gofalcon/falcon/client/ngsiem"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/crowdstrike/falcon-mcp/internal/modules/base"
	"github.com/crowdstrike/falcon-mcp/internal/modules/registry"
)

// defaultRepository is the NGSIEM repository searched when the caller omits one,
// mirroring the Python falcon-mcp ngsiem module's default of "search-all".
const defaultRepository = "search-all"

// Polling defaults and their environment overrides, mirroring the Python
// falcon-mcp ngsiem module. FALCON_MCP_NGSIEM_POLL_INTERVAL sets the delay
// between job-status polls; FALCON_MCP_NGSIEM_TIMEOUT bounds the total time the
// handler waits for a job to finish before stopping it.
const (
	defaultPollInterval = 5 * time.Second
	defaultTimeout      = 300 * time.Second

	envPollInterval = "FALCON_MCP_NGSIEM_POLL_INTERVAL"
	envTimeout      = "FALCON_MCP_NGSIEM_TIMEOUT"
)

// scopeNGSIEM is the CrowdStrike API scope required by this module's operations.
// Both read and write are required: StartSearchV1 and StopSearchV1 are mutating
// verbs even though the tool only reads events. Surfaced on a 403 via
// base.APIError.
var scopeNGSIEM = base.Scope{Name: "NGSIEM", Read: true, Write: true}

// errSearch classifies non-API failures of the search job (a start response
// with no job id, or a poll timeout) so the handler returns a descriptive Go
// error rather than a bare API error.
var errSearch = errors.New("ngsiem: search failed")

// Factory builds the ngsiem module from shared deps. The generated aggregator
// (internal/mcpserver) collects it, so the module needs no init side effect. The
// polling interval and timeout are read from the environment here (the module's
// only operational knobs, matching the Python module) rather than threaded
// through the central config, since no other module needs them. This is a
// single job-based query, so the module ignores Deps.Concurrency.
var Factory registry.Factory = func(d registry.Deps) base.Module {
	return &Module{
		API:          d.API.Ngsiem,
		Logger:       d.Logger,
		PollInterval: durationFromEnv(envPollInterval, defaultPollInterval),
		Timeout:      durationFromEnv(envTimeout, defaultTimeout),
	}
}

// durationFromEnv reads a whole-seconds duration from the named environment
// variable, falling back to def when the variable is unset, unparseable, or not
// a positive integer. It mirrors the Python module's int(os.environ.get(...))
// with a safe default.
func durationFromEnv(name string, def time.Duration) time.Duration {
	v, ok := os.LookupEnv(name)
	if !ok {
		return def
	}
	secs, err := strconv.Atoi(v)
	if err != nil || secs <= 0 {
		return def
	}
	return time.Duration(secs) * time.Second
}

// ngsiemAPI is the minimal slice of the gofalcon ngsiem client this module
// consumes, declared next to its consumer so handlers can be tested with a fake.
type ngsiemAPI interface {
	StartSearchV1(params *ngsiem.StartSearchV1Params, opts ...ngsiem.ClientOption) (*ngsiem.StartSearchV1OK, error)
	GetSearchStatusV1(params *ngsiem.GetSearchStatusV1Params, opts ...ngsiem.ClientOption) (*ngsiem.GetSearchStatusV1OK, error)
	StopSearchV1(params *ngsiem.StopSearchV1Params, opts ...ngsiem.ClientOption) (*ngsiem.StopSearchV1OK, error)
}

// Module registers the ngsiem tool. It holds the shared, concurrency-safe Falcon
// client plus the polling configuration; handlers are stateless and reentrant.
// Logger must be non-nil. PollInterval and Timeout must be positive (the Factory
// guarantees this); tests set small values to keep the poll loop fast.
type Module struct {
	API          ngsiemAPI
	Logger       *slog.Logger
	PollInterval time.Duration
	Timeout      time.Duration
}

// Name reports the module name.
func (m *Module) Name() string { return "ngsiem" }

// Description reports a one-line summary of the module.
func (m *Module) Description() string {
	return "Run search queries against CrowdStrike Next-Gen SIEM"
}

// searchNGSIEMDescription mirrors the Python falcon-mcp ngsiem module's tool
// docstring 1:1 for client compatibility.
const searchNGSIEMDescription = "Execute a CQL query against CrowdStrike Next-Gen SIEM.\n\n" +
	"Use this to search security events, logs, and telemetry; callers must supply\n" +
	"a complete, valid CQL query — this tool does not assist with query construction.\n" +
	"Returns matching event records, or an error dict if the job fails or times out.\n" +
	"Search times out after FALCON_MCP_NGSIEM_TIMEOUT seconds (default: 300)."

// RegisterTools registers the ngsiem tool into r.
func (m *Module) RegisterTools(r base.Registrar) {
	searchTool := &mcp.Tool{
		Name:        "search_ngsiem",
		Description: searchNGSIEMDescription,
	}
	base.AddTool(r, searchTool, m.searchNGSIEM)
}

// RegisterResources is a no-op: NGSIEM uses CQL, not FQL, so there is no filter
// guide to publish (the Python module registers no resources either).
func (m *Module) RegisterResources(_ *mcp.Server) {}

// RegisterPrompts is a no-op: the ngsiem module exposes no prompts.
func (m *Module) RegisterPrompts(_ *mcp.Server) {}

// SearchInput is the input for falcon_search_ngsiem. The json tags use the same
// snake_case names as the Python module so existing clients stay compatible; the
// served schema is inferred from these jsonschema tags. QueryString and Start
// are required; the handler validates them and the timestamp format.
type SearchInput struct {
	QueryString string `json:"query_string" jsonschema:"The CQL query string to execute. This tool executes pre-written CQL queries - it does NOT help construct queries. Users must provide a complete valid CQL query. Example: '#event_simpleName=ProcessRollup2' or 'source=firewall | count()'"`
	Start       string `json:"start" jsonschema:"Search start time as an ISO 8601 timestamp (REQUIRED format). Example: start='2025-01-01T00:00:00Z'"`
	Repository  string `json:"repository,omitempty" jsonschema:"Repository to search. Valid options: search-all (default - all event data) investigate_view (endpoint events) third-party (third-party source events) falcon_for_it_view (Falcon for IT data) forensics_view (Falcon Forensics triage data)"`
	End         string `json:"end,omitempty" jsonschema:"Search end time as an ISO 8601 timestamp. If not provided defaults to the current time. Example: end='2025-02-06T00:00:00Z'"`
}

// searchNGSIEM starts a CQL query job, polls it to completion, and returns the
// matching event records. On an API failure it returns a *base.Error (with scope
// hints on a 403); on a job that never returns an id or that exceeds the poll
// timeout it returns an errSearch-wrapped error, stopping the job first on
// timeout. Events are arbitrary JSON objects, so they are carried as any.
func (m *Module) searchNGSIEM(ctx context.Context, _ *mcp.CallToolRequest, in SearchInput) (*mcp.CallToolResult, base.EntitiesResult[any], error) {
	var zero base.EntitiesResult[any]

	if in.QueryString == "" {
		return nil, zero, fmt.Errorf("%w: query_string is required", errSearch)
	}
	startMS, err := isoToEpochMS(in.Start)
	if err != nil {
		return nil, zero, fmt.Errorf("%w: invalid start timestamp %q: %w", errSearch, in.Start, err)
	}

	repository := in.Repository
	if repository == "" {
		repository = defaultRepository
	}

	// Step 1: start the search job. The API expects epoch-millisecond strings for
	// start/end (live-verified), not the ISO 8601 the caller supplies.
	body := &models.APIQueryJobInput{
		QueryString: &in.QueryString,
		Start:       startMS,
	}
	if in.End != "" {
		endMS, err := isoToEpochMS(in.End)
		if err != nil {
			return nil, zero, fmt.Errorf("%w: invalid end timestamp %q: %w", errSearch, in.End, err)
		}
		body.End = endMS
	}

	m.Logger.Debug("search_ngsiem starting", "query_string", in.QueryString, "repository", repository)

	startParams := ngsiem.NewStartSearchV1ParamsWithContext(ctx)
	startParams.Repository = repository
	startParams.Body = body

	startResp, err := m.API.StartSearchV1(startParams)
	if e := base.APIError(err, startResp, scopeNGSIEM); e != nil {
		return nil, zero, e
	}

	jobID := ""
	if startResp.Payload != nil && startResp.Payload.ID != nil {
		jobID = *startResp.Payload.ID
	}
	if jobID == "" {
		return nil, zero, fmt.Errorf("%w: start response contained no job id", errSearch)
	}

	m.Logger.Debug("search_ngsiem job started", "job_id", jobID)

	// Step 2: poll for completion, sleeping between polls, until the job reports
	// done or the cumulative wait reaches the timeout. Mirrors the Python module's
	// sleep-then-poll loop; ctx cancellation is honored during the sleep.
	elapsed := time.Duration(0)
	for elapsed < m.Timeout {
		select {
		case <-ctx.Done():
			return nil, zero, ctx.Err()
		case <-time.After(m.PollInterval):
		}
		elapsed += m.PollInterval

		pollParams := ngsiem.NewGetSearchStatusV1ParamsWithContext(ctx)
		pollParams.Repository = repository
		pollParams.ID = jobID

		pollResp, err := m.API.GetSearchStatusV1(pollParams)
		if e := base.APIError(err, pollResp, scopeNGSIEM); e != nil {
			return nil, zero, e
		}

		payload := pollResp.Payload
		if payload != nil && payload.Done != nil && *payload.Done {
			// A job can finish because it was cancelled server-side (stopped by
			// another caller, a resource limit, or an admin action) — the API
			// reports that as Done=true with Cancelled=true, and its events are
			// absent or partial. Surface it as an error rather than returning a
			// misleading empty success.
			if payload.Cancelled != nil && *payload.Cancelled {
				m.Logger.Warn("search_ngsiem job cancelled", "job_id", jobID)
				return nil, zero, fmt.Errorf(
					"%w: search job %s was cancelled before completing; its results are incomplete",
					errSearch, jobID)
			}
			events := toEvents(payload.Events)
			m.Logger.Debug("search_ngsiem job completed", "job_id", jobID, "events", len(events))
			// No meta is attached: the job-results payload carries MetaData
			// (quota/costs/event counts), not a pagination cursor, and this
			// endpoint is not paginated.
			return nil, base.Entities(events), nil
		}
	}

	// Step 3: timeout — attempt best-effort cleanup, then report the timeout. The
	// stop error is intentionally ignored: the job is abandoned regardless, and
	// the timeout is the actionable failure to surface.
	m.Logger.Warn("search_ngsiem job timed out", "job_id", jobID, "timeout", m.Timeout)
	stopParams := ngsiem.NewStopSearchV1ParamsWithContext(ctx)
	stopParams.Repository = repository
	stopParams.ID = jobID
	if _, stopErr := m.API.StopSearchV1(stopParams); stopErr != nil {
		m.Logger.Debug("search_ngsiem stop after timeout failed", "job_id", jobID, "error", stopErr)
	}

	return nil, zero, fmt.Errorf(
		"%w: search timed out after %d seconds (job_id %s). Try narrowing your query or reducing the time range",
		errSearch, int(m.Timeout.Seconds()), jobID)
}

// toEvents copies the gofalcon event slice into a non-nil []any so the result is
// always a JSON array. Each event is an arbitrary JSON object
// (models.APIQueryJobsResultsEvents is an interface{} alias).
func toEvents(in []models.APIQueryJobsResultsEvents) []any {
	events := make([]any, 0, len(in))
	for _, e := range in {
		events = append(events, e)
	}
	return events
}

// isoToEpochMS converts an ISO 8601 timestamp to a Unix epoch-millisecond string,
// the format the NGSIEM query-job API expects for start/end (live-verified). It
// accepts RFC 3339 with or without sub-second precision; a value without a time
// zone is treated as UTC, matching the documented "...Z" example.
func isoToEpochMS(iso string) (string, error) {
	t, err := time.Parse(time.RFC3339, iso)
	if err != nil {
		// Fall back to a zoneless form (e.g. "2025-01-01T00:00:00"), interpreting
		// it as UTC to match the documented UTC examples.
		t, err = time.Parse("2006-01-02T15:04:05", iso)
		if err != nil {
			return "", fmt.Errorf("expected an ISO 8601 timestamp such as 2025-01-01T00:00:00Z: %w", err)
		}
	}
	return strconv.FormatInt(t.UnixMilli(), 10), nil
}
