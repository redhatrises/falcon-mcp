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
// construct queries. It publishes a CQL authoring guide as an MCP text resource
// (falcon://ngsiem/search/cql-guide) and attaches that guide plus a repair hint
// to an empty result — the API free-text-matches malformed CQL and returns an
// empty HTTP 200 rather than a parser error, so an empty result is the common
// silent-failure signal. The Falcon API expects the job's start/end times as
// epoch-millisecond strings, so the handler converts the caller's ISO 8601
// timestamps before submitting.
//
// This intentionally diverges from the upstream Python module, which routes
// every failure return (start/poll errors, timeout, cancellation, a missing job
// id) through a single _format_cql_error_response that attaches the CQL guide and
// a hint. The port instead attaches the guide only on the empty HTTP 200 path and
// surfaces operational failures as Go errors, per this codebase's contract: a Go
// error means the request could not be completed, while a data-result envelope
// (empty results, invalid FQL) means the request succeeded but matched nothing.
// The empty 200 is the only path where a query-authoring mistake masquerades as
// success, so it is the only one that warrants the guide.
package ngsiem

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"github.com/crowdstrike/gofalcon/falcon/client/ngsiem"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/crowdstrike/falcon-mcp/internal/modules/base"
	"github.com/crowdstrike/falcon-mcp/internal/modules/registry"
)

// defaultRepository is the NGSIEM repository searched when the caller omits one,
// mirroring the Python falcon-mcp ngsiem module's default of "search-all".
const defaultRepository = "search-all"

// stopCleanupTimeout bounds the best-effort StopSearchV1 issued when the client
// cancels mid-poll. The original context is already done, so the cleanup runs on
// a short detached context rather than blocking indefinitely.
const stopCleanupTimeout = 5 * time.Second

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
// poll interval and timeout come from the resolved config (env-configurable via
// FALCON_MCP_NGSIEM_POLL_INTERVAL / FALCON_MCP_NGSIEM_TIMEOUT). This is a single
// job-based query, so the module ignores Deps.Concurrency.
var Factory registry.Factory = func(d registry.Deps) base.Module {
	return &Module{
		API:          d.API.Ngsiem,
		Logger:       d.Logger,
		PollInterval: d.NgsiemPollInterval,
		Timeout:      d.NgsiemTimeout,
	}
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
const searchNGSIEMDescription = "Execute a CQL (CrowdStrike Query Language) query against CrowdStrike Next-Gen SIEM.\n\n" +
	"Use this to search security events, logs, and telemetry with CQL. CQL is a\n" +
	"pipe-based language (`filter | command | command`): start from a tag or field\n" +
	"filter (e.g. `#event_simpleName=ProcessRollup2`, `UserName=*`) and pipe into\n" +
	"commands like `groupBy([...], function=count())` and `sort()`; keep the time\n" +
	"range tight. Consult `falcon://ngsiem/search/cql-guide` to construct the query —\n" +
	"it has the pipe model, core commands, and working examples (distinct count, time\n" +
	"bucketing, regex match, filtering on an aggregate). Returns matching event\n" +
	"records, or an error/empty dict carrying the CQL guide when the job fails,\n" +
	"times out, or returns no rows. Note: the API does not return detailed CQL parser\n" +
	"diagnostics — a malformed query may error or silently return unexpected/empty\n" +
	"results rather than a helpful message, so a result is not proof the query parsed\n" +
	"as intended. Search times out after FALCON_MCP_NGSIEM_TIMEOUT seconds\n" +
	"(default: 300)."

// queryStringDescription is the schema description for the query_string param.
// It carries backticks and embedded examples, so it lives as a const applied by
// searchNGSIEMSchema rather than in a struct tag.
const queryStringDescription = "The CQL (CrowdStrike Query Language) query to execute. " +
	"Consult `falcon://ngsiem/search/cql-guide` to construct this query. " +
	"CQL is pipe-based: `filter | command | command` — not SQL or Splunk " +
	"SPL (do not use SELECT/WHERE/stats/`| limit`). Build a query by " +
	"starting from a tag or field filter and piping into commands. " +
	"Common building blocks: tag filter `#event_simpleName=ProcessRollup2`; " +
	"field match `UserName=*`; aggregate `groupBy([ComputerName], function=count())`; " +
	"order `sort(_count, order=desc)`; limit raw events `head(5)`. " +
	"Examples: '#event_simpleName=ProcessRollup2 | head(5)' and " +
	"'#event_simpleName=ProcessRollup2 | groupBy([ComputerName], function=count()) " +
	"| sort(_count, order=desc)'. " +
	"For anything beyond these building blocks (distinct count, time " +
	"bucketing, regex/contains match, filtering on an aggregate), read " +
	"`falcon://ngsiem/search/cql-guide` — it has working examples."

// repositoryDescription is the schema description for the repository param.
const repositoryDescription = "Repository (or view) to search. Defaults to search-all (all event " +
	"data). Which repositories exist depends on the users tenant and its " +
	"configuration, so this is not a closed list. Common repositories/views: " +
	"search-all (all event data), " +
	"investigate_view (endpoint events), " +
	"xdr (XDR data), " +
	"third-party (third-party source events), " +
	"falcon_for_it_view (Falcon for IT data), " +
	"forensics_view (Falcon Forensics triage data). " +
	"Custom and other built-in repositories/views can also be passed by name."

// A zero-row result carries one of two hints, chosen by whether the job
// actually scanned any events. The NGSIEM API free-text-matches malformed CQL
// and returns an empty HTTP 200 rather than a parser error, so an empty result
// is the most common silent-failure signal; job.processed_events distinguishes
// a real negative (a completed scan that matched nothing) from an unscanned one
// (a query that likely never parsed as intended). Mirror the Python module's
// _CQL_CONFIRMED_ZERO_HINT and _CQL_UNSCANNED_ZERO_HINT 1:1; the confirmed hint
// takes the scanned-event count.
const (
	cqlConfirmedZeroHint = "No rows matched, and the job scanned %s events — a real negative. " +
		"Report it as such rather than retrying. If you expected rows, check " +
		"`job.parsed_query` against the query you sent."
	cqlUnscannedZeroHint = "No rows, and `job.processed_events` does not show a completed scan, so " +
		"this alone is not a confirmed negative. Compare `job.parsed_query` to the " +
		"query you sent: unrecognized words become free-text stages instead of an error."
)

// Repository names must be safe path segments: the value is placed directly in
// the query-job endpoint's URL path, so a value containing a path or escape
// character, or a "." / ".." dot segment, is rejected before the request is
// built. Mirrors the Python module's _UNSAFE_REPOSITORY_CHARS / _DOT_SEGMENTS.
const unsafeRepositoryChars = `/\%`

var dotSegments = map[string]bool{".": true, "..": true}

// searchNGSIEMSchema is the served input schema for falcon_search_ngsiem. It is
// inferred from SearchInput, then a mutate func applies the query_string and
// repository descriptions that cannot live in struct tags (they carry backticks).
var searchNGSIEMSchema = base.SchemaFor[SearchInput](func(s *jsonschema.Schema) {
	s.Properties["query_string"].Description = queryStringDescription
	s.Properties["repository"].Description = repositoryDescription
})

// RegisterTools registers the ngsiem tool into r.
func (m *Module) RegisterTools(r base.Registrar) {
	searchTool := &mcp.Tool{
		Name:        "search_ngsiem",
		Description: searchNGSIEMDescription,
		InputSchema: searchNGSIEMSchema,
	}
	base.AddTool(r, searchTool, m.searchNGSIEM)
}

// RegisterResources publishes the CQL authoring guide for the query_string param
// of falcon_search_ngsiem. NGSIEM uses CQL, not FQL, so this is a plain authoring
// guide rather than an FQL filter guide.
func (m *Module) RegisterResources(s *mcp.Server) {
	base.TextResource(s,
		cqlGuideURI,
		"search_ngsiem_cql_guide",
		"Contains the CQL authoring guide for the `query_string` param of the `falcon_search_ngsiem` tool.",
		"text/markdown",
		cqlGuide,
	)
}

// RegisterPrompts is a no-op: the ngsiem module exposes no prompts.
func (m *Module) RegisterPrompts(_ *mcp.Server) {}

// SearchInput is the input for falcon_search_ngsiem. The json tags use the same
// snake_case names as the Python module so existing clients stay compatible. The
// query_string and repository descriptions carry backticks, so they are applied
// by searchNGSIEMSchema rather than in these tags. QueryString and Start are
// required; the handler validates them and the timestamp format.
type SearchInput struct {
	QueryString string `json:"query_string" jsonschema:"The CQL query to execute. See the falcon://ngsiem/search/cql-guide resource to construct it."`
	Start       string `json:"start" jsonschema:"Search start time as an ISO 8601 timestamp (REQUIRED format). Example: start='2025-01-01T00:00:00Z'"`
	Repository  string `json:"repository,omitempty" jsonschema:"Repository (or view) to search. Defaults to search-all (all event data)."`
	End         string `json:"end,omitempty" jsonschema:"Search end time as an ISO 8601 timestamp. If not provided, defaults to the current time. Example: end='2025-02-06T00:00:00Z'"`
}

// searchResult is the success-path envelope for falcon_search_ngsiem. Results
// holds the matching event records (always a non-nil JSON array); Job carries
// the completed job's metadata (see jobMetadata) and QueryUsed echoes the CQL
// that ran, so a caller can compare what it sent against what the API parsed.
// On a zero-row result the CQL guide and a repair hint are attached: the API
// free-text-matches malformed CQL and returns an empty HTTP 200 rather than a
// parser error, so an empty result is the common silent-failure signal a caller
// must be able to self-correct from. CQLGuide and Hint are present only when
// Results is empty.
type searchResult struct {
	Results   []any        `json:"results"`
	QueryUsed string       `json:"query_used"`
	Job       *jobMetadata `json:"job,omitempty"`
	CQLGuide  string       `json:"cql_guide,omitempty"`
	Hint      string       `json:"hint,omitempty"`
}

// jobMetadata summarizes a completed NGSIEM query job for the caller. It is
// built from the poll payload's MetaData and top-level fields. Numeric fields
// are pointers so an absent value is omitted rather than reported as a
// misleading zero; ParsedQuery and the ISO timestamps are omitted when the API
// did not supply them. Warnings concatenates the job's top-level warnings and
// its metadata warnings (each an arbitrary JSON object or string).
type jobMetadata struct {
	JobID           string `json:"job_id,omitempty"`
	Repository      string `json:"repository,omitempty"`
	EventCount      *int64 `json:"event_count,omitempty"`
	ProcessedEvents *int64 `json:"processed_events,omitempty"`
	ProcessedBytes  *int64 `json:"processed_bytes,omitempty"`
	ParsedQuery     string `json:"parsed_query,omitempty"`
	SearchStart     string `json:"search_start,omitempty"`
	SearchEnd       string `json:"search_end,omitempty"`
	DurationMS      *int64 `json:"duration_ms,omitempty"`
	IsAggregate     *bool  `json:"is_aggregate,omitempty"`
	Warnings        []any  `json:"warnings,omitempty"`
}

// searchNGSIEM starts a CQL query job, polls it to completion, and returns the
// matching event records. On an API failure it returns a *base.Error (with scope
// hints on a 403); on a job that never returns an id or that exceeds the poll
// timeout it returns an errSearch-wrapped error, stopping the job first on
// timeout. Events are arbitrary JSON objects, so they are carried as any. An
// empty result carries the CQL guide and a repair hint (see searchResult).
func (m *Module) searchNGSIEM(ctx context.Context, _ *mcp.CallToolRequest, in SearchInput) (*mcp.CallToolResult, searchResult, error) {
	var zero searchResult

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
	if err := validateRepository(repository); err != nil {
		return nil, zero, fmt.Errorf("%w: %w", errSearch, err)
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
			// The client cancelled or disconnected. Stop the server-side job so it
			// is not abandoned, using a short detached context because ctx itself
			// is already done and cannot drive the cleanup call.
			stopCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), stopCleanupTimeout)
			m.stopSearch(stopCtx, repository, jobID)
			cancel()
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
			job := buildJobMetadata(jobID, repository, payload)
			// No meta is attached: the job-results payload carries MetaData
			// (quota/costs/event counts), not a pagination cursor, and this
			// endpoint is not paginated; the counts are surfaced via job instead.
			if len(events) == 0 {
				// The API free-text-matches invalid CQL and returns HTTP 200 with
				// an empty list, so an empty result is the most common silent-
				// failure signal. Attach the guide and a hint chosen by whether the
				// job actually scanned events, so the caller can tell a real
				// negative from a query that never parsed as intended.
				return nil, searchResult{
					Results:   []any{},
					QueryUsed: in.QueryString,
					Job:       job,
					CQLGuide:  cqlGuide,
					Hint:      zeroRowHint(job),
				}, nil
			}
			return nil, searchResult{
				Results:   events,
				QueryUsed: in.QueryString,
				Job:       job,
			}, nil
		}
	}

	// Step 3: timeout — attempt best-effort cleanup, then report the timeout.
	m.Logger.Warn("search_ngsiem job timed out", "job_id", jobID, "timeout", m.Timeout)
	m.stopSearch(ctx, repository, jobID)

	return nil, zero, fmt.Errorf(
		"%w: search timed out after %d seconds (job_id %s). Try narrowing your query or reducing the time range",
		errSearch, int(m.Timeout.Seconds()), jobID)
}

// stopSearch issues a best-effort StopSearchV1 for jobID. The stop error is
// intentionally swallowed (debug-logged only): the job is abandoned regardless,
// and the caller has a more actionable failure to surface. On client
// cancellation the caller passes a short detached context, since the original
// context is already done and cannot drive the cleanup call.
func (m *Module) stopSearch(ctx context.Context, repository, jobID string) {
	stopParams := ngsiem.NewStopSearchV1ParamsWithContext(ctx)
	stopParams.Repository = repository
	stopParams.ID = jobID
	if _, err := m.API.StopSearchV1(stopParams); err != nil {
		m.Logger.Debug("search_ngsiem stop failed", "job_id", jobID, "error", err)
	}
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

// validateRepository rejects a repository name that would be unsafe in the
// query-job endpoint's URL path: a name containing a path or escape character
// (/, \, %) or equal to a "." / ".." dot segment. It returns a plain validation
// error (the caller wraps it in errSearch), distinct from the CQL-guide
// soft-error path, since a bad repository is a request mistake, not a query one.
func validateRepository(repository string) error {
	if dotSegments[repository] {
		return fmt.Errorf("repository %q is not a valid name", repository)
	}
	if i := strings.IndexAny(repository, unsafeRepositoryChars); i >= 0 {
		return fmt.Errorf("repository %q contains an unsafe character %q", repository, string(repository[i]))
	}
	return nil
}

// buildJobMetadata assembles the jobMetadata envelope from a completed job's
// poll payload. Numeric fields are carried as pointers straight from the API
// metadata so an absent value stays absent rather than becoming a misleading
// zero; the ISO timestamps and parsed query are omitted when the API did not
// supply them.
func buildJobMetadata(jobID, repository string, payload *models.APIQueryJobsResults) *jobMetadata {
	job := &jobMetadata{
		JobID:      jobID,
		Repository: repository,
	}
	if meta := payload.MetaData; meta != nil {
		job.EventCount = meta.EventCount
		job.ProcessedEvents = meta.ProcessedEvents
		job.ProcessedBytes = meta.ProcessedBytes
		job.DurationMS = meta.TimeMillis
		job.IsAggregate = meta.IsAggregate
		job.ParsedQuery = parsedQueryFrom(meta.FilterQuery)
		job.SearchStart = epochMSToISO(meta.QueryStart)
		job.SearchEnd = epochMSToISO(meta.QueryEnd)
	}
	job.Warnings = warningsFrom(payload)
	return job
}

// parsedQueryFrom extracts the queryString the API parsed from a job's filter
// query. FilterQuery is an untyped JSON value (interface{}); the parsed query
// lives at its "queryString" key when present.
func parsedQueryFrom(filterQuery any) string {
	m, ok := filterQuery.(map[string]any)
	if !ok {
		return ""
	}
	s, _ := m["queryString"].(string)
	return s
}

// epochMSToISO renders an epoch-millisecond pointer as a UTC RFC 3339 string,
// returning "" when the value is absent so the field is omitted.
func epochMSToISO(ms *int64) string {
	if ms == nil {
		return ""
	}
	return time.UnixMilli(*ms).UTC().Format(time.RFC3339)
}

// warningsFrom concatenates a job's top-level warnings and its metadata
// warnings into a single list, preserving each warning as its native shape (the
// structured top-level objects, then the metadata's plain strings). Returns nil
// when there are none so the field is omitted.
func warningsFrom(payload *models.APIQueryJobsResults) []any {
	var out []any
	for _, w := range payload.Warnings {
		if w != nil {
			out = append(out, w)
		}
	}
	if meta := payload.MetaData; meta != nil {
		for _, w := range meta.Warnings {
			out = append(out, w)
		}
	}
	return out
}

// zeroRowHint selects the repair hint for a zero-row result. A job that scanned
// events matched nothing for real (the confirmed hint, carrying the scanned
// count); otherwise the scan did not complete and the empty result is not a
// confirmed negative (the unscanned hint).
func zeroRowHint(job *jobMetadata) string {
	if job != nil && job.ProcessedEvents != nil && *job.ProcessedEvents > 0 {
		return fmt.Sprintf(cqlConfirmedZeroHint, groupThousands(*job.ProcessedEvents))
	}
	return cqlUnscannedZeroHint
}

// groupThousands formats n with comma thousands separators (e.g. 1234567 ->
// "1,234,567"), matching the Python hint's {n:,} rendering.
func groupThousands(n int64) string {
	s := strconv.FormatInt(n, 10)
	neg := ""
	if n < 0 {
		neg, s = "-", s[1:]
	}
	var b strings.Builder
	lead := len(s) % 3
	if lead == 0 {
		lead = 3
	}
	b.WriteString(s[:lead])
	for i := lead; i < len(s); i += 3 {
		b.WriteByte(',')
		b.WriteString(s[i : i+3])
	}
	return neg + b.String()
}
