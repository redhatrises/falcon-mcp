// MIT License
//
// Copyright (c) 2026 CrowdStrike
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

// Package guardian implements the falcon-mcp Guardian tools over the gofalcon
// aidr_events client (CrowdStrike's AIDR — AI Detection & Response — API). It
// exposes read-only search, entity-fetch, and aggregate rollup tools for AI
// agent activity and inventory, plus fan-out report/inventory/pivot tools that
// compose those queries. It registers four documentation resources (query
// guide, entity schema, inventory schema, example queries).
//
// The AIDR routes take typed query parameters rather than FQL, so there is no
// FQL guide and no filter-hints entry. Every route funnels through the narrowing
// ladder: the requested lookback window is sent as asked, and when the API
// refuses it (a 504 timeout, or a 400 naming time_range) the window is retried
// progressively narrower within a wall-clock budget, and any adjustment is
// reported to the caller as advisory notices on the result meta.
package guardian

import (
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/crowdstrike/gofalcon/falcon"
	"github.com/crowdstrike/gofalcon/falcon/client/aidr_events"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/go-openapi/runtime"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/crowdstrike/falcon-mcp/internal/modules/base"
	"github.com/crowdstrike/falcon-mcp/internal/modules/registry"
)

// scopeAIDRRead is the API scope every Guardian operation requires; it is
// attached to a 403 so the caller learns exactly which permission to grant.
var scopeAIDRRead = base.Scope{Name: "AIDR", Read: true}

// narrowingLadder lists the progressively narrower lookback windows tried when
// the API refuses the requested one, widest first.
var narrowingLadder = []string{"7d", "24h", "6h", "1h"}

const (
	// ladderBudget caps the wall-clock time spent narrowing the window. It sits
	// below the MCP client request timeout: a call that outlives the client is
	// killed mid-flight, so it is better to answer with a notice. Fan-out tools
	// run the ladder on several legs at once, so the cap is per request.
	ladderBudget = 30 * time.Second

	// aggregateGroupLimit is the number of buckets an aggregate route groups at
	// most. It offers no pagination, so a page of exactly this size is
	// indistinguishable from a truncated one without a warning.
	aggregateGroupLimit = 500

	// supportedTimeRangeUnits names the time_range units the API accepts. Minutes
	// were dropped upstream, so a value like "30m" is rejected before the request.
	supportedTimeRangeUnits = "'h' (hours), 'd' (days)"

	// logscaleToolDefault is the default window exposed on LogScale-backed tool
	// parameters, matching the API's own default so an unspecified window runs the
	// cheap query the server would have run anyway.
	logscaleToolDefault = "2h"

	// logscaleFanoutLookback is the window stated explicitly on internal
	// LogScale-backed fan-out legs, since those endpoints default to a near-empty
	// 2h window when the parameter is omitted.
	logscaleFanoutLookback = "7d"

	// inventoryDefaultLookback is the default window for inventory rollups.
	inventoryDefaultLookback = "7d"

	// detectionsDefaultLookback is the default window for detection queries.
	detectionsDefaultLookback = "7d"
)

// timeUnitDays converts a time_range unit to a number of days.
var timeUnitDays = map[string]float64{"h": 1.0 / 24.0, "d": 1.0}

var (
	timeRangePattern    = regexp.MustCompile(`^(\d+)([hd])$`)
	timeRangeUnitFinder = regexp.MustCompile(`^(\d+)([a-zA-Z]+)$`)
	// agentIDsTokenPattern matches a 64-hex AIAgent.Id/AgentIds token, which the
	// detection routes' 32-hex agent_id (SensorId) parameter must not receive.
	agentIDsTokenPattern = regexp.MustCompile(`^[a-fA-F0-9]{64}$`)
)

// Factory builds the guardian module from shared deps. The generated aggregator
// collects it, so the module needs no init side effect.
var Factory registry.Factory = func(d registry.Deps) base.Module {
	return &Module{
		API:         d.API.AidrEvents,
		Concurrency: d.Concurrency,
		Logger:      d.Logger,
	}
}

// Module registers the Guardian tools. It holds the aidr_events sub-client
// behind a narrow local interface so handlers can be tested against a small
// fake. Logger must be non-nil.
type Module struct {
	API         api
	Concurrency int
	Logger      *slog.Logger
}

// api is the slice of the gofalcon aidr_events client this module consumes. The
// query and aggregate routes return full records (not just IDs), so most search
// tools are a single call; only get_guardian_agent and get_guardian_session_detail
// reach the entity-fetch routes.
type api interface {
	QueryAgentsV1(*aidr_events.QueryAgentsV1Params, ...aidr_events.ClientOption) (*aidr_events.QueryAgentsV1OK, error)
	EntitiesAgentsV1(*aidr_events.EntitiesAgentsV1Params, ...aidr_events.ClientOption) (*aidr_events.EntitiesAgentsV1OK, error)
	QueryAgentSessionsV1(*aidr_events.QueryAgentSessionsV1Params, ...aidr_events.ClientOption) (*aidr_events.QueryAgentSessionsV1OK, error)
	AggregateAgentSessionsV1(*aidr_events.AggregateAgentSessionsV1Params, ...aidr_events.ClientOption) (*aidr_events.AggregateAgentSessionsV1OK, error)
	QueryToolsV1(*aidr_events.QueryToolsV1Params, ...aidr_events.ClientOption) (*aidr_events.QueryToolsV1OK, error)
	QueryToolUsageV1(*aidr_events.QueryToolUsageV1Params, ...aidr_events.ClientOption) (*aidr_events.QueryToolUsageV1OK, error)
	QuerySkillsV1(*aidr_events.QuerySkillsV1Params, ...aidr_events.ClientOption) (*aidr_events.QuerySkillsV1OK, error)
	AggregateSkillsV1(*aidr_events.AggregateSkillsV1Params, ...aidr_events.ClientOption) (*aidr_events.AggregateSkillsV1OK, error)
	QuerySkillUsageV1(*aidr_events.QuerySkillUsageV1Params, ...aidr_events.ClientOption) (*aidr_events.QuerySkillUsageV1OK, error)
	QueryExecutionsV1(*aidr_events.QueryExecutionsV1Params, ...aidr_events.ClientOption) (*aidr_events.QueryExecutionsV1OK, error)
	EntitiesExecutionsV1(*aidr_events.EntitiesExecutionsV1Params, ...aidr_events.ClientOption) (*aidr_events.EntitiesExecutionsV1OK, error)
	QueryPromptsV1(*aidr_events.QueryPromptsV1Params, ...aidr_events.ClientOption) (*aidr_events.QueryPromptsV1OK, error)
	QueryDetectionsV1(*aidr_events.QueryDetectionsV1Params, ...aidr_events.ClientOption) (*aidr_events.QueryDetectionsV1OK, error)
	AggregateDetectionsV1(*aidr_events.AggregateDetectionsV1Params, ...aidr_events.ClientOption) (*aidr_events.AggregateDetectionsV1OK, error)
	QueryAgentInstallationsV1(*aidr_events.QueryAgentInstallationsV1Params, ...aidr_events.ClientOption) (*aidr_events.QueryAgentInstallationsV1OK, error)
	QueryAgentOSUsersV1(*aidr_events.QueryAgentOSUsersV1Params, ...aidr_events.ClientOption) (*aidr_events.QueryAgentOSUsersV1OK, error)
	QueryModelNamesV1(*aidr_events.QueryModelNamesV1Params, ...aidr_events.ClientOption) (*aidr_events.QueryModelNamesV1OK, error)
	QueryMcpServerNamesV1(*aidr_events.QueryMcpServerNamesV1Params, ...aidr_events.ClientOption) (*aidr_events.QueryMcpServerNamesV1OK, error)
	AggregateAgentsV1(*aidr_events.AggregateAgentsV1Params, ...aidr_events.ClientOption) (*aidr_events.AggregateAgentsV1OK, error)
	AggregateToolsV1(*aidr_events.AggregateToolsV1Params, ...aidr_events.ClientOption) (*aidr_events.AggregateToolsV1OK, error)
	EntitiesSessionActivityV1(*aidr_events.EntitiesSessionActivityV1Params, ...aidr_events.ClientOption) (*aidr_events.EntitiesSessionActivityV1OK, error)
	EntitiesProcessTreeV1(*aidr_events.EntitiesProcessTreeV1Params, ...aidr_events.ClientOption) (*aidr_events.EntitiesProcessTreeV1OK, error)
	EntitiesNetworkEventsV1(*aidr_events.EntitiesNetworkEventsV1Params, ...aidr_events.ClientOption) (*aidr_events.EntitiesNetworkEventsV1OK, error)
	EntitiesFileEventsV1(*aidr_events.EntitiesFileEventsV1Params, ...aidr_events.ClientOption) (*aidr_events.EntitiesFileEventsV1OK, error)
	EntitiesClassifiedFileAccessV1(*aidr_events.EntitiesClassifiedFileAccessV1Params, ...aidr_events.ClientOption) (*aidr_events.EntitiesClassifiedFileAccessV1OK, error)
}

// Name reports the module name.
func (m *Module) Name() string { return "guardian" }

// Description reports a one-line summary of the module.
func (m *Module) Description() string {
	return "Query AI agent activity and inventory via the Guardian (AIDR) API: agents, sessions, tools, skills, executions, prompts, detections, and fleet rollups"
}

// RegisterPrompts is a no-op: the guardian module exposes no prompts.
func (m *Module) RegisterPrompts(_ *mcp.Server) {}

// --- Query engine: the narrowing ladder shared by every route ---

// aidrResp holds one AIDR response's payload, extracted to shared types. raw is
// the gofalcon *OK value, retained so base.APIError can read its payload errors
// reflectively (and attach the AIDR:read scope on a 403).
type aidrResp[T any] struct {
	resources []T
	meta      *models.MsahandlerMSAMeta
	raw       any
}

// aidrCall issues one AIDR request for the given lookback window. The narrowing
// ladder invokes it once per rung, changing only the window.
type aidrCall[T any] func(timeRange string) (aidrResp[T], error)

// runLadder runs call once at the requested window and, if the API refuses it,
// retries at progressively narrower windows within the budget. It returns the
// final response, the advisory notices describing any adjustment, and the final
// transport error. It is a free function because Go methods cannot be generic.
func runLadder[T any](timeRange string, call aidrCall[T]) (aidrResp[T], []string, error) {
	resp, err := call(timeRange)
	if timeRange == "" || !windowRejected(err) {
		return resp, nil, err
	}

	rungs := narrowingRungs(timeRange)
	deadline := time.Now().Add(ladderBudget)
	notice := exhaustedNotice(rungs)
	attempted, attemptedErr := resp, err
	for _, rung := range rungs {
		if !time.Now().Before(deadline) {
			notice = budgetNotice()
			break
		}
		attempted, attemptedErr = call(rung)
		if !windowRejected(attemptedErr) {
			notice = narrowedNotice(timeRange, rung)
			break
		}
	}
	return attempted, []string{notice}, attemptedErr
}

// queryOpts carries the shaping inputs a search/aggregate handler needs beyond
// the API call itself.
type queryOpts struct {
	op          string // log label / route identity
	timeRange   string // requested window; "" when the route has none
	limit       int    // client-side truncation and page-size echo; 0 = none
	isAggregate bool   // adds the group-cap truncation notice
}

// runQuery drives one AIDR route through the ladder and shapes the result into
// the resources, meta, and error a search or aggregate tool returns. meta merges
// the API pagination (with an unusable full-page total blanked), the caller's
// page size, and any advisory notices.
func runQuery[T any](l *slog.Logger, o queryOpts, call aidrCall[T]) ([]T, *base.Meta, *base.Error) {
	l.Debug(o.op, "time_range", o.timeRange, "limit", o.limit)

	if unit := badTimeRangeUnit(o.timeRange); unit != "" {
		return nil, nil, &base.Error{
			Message: fmt.Sprintf("invalid time_range unit: %q; supported: %s", unit, supportedTimeRangeUnits),
		}
	}

	resp, notices, err := runLadder(o.timeRange, call)
	if e := base.APIError(err, resp.raw, scopeAIDRRead); e != nil {
		return nil, nil, noticedError(e, notices)
	}

	returned := len(resp.resources)
	if o.isAggregate && returned == aggregateGroupLimit {
		notices = append(notices, aggregateTruncatedNotice())
	}

	resources := resp.resources
	if o.limit > 0 && returned > o.limit {
		resources = resources[:o.limit]
	}

	meta := base.NormalizedMeta(resp.meta)
	meta = blankUnusableTotal(meta, o.limit, returned)
	meta = attachNotices(meta, notices)
	return resources, meta, nil
}

// blankUnusableTotal reproduces AIDR's pagination contract: the API reports
// meta.pagination.total as offset+len(page), so on a full page that merely
// restates the cursor rather than a match count and must be nulled; on a short
// page the rows ran out and the total is real. The caller's page size is echoed
// as the limit, since the aggregate routes echo their group cap instead.
func blankUnusableTotal(meta *base.Meta, limit, returned int) *base.Meta {
	if meta == nil || meta.Pagination == nil {
		return meta
	}
	pageLimit := int64(0)
	switch {
	case meta.Pagination.Limit != nil:
		pageLimit = *meta.Pagination.Limit
	case limit > 0:
		pageLimit = int64(limit)
	}
	if pageLimit > 0 && int64(returned) >= pageLimit {
		meta.Pagination.Total = nil
	}
	if limit > 0 {
		l := int64(limit)
		meta.Pagination.Limit = &l
	}
	return meta
}

// attachNotices records advisory notices on meta, allocating a bare meta when
// the API returned none but the request was adjusted.
func attachNotices(meta *base.Meta, notices []string) *base.Meta {
	if len(notices) == 0 {
		return meta
	}
	if meta == nil {
		meta = &base.Meta{}
	}
	meta.Notices = notices
	return meta
}

// noticedError folds advisory notices into e's message. A failed tool call is
// delivered to the caller as its error text alone, so a notice left on the
// result meta (which a failed call never returns) would be dropped; carrying it
// in the message keeps the ladder's exhaustion and budget guidance visible when
// the API refuses every window down to the narrowest rung.
func noticedError(e *base.Error, notices []string) *base.Error {
	if e == nil || len(notices) == 0 {
		return e
	}
	e.Message = strings.TrimSpace(e.Message + " " + strings.Join(notices, " "))
	return e
}

// windowRejected reports whether err means the API refused the request because
// of its lookback window: a 504 when the engine gives up, or a 400 that names
// time_range. base.APIError cannot be used here because its status extraction
// remaps 504 to 500, which would disable the ladder.
func windowRejected(err error) bool {
	if err == nil {
		return false
	}
	var st runtime.ClientResponseStatus
	if !errors.As(err, &st) {
		return false
	}
	if st.IsCode(504) {
		return true
	}
	if st.IsCode(400) {
		return strings.Contains(strings.ToLower(falcon.ErrorExplain(err)), "time_range")
	}
	return false
}

// narrowingRungs returns the ladder windows strictly narrower than effective.
func narrowingRungs(effective string) []string {
	currentDays := parseTimeRangeDays(effective)
	if currentDays < 0 {
		return nil
	}
	var rungs []string
	for _, rung := range narrowingLadder {
		if d := parseTimeRangeDays(rung); d >= 0 && d < currentDays {
			rungs = append(rungs, rung)
		}
	}
	return rungs
}

// parseTimeRangeDays converts a window like "24h" or "7d" to a number of days,
// returning -1 when the value cannot be parsed so it passes through to the API
// untouched rather than being guessed at.
func parseTimeRangeDays(value string) float64 {
	m := timeRangePattern.FindStringSubmatch(strings.TrimSpace(value))
	if m == nil {
		return -1
	}
	amount, err := strconv.Atoi(m[1])
	if err != nil {
		return -1
	}
	return float64(amount) * timeUnitDays[m[2]]
}

// badTimeRangeUnit returns the offending unit when value uses a unit the API
// rejects (e.g. "30m"). A value that cannot be parsed at all returns "", so the
// API stays the authority on genuinely unfamiliar formats.
func badTimeRangeUnit(value string) string {
	if value == "" {
		return ""
	}
	m := timeRangeUnitFinder.FindStringSubmatch(strings.TrimSpace(value))
	if m == nil {
		return ""
	}
	if _, ok := timeUnitDays[m[2]]; !ok {
		return m[2]
	}
	return ""
}

// budgetNotice reports that the ladder stopped narrowing to stay under the
// budget.
func budgetNotice() string {
	return fmt.Sprintf(
		"Stopped narrowing the window after %ds so the call returns before the MCP "+
			"client times out. Retry with a smaller time_range.", int(ladderBudget.Seconds()))
}

// narrowedNotice reports that a narrower window served the results.
func narrowedNotice(effective, rung string) string {
	return fmt.Sprintf(
		"The API refused the %s window; results are from a narrower %s window instead. "+
			"Counts cover %s, not the window you asked for.", effective, rung, rung)
}

// exhaustedNotice reports that the window was refused and no narrower rung
// succeeded, naming the narrowest window actually tried.
func exhaustedNotice(rungs []string) string {
	if len(rungs) > 0 {
		return fmt.Sprintf(
			"The API refused every window down to %s. Add a filter (aid, product, or "+
				"session_id) to narrow the query instead of widening time.", rungs[len(rungs)-1])
	}
	return "The API refused this time window and no narrower one was available to retry. " +
		"Add a filter (aid, product, or session_id) to narrow the query instead of widening time."
}

// aggregateTruncatedNotice warns that an aggregate returned exactly the
// server-side group cap and is likely truncated.
func aggregateTruncatedNotice() string {
	return fmt.Sprintf(
		"Aggregate returned exactly %d groups, the server-side maximum, and these routes "+
			"do not paginate. Results are likely truncated — narrow with aid, product, or a "+
			"shorter time_range.", aggregateGroupLimit)
}

// --- Value helpers ported from the Python module ---

// normalizeProductName maps a human-readable product name to the stored
// UPPER_SNAKE_CASE form (e.g. "Claude Code" -> "CLAUDE_CODE").
func normalizeProductName(product string) string {
	if product == strings.ToUpper(product) && strings.Contains(product, "_") {
		return product
	}
	up := strings.ToUpper(strings.TrimSpace(product))
	up = strings.ReplaceAll(up, " ", "_")
	return strings.ReplaceAll(up, "-", "_")
}

// sanitizeGuardianValue rejects a user-supplied value containing characters that
// are dangerous in Guardian queries (single quotes, backslashes, newlines).
func sanitizeGuardianValue(value string) error {
	switch {
	case strings.Contains(value, "'"):
		return base.InvalidInput("guardian", fmt.Sprintf("single quotes are not allowed: %q", value))
	case strings.Contains(value, `\`):
		return base.InvalidInput("guardian", fmt.Sprintf("backslashes are not allowed: %q", value))
	case strings.ContainsAny(value, "\n\r"):
		return base.InvalidInput("guardian", fmt.Sprintf("newlines are not allowed: %q", value))
	}
	return nil
}

// rejectAgentIDsToken guards a 32-hex agent_id filter against the 64-hex
// AIAgent.Id/AgentIds token, which the detection routes silently answer with an
// empty result. It returns a guiding error, or nil when the value is fine.
func rejectAgentIDsToken(agentID string) *base.Error {
	if agentID != "" && agentIDsTokenPattern.MatchString(agentID) {
		return &base.Error{Message: fmt.Sprintf(
			"agent_id %q looks like a 64-hex AIAgent.Id/AgentIds value. This filter wants "+
				"the 32-hex SensorId (aid); the API silently returns zero rows for the 64-hex "+
				"form. Use the SensorId from a search_guardian_agents result.", agentID)}
	}
	return nil
}

// asInt coerces an aggregate count (which may be a JSON string) to an int,
// degrading to 0 rather than failing the rollup.
func asInt(value any) int {
	switch v := value.(type) {
	case float64:
		return int(v)
	case int:
		return v
	case int64:
		return int(v)
	case string:
		n, err := strconv.Atoi(strings.TrimSpace(v))
		if err != nil {
			return 0
		}
		return n
	default:
		return 0
	}
}

// tagKey renders a product tag ID as a comparable string, collapsing the
// string-encoded and int-encoded forms the join sides disagree on. A nil or
// absent value returns "".
func tagKey(value any) string {
	switch v := value.(type) {
	case nil:
		return ""
	case bool:
		return strconv.FormatBool(v)
	case string:
		return v
	case float64:
		if v == float64(int64(v)) {
			return strconv.FormatInt(int64(v), 10)
		}
		return strconv.FormatFloat(v, 'g', -1, 64)
	default:
		return fmt.Sprintf("%v", v)
	}
}

// isUnattributedTag reports whether a product tag means "could not be attributed
// to a product". aggregates/detections encodes this as 0 and queries/detections
// as null; neither is a member of the product taxonomy, so both are treated as
// absent.
func isUnattributedTag(value any) bool {
	switch v := value.(type) {
	case nil:
		return true
	case string:
		if v == "" {
			return true
		}
		n, err := strconv.Atoi(strings.TrimSpace(v))
		return err == nil && n == 0
	case float64:
		return int64(v) == 0
	case int:
		return v == 0
	case int64:
		return v == 0
	default:
		return false
	}
}

// mapsOf converts a slice of gofalcon models to []map[string]any for the
// dict-style field access the fan-out joins need, degrading to an empty slice on
// a marshal failure so a leg cannot abort the whole rollup.
func mapsOf[T any](in []T) []map[string]any {
	out, err := base.ModelsToMaps(in)
	if err != nil {
		return nil
	}
	return out
}

// optStr returns a pointer to v, or nil when v is empty, so an unset filter is
// dropped from the request rather than sent as an empty string.
func optStr(v string) *string {
	if v == "" {
		return nil
	}
	return &v
}

// optInt64 returns a pointer to v as int64, or nil when v is zero.
func optInt64(v int) *int64 {
	if v == 0 {
		return nil
	}
	n := int64(v)
	return &n
}
