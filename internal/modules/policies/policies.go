// Package policies implements a unified set of tools for managing CrowdStrike
// host-based policies across all six policy types — prevention, sensor_update,
// firewall, device_control, response, and content_update — behind a single
// policy_type discriminator. Per-type backends absorb the API differences (search
// mode, body model, platform requirements, valid actions) so the tool surface
// stays clean for the calling agent.
//
// This module manages the policy *container* (assignment, precedence,
// enable/disable). It does not manage firewall rules or rule groups — those live
// in the firewall module, which operates on what is *inside* a firewall policy.
//
// The six policy types return heterogeneous gofalcon models (PreventionPolicyV1,
// SensorUpdatePolicyV2, FirewallPolicyV1, …). The typed models decode live
// responses cleanly (unlike ML exclusions), but a single search tool cannot
// return six different typed slices, so record-returning operations round-trip
// the typed models through JSON into a uniform []map[string]any. This keeps the
// returned records 1:1 with the Python falcon-mcp module, which returns raw API
// dictionaries.
package policies

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/crowdstrike/falcon-mcp/internal/modules/base"
	"github.com/crowdstrike/falcon-mcp/internal/modules/registry"
)

// Factory builds the policies module from shared deps. It wires one backend per
// policy type over the six gofalcon policy sub-clients. The generated aggregator
// (internal/mcpserver) collects it, so the module needs no init side effect.
var Factory registry.Factory = func(d registry.Deps) base.Module {
	return &Module{
		backends: map[string]backend{
			"prevention":     preventionBackend{c: d.API.PreventionPolicies},
			"sensor_update":  sensorUpdateBackend{c: d.API.SensorUpdatePolicies},
			"firewall":       firewallBackend{c: d.API.FirewallPolicies},
			"device_control": deviceControlBackend{c: d.API.DeviceControlPolicies},
			"response":       responseBackend{c: d.API.ResponsePolicies},
			"content_update": contentUpdateBackend{c: d.API.ContentUpdatePolicies},
		},
		Logger: d.Logger,
	}
}

// fqlGuideURI is the MCP resource URI serving the policies search FQL guide,
// mirroring falcon-mcp's falcon://policies/search/fql-guide.
const fqlGuideURI = "falcon://policies/search/fql-guide"

// policyTypes is the ordered set of discriminator values exposed to the agent.
var policyTypes = []string{"prevention", "sensor_update", "firewall", "device_control", "response", "content_update"}

// createNeedsPlatform reports whether creating a policy of the given type
// requires platform_name. content_update is platform-agnostic (platform_name is
// always 'all') and its create model has no platform_name field.
var createNeedsPlatform = map[string]bool{
	"prevention":     true,
	"sensor_update":  true,
	"firewall":       true,
	"device_control": true,
	"response":       true,
	"content_update": false,
}

// precedenceNeedsPlatform mirrors createNeedsPlatform for set-precedence: every
// type except content_update requires platform_name (its precedence body model
// has no platform_name field).
var precedenceNeedsPlatform = map[string]bool{
	"prevention":     true,
	"sensor_update":  true,
	"firewall":       true,
	"device_control": true,
	"response":       true,
	"content_update": false,
}

// validActions is the set of accepted action_name values per policy type for
// perform_policy_action. Only prevention supports rule-group actions; the API
// rejects them for every other type. content_update has unique content-override
// actions. set-pinned-content-version / remove-pinned-content-version are
// intentionally omitted: they require a content-version value this tool has no
// parameter to carry, so exposing them would advertise a capability that cannot execute.
var validActions = map[string]map[string]bool{
	"prevention":     actionSet("enable", "disable", "add-host-group", "remove-host-group", "add-rule-group", "remove-rule-group"),
	"sensor_update":  actionSet("enable", "disable", "add-host-group", "remove-host-group"),
	"response":       actionSet("enable", "disable", "add-host-group", "remove-host-group"),
	"firewall":       actionSet("enable", "disable", "add-host-group", "remove-host-group"),
	"device_control": actionSet("enable", "disable", "add-host-group", "remove-host-group"),
	"content_update": actionSet("enable", "disable", "add-host-group", "remove-host-group", "override-allow", "override-pause", "override-revert"),
}

// groupActionParam maps a group action_name to the action_parameters body key
// the API expects: host-group actions carry the value under "group_id",
// rule-group actions under "rule_group_id". Membership also marks which actions
// require a group_id argument.
var groupActionParam = map[string]string{
	"add-host-group":    "group_id",
	"remove-host-group": "group_id",
	"add-rule-group":    "rule_group_id",
	"remove-rule-group": "rule_group_id",
}

// supportsSettings reports whether a policy type accepts a settings object.
// Firewall policies have no settings field on their create/update model — their
// behavior is managed through the firewall module's rule/rule-group tools — so
// passing settings to one is rejected rather than silently ignored.
var supportsSettings = map[string]bool{
	"prevention":     true,
	"sensor_update":  true,
	"firewall":       false,
	"device_control": true,
	"response":       true,
	"content_update": true,
}

// safeSortFields are the sort field bases the API accepts (each with a
// .asc/.desc direction). platform_name is deliberately excluded — sorting by it
// returns HTTP 500 on every policy type.
var safeSortFields = actionSet("name", "created_timestamp", "modified_timestamp", "enabled", "created_by", "modified_by", "precedence")

// actionSet builds a set from the given values.
func actionSet(values ...string) map[string]bool {
	m := make(map[string]bool, len(values))
	for _, v := range values {
		m[v] = true
	}
	return m
}

// errInvalidInput classifies client-side validation failures (invalid type,
// missing required fields, bad sort/action) so the handler returns a guiding data
// result rather than an opaque API error.
var errInvalidInput = errors.New("policies: invalid input")

// CrowdStrike API scopes required by this module's operations, surfaced on a 403
// via base.APIError. Each policy type has its own read/write console permission.
var (
	scopePreventionRead     = base.Scope{Name: "Prevention Policies", Read: true}
	scopePreventionWrite    = base.Scope{Name: "Prevention Policies", Write: true}
	scopeSensorUpdateRead   = base.Scope{Name: "Sensor Update Policies", Read: true}
	scopeSensorUpdateWrite  = base.Scope{Name: "Sensor Update Policies", Write: true}
	scopeFirewallRead       = base.Scope{Name: "Firewall Management", Read: true}
	scopeFirewallWrite      = base.Scope{Name: "Firewall Management", Write: true}
	scopeDeviceControlRead  = base.Scope{Name: "Device Control Policies", Read: true}
	scopeDeviceControlWrite = base.Scope{Name: "Device Control Policies", Write: true}
	scopeResponseRead       = base.Scope{Name: "Response Policies", Read: true}
	scopeResponseWrite      = base.Scope{Name: "Response Policies", Write: true}
	scopeContentUpdateRead  = base.Scope{Name: "Content Update Policies", Read: true}
	scopeContentUpdateWrite = base.Scope{Name: "Content Update Policies", Write: true}
)

// readScope and writeScope map a policy type to its required API scope.
func readScope(t string) base.Scope {
	switch t {
	case "sensor_update":
		return scopeSensorUpdateRead
	case "firewall":
		return scopeFirewallRead
	case "device_control":
		return scopeDeviceControlRead
	case "response":
		return scopeResponseRead
	case "content_update":
		return scopeContentUpdateRead
	default: // prevention
		return scopePreventionRead
	}
}

func writeScope(t string) base.Scope {
	switch t {
	case "sensor_update":
		return scopeSensorUpdateWrite
	case "firewall":
		return scopeFirewallWrite
	case "device_control":
		return scopeDeviceControlWrite
	case "response":
		return scopeResponseWrite
	case "content_update":
		return scopeContentUpdateWrite
	default: // prevention
		return scopePreventionWrite
	}
}

// Module registers the policies tools. It holds the per-type backends; handlers
// are stateless and reentrant. Logger must be non-nil.
type Module struct {
	backends map[string]backend
	Logger   *slog.Logger
}

// Name reports the module name.
func (m *Module) Name() string { return "policies" }

// Description reports a one-line summary of the module.
func (m *Module) Description() string {
	return "Search and manage Falcon prevention, sensor update, firewall, device control, response, and content update policies"
}

// searchPoliciesSchema is the input schema for falcon_search_policies. It is
// inferred from SearchInput's tags, then a mutate func adds the limit
// bounds/default and offset minimum the tag syntax cannot express.
var searchPoliciesSchema = base.SchemaFor[SearchInput](func(s *jsonschema.Schema) {
	s.Properties["limit"].Minimum = jsonschema.Ptr(1.0)
	s.Properties["limit"].Maximum = jsonschema.Ptr(500.0)
	s.Properties["limit"].Default = json.RawMessage(`100`)
	s.Properties["offset"].Minimum = jsonschema.Ptr(0.0)
})

// searchPolicyMembersSchema is the input schema for falcon_search_policy_members.
var searchPolicyMembersSchema = base.SchemaFor[MembersInput](func(s *jsonschema.Schema) {
	s.Properties["limit"].Minimum = jsonschema.Ptr(1.0)
	s.Properties["limit"].Maximum = jsonschema.Ptr(5000.0)
	s.Properties["limit"].Default = json.RawMessage(`100`)
	s.Properties["offset"].Minimum = jsonschema.Ptr(0.0)
})

// RegisterTools registers the seven policies tools into r.
func (m *Module) RegisterTools(r base.Registrar) {
	base.AddTool(r, &mcp.Tool{
		Name: "search_policies",
		Description: "Search host-based policies of a given type (prevention, sensor_update, firewall, " +
			"device_control, response, or content_update) by name, platform, enabled state, or timestamp. " +
			"Select which policy API is queried with policy_type. Consult falcon://policies/search/fql-guide " +
			"before constructing filter expressions — the name match operator differs per type. Returns full " +
			"policy records including id, name, platform_name, enabled, settings, and assigned host groups.\n" +
			"Responses include `pagination.total` (the total number of records matching the filter, " +
			"or null when the API does not report a count) — use it to answer \"how many\" questions.",
		InputSchema: searchPoliciesSchema,
	}, m.searchPolicies)

	base.AddTool(r, &mcp.Tool{
		Name: "search_policy_members",
		Description: "List the host devices governed by a specific policy. Provide the policy_type and policy " +
			"id; the filter and sort operate on HOST/DEVICE attributes, not policy " +
			"attributes. Consult falcon://hosts/search/fql-guide before constructing filter expressions. Differs from falcon_search_policies (which returns the policy object) and " +
			"falcon_search_host_group_members (one group's hosts). Returns full host device records.\n" +
			"Responses include `pagination.total` (the total number of records matching the filter, " +
			"or null when the API does not report a count) — use it to answer \"how many\" questions.",
		InputSchema: searchPolicyMembersSchema,
	}, m.searchPolicyMembers)

	base.AddTool(r, &mcp.Tool{
		Name: "create_policy",
		Description: "Create a host-based policy of the given policy_type. Provide a name and (for every type " +
			"except content_update) a platform_name. Detailed per-type settings construction is out of scope; " +
			"prefer cloning an existing policy with clone_id then adjusting via falcon_update_policy. New " +
			"policies are created disabled. Returns the created policy record.",
		Annotations: base.MutatingAnnotations(false),
	}, m.createPolicy)

	base.AddTool(r, &mcp.Tool{
		Name: "update_policy",
		Description: "Update an existing host-based policy of the given policy_type. Provide the policy id plus " +
			"any fields to change (name, description, settings). platform_name is not updatable after creation. " +
			"Uses PATCH semantics — unspecified fields are left unchanged. Returns the updated policy record.",
		Annotations: base.MutatingAnnotations(false),
	}, m.updatePolicy)

	base.AddTool(r, &mcp.Tool{
		Name: "delete_policies",
		Description: "Permanently delete one or more host-based policies of the given policy_type by ID. A " +
			"policy must usually be DISABLED before deletion (an enabled policy returns HTTP 400); disable it " +
			"first with falcon_perform_policy_action. The Default policy of each type cannot be deleted. Idempotent.",
		Annotations: base.DestructiveAnnotations(true),
	}, m.deletePolicies)

	base.AddTool(r, &mcp.Tool{
		Name: "perform_policy_action",
		Description: "Perform an action on one or more policies of the given policy_type: enable/disable, " +
			"attach/detach host groups or rule groups, or (content_update only) content overrides. action_name " +
			"is validated per type. The add/remove-host-group and add/remove-rule-group actions require a " +
			"group_id. Returns the updated policy records.",
		Annotations: base.MutatingAnnotations(false),
	}, m.performPolicyAction)

	base.AddTool(r, &mcp.Tool{
		Name: "set_policy_precedence",
		Description: "Set the precedence (evaluation order) of policies for a platform. The ids list must be the " +
			"COMPLETE ordered set of non-Default policies for the platform, highest precedence first; partial " +
			"lists are rejected. platform_name is required for every type except content_update. Returns the API response.",
		Annotations: base.MutatingAnnotations(false),
	}, m.setPolicyPrecedence)
}

// RegisterResources publishes the policies search FQL guide as an MCP resource,
// mirroring falcon-mcp's falcon://policies/search/fql-guide resource.
func (m *Module) RegisterResources(s *mcp.Server) {
	base.TextResource(s,
		fqlGuideURI,
		"search_policies_fql_guide",
		"Contains the guide for the `filter` param of the `falcon_search_policies` tool.",
		"text/markdown",
		fqlGuide,
	)
}

// RegisterPrompts is a no-op: the policies module exposes no prompts.
func (m *Module) RegisterPrompts(_ *mcp.Server) {}

// SearchInput is the input for falcon_search_policies.
type SearchInput struct {
	PolicyType string `json:"policy_type" jsonschema:"policy type to search: prevention, sensor_update, firewall, device_control, response, or content_update"`
	Filter     string `json:"filter,omitempty" jsonschema:"FQL filter. For name matching use the contains operator name:~'value' (a name:'*value*' glob matches nothing); name is not filterable for sensor_update/content_update. See falcon://policies/search/fql-guide."`
	Limit      int    `json:"limit,omitempty" jsonschema:"maximum policies to return [1-500]"`
	Offset     int    `json:"offset,omitempty" jsonschema:"starting index of the result set"`
	Sort       string `json:"sort,omitempty" jsonschema:"FQL sort (e.g. modified_timestamp.desc). Do NOT sort by platform_name (returns HTTP 500). See falcon://policies/search/fql-guide."`
}

func (m *Module) searchPolicies(ctx context.Context, _ *mcp.CallToolRequest, in SearchInput) (*mcp.CallToolResult, base.SearchResult[map[string]any], error) {
	var zero base.SearchResult[map[string]any]
	b, ok := m.backends[in.PolicyType]
	if !ok {
		return nil, zero, invalidType(in.PolicyType)
	}
	if err := validateSort(in.Sort); err != nil {
		return nil, zero, err
	}
	m.Logger.Debug("search_policies", "type", in.PolicyType, "filter", in.Filter, "limit", in.Limit, "offset", in.Offset, "sort", in.Sort)

	args := queryArgs{filter: in.Filter, sort: in.Sort, limit: clampLimit(in.Limit, 500)}
	if in.Offset != 0 {
		args.offset = new(int64(in.Offset))
	}

	records, meta, err := b.search(ctx, args)
	if err != nil {
		if details, isFQL := b.classifyFQL(err); isFQL {
			return nil, base.FQLError[map[string]any](details, in.Filter, fqlGuide), nil
		}
		if e := base.APIError(err, nil, readScope(in.PolicyType)); e != nil {
			return nil, zero, e
		}
	}
	m.Logger.Debug("search_policies complete", "type", in.PolicyType, "matched", len(records))
	return nil, base.Found(records, in.Filter).WithMeta(meta), nil
}

// MembersInput is the input for falcon_search_policy_members.
type MembersInput struct {
	PolicyType string `json:"policy_type" jsonschema:"policy type: prevention, sensor_update, firewall, device_control, response, or content_update"`
	ID         string `json:"id" jsonschema:"the policy ID whose host members to list; use falcon_search_policies to look it up"`
	Filter     string `json:"filter,omitempty" jsonschema:"FQL filter on HOST attributes (e.g. platform_name:'Windows'). See falcon://hosts/search/fql-guide for syntax."`
	Limit      int    `json:"limit,omitempty" jsonschema:"maximum records to return [1-5000]"`
	Offset     int    `json:"offset,omitempty" jsonschema:"starting index of the result set"`
	Sort       string `json:"sort,omitempty" jsonschema:"host FQL sort (e.g. hostname.asc, last_seen.desc)"`
}

func (m *Module) searchPolicyMembers(ctx context.Context, _ *mcp.CallToolRequest, in MembersInput) (*mcp.CallToolResult, base.SearchResult[*models.DeviceDevice], error) {
	var zero base.SearchResult[*models.DeviceDevice]
	b, ok := m.backends[in.PolicyType]
	if !ok {
		return nil, zero, invalidType(in.PolicyType)
	}
	if in.ID == "" {
		return nil, zero, wrapInvalid("search policy members", "a policy id is required")
	}
	m.Logger.Debug("search_policy_members", "type", in.PolicyType, "id", in.ID, "filter", in.Filter, "limit", in.Limit, "offset", in.Offset, "sort", in.Sort)

	args := queryArgs{filter: in.Filter, sort: in.Sort, limit: clampLimit(in.Limit, 5000)}
	if in.Offset != 0 {
		args.offset = new(int64(in.Offset))
	}

	members, meta, err := b.members(ctx, in.ID, args)
	if e := base.APIError(err, nil, readScope(in.PolicyType)); e != nil {
		return nil, zero, e
	}
	m.Logger.Debug("search_policy_members complete", "type", in.PolicyType, "matched", len(members))
	return nil, base.Found(members, in.Filter).WithMeta(meta), nil
}

// validateSort rejects a platform_name sort (HTTP 500) and any sort base not in
// safeSortFields. It accepts an optional .asc/.desc/|asc/|desc direction suffix.
func validateSort(sort string) error {
	if sort == "" {
		return nil
	}
	base := strings.TrimSpace(strings.SplitN(strings.SplitN(sort, ".", 2)[0], "|", 2)[0])
	if base == "platform_name" {
		return wrapInvalid("search policies", "sorting by 'platform_name' is not supported (the API returns HTTP 500); use name, created_timestamp, modified_timestamp, enabled, created_by, modified_by, or precedence")
	}
	if !safeSortFields[base] {
		return wrapInvalid("search policies", fmt.Sprintf("invalid sort field %q; valid sort fields are name, created_timestamp, modified_timestamp, enabled, created_by, modified_by, precedence", base))
	}
	return nil
}

// clampLimit clamps limit to [1, maxLimit], defaulting to 100 when unset.
func clampLimit(limit int, maxLimit int64) int64 {
	if limit <= 0 {
		return 100
	}
	if int64(limit) > maxLimit {
		return maxLimit
	}
	return int64(limit)
}

// invalidType builds the guiding error returned for an unknown policy_type.
func invalidType(t string) error {
	return fmt.Errorf("policies: %w: invalid policy_type %q (want one of %v)", errInvalidInput, t, policyTypes)
}

// wrapInvalid builds an errInvalidInput-wrapped error for op with detail.
func wrapInvalid(op, detail string) error {
	return fmt.Errorf("%s: %w: %s", op, errInvalidInput, detail)
}

// toMaps marshals typed gofalcon records and unmarshals them back into uniform
// map records, so the six heterogeneous policy models are returned as one shape.
// A nil slice yields a non-nil empty slice for stable JSON array output.
func toMaps[T any](in []T) ([]map[string]any, error) {
	out := make([]map[string]any, 0, len(in))
	for _, rec := range in {
		b, err := json.Marshal(rec)
		if err != nil {
			return nil, fmt.Errorf("encode policy record: %w", err)
		}
		var mp map[string]any
		if err := json.Unmarshal(b, &mp); err != nil {
			return nil, fmt.Errorf("decode policy record: %w", err)
		}
		out = append(out, mp)
	}
	return out, nil
}

// reorderByID reorders records to match the query-step id order, keyed by each
// record's "id" field. Records without a string id, or whose id is not in ids,
// are appended in their original order and never dropped. It restores the
// query-step sort for the device_control two-step search, whose get endpoint may
// reorder results.
func reorderByID(ids []string, records []map[string]any) []map[string]any {
	if len(records) == 0 {
		return records
	}
	byID := make(map[string]map[string]any, len(records))
	for _, rec := range records {
		if id, ok := rec["id"].(string); ok && id != "" {
			if _, dup := byID[id]; !dup {
				byID[id] = rec
			}
		}
	}
	out := make([]map[string]any, 0, len(records))
	placed := make(map[string]struct{}, len(records))
	for _, id := range ids {
		if rec, ok := byID[id]; ok {
			if _, done := placed[id]; !done {
				out = append(out, rec)
				placed[id] = struct{}{}
			}
		}
	}
	for _, rec := range records {
		id, _ := rec["id"].(string)
		if id == "" {
			out = append(out, rec)
			continue
		}
		if _, done := placed[id]; !done {
			out = append(out, rec)
		}
	}
	return out
}

// applyQuery copies the shared query args onto an operation's parameter pointers.
// Filter, sort, and offset are only set when meaningful so unset optionals stay nil.
func applyQuery(a queryArgs, filter **string, sort **string, limit **int64, offset **int64) {
	*limit = &a.limit
	if a.filter != "" {
		*filter = &a.filter
	}
	if a.sort != "" {
		*sort = &a.sort
	}
	if a.offset != nil {
		*offset = a.offset
	}
}

// errorsAs is a thin wrapper over errors.As, kept in this package so backends.go
// can classify typed 400s without importing errors at every call site.
func errorsAs(err error, target any) bool { return errors.As(err, target) }
