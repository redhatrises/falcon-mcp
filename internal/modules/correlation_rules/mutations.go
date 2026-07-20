package correlation_rules

import (
	"context"

	"github.com/crowdstrike/gofalcon/falcon/client/correlation_rules"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/crowdstrike/falcon-mcp/internal/modules/base"
)

// Default create-rule field values matching falcon-mcp, applied when the caller
// omits them.
const (
	defaultSearchOutcome = "detection"
	defaultLookback      = "1h0m"
	defaultSchedule      = "@every 1h0m"
	defaultStatus        = "active"
	defaultTriggerMode   = "summary"
)

// validSeverities is the set of severity scores the correlation-rules API
// accepts, per the create/update tool documentation.
var validSeverities = map[int]struct{}{10: {}, 30: {}, 50: {}, 70: {}, 90: {}}

// MitreAttackMapping is a single MITRE ATT&CK tactic/technique mapping supplied
// to the create and update tools.
type MitreAttackMapping struct {
	TacticID    string `json:"tactic_id,omitempty" jsonschema:"MITRE ATT&CK tactic ID (e.g. TA0002)"`
	TechniqueID string `json:"technique_id,omitempty" jsonschema:"MITRE ATT&CK technique ID (e.g. T1059)"`
}

// toModels converts the tool-level MITRE mappings into gofalcon request models.
func toModels(mappings []MitreAttackMapping) []*models.CorrelationrulesapiMitreAttackMappingV1 {
	if len(mappings) == 0 {
		return nil
	}
	out := make([]*models.CorrelationrulesapiMitreAttackMappingV1, 0, len(mappings))
	for _, mm := range mappings {
		tactic := mm.TacticID
		out = append(out, &models.CorrelationrulesapiMitreAttackMappingV1{
			TacticID:    &tactic,
			TechniqueID: mm.TechniqueID,
		})
	}
	return out
}

// CreateInput is the input for falcon_create_correlation_rule.
type CreateInput struct {
	CustomerID    string               `json:"customer_id,omitempty" jsonschema:"CID of the tenant to create the rule in"`
	Name          string               `json:"name,omitempty" jsonschema:"name for the new detection rule"`
	SearchFilter  string               `json:"search_filter,omitempty" jsonschema:"CQL query that defines the detection logic evaluated against NG-SIEM events"`
	Severity      int                  `json:"severity,omitempty" jsonschema:"severity score for alerts (one of 10, 30, 50, 70, 90)"`
	SearchOutcome string               `json:"search_outcome,omitempty" jsonschema:"outcome type for rule matches (e.g. detection, case); default detection"`
	Lookback      string               `json:"lookback,omitempty" jsonschema:"lookback window for event aggregation (e.g. 1h0m, 24h0m); default 1h0m"`
	Schedule      string               `json:"schedule,omitempty" jsonschema:"schedule definition for rule evaluation, minimum @every 0h5m; default @every 1h0m"`
	Status        string               `json:"status,omitempty" jsonschema:"initial rule status (active or inactive); default active"`
	TriggerMode   string               `json:"trigger_mode,omitempty" jsonschema:"how alerts are triggered per evaluation window (summary or verbose); default summary"`
	UseIngestTime bool                 `json:"use_ingest_time,omitempty" jsonschema:"use event ingest time instead of event timestamp for the lookback window"`
	Description   string               `json:"description,omitempty" jsonschema:"optional description explaining what the rule detects and why"`
	MitreAttack   []MitreAttackMapping `json:"mitre_attack,omitempty" jsonschema:"MITRE ATT&CK mapping as a list of objects with tactic_id and technique_id"`
	Comment       string               `json:"comment,omitempty" jsonschema:"audit comment explaining why the rule is being created"`
}

func (m *Module) createCorrelationRule(ctx context.Context, _ *mcp.CallToolRequest, in CreateInput) (*mcp.CallToolResult, base.EntitiesResult[*models.CorrelationrulesapiRuleV1], error) {
	var zero base.EntitiesResult[*models.CorrelationrulesapiRuleV1]
	if in.CustomerID == "" || in.Name == "" || in.SearchFilter == "" {
		return nil, zero, wrapInvalid("create correlation rule", "customer_id, name, and search_filter are required")
	}
	if in.Severity == 0 {
		return nil, zero, wrapInvalid("create correlation rule", "severity is required (one of 10, 30, 50, 70, 90)")
	}
	if _, ok := validSeverities[in.Severity]; !ok {
		return nil, zero, wrapInvalid("create correlation rule", "severity must be one of 10, 30, 50, 70, 90")
	}
	m.Logger.Debug("create_correlation_rule", "name", in.Name, "severity", in.Severity)

	outcome := in.SearchOutcome
	if outcome == "" {
		outcome = defaultSearchOutcome
	}
	lookback := in.Lookback
	if lookback == "" {
		lookback = defaultLookback
	}
	schedule := in.Schedule
	if schedule == "" {
		schedule = defaultSchedule
	}
	status := in.Status
	if status == "" {
		status = defaultStatus
	}
	triggerMode := in.TriggerMode
	if triggerMode == "" {
		triggerMode = defaultTriggerMode
	}

	customerID := in.CustomerID
	name := in.Name
	severity := int32(in.Severity) //nolint:gosec // bounded to {10,30,50,70,90} by validSeverities check above
	searchFilter := in.SearchFilter

	body := &models.CorrelationrulesapiRuleCreateRequestV1{
		CustomerID: &customerID,
		Name:       &name,
		Severity:   &severity,
		Status:     &status,
		Search: &models.CorrelationrulesapiRuleSearchV1{
			Filter:        &searchFilter,
			Outcome:       &outcome,
			Lookback:      &lookback,
			TriggerMode:   &triggerMode,
			UseIngestTime: in.UseIngestTime,
		},
		Operation: &models.CorrelationrulesapiCreateRuleOperationV1{
			Schedule: &models.CorrelationrulesapiRuleScheduleV1{
				Definition: &schedule,
			},
		},
	}
	if in.Description != "" {
		body.Description = in.Description
	}
	if mm := toModels(in.MitreAttack); mm != nil {
		body.MitreAttack = mm
	}
	if in.Comment != "" {
		body.Comment = in.Comment
	}

	params := correlation_rules.NewEntitiesRulesPostV1ParamsWithContext(ctx)
	params.Body = body

	resp, err := m.API.EntitiesRulesPostV1(params)
	if e := base.APIError(err, resp, scopeCorrelationWrite); e != nil {
		return nil, zero, e
	}
	return nil, base.Entities(resp.Payload.Resources).WithMeta(resp.Payload.Meta), nil
}

// UpdateInput is the input for falcon_update_correlation_rule.
type UpdateInput struct {
	RuleID        string               `json:"rule_id,omitempty" jsonschema:"rule ID to update; use the rule_id field from falcon_search_correlation_rules results"`
	Name          string               `json:"name,omitempty" jsonschema:"new name for the rule"`
	Description   string               `json:"description,omitempty" jsonschema:"new description for the rule"`
	Status        string               `json:"status,omitempty" jsonschema:"new status (active or inactive)"`
	Severity      int                  `json:"severity,omitempty" jsonschema:"new severity score (one of 10, 30, 50, 70, 90)"`
	SearchFilter  string               `json:"search_filter,omitempty" jsonschema:"updated CQL query for the detection logic"`
	Lookback      string               `json:"lookback,omitempty" jsonschema:"updated lookback window (e.g. 1h0m, 24h0m)"`
	TriggerMode   string               `json:"trigger_mode,omitempty" jsonschema:"updated trigger mode (summary or verbose)"`
	UseIngestTime *bool                `json:"use_ingest_time,omitempty" jsonschema:"use event ingest time instead of event timestamp for the lookback window"`
	MitreAttack   []MitreAttackMapping `json:"mitre_attack,omitempty" jsonschema:"updated MITRE ATT&CK mapping as a list of objects with tactic_id and technique_id"`
	Comment       string               `json:"comment,omitempty" jsonschema:"audit comment explaining why the rule is being updated"`
}

func (m *Module) updateCorrelationRule(ctx context.Context, _ *mcp.CallToolRequest, in UpdateInput) (*mcp.CallToolResult, base.EntitiesResult[*models.CorrelationrulesapiRuleV1], error) {
	var zero base.EntitiesResult[*models.CorrelationrulesapiRuleV1]
	if in.RuleID == "" {
		return nil, zero, wrapInvalid("update correlation rule", "rule_id is required")
	}
	if in.Severity != 0 {
		if _, ok := validSeverities[in.Severity]; !ok {
			return nil, zero, wrapInvalid("update correlation rule", "severity must be one of 10, 30, 50, 70, 90")
		}
	}
	m.Logger.Debug("update_correlation_rule", "rule_id", in.RuleID)

	// Build the patch body as a map holding ONLY the caller-supplied keys. The
	// gofalcon CorrelationrulesapiRulePatchRequestV1 model omits `omitempty` on
	// its mitre_attack, notifications, and guardrail_notifications slices, so
	// marshaling the typed struct would emit those keys as explicit `null` on
	// every call — which a PATCH endpoint may interpret as "clear this field".
	// The API contract (and the Python reference) is send-only-what-changed, so
	// we assemble the body ourselves and send it via a body override below.
	patch := in.patchBody()

	params := correlation_rules.NewEntitiesRulesPatchV1ParamsWithContext(ctx)
	// The PATCH endpoint accepts a list of rule patch objects. We leave
	// params.Body nil and override the request writer so only the provided keys
	// are serialized (see patchBody). The override first delegates to the typed
	// params' WriteToRequest, which applies the client timeout and — because
	// Body is nil — writes no body, then sets our map body.
	bodyOverride := func(op *runtime.ClientOperation) {
		typed := op.Params
		op.Params = runtime.ClientRequestWriterFunc(func(r runtime.ClientRequest, reg strfmt.Registry) error {
			if err := typed.WriteToRequest(r, reg); err != nil {
				return err
			}
			return r.SetBodyParam([]map[string]any{patch})
		})
	}

	resp, err := m.API.EntitiesRulesPatchV1(params, bodyOverride)
	if e := base.APIError(err, resp, scopeCorrelationWrite); e != nil {
		return nil, zero, e
	}
	return nil, base.Entities(resp.Payload.Resources).WithMeta(resp.Payload.Meta), nil
}

// patchBody builds the correlation-rules PATCH request object as a map holding
// only the fields the caller supplied, mirroring the Python module (which adds
// a key only when its argument is non-nil). id is always present. Sending only
// changed keys avoids clobbering unspecified fields — notably the gofalcon
// model's mitre_attack/notifications slices, which lack `omitempty` and would
// otherwise serialize to explicit null.
func (in UpdateInput) patchBody() map[string]any {
	patch := map[string]any{"id": in.RuleID}
	if in.Name != "" {
		patch["name"] = in.Name
	}
	if in.Description != "" {
		patch["description"] = in.Description
	}
	if in.Status != "" {
		patch["status"] = in.Status
	}
	if in.Severity != 0 {
		patch["severity"] = in.Severity
	}
	if in.Comment != "" {
		patch["comment"] = in.Comment
	}
	if len(in.MitreAttack) > 0 {
		mitre := make([]map[string]any, 0, len(in.MitreAttack))
		for _, mm := range in.MitreAttack {
			entry := map[string]any{"tactic_id": mm.TacticID}
			if mm.TechniqueID != "" {
				entry["technique_id"] = mm.TechniqueID
			}
			mitre = append(mitre, entry)
		}
		patch["mitre_attack"] = mitre
	}

	if in.SearchFilter != "" || in.Lookback != "" || in.TriggerMode != "" || in.UseIngestTime != nil {
		search := map[string]any{}
		if in.SearchFilter != "" {
			search["filter"] = in.SearchFilter
		}
		if in.Lookback != "" {
			search["lookback"] = in.Lookback
		}
		if in.TriggerMode != "" {
			search["trigger_mode"] = in.TriggerMode
		}
		if in.UseIngestTime != nil {
			search["use_ingest_time"] = *in.UseIngestTime
		}
		patch["search"] = search
	}
	return patch
}

// DeleteInput is the input for falcon_delete_correlation_rules.
type DeleteInput struct {
	IDs []string `json:"ids,omitempty" jsonschema:"rule IDs to delete; use the rule_id field from falcon_search_correlation_rules results"`
}

func (m *Module) deleteCorrelationRules(ctx context.Context, _ *mcp.CallToolRequest, in DeleteInput) (*mcp.CallToolResult, base.EntitiesResult[string], error) {
	var zero base.EntitiesResult[string]
	if len(in.IDs) == 0 {
		return nil, zero, wrapInvalid("delete correlation rules", "ids must be provided")
	}
	m.Logger.Debug("delete_correlation_rules", "ids", len(in.IDs))

	params := correlation_rules.NewEntitiesRulesDeleteV1ParamsWithContext(ctx)
	params.Ids = in.IDs

	resp, err := m.API.EntitiesRulesDeleteV1(params)
	if e := base.APIError(err, resp, scopeCorrelationWrite); e != nil {
		return nil, zero, e
	}
	return nil, base.Entities(resp.Payload.Resources).WithMeta(resp.Payload.Meta), nil
}
