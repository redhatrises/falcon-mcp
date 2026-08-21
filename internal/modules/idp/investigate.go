package idp

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/crowdstrike/falcon-mcp/internal/modules/base"
)

// InvestigateInput is the input for falcon_idp_investigate_entity. The json tag
// names are part of the tool's wire contract, so existing clients stay
// compatible; the served schema is inferred from these jsonschema tags, then
// refined by investigateEntitySchema for bounds and defaults the tags cannot
// express.
//
// At least one of the identifier fields (EntityIDs, EntityNames, EmailAddresses,
// IPAddresses, DomainNames) must be supplied; this is validated in the handler
// and returned as data.
type InvestigateInput struct {
	EntityIDs      []string `json:"entity_ids,omitempty" jsonschema:"List of specific entity IDs to investigate (e.g., ['entity-001'])"`
	EntityNames    string   `json:"entity_names,omitempty" jsonschema:"Entity display name pattern to search for (e.g., 'John Doe' or 'Doe, John' or 'Administrator' or 'Admin*'). Supports '*' wildcards. When combined with other parameters, uses AND logic."`
	EmailAddresses string   `json:"email_addresses,omitempty" jsonschema:"UPN, email address, or Azure external identity pattern to search for (e.g., 'user@example.com', '*@example.com', or 'john.doe_contoso.com#EXT#@tenant.onmicrosoft.com'). Supports '*' wildcards. For AD samAccountName lookups, use domain_names + entity_names together instead. When combined with other parameters, uses AND logic."`
	IPAddresses    []string `json:"ip_addresses,omitempty" jsonschema:"List of IP addresses/endpoints to investigate (e.g., ['1.1.1.1']). When combined with other parameters, uses AND logic."`
	DomainNames    []string `json:"domain_names,omitempty" jsonschema:"List of domain names to search for (e.g., ['XDRHOLDINGS.COM', 'CORP.LOCAL']). When combined with other parameters, uses AND logic. Example: entity_names='Administrator' + domain_names=['DOMAIN.COM'] finds Administrator user in that specific domain."`

	InvestigationTypes []string `json:"investigation_types,omitempty" jsonschema:"Types of investigation to perform: 'entity_details', 'timeline_analysis', 'relationship_analysis', 'risk_assessment'. Use multiple for comprehensive analysis."`

	TimelineStartTime  string   `json:"timeline_start_time,omitempty" jsonschema:"Start time for timeline analysis in ISO format (e.g., '2024-01-01T00:00:00Z')"`
	TimelineEndTime    string   `json:"timeline_end_time,omitempty" jsonschema:"End time for timeline analysis in ISO format"`
	TimelineEventTypes []string `json:"timeline_event_types,omitempty" jsonschema:"Filter timeline by event types: 'ACTIVITY', 'NOTIFICATION', 'THREAT', 'ENTITY', 'AUDIT', 'POLICY', 'SYSTEM'"`

	RelationshipDepth int `json:"relationship_depth,omitempty" jsonschema:"Depth of relationship analysis (1-3 levels)"`

	Limit               int  `json:"limit,omitempty" jsonschema:"Maximum number of results to return"`
	IncludeAssociations bool `json:"include_associations,omitempty" jsonschema:"Include entity associations and relationships in results"`
	IncludeAccounts     bool `json:"include_accounts,omitempty" jsonschema:"Include account information in results"`
	IncludeIncidents    bool `json:"include_incidents,omitempty" jsonschema:"Include open security incidents in results"`
}

// investigateEntitySchema refines the inferred schema with the bounds and
// defaults the struct tags cannot express. The handler applies the same defaults
// at runtime because MCP clients omit zero-valued fields, so the schema default
// is advisory only.
var investigateEntitySchema = base.SchemaFor[InvestigateInput](func(s *jsonschema.Schema) {
	s.Properties["relationship_depth"].Minimum = jsonschema.Ptr(float64(minRelationshipDepth))
	s.Properties["relationship_depth"].Maximum = jsonschema.Ptr(float64(maxRelationshipDepth))
	s.Properties["relationship_depth"].Default = json.RawMessage(`2`)
	s.Properties["limit"].Minimum = jsonschema.Ptr(float64(minLimit))
	s.Properties["limit"].Maximum = jsonschema.Ptr(float64(maxLimit))
	s.Properties["limit"].Default = json.RawMessage(`10`)
	s.Properties["investigation_types"].Default = json.RawMessage(`["entity_details"]`)
	s.Properties["include_associations"].Default = json.RawMessage(`true`)
	s.Properties["include_accounts"].Default = json.RawMessage(`true`)
	s.Properties["include_incidents"].Default = json.RawMessage(`true`)
})

// InvestigationResult is the bespoke result envelope returned by
// falcon_idp_investigate_entity. It carries a summary, the resolved entity IDs,
// and one field per requested investigation type. On a validation or resolution
// failure only Error and Summary (status "failed") are populated — these are
// returned as data, not as a Go error.
//
// The per-type result fields hold the raw shapes the GraphQL queries return, so
// they are typed as any and omitted when their investigation type was not
// requested.
type InvestigationResult struct {
	Error                     string             `json:"error,omitempty"`
	Summary                   *InvestigationMeta `json:"investigation_summary,omitempty"`
	SearchCriteria            *SearchCriteria    `json:"search_criteria,omitempty"`
	Entities                  []string           `json:"entities,omitempty"`
	EntityDetails             any                `json:"entity_details,omitempty"`
	TimelineAnalysis          any                `json:"timeline_analysis,omitempty"`
	RelationshipAnalysis      any                `json:"relationship_analysis,omitempty"`
	RiskAssessment            any                `json:"risk_assessment,omitempty"`
	CrossInvestigationInsight any                `json:"cross_investigation_insights,omitempty"`
}

// InvestigationMeta is the investigation_summary block. EntityCount, the
// requested types, an RFC 3339 timestamp, and a status ("completed"/"failed")
// are always present; ResolvedEntityIDs and SearchCriteria appear only on
// success.
type InvestigationMeta struct {
	EntityCount        int             `json:"entity_count"`
	ResolvedEntityIDs  []string        `json:"resolved_entity_ids,omitempty"`
	InvestigationTypes []string        `json:"investigation_types"`
	Timestamp          string          `json:"timestamp"`
	Status             string          `json:"status"`
	SearchCriteria     *SearchCriteria `json:"search_criteria,omitempty"`
}

// SearchCriteria echoes the identifiers the caller supplied. Empty fields are
// omitted.
type SearchCriteria struct {
	EntityIDs      []string `json:"entity_ids,omitempty"`
	EntityNames    string   `json:"entity_names,omitempty"`
	EmailAddresses string   `json:"email_addresses,omitempty"`
	IPAddresses    []string `json:"ip_addresses,omitempty"`
	DomainNames    []string `json:"domain_names,omitempty"`
}

// hasAny reports whether at least one identifier is set.
func (s SearchCriteria) hasAny() bool {
	return len(s.EntityIDs) > 0 || s.EntityNames != "" || s.EmailAddresses != "" ||
		len(s.IPAddresses) > 0 || len(s.DomainNames) > 0
}

// investigateEntity is the tool handler. It validates identifiers, resolves them
// to entity IDs via a unified AND-based GraphQL query, runs each requested
// investigation type, and synthesizes the response. Validation errors and an
// empty resolution are returned as data (InvestigationResult.Error populated);
// only a GraphQL transport/API failure returns a *base.Error.
func (m *Module) investigateEntity(ctx context.Context, _ *mcp.CallToolRequest, in InvestigateInput) (*mcp.CallToolResult, InvestigationResult, error) {
	m.Logger.Debug("Starting comprehensive entity investigation")

	// Apply defaults for fields MCP clients omit when zero-valued.
	investigationTypes := in.InvestigationTypes
	if len(investigationTypes) == 0 {
		investigationTypes = []string{investigationEntityDetails}
	}
	limit := in.Limit
	if limit == 0 {
		limit = defaultLimit
	}
	depth := in.RelationshipDepth
	if depth == 0 {
		depth = defaultDepth
	}

	criteria := SearchCriteria{
		EntityIDs:      in.EntityIDs,
		EntityNames:    in.EntityNames,
		EmailAddresses: in.EmailAddresses,
		IPAddresses:    in.IPAddresses,
		DomainNames:    in.DomainNames,
	}

	// Step 1: validate inputs (returned as data, not a Go error). This also
	// rejects unknown investigation types, so runInvestigation only dispatches
	// known ones below.
	if verr := m.validateInput(criteria, investigationTypes); verr != nil {
		return nil, *verr, nil
	}

	// Step 2: resolve entities from the provided identifiers.
	m.Logger.Debug("Resolving entities from provided identifiers")
	resolvedIDs, apiErr := m.resolveEntities(ctx, criteria, limit)
	if apiErr != nil {
		return nil, InvestigationResult{}, apiErr
	}
	if len(resolvedIDs) == 0 {
		return nil, m.errorResult("No entities found matching the provided criteria", investigationTypes, &criteria), nil
	}

	m.Logger.Debug("Resolved entities for investigation", "count", len(resolvedIDs))

	// Step 3: run each requested investigation type.
	params := investigationParams{
		includeAssociations: in.IncludeAssociations,
		includeAccounts:     in.IncludeAccounts,
		includeIncidents:    in.IncludeIncidents,
		timelineStartTime:   in.TimelineStartTime,
		timelineEndTime:     in.TimelineEndTime,
		timelineEventTypes:  in.TimelineEventTypes,
		relationshipDepth:   depth,
		limit:               limit,
	}

	results := map[string]any{}
	for _, t := range investigationTypes {
		res, apiErr := m.runInvestigation(ctx, t, resolvedIDs, params)
		if apiErr != nil {
			return nil, InvestigationResult{}, apiErr
		}
		results[t] = res
	}

	// Step 4: synthesize the response.
	return nil, m.synthesize(resolvedIDs, investigationTypes, criteria, results), nil
}

// validateInput returns a failed-status result when no identifier is supplied,
// when entity_names / email_addresses is a bare wildcard, or when an unknown
// investigation type is requested. A nil return means the input is valid, so the
// dispatch in runInvestigation only ever sees a known type. Failures are returned
// as data (a failed-status InvestigationResult), not as a Go error.
func (m *Module) validateInput(c SearchCriteria, investigationTypes []string) *InvestigationResult {
	if !c.hasAny() {
		r := m.errorResult(
			"At least one entity identifier must be provided (entity_ids, entity_names, email_addresses, ip_addresses, or domain_names)",
			investigationTypes, nil)
		return &r
	}
	if isBareWildcard(c.EntityNames) || isBareWildcard(c.EmailAddresses) {
		r := m.errorResult(
			"entity_names/email_addresses cannot be a bare wildcard ('*'). "+
				"Provide a more specific pattern (e.g., 'Admin*') or narrow the search.",
			investigationTypes, nil)
		return &r
	}
	for _, t := range investigationTypes {
		if _, ok := knownInvestigationTypes[t]; !ok {
			r := m.errorResult(
				fmt.Sprintf("Unknown investigation type: %s", t),
				investigationTypes, nil)
			return &r
		}
	}
	return nil
}

// isBareWildcard reports whether s is non-empty but collapses to nothing once
// '*' and spaces are stripped (e.g. "*", "  * ").
func isBareWildcard(s string) bool {
	return s != "" && strings.Trim(s, "* ") == ""
}

// errorResult builds a failed-status InvestigationResult. Every failure it
// reports (input validation or an empty resolution) happens before or without a
// resolved entity set, so EntityCount is always 0. searchCriteria is attached
// only when non-nil and carrying at least one identifier.
func (m *Module) errorResult(msg string, investigationTypes []string, criteria *SearchCriteria) InvestigationResult {
	res := InvestigationResult{
		Error: msg,
		Summary: &InvestigationMeta{
			EntityCount:        0,
			InvestigationTypes: investigationTypes,
			Timestamp:          m.timestamp(),
			Status:             "failed",
		},
	}
	if criteria != nil && criteria.hasAny() {
		res.SearchCriteria = new(*criteria)
	}
	return res
}

// synthesize builds the success response. It assembles the summary, echoes the
// resolved IDs, attaches each investigation type's result to its field, and adds
// cross-investigation insights when applicable.
func (m *Module) synthesize(entityIDs, investigationTypes []string, criteria SearchCriteria, results map[string]any) InvestigationResult {
	summary := &InvestigationMeta{
		EntityCount:        len(entityIDs),
		ResolvedEntityIDs:  entityIDs,
		InvestigationTypes: investigationTypes,
		Timestamp:          m.timestamp(),
		Status:             "completed",
	}
	if criteria.hasAny() {
		summary.SearchCriteria = new(criteria)
	}

	res := InvestigationResult{Summary: summary, Entities: entityIDs}
	for t, r := range results {
		switch t {
		case investigationEntityDetails:
			res.EntityDetails = r
		case investigationTimeline:
			res.TimelineAnalysis = r
		case investigationRelationships:
			res.RelationshipAnalysis = r
		case investigationRiskAssessment:
			res.RiskAssessment = r
		}
	}

	if insights := generateInsights(results, entityIDs); insights != nil {
		res.CrossInvestigationInsight = insights
	}
	return res
}
