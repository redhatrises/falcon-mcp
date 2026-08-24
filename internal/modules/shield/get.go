package shield

import (
	"context"

	"github.com/crowdstrike/gofalcon/falcon/client/saas_security"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/crowdstrike/falcon-mcp/internal/modules/base"
)

// registerGetTools registers the nine read-only Shield get/list tools.
func (m *Module) registerGetTools(r base.Registrar) {
	base.AddTool(r, &mcp.Tool{
		Name:        "get_shield_check_affected_entities",
		Description: getAffectedDescription,
		InputSchema: base.SchemaFor[GetAffectedInput](pagingSchema),
	}, m.getShieldCheckAffectedEntities)

	base.AddTool(r, &mcp.Tool{
		Name:        "get_shield_posture_metrics",
		Description: getMetricsDescription,
		InputSchema: base.SchemaFor[GetMetricsInput](pagingSchema),
	}, m.getShieldPostureMetrics)

	base.AddTool(r, &mcp.Tool{
		Name:        "get_shield_check_compliance",
		Description: getComplianceDescription,
	}, m.getShieldCheckCompliance)

	base.AddTool(r, &mcp.Tool{
		Name:        "get_shield_activity_monitor",
		Description: getActivityDescription,
		InputSchema: base.SchemaFor[GetActivityInput](func(s *jsonschema.Schema) {
			if p, ok := s.Properties["limit"]; ok {
				p.Minimum = jsonschema.Ptr(1.0)
				p.Maximum = jsonschema.Ptr(10000.0)
			}
			if p, ok := s.Properties["skip"]; ok {
				p.Minimum = jsonschema.Ptr(0.0)
			}
		}),
	}, m.getShieldActivityMonitor)

	base.AddTool(r, &mcp.Tool{
		Name:        "get_shield_app_users",
		Description: getAppUsersDescription,
	}, m.getShieldAppUsers)

	base.AddTool(r, &mcp.Tool{
		Name:        "get_shield_integrations",
		Description: getIntegrationsDescription,
	}, m.getShieldIntegrations)

	base.AddTool(r, &mcp.Tool{
		Name:        "get_shield_system_users",
		Description: getSystemUsersDescription,
	}, m.getShieldSystemUsers)

	base.AddTool(r, &mcp.Tool{
		Name:        "get_shield_supported_saas",
		Description: getSupportedSaasDescription,
	}, m.getShieldSupportedSaas)

	base.AddTool(r, &mcp.Tool{
		Name:        "get_shield_system_logs",
		Description: getSystemLogsDescription,
		InputSchema: base.SchemaFor[GetSystemLogsInput](pagingSchema),
	}, m.getShieldSystemLogs)
}

// --- get_shield_check_affected_entities ---

const getAffectedDescription = "Retrieve the specific entities (users, apps, or devices) that are violating a given Falcon Shield posture check.\n\n" +
	"Use this after search_shield_checks to drill into which entities are failing a specific check. Returns entity " +
	"objects with entity name, type, and relevant security details."

// GetAffectedInput is the input for falcon_get_shield_check_affected_entities.
type GetAffectedInput struct {
	ID     string `json:"id" jsonschema:"Security check ID. Obtain from the id field in results returned by search_shield_checks."`
	Limit  int    `json:"limit,omitempty" jsonschema:"Maximum number of results to return (default: 10)."`
	Offset int    `json:"offset,omitempty" jsonschema:"Zero-based offset for pagination. Omit or set to 0 for the first page."`
}

func (m *Module) getShieldCheckAffectedEntities(ctx context.Context, _ *mcp.CallToolRequest, in GetAffectedInput) (*mcp.CallToolResult, base.SearchResult[*models.AffectedEntityGetAffected], error) {
	var zero base.SearchResult[*models.AffectedEntityGetAffected]
	if in.ID == "" {
		return nil, zero, wrapInvalid("get shield check affected entities", "id must not be empty")
	}
	p := saas_security.NewGetSecurityCheckAffectedV3ParamsWithContext(ctx)
	p.ID = in.ID
	p.Limit = int64Ptr(defaultLimit(in.Limit, 10))
	p.Offset = int64Ptr(in.Offset)

	resp, err := m.API.GetSecurityCheckAffectedV3(p)
	if e := base.APIError(err, resp, scopeShieldRead); e != nil {
		return nil, zero, e
	}
	return nil, foundOrGuided(resp.Payload.Resources, resp.Payload.Meta), nil
}

// --- get_shield_posture_metrics ---

const getMetricsDescription = "Get aggregated Falcon Shield (SaaS Security) posture metrics for a dashboard or summary view.\n\n" +
	"Use this for a high-level overview of your SaaS security posture; for individual check records " +
	"with remediation details, use search_shield_checks instead. Returns total check counts, overall " +
	"score percentage, and a breakdown of checks by status across connected SaaS applications."

// GetMetricsInput is the input for falcon_get_shield_posture_metrics.
type GetMetricsInput struct {
	Status        string `json:"status,omitempty" jsonschema:"Filter by status: Passed, Failed, Dismissed, Pending, Can't Run, Stale."`
	Impact        string `json:"impact,omitempty" jsonschema:"Filter by impact: Low, Medium, High."`
	IntegrationID string `json:"integration_id,omitempty" jsonschema:"Comma-separated IDs of SaaS integrations to filter by. Use get_shield_integrations to retrieve available integration IDs."`
	Compliance    *bool  `json:"compliance,omitempty" jsonschema:"If true, return only metrics for checks that are defined as part of a compliance framework (SOC 2, CIS, NIST, etc.) at the catalog level."`
	CheckType     string `json:"check_type,omitempty" jsonschema:"Filter by type: apps, devices, users, assets, permissions, custom, Falcon Shield Security Check."`
	Limit         int    `json:"limit,omitempty" jsonschema:"Maximum number of results to return (default: 10)."`
	Offset        int    `json:"offset,omitempty" jsonschema:"Zero-based offset for pagination. Omit or set to 0 for the first page."`
}

func (m *Module) getShieldPostureMetrics(ctx context.Context, _ *mcp.CallToolRequest, in GetMetricsInput) (*mcp.CallToolResult, base.SearchResult[*models.SecurityCheckMetricsGetMetrics], error) {
	var zero base.SearchResult[*models.SecurityCheckMetricsGetMetrics]
	p := saas_security.NewGetMetricsV3ParamsWithContext(ctx)
	p.Status = base.PtrIfSet(in.Status)
	p.Impact = m.normalizeImpact(in.Impact)
	p.IntegrationID = base.PtrIfSet(in.IntegrationID)
	p.Compliance = in.Compliance
	p.CheckType = base.PtrIfSet(in.CheckType)
	p.Limit = int64Ptr(defaultLimit(in.Limit, 10))
	p.Offset = int64Ptr(in.Offset)

	resp, err := m.API.GetMetricsV3(p)
	if e := base.APIError(err, resp, scopeShieldRead); e != nil {
		return nil, zero, e
	}
	return nil, foundOrGuided(resp.Payload.Resources, resp.Payload.Meta), nil
}

// --- get_shield_check_compliance ---

const getComplianceDescription = "Retrieve the compliance framework mappings for a specific Falcon Shield posture check.\n\n" +
	"Use this after search_shield_checks to understand the regulatory impact of a failing check. " +
	"Returns compliance objects identifying the framework (e.g., SOC 2, CIS, NIST, PCI DSS), " +
	"control ID, and control description that the check satisfies."

// GetComplianceInput is the input for falcon_get_shield_check_compliance.
type GetComplianceInput struct {
	ID string `json:"id" jsonschema:"Security check ID. Obtain from the id field in results returned by search_shield_checks."`
}

func (m *Module) getShieldCheckCompliance(ctx context.Context, _ *mcp.CallToolRequest, in GetComplianceInput) (*mcp.CallToolResult, base.SearchResult[*models.CriteriaGetSecurityCompliance], error) {
	var zero base.SearchResult[*models.CriteriaGetSecurityCompliance]
	if in.ID == "" {
		return nil, zero, wrapInvalid("get shield check compliance", "id must not be empty")
	}
	p := saas_security.NewGetSecurityCheckComplianceV3ParamsWithContext(ctx)
	p.ID = in.ID

	resp, err := m.API.GetSecurityCheckComplianceV3(p)
	if e := base.APIError(err, resp, scopeShieldRead); e != nil {
		return nil, zero, e
	}
	return nil, foundOrGuided(resp.Payload.Resources, resp.Payload.Meta), nil
}

// --- get_shield_activity_monitor ---

const getActivityDescription = "Get events from the Falcon Shield (SaaS Security) activity monitor; data is retained for 180 days.\n\n" +
	"Use this to investigate user activity, threats, or IoC events across connected SaaS platforms; " +
	"when filtering by integration_id, category, or actor, the date range must be within 24 hours. " +
	"Returns activity event objects including timestamp, event name, actor identity, integration, category, and location details. " +
	"This endpoint does not report a total count, so `pagination.total` is always null — " +
	"page through results with `pagination.next`/`skip` rather than asking \"how many\"."

// GetActivityInput is the input for falcon_get_shield_activity_monitor.
type GetActivityInput struct {
	IntegrationID string `json:"integration_id,omitempty" jsonschema:"Comma-separated IDs of SaaS integrations to filter by. Use get_shield_integrations to retrieve available integration IDs."`
	Actor         string `json:"actor,omitempty" jsonschema:"Filter by the identity that performed the activity (e.g., user email, service account name). This is not a threat actor name."`
	Category      string `json:"category,omitempty" jsonschema:"Comma-separated activity categories: Events, Threat, IoC."`
	Projection    string `json:"projection,omitempty" jsonschema:"Comma-separated list of fields to include in each event. Valid fields: timestamp_utc, severity, datetime, event_name, actor, integration_id, integration_name, type, category, created_by, ip, asn_name, country, browser, os, target, object_type, object, status. Omit for default fields."`
	FromDate      string `json:"from_date,omitempty" jsonschema:"Start datetime (ISO 8601)."`
	ToDate        string `json:"to_date,omitempty" jsonschema:"End datetime (ISO 8601)."`
	Limit         int    `json:"limit,omitempty" jsonschema:"Maximum number of results to return (default: 100, max: 10000)."`
	Skip          int    `json:"skip,omitempty" jsonschema:"Pagination offset. Use meta.pagination.offset from the previous response for subsequent pages."`
}

func (m *Module) getShieldActivityMonitor(ctx context.Context, _ *mcp.CallToolRequest, in GetActivityInput) (*mcp.CallToolResult, base.SearchResult[*models.Activity2GetActivityMonitor], error) {
	var zero base.SearchResult[*models.Activity2GetActivityMonitor]
	p := saas_security.NewGetActivityMonitorV3ParamsWithContext(ctx)
	p.IntegrationID = base.PtrIfSet(in.IntegrationID)
	p.Actor = base.PtrIfSet(in.Actor)
	p.Category = base.PtrIfSet(in.Category)
	p.Projection = base.PtrIfSet(in.Projection)
	p.Limit = int64Ptr(defaultLimit(in.Limit, 100))
	p.Skip = int64Ptr(in.Skip)
	if from, err := parseDate("from_date", in.FromDate); err != nil {
		return nil, zero, err
	} else {
		p.FromDate = from
	}
	if to, err := parseDate("to_date", in.ToDate); err != nil {
		return nil, zero, err
	} else {
		p.ToDate = to
	}

	resp, err := m.API.GetActivityMonitorV3(p)
	if e := base.APIError(err, resp, scopeShieldRead); e != nil {
		return nil, zero, e
	}
	return nil, foundOrGuided(resp.Payload.Resources, resp.Payload.Meta), nil
}

// --- get_shield_app_users ---

const getAppUsersDescription = "Retrieve the users who have authorized or are associated with a specific third-party app in Falcon Shield.\n\n" +
	"Use this after search_shield_apps to drill into a specific app's user population. " +
	"Returns user objects including email, display name, and granted permissions."

// GetAppUsersInput is the input for falcon_get_shield_app_users.
type GetAppUsersInput struct {
	ItemID string `json:"item_id" jsonschema:"Composite app identifier in the format integration_id|||app_id. Obtain from the item_id field in results returned by search_shield_apps."`
}

func (m *Module) getShieldAppUsers(ctx context.Context, _ *mcp.CallToolRequest, in GetAppUsersInput) (*mcp.CallToolResult, base.SearchResult[*models.AppUsersAppInventoryUsers], error) {
	var zero base.SearchResult[*models.AppUsersAppInventoryUsers]
	if in.ItemID == "" {
		return nil, zero, wrapInvalid("get shield app users", "item_id must not be empty")
	}
	p := saas_security.NewGetAppInventoryUsersParamsWithContext(ctx)
	p.ItemID = in.ItemID

	resp, err := m.API.GetAppInventoryUsers(p)
	if e := base.APIError(err, resp, scopeShieldRead); e != nil {
		return nil, zero, e
	}
	return nil, foundOrGuided(resp.Payload.Resources, resp.Payload.Meta), nil
}

// --- get_shield_integrations ---

const getIntegrationsDescription = "List all SaaS integrations connected to Falcon Shield and their current connection status.\n\n" +
	"Call this first when starting a Shield investigation to discover available integration IDs, " +
	"which are required as input to most other Shield tools. Returns integration objects containing " +
	"integration_id, SaaS platform name, connection health, and last sync time."

// GetIntegrationsInput is the input for falcon_get_shield_integrations.
type GetIntegrationsInput struct {
	SaasID string `json:"saas_id,omitempty" jsonschema:"Comma-separated SaaS platform IDs to filter by."`
}

func (m *Module) getShieldIntegrations(ctx context.Context, _ *mcp.CallToolRequest, in GetIntegrationsInput) (*mcp.CallToolResult, base.SearchResult[*models.AccountIntegrationGetIntegrations], error) {
	var zero base.SearchResult[*models.AccountIntegrationGetIntegrations]
	p := saas_security.NewGetIntegrationsV3ParamsWithContext(ctx)
	p.SaasID = base.PtrIfSet(in.SaasID)

	resp, err := m.API.GetIntegrationsV3(p)
	if e := base.APIError(err, resp, scopeShieldRead); e != nil {
		return nil, zero, e
	}
	return nil, foundOrGuided(resp.Payload.Resources, resp.Payload.Meta), nil
}

// --- get_shield_system_users ---

const getSystemUsersDescription = "List Falcon Shield (SaaS Security) platform administrators.\n\n" +
	"Use this to audit console-level admin accounts; for end-users of connected SaaS applications, " +
	"use search_shield_users instead. Returns system-level user objects including email, role, and MFA status."

func (m *Module) getShieldSystemUsers(ctx context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, base.SearchResult[*models.SystemUserGetSystemUsers], error) {
	var zero base.SearchResult[*models.SystemUserGetSystemUsers]
	p := saas_security.NewGetSystemUsersV3ParamsWithContext(ctx)

	resp, err := m.API.GetSystemUsersV3(p)
	if e := base.APIError(err, resp, scopeShieldRead); e != nil {
		return nil, zero, e
	}
	return nil, foundOrGuided(resp.Payload.Resources, resp.Payload.Meta), nil
}

// --- get_shield_supported_saas ---

const getSupportedSaasDescription = "List SaaS platforms supported by Falcon Shield for integration.\n\n" +
	"Use this to discover which SaaS applications can be connected before setting up new integrations. " +
	"Returns supported SaaS platform objects including platform name and ID."

func (m *Module) getShieldSupportedSaas(ctx context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, base.SearchResult[*models.SupportedIntegrationGetSupportedSaas], error) {
	var zero base.SearchResult[*models.SupportedIntegrationGetSupportedSaas]
	p := saas_security.NewGetSupportedSaasV3ParamsWithContext(ctx)

	resp, err := m.API.GetSupportedSaasV3(p)
	if e := base.APIError(err, resp, scopeShieldRead); e != nil {
		return nil, zero, e
	}
	return nil, foundOrGuided(resp.Payload.Resources, resp.Payload.Meta), nil
}

// --- get_shield_system_logs ---

const getSystemLogsDescription = "Retrieve Falcon Shield (SaaS Security) system audit logs; data is retained for 90 days.\n\n" +
	"Use date range filters to narrow results, covering events such as integration creates, check " +
	"dismissals, and data syncs. Returns log objects containing timestamp, event type, actor, and details."

// GetSystemLogsInput is the input for falcon_get_shield_system_logs.
type GetSystemLogsInput struct {
	FromDate   string `json:"from_date,omitempty" jsonschema:"Start date (YYYY-MM-DD)."`
	ToDate     string `json:"to_date,omitempty" jsonschema:"End date (YYYY-MM-DD)."`
	Limit      int    `json:"limit,omitempty" jsonschema:"Maximum number of results to return (default: 100)."`
	Offset     int    `json:"offset,omitempty" jsonschema:"Zero-based offset for pagination. Omit or set to 0 for the first page."`
	TotalCount *bool  `json:"total_count,omitempty" jsonschema:"If true, include total count of matching logs in the response metadata."`
}

func (m *Module) getShieldSystemLogs(ctx context.Context, _ *mcp.CallToolRequest, in GetSystemLogsInput) (*mcp.CallToolResult, base.SearchResult[*models.SystemLogGetSystemLogs], error) {
	var zero base.SearchResult[*models.SystemLogGetSystemLogs]
	p := saas_security.NewGetSystemLogsV3ParamsWithContext(ctx)
	p.Limit = int64Ptr(defaultLimit(in.Limit, 100))
	p.Offset = int64Ptr(in.Offset)
	p.TotalCount = in.TotalCount
	if from, err := parseDate("from_date", in.FromDate); err != nil {
		return nil, zero, err
	} else {
		p.FromDate = from
	}
	if to, err := parseDate("to_date", in.ToDate); err != nil {
		return nil, zero, err
	} else {
		p.ToDate = to
	}

	resp, err := m.API.GetSystemLogsV3(p)
	if e := base.APIError(err, resp, scopeShieldRead); e != nil {
		return nil, zero, e
	}
	return nil, foundOrGuided(resp.Payload.Resources, resp.Payload.Meta), nil
}
