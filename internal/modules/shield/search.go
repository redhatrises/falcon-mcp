package shield

import (
	"context"

	"github.com/crowdstrike/gofalcon/falcon/client/saas_security"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/go-openapi/strfmt"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/crowdstrike/falcon-mcp/internal/modules/base"
)

// registerSearchTools registers the six Shield search tools.
func (m *Module) registerSearchTools(r base.Registrar) {
	base.AddTool(r, &mcp.Tool{
		Name:        "search_shield_checks",
		Description: searchChecksDescription,
		InputSchema: base.SchemaFor[SearchChecksInput](pagingSchema),
	}, m.searchShieldChecks)

	base.AddTool(r, &mcp.Tool{
		Name:        "search_shield_alerts",
		Description: searchAlertsDescription,
		InputSchema: base.SchemaFor[SearchAlertsInput](pagingSchema),
	}, m.searchShieldAlerts)

	base.AddTool(r, &mcp.Tool{
		Name:        "search_shield_users",
		Description: searchUsersDescription,
		InputSchema: base.SchemaFor[SearchUsersInput](pagingSchema),
	}, m.searchShieldUsers)

	base.AddTool(r, &mcp.Tool{
		Name:        "search_shield_devices",
		Description: searchDevicesDescription,
		InputSchema: base.SchemaFor[SearchDevicesInput](pagingSchema),
	}, m.searchShieldDevices)

	base.AddTool(r, &mcp.Tool{
		Name:        "search_shield_apps",
		Description: searchAppsDescription,
		InputSchema: base.SchemaFor[SearchAppsInput](pagingSchema),
	}, m.searchShieldApps)

	base.AddTool(r, &mcp.Tool{
		Name:        "search_shield_data_shares",
		Description: searchDataSharesDescription,
		InputSchema: base.SchemaFor[SearchDataSharesInput](pagingSchema),
	}, m.searchShieldDataShares)
}

// --- search_shield_checks ---

const searchChecksDescription = "Search individual Falcon Shield (SaaS Security) posture checks with filtering.\n\n" +
	"Use this to find specific failing checks by status, impact, integration, or type; consult " +
	"falcon://shield/search/query-guide for valid filter values. Returns check records containing " +
	"id, name, status, impact level, affected entity count, and remediation plan."

// SearchChecksInput is the input for falcon_search_shield_checks.
type SearchChecksInput struct {
	ID            string `json:"id,omitempty" jsonschema:"Specific security check ID."`
	Status        string `json:"status,omitempty" jsonschema:"Filter by status: Passed, Failed, Dismissed, Pending, Can't Run, Stale."`
	Impact        string `json:"impact,omitempty" jsonschema:"Filter by impact: Low, Medium, High."`
	IntegrationID string `json:"integration_id,omitempty" jsonschema:"Comma-separated IDs of SaaS integrations to filter by. Use get_shield_integrations to retrieve available integration IDs."`
	Compliance    *bool  `json:"compliance,omitempty" jsonschema:"If true, return only checks that are defined as part of a compliance framework (SOC 2, CIS, NIST, etc.) at the catalog level."`
	CheckType     string `json:"check_type,omitempty" jsonschema:"Filter by type: apps, devices, users, assets, permissions, custom, Falcon Shield Security Check."`
	CheckTags     string `json:"check_tags,omitempty" jsonschema:"Comma-separated tag filters."`
	Limit         int    `json:"limit,omitempty" jsonschema:"Maximum number of results to return (default: 10)."`
	Offset        int    `json:"offset,omitempty" jsonschema:"Zero-based offset for pagination. Omit or set to 0 for the first page."`
}

func (m *Module) searchShieldChecks(ctx context.Context, _ *mcp.CallToolRequest, in SearchChecksInput) (*mcp.CallToolResult, base.SearchResult[*models.SecurityCheckWithComplianceGetSecurityChecks], error) {
	var zero base.SearchResult[*models.SecurityCheckWithComplianceGetSecurityChecks]
	p := saas_security.NewGetSecurityChecksV3ParamsWithContext(ctx)
	p.ID = strPtr(in.ID)
	p.Status = strPtr(in.Status)
	p.Impact = m.normalizeImpact(in.Impact)
	p.IntegrationID = strPtr(in.IntegrationID)
	p.Compliance = boolPtr(in.Compliance)
	p.CheckType = strPtr(in.CheckType)
	p.CheckTags = strPtr(in.CheckTags)
	p.Limit = int64Ptr(defaultLimit(in.Limit, 10))
	p.Offset = int64Ptr(in.Offset)

	resp, err := m.API.GetSecurityChecksV3(p)
	if e := base.APIError(err, resp, scopeShieldRead); e != nil {
		return nil, zero, e
	}
	return nil, foundOrGuided(resp.Payload.Resources, resp.Payload.Meta), nil
}

// --- search_shield_alerts ---

const searchAlertsDescription = "Search Falcon Shield (SaaS Security) alerts for monitored SaaS applications.\n\n" +
	"Use this to find configuration drift, degraded checks, integration failures, or active threats; " +
	"paginate by passing `pagination.next` from the previous result as the `last_id` parameter. " +
	"Returns alert objects containing id, type, integration details, timestamp, and severity."

// SearchAlertsInput is the input for falcon_search_shield_alerts.
//
// Pagination is cursor-only: pass pagination.next from the previous result as
// last_id.
type SearchAlertsInput struct {
	ID            string `json:"id,omitempty" jsonschema:"Specific alert ID."`
	Type          string `json:"type,omitempty" jsonschema:"Filter by type: configuration_drift, check_degraded, integration_failure, threat."`
	IntegrationID string `json:"integration_id,omitempty" jsonschema:"Comma-separated IDs of SaaS integrations to filter by. Use get_shield_integrations to retrieve available integration IDs."`
	FromDate      string `json:"from_date,omitempty" jsonschema:"Start date (YYYY-MM-DD)."`
	ToDate        string `json:"to_date,omitempty" jsonschema:"End date (YYYY-MM-DD)."`
	Ascending     *bool  `json:"ascending,omitempty" jsonschema:"If true, return oldest alerts first. If false or omitted, return newest first."`
	Limit         int    `json:"limit,omitempty" jsonschema:"Maximum number of results to return (default: 10)."`
	LastID        string `json:"last_id,omitempty" jsonschema:"Cursor-based pagination token. Pass pagination.next from the previous result to fetch the next page."`
}

func (m *Module) searchShieldAlerts(ctx context.Context, _ *mcp.CallToolRequest, in SearchAlertsInput) (*mcp.CallToolResult, base.SearchResult[*models.AlertGetAlertsResponse], error) {
	var zero base.SearchResult[*models.AlertGetAlertsResponse]
	p := saas_security.NewGetAlertsV3ParamsWithContext(ctx)
	p.ID = strPtr(in.ID)
	p.Type = strPtr(in.Type)
	p.IntegrationID = strPtr(in.IntegrationID)
	p.Ascending = boolPtr(in.Ascending)
	p.LastID = strPtr(in.LastID)
	p.Limit = int64Ptr(defaultLimit(in.Limit, 10))
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

	resp, err := m.API.GetAlertsV3(p)
	if e := base.APIError(err, resp, scopeShieldRead); e != nil {
		return nil, zero, e
	}
	return nil, foundOrGuided(resp.Payload.Resources, resp.Payload.Meta), nil
}

// --- search_shield_users ---

const searchUsersDescription = "List end-users discovered across Falcon Shield (SaaS Security) connected SaaS applications.\n\n" +
	"Use this to audit user access across your SaaS estate or identify over-privileged or stale accounts; " +
	"for Shield platform administrators instead of SaaS app end-users, use get_shield_system_users. " +
	"Returns user objects containing email, display name, connected application details, privilege status, and exposure metrics."

// SearchUsersInput is the input for falcon_search_shield_users.
type SearchUsersInput struct {
	IntegrationID  string `json:"integration_id,omitempty" jsonschema:"Comma-separated IDs of SaaS integrations to filter by. Use get_shield_integrations to retrieve available integration IDs."`
	Email          string `json:"email,omitempty" jsonschema:"Filter results to users matching this email address."`
	PrivilegedOnly *bool  `json:"privileged_only,omitempty" jsonschema:"If true, return only users with privileged or administrative roles."`
	Limit          int    `json:"limit,omitempty" jsonschema:"Maximum number of results to return (default: 10)."`
	Offset         int    `json:"offset,omitempty" jsonschema:"Zero-based offset for pagination. Omit or set to 0 for the first page."`
}

func (m *Module) searchShieldUsers(ctx context.Context, _ *mcp.CallToolRequest, in SearchUsersInput) (*mcp.CallToolResult, base.SearchResult[*models.UserGetUserInventory], error) {
	var zero base.SearchResult[*models.UserGetUserInventory]
	p := saas_security.NewGetUserInventoryV3ParamsWithContext(ctx)
	p.IntegrationID = strPtr(in.IntegrationID)
	p.Email = strPtr(in.Email)
	p.PrivilegedOnly = boolPtr(in.PrivilegedOnly)
	p.Limit = int64Ptr(defaultLimit(in.Limit, 10))
	p.Offset = int64Ptr(in.Offset)

	resp, err := m.API.GetUserInventoryV3(p)
	if e := base.APIError(err, resp, scopeShieldRead); e != nil {
		return nil, zero, e
	}
	return nil, foundOrGuided(resp.Payload.Resources, resp.Payload.Meta), nil
}

// --- search_shield_devices ---

const searchDevicesDescription = "List devices registered to users in Falcon Shield (SaaS Security) connected SaaS applications.\n\n" +
	"Use this to identify unmanaged or unassociated devices in your SaaS estate; note that this returns " +
	"devices from SaaS provider records, not Falcon sensor inventory — use search_hosts for that. " +
	"Returns device objects containing device name, owner email, compliance posture, and management status."

// SearchDevicesInput is the input for falcon_search_shield_devices.
type SearchDevicesInput struct {
	IntegrationID       string `json:"integration_id,omitempty" jsonschema:"Comma-separated IDs of SaaS integrations to filter by. Use get_shield_integrations to retrieve available integration IDs."`
	Email               string `json:"email,omitempty" jsonschema:"Filter by user email associated with the device."`
	PrivilegedOnly      *bool  `json:"privileged_only,omitempty" jsonschema:"If true, return only devices belonging to users with privileged roles."`
	UnassociatedDevices *bool  `json:"unassociated_devices,omitempty" jsonschema:"If true, include devices not associated with a known user."`
	Limit               int    `json:"limit,omitempty" jsonschema:"Maximum number of results to return (default: 10)."`
	Offset              int    `json:"offset,omitempty" jsonschema:"Zero-based offset for pagination. Omit or set to 0 for the first page."`
}

func (m *Module) searchShieldDevices(ctx context.Context, _ *mcp.CallToolRequest, in SearchDevicesInput) (*mcp.CallToolResult, base.SearchResult[*models.DeviceGetDeviceInventory], error) {
	var zero base.SearchResult[*models.DeviceGetDeviceInventory]
	p := saas_security.NewGetDeviceInventoryV3ParamsWithContext(ctx)
	p.IntegrationID = strPtr(in.IntegrationID)
	p.Email = strPtr(in.Email)
	p.PrivilegedOnly = boolPtr(in.PrivilegedOnly)
	p.UnassociatedDevices = boolPtr(in.UnassociatedDevices)
	p.Limit = int64Ptr(defaultLimit(in.Limit, 10))
	p.Offset = int64Ptr(in.Offset)

	resp, err := m.API.GetDeviceInventoryV3(p)
	if e := base.APIError(err, resp, scopeShieldRead); e != nil {
		return nil, zero, e
	}
	return nil, foundOrGuided(resp.Payload.Resources, resp.Payload.Meta), nil
}

// --- search_shield_apps ---

const searchAppsDescription = "List third-party applications (OAuth apps, API tokens, browser extensions, service principals) " +
	"with access to Falcon Shield (SaaS Security) monitored platforms.\n\n" +
	"Use this to audit app access across your SaaS estate; use the item_id from results with " +
	"get_shield_app_users to see who authorized a specific app. Returns app objects containing " +
	"item_id, name, type, status, access_level, granted scopes, and user count."

// SearchAppsInput is the input for falcon_search_shield_apps.
type SearchAppsInput struct {
	Type          string `json:"type,omitempty" jsonschema:"App type: oauth, sign_in, api_token, browser_extension, etc."`
	Status        string `json:"status,omitempty" jsonschema:"Status: approved, in review, rejected, unclassified."`
	AccessLevel   string `json:"access_level,omitempty" jsonschema:"Access level: high, medium, low, none."`
	IntegrationID string `json:"integration_id,omitempty" jsonschema:"Comma-separated IDs of SaaS integrations to filter by. Use get_shield_integrations to retrieve available integration IDs."`
	Scopes        string `json:"scopes,omitempty" jsonschema:"Comma-separated OAuth scope filter."`
	Users         string `json:"users,omitempty" jsonschema:"Filter by user association. Format: 'is equal <email>' for exact match, or 'contains <value>' for partial match. Example: 'is equal user@example.com'."`
	Groups        string `json:"groups,omitempty" jsonschema:"Group filter."`
	LastActivity  string `json:"last_activity,omitempty" jsonschema:"Filter by time since the app was last active. Format: 'was N' (active within N days) or 'was not N' (inactive for more than N days). Example: 'was not 90'."`
	Limit         int    `json:"limit,omitempty" jsonschema:"Maximum number of results to return (default: 10)."`
	Offset        int    `json:"offset,omitempty" jsonschema:"Zero-based offset for pagination. Omit or set to 0 for the first page."`
}

func (m *Module) searchShieldApps(ctx context.Context, _ *mcp.CallToolRequest, in SearchAppsInput) (*mcp.CallToolResult, base.SearchResult[*models.AppAppInventory], error) {
	var zero base.SearchResult[*models.AppAppInventory]
	p := saas_security.NewGetAppInventoryParamsWithContext(ctx)
	p.Type = strPtr(in.Type)
	p.Status = strPtr(in.Status)
	p.AccessLevel = strPtr(in.AccessLevel)
	p.IntegrationID = strPtr(in.IntegrationID)
	p.Scopes = strPtr(in.Scopes)
	p.Users = strPtr(in.Users)
	p.Groups = strPtr(in.Groups)
	p.LastActivity = strPtr(in.LastActivity)
	p.Limit = int64Ptr(defaultLimit(in.Limit, 10))
	p.Offset = int64Ptr(in.Offset)

	resp, err := m.API.GetAppInventory(p)
	if e := base.APIError(err, resp, scopeShieldRead); e != nil {
		return nil, zero, e
	}
	return nil, foundOrGuided(resp.Payload.Resources, resp.Payload.Meta), nil
}

// --- search_shield_data_shares ---

const searchDataSharesDescription = "List files and resources shared externally across Falcon Shield (SaaS Security) monitored applications.\n\n" +
	"Use this to identify overshared or externally exposed files such as Google Drive documents shared " +
	"outside the organization. Returns resource objects containing resource name, type, owner, sharing " +
	"access level, password protection status, and last access/modification timestamps."

// SearchDataSharesInput is the input for falcon_search_shield_data_shares.
type SearchDataSharesInput struct {
	IntegrationID        string `json:"integration_id,omitempty" jsonschema:"Comma-separated IDs of SaaS integrations to filter by. Use get_shield_integrations to retrieve available integration IDs."`
	ResourceType         string `json:"resource_type,omitempty" jsonschema:"File type filter (e.g., PDF, XLSX)."`
	AccessLevel          string `json:"access_level,omitempty" jsonschema:"Sharing access level filter (comma-separated). Values: public_link, external_user, org_wide, internal."`
	ResourceName         string `json:"resource_name,omitempty" jsonschema:"Filter to resources whose name contains this value."`
	ResourceOwner        string `json:"resource_owner,omitempty" jsonschema:"Filter to resources whose owner name or email contains this value."`
	ResourceOwnerEnabled *bool  `json:"resource_owner_enabled,omitempty" jsonschema:"If true, return only resources with an active owner account. If false, only disabled owner accounts."`
	PasswordProtected    *bool  `json:"password_protected,omitempty" jsonschema:"If true, return only password-protected resources. If false, only unprotected resources."`
	LastAccessed         string `json:"last_accessed,omitempty" jsonschema:"Filter by time since the resource was last accessed. Format: 'was N' (within N days) or 'was not N' (not accessed in more than N days). Example: 'was not 30'."`
	LastModified         string `json:"last_modified,omitempty" jsonschema:"Filter by time since the resource was last modified. Format: 'was N' (within N days) or 'was not N' (not modified in more than N days). Example: 'was not 30'."`
	UnmanagedDomain      string `json:"unmanaged_domain,omitempty" jsonschema:"Filter to resources shared with external (non-organization) domains. Comma-separated domain names (e.g., 'gmail.com,yahoo.com')."`
	Limit                int    `json:"limit,omitempty" jsonschema:"Maximum number of results to return (default: 10)."`
	Offset               int    `json:"offset,omitempty" jsonschema:"Zero-based offset for pagination. Omit or set to 0 for the first page."`
}

func (m *Module) searchShieldDataShares(ctx context.Context, _ *mcp.CallToolRequest, in SearchDataSharesInput) (*mcp.CallToolResult, base.SearchResult[*models.AssetGetAssetInventory], error) {
	var zero base.SearchResult[*models.AssetGetAssetInventory]
	p := saas_security.NewGetAssetInventoryV3ParamsWithContext(ctx)
	p.IntegrationID = strPtr(in.IntegrationID)
	p.ResourceType = strPtr(in.ResourceType)
	p.AccessLevel = strPtr(in.AccessLevel)
	p.ResourceName = strPtr(in.ResourceName)
	p.ResourceOwner = strPtr(in.ResourceOwner)
	p.ResourceOwnerEnabled = boolPtr(in.ResourceOwnerEnabled)
	p.PasswordProtected = boolPtr(in.PasswordProtected)
	p.LastAccessed = strPtr(in.LastAccessed)
	p.LastModified = strPtr(in.LastModified)
	p.UnmanagedDomain = strPtr(in.UnmanagedDomain)
	p.Limit = int64Ptr(defaultLimit(in.Limit, 10))
	p.Offset = int64Ptr(in.Offset)

	resp, err := m.API.GetAssetInventoryV3(p)
	if e := base.APIError(err, resp, scopeShieldRead); e != nil {
		return nil, zero, e
	}
	return nil, foundOrGuided(resp.Payload.Resources, resp.Payload.Meta), nil
}

// defaultLimit returns v when v > 0, else def, mirroring the Python default of
// 10 (or 100 for activity/logs) applied when the caller omits limit.
func defaultLimit(v, def int) int {
	if v > 0 {
		return v
	}
	return def
}

// parseDate parses a Shield date/datetime string (YYYY-MM-DD or ISO 8601) into
// a *strfmt.DateTime, returning nil for an empty string. An unparseable value
// is a caller input error.
func parseDate(field, s string) (*strfmt.DateTime, error) {
	if s == "" {
		return nil, nil
	}
	dt, err := strfmt.ParseDateTime(s)
	if err != nil {
		return nil, wrapInvalid("shield search", field+": invalid date "+s+" (want YYYY-MM-DD or ISO 8601)")
	}
	return &dt, nil
}
