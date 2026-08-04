// Package shield implements the Falcon Shield (SaaS Security) tools over the
// gofalcon saas_security client. It mirrors the Python falcon_mcp shield module
// 1:1: 16 tools (6 search, 9 get/list, 1 mutating dismiss) plus a query
// parameter guide resource.
//
// Shield endpoints use named query parameters rather than FQL, and each read
// operation returns full entity records in a single call, so this module does
// no two-step detail fetch. Query APIs silently return HTTP 200 with zero
// resources for unsupported filters (they do not 400), so there is no FQL-error
// data path; every transport/API failure is surfaced as a base.Error. On an
// empty result the query guide and a hint are attached to steer the caller,
// mirroring the Python module's _format_empty_or_error behavior.
package shield

import (
	"log/slog"

	"github.com/crowdstrike/gofalcon/falcon/client/saas_security"
	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/crowdstrike/falcon-mcp/internal/modules/base"
	"github.com/crowdstrike/falcon-mcp/internal/modules/registry"
)

// queryGuideURI is the MCP resource URI serving the Shield query parameter
// guide, mirroring falcon-mcp's falcon://shield/search/query-guide.
const queryGuideURI = "falcon://shield/search/query-guide"

// scopeShieldRead and scopeShieldWrite are the CrowdStrike API scopes required
// by this module's operations, surfaced on a 403 via base.APIError.
var (
	scopeShieldRead  = base.Scope{Name: "SaaS Security", Read: true}
	scopeShieldWrite = base.Scope{Name: "SaaS Security", Write: true}
)

// impactNames maps lowercase impact values to the title-case form the Shield
// checks/metrics endpoints accept, mirroring the Python module's IMPACT_NAMES.
var impactNames = map[string]string{"low": "Low", "medium": "Medium", "high": "High"}

// Factory builds the shield module from shared deps. The generated aggregator
// collects it, so the module needs no init side effect. Every read op is a
// single-call query, so the module ignores Deps.Concurrency.
var Factory registry.Factory = func(d registry.Deps) base.Module {
	return &Module{API: d.API.SaasSecurity, Logger: d.Logger}
}

// shieldAPI is the minimal slice of the gofalcon saas_security client this
// module consumes, declared next to its consumer so handlers can be tested with
// a fake.
type shieldAPI interface {
	GetSecurityChecksV3(*saas_security.GetSecurityChecksV3Params, ...saas_security.ClientOption) (*saas_security.GetSecurityChecksV3OK, error)
	GetSecurityCheckAffectedV3(*saas_security.GetSecurityCheckAffectedV3Params, ...saas_security.ClientOption) (*saas_security.GetSecurityCheckAffectedV3OK, error)
	GetSecurityCheckComplianceV3(*saas_security.GetSecurityCheckComplianceV3Params, ...saas_security.ClientOption) (*saas_security.GetSecurityCheckComplianceV3OK, error)
	GetMetricsV3(*saas_security.GetMetricsV3Params, ...saas_security.ClientOption) (*saas_security.GetMetricsV3OK, error)
	GetAlertsV3(*saas_security.GetAlertsV3Params, ...saas_security.ClientOption) (*saas_security.GetAlertsV3OK, error)
	GetActivityMonitorV3(*saas_security.GetActivityMonitorV3Params, ...saas_security.ClientOption) (*saas_security.GetActivityMonitorV3OK, error)
	GetUserInventoryV3(*saas_security.GetUserInventoryV3Params, ...saas_security.ClientOption) (*saas_security.GetUserInventoryV3OK, error)
	GetDeviceInventoryV3(*saas_security.GetDeviceInventoryV3Params, ...saas_security.ClientOption) (*saas_security.GetDeviceInventoryV3OK, error)
	GetAppInventory(*saas_security.GetAppInventoryParams, ...saas_security.ClientOption) (*saas_security.GetAppInventoryOK, error)
	GetAppInventoryUsers(*saas_security.GetAppInventoryUsersParams, ...saas_security.ClientOption) (*saas_security.GetAppInventoryUsersOK, error)
	GetAssetInventoryV3(*saas_security.GetAssetInventoryV3Params, ...saas_security.ClientOption) (*saas_security.GetAssetInventoryV3OK, error)
	GetIntegrationsV3(*saas_security.GetIntegrationsV3Params, ...saas_security.ClientOption) (*saas_security.GetIntegrationsV3OK, error)
	GetSystemUsersV3(*saas_security.GetSystemUsersV3Params, ...saas_security.ClientOption) (*saas_security.GetSystemUsersV3OK, error)
	GetSupportedSaasV3(*saas_security.GetSupportedSaasV3Params, ...saas_security.ClientOption) (*saas_security.GetSupportedSaasV3OK, error)
	GetSystemLogsV3(*saas_security.GetSystemLogsV3Params, ...saas_security.ClientOption) (*saas_security.GetSystemLogsV3OK, error)
	DismissSecurityCheckV3(*saas_security.DismissSecurityCheckV3Params, ...saas_security.ClientOption) (*saas_security.DismissSecurityCheckV3OK, error)
	DismissAffectedEntityV3(*saas_security.DismissAffectedEntityV3Params, ...saas_security.ClientOption) (*saas_security.DismissAffectedEntityV3OK, error)
}

// Module registers the Shield tools. It holds only the shared,
// concurrency-safe Falcon client and configuration; handlers are stateless and
// reentrant. Logger must be non-nil.
type Module struct {
	API    shieldAPI
	Logger *slog.Logger
}

// Name reports the module name.
func (m *Module) Name() string { return "shield" }

// Description reports a one-line summary of the module.
func (m *Module) Description() string {
	return "Query Falcon Shield (SaaS Security) posture, alerts, inventory, and activity"
}

// int64Ptr returns a pointer to int64(v) when v != 0, else nil, so a zero/unset
// paging value is omitted from the request.
func int64Ptr(v int) *int64 {
	if v == 0 {
		return nil
	}
	return new(int64(v))
}

// strPtr returns a pointer to s when non-empty, else nil.
func strPtr(s string) *string {
	if s == "" {
		return nil
	}
	return new(s)
}

// boolPtr returns b unchanged; it exists so callers can pass the *bool inputs
// straight through and read as intentful at the call site.
func boolPtr(b *bool) *bool { return b }

// normalizeImpact maps an impact value to the title-case form the Shield API
// accepts (low/medium/high -> Low/Medium/High), mirroring the Python module.
// It returns nil when impact is empty or unrecognized; an unrecognized value is
// logged and dropped rather than sent verbatim.
func (m *Module) normalizeImpact(impact string) *string {
	if impact == "" {
		return nil
	}
	if n, ok := impactNames[toLower(impact)]; ok {
		return &n
	}
	m.Logger.Warn("shield: unknown impact value", "impact", impact)
	return nil
}

// toLower lowercases ASCII letters without importing strings for one call.
func toLower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + ('a' - 'A')
		}
	}
	return string(b)
}

// RegisterTools registers the Shield tools into r. Tool names and descriptions
// are kept 1:1 with the Python shield module for client compatibility.
func (m *Module) RegisterTools(r base.Registrar) {
	m.registerSearchTools(r)
	m.registerGetTools(r)

	base.AddTool(r, &mcp.Tool{
		Name:        "dismiss_shield_check",
		Description: dismissShieldCheckDescription,
		Annotations: base.DestructiveAnnotations(true),
	}, m.dismissShieldCheck)
}

// RegisterResources publishes the Shield query parameter guide as an MCP
// resource, mirroring the Python module's falcon_shield_query_guide.
func (m *Module) RegisterResources(s *mcp.Server) {
	base.TextResource(s, queryGuideURI, "shield_query_guide",
		"Query parameter guide for Falcon Shield (SaaS Security) tools.",
		"text/markdown", queryGuide)
}

// RegisterPrompts registers no prompts for this module.
func (m *Module) RegisterPrompts(*mcp.Server) {}

// pagingSchema applies the shared limit/offset bounds used by the paginated
// Shield search tools: limit >= 1 default 10, offset >= 0.
func pagingSchema(s *jsonschema.Schema) {
	if p, ok := s.Properties["limit"]; ok {
		p.Minimum = jsonschema.Ptr(1.0)
	}
	if p, ok := s.Properties["offset"]; ok {
		p.Minimum = jsonschema.Ptr(0.0)
	}
}
