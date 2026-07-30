// Package idp implements the falcon_idp_investigate_entity tool over the
// gofalcon identity_protection GraphQL client: a single read-only investigation
// tool that resolves Identity Protection entities from a mix of identifiers
// (IDs, names, emails, IPs, domains) and then runs one or more investigation
// types against them — entity details, activity timeline, relationship graph,
// and risk assessment.
//
// All Falcon access goes through a single endpoint,
// POST /identity-protection/combined/graphql/v1 (gofalcon operation
// APIPreemptProxyPostGraphql), driven by GraphQL query strings this module
// builds. Invalid input (no identifier, a bare wildcard) and "no entities
// found" are returned as data on the result envelope rather than as Go errors;
// only a transport/API failure surfaces as a *base.Error.
package idp

import (
	"log/slog"
	"time"

	"github.com/crowdstrike/gofalcon/falcon/client/identity_protection"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/crowdstrike/falcon-mcp/internal/modules/base"
	"github.com/crowdstrike/falcon-mcp/internal/modules/registry"
)

// scopeIdentityProtection is the CrowdStrike API scope required by this module's
// GraphQL operation. Surfaced on a 403 via base.APIError.
var scopeIdentityProtection = base.Scope{Name: "Identity Protection Entities", Read: true}

// Investigation type identifiers.
const (
	investigationEntityDetails  = "entity_details"
	investigationTimeline       = "timeline_analysis"
	investigationRelationships  = "relationship_analysis"
	investigationRiskAssessment = "risk_assessment"
)

// Bounds on the investigation parameters, advertised on the served schema and
// enforced by the MCP layer before a call reaches the handler.
const (
	minRelationshipDepth = 1
	maxRelationshipDepth = 3
	defaultDepth         = 2

	minLimit     = 1
	maxLimit     = 200
	defaultLimit = 10
)

// idpAPI is the minimal slice of the gofalcon identity_protection client this
// module consumes, declared next to its consumer so handlers can be tested with
// a fake. The single GraphQL endpoint backs every investigation.
type idpAPI interface {
	APIPreemptProxyPostGraphql(params *identity_protection.APIPreemptProxyPostGraphqlParams, opts ...identity_protection.ClientOption) (*identity_protection.APIPreemptProxyPostGraphqlOK, error)
}

// Factory builds the idp module from shared deps. The generated aggregator
// (internal/mcpserver) collects it, so the module needs no init side effect.
// This is a GraphQL-per-entity module with no bulk detail-fetch fan-out, so it
// ignores Deps.Concurrency.
var Factory registry.Factory = func(d registry.Deps) base.Module {
	return &Module{API: d.API.IdentityProtection, Logger: d.Logger}
}

// Module registers the idp tool. It holds only the shared, concurrency-safe
// Falcon client; handlers are stateless. Logger must be non-nil. now returns the
// current time and is overridable in tests for deterministic timestamps.
type Module struct {
	API    idpAPI
	Logger *slog.Logger
	now    func() time.Time
}

// Name reports the module name.
func (m *Module) Name() string { return "idp" }

// Description reports a one-line summary of the module.
func (m *Module) Description() string {
	return "Investigate CrowdStrike Falcon Identity Protection entities"
}

// timestamp returns the current UTC time as a naive ISO 8601 timestamp: no
// timezone designator, and with the fractional-seconds component present only
// when the microsecond field is non-zero. Clients parse this format, so it is
// part of the tool's wire contract. It uses m.now when set so tests can pin the
// value.
func (m *Module) timestamp() string {
	now := time.Now
	if m.now != nil {
		now = m.now
	}
	t := now().UTC()
	if t.Nanosecond() == 0 {
		return t.Format("2006-01-02T15:04:05")
	}
	return t.Format("2006-01-02T15:04:05.000000")
}

// investigateEntityDescription is the tool description served to clients.
const investigateEntityDescription = "Investigate one or more Identity Protection entities by ID, name, email, IP, or domain.\n\n" +
	"Use this to look up entity details, activity timelines, relationship graphs, and risk\n" +
	"assessments; at least one identifier must be supplied, and multiple identifiers are\n" +
	"combined with AND logic (email and IP cannot be combined — email takes precedence).\n" +
	"Returns a structured response with an investigation_summary, resolved entity IDs,\n" +
	"and results keyed by each requested investigation type."

// RegisterTools registers the idp tool into r.
func (m *Module) RegisterTools(r base.Registrar) {
	base.AddTool(r, &mcp.Tool{
		Name:        "idp_investigate_entity",
		Description: investigateEntityDescription,
		InputSchema: investigateEntitySchema,
	}, m.investigateEntity)
}

// RegisterResources is a no-op: IDP uses GraphQL, not FQL, so there is no filter
// guide to publish.
func (m *Module) RegisterResources(_ *mcp.Server) {}

// RegisterPrompts is a no-op: the idp module exposes no prompts.
func (m *Module) RegisterPrompts(_ *mcp.Server) {}
