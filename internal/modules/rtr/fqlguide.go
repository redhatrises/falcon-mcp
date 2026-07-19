package rtr

import _ "embed"

//go:generate go run github.com/crowdstrike/falcon-mcp/tools/genfqlguide -in sessions_fql_guide.md
//go:generate go run github.com/crowdstrike/falcon-mcp/tools/genfqlguide -in audit_fql_guide.md
//go:generate go run github.com/crowdstrike/falcon-mcp/tools/genfqlguide -in aggregate_guide.md
//go:generate go run github.com/crowdstrike/falcon-mcp/tools/genfqlguide -in investigation_guide.md

// Resource URIs, kept 1:1 with falcon-mcp's RTR module.
const (
	sessionsFQLGuideURI   = "falcon://rtr/sessions/search/fql-guide"
	auditFQLGuideURI      = "falcon://rtr/audit/sessions/search/fql-guide"
	aggregateGuideURI     = "falcon://rtr/sessions/aggregate-guide"
	investigationGuideURI = "falcon://rtr/workflows/investigation-guide"
)

// sessionsFQLGuide is the FQL documentation for searching RTR sessions. It is
// served as the sessions FQL guide resource and also returned inline inside
// FQL-error responses to guide filter correction. Whitespace is normalized by
// `go generate` (see the directives above).
//
//go:embed sessions_fql_guide.md
var sessionsFQLGuide string

// auditFQLGuide is the FQL documentation for searching RTR audit sessions.
//
//go:embed audit_fql_guide.md
var auditFQLGuide string

// aggregateGuide explains how to summarize RTR session activity with the
// aggregate tool.
//
//go:embed aggregate_guide.md
var aggregateGuide string

// investigationGuide describes the safe read-only RTR investigation workflow.
//
//go:embed investigation_guide.md
var investigationGuide string
