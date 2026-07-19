package scheduledreports

import _ "embed"

//go:generate go run github.com/crowdstrike/falcon-mcp/tools/genfqlguide -in fql_guide_reports.md
//go:generate go run github.com/crowdstrike/falcon-mcp/tools/genfqlguide -in fql_guide_executions.md

// reportsFQLGuide is the FQL documentation for searching scheduled report/search
// entities. It is served as the search_scheduled_reports FQL guide resource and
// returned inline inside FQL-error responses to guide filter correction.
// Whitespace in fql_guide_reports.md is normalized by `go generate` (see the
// directives above).
//
//go:embed fql_guide_reports.md
var reportsFQLGuide string

// executionsFQLGuide is the FQL documentation for searching report/search
// execution history.
//
//go:embed fql_guide_executions.md
var executionsFQLGuide string
