package fusion

import _ "embed"

//go:generate go run github.com/crowdstrike/falcon-mcp/tools/genfqlguide -in fql_guide_definitions.md
//go:generate go run github.com/crowdstrike/falcon-mcp/tools/genfqlguide -in fql_guide_executions.md

// definitionsFQLGuide is the FQL documentation for searching Fusion SOAR
// workflow definitions. It is served as the search_workflow_definitions FQL
// guide resource and returned inline inside FQL-error responses to guide filter
// correction. Whitespace in fql_guide_definitions.md is normalized by
// `go generate` (see the directives above).
//
//go:embed fql_guide_definitions.md
var definitionsFQLGuide string

// executionsFQLGuide is the FQL documentation for searching Fusion SOAR
// workflow executions.
//
//go:embed fql_guide_executions.md
var executionsFQLGuide string
