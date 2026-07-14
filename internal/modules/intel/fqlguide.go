package intel

import _ "embed"

//go:generate go run github.com/crowdstrike/falcon-mcp/tools/genfqlguide -in fql_guide_actors.md
//go:generate go run github.com/crowdstrike/falcon-mcp/tools/genfqlguide -in fql_guide_indicators.md
//go:generate go run github.com/crowdstrike/falcon-mcp/tools/genfqlguide -in fql_guide_reports.md

// MCP resource URIs for the three intel FQL guides, matching falcon-mcp's
// falcon://intel/{actors,indicators,reports}/fql-guide resources.
const (
	actorsFQLGuideURI     = "falcon://intel/actors/fql-guide"
	indicatorsFQLGuideURI = "falcon://intel/indicators/fql-guide"
	reportsFQLGuideURI    = "falcon://intel/reports/fql-guide"
)

// actorsFQLGuide is the FQL documentation for searching threat actors. It is
// served as the search_actors FQL guide resource and returned inline inside
// FQL-error responses. Whitespace in fql_guide_actors.md is normalized by
// `go generate` (see the directives above).
//
//go:embed fql_guide_actors.md
var actorsFQLGuide string

// indicatorsFQLGuide is the FQL documentation for searching intel indicators.
//
//go:embed fql_guide_indicators.md
var indicatorsFQLGuide string

// reportsFQLGuide is the FQL documentation for searching intel reports.
//
//go:embed fql_guide_reports.md
var reportsFQLGuide string
