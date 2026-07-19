package quarantine

import _ "embed"

//go:generate go run github.com/crowdstrike/falcon-mcp/tools/genfqlguide -in fql_guide.md

// fqlGuideURI is the MCP resource URI for the quarantine search FQL guide,
// matching falcon-mcp's falcon://quarantine/files/search/fql-guide.
const fqlGuideURI = "falcon://quarantine/files/search/fql-guide"

// fqlGuide is the FQL documentation for searching quarantined files. It is
// served as the quarantine search FQL guide resource and shared by the
// filter-based action tools. Whitespace in fql_guide.md is normalized by
// `go generate` (see the directive above).
//
//go:embed fql_guide.md
var fqlGuide string
