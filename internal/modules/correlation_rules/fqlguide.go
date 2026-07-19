package correlation_rules

import _ "embed"

//go:generate go run github.com/crowdstrike/falcon-mcp/tools/genfqlguide -in fql_guide.md

// fqlGuideURI is the MCP resource URI for the correlation-rules search FQL
// guide, matching falcon-mcp's falcon://correlation-rules/search/fql-guide.
const fqlGuideURI = "falcon://correlation-rules/search/fql-guide"

// fqlGuide is the FQL documentation for searching correlation rules. It is
// served as the search FQL guide resource and also returned inline inside
// FQL-error responses to guide filter correction. Whitespace in fql_guide.md is
// normalized by `go generate` (see the directive above).
//
//go:embed fql_guide.md
var fqlGuide string
