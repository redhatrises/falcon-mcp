package ioc

import _ "embed"

//go:generate go run github.com/crowdstrike/falcon-mcp/tools/genfqlguide -in fql_guide.md

// fqlGuideURI is the MCP resource URI for the IOC search FQL guide, matching
// falcon-mcp's falcon://ioc/search/fql-guide.
const fqlGuideURI = "falcon://ioc/search/fql-guide"

// fqlGuide is the FQL documentation for searching IOCs. It is served as the IOC
// search FQL guide resource and also returned inline inside FQL-error responses
// to guide filter correction. Whitespace in fql_guide.md is normalized by
// `go generate` (see the directive above).
//
//go:embed fql_guide.md
var fqlGuide string
