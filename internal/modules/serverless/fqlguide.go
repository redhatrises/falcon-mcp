package serverless

import _ "embed"

//go:generate go run github.com/crowdstrike/falcon-mcp/tools/genfqlguide -in fql_guide.md

// fqlGuide is the FQL documentation for searching serverless vulnerabilities. It
// is served as the search_serverless_vulnerabilities FQL guide resource and
// returned inline inside FQL-error responses. Whitespace in fql_guide.md is
// normalized by `go generate` (see the directive above).
//
//go:embed fql_guide.md
var fqlGuide string
