package shield

import _ "embed"

//go:generate go run github.com/crowdstrike/falcon-mcp/tools/genfqlguide -in query_guide.md

// queryGuide is the query parameter documentation for the Falcon Shield (SaaS
// Security) tools. It is served as the falcon_shield_query_guide resource and
// returned inline inside empty/error search responses. Shield tools use named
// query parameters rather than FQL, so this is a parameter guide (not an FQL
// grammar). Whitespace in query_guide.md is normalized by `go generate` (see
// the directive above).
//
//go:embed query_guide.md
var queryGuide string
