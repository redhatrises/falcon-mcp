package cases

import _ "embed"

//go:generate go run github.com/crowdstrike/falcon-mcp/tools/genfqlguide -in fql_guide.md

// fqlGuide is the FQL documentation for searching cases. It is served as the
// case-search FQL guide resource and also returned inline inside FQL-error
// responses to guide filter correction. Whitespace in fql_guide.md is normalized
// by `go generate` (see the directive above).
//
//go:embed fql_guide.md
var fqlGuide string
