package custom_ioa

import _ "embed"

//go:generate go run github.com/crowdstrike/falcon-mcp/tools/genfqlguide -in fql_guide.md

// fqlGuideURI is the MCP resource URI for the Custom IOA rule-groups FQL guide,
// matching falcon-mcp's falcon://custom-ioa/rule-groups/fql-guide.
const fqlGuideURI = "falcon://custom-ioa/rule-groups/fql-guide"

// fqlGuide is the FQL documentation for searching Custom IOA rule groups. It is
// served as the rule-groups FQL guide resource and also returned inline inside
// FQL-error responses to guide filter correction. Whitespace in fql_guide.md is
// normalized by `go generate` (see the directive above).
//
//go:embed fql_guide.md
var fqlGuide string
