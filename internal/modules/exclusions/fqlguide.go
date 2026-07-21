package exclusions

import _ "embed"

//go:generate go run github.com/crowdstrike/falcon-mcp/tools/genfqlguide -in fql_guide.md

//go:embed fql_guide.md
var fqlGuide string
