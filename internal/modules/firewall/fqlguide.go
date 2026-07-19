package firewall

import _ "embed"

//go:generate go run github.com/crowdstrike/falcon-mcp/tools/genfqlguide -in fql_guide.md

const fqlGuideURI = "falcon://firewall/rules/fql-guide"

//go:embed fql_guide.md
var fqlGuide string
