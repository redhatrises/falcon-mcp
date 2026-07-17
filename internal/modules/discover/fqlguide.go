package discover

import _ "embed"

//go:generate go run github.com/crowdstrike/falcon-mcp/tools/genfqlguide -in fql_guide_applications.md
//go:generate go run github.com/crowdstrike/falcon-mcp/tools/genfqlguide -in fql_guide_hosts.md

// MCP resource URIs for the two discover FQL guides, matching falcon-mcp's
// falcon://discover/applications/fql-guide and falcon://discover/hosts/fql-guide
// resources.
const (
	applicationsFQLGuideURI    = "falcon://discover/applications/fql-guide"
	unmanagedAssetsFQLGuideURI = "falcon://discover/hosts/fql-guide"
)

// applicationsFQLGuide is the FQL documentation for searching applications. It
// is served as the search_applications FQL guide resource and returned inline
// inside FQL-error responses. Whitespace in fql_guide_applications.md is
// normalized by `go generate` (see the directives above).
//
//go:embed fql_guide_applications.md
var applicationsFQLGuide string

// unmanagedAssetsFQLGuide is the FQL documentation for searching unmanaged
// assets. It is served as the search_unmanaged_assets FQL guide resource and
// returned inline inside FQL-error responses.
//
//go:embed fql_guide_hosts.md
var unmanagedAssetsFQLGuide string
