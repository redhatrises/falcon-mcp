package cases

import _ "embed"

//go:generate go run github.com/crowdstrike/falcon-mcp/tools/genfqlguide -in fql_guide.md
//go:generate go run github.com/crowdstrike/falcon-mcp/tools/genfqlguide -in aggregates_fql_guide.md
//go:generate go run github.com/crowdstrike/falcon-mcp/tools/genfqlguide -in file_aggregates_fql_guide.md

// fqlGuide is the FQL documentation for searching cases. It is served as the
// case-search FQL guide resource and also returned inline inside FQL-error
// responses to guide filter correction. Whitespace in fql_guide.md is normalized
// by `go generate` (see the directive above).
//
//go:embed fql_guide.md
var fqlGuide string

// aggregatesFQLGuide is the FQL documentation for the case-configuration
// aggregate tools (SLAs, templates, access tags, notification groups). It is
// served as the aggregates FQL guide resource and returned inline inside
// FQL-error responses from those tools.
//
//go:embed aggregates_fql_guide.md
var aggregatesFQLGuide string

// fileAggregatesFQLGuide is the FQL documentation for the case-file aggregate
// tool. It is served as the file-aggregates FQL guide resource and returned
// inline inside FQL-error responses from falcon_aggregate_case_file_details.
//
//go:embed file_aggregates_fql_guide.md
var fileAggregatesFQLGuide string
