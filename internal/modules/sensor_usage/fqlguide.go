package sensorusage

import _ "embed"

//go:generate go run github.com/crowdstrike/falcon-mcp/tools/genfqlguide -in fql_guide.md

// fqlGuide is the FQL documentation for searching weekly sensor usage. It is
// served as the search_sensor_usage FQL guide resource and returned inline
// inside FQL-error responses. Whitespace in fql_guide.md is normalized by
// `go generate` (see the directive above).
//
//go:embed fql_guide.md
var fqlGuide string
