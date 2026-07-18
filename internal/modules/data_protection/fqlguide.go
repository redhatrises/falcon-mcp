package data_protection

import _ "embed"

//go:generate go run github.com/crowdstrike/falcon-mcp/tools/genfqlguide -in classifications_fql_guide.md
//go:generate go run github.com/crowdstrike/falcon-mcp/tools/genfqlguide -in policies_fql_guide.md
//go:generate go run github.com/crowdstrike/falcon-mcp/tools/genfqlguide -in content_patterns_fql_guide.md

// classificationsFQLGuide is the FQL documentation for searching Data Protection
// classifications, served as the classifications FQL guide resource and returned
// inline on an FQL error. Whitespace is normalized by `go generate`.
//
//go:embed classifications_fql_guide.md
var classificationsFQLGuide string

// policiesFQLGuide is the FQL documentation for searching Data Protection
// policies. Whitespace is normalized by `go generate`.
//
//go:embed policies_fql_guide.md
var policiesFQLGuide string

// contentPatternsFQLGuide is the FQL documentation for searching Data Protection
// content patterns. Whitespace is normalized by `go generate`.
//
//go:embed content_patterns_fql_guide.md
var contentPatternsFQLGuide string
