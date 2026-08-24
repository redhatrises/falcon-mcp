package ngsiem

import _ "embed"

// cqlGuideURI is the MCP resource URI under which the CQL authoring guide is
// served, matching the Python falcon-mcp ngsiem module.
const cqlGuideURI = "falcon://ngsiem/search/cql-guide"

// cqlGuide is the CQL (CrowdStrike Query Language) authoring guide for the
// query_string param of falcon_search_ngsiem, served as an MCP text resource.
// It is embedded verbatim (no whitespace normalization) because the guide's
// worked examples rely on code-block indentation.
//
//go:embed cql_guide.md
var cqlGuide string
