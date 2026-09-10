// MIT License
//
// Copyright (c) 2026 CrowdStrike
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

package intel

import _ "embed"

//go:generate go run github.com/crowdstrike/falcon-mcp/tools/genfqlguide -in fql_guide_actors.md
//go:generate go run github.com/crowdstrike/falcon-mcp/tools/genfqlguide -in fql_guide_indicators.md
//go:generate go run github.com/crowdstrike/falcon-mcp/tools/genfqlguide -in fql_guide_reports.md

// MCP resource URIs for the three intel FQL guides, matching falcon-mcp's
// falcon://intel/{actors,indicators,reports}/fql-guide resources.
const (
	actorsFQLGuideURI     = "falcon://intel/actors/fql-guide"
	indicatorsFQLGuideURI = "falcon://intel/indicators/fql-guide"
	reportsFQLGuideURI    = "falcon://intel/reports/fql-guide"
)

// actorsFQLGuide is the FQL documentation for searching threat actors. It is
// served as the search_actors FQL guide resource and returned inline inside
// FQL-error responses. Whitespace in fql_guide_actors.md is normalized by
// `go generate` (see the directives above).
//
//go:embed fql_guide_actors.md
var actorsFQLGuide string

// indicatorsFQLGuide is the FQL documentation for searching intel indicators.
//
//go:embed fql_guide_indicators.md
var indicatorsFQLGuide string

// reportsFQLGuide is the FQL documentation for searching intel reports.
//
//go:embed fql_guide_reports.md
var reportsFQLGuide string
