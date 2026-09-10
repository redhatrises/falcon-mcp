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

package scheduledreports

import _ "embed"

//go:generate go run github.com/crowdstrike/falcon-mcp/tools/genfqlguide -in fql_guide_reports.md
//go:generate go run github.com/crowdstrike/falcon-mcp/tools/genfqlguide -in fql_guide_executions.md

// reportsFQLGuide is the FQL documentation for searching scheduled report/search
// entities. It is served as the search_scheduled_reports FQL guide resource and
// returned inline inside FQL-error responses to guide filter correction.
// Whitespace in fql_guide_reports.md is normalized by `go generate` (see the
// directives above).
//
//go:embed fql_guide_reports.md
var reportsFQLGuide string

// executionsFQLGuide is the FQL documentation for searching report/search
// execution history.
//
//go:embed fql_guide_executions.md
var executionsFQLGuide string
