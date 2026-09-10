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
