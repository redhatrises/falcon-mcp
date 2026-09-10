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

package rtr

import _ "embed"

//go:generate go run github.com/crowdstrike/falcon-mcp/tools/genfqlguide -in sessions_fql_guide.md
//go:generate go run github.com/crowdstrike/falcon-mcp/tools/genfqlguide -in audit_fql_guide.md
//go:generate go run github.com/crowdstrike/falcon-mcp/tools/genfqlguide -in aggregate_guide.md
//go:generate go run github.com/crowdstrike/falcon-mcp/tools/genfqlguide -in investigation_guide.md

// Resource URIs, kept 1:1 with falcon-mcp's RTR module.
const (
	sessionsFQLGuideURI   = "falcon://rtr/sessions/search/fql-guide"
	auditFQLGuideURI      = "falcon://rtr/audit/sessions/search/fql-guide"
	aggregateGuideURI     = "falcon://rtr/sessions/aggregate-guide"
	investigationGuideURI = "falcon://rtr/workflows/investigation-guide"
)

// sessionsFQLGuide is the FQL documentation for searching RTR sessions. It is
// served as the sessions FQL guide resource and also returned inline inside
// FQL-error responses to guide filter correction. Whitespace is normalized by
// `go generate` (see the directives above).
//
//go:embed sessions_fql_guide.md
var sessionsFQLGuide string

// auditFQLGuide is the FQL documentation for searching RTR audit sessions.
//
//go:embed audit_fql_guide.md
var auditFQLGuide string

// aggregateGuide explains how to summarize RTR session activity with the
// aggregate tool.
//
//go:embed aggregate_guide.md
var aggregateGuide string

// investigationGuide describes the safe read-only RTR investigation workflow.
//
//go:embed investigation_guide.md
var investigationGuide string
