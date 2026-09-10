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

package recon

import _ "embed"

//go:generate go run github.com/crowdstrike/falcon-mcp/tools/genfqlguide -in fql_guide_notifications.md
//go:generate go run github.com/crowdstrike/falcon-mcp/tools/genfqlguide -in fql_guide_rules.md
//go:generate go run github.com/crowdstrike/falcon-mcp/tools/genfqlguide -in fql_guide_exposed_data_records.md
//go:generate go run github.com/crowdstrike/falcon-mcp/tools/genfqlguide -in fql_guide_preview.md

// notificationsFQLGuide is the FQL documentation for searching recon
// notifications. It is served as the search_recon_notifications FQL guide
// resource and returned inline inside FQL-error responses to guide filter
// correction. Whitespace in fql_guide_notifications.md is normalized by
// `go generate` (see the directives above).
//
//go:embed fql_guide_notifications.md
var notificationsFQLGuide string

// rulesFQLGuide is the FQL documentation for searching recon monitoring rules.
//
//go:embed fql_guide_rules.md
var rulesFQLGuide string

// exposedDataRecordsFQLGuide is the FQL documentation for searching recon
// exposed-data records.
//
//go:embed fql_guide_exposed_data_records.md
var exposedDataRecordsFQLGuide string

// previewRuleFQLGuide documents the rule-filter dialect, valid topics, and
// lookback values for preview_recon_rule. Unlike the search guides it describes
// the monitoring-rule filter language rather than notification search FQL; it is
// served as the preview guide resource and returned inline inside preview
// FQL-error responses.
//
//go:embed fql_guide_preview.md
var previewRuleFQLGuide string
