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
