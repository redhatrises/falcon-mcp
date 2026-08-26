package agentworks

import _ "embed"

//go:generate go run github.com/crowdstrike/falcon-mcp/tools/genfqlguide -in fql_guide_agents.md
//go:generate go run github.com/crowdstrike/falcon-mcp/tools/genfqlguide -in fql_guide_agent_versions.md
//go:generate go run github.com/crowdstrike/falcon-mcp/tools/genfqlguide -in fql_guide_spans.md

// agentsFQLGuide is the FQL documentation for searching AgentWorks agents. It is
// served as the agents FQL guide resource and returned inline inside FQL-error
// responses from falcon_search_agentworks_agents. Whitespace in the source
// markdown is normalized by `go generate` (see the directives above).
//
//go:embed fql_guide_agents.md
var agentsFQLGuide string

// agentVersionsFQLGuide is the FQL documentation for searching AgentWorks agent
// versions. It is served as the agent-versions FQL guide resource and returned
// inline inside FQL-error responses from falcon_search_agentworks_agent_versions.
//
//go:embed fql_guide_agent_versions.md
var agentVersionsFQLGuide string

// spansFQLGuide is the FQL documentation for searching AgentWorks spans. It is
// served as the spans FQL guide resource and returned inline inside FQL-error
// responses from falcon_search_agentworks_spans.
//
//go:embed fql_guide_spans.md
var spansFQLGuide string
