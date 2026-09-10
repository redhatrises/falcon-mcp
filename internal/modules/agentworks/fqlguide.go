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
