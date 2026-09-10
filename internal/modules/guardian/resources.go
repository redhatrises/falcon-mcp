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

package guardian

import (
	_ "embed"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/crowdstrike/falcon-mcp/internal/modules/base"
)

// Documentation resource URIs, matching the upstream Python guardian module.
const (
	queryGuideURI      = "falcon://guardian/events/query-guide"
	entitySchemaURI    = "falcon://guardian/entities/schema-guide"
	inventorySchemaURI = "falcon://guardian/inventory/schema-guide"
	exampleQueriesURI  = "falcon://guardian/events/examples-guide"
)

//go:embed query_guide.md
var queryGuide string

//go:embed entity_schema.md
var entitySchema string

//go:embed inventory_schema.md
var inventorySchema string

//go:embed example_queries.md
var exampleQueries string

// RegisterResources publishes the four Guardian documentation guides as MCP
// resources, mirroring the Python falcon-mcp guardian resources.
func (m *Module) RegisterResources(s *mcp.Server) {
	base.TextResource(s, queryGuideURI,
		"guardian_query_guide",
		"Guardian API reference for the AI entity and LogScale event query endpoints. Use this when choosing endpoints and parameters for the Guardian tools.",
		"text/markdown", queryGuide)
	base.TextResource(s, entitySchemaURI,
		"guardian_entity_schema",
		"AI vertex and edge field reference. Shows available fields for AIAgent, AISession, AITool, AIModel, AISkill, MCPServer, AIPrompt entities.",
		"text/markdown", entitySchema)
	base.TextResource(s, inventorySchemaURI,
		"guardian_inventory_schema",
		"AI entity and LogScale event field reference. Shows available fields for the AIAgent/AIAgentSession/AITool/AISkillFrontmatter/MCPServerName/AIAgentInstallation/AIModelName/AIAgentOSUser entity store and the LogScale AgenticSessionStart/AgenticToolRequest/AgenticUserPromptSubmit events.",
		"text/markdown", inventorySchema)
	base.TextResource(s, exampleQueriesURI,
		"guardian_example_queries",
		"Example Guardian queries for common AI activity questions. Reference these when choosing Guardian tools and parameters.",
		"text/markdown", exampleQueries)
}
