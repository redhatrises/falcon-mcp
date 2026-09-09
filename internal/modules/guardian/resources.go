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
