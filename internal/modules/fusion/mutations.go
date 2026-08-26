package fusion

import (
	"context"
	"errors"
	"fmt"

	"github.com/crowdstrike/gofalcon/falcon/client/workflows"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/crowdstrike/falcon-mcp/internal/modules/base"
)

// errInvalidArgs classifies a caller-side argument error that never reaches the
// Falcon API, so callers can distinguish it from a transport or API failure.
var errInvalidArgs = errors.New("fusion: invalid arguments")

// executeParamDescriptions carry backticks or reference sibling tools, so they
// are applied via the schema mutate func rather than struct tags.
const (
	executeDefinitionIDDescription = "Workflow definition ID to execute. Provide this or `name`. Look it up " +
		"with falcon_search_workflow_definitions."

	executeNameDescription = "Workflow name to execute. Provide this or `definition_id`. Prefer " +
		"`definition_id` — names are not guaranteed unique."

	executeParametersDescription = "Trigger input for the workflow, sent verbatim as the request body. The " +
		"accepted keys are defined by the workflow, not by this tool: read " +
		"`trigger.parameters` on the definition (from " +
		"falcon_search_workflow_definitions) for its JSON Schema and required " +
		"fields. Pass {} for a workflow that takes no input."

	executeKeyDescription = "Idempotency key used to deduplicate executions. Reuse the same key when " +
		"retrying so the retry returns the original execution instead of starting " +
		"a second run."

	executeDepthDescription = "Execution depth guard for workflows that trigger workflows. Max 4."

	executeSourceEventURLDescription = "URL of the source that led to this execution, recorded as provenance."
)

// ExecuteInput is the input for falcon_execute_workflow. definition_id and name
// are mutually exclusive (exactly one required); the handler enforces that
// because JSON Schema cannot. Depth is a pointer so an explicit 0 is
// distinguishable from unset, since 0 is a valid depth guard.
type ExecuteInput struct {
	DefinitionID   string         `json:"definition_id,omitempty" jsonschema:"workflow definition ID to execute"`
	Name           string         `json:"name,omitempty" jsonschema:"workflow name to execute"`
	Parameters     map[string]any `json:"parameters,omitempty" jsonschema:"trigger input sent verbatim as the request body"`
	Key            string         `json:"key,omitempty" jsonschema:"idempotency key used to deduplicate executions"`
	Depth          *int           `json:"depth,omitempty" jsonschema:"execution depth guard, max 4"`
	SourceEventURL string         `json:"source_event_url,omitempty" jsonschema:"URL of the source that led to this execution"`
}

// executeSchema is the input schema for falcon_execute_workflow, applying the
// backtick-bearing descriptions and the 0-4 bound on depth.
var executeSchema = base.SchemaFor[ExecuteInput](func(s *jsonschema.Schema) {
	s.Properties["definition_id"].Description = executeDefinitionIDDescription
	s.Properties["name"].Description = executeNameDescription
	s.Properties["parameters"].Description = executeParametersDescription
	s.Properties["key"].Description = executeKeyDescription
	s.Properties["depth"].Description = executeDepthDescription
	s.Properties["depth"].Minimum = jsonschema.Ptr(0.0)
	s.Properties["depth"].Maximum = jsonschema.Ptr(4.0)
	s.Properties["source_event_url"].Description = executeSourceEventURLDescription
})

// executionRef labels a bare execution ID returned by Execute so it can be fed
// to falcon_get_workflow_execution_results.
type executionRef struct {
	ExecutionID string `json:"execution_id"`
}

func (m *Module) executeWorkflow(ctx context.Context, _ *mcp.CallToolRequest, in ExecuteInput) (*mcp.CallToolResult, base.EntitiesResult[executionRef], error) {
	var zero base.EntitiesResult[executionRef]

	// Exactly one identifier must be supplied: both set, or neither, is a
	// caller error the endpoint cannot disambiguate.
	if (in.DefinitionID != "") == (in.Name != "") {
		return nil, zero, fmt.Errorf("%w: provide exactly one of definition_id or name", errInvalidArgs)
	}

	m.Logger.Debug("execute_workflow", "definition_id", in.DefinitionID, "name", in.Name, "has_key", in.Key != "")

	params := workflows.NewExecuteParamsWithContext(ctx)
	// Body is required by the endpoint but legitimately empty for a workflow
	// that declares no trigger.parameters, so an empty map is sent explicitly.
	if in.Parameters != nil {
		params.Body = models.MapStringInterface(in.Parameters)
	} else {
		params.Body = models.MapStringInterface(map[string]any{})
	}
	if in.DefinitionID != "" {
		params.DefinitionID = []string{in.DefinitionID}
	}
	if in.Name != "" {
		params.Name = &in.Name
	}
	if in.Key != "" {
		params.Key = &in.Key
	}
	if in.Depth != nil {
		d := int64(*in.Depth)
		params.Depth = &d
	}
	if in.SourceEventURL != "" {
		params.SourceEventURL = &in.SourceEventURL
	}

	resp, err := m.API.Execute(params)
	if e := base.APIError(err, resp, scopeWorkflowsWrite); e != nil {
		return nil, zero, e
	}

	// The API returns bare execution-ID strings, not entities. Label each so it
	// can be fed to falcon_get_workflow_execution_results.
	out := make([]executionRef, 0, len(resp.Payload.Resources))
	for _, id := range resp.Payload.Resources {
		out = append(out, executionRef{ExecutionID: id})
	}
	return nil, base.Entities(out).WithMeta(resp.Payload.Meta), nil
}
