// Package sensorusage implements the falcon_search_sensor_usage tool over the
// gofalcon sensor_usage_api client, and registers the sensor usage FQL guide
// resource.
//
// search_sensor_usage is a single-step typed gofalcon call
// (GetSensorUsageWeekly) that returns full weekly usage records directly, so
// this module does no bulk detail fetch and ignores Deps.Concurrency. The tool
// is read-only.
package sensorusage

import (
	"context"
	"errors"
	"log/slog"

	"github.com/crowdstrike/gofalcon/falcon/client/sensor_usage_api"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/crowdstrike/falcon-mcp/internal/modules/base"
	"github.com/crowdstrike/falcon-mcp/internal/modules/registry"
)

// fqlGuideURI is the MCP resource URI serving the sensor usage FQL filter
// guide, mirroring falcon-mcp's falcon://sensor-usage/weekly/fql-guide.
const fqlGuideURI = "falcon://sensor-usage/weekly/fql-guide"

// scopeSensorUsageRead is the CrowdStrike API scope required by this module's
// operations. Surfaced on a 403 via base.APIError.
var scopeSensorUsageRead = base.Scope{Name: "Sensor Usage", Read: true}

// Factory builds the sensor usage module from shared deps. The generated
// aggregator (internal/mcpserver) collects it, so the module needs no init side
// effect. The single tool is a one-call query, so the module ignores
// Deps.Concurrency.
var Factory registry.Factory = func(d registry.Deps) base.Module {
	return &Module{API: d.API.SensorUsageAPI, Logger: d.Logger}
}

// sensorUsageAPI is the minimal slice of the gofalcon sensor usage client this
// module consumes, declared next to its consumer for testability.
type sensorUsageAPI interface {
	GetSensorUsageWeekly(params *sensor_usage_api.GetSensorUsageWeeklyParams, opts ...sensor_usage_api.ClientOption) (*sensor_usage_api.GetSensorUsageWeeklyOK, error)
}

// Module registers the sensor usage tools. It holds only the shared,
// concurrency-safe Falcon client and configuration; handlers are stateless and
// reentrant. Logger must be non-nil.
type Module struct {
	API    sensorUsageAPI
	Logger *slog.Logger
}

// Name reports the module name.
func (m *Module) Name() string { return "sensorusage" }

// Description reports a one-line summary of the module.
func (m *Module) Description() string {
	return "Access CrowdStrike Falcon sensor usage data"
}

// searchSensorUsageDescription mirrors the Python falcon-mcp sensor_usage
// module's tool docstring 1:1 for client compatibility.
const searchSensorUsageDescription = "Search for weekly sensor usage data in your CrowdStrike environment.\n\n" +
	"Use this to retrieve sensor billing and usage metrics by date or period. Consult\n" +
	"falcon://sensor-usage/weekly/fql-guide before constructing filter expressions.\n" +
	"Returns weekly usage records."

// filterParamDescription carries backticks, so it cannot live in a jsonschema
// struct tag; it is applied to searchSensorUsageSchema by the mutate func below.
const filterParamDescription = "FQL filter expression. See `falcon://sensor-usage/weekly/fql-guide` for syntax."

// searchSensorUsageSchema is the input schema for falcon_search_sensor_usage.
// It is inferred from SearchInput's struct tags, then a mutate func adds the
// backtick-bearing filter description the tag syntax cannot express.
var searchSensorUsageSchema = base.SchemaFor[SearchInput](func(s *jsonschema.Schema) {
	s.Properties["filter"].Description = filterParamDescription
})

// RegisterTools registers the sensor usage tools into r.
func (m *Module) RegisterTools(r base.Registrar) {
	searchTool := &mcp.Tool{
		Name:        "search_sensor_usage",
		Description: searchSensorUsageDescription,
		InputSchema: searchSensorUsageSchema,
	}
	base.AddTool(r, searchTool, m.searchSensorUsage)
}

// RegisterResources publishes the sensor usage FQL guide as an MCP resource,
// mirroring falcon-mcp's falcon://sensor-usage/weekly/fql-guide resource.
func (m *Module) RegisterResources(s *mcp.Server) {
	base.TextResource(s,
		fqlGuideURI,
		"search_sensor_usage_fql_guide",
		"Contains the guide for the `filter` param of the `falcon_search_sensor_usage` tool.",
		"text/markdown",
		fqlGuide,
	)
}

// RegisterPrompts is a no-op: the sensor usage module exposes no prompts.
func (m *Module) RegisterPrompts(_ *mcp.Server) {}

// SearchInput is the input for falcon_search_sensor_usage. The json tags drive
// the SDK's unmarshal into this struct; the served schema
// (searchSensorUsageSchema) is inferred from these jsonschema tags, then
// augmented with the backtick-bearing filter description.
//
// GetSensorUsageWeekly accepts only a filter (no limit, sort, or offset), so
// this input carries just the filter, matching the Python module.
type SearchInput struct {
	Filter string `json:"filter,omitempty" jsonschema:"FQL filter (e.g. event_date:'2024-06-11', period:'30')"`
}

func (m *Module) searchSensorUsage(ctx context.Context, _ *mcp.CallToolRequest, in SearchInput) (*mcp.CallToolResult, base.SearchResult[*models.EntitiesRollingAverage], error) {
	var zero base.SearchResult[*models.EntitiesRollingAverage]
	m.Logger.Debug("search_sensor_usage", "filter", in.Filter)

	params := sensor_usage_api.NewGetSensorUsageWeeklyParamsWithContext(ctx)
	if in.Filter != "" {
		params.Filter = &in.Filter
	}

	resp, err := m.API.GetSensorUsageWeekly(params)
	if err != nil {
		if details, ok := fqlBadRequest(err); ok {
			return nil, base.FQLError[*models.EntitiesRollingAverage](details, in.Filter, fqlGuide), nil
		}
	}
	if e := base.APIError(err, resp, scopeSensorUsageRead); e != nil {
		return nil, zero, e
	}

	usage := resp.Payload.Resources
	m.Logger.Debug("search_sensor_usage query complete", "matched", len(usage))
	return nil, base.Found(usage, in.Filter).WithMeta(resp.Payload.Meta), nil
}

// fqlBadRequest reports whether err is a 400-class weekly usage query error and,
// if so, extracts the API error details for an FQL-error response. gofalcon
// surfaces 400s as a typed *sensor_usage_api.GetSensorUsageWeeklyBadRequest
// whose payload carries the errors; classify with errors.As rather than string
// matching.
func fqlBadRequest(err error) ([]base.FQLErrorDetail, bool) {
	var badReq *sensor_usage_api.GetSensorUsageWeeklyBadRequest
	if !errors.As(err, &badReq) || badReq.Payload == nil {
		return nil, false
	}
	return base.FQLErrorDetails(badReq.Payload.Errors), true
}
