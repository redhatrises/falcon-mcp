package intel

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/crowdstrike/gofalcon/falcon/client/intel"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/crowdstrike/falcon-mcp/internal/modules/base"
)

// errActorNotFound classifies a name-resolution lookup that matched no actor.
var errActorNotFound = errors.New("intel: actor not found")

// MitreInput is the input for falcon_get_mitre_report.
type MitreInput struct {
	Actor  string `json:"actor" jsonschema:"threat actor name (e.g. 'WARP PANDA') or numeric ID"`
	Format string `json:"format,omitempty" jsonschema:"report format: 'json' (parsed) or 'csv' (raw text); default 'json'"`
}

// MitreResult is the structured output envelope for falcon_get_mitre_report. A
// JSON-format request populates Report with the parsed MITRE ATT&CK document; a
// CSV-format request populates Raw with the report text verbatim. ActorID echoes
// the resolved numeric actor ID.
type MitreResult struct {
	ActorID string          `json:"actor_id"`
	Format  string          `json:"format"`
	Report  json.RawMessage `json:"report,omitempty"`
	Raw     string          `json:"raw,omitempty"`
}

func (m *Module) getMitreReport(ctx context.Context, _ *mcp.CallToolRequest, in MitreInput) (*mcp.CallToolResult, MitreResult, error) {
	var zero MitreResult
	actor := strings.TrimSpace(in.Actor)
	if actor == "" {
		return nil, zero, fmt.Errorf("%w: actor is required", base.ErrInvalidInput)
	}
	format := strings.ToLower(strings.TrimSpace(in.Format))
	if format == "" {
		format = "json"
	}
	if format != "json" && format != "csv" {
		return nil, zero, fmt.Errorf("%w: format must be 'json' or 'csv', got %q", base.ErrInvalidInput, in.Format)
	}

	actorID, err := m.resolveActorID(ctx, actor)
	if err != nil {
		return nil, zero, err
	}

	m.Logger.Debug("get_mitre_report", "actor_id", actorID, "format", format)
	params := intel.NewGetMitreReportParamsWithContext(ctx)
	params.ActorID = actorID
	params.Format = format

	var buf bytes.Buffer
	_, err = m.API.GetMitreReport(params, &buf)
	if e := base.APIError(err, nil, scopeActors); e != nil {
		return nil, zero, e
	}
	body := buf.Bytes()

	result := MitreResult{ActorID: actorID, Format: format}
	if format == "csv" {
		result.Raw = string(body)
		return nil, result, nil
	}

	// JSON format: validate/normalize the captured body. Empty or "null"
	// bodies yield an omitted report rather than an error.
	trimmed := strings.TrimSpace(string(body))
	if trimmed == "" || trimmed == "null" {
		return nil, result, nil
	}
	if !json.Valid([]byte(trimmed)) {
		return nil, zero, fmt.Errorf("%w: MITRE report was not valid JSON", base.ErrInvalidInput)
	}
	result.Report = json.RawMessage(trimmed)
	return nil, result, nil
}

// resolveActorID returns the numeric actor ID for actor. A numeric input is
// returned verbatim; a name is resolved via a single-result
// QueryIntelActorEntities lookup on name:'<actor>'. It wraps errActorNotFound
// when the name matches no actor and base.ErrInvalidInput when the matched actor has
// no ID.
func (m *Module) resolveActorID(ctx context.Context, actor string) (string, error) {
	if _, err := strconv.ParseInt(actor, 10, 64); err == nil {
		return actor, nil
	}

	m.Logger.Debug("get_mitre_report resolving actor by name", "actor", actor)
	params := intel.NewQueryIntelActorEntitiesParamsWithContext(ctx)
	params.Filter = new(fmt.Sprintf("name:'%s'", actor))
	params.Limit = new(int64(1))

	resp, err := m.API.QueryIntelActorEntities(params)
	if e := base.APIError(err, resp, scopeActors); e != nil {
		return "", e
	}

	actors := resp.Payload.Resources
	if len(actors) == 0 || actors[0] == nil {
		return "", fmt.Errorf("%w: no actor found with name %q", errActorNotFound, actor)
	}
	if actors[0].ID == nil {
		return "", fmt.Errorf("%w: actor %q has no ID", base.ErrInvalidInput, actor)
	}
	id := strconv.FormatInt(*actors[0].ID, 10)
	m.Logger.Debug("get_mitre_report resolved actor", "actor", actor, "actor_id", id)
	return id, nil
}
