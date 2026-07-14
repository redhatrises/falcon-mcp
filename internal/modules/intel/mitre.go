package intel

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/crowdstrike/gofalcon/falcon/client/intel"
	"github.com/go-openapi/runtime"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/crowdstrike/falcon-mcp/internal/modules/base"
)

// errActorNotFound classifies a name-resolution lookup that matched no actor.
var errActorNotFound = errors.New("intel: actor not found")

// errInvalidInput classifies client-side validation failures in get_mitre_report.
var errInvalidInput = errors.New("intel: invalid input")

// mitreClient adapts the gofalcon intel.ClientService to the intelAPI interface,
// overriding only GetMitreReport. The generated GetMitreReport returns a typed
// *GetMitreReportOK that carries no report body: the swagger spec defines no 200
// schema for /intel/entities/mitre-reports/v1, so go-openapi generated a reader
// that never consumes the response body. Worse, the generated method panics if
// the transport returns any non-*GetMitreReportOK value, so a Reader override
// cannot simply return the raw bytes in its place. Instead the override captures
// the 200 body into a field on a custom reader while still returning a valid
// *GetMitreReportOK to satisfy the method's type assertion; this adapter then
// hands the captured bytes back as the any result. Non-200 responses
// fall through to the generated typed errors.
type mitreClient struct {
	intel.ClientService
}

// GetMitreReport fetches the MITRE report, recovering the 200 body the generated
// reader discards. It returns the report bytes as an any ([]byte) on
// success, or the generated typed error on a non-200 response. Callers pass no
// opts (the reader override is applied internally); any opts are forwarded after
// it so a caller could still layer on further overrides.
func (c mitreClient) GetMitreReport(params *intel.GetMitreReportParams, opts ...intel.ClientOption) (any, error) {
	capture := &mitreReportReader{}
	override := func(op *runtime.ClientOperation) {
		capture.orig = op.Reader
		op.Reader = capture
	}
	_, err := c.ClientService.GetMitreReport(params, append([]intel.ClientOption{override}, opts...)...)
	if err != nil {
		return nil, err
	}
	return capture.body, nil
}

// mitreReportReader wraps the generated reader to capture the 200 response body,
// which the generated reader leaves unconsumed (see mitreClient). On non-200
// responses it delegates to the original reader so 403/429/500 still surface as
// gofalcon's typed errors.
type mitreReportReader struct {
	orig runtime.ClientResponseReader
	body []byte
}

// ReadResponse captures the 200 body into r.body and returns a valid
// *GetMitreReportOK so the generated method's type assertion succeeds; other
// status codes delegate to the wrapped reader.
func (r *mitreReportReader) ReadResponse(resp runtime.ClientResponse, c runtime.Consumer) (any, error) {
	if resp.Code() == 200 {
		b, err := io.ReadAll(resp.Body())
		if err != nil {
			return nil, fmt.Errorf("read mitre report body: %w", err)
		}
		r.body = b
		return intel.NewGetMitreReportOK(), nil
	}
	return r.orig.ReadResponse(resp, c)
}

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
		return nil, zero, fmt.Errorf("%w: actor is required", errInvalidInput)
	}
	format := strings.ToLower(strings.TrimSpace(in.Format))
	if format == "" {
		format = "json"
	}
	if format != "json" && format != "csv" {
		return nil, zero, fmt.Errorf("%w: format must be 'json' or 'csv', got %q", errInvalidInput, in.Format)
	}

	actorID, err := m.resolveActorID(ctx, actor)
	if err != nil {
		return nil, zero, err
	}

	m.Logger.Debug("get_mitre_report", "actor_id", actorID, "format", format)
	params := intel.NewGetMitreReportParamsWithContext(ctx)
	params.ActorID = actorID
	params.Format = format

	raw, err := m.API.GetMitreReport(params)
	if e := base.APIError(err, nil, scopeActors); e != nil {
		return nil, zero, e
	}
	body, _ := raw.([]byte)

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
		return nil, zero, fmt.Errorf("%w: MITRE report was not valid JSON", errInvalidInput)
	}
	result.Report = json.RawMessage(trimmed)
	return nil, result, nil
}

// resolveActorID returns the numeric actor ID for actor. A numeric input is
// returned verbatim; a name is resolved via a single-result
// QueryIntelActorEntities lookup on name:'<actor>'. It wraps errActorNotFound
// when the name matches no actor and errInvalidInput when the matched actor has
// no ID.
func (m *Module) resolveActorID(ctx context.Context, actor string) (string, error) {
	if _, err := strconv.ParseInt(actor, 10, 64); err == nil {
		return actor, nil
	}

	m.Logger.Debug("get_mitre_report resolving actor by name", "actor", actor)
	filter := fmt.Sprintf("name:'%s'", actor)
	limit := int64(1)
	params := intel.NewQueryIntelActorEntitiesParamsWithContext(ctx)
	params.Filter = &filter
	params.Limit = &limit

	resp, err := m.API.QueryIntelActorEntities(params)
	if e := base.APIError(err, resp, scopeActors); e != nil {
		return "", e
	}

	actors := resp.Payload.Resources
	if len(actors) == 0 || actors[0] == nil {
		return "", fmt.Errorf("%w: no actor found with name %q", errActorNotFound, actor)
	}
	if actors[0].ID == nil {
		return "", fmt.Errorf("%w: actor %q has no ID", errInvalidInput, actor)
	}
	id := strconv.FormatInt(*actors[0].ID, 10)
	m.Logger.Debug("get_mitre_report resolved actor", "actor", actor, "actor_id", id)
	return id, nil
}
