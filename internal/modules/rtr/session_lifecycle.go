package rtr

import (
	"context"
	"errors"
	"fmt"

	"github.com/crowdstrike/gofalcon/falcon/client/real_time_response"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/crowdstrike/falcon-mcp/internal/modules/base"
)

// defaultOrigin is the origin label sent on init/pulse when the caller omits
// one, matching the Python module's "falcon-mcp" default.
const defaultOrigin = "falcon-mcp"

// errInvalidInput classifies client-side validation failures in this module's
// tools (empty required fields, unknown enum values).
var errInvalidInput = errors.New("rtr: invalid input")

// InitInput is the input for falcon_init_rtr_session.
type InitInput struct {
	DeviceID        string `json:"device_id" jsonschema:"the host agent ID (AID) to open or reuse an RTR session for (required)"`
	Origin          string `json:"origin,omitempty" jsonschema:"origin label for the RTR request (default falcon-mcp)"`
	QueueOffline    bool   `json:"queue_offline,omitempty" jsonschema:"queue the request if the host is currently offline"`
	Timeout         int    `json:"timeout,omitempty" jsonschema:"how long to wait for the request in seconds (max 600)"`
	TimeoutDuration string `json:"timeout_duration,omitempty" jsonschema:"alternate duration syntax such as 30s, 2m, or 1h"`
}

func (m *Module) initSession(ctx context.Context, _ *mcp.CallToolRequest, in InitInput) (*mcp.CallToolResult, base.EntitiesResult[*models.DomainInitResponse], error) {
	var zero base.EntitiesResult[*models.DomainInitResponse]
	if in.DeviceID == "" {
		return nil, zero, wrapInvalid("init rtr session", "device_id must not be empty")
	}
	origin := in.Origin
	if origin == "" {
		origin = defaultOrigin
	}
	m.Logger.Debug("init_rtr_session", "device_id", in.DeviceID, "origin", origin, "queue_offline", in.QueueOffline)

	params := real_time_response.NewRTRInitSessionParamsWithContext(ctx)
	params.Body = &models.DomainInitRequest{
		DeviceID:     &in.DeviceID,
		Origin:       &origin,
		QueueOffline: &in.QueueOffline,
	}
	if in.Timeout != 0 {
		timeout := int64(in.Timeout)
		params.Timeout = &timeout
	}
	if in.TimeoutDuration != "" {
		params.TimeoutDuration = &in.TimeoutDuration
	}

	resp, err := m.API.RTRInitSession(params)
	if e := base.APIError(err, resp, scopeRTRRead); e != nil {
		return nil, zero, e
	}
	return nil, base.Entities(resp.Payload.Resources).WithMeta(resp.Payload.Meta), nil
}

// PulseInput is the input for falcon_pulse_rtr_session.
type PulseInput struct {
	DeviceID     string `json:"device_id" jsonschema:"the host agent ID (AID) whose RTR session timeout should be refreshed (required)"`
	Origin       string `json:"origin,omitempty" jsonschema:"origin label for the RTR request (default falcon-mcp)"`
	QueueOffline bool   `json:"queue_offline,omitempty" jsonschema:"queue the pulse if the host is currently offline"`
}

func (m *Module) pulseSession(ctx context.Context, _ *mcp.CallToolRequest, in PulseInput) (*mcp.CallToolResult, base.EntitiesResult[*models.DomainInitResponse], error) {
	var zero base.EntitiesResult[*models.DomainInitResponse]
	if in.DeviceID == "" {
		return nil, zero, wrapInvalid("pulse rtr session", "device_id must not be empty")
	}
	origin := in.Origin
	if origin == "" {
		origin = defaultOrigin
	}
	m.Logger.Debug("pulse_rtr_session", "device_id", in.DeviceID, "origin", origin, "queue_offline", in.QueueOffline)

	params := real_time_response.NewRTRPulseSessionParamsWithContext(ctx)
	params.Body = &models.DomainInitRequest{
		DeviceID:     &in.DeviceID,
		Origin:       &origin,
		QueueOffline: &in.QueueOffline,
	}

	resp, err := m.API.RTRPulseSession(params)
	if e := base.APIError(err, resp, scopeRTRRead); e != nil {
		return nil, zero, e
	}
	return nil, base.Entities(resp.Payload.Resources).WithMeta(resp.Payload.Meta), nil
}

// DeleteInput is the input for falcon_delete_rtr_session.
type DeleteInput struct {
	SessionID string `json:"session_id" jsonschema:"RTR session ID to close (required)"`
}

func (m *Module) deleteSession(ctx context.Context, _ *mcp.CallToolRequest, in DeleteInput) (*mcp.CallToolResult, base.ActionResult, error) {
	if in.SessionID == "" {
		return nil, base.ActionResult{}, wrapInvalid("delete rtr session", "session_id must not be empty")
	}
	m.Logger.Debug("delete_rtr_session", "session_id", in.SessionID)

	params := real_time_response.NewRTRDeleteSessionParamsWithContext(ctx)
	params.SessionID = in.SessionID

	resp, err := m.API.RTRDeleteSession(params)
	if e := base.APIError(err, resp, scopeRTRRead); e != nil {
		return nil, base.ActionResult{}, e
	}
	return nil, base.ActionResult{Ok: true}.WithMeta(resp.Payload.Meta), nil
}

// wrapInvalid builds an errInvalidInput-wrapped error for op with detail.
func wrapInvalid(op, detail string) error {
	return fmt.Errorf("%s: %w: %s", op, errInvalidInput, detail)
}
