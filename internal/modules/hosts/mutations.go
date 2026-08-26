package hosts

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/crowdstrike/gofalcon/falcon/client/hosts"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/crowdstrike/falcon-mcp/internal/modules/base"
)

// scopeHostsWrite is the CrowdStrike API scope required to change device tags.
var scopeHostsWrite = base.Scope{Name: "Hosts", Write: true}

// Falcon grouping-tag conventions ported from falcon-mcp.
const (
	// groupingPrefix is prepended to bare tag names; grouping tags drive dynamic
	// host group (and therefore policy) assignment.
	groupingPrefix = "FalconGroupingTags/"
	// sensorPrefix marks tags applied by the sensor installer, which are
	// read-only through this API and rejected on input.
	sensorPrefix = "SensorGroupingTags/"
	// maxTagDeviceIDs and maxTagsPerRequest bound a single tag update.
	maxTagDeviceIDs   = 5000
	maxTagsPerRequest = 50
)

// tagActions is the set of accepted action values.
var tagActions = []string{"add", "remove"}

const manageGroupingTagsDescription = "Add or remove Falcon Grouping Tags on one or more hosts. " +
	"Set action to 'add' to attach tags, or 'remove' to detach them, on every device in `ids`. " +
	"Grouping tags can drive dynamic host group assignment and therefore policy assignment, so changing them may change a host's security posture. " +
	"Adding a tag a host already has, or removing one it lacks, is a no-op. " +
	"Returns one record per device, each with `device_id`, `updated`, and `code`. " +
	"Tag names are case-sensitive, so removing a tag requires the exact casing it was created with."

// ManageGroupingTagsInput is the input for falcon_manage_host_grouping_tags.
type ManageGroupingTagsInput struct {
	IDs    []string `json:"ids" jsonschema:"Host device IDs (AIDs) to tag. You can get device IDs from the falcon_search_hosts operation, the Falcon console, or the Streaming API. Maximum: 5000 IDs per request."`
	Action string   `json:"action" jsonschema:"Action to perform. Values: 'add' or 'remove'."`
	Tags   []string `json:"tags" jsonschema:"Falcon Grouping Tags to add or remove. The 'FalconGroupingTags/' prefix is optional and is added automatically. Sensor grouping tags ('SensorGroupingTags/') are applied by the sensor installer and cannot be changed through this API. Maximum: 50 tags per request."`
}

func (m *Module) manageGroupingTags(ctx context.Context, _ *mcp.CallToolRequest, in ManageGroupingTagsInput) (*mcp.CallToolResult, base.EntitiesResult[*models.DeviceapiUpdateDeviceDetailsResponseV1], error) {
	var zero base.EntitiesResult[*models.DeviceapiUpdateDeviceDetailsResponseV1]

	if !slices.Contains(tagActions, in.Action) {
		return nil, zero, base.InvalidInput("manage host grouping tags", fmt.Sprintf("action must be one of %s", strings.Join(tagActions, ", ")))
	}
	if len(in.IDs) == 0 {
		return nil, zero, base.InvalidInput("manage host grouping tags", "at least one device id is required")
	}
	if len(in.IDs) > maxTagDeviceIDs {
		return nil, zero, base.InvalidInput("manage host grouping tags", fmt.Sprintf("too many device ids: %d (max %d)", len(in.IDs), maxTagDeviceIDs))
	}
	if len(in.Tags) == 0 {
		return nil, zero, base.InvalidInput("manage host grouping tags", "at least one tag is required")
	}
	if len(in.Tags) > maxTagsPerRequest {
		return nil, zero, base.InvalidInput("manage host grouping tags", fmt.Sprintf("too many tags: %d (max %d)", len(in.Tags), maxTagsPerRequest))
	}

	tags, err := normalizeGroupingTags(in.Tags)
	if err != nil {
		return nil, zero, err
	}

	m.Logger.Debug("manage_host_grouping_tags", "action", in.Action, "ids", len(in.IDs), "tags", len(tags))

	params := hosts.NewUpdateDeviceTagsParamsWithContext(ctx)
	params.Body = &models.DeviceapiUpdateDeviceTagsRequestV1{
		Action:    &in.Action,
		DeviceIds: in.IDs,
		Tags:      tags,
	}

	ok, accepted, err := m.API.UpdateDeviceTags(params)
	payload := updateTagsPayload(ok, accepted)
	if e := base.APIError(err, resultForError(ok, accepted), scopeHostsWrite); e != nil {
		return nil, zero, e
	}
	if payload == nil {
		return nil, base.Entities([]*models.DeviceapiUpdateDeviceDetailsResponseV1{}), nil
	}
	return nil, base.Entities(payload.Resources).WithMeta(payload.Meta), nil
}

// normalizeGroupingTags trims each tag, rejects sensor-installer tags, and
// prepends the grouping prefix to bare names. A tag that already carries the
// grouping prefix in any casing is rewritten to the canonical prefix, because
// the API matches the prefix exactly and would treat a miscased one as an
// ordinary tag that does not drive host-group assignment. Only the prefix is
// canonicalized; the caller's casing on the tag name is preserved.
func normalizeGroupingTags(tags []string) ([]string, error) {
	out := make([]string, 0, len(tags))
	for _, raw := range tags {
		tag := strings.TrimSpace(raw)
		if tag == "" {
			return nil, base.InvalidInput("manage host grouping tags", "tag values must not be empty")
		}
		switch {
		case hasFoldPrefix(tag, sensorPrefix):
			return nil, base.InvalidInput("manage host grouping tags", fmt.Sprintf("%q is a sensor grouping tag, which cannot be changed through this API", tag))
		case hasFoldPrefix(tag, groupingPrefix):
			tag = groupingPrefix + tag[len(groupingPrefix):]
		default:
			tag = groupingPrefix + tag
		}
		out = append(out, tag)
	}
	return out, nil
}

// hasFoldPrefix reports whether s begins with prefix under a case-insensitive
// comparison, without allocating the lower-cased copies strings.ToLower would.
func hasFoldPrefix(s, prefix string) bool {
	return len(s) >= len(prefix) && strings.EqualFold(s[:len(prefix)], prefix)
}

// updateTagsPayload returns whichever of the 200 or 202 responses is populated,
// or nil when neither is (the error path).
func updateTagsPayload(ok *hosts.UpdateDeviceTagsOK, accepted *hosts.UpdateDeviceTagsAccepted) *models.DeviceapiUpdateDeviceTagsSwaggerV1 {
	switch {
	case ok != nil:
		return ok.Payload
	case accepted != nil:
		return accepted.Payload
	default:
		return nil
	}
}

// resultForError picks the non-nil response so base.APIError can read its
// payload errors; it returns a typed nil when neither response is present.
func resultForError(ok *hosts.UpdateDeviceTagsOK, accepted *hosts.UpdateDeviceTagsAccepted) any {
	switch {
	case ok != nil:
		return ok
	case accepted != nil:
		return accepted
	default:
		return ok
	}
}
