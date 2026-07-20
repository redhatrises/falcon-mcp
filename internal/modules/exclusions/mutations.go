package exclusions

import (
	"context"
	"fmt"

	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/go-openapi/strfmt"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/crowdstrike/falcon-mcp/internal/modules/base"
)

// MutateInput is the input for both falcon_create_exclusion and
// falcon_update_exclusion. The two tools share every field: update additionally
// requires id, and each exclusion_type reads only the subset of fields relevant
// to it (see the per-type body builders). Pointers are used for the booleans so
// an unset flag is omitted rather than sent as false.
type MutateInput struct {
	ExclusionType string `json:"exclusion_type" jsonschema:"exclusion type: ioa, ml, sensor_visibility, or certificate"`
	ID            string `json:"id,omitempty" jsonschema:"ID of the exclusion to update; required for update_exclusion, ignored by create_exclusion"`

	Name  string `json:"name,omitempty" jsonschema:"exclusion name; required for ioa and certificate"`
	Value string `json:"value,omitempty" jsonschema:"excluded path or pattern; required for ml and sensor_visibility"`

	PatternID           string `json:"pattern_id,omitempty" jsonschema:"IOA rule pattern ID to exclude (a real existing pattern); required for ioa"`
	IfnRegex            string `json:"ifn_regex,omitempty" jsonschema:"IOA image file name regex; required (non-empty) for ioa"`
	ClRegex             string `json:"cl_regex,omitempty" jsonschema:"IOA command line regex; required (non-empty) for ioa"`
	ParentIfnRegex      string `json:"parent_ifn_regex,omitempty" jsonschema:"IOA parent image file name regex; optional, ioa only"`
	ParentClRegex       string `json:"parent_cl_regex,omitempty" jsonschema:"IOA parent command line regex; optional, ioa only"`
	GrandparentIfnRegex string `json:"grandparent_ifn_regex,omitempty" jsonschema:"IOA grandparent image file name regex; optional, ioa only"`
	GrandparentClRegex  string `json:"grandparent_cl_regex,omitempty" jsonschema:"IOA grandparent command line regex; optional, ioa only"`

	Certificate *Certificate `json:"certificate,omitempty" jsonschema:"certificate details (issuer, subject, serial, thumbprint, valid_from, valid_to); required for certificate"`
	Status      string       `json:"status,omitempty" jsonschema:"certificate exclusion status: enabled or disabled; required for certificate"`

	ExcludedFrom        []string `json:"excluded_from,omitempty" jsonschema:"ML exclusion targets, e.g. ['blocking']; optional, ml only"`
	IsDescendantProcess *bool    `json:"is_descendant_process,omitempty" jsonschema:"whether the exclusion applies to descendant processes; ml and sensor_visibility"`

	HostGroups      []string `json:"host_groups,omitempty" jsonschema:"host group IDs to scope the exclusion; required (non-empty) for sensor_visibility, optional otherwise"`
	AppliedGlobally *bool    `json:"applied_globally,omitempty" jsonschema:"whether the exclusion applies to all hosts"`
	Description     string   `json:"description,omitempty" jsonschema:"exclusion description; applies to ioa and certificate"`
	Comment         string   `json:"comment,omitempty" jsonschema:"audit comment for the exclusion"`
}

// Certificate is the certificate payload for a certificate-based exclusion,
// mirroring gofalcon's APICertificateReqV1. All fields are required by the API
// when creating a certificate exclusion.
type Certificate struct {
	Issuer     string `json:"issuer,omitempty" jsonschema:"certificate issuer distinguished name"`
	Subject    string `json:"subject,omitempty" jsonschema:"certificate subject distinguished name"`
	Serial     string `json:"serial,omitempty" jsonschema:"certificate serial number"`
	Thumbprint string `json:"thumbprint,omitempty" jsonschema:"certificate thumbprint (SHA1/SHA256)"`
	ValidFrom  string `json:"valid_from,omitempty" jsonschema:"validity window start (RFC3339 timestamp)"`
	ValidTo    string `json:"valid_to,omitempty" jsonschema:"validity window end (RFC3339 timestamp)"`
}

func (m *Module) createExclusion(ctx context.Context, _ *mcp.CallToolRequest, in MutateInput) (*mcp.CallToolResult, base.EntitiesResult[map[string]any], error) {
	var zero base.EntitiesResult[map[string]any]
	b, ok := m.backends[in.ExclusionType]
	if !ok {
		return nil, zero, invalidType(in.ExclusionType)
	}
	body, err := buildBody(in.ExclusionType, in, "")
	if err != nil {
		return nil, zero, err
	}
	m.Logger.Debug("create_exclusion", "type", in.ExclusionType)

	raw, err := b.createRaw(ctx, body)
	if e := base.APIError(err, nil, writeScope(in.ExclusionType)); e != nil {
		return nil, zero, e
	}
	records, err := decodeResources(raw)
	if err != nil {
		return nil, zero, err
	}
	return nil, base.Entities(records), nil
}

func (m *Module) updateExclusion(ctx context.Context, _ *mcp.CallToolRequest, in MutateInput) (*mcp.CallToolResult, base.EntitiesResult[map[string]any], error) {
	var zero base.EntitiesResult[map[string]any]
	b, ok := m.backends[in.ExclusionType]
	if !ok {
		return nil, zero, invalidType(in.ExclusionType)
	}
	if in.ID == "" {
		return nil, zero, wrapInvalid("update exclusion", "id is required to update an exclusion")
	}
	body, err := buildBody(in.ExclusionType, in, in.ID)
	if err != nil {
		return nil, zero, err
	}
	m.Logger.Debug("update_exclusion", "type", in.ExclusionType, "id", in.ID)

	raw, err := b.updateRaw(ctx, body)
	if e := base.APIError(err, nil, writeScope(in.ExclusionType)); e != nil {
		return nil, zero, e
	}
	records, err := decodeResources(raw)
	if err != nil {
		return nil, zero, err
	}
	return nil, base.Entities(records), nil
}

// DeleteInput is the input for falcon_delete_exclusions.
type DeleteInput struct {
	ExclusionType string   `json:"exclusion_type" jsonschema:"exclusion type: ioa, ml, sensor_visibility, or certificate"`
	IDs           []string `json:"ids" jsonschema:"IDs of the exclusions to delete (required, non-empty)"`
	Comment       string   `json:"comment,omitempty" jsonschema:"audit comment describing why the exclusions are being deleted"`
}

func (m *Module) deleteExclusions(ctx context.Context, _ *mcp.CallToolRequest, in DeleteInput) (*mcp.CallToolResult, base.ActionResult, error) {
	b, ok := m.backends[in.ExclusionType]
	if !ok {
		return nil, base.ActionResult{}, invalidType(in.ExclusionType)
	}
	if len(in.IDs) == 0 {
		return nil, base.ActionResult{}, wrapInvalid("delete exclusions", "ids must not be empty")
	}
	m.Logger.Debug("delete_exclusions", "type", in.ExclusionType, "ids", len(in.IDs))

	err := b.deleteByIDs(ctx, in.IDs, in.Comment)
	if e := base.APIError(err, nil, writeScope(in.ExclusionType)); e != nil {
		return nil, base.ActionResult{}, e
	}
	return nil, base.ActionResult{Ok: true}, nil
}

// buildBody dispatches to the per-type body builder, validating the fields that
// type requires before any API call. exclusionID is empty for create and the
// target ID for update.
func buildBody(exclusionType string, in MutateInput, exclusionID string) (any, error) {
	switch exclusionType {
	case "ioa":
		return buildIOABody(in, exclusionID)
	case "ml":
		return buildMLBody(in, exclusionID)
	case "sensor_visibility":
		return buildSVBody(in, exclusionID)
	default: // certificate
		return buildCertBody(in, exclusionID)
	}
}

// buildIOABody builds the wrapped IOA v2 exclusion request. The gofalcon item
// model has no applied_globally field, so that param is not sent for IOA.
func buildIOABody(in MutateInput, id string) (any, error) {
	if in.Name == "" || in.PatternID == "" || in.IfnRegex == "" || in.ClRegex == "" {
		return nil, wrapInvalid("create ioa exclusion",
			"ioa exclusions require name, pattern_id (a real existing IOA rule pattern), "+
				"ifn_regex (non-empty), and cl_regex (non-empty)")
	}
	if in.IfnRegex == ".*" && in.ClRegex == ".*" {
		return nil, wrapInvalid("create ioa exclusion",
			"ifn_regex and cl_regex cannot both be '.*' (this would exclude everything); "+
				"provide more specific regexes")
	}

	if id == "" {
		item := &models.DomainSsIoaExclusionCreateReqV2{
			Name:                &in.Name,
			PatternID:           &in.PatternID,
			IfnRegex:            &in.IfnRegex,
			ClRegex:             &in.ClRegex,
			ParentIfnRegex:      in.ParentIfnRegex,
			ParentClRegex:       in.ParentClRegex,
			GrandparentIfnRegex: in.GrandparentIfnRegex,
			GrandparentClRegex:  in.GrandparentClRegex,
			Description:         in.Description,
			Comment:             in.Comment,
			HostGroups:          in.HostGroups,
		}
		return &models.DomainSsIoaExclusionsCreateReqV2{Exclusions: []*models.DomainSsIoaExclusionCreateReqV2{item}}, nil
	}
	item := &models.DomainSsIoaExclusionUpdateReqV2{
		ID:                  &id,
		Name:                in.Name,
		PatternID:           in.PatternID,
		IfnRegex:            in.IfnRegex,
		ClRegex:             in.ClRegex,
		ParentIfnRegex:      in.ParentIfnRegex,
		ParentClRegex:       in.ParentClRegex,
		GrandparentIfnRegex: in.GrandparentIfnRegex,
		GrandparentClRegex:  in.GrandparentClRegex,
		Description:         in.Description,
		Comment:             in.Comment,
		HostGroups:          in.HostGroups,
	}
	return &models.DomainSsIoaExclusionsUpdateReqV2{Exclusions: []*models.DomainSsIoaExclusionUpdateReqV2{item}}, nil
}

// buildMLBody builds the ML v2 request: create is wrapped, update is the SINGULAR
// DomainExclusionUpdateReqV2. As of gofalcon 7ccbeaf1 the ML item models carry
// applied_globally and is_descendant_process, so those params are forwarded when
// set (matching the Python module); a nil pointer leaves the omitempty field out.
func buildMLBody(in MutateInput, id string) (any, error) {
	if in.Value == "" {
		return nil, wrapInvalid("create ml exclusion", "ml exclusions require a value (the path or pattern to exclude)")
	}
	applied := in.AppliedGlobally != nil && *in.AppliedGlobally
	descendant := in.IsDescendantProcess != nil && *in.IsDescendantProcess
	if id == "" {
		item := &models.DomainExclusionCreateReqV2{
			Value:               in.Value,
			ExcludedFrom:        in.ExcludedFrom,
			Groups:              in.HostGroups,
			AppliedGlobally:     applied,
			IsDescendantProcess: descendant,
			Comment:             in.Comment,
		}
		return &models.DomainExclusionsCreateReqV2{Exclusions: []*models.DomainExclusionCreateReqV2{item}}, nil
	}
	return &models.DomainExclusionUpdateReqV2{
		ID:                  &id,
		Value:               in.Value,
		ExcludedFrom:        in.ExcludedFrom,
		Groups:              in.HostGroups,
		AppliedGlobally:     applied,
		IsDescendantProcess: descendant,
		Comment:             in.Comment,
	}, nil
}

// buildSVBody builds the Sensor Visibility v1 flat request. Sensor visibility
// requires a non-empty host_groups list even when applied_globally is true; the
// gofalcon model has no applied_globally field, so it is not sent.
func buildSVBody(in MutateInput, id string) (any, error) {
	if in.Value == "" {
		return nil, wrapInvalid("create sensor_visibility exclusion",
			"sensor visibility exclusions require a value (the path or pattern to exclude)")
	}
	if len(in.HostGroups) == 0 {
		return nil, wrapInvalid("create sensor_visibility exclusion",
			"sensor visibility exclusions require a non-empty host_groups list, even when applied_globally is true")
	}
	descendant := in.IsDescendantProcess != nil && *in.IsDescendantProcess
	if id == "" {
		return &models.SvExclusionsCreateReqV1{
			Value:               in.Value,
			Groups:              in.HostGroups,
			IsDescendantProcess: descendant,
			Comment:             in.Comment,
		}, nil
	}
	return &models.SvExclusionsUpdateReqV1{
		ID:                  &id,
		Value:               in.Value,
		Groups:              in.HostGroups,
		IsDescendantProcess: descendant,
		Comment:             in.Comment,
	}, nil
}

// buildCertBody builds the wrapped Certificate-Based v1 request. Certificate
// items carry applied_globally, unlike the other three types.
func buildCertBody(in MutateInput, id string) (any, error) {
	if in.Name == "" || in.Certificate == nil {
		return nil, wrapInvalid("create certificate exclusion",
			"certificate-based exclusions require a name and a certificate (issuer, subject, serial, "+
				"thumbprint, valid_from, valid_to); use falcon_get_certificate_details to look up a certificate first")
	}
	if in.Status != "enabled" && in.Status != "disabled" {
		return nil, wrapInvalid("create certificate exclusion",
			"certificate-based exclusions require status to be either 'enabled' or 'disabled'")
	}
	cert, err := in.Certificate.toModel()
	if err != nil {
		return nil, err
	}
	applied := in.AppliedGlobally != nil && *in.AppliedGlobally
	if id == "" {
		item := &models.APICertBasedExclusionCreateReqV1{
			Name:            &in.Name,
			Certificate:     cert,
			Status:          in.Status,
			AppliedGlobally: applied,
			HostGroups:      in.HostGroups,
			Description:     in.Description,
			Comment:         in.Comment,
		}
		return &models.APICertBasedExclusionsCreateReqV1{Exclusions: []*models.APICertBasedExclusionCreateReqV1{item}}, nil
	}
	item := &models.APICertBasedExclusionUpdateReqV1{
		ID:              &id,
		Name:            in.Name,
		Certificate:     cert,
		Status:          in.Status,
		AppliedGlobally: applied,
		HostGroups:      in.HostGroups,
		Description:     in.Description,
		Comment:         in.Comment,
	}
	return &models.APICertBasedExclusionsUpdateReqV1{Exclusions: []*models.APICertBasedExclusionUpdateReqV1{item}}, nil
}

// toModel converts the tool-facing Certificate into gofalcon's APICertificateReqV1,
// parsing the two timestamp fields into strfmt.DateTime.
func (c *Certificate) toModel() (*models.APICertificateReqV1, error) {
	from, err := parseTime("valid_from", c.ValidFrom)
	if err != nil {
		return nil, err
	}
	to, err := parseTime("valid_to", c.ValidTo)
	if err != nil {
		return nil, err
	}
	m := &models.APICertificateReqV1{
		Issuer:     &c.Issuer,
		Subject:    &c.Subject,
		Serial:     &c.Serial,
		Thumbprint: &c.Thumbprint,
		ValidFrom:  from,
		ValidTo:    to,
	}
	return m, nil
}

// parseTime converts an RFC3339 timestamp string into a *strfmt.DateTime. An
// empty string yields a nil pointer (the field is omitted). A malformed value
// returns a guiding validation error rather than reaching the API.
func parseTime(field, value string) (*strfmt.DateTime, error) {
	if value == "" {
		return nil, nil
	}
	t, err := strfmt.ParseDateTime(value)
	if err != nil {
		return nil, wrapInvalid("create certificate exclusion",
			fmt.Sprintf("certificate %s must be an RFC3339 timestamp (e.g. 2024-01-02T15:04:05Z): %v", field, err))
	}
	return &t, nil
}
