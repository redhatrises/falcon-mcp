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
	AppliedGlobally *bool    `json:"applied_globally,omitempty" jsonschema:"whether the exclusion applies to all hosts; supported only for ml and certificate, rejected for ioa and sensor_visibility"`
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

	records, meta, err := b.createRecords(ctx, body, writeScope(in.ExclusionType))
	if err != nil {
		return nil, zero, err
	}
	return nil, base.Entities(records).WithMeta(meta), nil
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

	records, meta, err := b.updateRecords(ctx, body, writeScope(in.ExclusionType))
	if err != nil {
		return nil, zero, err
	}
	return nil, base.Entities(records).WithMeta(meta), nil
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

	meta, err := b.deleteByIDs(ctx, in.IDs, in.Comment)
	if e := base.APIError(err, nil, writeScope(in.ExclusionType)); e != nil {
		return nil, base.ActionResult{}, e
	}
	return nil, base.ActionResult{Ok: true}.WithMeta(meta), nil
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

// mutateOp names the operation a body builder is serving, for the op prefix on
// its validation errors. exclusionID is empty for create and the target ID for
// update, matching buildBody's convention.
func mutateOp(exclusionType, exclusionID string) string {
	if exclusionID == "" {
		return "create " + exclusionType + " exclusion"
	}
	return "update " + exclusionType + " exclusion"
}

// rejectAppliedGlobally reports an error when the caller asked for
// applied_globally on an exclusion type whose gofalcon model cannot carry it.
// Only an explicit true is rejected: false matches the field's absence, so
// sending it loses nothing. op names the operation for the error prefix.
func rejectAppliedGlobally(in MutateInput, op string) error {
	if in.AppliedGlobally == nil || !*in.AppliedGlobally {
		return nil
	}
	return wrapInvalid(op,
		"this exclusion type cannot be applied globally; scope it with host_groups instead")
}

// buildIOABody builds the wrapped IOA v2 exclusion request. The gofalcon item
// model has no applied_globally field, so requesting it is rejected rather than
// silently dropped.
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
	for _, f := range []struct{ name, re string }{
		{"ifn_regex", in.IfnRegex},
		{"cl_regex", in.ClRegex},
		{"parent_ifn_regex", in.ParentIfnRegex},
		{"parent_cl_regex", in.ParentClRegex},
		{"grandparent_ifn_regex", in.GrandparentIfnRegex},
		{"grandparent_cl_regex", in.GrandparentClRegex},
	} {
		if f.re == "" {
			continue
		}
		if tok := findZeroWidthAssertion(f.re); tok != "" {
			return nil, wrapInvalid(mutateOp("ioa", id), fmt.Sprintf(
				"%q contains the zero-width assertion %q, which the IOA regex engine does not "+
					"support; remove ^, $, \\b, \\A, and \\Z (escape as \\\\^ / \\\\$ or use a "+
					"character class for a literal)", f.name, tok))
		}
	}
	if err := rejectAppliedGlobally(in, mutateOp("ioa", id)); err != nil {
		return nil, err
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

// findZeroWidthAssertion returns the first zero-width regex assertion in re
// ("^", "$", "\\b", "\\A", or "\\Z"), or "" when none is present. The IOA regex
// engine rejects these anchors, so callers reject the exclusion before the API
// call. An escaped anchor (\^, \$) and any character inside a character class
// [...] are literals and are not reported.
func findZeroWidthAssertion(re string) string {
	runes := []rune(re)
	inClass := false  // inside a [...] character class
	classMembers := 0 // members seen since the class opened, for the leading-] and [^ rules
	for i := 0; i < len(runes); i++ {
		switch runes[i] {
		case '\\':
			next, ok := peek(runes, i+1)
			if !ok {
				// Trailing lone backslash: a literal with nothing to escape.
				continue
			}
			if !inClass && (next == 'b' || next == 'A' || next == 'Z') {
				return `\` + string(next)
			}
			i++ // the escaped rune is a literal; consume it
			if inClass {
				classMembers++
			}
		case '[':
			if inClass {
				classMembers++
				continue
			}
			inClass = true
			classMembers = 0
		case ']':
			if inClass && classMembers > 0 {
				inClass = false
				continue
			}
			// A leading ] (no members yet) is a literal member, not a close.
			classMembers++
		case '^':
			if !inClass {
				return "^"
			}
			// A leading ^ negates the class and is not a member; elsewhere it is
			// a literal member.
			if classMembers > 0 {
				classMembers++
			}
		case '$':
			if !inClass {
				return "$"
			}
			classMembers++
		default:
			if inClass {
				classMembers++
			}
		}
	}
	return ""
}

// peek returns runes[i] and true when i is in range, or the zero rune and false
// otherwise, so a lookahead past the end is a single guarded call.
func peek(runes []rune, i int) (rune, bool) {
	if i >= len(runes) {
		return 0, false
	}
	return runes[i], true
}

// buildMLBody builds the ML v2 request: create is wrapped, update is the SINGULAR
// DomainExclusionUpdateReqV2. As of gofalcon 542ced95b748 the ML item models carry
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
// requires a non-empty host_groups list; the gofalcon model has no
// applied_globally field, so requesting it is rejected rather than silently
// dropped.
func buildSVBody(in MutateInput, id string) (any, error) {
	if in.Value == "" {
		return nil, wrapInvalid("create sensor_visibility exclusion",
			"sensor visibility exclusions require a value (the path or pattern to exclude)")
	}
	if len(in.HostGroups) == 0 {
		return nil, wrapInvalid("create sensor_visibility exclusion",
			"sensor visibility exclusions require a non-empty host_groups list")
	}
	if err := rejectAppliedGlobally(in, mutateOp("sensor_visibility", id)); err != nil {
		return nil, err
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
