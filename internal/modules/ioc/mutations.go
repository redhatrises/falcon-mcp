package ioc

import (
	"context"
	"fmt"

	"github.com/crowdstrike/gofalcon/falcon/client/ioc"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/go-openapi/strfmt"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/crowdstrike/falcon-mcp/internal/modules/base"
)

// Default single-IOC field values matching falcon-mcp, applied when the caller
// omits them on the single-indicator path.
const (
	defaultAction = "detect"
	defaultSource = "mcp"
)

// AddInput is the input for falcon_add_ioc. Provide the single-indicator
// convenience fields (Type and Value are required) or a bulk Indicators array;
// when Indicators is non-empty the single-indicator fields are ignored.
type AddInput struct {
	Type            string   `json:"type,omitempty" jsonschema:"IOC type for single-IOC creation (e.g. domain, ipv4, ipv6, md5, sha256); required unless indicators is provided"`
	Value           string   `json:"value,omitempty" jsonschema:"IOC value for single-IOC creation; required unless indicators is provided"`
	Action          string   `json:"action,omitempty" jsonschema:"action for single-IOC creation (e.g. detect, prevent, no_action); default detect"`
	Source          string   `json:"source,omitempty" jsonschema:"source label for the IOC; default mcp"`
	Severity        string   `json:"severity,omitempty" jsonschema:"severity label for single-IOC creation"`
	Description     string   `json:"description,omitempty" jsonschema:"description text for single-IOC creation"`
	Expiration      string   `json:"expiration,omitempty" jsonschema:"expiration timestamp in UTC (ISO 8601), e.g. 2026-12-31T23:59:59Z"`
	AppliedGlobally *bool    `json:"applied_globally,omitempty" jsonschema:"whether the IOC is applied globally"`
	MobileAction    string   `json:"mobile_action,omitempty" jsonschema:"action to apply on mobile platforms"`
	Platforms       []string `json:"platforms,omitempty" jsonschema:"platform list for single-IOC creation"`
	HostGroups      []string `json:"host_groups,omitempty" jsonschema:"host groups for scoped IOC application"`
	Tags            []string `json:"tags,omitempty" jsonschema:"Falcon grouping tags to attach to the IOC"`
	Filename        string   `json:"filename,omitempty" jsonschema:"convenience shortcut for the metadata filename"`
	Comment         string   `json:"comment,omitempty" jsonschema:"audit comment for IOC creation"`

	Indicators []*models.APIIndicatorCreateReqV1 `json:"indicators,omitempty" jsonschema:"bulk IOC payload; when provided, the single-IOC fields are ignored"`

	IgnoreWarnings bool  `json:"ignore_warnings,omitempty" jsonschema:"set true to ignore warnings and create all submitted IOCs"`
	Retrodetects   *bool `json:"retrodetects,omitempty" jsonschema:"whether to submit IOCs to retrodetect processing"`
}

func (m *Module) addIOC(ctx context.Context, _ *mcp.CallToolRequest, in AddInput) (*mcp.CallToolResult, base.EntitiesResult[*models.APIIndicatorV1], error) {
	var zero base.EntitiesResult[*models.APIIndicatorV1]
	body, err := in.body()
	if err != nil {
		return nil, zero, err
	}
	m.Logger.Debug("add_ioc", "bulk", len(in.Indicators) > 0, "count", len(body.Indicators), "ignore_warnings", in.IgnoreWarnings)

	params := ioc.NewIndicatorCreateV1ParamsWithContext(ctx)
	params.Body = body
	params.IgnoreWarnings = &in.IgnoreWarnings
	if in.Retrodetects != nil {
		params.Retrodetects = in.Retrodetects
	}

	resp, err := m.API.IndicatorCreateV1(params)
	if e := base.APIError(err, resp, scopeIOCWrite); e != nil {
		return nil, zero, e
	}
	return nil, base.Entities(resp.Payload.Resources).WithMeta(resp.Payload.Meta), nil
}

// body builds the IOC create request. The bulk Indicators array takes
// precedence; otherwise a single indicator is assembled from the convenience
// fields, which requires both type and value.
func (in AddInput) body() (*models.APIIndicatorCreateReqsV1, error) {
	if len(in.Indicators) > 0 {
		return &models.APIIndicatorCreateReqsV1{Comment: in.Comment, Indicators: in.Indicators}, nil
	}

	if in.Type == "" || in.Value == "" {
		return nil, base.InvalidInput("add ioc", "type and value are required when indicators is not provided")
	}

	action := in.Action
	if action == "" {
		action = defaultAction
	}
	source := in.Source
	if source == "" {
		source = defaultSource
	}

	indicator := &models.APIIndicatorCreateReqV1{
		Type:            in.Type,
		Value:           in.Value,
		Action:          action,
		Source:          source,
		Severity:        in.Severity,
		Description:     in.Description,
		MobileAction:    in.MobileAction,
		Platforms:       in.Platforms,
		HostGroups:      in.HostGroups,
		Tags:            in.Tags,
		AppliedGlobally: in.AppliedGlobally,
	}
	if in.Filename != "" {
		indicator.Metadata = &models.APIMetadataReqV1{Filename: in.Filename}
	}
	if in.Expiration != "" {
		exp, err := strfmt.ParseDateTime(in.Expiration)
		if err != nil {
			return nil, base.InvalidInput("add ioc", fmt.Sprintf("invalid expiration %q (want ISO 8601, e.g. 2026-12-31T23:59:59Z)", in.Expiration))
		}
		indicator.Expiration = &exp
	}

	return &models.APIIndicatorCreateReqsV1{Comment: in.Comment, Indicators: []*models.APIIndicatorCreateReqV1{indicator}}, nil
}

// RemoveInput is the input for falcon_remove_iocs. At least one of IDs or
// Filter must be provided; when both are given, Filter takes precedence.
type RemoveInput struct {
	IDs        []string `json:"ids,omitempty" jsonschema:"IOC IDs to remove"`
	Filter     string   `json:"filter,omitempty" jsonschema:"IOC FQL expression for bulk removal; takes precedence over ids when both are set"`
	Comment    string   `json:"comment,omitempty" jsonschema:"audit comment describing why these IOCs are removed"`
	FromParent *bool    `json:"from_parent,omitempty" jsonschema:"limit the action to IOCs originating from the MSSP parent"`
}

func (m *Module) removeIOCs(ctx context.Context, _ *mcp.CallToolRequest, in RemoveInput) (*mcp.CallToolResult, base.EntitiesResult[string], error) {
	var zero base.EntitiesResult[string]
	if len(in.IDs) == 0 && in.Filter == "" {
		return nil, zero, base.InvalidInput("remove iocs", "either ids or filter must be provided")
	}
	m.Logger.Debug("remove_iocs", "ids", len(in.IDs), "filter", in.Filter)

	params := ioc.NewIndicatorDeleteV1ParamsWithContext(ctx)
	if len(in.IDs) > 0 {
		params.Ids = in.IDs
	}
	if in.Filter != "" {
		params.Filter = &in.Filter
	}
	if in.Comment != "" {
		params.Comment = &in.Comment
	}
	if in.FromParent != nil {
		params.FromParent = in.FromParent
	}

	resp, err := m.API.IndicatorDeleteV1(params)
	if e := base.APIError(err, resp, scopeIOCWrite); e != nil {
		return nil, zero, e
	}
	return nil, base.Entities(resp.Payload.Resources).WithMeta(resp.Payload.Meta), nil
}
