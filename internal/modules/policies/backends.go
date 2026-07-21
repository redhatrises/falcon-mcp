package policies

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"

	"github.com/crowdstrike/gofalcon/falcon/client/content_update_policies"
	"github.com/crowdstrike/gofalcon/falcon/client/device_control_policies"
	"github.com/crowdstrike/gofalcon/falcon/client/firewall_policies"
	"github.com/crowdstrike/gofalcon/falcon/client/prevention_policies"
	"github.com/crowdstrike/gofalcon/falcon/client/response_policies"
	"github.com/crowdstrike/gofalcon/falcon/client/sensor_update_policies"
	"github.com/crowdstrike/gofalcon/falcon/models"

	"github.com/crowdstrike/falcon-mcp/internal/modules/base"
)

// queryArgs carries the search parameters shared across the policy query
// operations. sort is passed through verbatim (already validated).
type queryArgs struct {
	filter string
	sort   string
	limit  int64
	offset *int64
}

// createSpec and updateSpec carry the validated create/update fields into a
// backend. settings is the opaque per-type object; each backend converts it into
// its concrete gofalcon Settings type via convertSettings.
type createSpec struct {
	name         string
	platformName string
	description  string
	settings     any
	cloneID      string
}

type updateSpec struct {
	id          string
	name        string
	description string
	settings    any
}

// backend abstracts the per-type policy operations behind the unified tool
// surface. Each concrete backend wraps one gofalcon policy sub-client. Record-
// returning operations return uniform []map[string]any (see toMaps) so one tool
// can serve all six heterogeneous policy models. meta is the raw API meta object
// for verbatim pagination passthrough.
type backend interface {
	// search returns full policy records for a search plus the raw meta object.
	// device_control is a two-step query->get internally; the others use a single
	// combined query.
	search(ctx context.Context, a queryArgs) ([]map[string]any, any, error)
	// members returns the host devices governed by a policy plus the raw meta.
	members(ctx context.Context, id string, a queryArgs) ([]*models.DeviceDevice, any, error)
	// create creates a policy and returns the created record(s) plus meta.
	create(ctx context.Context, s createSpec) ([]map[string]any, any, error)
	// update updates a policy and returns the updated record(s) plus meta.
	update(ctx context.Context, s updateSpec) ([]map[string]any, any, error)
	// deleteByIDs deletes the given policy IDs, returning the raw meta object.
	deleteByIDs(ctx context.Context, ids []string) (any, error)
	// action performs action_name on ids (with an optional group_id for group
	// actions) and returns the updated record(s) plus meta.
	action(ctx context.Context, actionName string, ids []string, groupID string) ([]map[string]any, any, error)
	// setPrecedence sets policy precedence for a platform, returning the raw meta.
	// platformName is empty for content_update (its body has no platform field).
	setPrecedence(ctx context.Context, ids []string, platformName string) (any, error)
	// classifyFQL reports whether err is a 400-class FQL error for this type and,
	// if so, extracts the API error details for an FQL-error response.
	classifyFQL(err error) ([]base.FQLErrorDetail, bool)
}

// convertSettings converts the opaque caller-supplied settings object into the
// concrete gofalcon Settings type T via a JSON round-trip. A nil settings yields
// the zero value of T (a nil pointer or nil slice), leaving the body field unset.
func convertSettings[T any](settings any) (T, error) {
	var out T
	if settings == nil {
		return out, nil
	}
	b, err := json.Marshal(settings)
	if err != nil {
		return out, wrapInvalid("build policy", fmt.Sprintf("settings could not be encoded: %v", err))
	}
	if err := json.Unmarshal(b, &out); err != nil {
		return out, wrapInvalid("build policy", fmt.Sprintf("settings do not match the expected shape for this policy type: %v", err))
	}
	return out, nil
}

// actionBody builds the shared MsaEntityActionRequestV2 for a perform-action
// call, attaching a group_id action parameter for group actions.
func actionBody(ids []string, groupID string) *models.MsaEntityActionRequestV2 {
	body := &models.MsaEntityActionRequestV2{Ids: ids}
	if groupID != "" {
		name := "group_id"
		val := groupID
		body.ActionParameters = []*models.MsaspecActionParameter{{Name: &name, Value: &val}}
	}
	return body
}

// ---- Prevention backend ---------------------------------------------------------

type preventionClient interface {
	QueryCombinedPreventionPolicies(*prevention_policies.QueryCombinedPreventionPoliciesParams, ...prevention_policies.ClientOption) (*prevention_policies.QueryCombinedPreventionPoliciesOK, error)
	QueryCombinedPreventionPolicyMembers(*prevention_policies.QueryCombinedPreventionPolicyMembersParams, ...prevention_policies.ClientOption) (*prevention_policies.QueryCombinedPreventionPolicyMembersOK, error)
	CreatePreventionPolicies(*prevention_policies.CreatePreventionPoliciesParams, ...prevention_policies.ClientOption) (*prevention_policies.CreatePreventionPoliciesCreated, error)
	UpdatePreventionPolicies(*prevention_policies.UpdatePreventionPoliciesParams, ...prevention_policies.ClientOption) (*prevention_policies.UpdatePreventionPoliciesOK, error)
	DeletePreventionPolicies(*prevention_policies.DeletePreventionPoliciesParams, ...prevention_policies.ClientOption) (*prevention_policies.DeletePreventionPoliciesOK, error)
	PerformPreventionPoliciesAction(*prevention_policies.PerformPreventionPoliciesActionParams, ...prevention_policies.ClientOption) (*prevention_policies.PerformPreventionPoliciesActionOK, error)
	SetPreventionPoliciesPrecedence(*prevention_policies.SetPreventionPoliciesPrecedenceParams, ...prevention_policies.ClientOption) (*prevention_policies.SetPreventionPoliciesPrecedenceOK, error)
}

type preventionBackend struct{ c preventionClient }

func (b preventionBackend) search(ctx context.Context, a queryArgs) ([]map[string]any, any, error) {
	p := prevention_policies.NewQueryCombinedPreventionPoliciesParamsWithContext(ctx)
	applyQuery(a, &p.Filter, &p.Sort, &p.Limit, &p.Offset)
	resp, err := b.c.QueryCombinedPreventionPolicies(p)
	if err != nil {
		return nil, nil, err
	}
	records, err := toMaps(resp.Payload.Resources)
	return records, resp.Payload.Meta, err
}

func (b preventionBackend) members(ctx context.Context, id string, a queryArgs) ([]*models.DeviceDevice, any, error) {
	p := prevention_policies.NewQueryCombinedPreventionPolicyMembersParamsWithContext(ctx)
	p.ID = &id
	applyQuery(a, &p.Filter, &p.Sort, &p.Limit, &p.Offset)
	resp, err := b.c.QueryCombinedPreventionPolicyMembers(p)
	if err != nil {
		return nil, nil, err
	}
	return resp.Payload.Resources, resp.Payload.Meta, nil
}

func (b preventionBackend) create(ctx context.Context, s createSpec) ([]map[string]any, any, error) {
	settings, err := convertSettings[[]*models.PreventionSettingReqV1](s.settings)
	if err != nil {
		return nil, nil, err
	}
	name := s.name
	platform := s.platformName
	item := &models.PreventionCreatePolicyReqV1{
		Name:         &name,
		PlatformName: &platform,
		Description:  s.description,
		CloneID:      s.cloneID,
		Settings:     settings,
	}
	p := prevention_policies.NewCreatePreventionPoliciesParamsWithContext(ctx)
	p.Body = &models.PreventionCreatePoliciesReqV1{Resources: []*models.PreventionCreatePolicyReqV1{item}}
	resp, err := b.c.CreatePreventionPolicies(p)
	if err != nil {
		return nil, nil, err
	}
	records, err := toMaps(resp.Payload.Resources)
	return records, resp.Payload.Meta, err
}

func (b preventionBackend) update(ctx context.Context, s updateSpec) ([]map[string]any, any, error) {
	settings, err := convertSettings[[]*models.PreventionSettingReqV1](s.settings)
	if err != nil {
		return nil, nil, err
	}
	id := s.id
	item := &models.PreventionUpdatePolicyReqV1{ID: &id, Name: s.name, Settings: settings}
	if s.description != "" {
		item.Description = &s.description
	}
	p := prevention_policies.NewUpdatePreventionPoliciesParamsWithContext(ctx)
	p.Body = &models.PreventionUpdatePoliciesReqV1{Resources: []*models.PreventionUpdatePolicyReqV1{item}}
	resp, err := b.c.UpdatePreventionPolicies(p)
	if err != nil {
		return nil, nil, err
	}
	records, err := toMaps(resp.Payload.Resources)
	return records, resp.Payload.Meta, err
}

func (b preventionBackend) deleteByIDs(ctx context.Context, ids []string) (any, error) {
	p := prevention_policies.NewDeletePreventionPoliciesParamsWithContext(ctx)
	p.Ids = ids
	resp, err := b.c.DeletePreventionPolicies(p)
	return metaOf(resp, err)
}

func (b preventionBackend) action(ctx context.Context, actionName string, ids []string, groupID string) ([]map[string]any, any, error) {
	p := prevention_policies.NewPerformPreventionPoliciesActionParamsWithContext(ctx)
	p.ActionName = actionName
	p.Body = actionBody(ids, groupID)
	resp, err := b.c.PerformPreventionPoliciesAction(p)
	if err != nil {
		return nil, nil, err
	}
	records, err := toMaps(resp.Payload.Resources)
	return records, resp.Payload.Meta, err
}

func (b preventionBackend) setPrecedence(ctx context.Context, ids []string, platformName string) (any, error) {
	p := prevention_policies.NewSetPreventionPoliciesPrecedenceParamsWithContext(ctx)
	p.Body = &models.BaseSetPolicyPrecedenceReqV1{Ids: ids, PlatformName: &platformName}
	resp, err := b.c.SetPreventionPoliciesPrecedence(p)
	return metaOf(resp, err)
}

func (b preventionBackend) classifyFQL(err error) ([]base.FQLErrorDetail, bool) {
	var badReq *prevention_policies.QueryCombinedPreventionPoliciesBadRequest
	if !errorsAs(err, &badReq) || badReq.Payload == nil {
		return nil, false
	}
	return base.FQLErrorDetails(badReq.Payload.Errors), true
}

// ---- Sensor Update backend ------------------------------------------------------

type sensorUpdateClient interface {
	QueryCombinedSensorUpdatePoliciesV2(*sensor_update_policies.QueryCombinedSensorUpdatePoliciesV2Params, ...sensor_update_policies.ClientOption) (*sensor_update_policies.QueryCombinedSensorUpdatePoliciesV2OK, error)
	QueryCombinedSensorUpdatePolicyMembers(*sensor_update_policies.QueryCombinedSensorUpdatePolicyMembersParams, ...sensor_update_policies.ClientOption) (*sensor_update_policies.QueryCombinedSensorUpdatePolicyMembersOK, error)
	CreateSensorUpdatePoliciesV2(*sensor_update_policies.CreateSensorUpdatePoliciesV2Params, ...sensor_update_policies.ClientOption) (*sensor_update_policies.CreateSensorUpdatePoliciesV2Created, error)
	UpdateSensorUpdatePoliciesV2(*sensor_update_policies.UpdateSensorUpdatePoliciesV2Params, ...sensor_update_policies.ClientOption) (*sensor_update_policies.UpdateSensorUpdatePoliciesV2OK, error)
	DeleteSensorUpdatePolicies(*sensor_update_policies.DeleteSensorUpdatePoliciesParams, ...sensor_update_policies.ClientOption) (*sensor_update_policies.DeleteSensorUpdatePoliciesOK, error)
	PerformSensorUpdatePoliciesAction(*sensor_update_policies.PerformSensorUpdatePoliciesActionParams, ...sensor_update_policies.ClientOption) (*sensor_update_policies.PerformSensorUpdatePoliciesActionOK, error)
	SetSensorUpdatePoliciesPrecedence(*sensor_update_policies.SetSensorUpdatePoliciesPrecedenceParams, ...sensor_update_policies.ClientOption) (*sensor_update_policies.SetSensorUpdatePoliciesPrecedenceOK, error)
}

type sensorUpdateBackend struct{ c sensorUpdateClient }

func (b sensorUpdateBackend) search(ctx context.Context, a queryArgs) ([]map[string]any, any, error) {
	p := sensor_update_policies.NewQueryCombinedSensorUpdatePoliciesV2ParamsWithContext(ctx)
	applyQuery(a, &p.Filter, &p.Sort, &p.Limit, &p.Offset)
	resp, err := b.c.QueryCombinedSensorUpdatePoliciesV2(p)
	if err != nil {
		return nil, nil, err
	}
	records, err := toMaps(resp.Payload.Resources)
	return records, resp.Payload.Meta, err
}

func (b sensorUpdateBackend) members(ctx context.Context, id string, a queryArgs) ([]*models.DeviceDevice, any, error) {
	p := sensor_update_policies.NewQueryCombinedSensorUpdatePolicyMembersParamsWithContext(ctx)
	p.ID = &id
	applyQuery(a, &p.Filter, &p.Sort, &p.Limit, &p.Offset)
	resp, err := b.c.QueryCombinedSensorUpdatePolicyMembers(p)
	if err != nil {
		return nil, nil, err
	}
	return resp.Payload.Resources, resp.Payload.Meta, nil
}

func (b sensorUpdateBackend) create(ctx context.Context, s createSpec) ([]map[string]any, any, error) {
	settings, err := convertSettings[*models.SensorUpdateSettingsReqV2](s.settings)
	if err != nil {
		return nil, nil, err
	}
	name := s.name
	platform := s.platformName
	item := &models.SensorUpdateCreatePolicyReqV2{
		Name:         &name,
		PlatformName: &platform,
		Description:  s.description,
		Settings:     settings,
	}
	p := sensor_update_policies.NewCreateSensorUpdatePoliciesV2ParamsWithContext(ctx)
	p.Body = &models.SensorUpdateCreatePoliciesReqV2{Resources: []*models.SensorUpdateCreatePolicyReqV2{item}}
	resp, err := b.c.CreateSensorUpdatePoliciesV2(p)
	if err != nil {
		return nil, nil, err
	}
	records, err := toMaps(resp.Payload.Resources)
	return records, resp.Payload.Meta, err
}

func (b sensorUpdateBackend) update(ctx context.Context, s updateSpec) ([]map[string]any, any, error) {
	settings, err := convertSettings[*models.SensorUpdateSettingsReqV2](s.settings)
	if err != nil {
		return nil, nil, err
	}
	id := s.id
	item := &models.SensorUpdateUpdatePolicyReqV2{ID: &id, Name: s.name, Description: s.description, Settings: settings}
	p := sensor_update_policies.NewUpdateSensorUpdatePoliciesV2ParamsWithContext(ctx)
	p.Body = &models.SensorUpdateUpdatePoliciesReqV2{Resources: []*models.SensorUpdateUpdatePolicyReqV2{item}}
	resp, err := b.c.UpdateSensorUpdatePoliciesV2(p)
	if err != nil {
		return nil, nil, err
	}
	records, err := toMaps(resp.Payload.Resources)
	return records, resp.Payload.Meta, err
}

func (b sensorUpdateBackend) deleteByIDs(ctx context.Context, ids []string) (any, error) {
	p := sensor_update_policies.NewDeleteSensorUpdatePoliciesParamsWithContext(ctx)
	p.Ids = ids
	resp, err := b.c.DeleteSensorUpdatePolicies(p)
	return metaOf(resp, err)
}

func (b sensorUpdateBackend) action(ctx context.Context, actionName string, ids []string, groupID string) ([]map[string]any, any, error) {
	p := sensor_update_policies.NewPerformSensorUpdatePoliciesActionParamsWithContext(ctx)
	p.ActionName = actionName
	p.Body = actionBody(ids, groupID)
	resp, err := b.c.PerformSensorUpdatePoliciesAction(p)
	if err != nil {
		return nil, nil, err
	}
	records, err := toMaps(resp.Payload.Resources)
	return records, resp.Payload.Meta, err
}

func (b sensorUpdateBackend) setPrecedence(ctx context.Context, ids []string, platformName string) (any, error) {
	p := sensor_update_policies.NewSetSensorUpdatePoliciesPrecedenceParamsWithContext(ctx)
	p.Body = &models.BaseSetPolicyPrecedenceReqV1{Ids: ids, PlatformName: &platformName}
	resp, err := b.c.SetSensorUpdatePoliciesPrecedence(p)
	return metaOf(resp, err)
}

func (b sensorUpdateBackend) classifyFQL(err error) ([]base.FQLErrorDetail, bool) {
	var badReq *sensor_update_policies.QueryCombinedSensorUpdatePoliciesV2BadRequest
	if !errorsAs(err, &badReq) || badReq.Payload == nil {
		return nil, false
	}
	return base.FQLErrorDetails(badReq.Payload.Errors), true
}

// ---- Firewall backend -----------------------------------------------------------

type firewallClient interface {
	QueryCombinedFirewallPolicies(*firewall_policies.QueryCombinedFirewallPoliciesParams, ...firewall_policies.ClientOption) (*firewall_policies.QueryCombinedFirewallPoliciesOK, error)
	QueryCombinedFirewallPolicyMembers(*firewall_policies.QueryCombinedFirewallPolicyMembersParams, ...firewall_policies.ClientOption) (*firewall_policies.QueryCombinedFirewallPolicyMembersOK, error)
	CreateFirewallPolicies(*firewall_policies.CreateFirewallPoliciesParams, ...firewall_policies.ClientOption) (*firewall_policies.CreateFirewallPoliciesCreated, error)
	UpdateFirewallPolicies(*firewall_policies.UpdateFirewallPoliciesParams, ...firewall_policies.ClientOption) (*firewall_policies.UpdateFirewallPoliciesOK, error)
	DeleteFirewallPolicies(*firewall_policies.DeleteFirewallPoliciesParams, ...firewall_policies.ClientOption) (*firewall_policies.DeleteFirewallPoliciesOK, error)
	PerformFirewallPoliciesAction(*firewall_policies.PerformFirewallPoliciesActionParams, ...firewall_policies.ClientOption) (*firewall_policies.PerformFirewallPoliciesActionOK, error)
	SetFirewallPoliciesPrecedence(*firewall_policies.SetFirewallPoliciesPrecedenceParams, ...firewall_policies.ClientOption) (*firewall_policies.SetFirewallPoliciesPrecedenceOK, error)
}

type firewallBackend struct{ c firewallClient }

func (b firewallBackend) search(ctx context.Context, a queryArgs) ([]map[string]any, any, error) {
	p := firewall_policies.NewQueryCombinedFirewallPoliciesParamsWithContext(ctx)
	applyQuery(a, &p.Filter, &p.Sort, &p.Limit, &p.Offset)
	resp, err := b.c.QueryCombinedFirewallPolicies(p)
	if err != nil {
		return nil, nil, err
	}
	records, err := toMaps(resp.Payload.Resources)
	return records, resp.Payload.Meta, err
}

func (b firewallBackend) members(ctx context.Context, id string, a queryArgs) ([]*models.DeviceDevice, any, error) {
	p := firewall_policies.NewQueryCombinedFirewallPolicyMembersParamsWithContext(ctx)
	p.ID = &id
	applyQuery(a, &p.Filter, &p.Sort, &p.Limit, &p.Offset)
	resp, err := b.c.QueryCombinedFirewallPolicyMembers(p)
	if err != nil {
		return nil, nil, err
	}
	return resp.Payload.Resources, resp.Payload.Meta, nil
}

func (b firewallBackend) create(ctx context.Context, s createSpec) ([]map[string]any, any, error) {
	// Firewall create model has no settings field; settings are managed via the
	// firewall module's rule/rule-group tools, not the policy container.
	name := s.name
	platform := s.platformName
	item := &models.FirewallCreateFirewallPolicyReqV1{
		Name:         &name,
		PlatformName: &platform,
		Description:  s.description,
		CloneID:      s.cloneID,
	}
	p := firewall_policies.NewCreateFirewallPoliciesParamsWithContext(ctx)
	p.Body = &models.FirewallCreateFirewallPoliciesReqV1{Resources: []*models.FirewallCreateFirewallPolicyReqV1{item}}
	resp, err := b.c.CreateFirewallPolicies(p)
	if err != nil {
		return nil, nil, err
	}
	records, err := toMaps(resp.Payload.Resources)
	return records, resp.Payload.Meta, err
}

func (b firewallBackend) update(ctx context.Context, s updateSpec) ([]map[string]any, any, error) {
	id := s.id
	item := &models.FirewallUpdateFirewallPolicyReqV1{ID: &id, Name: s.name, Description: s.description}
	p := firewall_policies.NewUpdateFirewallPoliciesParamsWithContext(ctx)
	p.Body = &models.FirewallUpdateFirewallPoliciesReqV1{Resources: []*models.FirewallUpdateFirewallPolicyReqV1{item}}
	resp, err := b.c.UpdateFirewallPolicies(p)
	if err != nil {
		return nil, nil, err
	}
	records, err := toMaps(resp.Payload.Resources)
	return records, resp.Payload.Meta, err
}

func (b firewallBackend) deleteByIDs(ctx context.Context, ids []string) (any, error) {
	p := firewall_policies.NewDeleteFirewallPoliciesParamsWithContext(ctx)
	p.Ids = ids
	resp, err := b.c.DeleteFirewallPolicies(p)
	return metaOf(resp, err)
}

func (b firewallBackend) action(ctx context.Context, actionName string, ids []string, groupID string) ([]map[string]any, any, error) {
	p := firewall_policies.NewPerformFirewallPoliciesActionParamsWithContext(ctx)
	p.ActionName = actionName
	p.Body = actionBody(ids, groupID)
	resp, err := b.c.PerformFirewallPoliciesAction(p)
	if err != nil {
		return nil, nil, err
	}
	records, err := toMaps(resp.Payload.Resources)
	return records, resp.Payload.Meta, err
}

func (b firewallBackend) setPrecedence(ctx context.Context, ids []string, platformName string) (any, error) {
	p := firewall_policies.NewSetFirewallPoliciesPrecedenceParamsWithContext(ctx)
	p.Body = &models.BaseSetPolicyPrecedenceReqV1{Ids: ids, PlatformName: &platformName}
	resp, err := b.c.SetFirewallPoliciesPrecedence(p)
	return metaOf(resp, err)
}

func (b firewallBackend) classifyFQL(err error) ([]base.FQLErrorDetail, bool) {
	var badReq *firewall_policies.QueryCombinedFirewallPoliciesBadRequest
	if !errorsAs(err, &badReq) || badReq.Payload == nil {
		return nil, false
	}
	return base.FQLErrorDetails(badReq.Payload.Errors), true
}

// ---- Device Control backend -----------------------------------------------------
//
// device_control is the only two-step search: its combined query op has no V2
// variant and drops V2-only fields, so search queries for IDs then fetches full
// records via GetDeviceControlPolicies (operationId getDeviceControlPoliciesV2).

type deviceControlClient interface {
	QueryDeviceControlPolicies(*device_control_policies.QueryDeviceControlPoliciesParams, ...device_control_policies.ClientOption) (*device_control_policies.QueryDeviceControlPoliciesOK, error)
	GetDeviceControlPolicies(*device_control_policies.GetDeviceControlPoliciesParams, ...device_control_policies.ClientOption) (*device_control_policies.GetDeviceControlPoliciesOK, error)
	QueryCombinedDeviceControlPolicyMembers(*device_control_policies.QueryCombinedDeviceControlPolicyMembersParams, ...device_control_policies.ClientOption) (*device_control_policies.QueryCombinedDeviceControlPolicyMembersOK, error)
	CreateDeviceControlPolicies(*device_control_policies.CreateDeviceControlPoliciesParams, ...device_control_policies.ClientOption) (*device_control_policies.CreateDeviceControlPoliciesCreated, error)
	UpdateDeviceControlPolicies(*device_control_policies.UpdateDeviceControlPoliciesParams, ...device_control_policies.ClientOption) (*device_control_policies.UpdateDeviceControlPoliciesOK, error)
	DeleteDeviceControlPolicies(*device_control_policies.DeleteDeviceControlPoliciesParams, ...device_control_policies.ClientOption) (*device_control_policies.DeleteDeviceControlPoliciesOK, error)
	PerformDeviceControlPoliciesAction(*device_control_policies.PerformDeviceControlPoliciesActionParams, ...device_control_policies.ClientOption) (*device_control_policies.PerformDeviceControlPoliciesActionOK, error)
	SetDeviceControlPoliciesPrecedence(*device_control_policies.SetDeviceControlPoliciesPrecedenceParams, ...device_control_policies.ClientOption) (*device_control_policies.SetDeviceControlPoliciesPrecedenceOK, error)
}

type deviceControlBackend struct{ c deviceControlClient }

func (b deviceControlBackend) search(ctx context.Context, a queryArgs) ([]map[string]any, any, error) {
	qp := device_control_policies.NewQueryDeviceControlPoliciesParamsWithContext(ctx)
	applyQuery(a, &qp.Filter, &qp.Sort, &qp.Limit, &qp.Offset)
	qresp, err := b.c.QueryDeviceControlPolicies(qp)
	if err != nil {
		return nil, nil, err
	}
	ids := qresp.Payload.Resources
	if len(ids) == 0 {
		return []map[string]any{}, qresp.Payload.Meta, nil
	}
	gp := device_control_policies.NewGetDeviceControlPoliciesParamsWithContext(ctx)
	gp.Ids = ids
	gresp, err := b.c.GetDeviceControlPolicies(gp)
	if err != nil {
		return nil, nil, err
	}
	records, err := toMaps(gresp.Payload.Resources)
	if err != nil {
		return nil, nil, err
	}
	// Restore the query-step order in case the get endpoint reorders results.
	// Meta comes from the query step (it carries pagination for the search).
	return reorderByID(ids, records), qresp.Payload.Meta, nil
}

func (b deviceControlBackend) members(ctx context.Context, id string, a queryArgs) ([]*models.DeviceDevice, any, error) {
	p := device_control_policies.NewQueryCombinedDeviceControlPolicyMembersParamsWithContext(ctx)
	p.ID = &id
	applyQuery(a, &p.Filter, &p.Sort, &p.Limit, &p.Offset)
	resp, err := b.c.QueryCombinedDeviceControlPolicyMembers(p)
	if err != nil {
		return nil, nil, err
	}
	return resp.Payload.Resources, resp.Payload.Meta, nil
}

func (b deviceControlBackend) create(ctx context.Context, s createSpec) ([]map[string]any, any, error) {
	settings, err := convertSettings[*models.DeviceControlSettingsReqV1](s.settings)
	if err != nil {
		return nil, nil, err
	}
	name := s.name
	platform := s.platformName
	item := &models.DeviceControlCreatePolicyReqV1{
		Name:         &name,
		PlatformName: &platform,
		Description:  s.description,
		CloneID:      s.cloneID,
		Settings:     settings,
	}
	p := device_control_policies.NewCreateDeviceControlPoliciesParamsWithContext(ctx)
	p.Body = &models.DeviceControlCreatePoliciesV1{Resources: []*models.DeviceControlCreatePolicyReqV1{item}}
	resp, err := b.c.CreateDeviceControlPolicies(p)
	if err != nil {
		return nil, nil, err
	}
	records, err := toMaps(resp.Payload.Resources)
	return records, resp.Payload.Meta, err
}

func (b deviceControlBackend) update(ctx context.Context, s updateSpec) ([]map[string]any, any, error) {
	settings, err := convertSettings[*models.DeviceControlSettingsReqV1](s.settings)
	if err != nil {
		return nil, nil, err
	}
	id := s.id
	item := &models.DeviceControlUpdatePolicyReqV1{ID: &id, Name: s.name, Description: s.description, Settings: settings}
	p := device_control_policies.NewUpdateDeviceControlPoliciesParamsWithContext(ctx)
	p.Body = &models.DeviceControlUpdatePoliciesReqV1{Resources: []*models.DeviceControlUpdatePolicyReqV1{item}}
	resp, err := b.c.UpdateDeviceControlPolicies(p)
	if err != nil {
		return nil, nil, err
	}
	records, err := toMaps(resp.Payload.Resources)
	return records, resp.Payload.Meta, err
}

func (b deviceControlBackend) deleteByIDs(ctx context.Context, ids []string) (any, error) {
	p := device_control_policies.NewDeleteDeviceControlPoliciesParamsWithContext(ctx)
	p.Ids = ids
	resp, err := b.c.DeleteDeviceControlPolicies(p)
	return metaOf(resp, err)
}

func (b deviceControlBackend) action(ctx context.Context, actionName string, ids []string, groupID string) ([]map[string]any, any, error) {
	p := device_control_policies.NewPerformDeviceControlPoliciesActionParamsWithContext(ctx)
	p.ActionName = actionName
	p.Body = actionBody(ids, groupID)
	resp, err := b.c.PerformDeviceControlPoliciesAction(p)
	if err != nil {
		return nil, nil, err
	}
	records, err := toMaps(resp.Payload.Resources)
	return records, resp.Payload.Meta, err
}

func (b deviceControlBackend) setPrecedence(ctx context.Context, ids []string, platformName string) (any, error) {
	p := device_control_policies.NewSetDeviceControlPoliciesPrecedenceParamsWithContext(ctx)
	p.Body = &models.BaseSetPolicyPrecedenceReqV1{Ids: ids, PlatformName: &platformName}
	resp, err := b.c.SetDeviceControlPoliciesPrecedence(p)
	return metaOf(resp, err)
}

func (b deviceControlBackend) classifyFQL(err error) ([]base.FQLErrorDetail, bool) {
	var badReq *device_control_policies.QueryDeviceControlPoliciesBadRequest
	if !errorsAs(err, &badReq) || badReq.Payload == nil {
		return nil, false
	}
	return base.FQLErrorDetails(badReq.Payload.Errors), true
}

// ---- Response backend -----------------------------------------------------------
//
// The response_policies sub-client uses the RTResponsePolicies method prefix, but
// the request/response models use the RemoteResponse prefix.

type responseClient interface {
	QueryCombinedRTResponsePolicies(*response_policies.QueryCombinedRTResponsePoliciesParams, ...response_policies.ClientOption) (*response_policies.QueryCombinedRTResponsePoliciesOK, error)
	QueryCombinedRTResponsePolicyMembers(*response_policies.QueryCombinedRTResponsePolicyMembersParams, ...response_policies.ClientOption) (*response_policies.QueryCombinedRTResponsePolicyMembersOK, error)
	CreateRTResponsePolicies(*response_policies.CreateRTResponsePoliciesParams, ...response_policies.ClientOption) (*response_policies.CreateRTResponsePoliciesCreated, error)
	UpdateRTResponsePolicies(*response_policies.UpdateRTResponsePoliciesParams, ...response_policies.ClientOption) (*response_policies.UpdateRTResponsePoliciesOK, error)
	DeleteRTResponsePolicies(*response_policies.DeleteRTResponsePoliciesParams, ...response_policies.ClientOption) (*response_policies.DeleteRTResponsePoliciesOK, error)
	PerformRTResponsePoliciesAction(*response_policies.PerformRTResponsePoliciesActionParams, ...response_policies.ClientOption) (*response_policies.PerformRTResponsePoliciesActionOK, error)
	SetRTResponsePoliciesPrecedence(*response_policies.SetRTResponsePoliciesPrecedenceParams, ...response_policies.ClientOption) (*response_policies.SetRTResponsePoliciesPrecedenceOK, error)
}

type responseBackend struct{ c responseClient }

func (b responseBackend) search(ctx context.Context, a queryArgs) ([]map[string]any, any, error) {
	p := response_policies.NewQueryCombinedRTResponsePoliciesParamsWithContext(ctx)
	applyQuery(a, &p.Filter, &p.Sort, &p.Limit, &p.Offset)
	resp, err := b.c.QueryCombinedRTResponsePolicies(p)
	if err != nil {
		return nil, nil, err
	}
	records, err := toMaps(resp.Payload.Resources)
	return records, resp.Payload.Meta, err
}

func (b responseBackend) members(ctx context.Context, id string, a queryArgs) ([]*models.DeviceDevice, any, error) {
	p := response_policies.NewQueryCombinedRTResponsePolicyMembersParamsWithContext(ctx)
	p.ID = &id
	applyQuery(a, &p.Filter, &p.Sort, &p.Limit, &p.Offset)
	resp, err := b.c.QueryCombinedRTResponsePolicyMembers(p)
	if err != nil {
		return nil, nil, err
	}
	return resp.Payload.Resources, resp.Payload.Meta, nil
}

func (b responseBackend) create(ctx context.Context, s createSpec) ([]map[string]any, any, error) {
	settings, err := convertSettings[[]*models.PreventionSettingReqV1](s.settings)
	if err != nil {
		return nil, nil, err
	}
	name := s.name
	platform := s.platformName
	item := &models.RemoteResponseCreatePolicyReqV1{
		Name:         &name,
		PlatformName: &platform,
		Description:  s.description,
		CloneID:      s.cloneID,
		Settings:     settings,
	}
	p := response_policies.NewCreateRTResponsePoliciesParamsWithContext(ctx)
	p.Body = &models.RemoteResponseCreatePoliciesV1{Resources: []*models.RemoteResponseCreatePolicyReqV1{item}}
	resp, err := b.c.CreateRTResponsePolicies(p)
	if err != nil {
		return nil, nil, err
	}
	records, err := toMaps(resp.Payload.Resources)
	return records, resp.Payload.Meta, err
}

func (b responseBackend) update(ctx context.Context, s updateSpec) ([]map[string]any, any, error) {
	settings, err := convertSettings[[]*models.PreventionSettingReqV1](s.settings)
	if err != nil {
		return nil, nil, err
	}
	id := s.id
	item := &models.RemoteResponseUpdatePolicyReqV1{ID: &id, Name: s.name, Settings: settings}
	if s.description != "" {
		item.Description = &s.description
	}
	p := response_policies.NewUpdateRTResponsePoliciesParamsWithContext(ctx)
	p.Body = &models.RemoteResponseUpdatePoliciesReqV1{Resources: []*models.RemoteResponseUpdatePolicyReqV1{item}}
	resp, err := b.c.UpdateRTResponsePolicies(p)
	if err != nil {
		return nil, nil, err
	}
	records, err := toMaps(resp.Payload.Resources)
	return records, resp.Payload.Meta, err
}

func (b responseBackend) deleteByIDs(ctx context.Context, ids []string) (any, error) {
	p := response_policies.NewDeleteRTResponsePoliciesParamsWithContext(ctx)
	p.Ids = ids
	resp, err := b.c.DeleteRTResponsePolicies(p)
	return metaOf(resp, err)
}

func (b responseBackend) action(ctx context.Context, actionName string, ids []string, groupID string) ([]map[string]any, any, error) {
	p := response_policies.NewPerformRTResponsePoliciesActionParamsWithContext(ctx)
	p.ActionName = actionName
	p.Body = actionBody(ids, groupID)
	resp, err := b.c.PerformRTResponsePoliciesAction(p)
	if err != nil {
		return nil, nil, err
	}
	records, err := toMaps(resp.Payload.Resources)
	return records, resp.Payload.Meta, err
}

func (b responseBackend) setPrecedence(ctx context.Context, ids []string, platformName string) (any, error) {
	p := response_policies.NewSetRTResponsePoliciesPrecedenceParamsWithContext(ctx)
	p.Body = &models.BaseSetPolicyPrecedenceReqV1{Ids: ids, PlatformName: &platformName}
	resp, err := b.c.SetRTResponsePoliciesPrecedence(p)
	return metaOf(resp, err)
}

func (b responseBackend) classifyFQL(err error) ([]base.FQLErrorDetail, bool) {
	var badReq *response_policies.QueryCombinedRTResponsePoliciesBadRequest
	if !errorsAs(err, &badReq) || badReq.Payload == nil {
		return nil, false
	}
	return base.FQLErrorDetails(badReq.Payload.Errors), true
}

// ---- Content Update backend -----------------------------------------------------
//
// content_update is platform-agnostic: its create model has no platform_name
// field and its precedence body model (BaseSetContentUpdatePolicyPrecedenceReqV1)
// has no platform_name field, so platformName is ignored here.

type contentUpdateClient interface {
	QueryCombinedContentUpdatePolicies(*content_update_policies.QueryCombinedContentUpdatePoliciesParams, ...content_update_policies.ClientOption) (*content_update_policies.QueryCombinedContentUpdatePoliciesOK, error)
	QueryCombinedContentUpdatePolicyMembers(*content_update_policies.QueryCombinedContentUpdatePolicyMembersParams, ...content_update_policies.ClientOption) (*content_update_policies.QueryCombinedContentUpdatePolicyMembersOK, error)
	CreateContentUpdatePolicies(*content_update_policies.CreateContentUpdatePoliciesParams, ...content_update_policies.ClientOption) (*content_update_policies.CreateContentUpdatePoliciesCreated, error)
	UpdateContentUpdatePolicies(*content_update_policies.UpdateContentUpdatePoliciesParams, ...content_update_policies.ClientOption) (*content_update_policies.UpdateContentUpdatePoliciesOK, error)
	DeleteContentUpdatePolicies(*content_update_policies.DeleteContentUpdatePoliciesParams, ...content_update_policies.ClientOption) (*content_update_policies.DeleteContentUpdatePoliciesOK, error)
	PerformContentUpdatePoliciesAction(*content_update_policies.PerformContentUpdatePoliciesActionParams, ...content_update_policies.ClientOption) (*content_update_policies.PerformContentUpdatePoliciesActionOK, error)
	SetContentUpdatePoliciesPrecedence(*content_update_policies.SetContentUpdatePoliciesPrecedenceParams, ...content_update_policies.ClientOption) (*content_update_policies.SetContentUpdatePoliciesPrecedenceOK, error)
}

type contentUpdateBackend struct{ c contentUpdateClient }

func (b contentUpdateBackend) search(ctx context.Context, a queryArgs) ([]map[string]any, any, error) {
	p := content_update_policies.NewQueryCombinedContentUpdatePoliciesParamsWithContext(ctx)
	applyQuery(a, &p.Filter, &p.Sort, &p.Limit, &p.Offset)
	resp, err := b.c.QueryCombinedContentUpdatePolicies(p)
	if err != nil {
		return nil, nil, err
	}
	records, err := toMaps(resp.Payload.Resources)
	return records, resp.Payload.Meta, err
}

func (b contentUpdateBackend) members(ctx context.Context, id string, a queryArgs) ([]*models.DeviceDevice, any, error) {
	p := content_update_policies.NewQueryCombinedContentUpdatePolicyMembersParamsWithContext(ctx)
	p.ID = &id
	applyQuery(a, &p.Filter, &p.Sort, &p.Limit, &p.Offset)
	resp, err := b.c.QueryCombinedContentUpdatePolicyMembers(p)
	if err != nil {
		return nil, nil, err
	}
	return resp.Payload.Resources, resp.Payload.Meta, nil
}

func (b contentUpdateBackend) create(ctx context.Context, s createSpec) ([]map[string]any, any, error) {
	settings, err := convertSettings[*models.ContentUpdateContentUpdateSettingsReqV1](s.settings)
	if err != nil {
		return nil, nil, err
	}
	name := s.name
	item := &models.ContentUpdateCreatePolicyReqV1{
		Name:        &name,
		Description: s.description,
		Settings:    settings,
	}
	p := content_update_policies.NewCreateContentUpdatePoliciesParamsWithContext(ctx)
	p.Body = &models.ContentUpdateCreatePoliciesReqV1{Resources: []*models.ContentUpdateCreatePolicyReqV1{item}}
	resp, err := b.c.CreateContentUpdatePolicies(p)
	if err != nil {
		return nil, nil, err
	}
	records, err := toMaps(resp.Payload.Resources)
	return records, resp.Payload.Meta, err
}

func (b contentUpdateBackend) update(ctx context.Context, s updateSpec) ([]map[string]any, any, error) {
	settings, err := convertSettings[*models.ContentUpdateContentUpdateSettingsReqV1](s.settings)
	if err != nil {
		return nil, nil, err
	}
	id := s.id
	item := &models.ContentUpdateUpdatePolicyReqV1{ID: &id, Name: s.name, Description: s.description, Settings: settings}
	p := content_update_policies.NewUpdateContentUpdatePoliciesParamsWithContext(ctx)
	p.Body = &models.ContentUpdateUpdatePoliciesReqV1{Resources: []*models.ContentUpdateUpdatePolicyReqV1{item}}
	resp, err := b.c.UpdateContentUpdatePolicies(p)
	if err != nil {
		return nil, nil, err
	}
	records, err := toMaps(resp.Payload.Resources)
	return records, resp.Payload.Meta, err
}

func (b contentUpdateBackend) deleteByIDs(ctx context.Context, ids []string) (any, error) {
	p := content_update_policies.NewDeleteContentUpdatePoliciesParamsWithContext(ctx)
	p.Ids = ids
	resp, err := b.c.DeleteContentUpdatePolicies(p)
	return metaOf(resp, err)
}

func (b contentUpdateBackend) action(ctx context.Context, actionName string, ids []string, groupID string) ([]map[string]any, any, error) {
	p := content_update_policies.NewPerformContentUpdatePoliciesActionParamsWithContext(ctx)
	p.ActionName = actionName
	p.Body = actionBody(ids, groupID)
	resp, err := b.c.PerformContentUpdatePoliciesAction(p)
	if err != nil {
		return nil, nil, err
	}
	records, err := toMaps(resp.Payload.Resources)
	return records, resp.Payload.Meta, err
}

func (b contentUpdateBackend) setPrecedence(ctx context.Context, ids []string, _ string) (any, error) {
	// content_update precedence body has no platform_name field.
	p := content_update_policies.NewSetContentUpdatePoliciesPrecedenceParamsWithContext(ctx)
	p.Body = &models.BaseSetContentUpdatePolicyPrecedenceReqV1{Ids: ids}
	resp, err := b.c.SetContentUpdatePoliciesPrecedence(p)
	return metaOf(resp, err)
}

func (b contentUpdateBackend) classifyFQL(err error) ([]base.FQLErrorDetail, bool) {
	var badReq *content_update_policies.QueryCombinedContentUpdatePoliciesBadRequest
	if !errorsAs(err, &badReq) || badReq.Payload == nil {
		return nil, false
	}
	return base.FQLErrorDetails(badReq.Payload.Errors), true
}

// metaOf returns the raw meta object from a gofalcon *OK response (delete and
// set-precedence ops, which carry *models.MsaQueryResponse), or the transport
// error unchanged. When err is non-nil it short-circuits with a nil meta. The
// meta is read reflectively so one helper serves every sub-client's *OK type
// without a per-type switch; a nil resp/payload or absent field yields nil meta,
// which base.ActionResult.WithMeta then omits.
func metaOf(resp any, err error) (any, error) {
	if err != nil {
		return nil, err
	}
	return payloadMeta(resp), nil
}

// payloadMeta reads resp.Payload.Meta from any gofalcon *OK response reflectively,
// returning nil when the field or payload is absent or nil.
func payloadMeta(resp any) any {
	v := reflect.ValueOf(resp)
	for v.Kind() == reflect.Pointer {
		if v.IsNil() {
			return nil
		}
		v = v.Elem()
	}
	if v.Kind() != reflect.Struct {
		return nil
	}
	payload := v.FieldByName("Payload")
	if !payload.IsValid() {
		return nil
	}
	for payload.Kind() == reflect.Pointer {
		if payload.IsNil() {
			return nil
		}
		payload = payload.Elem()
	}
	if payload.Kind() != reflect.Struct {
		return nil
	}
	meta := payload.FieldByName("Meta")
	if !meta.IsValid() || (meta.Kind() == reflect.Pointer && meta.IsNil()) {
		return nil
	}
	return meta.Interface()
}
