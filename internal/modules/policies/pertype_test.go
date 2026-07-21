package policies

import (
	"context"
	"errors"
	"testing"

	"github.com/crowdstrike/gofalcon/falcon/client/content_update_policies"
	"github.com/crowdstrike/gofalcon/falcon/client/firewall_policies"
	"github.com/crowdstrike/gofalcon/falcon/client/response_policies"
	"github.com/crowdstrike/gofalcon/falcon/client/sensor_update_policies"
	"github.com/crowdstrike/gofalcon/falcon/models"
)

// These tests exercise the remaining four backend types (sensor_update, firewall,
// response, content_update) that share prevention's single-call structure. They
// cover each type's create body shape and search happy-path so the per-type
// branches are not left untested; the divergent behaviors (device_control two-step,
// content_update precedence without platform) are covered in backends_test.go.

// ---- sensor_update -------------------------------------------------------------

type fakeSensorUpdate struct {
	lastCreateBody *models.SensorUpdateCreatePoliciesReqV2
}

func (f *fakeSensorUpdate) QueryCombinedSensorUpdatePoliciesV2(*sensor_update_policies.QueryCombinedSensorUpdatePoliciesV2Params, ...sensor_update_policies.ClientOption) (*sensor_update_policies.QueryCombinedSensorUpdatePoliciesV2OK, error) {
	id := "s1"
	return &sensor_update_policies.QueryCombinedSensorUpdatePoliciesV2OK{Payload: &models.SensorUpdateRespV2{Resources: []*models.SensorUpdatePolicyV2{{ID: &id}}}}, nil
}
func (f *fakeSensorUpdate) QueryCombinedSensorUpdatePolicyMembers(*sensor_update_policies.QueryCombinedSensorUpdatePolicyMembersParams, ...sensor_update_policies.ClientOption) (*sensor_update_policies.QueryCombinedSensorUpdatePolicyMembersOK, error) {
	return &sensor_update_policies.QueryCombinedSensorUpdatePolicyMembersOK{Payload: &models.BasePolicyMembersRespV1{}}, nil
}
func (f *fakeSensorUpdate) CreateSensorUpdatePoliciesV2(p *sensor_update_policies.CreateSensorUpdatePoliciesV2Params, _ ...sensor_update_policies.ClientOption) (*sensor_update_policies.CreateSensorUpdatePoliciesV2Created, error) {
	f.lastCreateBody = p.Body
	id := "new"
	return &sensor_update_policies.CreateSensorUpdatePoliciesV2Created{Payload: &models.SensorUpdateRespV2{Resources: []*models.SensorUpdatePolicyV2{{ID: &id}}}}, nil
}
func (f *fakeSensorUpdate) UpdateSensorUpdatePoliciesV2(*sensor_update_policies.UpdateSensorUpdatePoliciesV2Params, ...sensor_update_policies.ClientOption) (*sensor_update_policies.UpdateSensorUpdatePoliciesV2OK, error) {
	return &sensor_update_policies.UpdateSensorUpdatePoliciesV2OK{Payload: &models.SensorUpdateRespV2{}}, nil
}
func (f *fakeSensorUpdate) DeleteSensorUpdatePolicies(*sensor_update_policies.DeleteSensorUpdatePoliciesParams, ...sensor_update_policies.ClientOption) (*sensor_update_policies.DeleteSensorUpdatePoliciesOK, error) {
	return &sensor_update_policies.DeleteSensorUpdatePoliciesOK{Payload: &models.MsaQueryResponse{}}, nil
}
func (f *fakeSensorUpdate) PerformSensorUpdatePoliciesAction(*sensor_update_policies.PerformSensorUpdatePoliciesActionParams, ...sensor_update_policies.ClientOption) (*sensor_update_policies.PerformSensorUpdatePoliciesActionOK, error) {
	return &sensor_update_policies.PerformSensorUpdatePoliciesActionOK{Payload: &models.SensorUpdateRespV1{}}, nil
}
func (f *fakeSensorUpdate) SetSensorUpdatePoliciesPrecedence(*sensor_update_policies.SetSensorUpdatePoliciesPrecedenceParams, ...sensor_update_policies.ClientOption) (*sensor_update_policies.SetSensorUpdatePoliciesPrecedenceOK, error) {
	return &sensor_update_policies.SetSensorUpdatePoliciesPrecedenceOK{Payload: &models.MsaQueryResponse{}}, nil
}

func TestSensorUpdateBackend(t *testing.T) {
	t.Parallel()
	fake := &fakeSensorUpdate{}
	b := sensorUpdateBackend{c: fake}

	recs, _, err := b.search(context.Background(), queryArgs{limit: 100})
	if err != nil || len(recs) != 1 || recs[0]["id"] != "s1" {
		t.Fatalf("search: err=%v recs=%v", err, recs)
	}

	recs, _, err = b.create(context.Background(), createSpec{name: "n", platformName: "Windows"})
	if err != nil || len(recs) != 1 {
		t.Fatalf("create: err=%v recs=%v", err, recs)
	}
	item := fake.lastCreateBody.Resources[0]
	if item.Name == nil || *item.Name != "n" || item.PlatformName == nil || *item.PlatformName != "Windows" {
		t.Fatalf("unexpected sensor_update create item: %+v", item)
	}
	if _, ok := b.classifyFQL(errors.New("x")); ok {
		t.Fatalf("classifyFQL should not match a plain error")
	}
	if _, err := b.deleteByIDs(context.Background(), []string{"a"}); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := b.setPrecedence(context.Background(), []string{"a"}, "Windows"); err != nil {
		t.Fatalf("setPrecedence: %v", err)
	}
}

// ---- firewall (create has no settings field) -----------------------------------

type fakeFirewall struct {
	lastCreateBody *models.FirewallCreateFirewallPoliciesReqV1
}

func (f *fakeFirewall) QueryCombinedFirewallPolicies(*firewall_policies.QueryCombinedFirewallPoliciesParams, ...firewall_policies.ClientOption) (*firewall_policies.QueryCombinedFirewallPoliciesOK, error) {
	id := "f1"
	return &firewall_policies.QueryCombinedFirewallPoliciesOK{Payload: &models.FirewallRespV1{Resources: []*models.FirewallPolicyV1{{ID: &id}}}}, nil
}
func (f *fakeFirewall) QueryCombinedFirewallPolicyMembers(*firewall_policies.QueryCombinedFirewallPolicyMembersParams, ...firewall_policies.ClientOption) (*firewall_policies.QueryCombinedFirewallPolicyMembersOK, error) {
	return &firewall_policies.QueryCombinedFirewallPolicyMembersOK{Payload: &models.BasePolicyMembersRespV1{}}, nil
}
func (f *fakeFirewall) CreateFirewallPolicies(p *firewall_policies.CreateFirewallPoliciesParams, _ ...firewall_policies.ClientOption) (*firewall_policies.CreateFirewallPoliciesCreated, error) {
	f.lastCreateBody = p.Body
	id := "new"
	return &firewall_policies.CreateFirewallPoliciesCreated{Payload: &models.FirewallRespV1{Resources: []*models.FirewallPolicyV1{{ID: &id}}}}, nil
}
func (f *fakeFirewall) UpdateFirewallPolicies(*firewall_policies.UpdateFirewallPoliciesParams, ...firewall_policies.ClientOption) (*firewall_policies.UpdateFirewallPoliciesOK, error) {
	return &firewall_policies.UpdateFirewallPoliciesOK{Payload: &models.FirewallRespV1{}}, nil
}
func (f *fakeFirewall) DeleteFirewallPolicies(*firewall_policies.DeleteFirewallPoliciesParams, ...firewall_policies.ClientOption) (*firewall_policies.DeleteFirewallPoliciesOK, error) {
	return &firewall_policies.DeleteFirewallPoliciesOK{Payload: &models.MsaQueryResponse{}}, nil
}
func (f *fakeFirewall) PerformFirewallPoliciesAction(*firewall_policies.PerformFirewallPoliciesActionParams, ...firewall_policies.ClientOption) (*firewall_policies.PerformFirewallPoliciesActionOK, error) {
	return &firewall_policies.PerformFirewallPoliciesActionOK{Payload: &models.FirewallRespV1{}}, nil
}
func (f *fakeFirewall) SetFirewallPoliciesPrecedence(*firewall_policies.SetFirewallPoliciesPrecedenceParams, ...firewall_policies.ClientOption) (*firewall_policies.SetFirewallPoliciesPrecedenceOK, error) {
	return &firewall_policies.SetFirewallPoliciesPrecedenceOK{Payload: &models.MsaQueryResponse{}}, nil
}

func TestFirewallBackend(t *testing.T) {
	t.Parallel()
	fake := &fakeFirewall{}
	b := firewallBackend{c: fake}

	recs, _, err := b.search(context.Background(), queryArgs{limit: 100})
	if err != nil || len(recs) != 1 || recs[0]["id"] != "f1" {
		t.Fatalf("search: err=%v recs=%v", err, recs)
	}
	// Firewall create ignores settings (its model has no settings field) but still
	// carries name and platform.
	recs, _, err = b.create(context.Background(), createSpec{name: "n", platformName: "Linux", settings: map[string]any{"ignored": true}})
	if err != nil || len(recs) != 1 {
		t.Fatalf("create: err=%v recs=%v", err, recs)
	}
	item := fake.lastCreateBody.Resources[0]
	if item.Name == nil || *item.Name != "n" || item.PlatformName == nil || *item.PlatformName != "Linux" {
		t.Fatalf("unexpected firewall create item: %+v", item)
	}
	if _, _, err := b.update(context.Background(), updateSpec{id: "f1", name: "n2"}); err != nil {
		t.Fatalf("update: %v", err)
	}
	if _, _, err := b.action(context.Background(), "enable", []string{"f1"}, ""); err != nil {
		t.Fatalf("action: %v", err)
	}
	if _, ok := b.classifyFQL(errors.New("x")); ok {
		t.Fatalf("classifyFQL should not match a plain error")
	}
}

// ---- response (RTResponse methods, RemoteResponse models) ----------------------

type fakeResponse struct {
	lastCreateBody *models.RemoteResponseCreatePoliciesV1
}

func (f *fakeResponse) QueryCombinedRTResponsePolicies(*response_policies.QueryCombinedRTResponsePoliciesParams, ...response_policies.ClientOption) (*response_policies.QueryCombinedRTResponsePoliciesOK, error) {
	id := "r1"
	return &response_policies.QueryCombinedRTResponsePoliciesOK{Payload: &models.RemoteResponseRespV1{Resources: []*models.RemoteResponsePolicyV1{{ID: &id}}}}, nil
}
func (f *fakeResponse) QueryCombinedRTResponsePolicyMembers(*response_policies.QueryCombinedRTResponsePolicyMembersParams, ...response_policies.ClientOption) (*response_policies.QueryCombinedRTResponsePolicyMembersOK, error) {
	return &response_policies.QueryCombinedRTResponsePolicyMembersOK{Payload: &models.BasePolicyMembersRespV1{}}, nil
}
func (f *fakeResponse) CreateRTResponsePolicies(p *response_policies.CreateRTResponsePoliciesParams, _ ...response_policies.ClientOption) (*response_policies.CreateRTResponsePoliciesCreated, error) {
	f.lastCreateBody = p.Body
	id := "new"
	return &response_policies.CreateRTResponsePoliciesCreated{Payload: &models.RemoteResponseRespV1{Resources: []*models.RemoteResponsePolicyV1{{ID: &id}}}}, nil
}
func (f *fakeResponse) UpdateRTResponsePolicies(*response_policies.UpdateRTResponsePoliciesParams, ...response_policies.ClientOption) (*response_policies.UpdateRTResponsePoliciesOK, error) {
	return &response_policies.UpdateRTResponsePoliciesOK{Payload: &models.RemoteResponseRespV1{}}, nil
}
func (f *fakeResponse) DeleteRTResponsePolicies(*response_policies.DeleteRTResponsePoliciesParams, ...response_policies.ClientOption) (*response_policies.DeleteRTResponsePoliciesOK, error) {
	return &response_policies.DeleteRTResponsePoliciesOK{Payload: &models.MsaQueryResponse{}}, nil
}
func (f *fakeResponse) PerformRTResponsePoliciesAction(*response_policies.PerformRTResponsePoliciesActionParams, ...response_policies.ClientOption) (*response_policies.PerformRTResponsePoliciesActionOK, error) {
	return &response_policies.PerformRTResponsePoliciesActionOK{Payload: &models.RemoteResponseRespV1{}}, nil
}
func (f *fakeResponse) SetRTResponsePoliciesPrecedence(*response_policies.SetRTResponsePoliciesPrecedenceParams, ...response_policies.ClientOption) (*response_policies.SetRTResponsePoliciesPrecedenceOK, error) {
	return &response_policies.SetRTResponsePoliciesPrecedenceOK{Payload: &models.MsaQueryResponse{}}, nil
}

func TestResponseBackend(t *testing.T) {
	t.Parallel()
	fake := &fakeResponse{}
	b := responseBackend{c: fake}

	recs, _, err := b.search(context.Background(), queryArgs{limit: 100})
	if err != nil || len(recs) != 1 || recs[0]["id"] != "r1" {
		t.Fatalf("search: err=%v recs=%v", err, recs)
	}
	recs, _, err = b.create(context.Background(), createSpec{name: "n", platformName: "Mac"})
	if err != nil || len(recs) != 1 {
		t.Fatalf("create: err=%v recs=%v", err, recs)
	}
	item := fake.lastCreateBody.Resources[0]
	if item.Name == nil || *item.Name != "n" || item.PlatformName == nil || *item.PlatformName != "Mac" {
		t.Fatalf("unexpected response create item: %+v", item)
	}
	if _, _, err := b.update(context.Background(), updateSpec{id: "r1", name: "n2", description: "d"}); err != nil {
		t.Fatalf("update: %v", err)
	}
	if _, _, err := b.action(context.Background(), "add-rule-group", []string{"r1"}, "g1"); err != nil {
		t.Fatalf("action: %v", err)
	}
	if _, err := b.deleteByIDs(context.Background(), []string{"r1"}); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := b.setPrecedence(context.Background(), []string{"r1"}, "Mac"); err != nil {
		t.Fatalf("setPrecedence: %v", err)
	}
}

// ---- content_update (create has no platform field) -----------------------------

type fakeContentUpdateCreate struct {
	lastCreateBody *models.ContentUpdateCreatePoliciesReqV1
	fakeContentUpdate
}

func (f *fakeContentUpdateCreate) QueryCombinedContentUpdatePolicies(*content_update_policies.QueryCombinedContentUpdatePoliciesParams, ...content_update_policies.ClientOption) (*content_update_policies.QueryCombinedContentUpdatePoliciesOK, error) {
	id := "c1"
	return &content_update_policies.QueryCombinedContentUpdatePoliciesOK{Payload: &models.ContentUpdateRespV1{Resources: []*models.ContentUpdatePolicyV1{{ID: &id}}}}, nil
}
func (f *fakeContentUpdateCreate) CreateContentUpdatePolicies(p *content_update_policies.CreateContentUpdatePoliciesParams, _ ...content_update_policies.ClientOption) (*content_update_policies.CreateContentUpdatePoliciesCreated, error) {
	f.lastCreateBody = p.Body
	id := "new"
	return &content_update_policies.CreateContentUpdatePoliciesCreated{Payload: &models.ContentUpdateRespV1{Resources: []*models.ContentUpdatePolicyV1{{ID: &id}}}}, nil
}
func (f *fakeContentUpdateCreate) PerformContentUpdatePoliciesAction(*content_update_policies.PerformContentUpdatePoliciesActionParams, ...content_update_policies.ClientOption) (*content_update_policies.PerformContentUpdatePoliciesActionOK, error) {
	return &content_update_policies.PerformContentUpdatePoliciesActionOK{Payload: &models.ContentUpdateRespV1{}}, nil
}
func (f *fakeContentUpdateCreate) UpdateContentUpdatePolicies(*content_update_policies.UpdateContentUpdatePoliciesParams, ...content_update_policies.ClientOption) (*content_update_policies.UpdateContentUpdatePoliciesOK, error) {
	return &content_update_policies.UpdateContentUpdatePoliciesOK{Payload: &models.ContentUpdateRespV1{}}, nil
}
func (f *fakeContentUpdateCreate) DeleteContentUpdatePolicies(*content_update_policies.DeleteContentUpdatePoliciesParams, ...content_update_policies.ClientOption) (*content_update_policies.DeleteContentUpdatePoliciesOK, error) {
	return &content_update_policies.DeleteContentUpdatePoliciesOK{Payload: &models.MsaQueryResponse{}}, nil
}

func TestContentUpdateBackend(t *testing.T) {
	t.Parallel()
	fake := &fakeContentUpdateCreate{}
	b := contentUpdateBackend{c: fake}

	recs, _, err := b.search(context.Background(), queryArgs{limit: 100})
	if err != nil || len(recs) != 1 || recs[0]["id"] != "c1" {
		t.Fatalf("search: err=%v recs=%v", err, recs)
	}
	// content_update create carries name + description but no platform field.
	recs, _, err = b.create(context.Background(), createSpec{name: "n", description: "d"})
	if err != nil || len(recs) != 1 {
		t.Fatalf("create: err=%v recs=%v", err, recs)
	}
	item := fake.lastCreateBody.Resources[0]
	if item.Name == nil || *item.Name != "n" || item.Description != "d" {
		t.Fatalf("unexpected content_update create item: %+v", item)
	}
	if _, _, err := b.update(context.Background(), updateSpec{id: "c1", name: "n2"}); err != nil {
		t.Fatalf("update: %v", err)
	}
	if _, _, err := b.action(context.Background(), "override-allow", []string{"c1"}, ""); err != nil {
		t.Fatalf("action: %v", err)
	}
	if _, err := b.deleteByIDs(context.Background(), []string{"c1"}); err != nil {
		t.Fatalf("delete: %v", err)
	}
}
