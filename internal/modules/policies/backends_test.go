package policies

import (
	"context"
	"errors"
	"testing"

	"github.com/crowdstrike/gofalcon/falcon/client/content_update_policies"
	"github.com/crowdstrike/gofalcon/falcon/client/device_control_policies"
	"github.com/crowdstrike/gofalcon/falcon/client/prevention_policies"
	"github.com/crowdstrike/gofalcon/falcon/models"
)

// ---- device_control two-step search --------------------------------------------

// fakeDeviceControl implements deviceControlClient for the two-step search test.
type fakeDeviceControl struct {
	queryIDs   []string
	queryMeta  *models.MsaMetaInfo
	getRecords []*models.DeviceControlPolicyV1
	lastGetIDs []string
	getCalls   int
}

func (f *fakeDeviceControl) QueryDeviceControlPolicies(*device_control_policies.QueryDeviceControlPoliciesParams, ...device_control_policies.ClientOption) (*device_control_policies.QueryDeviceControlPoliciesOK, error) {
	return &device_control_policies.QueryDeviceControlPoliciesOK{
		Payload: &models.MsaQueryResponse{Resources: f.queryIDs, Meta: f.queryMeta},
	}, nil
}
func (f *fakeDeviceControl) GetDeviceControlPolicies(p *device_control_policies.GetDeviceControlPoliciesParams, _ ...device_control_policies.ClientOption) (*device_control_policies.GetDeviceControlPoliciesOK, error) {
	f.getCalls++
	f.lastGetIDs = p.Ids
	return &device_control_policies.GetDeviceControlPoliciesOK{
		Payload: &models.DeviceControlRespV1{Resources: f.getRecords},
	}, nil
}
func (f *fakeDeviceControl) QueryCombinedDeviceControlPolicyMembers(*device_control_policies.QueryCombinedDeviceControlPolicyMembersParams, ...device_control_policies.ClientOption) (*device_control_policies.QueryCombinedDeviceControlPolicyMembersOK, error) {
	return nil, errors.New("not used")
}
func (f *fakeDeviceControl) CreateDeviceControlPolicies(*device_control_policies.CreateDeviceControlPoliciesParams, ...device_control_policies.ClientOption) (*device_control_policies.CreateDeviceControlPoliciesCreated, error) {
	return nil, errors.New("not used")
}
func (f *fakeDeviceControl) UpdateDeviceControlPolicies(*device_control_policies.UpdateDeviceControlPoliciesParams, ...device_control_policies.ClientOption) (*device_control_policies.UpdateDeviceControlPoliciesOK, error) {
	return nil, errors.New("not used")
}
func (f *fakeDeviceControl) DeleteDeviceControlPolicies(*device_control_policies.DeleteDeviceControlPoliciesParams, ...device_control_policies.ClientOption) (*device_control_policies.DeleteDeviceControlPoliciesOK, error) {
	return nil, errors.New("not used")
}
func (f *fakeDeviceControl) PerformDeviceControlPoliciesAction(*device_control_policies.PerformDeviceControlPoliciesActionParams, ...device_control_policies.ClientOption) (*device_control_policies.PerformDeviceControlPoliciesActionOK, error) {
	return nil, errors.New("not used")
}
func (f *fakeDeviceControl) SetDeviceControlPoliciesPrecedence(*device_control_policies.SetDeviceControlPoliciesPrecedenceParams, ...device_control_policies.ClientOption) (*device_control_policies.SetDeviceControlPoliciesPrecedenceOK, error) {
	return nil, errors.New("not used")
}

func TestDeviceControlSearchTwoStep(t *testing.T) {
	t.Parallel()
	idA, idB := "a", "b"
	meta := &models.MsaMetaInfo{}
	fake := &fakeDeviceControl{
		queryIDs:  []string{"b", "a"}, // query order [b, a]
		queryMeta: meta,
		getRecords: []*models.DeviceControlPolicyV1{
			{ID: &idA}, {ID: &idB}, // get returns [a, b] out of order
		},
	}
	b := deviceControlBackend{c: fake}

	records, gotMeta, err := b.search(context.Background(), queryArgs{limit: 100})
	if err != nil {
		t.Fatalf("search: %v", err)
	}
	if fake.getCalls != 1 {
		t.Fatalf("expected one get call, got %d", fake.getCalls)
	}
	// Records must be reordered to match the query order [b, a].
	if len(records) != 2 || records[0]["id"] != "b" || records[1]["id"] != "a" {
		t.Fatalf("expected reorder to [b,a], got %v", records)
	}
	// Meta comes from the query step (it carries search pagination).
	if gotMeta != any(meta) {
		t.Fatalf("expected query-step meta, got %+v", gotMeta)
	}
}

func TestDeviceControlSearchEmptySkipsGet(t *testing.T) {
	t.Parallel()
	fake := &fakeDeviceControl{queryIDs: []string{}}
	b := deviceControlBackend{c: fake}

	records, _, err := b.search(context.Background(), queryArgs{limit: 100})
	if err != nil {
		t.Fatalf("search: %v", err)
	}
	if records == nil || len(records) != 0 {
		t.Fatalf("expected non-nil empty slice, got %v", records)
	}
	if fake.getCalls != 0 {
		t.Fatalf("expected no get call on empty query, got %d", fake.getCalls)
	}
}

// ---- prevention create body shape ----------------------------------------------

type fakePrevention struct {
	lastCreateBody *models.PreventionCreatePoliciesReqV1
	createResp     *prevention_policies.CreatePreventionPoliciesCreated
	lastActionName string
	lastActionBody *models.MsaEntityActionRequestV2
}

func (f *fakePrevention) QueryCombinedPreventionPolicies(*prevention_policies.QueryCombinedPreventionPoliciesParams, ...prevention_policies.ClientOption) (*prevention_policies.QueryCombinedPreventionPoliciesOK, error) {
	return nil, errors.New("not used")
}
func (f *fakePrevention) QueryCombinedPreventionPolicyMembers(*prevention_policies.QueryCombinedPreventionPolicyMembersParams, ...prevention_policies.ClientOption) (*prevention_policies.QueryCombinedPreventionPolicyMembersOK, error) {
	return nil, errors.New("not used")
}
func (f *fakePrevention) CreatePreventionPolicies(p *prevention_policies.CreatePreventionPoliciesParams, _ ...prevention_policies.ClientOption) (*prevention_policies.CreatePreventionPoliciesCreated, error) {
	f.lastCreateBody = p.Body
	return f.createResp, nil
}
func (f *fakePrevention) UpdatePreventionPolicies(*prevention_policies.UpdatePreventionPoliciesParams, ...prevention_policies.ClientOption) (*prevention_policies.UpdatePreventionPoliciesOK, error) {
	return nil, errors.New("not used")
}
func (f *fakePrevention) DeletePreventionPolicies(*prevention_policies.DeletePreventionPoliciesParams, ...prevention_policies.ClientOption) (*prevention_policies.DeletePreventionPoliciesOK, error) {
	return nil, errors.New("not used")
}
func (f *fakePrevention) PerformPreventionPoliciesAction(p *prevention_policies.PerformPreventionPoliciesActionParams, _ ...prevention_policies.ClientOption) (*prevention_policies.PerformPreventionPoliciesActionOK, error) {
	f.lastActionName = p.ActionName
	f.lastActionBody = p.Body
	return &prevention_policies.PerformPreventionPoliciesActionOK{Payload: &models.PreventionRespV1{}}, nil
}
func (f *fakePrevention) SetPreventionPoliciesPrecedence(*prevention_policies.SetPreventionPoliciesPrecedenceParams, ...prevention_policies.ClientOption) (*prevention_policies.SetPreventionPoliciesPrecedenceOK, error) {
	return nil, errors.New("not used")
}

func TestPreventionCreateBodyShape(t *testing.T) {
	t.Parallel()
	id := "new"
	fake := &fakePrevention{createResp: &prevention_policies.CreatePreventionPoliciesCreated{
		Payload: &models.PreventionRespV1{Resources: []*models.PreventionPolicyV1{{ID: &id}}},
	}}
	b := preventionBackend{c: fake}

	records, _, err := b.create(context.Background(), createSpec{name: "n", platformName: "Windows", description: "d", cloneID: "c1"})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if len(records) != 1 || records[0]["id"] != "new" {
		t.Fatalf("unexpected records: %v", records)
	}
	// The create body wraps a single resource with the given fields.
	body := fake.lastCreateBody
	if body == nil || len(body.Resources) != 1 {
		t.Fatalf("expected wrapped create body, got %+v", body)
	}
	item := body.Resources[0]
	if item.Name == nil || *item.Name != "n" || item.PlatformName == nil || *item.PlatformName != "Windows" {
		t.Fatalf("unexpected create item: %+v", item)
	}
	if item.CloneID != "c1" || item.Description != "d" {
		t.Fatalf("clone_id/description not carried: %+v", item)
	}
}

func TestPreventionActionBodyShape(t *testing.T) {
	t.Parallel()
	fake := &fakePrevention{}
	b := preventionBackend{c: fake}

	_, _, err := b.action(context.Background(), "add-host-group", []string{"p1"}, "g1")
	if err != nil {
		t.Fatalf("action: %v", err)
	}
	if fake.lastActionName != "add-host-group" {
		t.Fatalf("action_name = %q, want add-host-group", fake.lastActionName)
	}
	body := fake.lastActionBody
	if body == nil || len(body.Ids) != 1 || len(body.ActionParameters) != 1 {
		t.Fatalf("unexpected action body: %+v", body)
	}
	p := body.ActionParameters[0]
	if p.Name == nil || *p.Name != "group_id" || p.Value == nil || *p.Value != "g1" {
		t.Fatalf("unexpected action parameter: %+v", p)
	}
}

// ---- content_update precedence: no platform_name -------------------------------

type fakeContentUpdate struct {
	lastPrecedenceBody *models.BaseSetContentUpdatePolicyPrecedenceReqV1
}

func (f *fakeContentUpdate) QueryCombinedContentUpdatePolicies(*content_update_policies.QueryCombinedContentUpdatePoliciesParams, ...content_update_policies.ClientOption) (*content_update_policies.QueryCombinedContentUpdatePoliciesOK, error) {
	return nil, errors.New("not used")
}
func (f *fakeContentUpdate) QueryCombinedContentUpdatePolicyMembers(*content_update_policies.QueryCombinedContentUpdatePolicyMembersParams, ...content_update_policies.ClientOption) (*content_update_policies.QueryCombinedContentUpdatePolicyMembersOK, error) {
	return nil, errors.New("not used")
}
func (f *fakeContentUpdate) CreateContentUpdatePolicies(*content_update_policies.CreateContentUpdatePoliciesParams, ...content_update_policies.ClientOption) (*content_update_policies.CreateContentUpdatePoliciesCreated, error) {
	return nil, errors.New("not used")
}
func (f *fakeContentUpdate) UpdateContentUpdatePolicies(*content_update_policies.UpdateContentUpdatePoliciesParams, ...content_update_policies.ClientOption) (*content_update_policies.UpdateContentUpdatePoliciesOK, error) {
	return nil, errors.New("not used")
}
func (f *fakeContentUpdate) DeleteContentUpdatePolicies(*content_update_policies.DeleteContentUpdatePoliciesParams, ...content_update_policies.ClientOption) (*content_update_policies.DeleteContentUpdatePoliciesOK, error) {
	return nil, errors.New("not used")
}
func (f *fakeContentUpdate) PerformContentUpdatePoliciesAction(*content_update_policies.PerformContentUpdatePoliciesActionParams, ...content_update_policies.ClientOption) (*content_update_policies.PerformContentUpdatePoliciesActionOK, error) {
	return nil, errors.New("not used")
}
func (f *fakeContentUpdate) SetContentUpdatePoliciesPrecedence(p *content_update_policies.SetContentUpdatePoliciesPrecedenceParams, _ ...content_update_policies.ClientOption) (*content_update_policies.SetContentUpdatePoliciesPrecedenceOK, error) {
	f.lastPrecedenceBody = p.Body
	return &content_update_policies.SetContentUpdatePoliciesPrecedenceOK{Payload: &models.MsaQueryResponse{}}, nil
}

func TestContentUpdatePrecedenceOmitsPlatform(t *testing.T) {
	t.Parallel()
	fake := &fakeContentUpdate{}
	b := contentUpdateBackend{c: fake}

	// Even if a platform is passed, the content_update precedence body model has
	// no platform field, so it is structurally dropped.
	_, err := b.setPrecedence(context.Background(), []string{"a", "b"}, "Windows")
	if err != nil {
		t.Fatalf("setPrecedence: %v", err)
	}
	if fake.lastPrecedenceBody == nil || len(fake.lastPrecedenceBody.Ids) != 2 {
		t.Fatalf("unexpected precedence body: %+v", fake.lastPrecedenceBody)
	}
}
