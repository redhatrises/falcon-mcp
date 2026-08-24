package cases

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/crowdstrike/gofalcon/falcon/client/case_files"
	"github.com/crowdstrike/gofalcon/falcon/client/case_management"
	"github.com/crowdstrike/gofalcon/falcon/client/cases"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/crowdstrike/falcon-mcp/internal/modules/base"
	"github.com/crowdstrike/falcon-mcp/internal/testutil"
)

// metaQueryTime is a non-zero query_time for test fakes, so a handler's
// normalized meta is a populated value rather than nil.
var metaQueryTime = 0.02

var testLogger = testutil.DiscardLogger()

// fakeCases is a configurable test double for the casesAPI interface.
type fakeCases struct {
	queryResp   *cases.QueriesCasesGetV1OK
	queryErr    error
	getResp     *cases.EntitiesCasesPostV2OK
	getErr      error
	getCalls    int
	createResp  *cases.EntitiesCasesPutV2Created
	createErr   error
	patchResp   *cases.EntitiesCasesPatchV2OK
	patchErr    error
	alertResp   *cases.EntitiesAlertEvidencePostV1OK
	alertErr    error
	eventResp   *cases.EntitiesEventEvidencePostV1OK
	eventErr    error
	tagPostResp *cases.EntitiesCaseTagsPostV1OK
	tagPostErr  error
	tagDelResp  *cases.EntitiesCaseTagsDeleteV1OK
	tagDelErr   error

	lastGetIDs      []string
	lastCreateBody  *models.OperationsCreateCaseRequest
	lastPatchBody   *models.OperationsUpdateCaseRequest
	lastAlertBody   *models.OperationsAddAlertsToCaseRequest
	lastEventBody   *models.OperationsAddEventsToCaseRequest
	lastTagPostBody *models.OperationsAddTagsToCaseRequest
	lastTagDelID    string
	lastTagDelTags  []string
}

func (f *fakeCases) QueriesCasesGetV1(*cases.QueriesCasesGetV1Params, ...cases.ClientOption) (*cases.QueriesCasesGetV1OK, error) {
	return f.queryResp, f.queryErr
}

func (f *fakeCases) EntitiesCasesPostV2(p *cases.EntitiesCasesPostV2Params, _ ...cases.ClientOption) (*cases.EntitiesCasesPostV2OK, error) {
	f.getCalls++
	if p.Body != nil {
		f.lastGetIDs = p.Body.Ids
	}
	return f.getResp, f.getErr
}

func (f *fakeCases) EntitiesCasesPutV2(p *cases.EntitiesCasesPutV2Params, _ ...cases.ClientOption) (*cases.EntitiesCasesPutV2Created, error) {
	f.lastCreateBody = p.Body
	return f.createResp, f.createErr
}

func (f *fakeCases) EntitiesCasesPatchV2(p *cases.EntitiesCasesPatchV2Params, _ ...cases.ClientOption) (*cases.EntitiesCasesPatchV2OK, error) {
	f.lastPatchBody = p.Body
	return f.patchResp, f.patchErr
}

func (f *fakeCases) EntitiesAlertEvidencePostV1(p *cases.EntitiesAlertEvidencePostV1Params, _ ...cases.ClientOption) (*cases.EntitiesAlertEvidencePostV1OK, error) {
	f.lastAlertBody = p.Body
	return f.alertResp, f.alertErr
}

func (f *fakeCases) EntitiesEventEvidencePostV1(p *cases.EntitiesEventEvidencePostV1Params, _ ...cases.ClientOption) (*cases.EntitiesEventEvidencePostV1OK, error) {
	f.lastEventBody = p.Body
	return f.eventResp, f.eventErr
}

func (f *fakeCases) EntitiesCaseTagsPostV1(p *cases.EntitiesCaseTagsPostV1Params, _ ...cases.ClientOption) (*cases.EntitiesCaseTagsPostV1OK, error) {
	f.lastTagPostBody = p.Body
	return f.tagPostResp, f.tagPostErr
}

func (f *fakeCases) EntitiesCaseTagsDeleteV1(p *cases.EntitiesCaseTagsDeleteV1Params, _ ...cases.ClientOption) (*cases.EntitiesCaseTagsDeleteV1OK, error) {
	f.lastTagDelID = p.ID
	f.lastTagDelTags = p.Tag
	return f.tagDelResp, f.tagDelErr
}

// fakeTemplates is a configurable test double for the templatesAPI interface.
type fakeTemplates struct {
	queryResp  *case_management.QueriesTemplatesGetV1OK
	queryErr   error
	getResp    *case_management.EntitiesTemplatesGetV1OK
	getErr     error
	getCalls   int
	lastGetIDs []string

	slasResp    *case_management.AggregatesSlasPostV1OK
	slasErr     error
	tmplAggResp *case_management.AggregatesTemplatesPostV1OK
	tmplAggErr  error
	tagsResp    *case_management.AggregatesAccessTagsPostV1OK
	tagsErr     error
	notifResp   *case_management.AggregatesNotificationGroupsPostV2OK
	notifErr    error

	lastAggBody []*models.APIMSAAggregateQueryRequest
}

func (f *fakeTemplates) QueriesTemplatesGetV1(*case_management.QueriesTemplatesGetV1Params, ...case_management.ClientOption) (*case_management.QueriesTemplatesGetV1OK, error) {
	return f.queryResp, f.queryErr
}

func (f *fakeTemplates) EntitiesTemplatesGetV1(p *case_management.EntitiesTemplatesGetV1Params, _ ...case_management.ClientOption) (*case_management.EntitiesTemplatesGetV1OK, error) {
	f.getCalls++
	f.lastGetIDs = p.Ids
	return f.getResp, f.getErr
}

func (f *fakeTemplates) AggregatesSlasPostV1(p *case_management.AggregatesSlasPostV1Params, _ ...case_management.ClientOption) (*case_management.AggregatesSlasPostV1OK, error) {
	f.lastAggBody = p.Body
	return f.slasResp, f.slasErr
}

func (f *fakeTemplates) AggregatesTemplatesPostV1(p *case_management.AggregatesTemplatesPostV1Params, _ ...case_management.ClientOption) (*case_management.AggregatesTemplatesPostV1OK, error) {
	f.lastAggBody = p.Body
	return f.tmplAggResp, f.tmplAggErr
}

func (f *fakeTemplates) AggregatesAccessTagsPostV1(p *case_management.AggregatesAccessTagsPostV1Params, _ ...case_management.ClientOption) (*case_management.AggregatesAccessTagsPostV1OK, error) {
	f.lastAggBody = p.Body
	return f.tagsResp, f.tagsErr
}

func (f *fakeTemplates) AggregatesNotificationGroupsPostV2(p *case_management.AggregatesNotificationGroupsPostV2Params, _ ...case_management.ClientOption) (*case_management.AggregatesNotificationGroupsPostV2OK, error) {
	f.lastAggBody = p.Body
	return f.notifResp, f.notifErr
}

// fakeCaseFiles is a configurable test double for the caseFilesAPI interface.
type fakeCaseFiles struct {
	resp     *case_files.AggregatesFileDetailsPostV1OK
	err      error
	lastBody []models.MsaAggregateQueryRequest
	lastIDs  []string
}

func (f *fakeCaseFiles) AggregatesFileDetailsPostV1(p *case_files.AggregatesFileDetailsPostV1Params, _ ...case_files.ClientOption) (*case_files.AggregatesFileDetailsPostV1OK, error) {
	f.lastBody = p.Body
	f.lastIDs = p.Ids
	return f.resp, f.err
}

// newModule builds a Module wired to the given fakes with a discarding logger.
// CaseFiles defaults to an empty fake; aggregate-file tests override it.
func newModule(c *fakeCases, t *fakeTemplates) *Module {
	return &Module{Cases: c, Templates: t, CaseFiles: &fakeCaseFiles{}, Concurrency: 4, Logger: testLogger}
}

func TestSearchCasesSuccess(t *testing.T) {
	t.Parallel()

	f := &fakeCases{
		queryResp: &cases.QueriesCasesGetV1OK{Payload: &models.CasesapiGetQueriesCasesV1Response{
			Resources: []string{"c1", "c2"},
			Meta:      &models.MsaMetaInfo{QueryTime: &metaQueryTime},
		}},
		getResp: &cases.EntitiesCasesPostV2OK{Payload: &models.OperationsGetCasesByIDsResponseVM{
			// Deliberately reversed to exercise reorder-by-id.
			Resources: []*models.SdkCaseVM{
				{ID: new("c2"), Status: new("in_progress")},
				{ID: new("c1"), Status: new("new")},
			},
		}},
	}
	m := newModule(f, &fakeTemplates{})

	_, out, err := m.searchCases(context.Background(), nil, SearchInput{Filter: "status:'new'"})
	if err != nil {
		t.Fatalf("searchCases: %v", err)
	}
	if len(out.Resources) != 2 || out.FilterUsed != "status:'new'" {
		t.Fatalf("unexpected result: %+v", out)
	}
	// Reorder must restore the query-step order c1, c2.
	if *out.Resources[0].ID != "c1" || *out.Resources[1].ID != "c2" {
		t.Fatalf("expected reordered [c1 c2], got [%s %s]", *out.Resources[0].ID, *out.Resources[1].ID)
	}
	if !reflect.DeepEqual(out.Meta, base.NormalizedMeta(f.queryResp.Payload.Meta)) {
		t.Fatalf("expected normalized meta, got %+v", out.Meta)
	}
}

func TestSearchCasesEmpty(t *testing.T) {
	t.Parallel()

	f := &fakeCases{queryResp: &cases.QueriesCasesGetV1OK{Payload: &models.CasesapiGetQueriesCasesV1Response{
		Resources: []string{},
	}}}
	m := newModule(f, &fakeTemplates{})

	_, out, err := m.searchCases(context.Background(), nil, SearchInput{Filter: "status:'new'"})
	if err != nil {
		t.Fatalf("searchCases: %v", err)
	}
	if len(out.Resources) != 0 || out.Resources == nil {
		t.Fatalf("expected non-nil empty slice, got %+v", out)
	}
	if f.getCalls != 0 {
		t.Fatalf("expected no detail fetch on empty result, got %d", f.getCalls)
	}
}

func TestSearchCasesFQLError(t *testing.T) {
	t.Parallel()

	badReq := &cases.QueriesCasesGetV1BadRequest{Payload: &models.CasesapiGetQueriesCasesV1Response{
		Errors: []*models.MsaAPIError{{Code: new(int32(400)), Message: new("invalid filter")}},
	}}
	f := &fakeCases{queryErr: badReq}
	m := newModule(f, &fakeTemplates{})

	_, out, err := m.searchCases(context.Background(), nil, SearchInput{Filter: "bogus:::"})
	if err != nil {
		t.Fatalf("expected FQL error to be formatted, not returned: %v", err)
	}
	if len(out.Errors) != 1 || out.Errors[0].Message != "invalid filter" {
		t.Fatalf("expected FQL error detail, got %+v", out.Errors)
	}
	if out.FQLGuide == "" || out.Hint == "" {
		t.Fatalf("expected fql_guide and hint to be populated")
	}
	if f.getCalls != 0 {
		t.Fatalf("expected no detail fetch on FQL error, got %d", f.getCalls)
	}
}

func TestSearchCasesAPIError(t *testing.T) {
	t.Parallel()

	f := &fakeCases{queryErr: errors.New("boom")}
	m := newModule(f, &fakeTemplates{})

	_, _, err := m.searchCases(context.Background(), nil, SearchInput{})
	if err == nil {
		t.Fatalf("expected non-FQL error to be returned")
	}
}

func TestGetCases(t *testing.T) {
	t.Parallel()

	t.Run("requires ids", func(t *testing.T) {
		t.Parallel()
		m := newModule(&fakeCases{}, &fakeTemplates{})
		_, _, err := m.getCases(context.Background(), nil, GetInput{})
		if !errors.Is(err, errInvalidInput) {
			t.Fatalf("expected errInvalidInput, got %v", err)
		}
	})

	t.Run("success", func(t *testing.T) {
		t.Parallel()
		f := &fakeCases{getResp: &cases.EntitiesCasesPostV2OK{Payload: &models.OperationsGetCasesByIDsResponseVM{
			Resources: []*models.SdkCaseVM{{ID: new("c1")}},
		}}}
		m := newModule(f, &fakeTemplates{})
		_, out, err := m.getCases(context.Background(), nil, GetInput{IDs: []string{"c1"}})
		if err != nil {
			t.Fatalf("getCases: %v", err)
		}
		if out.Total != 1 || len(f.lastGetIDs) != 1 || f.lastGetIDs[0] != "c1" {
			t.Fatalf("unexpected result: out=%+v ids=%v", out, f.lastGetIDs)
		}
	})
}

func TestListCaseTemplates(t *testing.T) {
	t.Parallel()

	t.Run("success", func(t *testing.T) {
		t.Parallel()
		ft := &fakeTemplates{
			queryResp: &case_management.QueriesTemplatesGetV1OK{Payload: &models.MsaspecQueryResponse{
				Resources: []string{"t1", "t2"},
				Meta:      &models.MsaMetaInfo{QueryTime: &metaQueryTime},
			}},
			getResp: &case_management.EntitiesTemplatesGetV1OK{Payload: &models.APITemplateV1Response{
				Resources: []*models.APITemplateV1{{ID: new("t2")}, {ID: new("t1")}},
			}},
		}
		m := newModule(&fakeCases{}, ft)
		_, out, err := m.listCaseTemplates(context.Background(), nil, TemplatesInput{})
		if err != nil {
			t.Fatalf("listCaseTemplates: %v", err)
		}
		if out.Total != 2 {
			t.Fatalf("expected 2 templates, got %+v", out)
		}
		// Reorder restores query order t1, t2.
		if *out.Resources[0].ID != "t1" || *out.Resources[1].ID != "t2" {
			t.Fatalf("expected reordered [t1 t2], got [%s %s]", *out.Resources[0].ID, *out.Resources[1].ID)
		}
		if !reflect.DeepEqual(out.Meta, base.NormalizedMeta(ft.queryResp.Payload.Meta)) {
			t.Fatalf("expected normalized meta, got %+v", out.Meta)
		}
	})

	t.Run("empty", func(t *testing.T) {
		t.Parallel()
		ft := &fakeTemplates{queryResp: &case_management.QueriesTemplatesGetV1OK{Payload: &models.MsaspecQueryResponse{
			Resources: []string{},
			Meta:      &models.MsaMetaInfo{QueryTime: &metaQueryTime},
		}}}
		m := newModule(&fakeCases{}, ft)
		_, out, err := m.listCaseTemplates(context.Background(), nil, TemplatesInput{})
		if err != nil {
			t.Fatalf("listCaseTemplates: %v", err)
		}
		if out.Total != 0 || out.Resources == nil {
			t.Fatalf("expected non-nil empty slice, got %+v", out)
		}
		if !reflect.DeepEqual(out.Meta, base.NormalizedMeta(ft.queryResp.Payload.Meta)) {
			t.Fatalf("expected normalized meta, got %+v", out.Meta)
		}
		if ft.getCalls != 0 {
			t.Fatalf("expected no detail fetch on empty result, got %d", ft.getCalls)
		}
	})
}

func TestCreateCaseValidation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		in      CreateInput
		wantErr bool
	}{
		{"missing name", CreateInput{Severity: 50}, true},
		{"severity too low", CreateInput{Name: "x", Severity: 0}, true},
		{"severity too high", CreateInput{Name: "x", Severity: 101}, true},
		{"valid minimal", CreateInput{Name: "x", Severity: 50}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := &fakeCases{createResp: &cases.EntitiesCasesPutV2Created{Payload: &models.OperationsCreateCaseResponseVM{}}}
			m := newModule(f, &fakeTemplates{})
			_, _, err := m.createCase(context.Background(), nil, tc.in)
			if tc.wantErr && !errors.Is(err, errInvalidInput) {
				t.Fatalf("expected errInvalidInput, got %v", err)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestCreateCaseBody(t *testing.T) {
	t.Parallel()

	f := &fakeCases{createResp: &cases.EntitiesCasesPutV2Created{Payload: &models.OperationsCreateCaseResponseVM{
		Resources: []*models.SdkCaseVM{{ID: new("new")}},
		Meta:      &models.MsaMetaInfo{QueryTime: &metaQueryTime},
	}}}
	m := newModule(f, &fakeTemplates{})

	_, out, err := m.createCase(context.Background(), nil, CreateInput{
		Name:       "Lateral movement",
		Severity:   70,
		Status:     "new",
		Tags:       []string{"triage"},
		TemplateID: "tmpl1",
		AlertIDs:   []string{"a1", "a2"},
		EventIDs:   []string{"e1"},
	})
	if err != nil {
		t.Fatalf("createCase: %v", err)
	}
	if out.Total != 1 {
		t.Fatalf("expected created record returned, got %+v", out)
	}
	if !reflect.DeepEqual(out.Meta, base.NormalizedMeta(f.createResp.Payload.Meta)) {
		t.Fatalf("expected normalized meta, got %+v", out.Meta)
	}
	b := f.lastCreateBody
	if b == nil || b.Name == nil || *b.Name != "Lateral movement" || b.Severity == nil || *b.Severity != 70 {
		t.Fatalf("unexpected create body core fields: %+v", b)
	}
	if b.Template == nil || b.Template.ID == nil || *b.Template.ID != "tmpl1" {
		t.Fatalf("expected template selector, got %+v", b.Template)
	}
	if b.Evidence == nil || len(b.Evidence.Alerts) != 2 || len(b.Evidence.Events) != 1 {
		t.Fatalf("expected 2 alerts + 1 event evidence, got %+v", b.Evidence)
	}
	if *b.Evidence.Alerts[0].ID != "a1" || *b.Evidence.Events[0].ID != "e1" {
		t.Fatalf("unexpected evidence ids: %+v", b.Evidence)
	}
}

func TestCreateCaseNoEvidenceWhenEmpty(t *testing.T) {
	t.Parallel()

	f := &fakeCases{createResp: &cases.EntitiesCasesPutV2Created{Payload: &models.OperationsCreateCaseResponseVM{}}}
	m := newModule(f, &fakeTemplates{})
	_, _, err := m.createCase(context.Background(), nil, CreateInput{Name: "x", Severity: 10})
	if err != nil {
		t.Fatalf("createCase: %v", err)
	}
	if f.lastCreateBody.Evidence != nil {
		t.Fatalf("expected no evidence block when no ids, got %+v", f.lastCreateBody.Evidence)
	}
}

func TestUpdateCase(t *testing.T) {
	t.Parallel()

	t.Run("requires id", func(t *testing.T) {
		t.Parallel()
		m := newModule(&fakeCases{}, &fakeTemplates{})
		_, _, err := m.updateCase(context.Background(), nil, UpdateInput{Name: "x"})
		if !errors.Is(err, errInvalidInput) {
			t.Fatalf("expected errInvalidInput, got %v", err)
		}
	})

	t.Run("requires at least one field", func(t *testing.T) {
		t.Parallel()
		m := newModule(&fakeCases{}, &fakeTemplates{})
		_, _, err := m.updateCase(context.Background(), nil, UpdateInput{ID: "c1"})
		if !errors.Is(err, errInvalidInput) {
			t.Fatalf("expected errInvalidInput, got %v", err)
		}
	})

	t.Run("severity out of range", func(t *testing.T) {
		t.Parallel()
		m := newModule(&fakeCases{}, &fakeTemplates{})
		sev := 200
		_, _, err := m.updateCase(context.Background(), nil, UpdateInput{ID: "c1", Severity: &sev})
		if !errors.Is(err, errInvalidInput) {
			t.Fatalf("expected errInvalidInput, got %v", err)
		}
	})

	t.Run("sends provided fields and expected_version", func(t *testing.T) {
		t.Parallel()
		f := &fakeCases{patchResp: &cases.EntitiesCasesPatchV2OK{Payload: &models.OperationsUpdateCaseResponseVM{
			Resources: []*models.SdkCaseVM{{ID: new("c1")}},
			Meta:      &models.MsaMetaInfo{QueryTime: &metaQueryTime},
		}}}
		m := newModule(f, &fakeTemplates{})
		sev := 90
		ver := 3
		remove := true
		_, out, err := m.updateCase(context.Background(), nil, UpdateInput{
			ID:                   "c1",
			Status:               "closed",
			Severity:             &sev,
			RemoveUserAssignment: &remove,
			ExpectedVersion:      &ver,
		})
		if err != nil {
			t.Fatalf("updateCase: %v", err)
		}
		if out.Total != 1 {
			t.Fatalf("expected updated record returned, got %+v", out)
		}
		if !reflect.DeepEqual(out.Meta, base.NormalizedMeta(f.patchResp.Payload.Meta)) {
			t.Fatalf("expected normalized meta, got %+v", out.Meta)
		}
		b := f.lastPatchBody
		if b == nil || b.ID == nil || *b.ID != "c1" {
			t.Fatalf("unexpected patch body id: %+v", b)
		}
		if b.Fields == nil || b.Fields.Status == nil || *b.Fields.Status != "closed" {
			t.Fatalf("expected status change, got %+v", b.Fields)
		}
		if b.Fields.Severity == nil || *b.Fields.Severity != 90 {
			t.Fatalf("expected severity 90, got %+v", b.Fields.Severity)
		}
		if b.Fields.RemoveUserAssignment == nil || !*b.Fields.RemoveUserAssignment {
			t.Fatalf("expected remove_user_assignment true")
		}
		if b.ExpectedVersion != 3 {
			t.Fatalf("expected expected_version 3, got %d", b.ExpectedVersion)
		}
	})
}

func TestAddCaseAlertEvidence(t *testing.T) {
	t.Parallel()

	t.Run("validation", func(t *testing.T) {
		t.Parallel()
		tests := []AlertEvidenceInput{
			{AlertIDs: []string{"a1"}}, // missing id
			{ID: "c1"},                 // missing alerts
		}
		for _, in := range tests {
			m := newModule(&fakeCases{}, &fakeTemplates{})
			_, _, err := m.addCaseAlertEvidence(context.Background(), nil, in)
			if !errors.Is(err, errInvalidInput) {
				t.Fatalf("expected errInvalidInput for %+v, got %v", in, err)
			}
		}
	})

	t.Run("success", func(t *testing.T) {
		t.Parallel()
		f := &fakeCases{alertResp: &cases.EntitiesAlertEvidencePostV1OK{Payload: &models.OperationsUpdateCaseResponseVM{
			Resources: []*models.SdkCaseVM{{ID: new("c1")}},
			Meta:      &models.MsaMetaInfo{QueryTime: &metaQueryTime},
		}}}
		m := newModule(f, &fakeTemplates{})
		_, out, err := m.addCaseAlertEvidence(context.Background(), nil, AlertEvidenceInput{ID: "c1", AlertIDs: []string{"a1", "a2"}})
		if err != nil {
			t.Fatalf("addCaseAlertEvidence: %v", err)
		}
		if out.Total != 1 {
			t.Fatalf("expected updated record, got %+v", out)
		}
		b := f.lastAlertBody
		if *b.ID != "c1" || len(b.Alerts) != 2 || *b.Alerts[0].ID != "a1" {
			t.Fatalf("unexpected alert body: %+v", b)
		}
		if !reflect.DeepEqual(out.Meta, base.NormalizedMeta(f.alertResp.Payload.Meta)) {
			t.Fatalf("expected normalized meta, got %+v", out.Meta)
		}
	})
}

func TestAddCaseEventEvidence(t *testing.T) {
	t.Parallel()

	t.Run("validation", func(t *testing.T) {
		t.Parallel()
		tests := []EventEvidenceInput{
			{EventIDs: []string{"e1"}}, // missing id
			{ID: "c1"},                 // missing events
		}
		for _, in := range tests {
			m := newModule(&fakeCases{}, &fakeTemplates{})
			_, _, err := m.addCaseEventEvidence(context.Background(), nil, in)
			if !errors.Is(err, errInvalidInput) {
				t.Fatalf("expected errInvalidInput for %+v, got %v", in, err)
			}
		}
	})

	t.Run("success", func(t *testing.T) {
		t.Parallel()
		f := &fakeCases{eventResp: &cases.EntitiesEventEvidencePostV1OK{Payload: &models.OperationsUpdateCaseResponseVM{
			Resources: []*models.SdkCaseVM{{ID: new("c1")}},
			Meta:      &models.MsaMetaInfo{QueryTime: &metaQueryTime},
		}}}
		m := newModule(f, &fakeTemplates{})
		_, out, err := m.addCaseEventEvidence(context.Background(), nil, EventEvidenceInput{ID: "c1", EventIDs: []string{"e1"}})
		if err != nil {
			t.Fatalf("addCaseEventEvidence: %v", err)
		}
		if out.Total != 1 {
			t.Fatalf("expected updated record, got %+v", out)
		}
		b := f.lastEventBody
		if *b.ID != "c1" || len(b.Events) != 1 || *b.Events[0].ID != "e1" {
			t.Fatalf("unexpected event body: %+v", b)
		}
		if !reflect.DeepEqual(out.Meta, base.NormalizedMeta(f.eventResp.Payload.Meta)) {
			t.Fatalf("expected normalized meta, got %+v", out.Meta)
		}
	})
}

func TestManageCaseTags(t *testing.T) {
	t.Parallel()

	t.Run("validation", func(t *testing.T) {
		t.Parallel()
		tests := []TagsInput{
			{Action: "add", Tags: []string{"t"}},             // missing id
			{ID: "c1", Action: "bogus", Tags: []string{"t"}}, // bad action
			{ID: "c1", Action: "add"},                        // missing tags
		}
		for _, in := range tests {
			m := newModule(&fakeCases{}, &fakeTemplates{})
			_, _, err := m.manageCaseTags(context.Background(), nil, in)
			if !errors.Is(err, errInvalidInput) {
				t.Fatalf("expected errInvalidInput for %+v, got %v", in, err)
			}
		}
	})

	t.Run("add", func(t *testing.T) {
		t.Parallel()
		f := &fakeCases{tagPostResp: &cases.EntitiesCaseTagsPostV1OK{Payload: &models.OperationsUpdateCaseResponseVM{
			Resources: []*models.SdkCaseVM{{ID: new("c1")}},
			Meta:      &models.MsaMetaInfo{QueryTime: &metaQueryTime},
		}}}
		m := newModule(f, &fakeTemplates{})
		_, out, err := m.manageCaseTags(context.Background(), nil, TagsInput{ID: "c1", Action: "add", Tags: []string{"triage", "p1"}})
		if err != nil {
			t.Fatalf("manageCaseTags add: %v", err)
		}
		if out.Total != 1 {
			t.Fatalf("expected updated record, got %+v", out)
		}
		if *f.lastTagPostBody.ID != "c1" || len(f.lastTagPostBody.Tags) != 2 {
			t.Fatalf("unexpected add-tags body: %+v", f.lastTagPostBody)
		}
		if !reflect.DeepEqual(out.Meta, base.NormalizedMeta(f.tagPostResp.Payload.Meta)) {
			t.Fatalf("expected normalized meta, got %+v", out.Meta)
		}
	})

	t.Run("remove", func(t *testing.T) {
		t.Parallel()
		f := &fakeCases{tagDelResp: &cases.EntitiesCaseTagsDeleteV1OK{Payload: &models.OperationsUpdateCaseResponseVM{
			Resources: []*models.SdkCaseVM{{ID: new("c1")}},
		}}}
		m := newModule(f, &fakeTemplates{})
		_, out, err := m.manageCaseTags(context.Background(), nil, TagsInput{ID: "c1", Action: "remove", Tags: []string{"triage"}})
		if err != nil {
			t.Fatalf("manageCaseTags remove: %v", err)
		}
		if out.Total != 1 {
			t.Fatalf("expected updated record, got %+v", out)
		}
		if f.lastTagDelID != "c1" || len(f.lastTagDelTags) != 1 || f.lastTagDelTags[0] != "triage" {
			t.Fatalf("unexpected delete-tags params: id=%q tags=%v", f.lastTagDelID, f.lastTagDelTags)
		}
	})
}

// TestRegisterResourcesServesFQLGuides verifies the cases module publishes all
// three FQL guide resources — case search, case-configuration aggregates, and
// case-file aggregates — with the Python-matching names and URIs, and that
// reading each returns its embedded guide text. The helper also asserts the
// module serves exactly these resources and no others.
func TestRegisterResourcesServesFQLGuides(t *testing.T) {
	t.Parallel()
	testutil.AssertServesFQLGuide(context.Background(), t, newModule(&fakeCases{}, &fakeTemplates{}).RegisterResources,
		testutil.FQLGuideExpectation{
			Name: "falcon_search_cases_fql_guide",
			URI:  fqlGuideURI,
			Body: fqlGuide,
		},
		testutil.FQLGuideExpectation{
			Name: "falcon_aggregate_case_config_fql_guide",
			URI:  aggregatesFQLGuideURI,
			Body: aggregatesFQLGuide,
		},
		testutil.FQLGuideExpectation{
			Name: "falcon_aggregate_case_file_details_fql_guide",
			URI:  fileAggregatesFQLGuideURI,
			Body: fileAggregatesFQLGuide,
		},
	)
}

// TestAggregateCaseConfig exercises the happy path of the four
// case-configuration aggregate tools: each forwards the built aggregate body to
// its op and returns the buckets with normalized meta.
func TestAggregateCaseConfig(t *testing.T) {
	t.Parallel()

	aggResp := func() *models.APIMSAAggregatesResponse {
		return &models.APIMSAAggregatesResponse{
			Resources: []*models.MsaAggregationResult{{Name: new("by-name")}},
			Meta:      &models.MsaMetaInfo{QueryTime: &metaQueryTime},
		}
	}

	tests := []struct {
		name      string
		configure func(*fakeTemplates)
		call      func(*Module) base.AggregateResult[*models.MsaAggregationResult]
	}{
		{
			name:      "slas",
			configure: func(f *fakeTemplates) { f.slasResp = &case_management.AggregatesSlasPostV1OK{Payload: aggResp()} },
			call: func(m *Module) base.AggregateResult[*models.MsaAggregationResult] {
				_, out, _ := m.aggregateCaseSlas(context.Background(), nil, AggregateInput{Field: "name"})
				return out
			},
		},
		{
			name: "templates",
			configure: func(f *fakeTemplates) {
				f.tmplAggResp = &case_management.AggregatesTemplatesPostV1OK{Payload: aggResp()}
			},
			call: func(m *Module) base.AggregateResult[*models.MsaAggregationResult] {
				_, out, _ := m.aggregateCaseTemplates(context.Background(), nil, AggregateInput{Field: "name"})
				return out
			},
		},
		{
			name:      "access_tags",
			configure: func(f *fakeTemplates) { f.tagsResp = &case_management.AggregatesAccessTagsPostV1OK{Payload: aggResp()} },
			call: func(m *Module) base.AggregateResult[*models.MsaAggregationResult] {
				_, out, _ := m.aggregateCaseAccessTags(context.Background(), nil, AggregateInput{Field: "key"})
				return out
			},
		},
		{
			name: "notification_groups",
			configure: func(f *fakeTemplates) {
				f.notifResp = &case_management.AggregatesNotificationGroupsPostV2OK{Payload: aggResp()}
			},
			call: func(m *Module) base.AggregateResult[*models.MsaAggregationResult] {
				_, out, _ := m.aggregateCaseNotificationGroups(context.Background(), nil, AggregateInput{Field: "name"})
				return out
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ft := &fakeTemplates{}
			tc.configure(ft)
			m := newModule(&fakeCases{}, ft)
			out := tc.call(m)

			if len(out.Resources) != 1 || out.Resources[0] == nil {
				t.Fatalf("expected 1 bucket, got %+v", out.Resources)
			}
			if len(out.Errors) != 0 {
				t.Fatalf("expected no errors, got %+v", out.Errors)
			}
			if len(ft.lastAggBody) != 1 || ft.lastAggBody[0] == nil {
				t.Fatalf("expected one aggregate body, got %+v", ft.lastAggBody)
			}
			// Aggregation type defaults to terms when the caller omits it.
			if ft.lastAggBody[0].Type == nil || *ft.lastAggBody[0].Type != base.AggregateTypeDefault {
				t.Fatalf("expected default type %q, got %+v", base.AggregateTypeDefault, ft.lastAggBody[0].Type)
			}
			if !reflect.DeepEqual(out.Meta, base.NormalizedMeta(&models.MsaMetaInfo{QueryTime: &metaQueryTime})) {
				t.Fatalf("expected normalized meta, got %+v", out.Meta)
			}
		})
	}
}

// TestAggregateCaseConfigFQLError verifies a typed 400 from a config aggregate
// op is surfaced as an FQL data result, not a Go error.
func TestAggregateCaseConfigFQLError(t *testing.T) {
	t.Parallel()

	badReq := &case_management.AggregatesSlasPostV1BadRequest{Payload: &models.MsaspecResponseFields{
		Errors: []*models.MsaAPIError{{Code: new(int32(400)), Message: new("invalid filter")}},
	}}
	ft := &fakeTemplates{slasErr: badReq}
	m := newModule(&fakeCases{}, ft)

	_, out, err := m.aggregateCaseSlas(context.Background(), nil, AggregateInput{Field: "name", Filter: "bogus:::"})
	if err != nil {
		t.Fatalf("expected FQL error to be formatted, not returned: %v", err)
	}
	if len(out.Errors) != 1 || out.Errors[0].Message != "invalid filter" {
		t.Fatalf("expected FQL error detail, got %+v", out.Errors)
	}
	if out.FQLGuide == "" {
		t.Fatalf("expected fql_guide to be populated")
	}
}

// TestAggregateCaseConfigNonFilterBadRequestSurfacesRaw verifies a typed 400
// whose message does not mention the filter (an unsupported field or
// aggregation type) is not misclassified as an FQL error: it surfaces as a Go
// error rather than a soft result carrying the FQL guide.
func TestAggregateCaseConfigNonFilterBadRequestSurfacesRaw(t *testing.T) {
	t.Parallel()

	badReq := &case_management.AggregatesSlasPostV1BadRequest{Payload: &models.MsaspecResponseFields{
		Errors: []*models.MsaAPIError{{Code: new(int32(400)), Message: new("unsupported aggregation field")}},
	}}
	ft := &fakeTemplates{slasErr: badReq}
	m := newModule(&fakeCases{}, ft)

	_, out, err := m.aggregateCaseSlas(context.Background(), nil, AggregateInput{Field: "bogus"})
	if err == nil {
		t.Fatalf("expected a Go error for a non-filter 400, got soft result %+v", out)
	}
	if len(out.Errors) != 0 || out.FQLGuide != "" {
		t.Fatalf("non-filter 400 must not be dressed as an FQL error, got %+v", out)
	}
}

// TestAggregateCaseFileDetails verifies the file aggregate tool folds case_ids
// into a case_id:[...] filter clause, sets the request Ids param, and returns
// the buckets with normalized meta.
func TestAggregateCaseFileDetails(t *testing.T) {
	t.Parallel()

	fcf := &fakeCaseFiles{resp: &case_files.AggregatesFileDetailsPostV1OK{Payload: &models.CasefilesapiAggregatesResponseV1{
		Resources: []*models.MsaAggregationResult{{Name: new("by-name")}},
		Meta:      &models.MsaMetaInfo{QueryTime: &metaQueryTime},
	}}}
	m := newModule(&fakeCases{}, &fakeTemplates{})
	m.CaseFiles = fcf

	_, out, err := m.aggregateCaseFileDetails(context.Background(), nil, FileAggregateInput{
		Field:   "name",
		CaseIDs: []string{"c1", "c2"},
		Filter:  "name:*'*.png'",
	})
	if err != nil {
		t.Fatalf("aggregateCaseFileDetails: %v", err)
	}
	if len(out.Resources) != 1 {
		t.Fatalf("expected 1 bucket, got %+v", out.Resources)
	}
	if len(fcf.lastIDs) != 2 || fcf.lastIDs[0] != "c1" {
		t.Fatalf("expected case ids forwarded to Ids param, got %v", fcf.lastIDs)
	}
	if len(fcf.lastBody) != 1 || fcf.lastBody[0].Filter == nil {
		t.Fatalf("expected one aggregate body with a filter, got %+v", fcf.lastBody)
	}
	got := *fcf.lastBody[0].Filter
	want := "case_id:['c1','c2']+(name:*'*.png')"
	if got != want {
		t.Fatalf("scoped filter mismatch:\n got %q\nwant %q", got, want)
	}
	if !reflect.DeepEqual(out.Meta, base.NormalizedMeta(&models.MsaMetaInfo{QueryTime: &metaQueryTime})) {
		t.Fatalf("expected normalized meta, got %+v", out.Meta)
	}
}

// TestAggregateCaseFileDetailsRejectsMalformedFilter proves a caller filter that
// would escape the case_id scope (a stray ) that lets a following comma reach
// top level) is rejected as a soft FQL result and never dispatched to the API.
func TestAggregateCaseFileDetailsRejectsMalformedFilter(t *testing.T) {
	t.Parallel()

	fcf := &fakeCaseFiles{}
	m := newModule(&fakeCases{}, &fakeTemplates{})
	m.CaseFiles = fcf

	_, out, err := m.aggregateCaseFileDetails(context.Background(), nil, FileAggregateInput{
		Field:   "name",
		CaseIDs: []string{"c1"},
		Filter:  "a:'1'),cid:*+(x:'1'",
	})
	if err != nil {
		t.Fatalf("expected a soft result, got Go error: %v", err)
	}
	if len(out.Errors) == 0 {
		t.Fatalf("expected FQL error details on rejection, got %+v", out)
	}
	if len(out.Resources) != 0 {
		t.Fatalf("expected no resources on rejection, got %+v", out.Resources)
	}
	if fcf.lastBody != nil {
		t.Fatalf("malformed filter must not be dispatched to the API, body=%+v", fcf.lastBody)
	}
}

// TestAggregateCaseFileDetailsEscapesCaseIDQuotes proves an embedded single
// quote in a case id is escaped so it cannot break out of the case_id clause.
func TestAggregateCaseFileDetailsEscapesCaseIDQuotes(t *testing.T) {
	t.Parallel()

	fcf := &fakeCaseFiles{resp: &case_files.AggregatesFileDetailsPostV1OK{Payload: &models.CasefilesapiAggregatesResponseV1{
		Resources: []*models.MsaAggregationResult{},
	}}}
	m := newModule(&fakeCases{}, &fakeTemplates{})
	m.CaseFiles = fcf

	_, _, err := m.aggregateCaseFileDetails(context.Background(), nil, FileAggregateInput{
		Field:   "name",
		CaseIDs: []string{`c'1`},
	})
	if err != nil {
		t.Fatalf("aggregateCaseFileDetails: %v", err)
	}
	if len(fcf.lastBody) != 1 || fcf.lastBody[0].Filter == nil {
		t.Fatalf("expected one aggregate body with a filter, got %+v", fcf.lastBody)
	}
	got := *fcf.lastBody[0].Filter
	want := `case_id:['c\'1']`
	if got != want {
		t.Fatalf("escaped scope mismatch:\n got %q\nwant %q", got, want)
	}
}

// TestRegisterToolsAnnotations verifies the mutator tools set complete
// annotations (DestructiveHint never left nil, MCP default true) and the
// read-only tools keep the default read-only annotations.
func TestRegisterToolsAnnotations(t *testing.T) {
	t.Parallel()

	var entries []base.ToolEntry
	reg := testutil.CaptureRegistrar(func(e base.ToolEntry) { entries = append(entries, e) })
	newModule(&fakeCases{}, &fakeTemplates{}).RegisterTools(reg)

	byName := map[string]*mcp.Tool{}
	for _, e := range entries {
		byName[e.Tool.Name] = e.Tool
	}

	// All thirteen tools must register.
	wantTools := []string{
		"falcon_search_cases", "falcon_get_cases", "falcon_create_case",
		"falcon_update_case", "falcon_add_case_alert_evidence",
		"falcon_add_case_event_evidence", "falcon_manage_case_tags",
		"falcon_list_case_templates",
		"falcon_aggregate_case_slas", "falcon_aggregate_case_templates",
		"falcon_aggregate_case_access_tags", "falcon_aggregate_case_notification_groups",
		"falcon_aggregate_case_file_details",
	}
	for _, name := range wantTools {
		if byName[name] == nil {
			t.Fatalf("missing tool %s", name)
		}
	}

	// Mutators: readOnly=false, destructive=false, idempotent=false.
	for _, name := range []string{
		"falcon_create_case", "falcon_update_case",
		"falcon_add_case_alert_evidence", "falcon_add_case_event_evidence",
		"falcon_manage_case_tags",
	} {
		testutil.AssertMutatingAnnotations(t, name, byName[name].Annotations, false)
	}

	// Read-only tools: readOnly=true. The five aggregate tools only count
	// records, so they carry the default read-only annotations.
	for _, name := range []string{
		"falcon_search_cases", "falcon_get_cases", "falcon_list_case_templates",
		"falcon_aggregate_case_slas", "falcon_aggregate_case_templates",
		"falcon_aggregate_case_access_tags", "falcon_aggregate_case_notification_groups",
		"falcon_aggregate_case_file_details",
	} {
		a := byName[name].Annotations
		if a == nil || !a.ReadOnlyHint {
			t.Fatalf("%s: expected ReadOnlyHint true, got %+v", name, a)
		}
	}
}
