package cases

import (
	"context"
	"errors"
	"log/slog"
	"testing"

	"github.com/crowdstrike/gofalcon/falcon/client/case_management"
	"github.com/crowdstrike/gofalcon/falcon/client/cases"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/crowdstrike/falcon-mcp/internal/modules/base"
)

// testLogger discards output; modules require a non-nil logger.
var testLogger = slog.New(slog.DiscardHandler)

func str(s string) *string { return &s }
func i32(v int32) *int32   { return &v }

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
}

func (f *fakeTemplates) QueriesTemplatesGetV1(*case_management.QueriesTemplatesGetV1Params, ...case_management.ClientOption) (*case_management.QueriesTemplatesGetV1OK, error) {
	return f.queryResp, f.queryErr
}

func (f *fakeTemplates) EntitiesTemplatesGetV1(p *case_management.EntitiesTemplatesGetV1Params, _ ...case_management.ClientOption) (*case_management.EntitiesTemplatesGetV1OK, error) {
	f.getCalls++
	f.lastGetIDs = p.Ids
	return f.getResp, f.getErr
}

// newModule builds a Module wired to the given fakes with a discarding logger.
func newModule(c *fakeCases, t *fakeTemplates) *Module {
	return &Module{Cases: c, Templates: t, Concurrency: 4, Logger: testLogger}
}

func TestSearchCasesSuccess(t *testing.T) {
	t.Parallel()

	f := &fakeCases{
		queryResp: &cases.QueriesCasesGetV1OK{Payload: &models.CasesapiGetQueriesCasesV1Response{
			Resources: []string{"c1", "c2"},
			Meta:      &models.MsaMetaInfo{},
		}},
		getResp: &cases.EntitiesCasesPostV2OK{Payload: &models.OperationsGetCasesByIDsResponseVM{
			// Deliberately reversed to exercise reorder-by-id.
			Resources: []*models.SdkCaseVM{
				{ID: str("c2"), Status: str("in_progress")},
				{ID: str("c1"), Status: str("new")},
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
	if out.Meta != any(f.queryResp.Payload.Meta) {
		t.Fatalf("expected verbatim meta passthrough, got %+v", out.Meta)
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
		Errors: []*models.MsaAPIError{{Code: i32(400), Message: str("invalid filter")}},
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
			Resources: []*models.SdkCaseVM{{ID: str("c1")}},
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
				Meta:      &models.MsaMetaInfo{},
			}},
			getResp: &case_management.EntitiesTemplatesGetV1OK{Payload: &models.APITemplateV1Response{
				Resources: []*models.APITemplateV1{{ID: str("t2")}, {ID: str("t1")}},
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
		if out.Meta != any(ft.queryResp.Payload.Meta) {
			t.Fatalf("expected verbatim meta passthrough, got %+v", out.Meta)
		}
	})

	t.Run("empty", func(t *testing.T) {
		t.Parallel()
		ft := &fakeTemplates{queryResp: &case_management.QueriesTemplatesGetV1OK{Payload: &models.MsaspecQueryResponse{
			Resources: []string{},
			Meta:      &models.MsaMetaInfo{},
		}}}
		m := newModule(&fakeCases{}, ft)
		_, out, err := m.listCaseTemplates(context.Background(), nil, TemplatesInput{})
		if err != nil {
			t.Fatalf("listCaseTemplates: %v", err)
		}
		if out.Total != 0 || out.Resources == nil {
			t.Fatalf("expected non-nil empty slice, got %+v", out)
		}
		if out.Meta != any(ft.queryResp.Payload.Meta) {
			t.Fatalf("expected verbatim meta passthrough, got %+v", out.Meta)
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
		Resources: []*models.SdkCaseVM{{ID: str("new")}},
		Meta:      &models.MsaMetaInfo{},
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
	if out.Meta != any(f.createResp.Payload.Meta) {
		t.Fatalf("expected verbatim meta passthrough, got %+v", out.Meta)
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
			Resources: []*models.SdkCaseVM{{ID: str("c1")}},
			Meta:      &models.MsaMetaInfo{},
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
		if out.Meta != any(f.patchResp.Payload.Meta) {
			t.Fatalf("expected verbatim meta passthrough, got %+v", out.Meta)
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
			Resources: []*models.SdkCaseVM{{ID: str("c1")}},
			Meta:      &models.MsaMetaInfo{},
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
		if out.Meta != any(f.alertResp.Payload.Meta) {
			t.Fatalf("expected verbatim meta passthrough, got %+v", out.Meta)
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
			Resources: []*models.SdkCaseVM{{ID: str("c1")}},
			Meta:      &models.MsaMetaInfo{},
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
		if out.Meta != any(f.eventResp.Payload.Meta) {
			t.Fatalf("expected verbatim meta passthrough, got %+v", out.Meta)
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
			Resources: []*models.SdkCaseVM{{ID: str("c1")}},
			Meta:      &models.MsaMetaInfo{},
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
		if out.Meta != any(f.tagPostResp.Payload.Meta) {
			t.Fatalf("expected verbatim meta passthrough, got %+v", out.Meta)
		}
	})

	t.Run("remove", func(t *testing.T) {
		t.Parallel()
		f := &fakeCases{tagDelResp: &cases.EntitiesCaseTagsDeleteV1OK{Payload: &models.OperationsUpdateCaseResponseVM{
			Resources: []*models.SdkCaseVM{{ID: str("c1")}},
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

// TestRegisterResourcesServesFQLGuide verifies the cases module publishes its
// FQL guide as the falcon://cases/search/fql-guide resource, with the
// Python-matching name, and that reading it returns the embedded guide text.
func TestRegisterResourcesServesFQLGuide(t *testing.T) {
	t.Parallel()

	srv := mcp.NewServer(&mcp.Implementation{Name: "test", Version: "test"}, nil)
	newModule(&fakeCases{}, &fakeTemplates{}).RegisterResources(srv)

	ctx := context.Background()
	clientT, serverT := mcp.NewInMemoryTransports()
	ss, err := srv.Connect(ctx, serverT, nil)
	if err != nil {
		t.Fatalf("server connect: %v", err)
	}
	t.Cleanup(func() { _ = ss.Wait() })

	cs, err := mcp.NewClient(&mcp.Implementation{Name: "c", Version: "test"}, nil).Connect(ctx, clientT, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	t.Cleanup(func() { _ = cs.Close() })

	list, err := cs.ListResources(ctx, nil)
	if err != nil {
		t.Fatalf("ListResources: %v", err)
	}
	if len(list.Resources) != 1 {
		t.Fatalf("expected 1 resource, got %d", len(list.Resources))
	}
	if got := list.Resources[0]; got.Name != "falcon_search_cases_fql_guide" || got.URI != fqlGuideURI {
		t.Fatalf("resource = {name:%q uri:%q}, want falcon_search_cases_fql_guide / %s", got.Name, got.URI, fqlGuideURI)
	}

	read, err := cs.ReadResource(ctx, &mcp.ReadResourceParams{URI: fqlGuideURI})
	if err != nil {
		t.Fatalf("ReadResource: %v", err)
	}
	if len(read.Contents) != 1 || read.Contents[0].Text != fqlGuide {
		t.Fatalf("read content does not match embedded guide")
	}
}

// TestRegisterToolsAnnotations verifies the mutator tools set complete
// annotations (DestructiveHint never left nil, MCP default true) and the
// read-only tools keep the default read-only annotations.
func TestRegisterToolsAnnotations(t *testing.T) {
	t.Parallel()

	var entries []base.ToolEntry
	reg := captureRegistrar(func(e base.ToolEntry) { entries = append(entries, e) })
	newModule(&fakeCases{}, &fakeTemplates{}).RegisterTools(reg)

	byName := map[string]*mcp.Tool{}
	for _, e := range entries {
		byName[e.Tool.Name] = e.Tool
	}

	// All eight tools must register.
	wantTools := []string{
		"falcon_search_cases", "falcon_get_cases", "falcon_create_case",
		"falcon_update_case", "falcon_add_case_alert_evidence",
		"falcon_add_case_event_evidence", "falcon_manage_case_tags",
		"falcon_list_case_templates",
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
		assertMutatingAnnotations(t, name, byName[name].Annotations)
	}

	// Read-only tools: readOnly=true.
	for _, name := range []string{"falcon_search_cases", "falcon_get_cases", "falcon_list_case_templates"} {
		a := byName[name].Annotations
		if a == nil || !a.ReadOnlyHint {
			t.Fatalf("%s: expected ReadOnlyHint true, got %+v", name, a)
		}
	}
}

// captureRegistrar adapts a func to base.Registrar for registration tests.
type captureRegistrar func(base.ToolEntry)

func (f captureRegistrar) Add(e base.ToolEntry) { f(e) }

func assertMutatingAnnotations(t *testing.T, name string, a *mcp.ToolAnnotations) {
	t.Helper()
	if a == nil {
		t.Fatalf("%s: annotations nil", name)
	}
	if a.ReadOnlyHint {
		t.Errorf("%s: ReadOnlyHint = true, want false", name)
	}
	if a.IdempotentHint {
		t.Errorf("%s: IdempotentHint = true, want false", name)
	}
	if a.DestructiveHint == nil || *a.DestructiveHint {
		t.Errorf("%s: DestructiveHint = %v, want non-nil false (MCP defaults omitted to true)", name, a.DestructiveHint)
	}
	if a.OpenWorldHint == nil || !*a.OpenWorldHint {
		t.Errorf("%s: OpenWorldHint = %v, want non-nil true", name, a.OpenWorldHint)
	}
}
