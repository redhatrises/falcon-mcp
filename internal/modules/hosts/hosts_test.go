package hosts

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"reflect"
	"strings"
	"testing"

	"github.com/crowdstrike/gofalcon/falcon/client/hosts"
	"github.com/crowdstrike/gofalcon/falcon/models"

	"github.com/crowdstrike/falcon-mcp/internal/modules/base"
	"github.com/crowdstrike/falcon-mcp/internal/testutil"
)

var testLogger = testutil.DiscardLogger()

type fakeHosts struct {
	queryResp *hosts.QueryDevicesByFilterOK
	getResp   *hosts.PostDeviceDetailsV2OK
	getCalls  int
	lastIDs   []string

	tagsResp     *hosts.UpdateDeviceTagsOK
	tagsAccepted *hosts.UpdateDeviceTagsAccepted
	tagsErr      error
	lastTagsBody *models.DeviceapiUpdateDeviceTagsRequestV1
	tagsCalls    int
}

func (f *fakeHosts) QueryDevicesByFilter(*hosts.QueryDevicesByFilterParams, ...hosts.ClientOption) (*hosts.QueryDevicesByFilterOK, error) {
	return f.queryResp, nil
}

func (f *fakeHosts) PostDeviceDetailsV2(p *hosts.PostDeviceDetailsV2Params, _ ...hosts.ClientOption) (*hosts.PostDeviceDetailsV2OK, error) {
	f.getCalls++
	f.lastIDs = append(f.lastIDs, p.Body.Ids...)
	return f.getResp, nil
}

func (f *fakeHosts) UpdateDeviceTags(p *hosts.UpdateDeviceTagsParams, _ ...hosts.ClientOption) (*hosts.UpdateDeviceTagsOK, *hosts.UpdateDeviceTagsAccepted, error) {
	f.tagsCalls++
	f.lastTagsBody = p.Body
	return f.tagsResp, f.tagsAccepted, f.tagsErr
}

func TestSearchHostsEmptyReturnsList(t *testing.T) {
	t.Parallel()

	f := &fakeHosts{queryResp: &hosts.QueryDevicesByFilterOK{Payload: &models.MsaQueryResponse{Resources: []string{}}}}
	m := &Module{API: f, Concurrency: 4, Logger: testLogger}
	_, out, err := m.searchHosts(context.Background(), nil, SearchInput{})
	if err != nil {
		t.Fatalf("searchHosts: %v", err)
	}
	if out.Resources == nil || len(out.Resources) != 0 {
		t.Fatalf("expected empty non-nil resources, got %+v", out)
	}
	if f.getCalls != 0 {
		t.Fatalf("expected no detail fetch, got %d", f.getCalls)
	}
}

func TestGetHostDetailsEmptyShortCircuits(t *testing.T) {
	t.Parallel()

	f := &fakeHosts{}
	m := &Module{API: f, Concurrency: 4, Logger: testLogger}
	_, _, err := m.getHostDetails(context.Background(), nil, DetailsInput{IDs: nil})
	if err != nil {
		t.Fatalf("getHostDetails: %v", err)
	}
	if f.getCalls != 0 {
		t.Fatalf("expected short-circuit, got %d calls", f.getCalls)
	}
}

// TestSearchHostsEmitsDebugLog verifies the injected logger receives a
// structured DEBUG entry naming the tool and its filter — proving the logger is
// wired through Params and the debug path fires.
func TestSearchHostsEmitsDebugLog(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	f := &fakeHosts{queryResp: &hosts.QueryDevicesByFilterOK{Payload: &models.MsaQueryResponse{Resources: []string{}}}}
	m := &Module{API: f, Concurrency: 4, Logger: logger}
	if _, _, err := m.searchHosts(context.Background(), nil, SearchInput{Filter: "hostname:'PC*'"}); err != nil {
		t.Fatalf("searchHosts: %v", err)
	}

	var found bool
	for line := range strings.SplitSeq(strings.TrimSpace(buf.String()), "\n") {
		var rec map[string]any
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("log line not JSON: %q: %v", line, err)
		}
		if rec["level"] == "DEBUG" && rec["msg"] == "search_hosts" {
			if rec["filter"] != "hostname:'PC*'" {
				t.Errorf("filter field = %v, want hostname:'PC*'", rec["filter"])
			}
			found = true
		}
	}
	if !found {
		t.Errorf("no DEBUG search_hosts log emitted; got:\n%s", buf.String())
	}
}

func TestSearchHostsFetchesDetails(t *testing.T) {
	t.Parallel()

	// PostDeviceDetailsV2 returns devices scrambled relative to the query order;
	// the tool must reorder them back to the query step's sort (device_id). The
	// query meta reports a full match count larger than this page, which must
	// surface as Total rather than the returned page size.
	d1, d2 := "d1", "d2"
	matchTotal := int64(42)
	f := &fakeHosts{
		queryResp: &hosts.QueryDevicesByFilterOK{Payload: &models.MsaQueryResponse{
			Resources: []string{"d1", "d2"},
			Meta:      &models.MsaMetaInfo{Pagination: &models.MsaPaging{Total: &matchTotal}},
		}},
		getResp: &hosts.PostDeviceDetailsV2OK{Payload: &models.DeviceapiDeviceDetailsResponseSwagger{Resources: []*models.DeviceapiDeviceSwagger{
			{DeviceID: &d2},
			{DeviceID: &d1},
		}}},
	}
	m := &Module{API: f, Concurrency: 4, Logger: testLogger}
	_, out, err := m.searchHosts(context.Background(), nil, SearchInput{})
	if err != nil {
		t.Fatalf("searchHosts: %v", err)
	}
	if len(out.Resources) != 2 {
		t.Fatalf("expected 2 fetched resources, got %+v", out)
	}
	if !reflect.DeepEqual(out.Meta, base.NormalizedMeta(f.queryResp.Payload.Meta)) {
		t.Fatalf("Meta = %+v, want verbatim passthrough of the query meta", out.Meta)
	}
	if got := *out.Resources[0].DeviceID; got != "d1" {
		t.Fatalf("expected query order restored (d1 first), got %q", got)
	}
	if got := *out.Resources[1].DeviceID; got != "d2" {
		t.Fatalf("expected query order restored (d2 second), got %q", got)
	}
	if f.getCalls != 1 {
		t.Fatalf("expected 1 detail-fetch call, got %d", f.getCalls)
	}
}

func TestManageGroupingTagsValidation(t *testing.T) {
	t.Parallel()

	manyIDs := make([]string, maxTagDeviceIDs+1)
	for i := range manyIDs {
		manyIDs[i] = "d"
	}
	manyTags := make([]string, maxTagsPerRequest+1)
	for i := range manyTags {
		manyTags[i] = "t"
	}

	tests := []struct {
		name string
		in   ManageGroupingTagsInput
	}{
		{"bad action", ManageGroupingTagsInput{IDs: []string{"d1"}, Action: "delete", Tags: []string{"t"}}},
		{"no ids", ManageGroupingTagsInput{Action: "add", Tags: []string{"t"}}},
		{"too many ids", ManageGroupingTagsInput{IDs: manyIDs, Action: "add", Tags: []string{"t"}}},
		{"no tags", ManageGroupingTagsInput{IDs: []string{"d1"}, Action: "add"}},
		{"too many tags", ManageGroupingTagsInput{IDs: []string{"d1"}, Action: "add", Tags: manyTags}},
		{"empty tag", ManageGroupingTagsInput{IDs: []string{"d1"}, Action: "add", Tags: []string{"  "}}},
		{"sensor prefix rejected", ManageGroupingTagsInput{IDs: []string{"d1"}, Action: "add", Tags: []string{"SensorGroupingTags/prod"}}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := &fakeHosts{}
			m := &Module{API: f, Concurrency: 4, Logger: testLogger}
			_, _, err := m.manageGroupingTags(context.Background(), nil, tc.in)
			if !errors.Is(err, errInvalidInput) {
				t.Fatalf("expected errInvalidInput, got %v", err)
			}
			if f.tagsCalls != 0 {
				t.Fatalf("expected no API call on validation failure, got %d", f.tagsCalls)
			}
		})
	}
}

func TestManageGroupingTagsNormalizesAndReturnsRecords(t *testing.T) {
	t.Parallel()

	dev := "d1"
	updated := true
	f := &fakeHosts{tagsResp: &hosts.UpdateDeviceTagsOK{Payload: &models.DeviceapiUpdateDeviceTagsSwaggerV1{
		Resources: []*models.DeviceapiUpdateDeviceDetailsResponseV1{
			{DeviceID: &dev, Updated: &updated, Code: 200},
		},
	}}}
	m := &Module{API: f, Concurrency: 4, Logger: testLogger}

	// A bare tag gets the grouping prefix; an already-prefixed tag keeps its
	// name casing; a miscased prefix is rewritten to the canonical prefix so the
	// API (which matches the prefix exactly) recognizes it as a grouping tag.
	_, out, err := m.manageGroupingTags(context.Background(), nil, ManageGroupingTagsInput{
		IDs:    []string{"d1"},
		Action: "add",
		Tags:   []string{"Production", "FalconGroupingTags/Web", "falcongroupingtags/Quarantined"},
	})
	if err != nil {
		t.Fatalf("manageGroupingTags: %v", err)
	}
	if f.lastTagsBody == nil || f.lastTagsBody.Action == nil || *f.lastTagsBody.Action != "add" {
		t.Fatalf("action not forwarded: %+v", f.lastTagsBody)
	}
	want := []string{"FalconGroupingTags/Production", "FalconGroupingTags/Web", "FalconGroupingTags/Quarantined"}
	if !reflect.DeepEqual(f.lastTagsBody.Tags, want) {
		t.Fatalf("tags = %v, want %v", f.lastTagsBody.Tags, want)
	}
	if len(out.Resources) != 1 || out.Resources[0].DeviceID == nil || *out.Resources[0].DeviceID != "d1" {
		t.Fatalf("expected one per-device record for d1, got %+v", out.Resources)
	}
}

func TestManageGroupingTagsSurfacesAcceptedPayload(t *testing.T) {
	t.Parallel()

	// A 202 Accepted (queued for offline hosts) carries the same payload shape;
	// the handler must read it just like the 200 path.
	dev := "d1"
	updated := false
	f := &fakeHosts{tagsAccepted: &hosts.UpdateDeviceTagsAccepted{Payload: &models.DeviceapiUpdateDeviceTagsSwaggerV1{
		Resources: []*models.DeviceapiUpdateDeviceDetailsResponseV1{{DeviceID: &dev, Updated: &updated, Code: 202}},
	}}}
	m := &Module{API: f, Concurrency: 4, Logger: testLogger}

	_, out, err := m.manageGroupingTags(context.Background(), nil, ManageGroupingTagsInput{IDs: []string{"d1"}, Action: "remove", Tags: []string{"old"}})
	if err != nil {
		t.Fatalf("manageGroupingTags: %v", err)
	}
	if len(out.Resources) != 1 || out.Resources[0].Code != 202 {
		t.Fatalf("expected the accepted payload surfaced, got %+v", out.Resources)
	}
}

// TestRegisterToolsAnnotations guards the tool annotations: the two read tools
// stay read-only and the grouping-tags mutator carries non-destructive mutating
// annotations. Without this, dropping Annotations on the mutator would silently
// advertise it as read-only, and neither conformance nor lint would catch it.
func TestRegisterToolsAnnotations(t *testing.T) {
	t.Parallel()
	var entries []base.ToolEntry
	reg := testutil.CaptureRegistrar(func(e base.ToolEntry) { entries = append(entries, e) })
	m := &Module{Logger: testLogger}
	m.RegisterTools(reg)

	byName := map[string]base.ToolEntry{}
	for _, e := range entries {
		byName[e.Tool.Name] = e
	}

	for _, name := range []string{"falcon_search_hosts", "falcon_get_host_details"} {
		e, ok := byName[name]
		if !ok {
			t.Fatalf("missing tool %s", name)
		}
		testutil.AssertReadOnlyAnnotations(t, name, e.Tool.Annotations)
	}

	tags, ok := byName["falcon_manage_host_grouping_tags"]
	if !ok {
		t.Fatal("missing falcon_manage_host_grouping_tags")
	}
	testutil.AssertMutatingAnnotations(t, "falcon_manage_host_grouping_tags", tags.Tool.Annotations, true)
}
