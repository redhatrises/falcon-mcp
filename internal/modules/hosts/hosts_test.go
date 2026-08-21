package hosts

import (
	"bytes"
	"context"
	"encoding/json"
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
}

func (f *fakeHosts) QueryDevicesByFilter(*hosts.QueryDevicesByFilterParams, ...hosts.ClientOption) (*hosts.QueryDevicesByFilterOK, error) {
	return f.queryResp, nil
}

func (f *fakeHosts) PostDeviceDetailsV2(p *hosts.PostDeviceDetailsV2Params, _ ...hosts.ClientOption) (*hosts.PostDeviceDetailsV2OK, error) {
	f.getCalls++
	f.lastIDs = append(f.lastIDs, p.Body.Ids...)
	return f.getResp, nil
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
