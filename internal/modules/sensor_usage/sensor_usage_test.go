package sensorusage

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"reflect"
	"strings"
	"testing"

	"github.com/crowdstrike/gofalcon/falcon/client/sensor_usage_api"
	"github.com/crowdstrike/gofalcon/falcon/models"

	"github.com/crowdstrike/falcon-mcp/internal/modules/base"
	"github.com/crowdstrike/falcon-mcp/internal/testutil"
)

var testLogger = testutil.DiscardLogger()

// fakeSensorUsage is a configurable test double for the sensorUsageAPI interface.
type fakeSensorUsage struct {
	resp *sensor_usage_api.GetSensorUsageWeeklyOK
	err  error

	calls      int
	lastFilter string
	filterSet  bool
}

func (f *fakeSensorUsage) GetSensorUsageWeekly(p *sensor_usage_api.GetSensorUsageWeeklyParams, _ ...sensor_usage_api.ClientOption) (*sensor_usage_api.GetSensorUsageWeeklyOK, error) {
	f.calls++
	if p.Filter != nil {
		f.filterSet = true
		f.lastFilter = *p.Filter
	}
	return f.resp, f.err
}

func okResp(records ...*models.EntitiesRollingAverage) *sensor_usage_api.GetSensorUsageWeeklyOK {
	return &sensor_usage_api.GetSensorUsageWeeklyOK{
		Payload: &models.APIWeeklyAverageResponse{Resources: records},
	}
}

func TestSearchSensorUsageSuccess(t *testing.T) {
	t.Parallel()

	workstations := 42.0
	f := &fakeSensorUsage{resp: okResp(&models.EntitiesRollingAverage{Workstations: &workstations})}
	f.resp.Payload.Meta = &models.MsaMetaInfo{PoweredBy: "sensor-usage-api"}
	m := &Module{API: f, Logger: testLogger}

	_, out, err := m.searchSensorUsage(context.Background(), nil, SearchInput{Filter: "period:'30'"})
	if err != nil {
		t.Fatalf("searchSensorUsage: %v", err)
	}
	if len(out.Resources) != 1 || out.FilterUsed != "period:'30'" {
		t.Fatalf("unexpected result: %+v", out)
	}
	if !reflect.DeepEqual(out.Meta, base.NormalizedMeta(f.resp.Payload.Meta)) {
		t.Fatalf("Meta = %+v, want verbatim passthrough of the response meta", out.Meta)
	}
}

// TestSearchSensorUsageForwardsFilter verifies the handler forwards the filter
// to the API params, and omits it when empty.
func TestSearchSensorUsageForwardsFilter(t *testing.T) {
	t.Parallel()

	f := &fakeSensorUsage{resp: okResp()}
	m := &Module{API: f, Logger: testLogger}

	if _, _, err := m.searchSensorUsage(context.Background(), nil, SearchInput{Filter: "event_date:'2024-06-11'+period:'30'"}); err != nil {
		t.Fatalf("searchSensorUsage: %v", err)
	}
	if !f.filterSet || f.lastFilter != "event_date:'2024-06-11'+period:'30'" {
		t.Errorf("filter = %q (set=%v)", f.lastFilter, f.filterSet)
	}
}

// TestSearchSensorUsageOmitsEmptyFilter verifies the handler leaves the filter
// param nil when no filter is supplied, so the API applies its own defaults.
func TestSearchSensorUsageOmitsEmptyFilter(t *testing.T) {
	t.Parallel()

	f := &fakeSensorUsage{resp: okResp()}
	m := &Module{API: f, Logger: testLogger}

	if _, _, err := m.searchSensorUsage(context.Background(), nil, SearchInput{}); err != nil {
		t.Fatalf("searchSensorUsage: %v", err)
	}
	if f.filterSet {
		t.Errorf("expected nil filter param on empty input, got %q", f.lastFilter)
	}
}

func TestSearchSensorUsageEmpty(t *testing.T) {
	t.Parallel()

	f := &fakeSensorUsage{resp: okResp()}
	m := &Module{API: f, Logger: testLogger}

	_, out, err := m.searchSensorUsage(context.Background(), nil, SearchInput{})
	if err != nil {
		t.Fatalf("searchSensorUsage: %v", err)
	}
	if out.Resources == nil || len(out.Resources) != 0 {
		t.Fatalf("expected empty non-nil resources, got %+v", out)
	}
	if out.Meta != nil {
		t.Fatalf("Meta = %+v, want nil when the response carries no meta", out.Meta)
	}
}

func TestSearchSensorUsageFQLError(t *testing.T) {
	t.Parallel()

	badReq := &sensor_usage_api.GetSensorUsageWeeklyBadRequest{
		Payload: &models.APIHourlyAverageResponse{
			Errors: []*models.MsaAPIError{{Code: new(int32(400)), Message: new("invalid filter")}},
		},
	}
	f := &fakeSensorUsage{err: badReq}
	m := &Module{API: f, Logger: testLogger}

	_, out, err := m.searchSensorUsage(context.Background(), nil, SearchInput{Filter: "bogus::"})
	if err != nil {
		t.Fatalf("expected soft FQL error result, got Go error: %v", err)
	}
	if len(out.Errors) != 1 || out.Errors[0].Message != "invalid filter" {
		t.Fatalf("expected FQL error detail, got %+v", out.Errors)
	}
	if out.FQLGuide == "" {
		t.Fatalf("expected FQL guide in error result")
	}
	if out.FilterUsed != "bogus::" {
		t.Fatalf("expected filter echoed, got %q", out.FilterUsed)
	}
}

// TestSearchSensorUsageEmitsDebugLog verifies the injected logger receives a
// structured DEBUG entry naming the tool and its filter.
func TestSearchSensorUsageEmitsDebugLog(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	f := &fakeSensorUsage{resp: okResp()}
	m := &Module{API: f, Logger: logger}
	if _, _, err := m.searchSensorUsage(context.Background(), nil, SearchInput{Filter: "period:'30'"}); err != nil {
		t.Fatalf("searchSensorUsage: %v", err)
	}

	var found bool
	for line := range strings.SplitSeq(strings.TrimSpace(buf.String()), "\n") {
		var rec map[string]any
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("log line not JSON: %q: %v", line, err)
		}
		if rec["level"] == "DEBUG" && rec["msg"] == "search_sensor_usage" {
			if rec["filter"] != "period:'30'" {
				t.Errorf("filter field = %v, want period:'30'", rec["filter"])
			}
			found = true
		}
	}
	if !found {
		t.Errorf("no DEBUG search_sensor_usage log emitted; got:\n%s", buf.String())
	}
}
