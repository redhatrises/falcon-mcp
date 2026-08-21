package metrics

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestNewRegistersRuntimeCollectors(t *testing.T) {
	t.Parallel()
	m := New()

	// The Go and process collectors replace what the old expvar memstats dump
	// provided; go_goroutines is a stable marker that the Go collector registered.
	got, err := testutil.GatherAndCount(m.reg, "go_goroutines")
	if err != nil {
		t.Fatalf("GatherAndCount: %v", err)
	}
	if got != 1 {
		t.Errorf("go_goroutines families = %d, want 1", got)
	}
}

func TestHandlerServesPrometheusText(t *testing.T) {
	t.Parallel()
	m := New()
	// Touch a vector so at least one application metric is exposed.
	m.toolCalls.WithLabelValues("falcon_list_enabled_modules", "ok").Inc()

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	m.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{"# TYPE falcon_mcp_tool_calls_total counter", "go_goroutines"} {
		if !strings.Contains(body, want) {
			t.Errorf("body missing %q\nbody:\n%s", want, body)
		}
	}
}

func TestToolMiddleware(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		method     string
		result     *mcp.CallToolResult
		handlerErr error
		wantTool   string
		wantStatus string
		wantCalls  float64 // expected tool_calls_total for {wantTool,wantStatus}
	}{
		{
			name:       "ok result",
			method:     methodCallTool,
			result:     &mcp.CallToolResult{},
			wantTool:   "falcon_search_hosts",
			wantStatus: "ok",
			wantCalls:  1,
		},
		{
			name:       "result is error",
			method:     methodCallTool,
			result:     &mcp.CallToolResult{IsError: true},
			wantTool:   "falcon_search_hosts",
			wantStatus: "error",
			wantCalls:  1,
		},
		{
			name:       "handler returns error",
			method:     methodCallTool,
			handlerErr: errors.New("boom"),
			wantTool:   "falcon_search_hosts",
			wantStatus: "error",
			wantCalls:  1,
		},
		{
			name:       "non tool-call method is not recorded",
			method:     "resources/read",
			result:     &mcp.CallToolResult{},
			wantTool:   "falcon_search_hosts",
			wantStatus: "ok",
			wantCalls:  0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			m := New()
			var called bool
			next := func(_ context.Context, _ string, _ mcp.Request) (mcp.Result, error) {
				called = true
				if tt.handlerErr != nil {
					return nil, tt.handlerErr
				}
				return tt.result, nil
			}
			req := &mcp.CallToolRequest{Params: &mcp.CallToolParamsRaw{Name: tt.wantTool}}

			known := map[string]struct{}{tt.wantTool: {}}
			res, err := m.ToolMiddleware(known)(next)(context.Background(), tt.method, req)
			if !called {
				t.Fatal("inner handler was not called")
			}
			if !errors.Is(err, tt.handlerErr) {
				t.Fatalf("err = %v, want %v", err, tt.handlerErr)
			}
			if tt.handlerErr == nil && res != tt.result {
				t.Errorf("result not passed through unchanged")
			}

			got := testutil.ToFloat64(m.toolCalls.WithLabelValues(tt.wantTool, tt.wantStatus))
			if got != tt.wantCalls {
				t.Errorf("tool_calls_total{%s,%s} = %v, want %v", tt.wantTool, tt.wantStatus, got, tt.wantCalls)
			}
		})
	}
}

func TestToolMiddlewareBoundsLabelCardinality(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		known    map[string]struct{}
		callName string
		wantTool string // label the call must be recorded under
	}{
		{
			name:     "registered name records under its own label",
			known:    map[string]struct{}{"falcon_search_hosts": {}},
			callName: "falcon_search_hosts",
			wantTool: "falcon_search_hosts",
		},
		{
			name:     "unregistered name collapses to unknown",
			known:    map[string]struct{}{"falcon_search_hosts": {}},
			callName: "../../etc/passwd",
			wantTool: unknownTool,
		},
		{
			name:     "nil known set records every name",
			known:    nil,
			callName: "falcon_anything",
			wantTool: "falcon_anything",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			m := New()
			next := func(_ context.Context, _ string, _ mcp.Request) (mcp.Result, error) {
				return &mcp.CallToolResult{}, nil
			}
			req := &mcp.CallToolRequest{Params: &mcp.CallToolParamsRaw{Name: tt.callName}}

			if _, err := m.ToolMiddleware(tt.known)(next)(context.Background(), methodCallTool, req); err != nil {
				t.Fatalf("middleware: %v", err)
			}

			if got := testutil.ToFloat64(m.toolCalls.WithLabelValues(tt.wantTool, "ok")); got != 1 {
				t.Errorf("tool_calls_total{%s,ok} = %v, want 1", tt.wantTool, got)
			}
			// The bounded set must never let an unrecognized name become its own
			// label, or a client could grow the metric's cardinality without limit.
			if tt.wantTool != tt.callName {
				if got := testutil.ToFloat64(m.toolCalls.WithLabelValues(tt.callName, "ok")); got != 0 {
					t.Errorf("tool_calls_total{%s,ok} = %v, want 0 (must not create a label from client input)", tt.callName, got)
				}
			}
		})
	}
}

func TestWrapRoundTripper(t *testing.T) {
	t.Parallel()

	t.Run("records status code", func(t *testing.T) {
		t.Parallel()
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusTeapot)
		}))
		t.Cleanup(srv.Close)

		m := New()
		c := &http.Client{Transport: m.WrapRoundTripper(http.DefaultTransport)}
		resp, err := c.Get(srv.URL) //nolint:noctx // short-lived test client
		if err != nil {
			t.Fatalf("GET: %v", err)
		}
		_ = resp.Body.Close()

		if got := testutil.ToFloat64(m.apiRequests.WithLabelValues(http.MethodGet, "418")); got != 1 {
			t.Errorf("api_requests_total{GET,418} = %v, want 1", got)
		}
	})

	t.Run("transport error labeled error", func(t *testing.T) {
		t.Parallel()
		m := New()
		wantErr := errors.New("dial refused")
		rt := m.WrapRoundTripper(roundTripperFunc(func(*http.Request) (*http.Response, error) {
			return nil, wantErr
		}))

		req := httptest.NewRequest(http.MethodPost, "http://example.invalid", nil)
		if _, err := rt.RoundTrip(req); !errors.Is(err, wantErr) {
			t.Fatalf("err = %v, want %v", err, wantErr)
		}
		if got := testutil.ToFloat64(m.apiRequests.WithLabelValues(http.MethodPost, "error")); got != 1 {
			t.Errorf("api_requests_total{POST,error} = %v, want 1", got)
		}
	})
}
