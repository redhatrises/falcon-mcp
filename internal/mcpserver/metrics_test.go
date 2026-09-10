// MIT License
//
// Copyright (c) 2026 CrowdStrike
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

package mcpserver

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/crowdstrike/falcon-mcp/internal/config"
	"github.com/crowdstrike/falcon-mcp/internal/metrics"
	"github.com/crowdstrike/falcon-mcp/internal/modules/base"
	"github.com/crowdstrike/falcon-mcp/internal/testutil"
)

// metricsBody scrapes rec's /metrics handler and returns the exposition text.
func metricsBody(t *testing.T, rec *metrics.Recorder) string {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	w := httptest.NewRecorder()
	rec.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("metrics handler status = %d, want 200", w.Code)
	}
	body, err := io.ReadAll(w.Body)
	if err != nil {
		t.Fatalf("read metrics body: %v", err)
	}
	return string(body)
}

func TestToolMetricsMiddleware(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		method string
		result mcp.Result
		err    error
		want   string // counter line that must appear, or "" for "no tool counter"
		absent bool
	}{
		{
			name:   "success records ok",
			method: methodCallTool,
			result: &mcp.CallToolResult{},
			want:   `falconmcp_tool_calls_total{outcome="ok",tool="falcon_x"} 1`,
		},
		{
			name:   "go error records error",
			method: methodCallTool,
			err:    errors.New("boom"),
			want:   `falconmcp_tool_calls_total{outcome="error",tool="falcon_x"} 1`,
		},
		{
			name:   "tool error result records tool_error",
			method: methodCallTool,
			result: &mcp.CallToolResult{IsError: true},
			want:   `falconmcp_tool_calls_total{outcome="tool_error",tool="falcon_x"} 1`,
		},
		{
			name:   "non-tool method is not recorded",
			method: "tools/list",
			result: &mcp.ListToolsResult{},
			absent: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			rec := metrics.New()
			next := func(context.Context, string, mcp.Request) (mcp.Result, error) {
				return tt.result, tt.err
			}
			h := toolMetricsMiddleware(rec)(next)

			req := &mcp.CallToolRequest{Params: &mcp.CallToolParamsRaw{Name: "falcon_x"}}
			if _, err := h(context.Background(), tt.method, req); !errors.Is(err, tt.err) {
				t.Fatalf("middleware err = %v, want %v", err, tt.err)
			}

			body := metricsBody(t, rec)
			if tt.absent {
				if strings.Contains(body, "falconmcp_tool_calls_total") {
					t.Errorf("non-tool method recorded a tool counter:\n%s", body)
				}
				return
			}
			if !strings.Contains(body, tt.want) {
				t.Errorf("metrics missing %q in:\n%s", tt.want, body)
			}
		})
	}
}

// TestServerRecordsToolCallMetrics drives a real tool call through the served
// server with metrics enabled and asserts the call was recorded under its name.
func TestServerRecordsToolCallMetrics(t *testing.T) {
	t.Parallel()

	rec := metrics.New()
	srv, err := New(&config.Config{}, &client.CrowdStrikeAPISpecification{}, WithMetrics(rec))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx := context.Background()
	cs := testutil.NewClientSession(ctx, t, srv.MCP())
	if _, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "falcon_list_enabled_tools"}); err != nil {
		t.Fatalf("CallTool: %v", err)
	}

	want := `falconmcp_tool_calls_total{outcome="ok",tool="falcon_list_enabled_tools"} 1`
	if body := metricsBody(t, rec); !strings.Contains(body, want) {
		t.Errorf("metrics missing %q in:\n%s", want, body)
	}
}

// TestCatalogInstrumentRecordsToolCallMetrics verifies that Instrument wires the
// metrics middleware onto the internal catalog server so dynamic-mode tool calls
// are recorded under their real names. It registers a fake tool on a catalog and
// calls it directly, avoiding any Falcon API dependency.
func TestCatalogInstrumentRecordsToolCallMetrics(t *testing.T) {
	t.Parallel()

	rec := metrics.New()
	cat := NewCatalog()
	cat.Instrument(toolMetricsMiddleware(rec))

	reg := cat.ForModule("fake")
	base.AddTool(reg, &mcp.Tool{Name: "fake_tool", Description: "fake tool"},
		func(context.Context, *mcp.CallToolRequest, struct{}) (*mcp.CallToolResult, any, error) {
			return &mcp.CallToolResult{}, nil, nil
		})

	ctx := context.Background()
	cs := testutil.NewClientSession(ctx, t, cat.internal)
	if _, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "falcon_fake_tool"}); err != nil {
		t.Fatalf("CallTool: %v", err)
	}

	want := `falconmcp_tool_calls_total{outcome="ok",tool="falcon_fake_tool"} 1`
	if body := metricsBody(t, rec); !strings.Contains(body, want) {
		t.Errorf("metrics missing %q in:\n%s", want, body)
	}
}
