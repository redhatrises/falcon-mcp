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

package metrics

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestObserveToolCall(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		tool    string
		outcome string
		calls   int
	}{
		{name: "ok outcome", tool: "falcon_search_hosts", outcome: OutcomeOK, calls: 3},
		{name: "error outcome", tool: "falcon_search_hosts", outcome: OutcomeError, calls: 1},
		{name: "tool_error outcome", tool: "falcon_get_host_details", outcome: OutcomeToolError, calls: 2},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			r := New()
			for range tt.calls {
				r.ObserveToolCall(ToolCall{Tool: tt.tool, Outcome: tt.outcome, Seconds: 0.01})
			}

			if got := testutil.ToFloat64(r.calls.WithLabelValues(tt.tool, tt.outcome)); got != float64(tt.calls) {
				t.Errorf("calls_total{tool=%q,outcome=%q} = %v, want %d", tt.tool, tt.outcome, got, tt.calls)
			}
			// One duration observation is recorded per call, keyed only by tool.
			if got := testutil.CollectAndCount(r.callDurns); got == 0 {
				t.Error("call_duration_seconds recorded no series")
			}
		})
	}
}

func TestHandlerServesPrometheus(t *testing.T) {
	t.Parallel()

	r := New()
	r.ObserveToolCall(ToolCall{Tool: "falcon_search_hosts", Outcome: OutcomeOK, Seconds: 0.02})

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rec := httptest.NewRecorder()
	r.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Errorf("Content-Type = %q, want text/plain exposition", ct)
	}

	body, err := io.ReadAll(rec.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	got := string(body)

	for _, want := range []string{
		`falconmcp_tool_calls_total{outcome="ok",tool="falcon_search_hosts"} 1`,
		"falconmcp_tool_call_duration_seconds",
		"go_goroutines",
		"process_",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("metrics body missing %q", want)
		}
	}
}
