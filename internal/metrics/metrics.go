// Package metrics owns the Prometheus instrumentation for falcon-mcp: a private
// registry, the application metric vectors, and the hooks that record them (an
// MCP middleware for tool calls and an http.RoundTripper wrapper for outbound
// Falcon API traffic). It also registers the Go runtime and process collectors,
// so the /metrics endpoint reports process stats in standard Prometheus form.
package metrics

import (
	"context"
	"net/http"
	"strconv"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// namespace prefixes every application metric name (e.g. falcon_mcp_tool_calls_total).
const namespace = "falcon_mcp"

// methodCallTool is the JSON-RPC method the MCP SDK dispatches for a tool
// invocation; the tool middleware only instruments this method.
const methodCallTool = "tools/call"

// unknownTool is the fixed label recorded for a tools/call whose name is not a
// registered tool (or is missing). Bucketing every unrecognized name here keeps
// the tool label's cardinality bounded by the registered tool set, so a client
// cannot grow the metric's memory footprint by calling arbitrary names.
const unknownTool = "unknown"

// durationBuckets are the latency histogram boundaries (seconds) shared by the
// tool-call and outbound-API histograms. They extend past prometheus.DefBuckets'
// 10s ceiling because Falcon API calls — and the dynamic-mode tool calls that
// wrap them — routinely run longer, and a bucket beyond the tail is needed to
// distinguish "slow" from "timed out".
var durationBuckets = []float64{.005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5, 10, 30, 60}

// Metrics owns a private Prometheus registry and the application metric vectors.
// Constructing it is cheap and side-effect-free, so callers build one
// unconditionally and instrument through its methods; whether the /metrics
// endpoint is served stays a separate opt-in decision.
type Metrics struct {
	reg *prometheus.Registry

	toolCalls    *prometheus.CounterVec
	toolDuration *prometheus.HistogramVec
	apiRequests  *prometheus.CounterVec
	apiDuration  *prometheus.HistogramVec
}

// New builds a Metrics with a fresh registry (not the global default, so nothing
// is registered process-wide), the application metric vectors, and the Go
// runtime and process collectors.
func New() *Metrics {
	reg := prometheus.NewRegistry()
	reg.MustRegister(
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
	)
	factory := promauto.With(reg)
	return &Metrics{
		reg: reg,
		toolCalls: factory.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "tool_calls_total",
			Help:      "Total number of MCP tool calls, labeled by tool and status (ok or error). In dynamic mode a falcon_execute_tool call is counted under both tool=\"falcon_execute_tool\" and the underlying tool it dispatches to.",
		}, []string{"tool", "status"}),
		toolDuration: factory.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: namespace,
			Name:      "tool_call_duration_seconds",
			Help:      "Duration of MCP tool calls in seconds, labeled by tool. In dynamic mode the falcon_execute_tool observation is end-to-end and includes the underlying tool's own dispatch time.",
			Buckets:   durationBuckets,
		}, []string{"tool"}),
		apiRequests: factory.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "api_requests_total",
			Help:      "Total number of outbound Falcon API requests, labeled by HTTP method and response code.",
		}, []string{"method", "code"}),
		apiDuration: factory.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: namespace,
			Name:      "api_request_duration_seconds",
			Help:      "Duration of outbound Falcon API requests in seconds, labeled by HTTP method.",
			Buckets:   durationBuckets,
		}, []string{"method"}),
	}
}

// Handler returns an http.Handler that serves the registry in Prometheus text
// exposition format. Unlike the former expvar dump it never emits os.Args, so
// there is no flag-passed-credential leak to filter.
func (m *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.reg, promhttp.HandlerOpts{})
}

// ToolMiddleware returns an MCP receiving middleware that records a call count
// and duration for each tool invocation. It only instruments the tools/call
// method and passes every other method straight through. The recorded status is
// "error" when the handler returns an error or the result's IsError is set,
// otherwise "ok".
//
// known bounds the tool label: a call whose name is not in known (or is
// missing) is recorded under a fixed "unknown" label, so untrusted client input
// cannot explode the metric's cardinality. A nil known records every name and is
// intended only for callers whose tool names are already validated upstream —
// e.g. the dynamic-mode catalog's internal server, which falcon_execute_tool
// only ever dispatches to after a successful catalog lookup.
//
// Attach it to the served server bounded by that server's registered tools. In
// dynamic mode also attach it to the catalog's internal server so the real
// underlying tool name is recorded rather than only the falcon_execute_tool
// meta-tool; that meta-tool call is then counted under both its own label and
// the underlying tool's.
func (m *Metrics) ToolMiddleware(known map[string]struct{}) mcp.Middleware {
	return func(next mcp.MethodHandler) mcp.MethodHandler {
		return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
			if method != methodCallTool {
				return next(ctx, method, req)
			}
			tool := unknownTool
			if r, ok := req.(*mcp.CallToolRequest); ok && r.Params != nil {
				if name := r.Params.Name; known == nil {
					tool = name
				} else if _, registered := known[name]; registered {
					tool = name
				}
			}

			start := time.Now()
			res, err := next(ctx, method, req)
			m.toolDuration.WithLabelValues(tool).Observe(time.Since(start).Seconds())

			status := "ok"
			if err != nil {
				status = "error"
			} else if r, ok := res.(*mcp.CallToolResult); ok && r.IsError {
				status = "error"
			}
			m.toolCalls.WithLabelValues(tool, status).Inc()
			return res, err
		}
	}
}

// WrapRoundTripper returns an http.RoundTripper that records a request count
// (labeled by HTTP method and response status code) and duration for each
// outbound call made through next. A nil next falls back to
// http.DefaultTransport. On a transport error the code label is "error", since
// no response status is available.
func (m *Metrics) WrapRoundTripper(next http.RoundTripper) http.RoundTripper {
	if next == nil {
		next = http.DefaultTransport
	}
	return roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		start := time.Now()
		resp, err := next.RoundTrip(req)
		m.apiDuration.WithLabelValues(req.Method).Observe(time.Since(start).Seconds())

		code := "error"
		if err == nil && resp != nil {
			code = strconv.Itoa(resp.StatusCode)
		}
		m.apiRequests.WithLabelValues(req.Method, code).Inc()
		return resp, err
	})
}

// roundTripperFunc adapts a function to http.RoundTripper, mirroring
// http.HandlerFunc for the client side.
type roundTripperFunc func(*http.Request) (*http.Response, error)

// RoundTrip calls f.
func (f roundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }
