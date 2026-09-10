// Package metrics provides Prometheus instrumentation for the falcon-mcp server.
//
// A Recorder owns a dedicated Prometheus registry (never the global default) so
// that metrics are self-contained and testable. It records per-tool call
// metrics and serves them, alongside Go runtime and process collectors, in the
// standard Prometheus text exposition format.
package metrics

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Outcome classifies how a tool call finished, and is used as the value of the
// "outcome" label on the tool-call counter.
const (
	// OutcomeOK marks a tool call that returned a successful result.
	OutcomeOK = "ok"
	// OutcomeError marks a tool call whose handler returned a Go error (a
	// protocol- or transport-level failure).
	OutcomeError = "error"
	// OutcomeToolError marks a tool call that returned a result with IsError
	// set: a business error (e.g. an API or FQL error) surfaced as tool content
	// rather than a Go error.
	OutcomeToolError = "tool_error"
)

// Recorder records falcon-mcp metrics into a private Prometheus registry and
// exposes them over HTTP.
type Recorder struct {
	registry  *prometheus.Registry
	calls     *prometheus.CounterVec
	callDurns *prometheus.HistogramVec
}

// New builds a Recorder with a fresh registry containing the Go runtime and
// process collectors plus the falcon-mcp tool-call metrics.
func New() *Recorder {
	reg := prometheus.NewRegistry()
	reg.MustRegister(
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
	)

	calls := prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "falconmcp",
		Subsystem: "tool",
		Name:      "calls_total",
		Help:      "Total number of MCP tool calls, labeled by tool and outcome.",
	}, []string{"tool", "outcome"})

	callDurns := prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: "falconmcp",
		Subsystem: "tool",
		Name:      "call_duration_seconds",
		Help:      "Duration of MCP tool calls in seconds, labeled by tool.",
		Buckets:   prometheus.DefBuckets,
	}, []string{"tool"})

	reg.MustRegister(calls, callDurns)

	return &Recorder{registry: reg, calls: calls, callDurns: callDurns}
}

// ToolCall describes a single completed tool call to record.
type ToolCall struct {
	// Tool is the tool name (e.g. "falcon_search_hosts").
	Tool string
	// Outcome is one of OutcomeOK, OutcomeError, or OutcomeToolError.
	Outcome string
	// Seconds is the call duration in seconds.
	Seconds float64
}

// ObserveToolCall records a single tool call: it increments the call counter for
// the tool and outcome and observes the call duration for the tool.
func (r *Recorder) ObserveToolCall(c ToolCall) {
	r.calls.WithLabelValues(c.Tool, c.Outcome).Inc()
	r.callDurns.WithLabelValues(c.Tool).Observe(c.Seconds)
}

// Handler returns an http.Handler that serves the recorded metrics on /metrics
// in the Prometheus text exposition format.
func (r *Recorder) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(r.registry, promhttp.HandlerOpts{Registry: r.registry}))
	return mux
}
