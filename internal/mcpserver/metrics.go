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
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/crowdstrike/falcon-mcp/internal/metrics"
)

// methodCallTool is the JSON-RPC method the SDK dispatches for a tool call. The
// SDK keeps its own constant unexported, so it is duplicated here.
const methodCallTool = "tools/call"

// toolMetricsMiddleware returns receiving middleware that records a metric for
// every tools/call request and passes all other methods through untouched.
func toolMetricsMiddleware(rec *metrics.Recorder) mcp.Middleware {
	return func(next mcp.MethodHandler) mcp.MethodHandler {
		return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
			call, ok := req.(*mcp.CallToolRequest)
			if method != methodCallTool || !ok {
				return next(ctx, method, req)
			}
			start := time.Now()
			res, err := next(ctx, method, req)
			name := call.Params.Name
			if isUnknownToolCall(res, err) {
				name = "unknown"
			}
			rec.ObserveToolCall(metrics.ToolCall{
				Tool:    name,
				Outcome: toolOutcome(res, err),
				Seconds: time.Since(start).Seconds(),
			})
			return res, err
		}
	}
}

// isUnknownToolCall reports whether the SDK treated this tools/call as a
// missing tool. Client-supplied names must not become Prometheus labels.
func isUnknownToolCall(res mcp.Result, err error) bool {
	if err != nil && strings.Contains(strings.ToLower(err.Error()), "unknown tool") {
		return true
	}
	// A handler that fails before producing a result yields a typed nil, which
	// satisfies the assertion, so the nil check must come first.
	ctr, ok := res.(*mcp.CallToolResult)
	if !ok || ctr == nil || !ctr.IsError {
		return false
	}
	for _, c := range ctr.Content {
		tc, ok := c.(*mcp.TextContent)
		if ok && strings.Contains(strings.ToLower(tc.Text), "unknown tool") {
			return true
		}
	}
	return false
}

// toolOutcome classifies a tool call for the outcome metric label. A Go error is
// a protocol/transport failure; a result with IsError set is a business error
// surfaced as tool content; otherwise the call succeeded.
func toolOutcome(res mcp.Result, err error) string {
	if err != nil {
		return metrics.OutcomeError
	}
	if ctr, ok := res.(*mcp.CallToolResult); ok && ctr != nil && ctr.IsError {
		return metrics.OutcomeToolError
	}
	return metrics.OutcomeOK
}
