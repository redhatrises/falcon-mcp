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
			rec.ObserveToolCall(metrics.ToolCall{
				Tool:    call.Params.Name,
				Outcome: toolOutcome(res, err),
				Seconds: time.Since(start).Seconds(),
			})
			return res, err
		}
	}
}

// toolOutcome classifies a tool call for the outcome metric label. A Go error is
// a protocol/transport failure; a result with IsError set is a business error
// surfaced as tool content; otherwise the call succeeded.
func toolOutcome(res mcp.Result, err error) string {
	if err != nil {
		return metrics.OutcomeError
	}
	if ctr, ok := res.(*mcp.CallToolResult); ok && ctr.IsError {
		return metrics.OutcomeToolError
	}
	return metrics.OutcomeOK
}
