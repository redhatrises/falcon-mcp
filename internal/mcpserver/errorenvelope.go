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
	"encoding/json"
	"errors"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/crowdstrike/falcon-mcp/internal/modules/base"
)

// errorEnvelopeMiddleware returns receiving middleware that restores the full
// error envelope on a denied tool call.
//
// A handler reports a permission failure by returning a *base.Error, which
// carries the API scopes the operation needs and how to grant them. The SDK
// reduces any returned error to its Error() text, so that guidance never reaches
// the client — the caller is told access was denied but not which scope to add.
// SetError keeps the original error on the result, so this middleware recovers
// it and republishes the envelope as both structured content and text.
//
// It runs outside the SDK's typed tool wrapper, so the structured content it
// sets is final: no output-schema validation applies to an error result.
func errorEnvelopeMiddleware() mcp.Middleware {
	return func(next mcp.MethodHandler) mcp.MethodHandler {
		return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
			res, err := next(ctx, method, req)
			if method != methodCallTool {
				return res, err
			}
			// A handler that fails before producing a result yields a typed nil, which
			// satisfies the assertion, so the nil check must come first.
			ctr, ok := res.(*mcp.CallToolResult)
			if !ok || ctr == nil || !ctr.IsError {
				return res, err
			}
			var apiErr *base.Error
			if !errors.As(ctr.GetError(), &apiErr) {
				return res, err
			}
			if len(apiErr.RequiredScopes) == 0 && apiErr.Resolution == "" {
				return res, err
			}
			envelope, marshalErr := json.Marshal(apiErr)
			if marshalErr != nil {
				return res, err
			}
			// The envelope is appended, not substituted: SetError leaves a message the
			// handler wrote in place, and that message may say more than the envelope.
			// Text carries it as well as structured content, because a client that
			// renders only text must still learn which scope to grant.
			ctr.StructuredContent = json.RawMessage(envelope)
			ctr.Content = append(ctr.Content, &mcp.TextContent{Text: string(envelope)})
			return ctr, err
		}
	}
}
