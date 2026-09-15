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
	"fmt"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/crowdstrike/falcon-mcp/internal/modules/base"
)

// errResult builds the CallToolResult the SDK produces when a tool handler
// returns err: SetError records the error and flags the result.
func errResult(err error) *mcp.CallToolResult {
	var res mcp.CallToolResult
	res.SetError(err)
	return &res
}

// scopeErr is a 403 *base.Error carrying the guidance a caller needs to fix the
// permission, as base.APIError builds it.
func scopeErr() *base.Error {
	return &base.Error{
		Message:        "access denied",
		StatusCode:     403,
		RequiredScopes: []string{"Hosts:read", "Hosts:write"},
		Resolution:     "This operation requires the following API scopes: Hosts:read, Hosts:write.",
	}
}

func TestErrorEnvelopeMiddleware(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		method     string
		res        mcp.Result
		err        error
		wantScopes bool
	}{
		{
			name:       "403 scope error gains the envelope",
			method:     methodCallTool,
			res:        errResult(scopeErr()),
			wantScopes: true,
		},
		{
			name:   "wrapped 403 scope error gains the envelope",
			method: methodCallTool,
			res:    errResult(fmt.Errorf("search_hosts: %w", scopeErr())),

			wantScopes: true,
		},
		{
			name:   "error without scopes is left alone",
			method: methodCallTool,
			res:    errResult(&base.Error{Message: "boom", StatusCode: 500}),
		},
		{
			name:   "plain error is left alone",
			method: methodCallTool,
			res:    errResult(errors.New("boom")),
		},
		{
			name:   "successful result is left alone",
			method: methodCallTool,
			res:    &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "ok"}}},
		},
		{
			name:   "other methods pass through",
			method: "tools/list",
			res:    errResult(scopeErr()),
		},
		{
			// A method that fails before it builds a result returns a typed nil, which
			// satisfies the type assertion. Dereferencing it crashes the session.
			name:   "typed nil result with an error does not panic",
			method: methodCallTool,
			res:    (*mcp.CallToolResult)(nil),
			err:    scopeErr(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			next := func(context.Context, string, mcp.Request) (mcp.Result, error) {
				return tt.res, tt.err
			}
			got, err := errorEnvelopeMiddleware()(next)(
				context.Background(), tt.method, &mcp.CallToolRequest{Params: &mcp.CallToolParamsRaw{Name: "falcon_search_hosts"}})
			// The middleware must pass an error through unchanged, never swallow it.
			if !errors.Is(err, tt.err) {
				t.Fatalf("middleware returned error %v, want %v", err, tt.err)
			}
			ctr, ok := got.(*mcp.CallToolResult)
			if !ok {
				t.Fatalf("result is %T, want *mcp.CallToolResult", got)
			}
			if !tt.wantScopes {
				if ctr != nil && ctr.StructuredContent != nil {
					t.Fatalf("StructuredContent was set on a result that must stay untouched: %v", ctr.StructuredContent)
				}
				return
			}

			// The client must be able to read the scopes both as data and as text.
			raw, err := json.Marshal(ctr.StructuredContent)
			if err != nil {
				t.Fatalf("marshal StructuredContent: %v", err)
			}
			var env struct {
				Error          string   `json:"error"`
				RequiredScopes []string `json:"required_scopes"`
				Resolution     string   `json:"resolution"`
			}
			if err := json.Unmarshal(raw, &env); err != nil {
				t.Fatalf("unmarshal envelope %s: %v", raw, err)
			}
			if len(env.RequiredScopes) != 2 || env.RequiredScopes[0] != "Hosts:read" {
				t.Errorf("required_scopes = %v, want [Hosts:read Hosts:write]", env.RequiredScopes)
			}
			if env.Resolution == "" {
				t.Error("resolution is empty")
			}
			if !strings.Contains(env.Error, "access denied") {
				t.Errorf("error = %q, want it to keep the original message", env.Error)
			}
			if !ctr.IsError {
				t.Error("IsError was cleared; a denied call must still read as an error")
			}
			text := allContentText(ctr)
			if !strings.Contains(text, "Hosts:read") {
				t.Errorf("content text = %q, want the scopes in it", text)
			}
			// SetError already wrote the handler's message; appending must keep it.
			if !strings.Contains(contentText(t, ctr), "access denied") {
				t.Errorf("first content block = %q, want the original message kept", contentText(t, ctr))
			}
		})
	}
}

// allContentText joins every text block of res.
func allContentText(res *mcp.CallToolResult) string {
	var b strings.Builder
	for _, c := range res.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			b.WriteString(tc.Text)
		}
	}
	return b.String()
}

// deniedToolModule registers one tool that always fails the way a real handler
// fails on a 403: it returns the *base.Error base.APIError built.
type deniedToolModule struct{}

func (deniedToolModule) Name() string                  { return "denied" }
func (deniedToolModule) Description() string           { return "fake module whose tool is always denied" }
func (deniedToolModule) RegisterResources(*mcp.Server) {}
func (deniedToolModule) RegisterPrompts(*mcp.Server)   {}
func (deniedToolModule) RegisterTools(r base.Registrar) {
	base.AddTool(r, &mcp.Tool{
		Name:        "search_denied",
		Description: "Always denied.",
	}, func(context.Context, *mcp.CallToolRequest, struct{}) (*mcp.CallToolResult, searchOut, error) {
		return nil, searchOut{}, scopeErr()
	})
}

// assertScopeEnvelope fails unless res carries the 403 envelope as structured
// content, still flagged as an error.
func assertScopeEnvelope(t *testing.T, res *mcp.CallToolResult) {
	t.Helper()
	if !res.IsError {
		t.Fatal("IsError is false; a denied call must read as an error")
	}
	raw, err := json.Marshal(res.StructuredContent)
	if err != nil {
		t.Fatalf("marshal StructuredContent: %v", err)
	}
	var env struct {
		RequiredScopes []string `json:"required_scopes"`
		Resolution     string   `json:"resolution"`
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatalf("unmarshal envelope %s: %v", raw, err)
	}
	if len(env.RequiredScopes) == 0 {
		t.Errorf("required_scopes is empty in %s", raw)
	}
	if env.Resolution == "" {
		t.Errorf("resolution is empty in %s", raw)
	}
}

// connectClient serves srv over an in-memory pipe and returns a connected
// client session.
func connectClient(t *testing.T, srv *mcp.Server) *mcp.ClientSession {
	t.Helper()
	ctx := context.Background()
	clientT, serverT := mcp.NewInMemoryTransports()
	ss, err := srv.Connect(ctx, serverT, nil)
	if err != nil {
		t.Fatalf("server connect: %v", err)
	}
	t.Cleanup(func() { _ = ss.Wait() })
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "c", Version: "test"}, nil).Connect(ctx, clientT, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	t.Cleanup(func() { _ = cs.Close() })
	return cs
}

// TestScopeGuidanceReachesClientCoreMode proves a denied tool call delivers the
// required scopes to a client calling the tool directly.
func TestScopeGuidanceReachesClientCoreMode(t *testing.T) {
	t.Parallel()

	srv := mcp.NewServer(&mcp.Implementation{Name: "test", Version: "test"}, nil)
	srv.AddReceivingMiddleware(errorEnvelopeMiddleware())
	deniedToolModule{}.RegisterTools(base.ServerRegistrar(srv))

	res, err := connectClient(t, srv).CallTool(context.Background(), &mcp.CallToolParams{
		Name:      "falcon_search_denied",
		Arguments: map[string]any{},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	assertScopeEnvelope(t, res)
}

// TestScopeGuidanceReachesClientDynamicMode proves the envelope survives the
// falcon_execute_tool relay, where the inner result crosses a JSON-RPC pipe.
func TestScopeGuidanceReachesClientDynamicMode(t *testing.T) {
	t.Parallel()

	mod := deniedToolModule{}
	cat := NewCatalog()
	mod.RegisterTools(cat.ForModule(mod.Name()))
	cat.Instrument(errorEnvelopeMiddleware())
	if err := cat.Connect(context.Background()); err != nil {
		t.Fatalf("catalog connect: %v", err)
	}
	t.Cleanup(func() { _ = cat.Close() })

	srv := mcp.NewServer(&mcp.Implementation{Name: "test", Version: "test"}, nil)
	NewMetaModule(cat, []base.Module{mod}).RegisterTools(base.ServerRegistrar(srv))

	res, err := connectClient(t, srv).CallTool(context.Background(), &mcp.CallToolParams{
		Name: "falcon_execute_tool",
		Arguments: map[string]any{
			"tool_name":  "falcon_search_denied",
			"parameters": map[string]any{},
		},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	assertScopeEnvelope(t, res)
}
