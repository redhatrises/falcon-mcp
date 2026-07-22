package base

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// TestToolsListOmitsOutputSchema is the Go regression guard for issues #325 /
// #376: tools/list must not advertise outputSchema (Python structured_output=
// False parity). The schema is still used server-side for StructuredContent
// validation — only the list advertisement is suppressed.
func TestToolsListOmitsOutputSchema(t *testing.T) {
	t.Parallel()

	srv := mcp.NewServer(&mcp.Implementation{Name: "test", Version: "test"}, nil)
	reg := ServerRegistrar(srv)
	AddTool(reg, &mcp.Tool{
		Name:        "echo",
		Description: "echoes input",
	}, func(_ context.Context, _ *mcp.CallToolRequest, in entryIn) (*mcp.CallToolResult, entryOut, error) {
		return nil, entryOut{Echo: in.Name, Count: in.Count}, nil
	})

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

	list, err := cs.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}
	if len(list.Tools) == 0 {
		t.Fatal("expected at least one tool")
	}

	var offenders []string
	for _, tool := range list.Tools {
		if tool.OutputSchema != nil {
			offenders = append(offenders, tool.Name)
		}
		if tool.InputSchema == nil {
			t.Errorf("tool %q missing InputSchema (must still be advertised)", tool.Name)
		}
	}
	if len(offenders) > 0 {
		t.Fatalf("tools/list must omit outputSchema (issues #325/#376); offenders: %v", offenders)
	}
}

// TestToolsListOmissionKeepsStructuredContent proves call-time structured
// results still work after list-side outputSchema redaction: the SDK keeps the
// resolved output schema in the handler closure for validation/packing.
func TestToolsListOmissionKeepsStructuredContent(t *testing.T) {
	t.Parallel()

	srv := mcp.NewServer(&mcp.Implementation{Name: "test", Version: "test"}, nil)
	reg := ServerRegistrar(srv)
	AddTool(reg, &mcp.Tool{
		Name:        "echo",
		Description: "echoes input",
	}, func(_ context.Context, _ *mcp.CallToolRequest, in entryIn) (*mcp.CallToolResult, entryOut, error) {
		return nil, entryOut{Echo: in.Name, Count: in.Count}, nil
	})

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

	// List first (middleware path), then call — order matches real clients.
	if _, err := cs.ListTools(ctx, nil); err != nil {
		t.Fatalf("ListTools: %v", err)
	}

	res, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name:      "falcon_echo",
		Arguments: map[string]any{"name": "hi", "count": 3},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if res.IsError {
		t.Fatalf("unexpected error result: %v", res.Content)
	}
	if res.StructuredContent == nil {
		t.Fatal("expected StructuredContent after outputSchema list omission")
	}

	var got entryOut
	if err := remarshalStructured(t, res.StructuredContent, &got); err != nil {
		t.Fatalf("decode structured content: %v", err)
	}
	if got.Echo != "hi" || got.Count != 3 {
		t.Errorf("got %+v, want {Echo:hi Count:3}", got)
	}
}

// TestToolEntryRegisterAlsoOmitsOutputSchema covers the dynamic-catalog path,
// which registers via ToolEntry.Register rather than ServerRegistrar.Add.
func TestToolEntryRegisterAlsoOmitsOutputSchema(t *testing.T) {
	t.Parallel()

	e := captureAddTool(t, func(_ context.Context, _ *mcp.CallToolRequest, in entryIn) (*mcp.CallToolResult, entryOut, error) {
		return nil, entryOut{Echo: in.Name, Count: in.Count}, nil
	})
	// Registration-time tool descriptor still carries OutputSchema for the SDK.
	if e.Tool.OutputSchema == nil {
		t.Fatal("AddTool should still infer OutputSchema for call-time validation")
	}

	srv := mcp.NewServer(&mcp.Implementation{Name: "test", Version: "test"}, nil)
	e.Register(srv)

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

	list, err := cs.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}
	for _, tool := range list.Tools {
		if tool.OutputSchema != nil {
			t.Fatalf("ToolEntry.Register path still advertised outputSchema on %q", tool.Name)
		}
	}
}

// TestOmitOutputSchemaMiddlewareIdempotent ensures repeated ServerRegistrar
// installs do not stack middleware or panic.
func TestOmitOutputSchemaMiddlewareIdempotent(t *testing.T) {
	t.Parallel()

	srv := mcp.NewServer(&mcp.Implementation{Name: "test", Version: "test"}, nil)
	reg1 := ServerRegistrar(srv)
	reg2 := ServerRegistrar(srv)
	AddTool(reg1, &mcp.Tool{Name: "a", Description: "a"}, func(_ context.Context, _ *mcp.CallToolRequest, _ entryIn) (*mcp.CallToolResult, entryOut, error) {
		return nil, entryOut{}, nil
	})
	AddTool(reg2, &mcp.Tool{Name: "b", Description: "b"}, func(_ context.Context, _ *mcp.CallToolRequest, _ entryIn) (*mcp.CallToolResult, entryOut, error) {
		return nil, entryOut{}, nil
	})
	// Second ensure on the same server must be a no-op.
	ensureOmitOutputSchemaFromToolsList(srv)
	ensureOmitOutputSchemaFromToolsList(srv)

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

	list, err := cs.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}
	if len(list.Tools) != 2 {
		t.Fatalf("got %d tools, want 2", len(list.Tools))
	}
	for _, tool := range list.Tools {
		if tool.OutputSchema != nil {
			t.Errorf("%q still has outputSchema", tool.Name)
		}
	}
}

// TestWireJSONOmitsOutputSchemaKey asserts the wire encoding truly drops the
// field (omitempty), not merely a client-side nil after decode.
func TestWireJSONOmitsOutputSchemaKey(t *testing.T) {
	t.Parallel()

	srv := mcp.NewServer(&mcp.Implementation{Name: "test", Version: "test"}, nil)
	AddTool(ServerRegistrar(srv), &mcp.Tool{Name: "echo", Description: "echo"}, func(_ context.Context, _ *mcp.CallToolRequest, in entryIn) (*mcp.CallToolResult, entryOut, error) {
		return nil, entryOut{Echo: in.Name}, nil
	})

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

	list, err := cs.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}
	raw, err := json.Marshal(list)
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	tools, _ := decoded["tools"].([]any)
	if len(tools) == 0 {
		t.Fatal("no tools in marshaled list")
	}
	for _, item := range tools {
		m, ok := item.(map[string]any)
		if !ok {
			t.Fatalf("tool entry type %T", item)
		}
		if _, has := m["outputSchema"]; has {
			t.Fatalf("wire JSON still contains outputSchema for tool %v", m["name"])
		}
		if _, has := m["inputSchema"]; !has {
			t.Fatalf("wire JSON missing inputSchema for tool %v", m["name"])
		}
	}
}
