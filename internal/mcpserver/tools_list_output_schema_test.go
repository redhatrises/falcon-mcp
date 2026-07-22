package mcpserver

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/crowdstrike/falcon-mcp/internal/config"
)

// toolsListBudget mirrors the Python soft budget in
// tests/test_tools_list_output_schema.py (issue #325 / #376). New modules may
// grow past this; use --modules for constrained clients.
const toolsListBudget = 120_000

// TestFullServerToolsListOmitsOutputSchema is the product-level regression for
// issues #325 / #376: every tool advertised by a full falcon-mcp server must
// omit outputSchema from tools/list, matching Python structured_output=False.
func TestFullServerToolsListOmitsOutputSchema(t *testing.T) {
	srv, err := New(&config.Config{}, &client.CrowdStrikeAPISpecification{})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	clientT, serverT := mcp.NewInMemoryTransports()
	ss, err := srv.MCP().Connect(ctx, serverT, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ss.Wait() })

	c := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "test"}, nil)
	cs, err := c.Connect(ctx, clientT, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cs.Close() })

	all := listAllTools(t, cs)
	if len(all) == 0 {
		t.Fatal("server registered no tools")
	}

	var offenders []string
	var missingInput []string
	total := 0
	for _, tool := range all {
		if tool.OutputSchema != nil {
			offenders = append(offenders, tool.Name)
		}
		if tool.InputSchema == nil {
			missingInput = append(missingInput, tool.Name)
		}
		b, err := json.Marshal(tool)
		if err != nil {
			t.Fatalf("marshal %q: %v", tool.Name, err)
		}
		total += len(b)
	}
	if len(offenders) > 0 {
		t.Fatalf("tools/list must omit outputSchema (issues #325/#376); %d offenders, e.g. %v",
			len(offenders), offenders[:min(5, len(offenders))])
	}
	if len(missingInput) > 0 {
		t.Fatalf("tools missing inputSchema: %v", missingInput)
	}

	t.Logf("tools/list payload: %d tools, %d bytes (%.1f KB)", len(all), total, float64(total)/1024)
	if total >= toolsListBudget {
		t.Logf("WARNING: tools/list payload %d bytes exceeds %d byte soft budget; "+
			"consider --modules for constrained clients (matches Python soft check)",
			total, toolsListBudget)
	}
}

// TestFullServerToolsListPayloadSavings documents the size evidence for the
// outputSchema omission policy: with the middleware active, the advertised
// catalogue must stay well below the pre-fix inflated size.
func TestFullServerToolsListPayloadSavings(t *testing.T) {
	// Pre-fix measurement (2026-07-22): 115 tools, ~178 KB with outputSchema,
	// ~135 KB without — ~45 KB / 24% savings. Guard against regressions that
	// re-inflate the list payload toward the with-schema figure.
	const maxAcceptableBytes = 160_000 // comfortably above without-schema (~135KB), below with-schema (~178KB)

	srv, err := New(&config.Config{}, &client.CrowdStrikeAPISpecification{})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	clientT, serverT := mcp.NewInMemoryTransports()
	ss, err := srv.MCP().Connect(ctx, serverT, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ss.Wait() })

	c := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "test"}, nil)
	cs, err := c.Connect(ctx, clientT, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cs.Close() })

	all := listAllTools(t, cs)
	total := 0
	withSchema := 0
	for _, tool := range all {
		if tool.OutputSchema != nil {
			withSchema++
		}
		b, _ := json.Marshal(tool)
		total += len(b)
	}
	if withSchema != 0 {
		t.Fatalf("%d tools still advertise outputSchema", withSchema)
	}
	t.Logf("tools=%d payloadBytes=%d maxAcceptable=%d", len(all), total, maxAcceptableBytes)
	if total > maxAcceptableBytes {
		t.Fatalf("tools/list payload %d bytes exceeds %d; outputSchema omission may have regressed",
			total, maxAcceptableBytes)
	}
}

func listAllTools(t *testing.T, cs *mcp.ClientSession) []*mcp.Tool {
	t.Helper()
	ctx := context.Background()
	var all []*mcp.Tool
	var cursor string
	for {
		params := &mcp.ListToolsParams{}
		if cursor != "" {
			params.Cursor = cursor
		}
		res, err := cs.ListTools(ctx, params)
		if err != nil {
			t.Fatalf("ListTools: %v", err)
		}
		all = append(all, res.Tools...)
		if res.NextCursor == "" {
			break
		}
		cursor = res.NextCursor
	}
	return all
}
