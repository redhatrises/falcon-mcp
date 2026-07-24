package mcpserver

import (
	"context"
	"slices"
	"testing"

	"github.com/crowdstrike/falcon-mcp/internal/config"
)

// orderedToolNames returns the tools/list order advertised by a New-built
// server, preserving the wire order (unlike listToolNames, which returns a set).
func orderedToolNames(t *testing.T, cfg *config.Config) []string {
	t.Helper()
	cs := connectNewServer(t, cfg)
	tools, err := cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}
	names := make([]string, len(tools.Tools))
	for i, tool := range tools.Tools {
		names[i] = tool.Name
	}
	return names
}

// contiguousBlock returns the sub-slice of names bounded by the first and last
// occurrence of any member of want, or nil if none of want appears.
func contiguousBlock(names, want []string) []string {
	first, last := -1, -1
	for i, n := range names {
		if slices.Contains(want, n) {
			if first == -1 {
				first = i
			}
			last = i
		}
	}
	if first == -1 {
		return nil
	}
	return names[first : last+1]
}

// TestToolsListOrderCoreFirst pins the normal-mode tools/list ordering to match
// the Python server: core tools first, then each module's tools grouped in
// registration order (not alphabetized).
func TestToolsListOrderCoreFirst(t *testing.T) {
	names := orderedToolNames(t, &config.Config{})

	wantCore := []string{
		"falcon_list_enabled_modules",
		"falcon_check_connectivity",
		"falcon_list_modules",
	}
	if len(names) < len(wantCore) {
		t.Fatalf("too few tools: %v", names)
	}
	if got := names[:len(wantCore)]; !slices.Equal(got, wantCore) {
		t.Fatalf("core tools = %v, want %v (full: %v)", got, wantCore, names)
	}

	// host_groups tools must appear as a contiguous block in registration
	// order. This sequence is non-alphabetical, so it doubles as the
	// anti-alphabetization assertion.
	wantHostGroups := []string{
		"falcon_search_host_groups",
		"falcon_search_host_group_members",
		"falcon_create_host_group",
		"falcon_update_host_group",
		"falcon_delete_host_groups",
		"falcon_perform_host_group_action",
	}
	block := contiguousBlock(names, wantHostGroups)
	if !slices.Equal(block, wantHostGroups) {
		t.Fatalf("host_groups block = %v, want %v (full: %v)", block, wantHostGroups, names)
	}
}

// TestToolsListOrderDynamic pins the dynamic-mode ordering: list_enabled_modules
// then the two meta-tools, matching Python.
func TestToolsListOrderDynamic(t *testing.T) {
	names := orderedToolNames(t, &config.Config{Dynamic: true})

	want := []string{
		"falcon_list_enabled_modules",
		"falcon_search_tools",
		"falcon_execute_tool",
	}
	if !slices.Equal(names, want) {
		t.Fatalf("dynamic tools/list = %v, want %v", names, want)
	}
}
