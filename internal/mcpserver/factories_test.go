package mcpserver

import (
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/crowdstrike/gofalcon/falcon/client"

	"github.com/crowdstrike/falcon-mcp/internal/modules/registry"
)

// excludedModuleDirs names the non-module packages under internal/modules that
// the aggregator generator skips: they provide the module contract (base,
// registry) or a distinct meta layer (dynamic) rather than a tool module with a
// Factory. This must stay in sync with the `excluded` map in
// tools/genmodules/main.go — the two are intentionally duplicated because
// genmodules is package main and cannot be imported here.
var excludedModuleDirs = map[string]bool{
	"base":     true,
	"registry": true,
	"dynamic":  true,
}

// TestModuleFactoriesDiscovered verifies that the generated aggregator wires
// every tool module in deterministic (directory-name) order. It guards against
// a stale factories_gen.go: a newly added module missing here means the
// generator was not re-run.
//
// The expected set is derived at runtime from the module directories rather than
// a hardcoded literal, so adding a module never edits this file (avoiding the
// merge conflicts a shared list produced). The invariant it relies on: every
// module's Name() equals its directory under internal/modules/.
func TestModuleFactoriesDiscovered(t *testing.T) {
	modules := registry.Build(registry.Deps{
		API: &client.CrowdStrikeAPISpecification{},
	}, moduleFactories())

	var got []string
	for _, m := range modules {
		got = append(got, m.Name())
	}

	want := discoverModuleDirs(t)
	if len(got) != len(want) {
		t.Fatalf("moduleFactories() built %v, want %v", got, want)
	}
	for i, name := range want {
		if got[i] != name {
			t.Errorf("module %d = %q, want %q", i, got[i], name)
		}
	}
}

// discoverModuleDirs returns the sorted names of the tool-module directories
// under ../modules, excluding the non-module packages.
func discoverModuleDirs(t *testing.T) []string {
	t.Helper()

	entries, err := os.ReadDir(filepath.Join("..", "modules"))
	if err != nil {
		t.Fatalf("read modules dir: %v", err)
	}

	var dirs []string
	for _, e := range entries {
		if !e.IsDir() || excludedModuleDirs[e.Name()] {
			continue
		}
		dirs = append(dirs, e.Name())
	}
	sort.Strings(dirs)
	return dirs
}
