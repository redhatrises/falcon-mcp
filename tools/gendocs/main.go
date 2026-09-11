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

// Command gendocs generates the falcon-mcp Starlight module documentation under
// docs/modules. It statically analyzes the tool-module packages under
// internal/modules with go/ast — reading each module's Name/Description, its
// registered tools (name, description, annotations), the API scopes each tool's
// handler requires, and its MCP resources — then renders one markdown page per
// module plus an overview page.
//
// It is the Go successor to the retired scripts/generate_module_docs.py, which
// introspected the Python package. Scopes are recovered statically because the
// Go modules keep them as package-local base.Scope vars passed to base.APIError
// at each call site rather than in any runtime-visible table. The generator is
// invoked from a //go:generate directive in the internal/mcpserver package and
// its output is deterministic (modules sorted by key), so re-running with no
// source changes rewrites the same bytes and the docs freshness gate stays green.
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// siteBasePath is the base URL path of the published documentation site. It
// prefixes every intra-site link the generator emits.
const siteBasePath = "/falcon-mcp"

// excluded names the non-module packages under internal/modules so the scan
// skips them: base defines the module contract and toolkit, registry defines
// the factory type and assembly. Neither is a documented tool module.
var excluded = map[string]bool{
	"base":     true,
	"registry": true,
}

// annotationKind classifies a tool by the mutating behavior its annotations
// declare, which selects the admonition rendered under the tool heading.
type annotationKind int

const (
	annotationReadOnly annotationKind = iota
	annotationMutating
	annotationDestructive
)

// toolDoc is one tool's documentation-relevant metadata, assembled from a
// module's source.
type toolDoc struct {
	Name        string // registered name, with the "falcon_" prefix applied
	Description string
	Annotation  annotationKind
	Scopes      []string // rendered console permissions, e.g. "Alerts:read"
	Examples    []string // curated natural-language prompt examples
}

// resourceDoc is one MCP resource's documentation-relevant metadata.
type resourceDoc struct {
	URI         string
	Description string
}

// moduleDoc is everything needed to render one module's page and its overview
// table row.
type moduleDoc struct {
	Key         string // the module's Name(), e.g. "detections", "hostgroups"
	Title       string
	Slug        string
	Description string
	Scopes      []string // union of the module's tool scopes
	Tools       []toolDoc
	Resources   []resourceDoc
}

func main() {
	log.SetFlags(0)

	modulesDir := flag.String("modules", "internal/modules", "path to the tool-module packages root")
	outDir := flag.String("out", "docs/modules", "output directory for generated module docs")
	flag.Parse()

	modules, err := discover(*modulesDir)
	if err != nil {
		log.Fatalf("gendocs: %v", err)
	}

	if err := validateHostedMCPNotes(modules); err != nil {
		log.Fatalf("gendocs: %v", err)
	}

	if err := writeDocs(*outDir, modules); err != nil {
		log.Fatalf("gendocs: %v", err)
	}
}

// discover scans root for tool-module packages, skipping the excluded set, and
// builds a moduleDoc for each. Modules are returned sorted by key for
// deterministic output.
func discover(root string) ([]moduleDoc, error) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, fmt.Errorf("read modules dir %s: %w", root, err)
	}

	var modules []moduleDoc
	for _, e := range entries {
		if !e.IsDir() || excluded[e.Name()] {
			continue
		}

		pkg, err := parsePackage(filepath.Join(root, e.Name()))
		if err != nil {
			return nil, err
		}

		doc, err := pkg.moduleDoc()
		if err != nil {
			return nil, fmt.Errorf("module %s: %w", e.Name(), err)
		}
		modules = append(modules, doc)
	}

	sort.Slice(modules, func(i, j int) bool { return modules[i].Key < modules[j].Key })
	return modules, nil
}

// writeDocs renders the overview page and one page per module into outDir, then
// removes any stale *.md file the current module set no longer produces.
func writeDocs(outDir string, modules []moduleDoc) error {
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return fmt.Errorf("create out dir %s: %w", outDir, err)
	}

	expected := map[string]bool{"overview.md": true}
	if err := os.WriteFile(filepath.Join(outDir, "overview.md"), []byte(renderOverview(modules)), 0o644); err != nil { //nolint:gosec // generated docs are not sensitive
		return fmt.Errorf("write overview.md: %w", err)
	}

	for _, m := range modules {
		name := m.Slug + ".md"
		expected[name] = true
		if err := os.WriteFile(filepath.Join(outDir, name), []byte(renderModule(m)), 0o644); err != nil { //nolint:gosec // generated docs are not sensitive
			return fmt.Errorf("write %s: %w", name, err)
		}
	}

	stale, err := filepath.Glob(filepath.Join(outDir, "*.md"))
	if err != nil {
		return fmt.Errorf("scan for stale docs: %w", err)
	}
	for _, path := range stale {
		if expected[filepath.Base(path)] {
			continue
		}
		if err := os.Remove(path); err != nil {
			return fmt.Errorf("remove stale %s: %w", path, err)
		}
	}
	return nil
}

// validateHostedMCPNotes fails when a hosted-MCP note key matches no discovered
// module or no registered tool. The note maps are keyed by name, so a rename
// would silently drop a note and still pass the docs freshness check; failing
// here surfaces the stale key at generation time instead.
func validateHostedMCPNotes(modules []moduleDoc) error {
	moduleKeys := map[string]bool{}
	toolNames := map[string]bool{}
	for _, m := range modules {
		moduleKeys[m.Key] = true
		for _, t := range m.Tools {
			toolNames[t.Name] = true
		}
	}

	var staleModules, staleTools []string
	for key := range hostedMCPModuleNotes {
		if !moduleKeys[key] {
			staleModules = append(staleModules, key)
		}
	}
	for name := range hostedMCPToolNotes {
		if !toolNames[name] {
			staleTools = append(staleTools, name)
		}
	}
	sort.Strings(staleModules)
	sort.Strings(staleTools)

	var problems []string
	if len(staleModules) > 0 {
		problems = append(problems, "hostedMCPModuleNotes keys match no discovered module: "+strings.Join(staleModules, ", "))
	}
	if len(staleTools) > 0 {
		problems = append(problems, "hostedMCPToolNotes keys match no registered tool: "+strings.Join(staleTools, ", "))
	}
	if len(problems) > 0 {
		return fmt.Errorf("stale hosted-MCP note keys (update or remove them after a rename):\n  %s", strings.Join(problems, "\n  "))
	}
	return nil
}
