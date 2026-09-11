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

package main

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// fixtureModule is synthetic module source exercising the extraction paths the
// real modules use: a const description, an inline tool, a tool built into a
// local variable, a tool registered from a helper method, discriminator scope
// helpers, a transitive scope through a private method, and a resource whose URI
// is a const.
const fixtureModule = `package testmod

import (
	"context"

	"github.com/crowdstrike/falcon-mcp/internal/modules/base"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const searchDesc = "Search things. " + "Consult the guide."
const thingURI = "falcon://testmod/things/fql-guide"

var (
	scopeFooRead  = base.Scope{Name: "Foo", Read: true}
	scopeFooWrite = base.Scope{Name: "Foo", Write: true}
)

func readScope(t string) base.Scope { return scopeFooRead }
func writeScope(t string) base.Scope { return scopeFooWrite }

type Module struct{}

func (m *Module) Name() string        { return "testmod" }
func (m *Module) Description() string { return "Test module description" }

func (m *Module) RegisterTools(r base.Registrar) {
	base.AddTool(r, &mcp.Tool{
		Name:        "search_thing",
		Description: searchDesc,
	}, m.searchThing)

	makeTool := &mcp.Tool{
		Name:        "make_thing",
		Description: "Make a thing.",
		Annotations: base.MutatingAnnotations(false),
	}
	base.AddTool(r, makeTool, m.makeThing)

	m.registerMore(r)
}

func (m *Module) registerMore(r base.Registrar) {
	base.AddTool(r, &mcp.Tool{
		Name:        "delete_thing",
		Description: "Delete a thing.",
		Annotations: base.DestructiveAnnotations(true),
	}, m.deleteThing)
}

func (m *Module) RegisterResources(s *mcp.Server) {
	base.TextResource(s, thingURI, "search_thing_fql_guide", "The things guide.", "text/markdown", "body")
}

func (m *Module) RegisterPrompts(s *mcp.Server) {}

func (m *Module) searchThing(ctx context.Context) error {
	return base.APIError(nil, nil, readScope("x"))
}

func (m *Module) makeThing(ctx context.Context) error {
	return base.APIError(nil, nil, writeScope("x"))
}

func (m *Module) deleteThing(ctx context.Context) error {
	return m.doDelete()
}

func (m *Module) doDelete() error {
	return base.APIError(nil, nil, scopeFooWrite)
}
`

// writeFixture writes src into a temp module directory and returns its path.
func writeFixture(t *testing.T, src string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "mod.go"), []byte(src), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	return dir
}

func TestModuleDocExtraction(t *testing.T) {
	pkg, err := parsePackage(writeFixture(t, fixtureModule))
	if err != nil {
		t.Fatalf("parsePackage: %v", err)
	}
	doc, err := pkg.moduleDoc()
	if err != nil {
		t.Fatalf("moduleDoc: %v", err)
	}

	if doc.Key != "testmod" {
		t.Errorf("Key = %q, want testmod", doc.Key)
	}
	if doc.Title != "Testmod" {
		t.Errorf("Title = %q, want Testmod (title-cased fallback)", doc.Title)
	}
	if doc.Slug != "testmod" {
		t.Errorf("Slug = %q, want testmod", doc.Slug)
	}
	if doc.Description != "Test module description" {
		t.Errorf("Description = %q", doc.Description)
	}
	if want := []string{"Foo:read", "Foo:write"}; !reflect.DeepEqual(doc.Scopes, want) {
		t.Errorf("module Scopes = %v, want %v", doc.Scopes, want)
	}

	wantTools := []struct {
		name   string
		anno   annotationKind
		scopes []string
		desc   string
	}{
		{"falcon_search_thing", annotationReadOnly, []string{"Foo:read"}, "Search things. Consult the guide."},
		{"falcon_make_thing", annotationMutating, []string{"Foo:write"}, "Make a thing."},
		{"falcon_delete_thing", annotationDestructive, []string{"Foo:write"}, "Delete a thing."},
	}
	if len(doc.Tools) != len(wantTools) {
		t.Fatalf("got %d tools, want %d: %+v", len(doc.Tools), len(wantTools), doc.Tools)
	}
	for i, w := range wantTools {
		got := doc.Tools[i]
		if got.Name != w.name {
			t.Errorf("tool[%d].Name = %q, want %q (order matters)", i, got.Name, w.name)
		}
		if got.Annotation != w.anno {
			t.Errorf("tool %s Annotation = %d, want %d", w.name, got.Annotation, w.anno)
		}
		if !reflect.DeepEqual(got.Scopes, w.scopes) {
			t.Errorf("tool %s Scopes = %v, want %v", w.name, got.Scopes, w.scopes)
		}
		if got.Description != w.desc {
			t.Errorf("tool %s Description = %q, want %q", w.name, got.Description, w.desc)
		}
	}

	if len(doc.Resources) != 1 {
		t.Fatalf("got %d resources, want 1", len(doc.Resources))
	}
	if doc.Resources[0].URI != "falcon://testmod/things/fql-guide" {
		t.Errorf("resource URI = %q", doc.Resources[0].URI)
	}
	if doc.Resources[0].Description != "The things guide." {
		t.Errorf("resource description = %q", doc.Resources[0].Description)
	}
}

func TestCleanDocstring(t *testing.T) {
	tests := []struct {
		name, in, want string
	}{
		{"passthrough", "A clean sentence.", "A clean sentence."},
		{"strips noise", "IMPORTANT: You must use the guide.\nReal content.", "Real content."},
		{"collapses blanks", "Line one.\n\n\n\nLine two.", "Line one.\n\nLine two."},
		{"trims", "\n\nContent.\n\n", "Content."},
		{"strips resource preamble", "This resource contains the guide for X.\nKeep this.", "Keep this."},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := cleanDocstring(tt.in); got != tt.want {
				t.Errorf("cleanDocstring(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestSortScopes(t *testing.T) {
	in := map[string]bool{
		"Cases:write":         true,
		"Alerts:read":         true,
		"Case Templates:read": true,
		"Alerts:write":        true,
	}
	want := []string{"Alerts:read", "Case Templates:read", "Alerts:write", "Cases:write"}
	if got := sortScopes(in); !reflect.DeepEqual(got, want) {
		t.Errorf("sortScopes = %v, want %v (reads first, then alpha)", got, want)
	}
}

func TestRenderModule(t *testing.T) {
	m := moduleDoc{
		Key:         "detections",
		Title:       "Detections",
		Slug:        "detections",
		Description: "Triage detections",
		Scopes:      []string{"Alerts:read", "Alerts:write"},
		Tools: []toolDoc{
			{
				Name:        "falcon_search_detections",
				Description: "Search detections.",
				Annotation:  annotationReadOnly,
				Scopes:      []string{"Alerts:read"},
				Examples:    []string{"Show me detections"},
			},
			{
				Name:        "falcon_update_detections",
				Description: "Update detections.",
				Annotation:  annotationMutating,
				Scopes:      []string{"Alerts:write"},
			},
		},
		Resources: []resourceDoc{{URI: "falcon://detections/search/fql-guide", Description: "The guide."}},
	}

	got := renderModule(m)
	wantContains := []string{
		"<!-- meta:title Detections -->",
		"<!-- frontmatter:sidebar order:10 -->",
		"## API Scopes",
		"- `Alerts:read`",
		"### `falcon_search_detections`",
		"**Required scopes:** `Alerts:read`",
		"- \"Show me detections\"",
		"> [!NOTE]\n> This tool modifies data.",
		"## Resources",
		"- **`falcon://detections/search/fql-guide`**: The guide.",
	}
	for _, want := range wantContains {
		if !strings.Contains(got, want) {
			t.Errorf("renderModule output missing %q\n---\n%s", want, got)
		}
	}
	// The read-only tool must not carry a mutating/destructive admonition.
	searchSection := got[strings.Index(got, "### `falcon_search_detections`"):strings.Index(got, "### `falcon_update_detections`")]
	if strings.Contains(searchSection, "modifies data") || strings.Contains(searchSection, "destructive") {
		t.Errorf("read-only tool should have no admonition, got:\n%s", searchSection)
	}
	if !strings.HasSuffix(got, "The guide.\n") {
		t.Errorf("page must end with a single trailing newline, got %q", got[len(got)-20:])
	}
}

func TestRenderDestructiveAdmonition(t *testing.T) {
	m := moduleDoc{
		Key: "ioc", Title: "IOC", Slug: "ioc", Description: "IOCs",
		Tools: []toolDoc{{Name: "falcon_remove_iocs", Description: "Remove.", Annotation: annotationDestructive}},
	}
	if !strings.Contains(renderModule(m), "> [!CAUTION]\n> This tool performs destructive operations.") {
		t.Errorf("destructive tool must render a CAUTION admonition:\n%s", renderModule(m))
	}
}

func TestValidateHostedMCPNotes(t *testing.T) {
	good := []moduleDoc{
		{Key: "fusion", Tools: []toolDoc{{Name: "falcon_search_cloud_insights"}}},
		{Key: "zerotrustassessment"},
		{Key: "rtr"},
		{Key: "policies"},
		{Key: "cloud", Tools: []toolDoc{
			{Name: "falcon_get_cloud_asset_insights"},
			{Name: "falcon_list_cloud_insight_definitions"},
			{Name: "falcon_search_managed_assets"},
		}},
	}
	if err := validateHostedMCPNotes(good); err != nil {
		t.Fatalf("expected no error for complete note coverage, got: %v", err)
	}

	// Dropping the module that a module-note references must be caught.
	missingModule := []moduleDoc{{Key: "cloud", Tools: []toolDoc{
		{Name: "falcon_search_cloud_insights"},
		{Name: "falcon_get_cloud_asset_insights"},
		{Name: "falcon_list_cloud_insight_definitions"},
		{Name: "falcon_search_managed_assets"},
	}}}
	if err := validateHostedMCPNotes(missingModule); err == nil {
		t.Error("expected error when a hostedMCPModuleNotes key matches no module")
	}
}

func TestEvalStringResolvesConstAndConcat(t *testing.T) {
	src := `package testmod
const part = "world"
const greeting = "hello " + part + "!"
type Module struct{}
func (m *Module) Name() string        { return "testmod" }
func (m *Module) Description() string { return greeting }
func (m *Module) RegisterTools(r base.Registrar)   {}
func (m *Module) RegisterResources(s *mcp.Server)  {}
func (m *Module) RegisterPrompts(s *mcp.Server)    {}
`
	pkg, err := parsePackage(writeFixture(t, src))
	if err != nil {
		t.Fatalf("parsePackage: %v", err)
	}
	doc, err := pkg.moduleDoc()
	if err != nil {
		t.Fatalf("moduleDoc: %v", err)
	}
	if doc.Description != "hello world!" {
		t.Errorf("Description = %q, want %q (const + concat resolution)", doc.Description, "hello world!")
	}
}

func TestEvalStringRepeatedConst(t *testing.T) {
	// The same const referenced twice in one concatenation must resolve both
	// times; the cycle guard must not treat the second reference as a cycle.
	src := `package testmod
const word = "go"
const phrase = word + "-" + word + "-" + word
type Module struct{}
func (m *Module) Name() string        { return "testmod" }
func (m *Module) Description() string { return phrase }
func (m *Module) RegisterTools(r base.Registrar)   {}
func (m *Module) RegisterResources(s *mcp.Server)  {}
func (m *Module) RegisterPrompts(s *mcp.Server)    {}
`
	pkg, err := parsePackage(writeFixture(t, src))
	if err != nil {
		t.Fatalf("parsePackage: %v", err)
	}
	doc, err := pkg.moduleDoc()
	if err != nil {
		t.Fatalf("moduleDoc: %v", err)
	}
	if doc.Description != "go-go-go" {
		t.Errorf("Description = %q, want %q", doc.Description, "go-go-go")
	}
}

// TestScopesUnionAcrossSameNamedMethods covers the discriminator-backend
// pattern (exclusions/policies): several receiver types define the same method
// name, and a handler dispatches to one through an interface value. Because the
// concrete type is not resolvable from the AST, the tracer must union the scopes
// of every same-named implementation rather than silently follow whichever was
// parsed first.
func TestScopesUnionAcrossSameNamedMethods(t *testing.T) {
	src := `package testmod

var (
	scopeARead = base.Scope{Name: "Alpha", Read: true}
	scopeBRead = base.Scope{Name: "Beta", Read: true}
)

type aBackend struct{}
type bBackend struct{}

func (aBackend) run() error { return base.APIError(nil, nil, scopeARead) }
func (bBackend) run() error { return base.APIError(nil, nil, scopeBRead) }

type Module struct{ backend interface{ run() error } }

func (m *Module) Name() string        { return "testmod" }
func (m *Module) Description() string { return "d" }

func (m *Module) RegisterTools(r base.Registrar) {
	base.AddTool(r, &mcp.Tool{Name: "do_it", Description: "x"}, m.doIt)
}
func (m *Module) RegisterResources(s *mcp.Server) {}
func (m *Module) RegisterPrompts(s *mcp.Server)   {}

func (m *Module) doIt(ctx context.Context) error { return m.backend.run() }
`
	pkg, err := parsePackage(writeFixture(t, src))
	if err != nil {
		t.Fatalf("parsePackage: %v", err)
	}
	doc, err := pkg.moduleDoc()
	if err != nil {
		t.Fatalf("moduleDoc: %v", err)
	}
	if len(doc.Tools) != 1 {
		t.Fatalf("got %d tools, want 1", len(doc.Tools))
	}
	want := []string{"Alpha:read", "Beta:read"}
	if !reflect.DeepEqual(doc.Tools[0].Scopes, want) {
		t.Errorf("Scopes = %v, want %v (union across same-named backend methods)", doc.Tools[0].Scopes, want)
	}
}

// realModulesDir is the repository's module root relative to this package.
const realModulesDir = "../../internal/modules"

// TestGenerateIdempotentSmoke runs discovery and rendering against the real
// module tree twice and requires byte-identical output, guarding the
// determinism the docs freshness gate depends on. It also smoke-checks that a
// representative module is discovered with the expected scopes.
func TestGenerateIdempotentSmoke(t *testing.T) {
	if _, err := os.Stat(realModulesDir); err != nil {
		t.Skipf("module tree not found at %s: %v", realModulesDir, err)
	}

	render := func() map[string]string {
		modules, err := discover(realModulesDir)
		if err != nil {
			t.Fatalf("discover: %v", err)
		}
		if err := validateHostedMCPNotes(modules); err != nil {
			t.Fatalf("validateHostedMCPNotes: %v", err)
		}
		pages := map[string]string{"overview.md": renderOverview(modules)}
		for _, m := range modules {
			pages[m.Slug+".md"] = renderModule(m)
		}
		return pages
	}

	first, second := render(), render()
	if !reflect.DeepEqual(first, second) {
		t.Fatal("generation is not idempotent: two runs produced different output")
	}

	det, ok := first["detections.md"]
	if !ok {
		t.Fatal("detections.md not generated")
	}
	for _, want := range []string{"### `falcon_search_detections`", "- `Alerts:read`", "- `Alerts:write`"} {
		if !strings.Contains(det, want) {
			t.Errorf("detections.md missing %q", want)
		}
	}
}
