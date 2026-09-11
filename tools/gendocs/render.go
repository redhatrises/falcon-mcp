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
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// docstringNoise are the leading-line patterns stripped from a tool description
// before rendering. They target boilerplate the descriptions do not need in the
// docs (resource-guide pointers and mandatory-usage preambles).
var docstringNoise = []*regexp.Regexp{
	regexp.MustCompile(`(?i)^\s*IMPORTANT:\s*You must use the\b`),
	regexp.MustCompile(`(?i)^\s*IMPORTANT:\s*use the\b`),
	regexp.MustCompile(`(?i)^\s*This resource contains the guide\b`),
	regexp.MustCompile(`(?i)^\s*Returns FQL syntax guide on error\b`),
	regexp.MustCompile(`(?i)^\s*when you need to use the\b`),
}

// cleanDocstring strips noise lines from a tool description and collapses runs of
// blank lines, then trims surrounding whitespace.
func cleanDocstring(doc string) string {
	var kept []string
	for _, line := range strings.Split(doc, "\n") {
		noise := false
		for _, p := range docstringNoise {
			if p.MatchString(line) {
				noise = true
				break
			}
		}
		if !noise {
			kept = append(kept, line)
		}
	}

	var out []string
	prevBlank := false
	for _, line := range kept {
		blank := strings.TrimSpace(line) == ""
		if blank && prevBlank {
			continue
		}
		out = append(out, line)
		prevBlank = blank
	}
	return strings.TrimSpace(strings.Join(out, "\n"))
}

// renderModule renders a module's complete markdown page.
func renderModule(m moduleDoc) string {
	var lines []string
	add := func(s ...string) { lines = append(lines, s...) }

	add(
		fmt.Sprintf("<!-- meta:title %s -->", m.Title),
		fmt.Sprintf("<!-- meta:description %s -->", m.Description),
		"<!-- meta:section modules -->",
		"<!-- meta:link-base /falcon-mcp/ -->",
		"<!-- frontmatter:sidebar order:10 -->",
		"",
		m.Description,
		"",
	)

	if note, ok := hostedMCPModuleNotes[m.Key]; ok {
		add("> [!NOTE]", "> "+note, "")
	}

	if len(m.Scopes) > 0 {
		add("## API Scopes", "")
		for _, s := range m.Scopes {
			add("- `" + s + "`")
		}
		add("")
	}

	if len(m.Tools) > 0 {
		add("## Tools", "")
		for _, t := range m.Tools {
			add("### `"+t.Name+"`", "")

			if note, ok := hostedMCPToolNotes[t.Name]; ok {
				add("> [!NOTE]", "> "+note, "")
			}

			switch t.Annotation {
			case annotationDestructive:
				add("> [!CAUTION]", "> This tool performs destructive operations.", "")
			case annotationMutating:
				add("> [!NOTE]", "> This tool modifies data.", "")
			}

			if len(t.Scopes) > 0 {
				quoted := make([]string, len(t.Scopes))
				for i, s := range t.Scopes {
					quoted[i] = "`" + s + "`"
				}
				add("**Required scopes:** "+strings.Join(quoted, ", "), "")
			}

			if cleaned := cleanDocstring(t.Description); cleaned != "" {
				add(cleaned, "")
			}

			if len(t.Examples) > 0 {
				add("**Example prompts:**", "")
				for _, ex := range t.Examples {
					add(`- "` + ex + `"`)
				}
				add("")
			}
		}
	}

	if len(m.Resources) > 0 {
		add("## Resources", "")
		for _, r := range m.Resources {
			add(fmt.Sprintf("- **`%s`**: %s", r.URI, r.Description))
		}
		add("")
	}

	return strings.Join(lines, "\n")
}

// renderOverview renders the overview page: a summary table over all modules
// followed by the hosted-MCP differences section.
func renderOverview(modules []moduleDoc) string {
	sorted := make([]moduleDoc, len(modules))
	copy(sorted, modules)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Key < sorted[j].Key })

	var lines []string
	add := func(s ...string) { lines = append(lines, s...) }

	add(
		"<!-- meta:title Module Overview -->",
		"<!-- meta:description Overview of all available Falcon MCP modules with API scopes. -->",
		"<!-- meta:section modules -->",
		"<!-- meta:link-base /falcon-mcp/ -->",
		"<!-- frontmatter:sidebar order:0 -->",
		"",
		"The Falcon MCP Server provides the following modules. Each module requires specific CrowdStrike API scopes.",
		"",
		"| Module | API Scopes | Description |",
		"|--------|-------------------|-------------|",
	)

	for _, m := range sorted {
		quoted := make([]string, len(m.Scopes))
		for i, s := range m.Scopes {
			quoted[i] = "`" + s + "`"
		}
		add(fmt.Sprintf("| [%s](%s/modules/%s/) | %s | %s |", m.Title, siteBasePath, m.Slug, strings.Join(quoted, ", "), m.Description))
	}

	add("")
	add(overviewDifferences()...)

	return strings.Join(lines, "\n")
}
