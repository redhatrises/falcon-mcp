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

// Command genfqlguide normalizes an FQL guide Markdown file in place: it trims
// trailing whitespace from every line and the surrounding blank lines of the
// file, leaving a single trailing newline. It is invoked from //go:generate
// directives so the file that //go:embed embeds carries no incidental
// whitespace. The operation is idempotent — running it on an already-normalized
// file leaves it byte-for-byte unchanged.
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
)

func main() {
	log.SetFlags(0)

	in := flag.String("in", "", "path to the Markdown guide to normalize in place")
	flag.Parse()

	if *in == "" {
		log.Fatal("genfqlguide: -in is required")
	}

	if err := normalize(*in); err != nil {
		log.Fatalf("genfqlguide: %v", err)
	}
}

func normalize(path string) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}

	// A single trailing newline keeps the file POSIX-clean and editor-friendly.
	guide := normalizeGuide(string(raw)) + "\n"

	// 0o644: this is a committed, world-readable source doc, not sensitive data.
	if err := os.WriteFile(path, []byte(guide), 0o644); err != nil { //nolint:gosec // G306: generated source doc is intentionally world-readable
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

func normalizeGuide(raw string) string {
	lines := strings.Split(raw, "\n")
	for i, line := range lines {
		lines[i] = strings.TrimSpace(line)
	}
	return strings.TrimSpace(strings.Join(lines, "\n"))
}
