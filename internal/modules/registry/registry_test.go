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

package registry

import (
	"log/slog"
	"testing"

	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/crowdstrike/falcon-mcp/internal/modules/base"
)

// fakeModule is a name-only base.Module for exercising Build without a live API.
type fakeModule struct {
	name string
	deps Deps
}

func (m fakeModule) Name() string                  { return m.name }
func (m fakeModule) Description() string           { return "fake " + m.name }
func (m fakeModule) RegisterTools(base.Registrar)  {}
func (m fakeModule) RegisterResources(*mcp.Server) {}
func (m fakeModule) RegisterPrompts(*mcp.Server)   {}

func TestBuildPreservesOrder(t *testing.T) {
	factories := []Factory{
		func(Deps) base.Module { return fakeModule{name: "hosts"} },
		func(Deps) base.Module { return fakeModule{name: "detections"} },
		func(Deps) base.Module { return fakeModule{name: "host_groups"} },
	}

	got := Build(Deps{}, factories)
	want := []string{"hosts", "detections", "host_groups"}
	if len(got) != len(want) {
		t.Fatalf("Build returned %d modules, want %d", len(got), len(want))
	}
	for i, m := range got {
		if m.Name() != want[i] {
			t.Errorf("module %d = %q, want %q", i, m.Name(), want[i])
		}
	}
}

func TestBuildPropagatesDeps(t *testing.T) {
	var captured Deps
	factories := []Factory{
		func(d Deps) base.Module {
			captured = d
			return fakeModule{name: "capture", deps: d}
		},
	}

	logger := slog.Default()
	api := &client.CrowdStrikeAPISpecification{}
	Build(Deps{API: api, Concurrency: 7, Logger: logger}, factories)

	if captured.API != api {
		t.Error("API not propagated to factory")
	}
	if captured.Concurrency != 7 {
		t.Errorf("Concurrency = %d, want 7", captured.Concurrency)
	}
	if captured.Logger != logger {
		t.Error("Logger not propagated to factory")
	}
}

func TestBuildEmpty(t *testing.T) {
	if got := Build(Deps{}, nil); len(got) != 0 {
		t.Errorf("Build with no factories returned %d modules, want 0", len(got))
	}
}
