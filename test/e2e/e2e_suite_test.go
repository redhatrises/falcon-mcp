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

// Package e2e contains live end-to-end tests that drive the real falcon-mcp
// server over an in-memory MCP transport against a real CrowdStrike Falcon
// tenant. The suite authenticates once (SynchronizedBeforeSuite) and skips
// entirely when FALCON_CLIENT_ID/FALCON_CLIENT_SECRET are absent, so it is safe
// to run without credentials. Credentials come from the environment, or from the
// repository .env when the environment does not carry them. It is excluded from
// the default `make test` by directory and invoked via `make test-e2e`.
package e2e

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/spf13/viper"

	"github.com/crowdstrike/falcon-mcp/internal/config"
	falconapi "github.com/crowdstrike/falcon-mcp/internal/falcon"
	"github.com/crowdstrike/falcon-mcp/internal/mcpserver"
)

// Suite-level state shared by every spec. It is populated once by
// SynchronizedBeforeSuite and read (never mutated) by the specs, so no
// synchronization is required.
var (
	// srv is the assembled falcon-mcp server backed by a live gofalcon client.
	// Specs open their own in-memory client session over it via newSession.
	srv *mcpserver.Server
)

// credCheck reports whether the required Falcon credentials are present in the
// environment. It is the runtime gate that lets the suite skip cleanly on a
// machine without credentials, mirroring the Python integration fixture.
func credCheck() (clientID, clientSecret string, ok bool) {
	clientID = os.Getenv("FALCON_CLIENT_ID")
	clientSecret = os.Getenv("FALCON_CLIENT_SECRET")
	return clientID, clientSecret, clientID != "" && clientSecret != ""
}

// findDotEnv returns the path to the nearest .env at or above the working
// directory. `go test` sets the working directory to the package directory, so
// the repository-root .env is only reachable by walking up.
func findDotEnv() (string, bool) {
	dir, err := os.Getwd()
	if err != nil {
		return "", false
	}
	for {
		path := filepath.Join(dir, ".env")
		if info, err := os.Stat(path); err == nil && !info.IsDir() {
			return path, true
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", false
		}
		dir = parent
	}
}

// loadDotEnv copies the repository .env into the process environment so a plain
// `go test` authenticates with the same credentials the server binary reads.
// Parsing goes through viper's "env" format, the same decoder the cli package
// uses, so a file that works for the binary works here. An existing environment
// variable is never overwritten, matching the cli's non-overriding merge, and a
// missing file is not an error: the suite then skips on the credential gate.
// Values are never logged.
func loadDotEnv() error {
	path, ok := findDotEnv()
	if !ok {
		return nil
	}
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()

	v := viper.New()
	v.SetConfigType("env")
	if err := v.ReadConfig(f); err != nil {
		return fmt.Errorf("parse %s: %w", path, err)
	}
	// viper lower-cases its keys; environment variables are upper-case.
	for _, key := range v.AllKeys() {
		name := strings.ToUpper(key)
		if _, set := os.LookupEnv(name); set {
			continue
		}
		if err := os.Setenv(name, v.GetString(key)); err != nil {
			return fmt.Errorf("set %s: %w", name, err)
		}
	}
	return nil
}

// TestE2E is the single stdlib entry point that hands off to Ginkgo. `go test`
// discovers it; Ginkgo runs the registered specs.
func TestE2E(t *testing.T) {
	RegisterFailHandler(Fail)
	// Every Ginkgo parallel process runs this entry point, so loading here gives
	// each one the credentials before its suite hooks check for them.
	if err := loadDotEnv(); err != nil {
		t.Fatalf("load .env: %v", err)
	}
	// Live API calls are slow and occasionally eventually-consistent; give
	// Eventually assertions room without masking real hangs.
	SetDefaultEventuallyTimeout(30 * time.Second)
	SetDefaultEventuallyPollingInterval(time.Second)
	RunSpecs(t, "falcon-mcp e2e suite")
}

// SynchronizedBeforeSuite builds the live client and server exactly once for the
// whole run. Under Ginkgo's parallel-process model the first function runs on a
// single process; here it performs the shared setup and the per-process function
// wires the result into each process's suite state. Authentication (the OAuth
// token exchange in falconapi.New) therefore happens once per process, not once
// per spec.
var _ = SynchronizedBeforeSuite(func() []byte {
	// Runs once, on process #1. Verify credentials are usable so the whole suite
	// skips (rather than every spec failing) when they are absent.
	if _, _, ok := credCheck(); !ok {
		Skip("live e2e tests require FALCON_CLIENT_ID and FALCON_CLIENT_SECRET")
	}
	return nil
}, func(_ []byte) {
	// Runs on every process. Build the server from validated config and a live
	// client. Skip here too so parallel worker processes skip consistently.
	clientID, clientSecret, ok := credCheck()
	if !ok {
		Skip("live e2e tests require FALCON_CLIENT_ID and FALCON_CLIENT_SECRET")
	}

	cfg, err := config.Load(config.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Cloud:        os.Getenv("FALCON_CLOUD"),
		MemberCID:    os.Getenv("FALCON_MEMBER_CID"),
		HostOverride: os.Getenv("FALCON_BASE_URL"),
	})
	Expect(err).NotTo(HaveOccurred(), "config.Load should accept the live credentials")

	server, err := buildServer(cfg)
	Expect(err).NotTo(HaveOccurred())
	srv = server
})

// buildServer constructs the live gofalcon client and the falcon-mcp server from
// cfg. It is separated from the suite hook so the hook stays declarative.
func buildServer(cfg *config.Config) (*mcpserver.Server, error) {
	api, err := falconapi.New(context.Background(), cfg)
	if err != nil {
		return nil, err
	}
	return mcpserver.New(cfg, api)
}

var _ = AfterSuite(func() {
	if srv != nil {
		Expect(srv.Close()).To(Succeed())
	}
})
