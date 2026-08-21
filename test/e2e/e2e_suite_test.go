// Package e2e contains live end-to-end tests that drive the real falcon-mcp
// server over an in-memory MCP transport against a real CrowdStrike Falcon
// tenant. The suite authenticates once (SynchronizedBeforeSuite) and skips
// entirely when FALCON_CLIENT_ID/FALCON_CLIENT_SECRET are absent, so it is safe
// to run without credentials. It is excluded from the default `make test` by
// directory and invoked via `make test-e2e`.
package e2e

import (
	"context"
	"os"
	"testing"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

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

// TestE2E is the single stdlib entry point that hands off to Ginkgo. `go test`
// discovers it; Ginkgo runs the registered specs.
func TestE2E(t *testing.T) {
	RegisterFailHandler(Fail)
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
	api, err := falconapi.New(context.Background(), cfg, nil)
	if err != nil {
		return nil, err
	}
	return mcpserver.New(mcpserver.Options{Config: cfg, API: api})
}

var _ = AfterSuite(func() {
	if srv != nil {
		Expect(srv.Close()).To(Succeed())
	}
})
