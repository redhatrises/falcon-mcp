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

package e2e

import (
	"context"
	"os"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/crowdstrike/falcon-mcp/internal/config"
)

// The mssp specs verify Flight Control (MSSP) routing: a member CID set on the
// client scopes calls to a child tenant. Unlike the Python client, which takes a
// per-call member_cid, the Go client bakes MemberCID into the gofalcon client at
// build time, so this spec builds its own member-scoped server (rather than
// reusing the shared suite server) and runs a read through it.
//
// It requires FALCON_MEMBER_CID (a valid child CID) in addition to the suite
// credentials and skips cleanly when it is unset. Label("mssp") selects just
// this spec; Label("integration") marks the live tier.
var _ = Describe("mssp routing", Label("integration", "mssp"), func() {
	var ctx context.Context

	BeforeEach(func() {
		ctx = newSpecContext()
		if os.Getenv("FALCON_MEMBER_CID") == "" {
			Skip("MSSP routing spec requires FALCON_MEMBER_CID (a child CID)")
		}
	})

	It("routes reads to the child CID when member_cid is set", func() {
		clientID, clientSecret, ok := credCheck()
		Expect(ok).To(BeTrue(), "suite credentials should be present")

		cfg, err := config.Load(config.Config{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			Cloud:        os.Getenv("FALCON_CLOUD"),
			MemberCID:    os.Getenv("FALCON_MEMBER_CID"),
			HostOverride: os.Getenv("FALCON_BASE_URL"),
		})
		Expect(err).NotTo(HaveOccurred(), "config.Load should accept the member CID")

		memberSrv, err := buildServer(cfg)
		Expect(err).NotTo(HaveOccurred(), "building the member-scoped server (auth against child CID)")
		DeferCleanup(func() { _ = memberSrv.Close() })

		// Open a session against the member server and run a broadly available
		// read. Success proves the OAuth exchange plus MemberCID routing reached
		// the child tenant; an empty child tenant is a valid outcome and skips.
		cs := newSessionFor(ctx, memberSrv)
		res := callTool(ctx, cs, "falcon_search_hosts", map[string]any{"limit": 3})
		expectNoToolError(res)
		skipIfEmpty(res, "child CID tenant has no hosts to validate routing against")
		expectSearchReturnsDetails(res, "device_id")
	})
})
