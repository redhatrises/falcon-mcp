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

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// The guardian specs exercise the Guardian (AIDR) tools against the live tenant.
// They are read-only, use small limits, and tolerate a tenant with no AI-agent
// activity. Label("guardian") allows selecting just this module. A tenant
// without the AIDR:read scope, or without Guardian enabled, will surface a tool
// error; these specs skip rather than fail in that case so a differently
// provisioned tenant stays green.
var _ = Describe("guardian module", Label("integration", "guardian"), func() {
	var ctx context.Context

	BeforeEach(func() {
		ctx = newSpecContext()
	})

	itAdvertisesTools(
		"falcon_search_guardian_agents",
		"falcon_get_guardian_agent",
		"falcon_get_guardian_inventory",
		"falcon_search_guardian_detections",
		"falcon_get_guardian_detection_scores",
		"falcon_generate_guardian_report",
	)

	It("searches AI agents and returns full records", func() {
		res := callOK(ctx, "falcon_search_guardian_agents", map[string]any{"limit": 3})
		skipIfToolError(res, "search_guardian_agents")
		skipIfEmpty(res, "tenant has no AI agents")
		// Id is the opaque record token every agent carries.
		expectSearchReturnsDetails(res, "Id")
	})

	It("lists AI model names fleet-wide", func() {
		res := callOK(ctx, "falcon_search_guardian_models", map[string]any{"limit": 3})
		skipIfToolError(res, "search_guardian_models")
		skipIfEmpty(res, "tenant has no AI model activity")
	})

	It("lists MCP server names fleet-wide", func() {
		res := callOK(ctx, "falcon_search_guardian_mcp_servers", map[string]any{"limit": 3})
		skipIfToolError(res, "search_guardian_mcp_servers")
		skipIfEmpty(res, "tenant has no MCP server activity")
	})

	It("returns a fleet inventory snapshot", func() {
		res := callOK(ctx, "falcon_get_guardian_inventory", map[string]any{"time_range": "7d"})
		skipIfToolError(res, "get_guardian_inventory")
		s := structured(res)
		Expect(s).To(HaveKey("agents"), "inventory should carry an agents rollup")
		Expect(s).To(HaveKey("detections"), "inventory should carry a detections rollup")
	})

	It("gets the fleet skill usage rollup", func() {
		res := callOK(ctx, "falcon_get_guardian_fleet_skill_inventory", map[string]any{"limit": 5})
		skipIfToolError(res, "get_guardian_fleet_skill_inventory")
		skipIfEmpty(res, "tenant has no AI skill activity")
	})

	It("gets agent details for an id found by search", func() {
		cs := newSession(ctx)
		search := callTool(ctx, cs, "falcon_search_guardian_agents", map[string]any{"limit": 1})
		skipIfToolError(search, "search_guardian_agents")
		id := firstResourceID(search, "Id") // skips when the tenant has no agents

		details := callTool(ctx, cs, "falcon_get_guardian_agent", map[string]any{"agent_id": id})
		skipIfToolError(details, "get_guardian_agent")
		obj := structured(details)
		Expect(obj).To(HaveKeyWithValue("Id", id))
	})
})
