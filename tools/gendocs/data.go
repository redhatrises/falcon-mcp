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
	"unicode"
)

// meta holds the display title and URL slug for a module. Titles and slugs are
// curated overrides; the retired Python generator derived them from module
// docstrings, which the Go modules do not carry.
type meta struct {
	title string
	slug  string
}

// moduleMetadata maps a module key (its Name()) to its display title and slug.
// A module absent from this map falls back to a title-cased key and the key
// itself as the slug (see moduleMeta).
var moduleMetadata = map[string]meta{
	"agentworks":          {title: "AgentWorks", slug: "agentworks"},
	"cases":               {title: "Case Management", slug: "cases"},
	"cloud":               {title: "Cloud Security", slug: "cloud"},
	"correlationrules":    {title: "Correlation Rules", slug: "correlationrules"},
	"customioa":           {title: "Custom IOA", slug: "custom-ioa"},
	"dataprotection":      {title: "Data Protection", slug: "data-protection"},
	"detections":          {title: "Detections", slug: "detections"},
	"discover":            {title: "Discover", slug: "discover"},
	"exclusions":          {title: "Exclusions", slug: "exclusions"},
	"firewall":            {title: "Firewall Management", slug: "firewall"},
	"fusion":              {title: "Fusion SOAR", slug: "fusion"},
	"hostgroups":          {title: "Host Groups", slug: "host-groups"},
	"hosts":               {title: "Hosts", slug: "hosts"},
	"idp":                 {title: "Identity Protection", slug: "idp"},
	"intel":               {title: "Intel", slug: "intel"},
	"ioc":                 {title: "IOC", slug: "ioc"},
	"ngsiem":              {title: "NGSIEM", slug: "ngsiem"},
	"policies":            {title: "Policies", slug: "policies"},
	"quarantine":          {title: "Quarantine", slug: "quarantine"},
	"recon":               {title: "Recon", slug: "recon"},
	"rtr":                 {title: "Real Time Response", slug: "rtr"},
	"scheduledreports":    {title: "Scheduled Reports", slug: "scheduled-reports"},
	"sensorusage":         {title: "Sensor Usage", slug: "sensor-usage"},
	"serverless":          {title: "Serverless", slug: "serverless"},
	"shield":              {title: "Shield", slug: "shield"},
	"spotlight":           {title: "Spotlight", slug: "spotlight"},
	"zerotrustassessment": {title: "Zero Trust Assessment", slug: "zero-trust-assessment"},
}

// moduleMeta returns the display title and slug for a module key, falling back
// to a title-cased key and the key as the slug when the key has no override.
func moduleMeta(key string) meta {
	if m, ok := moduleMetadata[key]; ok {
		return m
	}
	return meta{title: titleCase(key), slug: key}
}

// titleCase upper-cases the first rune of s, leaving the rest unchanged. It is
// the generic title fallback for a module with no metadata override.
func titleCase(s string) string {
	if s == "" {
		return s
	}
	r := []rune(s)
	r[0] = unicode.ToUpper(r[0])
	return string(r)
}

// moduleLink is the site URL for a module page, honoring its slug override.
func moduleLink(key string) string {
	return siteBasePath + "/modules/" + moduleMeta(key).slug + "/"
}

// overviewLink points at the hosted-MCP differences section of the overview
// page; the hosted-MCP notes link back to it.
var overviewLink = siteBasePath + "/modules/overview/#crowdstrike-hosted-mcp-differences"

// hostedMCPModuleNotes are notes on differences from CrowdStrike's hosted Falcon
// MCP, rendered as an admonition under the module description. Keyed by module
// key.
var hostedMCPModuleNotes = map[string]string{
	"fusion": "This module is not available on CrowdStrike's hosted Falcon MCP; it is only " +
		"available when self-hosting this server. See [module overview](" + overviewLink + ").",
	"zerotrustassessment": "This module is not available on CrowdStrike's hosted Falcon MCP; it is only " +
		"available when self-hosting this server. See [module overview](" + overviewLink + ").",
	"rtr": "This module is not available on CrowdStrike's hosted Falcon MCP; it is only " +
		"available when self-hosting this server. See [module overview](" + overviewLink + ").",
	"policies": "CrowdStrike's hosted Falcon MCP does not use these unified, `policy_type`-discriminated " +
		"tools. It instead exposes six policy-type-specific variants of each tool below, suffixed " +
		"by type (`_prevention`, `_sensor_update`, `_firewall`, `_device_control`, `_response`, " +
		"`_content_update`) with no `policy_type` parameter — for example `falcon_search_policies` " +
		"here corresponds to `falcon_search_policies_firewall`, `falcon_search_policies_prevention`, " +
		"etc. on the hosted MCP. See [module overview](" + overviewLink + ").",
}

// hostedMCPToolNotes are notes on tools not (yet) available on CrowdStrike's
// hosted Falcon MCP, rendered as an admonition under the tool heading. Keyed by
// full tool name (falcon_*).
var hostedMCPToolNotes = map[string]string{
	"falcon_search_cloud_insights":          "Not available on CrowdStrike's hosted Falcon MCP. See [module overview](" + overviewLink + ").",
	"falcon_get_cloud_asset_insights":       "Not available on CrowdStrike's hosted Falcon MCP. See [module overview](" + overviewLink + ").",
	"falcon_list_cloud_insight_definitions": "Not available on CrowdStrike's hosted Falcon MCP. See [module overview](" + overviewLink + ").",
	"falcon_search_managed_assets":          "Not available on CrowdStrike's hosted Falcon MCP. See [module overview](" + overviewLink + ").",
}

// overviewDifferences returns the lines of the "CrowdStrike-hosted MCP
// differences" section of the overview page. It is hand-written prose (with
// module links resolved) rather than derived from the modules; each returned
// element is one rendered line.
func overviewDifferences() []string {
	return []string{
		"## CrowdStrike-hosted MCP differences",
		"",
		"> [!NOTE]",
		"> This section compares this self-hosted server against CrowdStrike's hosted " +
			"Falcon MCP. Skip it unless you also use the hosted MCP, or are moving between the two.",
		"",
		"The two servers differ in how a client reaches a tool. The hosted Falcon MCP works " +
			"through discovery: a client calls `search_tools` to find a Falcon tool by name or " +
			"keyword, then `execute_tool` to run it with arguments. The self-hosted falcon-mcp " +
			"server registers each `falcon_*` tool up front instead, so a client calls one by name " +
			"with no discovery round-trip.",
		"",
		"If you self-host and want the same discovery pattern, enable " +
			"[dynamic mode](" + siteBasePath + "/usage/dynamic-mode/): it swaps the full tool surface " +
			"for `falcon_search_tools`, `falcon_execute_tool`, and an always-on " +
			"`falcon_list_enabled_tools` inventory. Mind the `falcon_` prefix — those three are " +
			"the self-hosted falcon-mcp server's tools, not the hosted MCP's.",
		"",
		"Module and tool coverage also differs:",
		"",
		"- [Fusion SOAR](" + moduleLink("fusion") + "), " +
			"[Zero Trust Assessment](" + moduleLink("zerotrustassessment") + "), and " +
			"[Real Time Response](" + moduleLink("rtr") + ") are available only on this self-hosted " +
			"server; the hosted MCP has no equivalent modules.",
		"- [Cloud Security](" + moduleLink("cloud") + "): `falcon_search_cloud_insights`, " +
			"`falcon_list_cloud_insight_definitions`, and `falcon_get_cloud_asset_insights` are not " +
			"available on the hosted MCP.",
		"- [Discover](" + moduleLink("discover") + "): `falcon_search_managed_assets` is " +
			"not available on the hosted MCP.",
		"- [Policies](" + moduleLink("policies") + "): the hosted MCP does not use the " +
			"unified `policy_type`-discriminated tools. It instead exposes six policy-type-specific " +
			"variants of each tool (for example `falcon_search_policies_firewall`, " +
			"`falcon_create_policy_prevention`).",
		"",
	}
}
