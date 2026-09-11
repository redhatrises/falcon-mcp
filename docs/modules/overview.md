<!-- meta:title Module Overview -->
<!-- meta:description Overview of all available Falcon MCP modules with API scopes. -->
<!-- meta:section modules -->
<!-- meta:link-base /falcon-mcp/ -->
<!-- frontmatter:sidebar order:0 -->

The Falcon MCP Server provides the following modules. Each module requires specific CrowdStrike API scopes.

| Module | API Scopes | Description |
|--------|-------------------|-------------|
| [AgentWorks](/falcon-mcp/modules/agentworks/) | `Charlotte AI Agent Definition:read`, `Charlotte AI Agent Definition:write` | Search AgentWorks (Charlotte AI) agents, versions, and spans, and invoke agents |
| [Case Management](/falcon-mcp/modules/cases/) | `Case Templates:read`, `Cases:read`, `Cases:write` | Search, retrieve, create, update, and manage CrowdStrike Falcon cases, evidence, tags, and templates |
| [Cloud Security](/falcon-mcp/modules/cloud/) | `Cloud Groups V2:read`, `Cloud Security API Assets:read`, `Cloud Security API Detections:read`, `Cloud Security API Risks:read`, `Cloud Security Policies:read`, `Falcon Container Image:read`, `Cloud Security Policies:write` | Search Falcon cloud resources: Kubernetes containers, image vulnerabilities, CSPM assets, IOM findings, cloud risks, cloud groups, suppression rules, and cloud insights |
| [Correlation Rules](/falcon-mcp/modules/correlationrules/) | `Correlation Rules:read`, `Correlation Rules:write` | Search, create, update, and delete NG-SIEM correlation rules |
| [Custom IOA](/falcon-mcp/modules/custom-ioa/) | `Custom IOA Rules:read`, `Custom IOA Rules:write` | Search, create, update, and delete Custom IOA (Indicators of Attack) behavioral detection rules and rule groups |
| [Data Protection](/falcon-mcp/modules/data-protection/) | `Data Protection:read` | Read-only access to Falcon Data Protection configuration — classifications, policies, and content patterns — so you can reason about why a Data Protection detection fired |
| [Detections](/falcon-mcp/modules/detections/) | `Alerts:read`, `Alerts:write` | Search, retrieve, and triage Falcon detections/alerts (EPP, IDP, XDR, OverWatch, NG-SIEM) |
| [Discover](/falcon-mcp/modules/discover/) | `Assets:read` | Search Falcon Discover applications, managed assets, and unmanaged assets |
| [Exclusions](/falcon-mcp/modules/exclusions/) | `IOA Exclusions:read`, `Machine Learning Exclusions:read`, `Sensor Visibility Exclusions:read`, `IOA Exclusions:write`, `Machine Learning Exclusions:write`, `Sensor Visibility Exclusions:write` | Search, create, update, and delete Falcon exclusions across four types — IOA, machine learning, sensor visibility, and certificate-based — behind a single exclusion_type discriminator |
| [Firewall Management](/falcon-mcp/modules/firewall/) | `Firewall Management:read`, `Firewall Management:write` | Search and manage Falcon firewall rules and rule groups |
| [Fusion SOAR](/falcon-mcp/modules/fusion/) | `Workflows:read`, `Workflows:write` | Search and run Fusion SOAR workflows and read their execution results |
| [Guardian](/falcon-mcp/modules/guardian/) | `AIDR:read` | Query AI agent activity and inventory via the Guardian (AIDR) API: agents, sessions, tools, skills, executions, prompts, detections, and fleet rollups |
| [Host Groups](/falcon-mcp/modules/host-groups/) | `Host Groups:read`, `Host Groups:write` | Search, create, update, and delete Falcon host groups and manage their membership |
| [Hosts](/falcon-mcp/modules/hosts/) | `Hosts:read`, `Hosts:write` | Search Falcon hosts/devices and retrieve their full details |
| [Identity Protection](/falcon-mcp/modules/idp/) | `Identity Protection Assessment:read`, `Identity Protection Detections:read`, `Identity Protection Entities:read`, `Identity Protection Timeline:read`, `Identity Protection GraphQL:write` | Investigate CrowdStrike Falcon Identity Protection entities |
| [Intel](/falcon-mcp/modules/intel/) | `Actors (Falcon Intelligence):read`, `Indicators (Falcon Intelligence):read`, `Reports (Falcon Intelligence):read` | Search Falcon threat intelligence: adversaries, indicators, reports, and MITRE ATT&CK profiles |
| [IOC](/falcon-mcp/modules/ioc/) | `IOC Management:read`, `IOC Management:write` | Search, create, and delete custom Falcon IOCs (indicators of compromise) |
| [NGSIEM](/falcon-mcp/modules/ngsiem/) | `NGSIEM:read`, `NGSIEM:write` | Run search queries against CrowdStrike Next-Gen SIEM via its asynchronous job-based search API |
| [Policies](/falcon-mcp/modules/policies/) | `Content Update Policies:read`, `Device Control Policies:read`, `Firewall Management:read`, `Prevention Policies:read`, `Response Policies:read`, `Sensor Update Policies:read`, `Content Update Policies:write`, `Device Control Policies:write`, `Firewall Management:write`, `Prevention Policies:write`, `Response Policies:write`, `Sensor Update Policies:write` | Search and manage Falcon host-based policies across all six types — prevention, sensor update, firewall, device control, response, and content update — behind a single policy_type discriminator |
| [Quarantine](/falcon-mcp/modules/quarantine/) | `Quarantined Files:read`, `Quarantined Files:write` | Search quarantine records, preview action counts, and release, unrelease, or delete quarantined files |
| [Recon](/falcon-mcp/modules/recon/) | `Monitoring rules (Falcon Intelligence Recon):read` | Search Falcon Intelligence Recon notifications, monitoring rules, and exposed-data records |
| [Real Time Response](/falcon-mcp/modules/rtr/) | `Real time response:read`, `real-time-response-audit:read`, `Real time response:write` | Initiate and inspect Real Time Response sessions, run read-only RTR commands during host investigations, and audit and summarize RTR activity |
| [Scheduled Reports](/falcon-mcp/modules/scheduled-reports/) | `Scheduled Reports:read` | Access and manage CrowdStrike Falcon scheduled reports and scheduled searches |
| [Sensor Usage](/falcon-mcp/modules/sensor-usage/) | `Sensor Usage:read` | Access CrowdStrike Falcon sensor usage data |
| [Serverless](/falcon-mcp/modules/serverless/) | `Falcon Container Image:read` | Search CrowdStrike Falcon serverless (Lambda/Cloud Functions/Azure Functions) vulnerabilities |
| [Shield](/falcon-mcp/modules/shield/) | `SaaS Security:read`, `SaaS Security:write` | Query Falcon Shield (SaaS Security) posture, alerts, inventory, and activity |
| [Spotlight](/falcon-mcp/modules/spotlight/) | `Vulnerabilities:read` | Search CrowdStrike Falcon Spotlight vulnerabilities |
| [Zero Trust Assessment](/falcon-mcp/modules/zero-trust-assessment/) | `Zero Trust Assessment:read` | Retrieve Zero Trust Assessment posture scores and hardening signals for hosts |

## CrowdStrike-hosted MCP differences

> [!NOTE]
> This section compares this self-hosted server against CrowdStrike's hosted Falcon MCP. Skip it unless you also use the hosted MCP, or are moving between the two.

The two servers differ in how a client reaches a tool. The hosted Falcon MCP works through discovery: a client calls `search_tools` to find a Falcon tool by name or keyword, then `execute_tool` to run it with arguments. The self-hosted falcon-mcp server registers each `falcon_*` tool up front instead, so a client calls one by name with no discovery round-trip.

If you self-host and want the same discovery pattern, enable [dynamic mode](/falcon-mcp/usage/dynamic-mode/): it swaps the full tool surface for `falcon_search_tools`, `falcon_execute_tool`, and an always-on `falcon_list_enabled_tools` inventory. Mind the `falcon_` prefix — those three are the self-hosted falcon-mcp server's tools, not the hosted MCP's.

Module and tool coverage also differs:

- [Fusion SOAR](/falcon-mcp/modules/fusion/), [Zero Trust Assessment](/falcon-mcp/modules/zero-trust-assessment/), and [Real Time Response](/falcon-mcp/modules/rtr/) are available only on this self-hosted server; the hosted MCP has no equivalent modules.
- [Cloud Security](/falcon-mcp/modules/cloud/): `falcon_search_cloud_insights`, `falcon_list_cloud_insight_definitions`, and `falcon_get_cloud_asset_insights` are not available on the hosted MCP.
- [Discover](/falcon-mcp/modules/discover/): `falcon_search_managed_assets` is not available on the hosted MCP.
- [Policies](/falcon-mcp/modules/policies/): the hosted MCP does not use the unified `policy_type`-discriminated tools. It instead exposes six policy-type-specific variants of each tool (for example `falcon_search_policies_firewall`, `falcon_create_policy_prevention`).
