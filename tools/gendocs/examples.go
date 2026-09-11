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

// toolExamples holds curated natural-language prompt examples for each tool,
// keyed by full tool name (falcon_*) and rendered under the tool's heading.
var toolExamples = map[string][]string{
	// AgentWorks
	"falcon_search_agentworks_agents": {
		"List my AgentWorks agents",
		"Which agents run on the claude-4-6-sonnet model?",
	},
	"falcon_search_agentworks_agent_versions": {
		"Show me all versions of agent 467e856f",
		"Find the published versions of this agent",
	},
	"falcon_search_agentworks_spans": {
		"Show the spans for trace abc123",
		"Find errored LLM spans in trace abc123",
	},
	"falcon_get_agentworks_agent_invocation": {
		"Check the status of invocation inv-123",
	},
	"falcon_invoke_agentworks_agent": {
		"Run the IOC review agent with the prompt 'Reply OK'",
		"Invoke agent 467e856f and summarize today's critical detections",
		"Test version v-42 of this agent with the prompt 'Reply OK'",
	},
	// Cases
	"falcon_search_cases": {
		"Show me any open cases with high severity or above",
		"What cases have been created in the last 24 hours?",
	},
	"falcon_get_cases": {
		"Pull up the full details on that case",
	},
	"falcon_create_case": {
		"Create a critical case called 'Suspicious lateral movement from WORKSTATION-42'",
		"Open a high-severity case for the credential theft alerts and attach them as evidence",
		"Create a case with a markdown-formatted description",
	},
	"falcon_update_case": {
		"Set that case to in_progress and assign it to the analyst",
		"Close the case — investigation is complete",
		"Rewrite the case description as markdown",
	},
	"falcon_add_case_alert_evidence": {
		"Attach these detection alerts to the case",
	},
	"falcon_add_case_event_evidence": {
		"Add these NGSIEM event IDs to the case as evidence",
	},
	"falcon_manage_case_tags": {
		"Tag that case with 'ransomware' and 'escalated'",
		"Remove the 'escalated' tag from that case",
	},
	"falcon_list_case_templates": {
		"What case templates are available?",
	},
	"falcon_aggregate_case_slas": {
		"How many case SLA policies do we have?",
		"Break down our case SLAs by who created them",
	},
	"falcon_aggregate_case_templates": {
		"How many case templates has each person created?",
		"Count the case templates added in the last 30 days",
	},
	"falcon_aggregate_case_access_tags": {
		"What access tags are used to restrict case visibility, and how many of each?",
	},
	"falcon_aggregate_case_notification_groups": {
		"How many case notification groups are configured?",
		"Show notification group counts by creator",
	},
	"falcon_aggregate_case_file_details": {
		"What file names show up most often across case attachments?",
		"How many files are attached to these two cases?",
	},
	// Correlation Rules
	"falcon_search_correlation_rules": {
		"Show me all active high-severity correlation rules",
		"Find correlation rules covering lateral movement tactics",
	},
	"falcon_create_correlation_rule": {
		"Create a correlation rule using this CQL query: #event_simpleName=ProcessRollup2 | CommandLine=*-EncodedCommand*",
	},
	"falcon_update_correlation_rule": {
		"Disable the correlation rule — set its status to inactive",
		"Update the rule severity to critical (90)",
	},
	"falcon_delete_correlation_rules": {
		"Delete the test correlation rule we created",
	},
	// Cloud
	"falcon_search_kubernetes_containers": {
		"Find all containers running in AWS clusters",
		"Show me containers in the prod cluster",
	},
	"falcon_count_kubernetes_containers": {
		"How many containers are running in Azure?",
	},
	"falcon_search_images_vulnerabilities": {
		"Find image vulnerabilities with CVSS score above 7",
	},
	"falcon_search_cspm_assets": {
		"Find all AWS EC2 instances in my cloud inventory",
	},
	"falcon_search_iom_findings": {
		"Show me critical open CSPM misconfiguration findings in AWS",
		"Find IOM findings for S3 buckets with public access",
		"What CSPM IOM findings are suppressed as accepted risk?",
	},
	"falcon_search_cspm_suppression_rules": {
		"List all CSPM IOM suppression rules and their reasons",
		"Show me which CSPM findings are being suppressed and why",
	},
	"falcon_create_cspm_suppression_rule": {
		"Create a CSPM suppression rule for the S3 encryption finding in the dev account as accepted risk",
		"Suppress the IAM password policy IOM finding as a false positive, expiring in 30 days",
	},
	"falcon_delete_cspm_suppression_rules": {
		"Delete CSPM suppression rule abc-123",
		"Remove the CSPM IOM suppression rule for the S3 public access finding",
	},
	"falcon_search_cloud_risks": {
		"Show me all open critical cloud risks in AWS",
		"Which account has the most unresolved critical risks?",
		"What new cloud risks appeared in the last 7 days?",
		"Show me risks for the production cloud group",
		"What cloud risks have been suppressed and why?",
	},
	"falcon_search_cloud_groups": {
		"What cloud groups are configured in my environment?",
		"List all cloud groups tagged as production",
	},
	"falcon_get_cloud_groups": {
		"Get the details for cloud group abc-123",
	},
	"falcon_search_cloud_insights": {
		"What is internet-exposed in my cloud accounts?",
		"Which IAM identities have admin and are actually unused?",
		"Which exposed storage might hold sensitive data?",
		"Which access keys are stale or unrotated?",
	},
	"falcon_get_cloud_asset_insights": {
		"Show me all the insight facts and context for cloud asset abc-123",
		"Why is this asset flagged — give me its full insight detail",
	},
	"falcon_list_cloud_insight_definitions": {
		"What cloud security insights are available for Identity?",
		"List all insight definitions across all categories",
		"Which compliance controls map to cloud network insights?",
	},
	// Custom IOA
	"falcon_search_ioa_rule_groups": {
		"Find enabled Windows Custom IOA rule groups",
	},
	"falcon_get_ioa_platforms": {
		"What platforms are available for Custom IOA rule groups?",
	},
	"falcon_get_ioa_rule_types": {
		"What Custom IOA rule types are available?",
	},
	"falcon_create_ioa_rule_group": {
		"Create a Windows IOA rule group named 'Suspicious PowerShell Activity'",
	},
	"falcon_update_ioa_rule_group": {
		"Disable IOA rule group abc123",
	},
	"falcon_delete_ioa_rule_groups": {
		"Delete Custom IOA rule groups abc123 and def456",
	},
	"falcon_create_ioa_rule": {
		"Add a process creation rule to IOA group abc123 that detects cmd.exe spawned from Word",
	},
	"falcon_update_ioa_rule": {
		"Enable IOA rule instance abc in group xyz",
	},
	"falcon_delete_ioa_rules": {
		"Delete rules from IOA group abc123",
	},
	// Data Protection
	"falcon_search_data_protection_classifications": {
		"What Data Protection classifications are configured in my environment?",
		"Show me the classification rules that detect credit card data",
	},
	"falcon_search_data_protection_policies": {
		"List all enabled Windows Data Protection policies",
		"Show me the Mac Data Protection policies and their precedence order",
	},
	"falcon_search_data_protection_content_patterns": {
		"What predefined content patterns are available for Data Protection?",
		"Show me custom Data Protection regex patterns in the Financial category",
	},
	// Detections
	"falcon_search_detections": {
		"Show me new high severity detections from the last 7 days",
		"Find all unassigned critical detections",
	},
	"falcon_get_detection_details": {
		"Get me the details for this detection",
	},
	"falcon_aggregate_detections": {
		"How many detections do we have by severity?",
		"What are the top 10 hosts by alert count this week?",
		"Show me alert volume per day for the last 30 days",
		"How many distinct hosts have critical alerts?",
	},
	"falcon_update_detections": {
		"Mark detection abc123 as in_progress",
		"Assign detection abc123 to analyst@example.com",
		"Close these detections and add a comment: resolved via playbook",
		"Mark detection abc123 as a true positive and close it",
		"Remove all fc/ prefixed tags from this detection",
	},
	// Discover
	"falcon_search_applications": {
		"Find all Chrome installations across my environment",
	},
	"falcon_search_unmanaged_assets": {
		"Show me unmanaged Windows devices on the network",
	},
	"falcon_search_managed_assets": {
		"Which managed Windows hosts are unencrypted?",
		"List critical assets that don't have Credential Guard enabled",
	},
	// Firewall
	"falcon_search_firewall_rules": {
		"Show me all enabled Windows firewall rules",
		"Find firewall rules matching 'outbound'",
	},
	"falcon_search_firewall_rule_groups": {
		"Find all enabled firewall rule groups for Windows",
	},
	"falcon_search_firewall_policy_rules": {
		"Show me all rules in firewall policy abc123",
	},
	"falcon_create_firewall_rule_group": {
		"Create a Windows firewall rule group named 'Prod Outbound'",
	},
	"falcon_delete_firewall_rule_groups": {
		"Delete firewall rule group abc123",
	},
	// Hosts
	"falcon_search_hosts": {
		"Find all Windows hosts in my environment",
		"Show me hosts last seen in the past 24 hours",
	},
	"falcon_get_host_details": {
		"Get the full details for host device abc123",
	},
	// Host Groups
	"falcon_search_host_groups": {
		"Show me all static host groups",
		"Find host groups created in the last 30 days",
	},
	"falcon_search_host_group_members": {
		"List the Windows hosts in host group abc123",
		"Show me the members of the Production Servers group",
	},
	"falcon_create_host_group": {
		"Create a static host group called 'Critical Servers'",
		"Create a dynamic host group for all Windows hosts",
	},
	"falcon_update_host_group": {
		"Rename host group abc123 to 'Decommissioned'",
		"Update the assignment rule for the dynamic Windows group",
	},
	"falcon_delete_host_groups": {
		"Delete host group abc123",
	},
	"falcon_perform_host_group_action": {
		"Add the hosts matching platform_name Windows to group abc123",
		"Remove host device xyz from host group abc123",
	},
	// Identity Protection
	"falcon_idp_investigate_entity": {
		"Investigate user john.doe@company.com and show their risk assessment",
		"Look up entity Administrator in domain CORP.LOCAL",
	},
	// Intel
	"falcon_search_actors": {
		"Find threat actors targeting financial services",
		"Search for BEAR adversary groups",
	},
	"falcon_search_indicators": {
		"Find intelligence IOCs of type domain published this year",
	},
	"falcon_search_reports": {
		"Find intelligence reports published in the last 30 days",
	},
	"falcon_get_mitre_report": {
		"Generate MITRE ATT&CK report for FANCY BEAR",
	},
	// Exclusions
	"falcon_search_exclusions": {
		"Show me my most recent IOA and machine learning exclusions",
		"List sensor visibility exclusions created in the last 7 days",
	},
	"falcon_create_exclusion": {
		"Create an ML exclusion for /tmp/foo.sh applied to all hosts",
		"Add a sensor visibility exclusion for C:\\Temp\\* on the Workstations group",
	},
	"falcon_update_exclusion": {
		"Update IOA exclusion abc123 to also match a new command line regex",
	},
	"falcon_delete_exclusions": {
		"Delete the certificate exclusion with ID abc123",
	},
	"falcon_get_certificate_details": {
		"Look up the signing certificate for SHA256 3dd9a...",
	},
	// IOC
	"falcon_search_iocs": {
		"Find all active domain IOCs",
		"Show me SHA256 hash IOCs with prevent action",
	},
	"falcon_add_ioc": {
		"Block the domain evil.example.com",
		"Add a SHA256 hash IOC with prevent action",
	},
	"falcon_remove_iocs": {
		"Delete IOC with ID abc123",
		"Remove all expired IOCs",
	},
	// NGSIEM
	"falcon_search_ngsiem": {
		"Run this CQL query for the last 24 hours: #event_simpleName=ProcessRollup2",
		"Search NGSIEM for DNS events from January 2025",
	},
	// Policies
	"falcon_search_policies": {
		"List all firewall policies",
		"Show enabled sensor update policies for Windows",
		"Find prevention policies whose name contains 'default'",
	},
	"falcon_search_policy_members": {
		"What hosts are assigned to firewall policy 1a2b3c?",
	},
	"falcon_create_policy": {
		"Create a disabled firewall policy named 'Test FW' for Windows",
	},
	"falcon_update_policy": {
		"Rename prevention policy 1a2b3c to 'Servers - Strict'",
	},
	"falcon_delete_policies": {
		"Delete firewall policy 1a2b3c",
	},
	"falcon_perform_policy_action": {
		"Disable prevention policy 1a2b3c",
		"Add host group 9z8y7x to sensor update policy 1a2b3c",
	},
	"falcon_set_policy_precedence": {
		"Set the precedence order of these Windows prevention policies: 1a2b3c, 4d5e6f, 7g8h9i",
	},
	// Quarantine
	"falcon_search_quarantined_files": {
		"Show me quarantined files on host SE-DAO-WIN10-CO",
		"Find quarantined files for user badguy updated in the last 7 days",
		"Search for quarantined files with SHA256 starting with 3dd9",
	},
	"falcon_preview_quarantine_actions": {
		"Preview how many quarantined files can be released vs deleted",
		"Preview quarantine action impact for state quarantined on host SE-DAO-WIN10-CO",
	},
	"falcon_update_quarantined_files": {
		"Release quarantine record abc123",
		"Release all quarantined files for user badguy",
	},
	"falcon_delete_quarantined_files": {
		"Delete quarantine records for host SE-DAO-WIN10-CO",
		"Delete quarantine record abc123",
	},
	// Recon
	"falcon_search_recon_notifications": {
		"Show me recon alerts from the past 7 days",
		"Show me new recon alerts with high priority",
		"Find recon notifications for domain monitoring rules",
		"Show typosquatting recon alerts",
		"Find leaked credential notifications from stealer logs",
	},
	"falcon_search_recon_rules": {
		"List all active Recon monitoring rules",
		"Show typosquatting monitoring rules",
		"Find Recon rules with breach monitoring enabled",
		"List high priority domain monitoring rules",
	},
	"falcon_search_recon_exposed_data_records": {
		"Find exposed credentials for example.com",
		"Show leaked credentials from the past 7 days",
		"Find exposed data records for a specific notification",
	},
	"falcon_aggregate_recon_notifications": {
		"How many recon notifications are there by status?",
		"What are the top 10 noisiest recon monitoring rules this month?",
		"Show recon notification volume per day for the past 30 days",
		"Break down typosquatting notifications by priority",
	},
	"falcon_aggregate_recon_exposed_data_records": {
		"Which sites leak the most of our credentials?",
		"How many exposed credentials are newly reported vs previously reported?",
		"Show exposed data record volume per day",
	},
	"falcon_preview_recon_rule": {
		"How noisy would a rule monitoring example.com be?",
		"Preview how many notifications a brand rule for Acme would generate in the past 30 days",
		"Estimate the notification volume before I create this monitoring rule",
	},
	// Scheduled Reports
	"falcon_search_scheduled_reports": {
		"Show me all active scheduled reports",
	},
	"falcon_launch_scheduled_report": {
		"Run scheduled report abc123 now",
	},
	"falcon_search_report_executions": {
		"Show me completed executions for report abc123",
	},
	"falcon_download_report_execution": {
		"Download the results for report execution abc123",
	},
	// Sensor Usage
	"falcon_search_sensor_usage": {
		"Show me sensor usage data for the week of 2024-06-11",
	},
	// Serverless
	"falcon_search_serverless_vulnerabilities": {
		"Find HIGH severity vulnerabilities in AWS Lambda functions",
	},
	// Shield
	"falcon_search_shield_checks": {
		"Show me the failed Shield security checks",
		"Search for high impact Shield checks related to devices",
	},
	"falcon_get_shield_check_affected_entities": {
		"Show me the entities affected by a failed Shield check",
	},
	"falcon_get_shield_posture_metrics": {
		"Show me my overall Falcon Shield posture metrics",
	},
	"falcon_get_shield_check_compliance": {
		"Find a Shield check with compliance framework mappings",
	},
	"falcon_search_shield_alerts": {
		"Show me Shield alerts of type Threat",
		"Show me the 5 oldest Shield alerts sorted by date",
	},
	"falcon_get_shield_activity_monitor": {
		"Show me Shield activity events from the last 24 hours",
	},
	"falcon_search_shield_users": {
		"List privileged users across my connected SaaS apps in Shield",
	},
	"falcon_search_shield_devices": {
		"Show me devices in Shield not associated with any known user",
	},
	"falcon_search_shield_apps": {
		"Find OAuth apps in Shield that haven't been active in 90 days",
		"List all Shield apps with status 'in review'",
	},
	"falcon_get_shield_app_users": {
		"Show me which users have authorized Shield app abc123",
	},
	"falcon_search_shield_data_shares": {
		"Find files shared via public link in Shield",
	},
	"falcon_get_shield_integrations": {
		"List all connected SaaS integrations in Falcon Shield",
	},
	"falcon_get_shield_system_users": {
		"Show me the Falcon Shield platform administrators and their MFA status",
	},
	"falcon_get_shield_supported_saas": {
		"List all SaaS platforms supported by Falcon Shield",
	},
	"falcon_get_shield_system_logs": {
		"Show me the last 10 Falcon Shield system audit logs",
	},
	"falcon_dismiss_shield_check": {
		"Dismiss a low-impact Shield check entity with reason 'No longer applicable'",
	},
	// Spotlight
	"falcon_search_vulnerabilities": {
		"Show me open HIGH severity vulnerabilities",
		"Find vulnerabilities on host xyz",
	},
	// Real Time Response
	"falcon_search_rtr_sessions": {
		"Find all active RTR sessions",
		"Show me RTR sessions for host abc123",
	},
	"falcon_search_rtr_audit_sessions": {
		"Show me RTR audit activity from the last 7 days",
		"Who used RTR against host BRR-WB-LIB-22?",
	},
	"falcon_aggregate_rtr_sessions": {
		"Summarize RTR sessions by command for the last 30 days",
		"Which hosts have the most RTR activity this week?",
	},
	"falcon_get_rtr_session_details": {
		"Get details for RTR session abc123",
	},
	"falcon_init_rtr_session": {
		"Start an RTR session on host xyz",
	},
	"falcon_pulse_rtr_session": {
		"Refresh the RTR session to keep it alive",
	},
	"falcon_execute_rtr_read_only_command": {
		"Run 'ps' on this host via RTR",
		"List running processes on host xyz",
	},
	"falcon_run_rtr_read_only_command_and_wait": {
		"Run 'ps' via RTR and return the output when it completes",
		"Check C:\\Windows\\win.ini on this RTR session and wait for the result",
	},
	"falcon_check_rtr_command_status": {
		"Check the status of RTR command request abc123",
	},
	"falcon_list_rtr_session_files": {
		"List files extracted during RTR session abc123",
	},
	"falcon_delete_rtr_session": {
		"End the RTR session abc123",
	},
	// Zero Trust Assessment
	"falcon_search_zta_assessments": {
		"Which hosts have the weakest Zero Trust posture?",
		"Show me hosts scoring below 40 on Zero Trust Assessment",
	},
	"falcon_get_zta_assessments": {
		"What is the security posture of host WEB-01?",
		"Show the Zero Trust hardening signals for this agent ID",
	},
	"falcon_get_zta_audit": {
		"What is our overall Zero Trust score?",
		"Break down our Zero Trust posture by platform",
	},
	// Fusion SOAR
	"falcon_search_workflow_definitions": {
		"What Fusion SOAR workflows can I trigger on demand?",
		"Find the Fusion workflow called 'Adversary Exposure Mitigation'",
		"Which Fusion workflows are currently disabled?",
	},
	"falcon_search_workflow_executions": {
		"Show me workflow executions that completed",
		"Which Fusion workflows failed in the last 7 days?",
		"Are any workflow runs waiting on someone to approve them?",
	},
	"falcon_get_workflow_execution_results": {
		"What did workflow execution 714511d8 actually do?",
		"Show me the ticket number the incident workflow created",
	},
	"falcon_execute_workflow": {
		"Run the 'Notify SOC Channel' workflow",
		"Start workflow 2617e3fc with the hash abc123",
	},
}
