import os
from datetime import datetime
from typing import Dict, Any, List, Union
import json

try:
    from .TierAnalystAgent import format_observed_facts_block
except (ImportError, ValueError):
    try:
        from TierAnalystAgent import format_observed_facts_block
    except ImportError:
        format_observed_facts_block = None  # type: ignore
try:
    from ...utils.Logger import setup_logger
except (ImportError, ValueError):
    try:
        from utils.Logger import setup_logger
    except ImportError:
        import logging
        def setup_logger(name):
            return logging.getLogger(name)

logger = setup_logger(__name__)

class ReportGeneratorAgent:
    """
    Agent responsible for generating comprehensive reports from SOC workflow results.
    """
    def __init__(self, output_dir: str = "Reports"):
        # Resolve output directory to project root (Project/Reports)
        base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
        self.output_dir = os.path.join(base_dir, output_dir)
        
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir, exist_ok=True)
            
    def generate_report(self, workflow_result: Dict[str, Any]) -> str:
        """
        Generates a markdown report from the workflow result and saves it.
        
        Args:
            workflow_result: The final dictionary output from SOCWorkflow.
            
        Returns:
            The absolute path to the generated report file.
        """
        logger.info("Generating final report...")
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        incident_id = str(id(workflow_result))[-6:] # Simple ID from object ID for now, or use UUID if available
        
        filename = f"SOC_Report_{timestamp}_{incident_id}.md"
        filepath = os.path.join(self.output_dir, filename)
        
        markdown_content = self._format_markdown(workflow_result)
        
        try:
            print(f"DEBUG: Writing report to {filepath}")
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(markdown_content)
            logger.info(f"Report saved successfully at {filepath}")
            print(f"DEBUG: Report saved successfully!")
            
            # DEBUG LOGGING
            with open("report_debug.log", "a") as debug_f:
                debug_f.write(f"[{datetime.now()}] SUCCESS: Generated {filepath}\n")
                
            return filepath
        except Exception as e:
            # DEBUG LOGGING
            with open("report_debug.log", "a") as debug_f:
                debug_f.write(f"[{datetime.now()}] ERROR: {str(e)}\n")
                debug_f.write(f"Output Dir: {self.output_dir}\n")
                
            print(f"DEBUG: FAILED to write report: {e}")
            logger.error(f"Failed to write report: {e}")
            return ""

    def _format_recommendations_field(self, rec: Union[str, List[Any], None]) -> str:
        if rec is None or rec == "N/A":
            return "None"
        if isinstance(rec, list):
            return "; ".join(str(x) for x in rec)
        return str(rec)

    def _telemetry_markdown(self, data: Dict[str, Any]) -> str:
        alert = data.get("alert_data") or {}
        tier1 = data.get("tier1_analysis") or {}
        if isinstance(alert, dict) and not alert:
            raw = tier1.get("raw_alert")
            if isinstance(raw, dict):
                alert = raw
        hex_e = data.get("hexstrike_enrichment") or {}
        if format_observed_facts_block:
            return format_observed_facts_block(
                alert if isinstance(alert, dict) else {},
                tier1_output=tier1 if tier1 else None,
                hexstrike_enrichment=hex_e if isinstance(hex_e, dict) else None,
            )
        return "## Observed telemetry\n*(TierAnalystAgent.format_observed_facts_block unavailable)*"

    def _format_markdown(self, data: Dict[str, Any]) -> str:
        """Formats the data into a Markdown string."""
        
        tier1 = data.get('tier1_analysis', {})
        tier2 = data.get('tier2_analysis', {})
        tier3 = data.get('tier3_analysis', {})
        war_room = data.get('war_room_analysis', {})
        remediation = data.get('remediation', {}) or {}
        execution_log = remediation.get('execution_log', []) or []
        
        final_severity = data.get('final_severity', 'Unknown')
        classification = data.get('incident_classification', 'Unknown')
        
        md = []
        md.append(f"# Security Incident Report")
        md.append(f"**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        md.append(f"**Final Severity:** {final_severity}")
        md.append(f"**Classification:** {classification}")
        md.append(f"**Workflow Version:** {data.get('workflow_version', '1.0')}")
        md.append("\n---")

        md.append(self._telemetry_markdown(data))
        ctx = data.get("context_logs", "")
        if isinstance(ctx, str) and ctx.strip() and ctx.strip() != "No additional logs available.":
            excerpt = ctx if len(ctx) <= 3500 else ctx[:3500] + "\n\n... *[truncated]*"
            md.append("\n### Flow / log feed (excerpt)\n")
            md.append(f"```\n{excerpt}\n```")

        if execution_log:
            md.append("\n## Actions executed (automated remediation)")
            md.append(
                "The following sandbox-backed actions were **actually run** for this incident "
                "(not a generic playbook)."
            )
            for entry in execution_log:
                ts = entry.get("timestamp", "")
                act = entry.get("action", "N/A")
                tgt = entry.get("target", "N/A")
                st = entry.get("status", "UNKNOWN")
                reason = entry.get("reason", "")
                md.append(
                    f"- **{act}** → `{tgt}` — **{st}** @ {ts}\n"
                    f"  - Reason: {reason}"
                )
                effect = entry.get("effect")
                if effect is not None:
                    md.append(f"  - Sandbox effect: `{json.dumps(effect, default=str)[:1200]}`")
                snap = entry.get("state_snapshot") or {}
                if isinstance(snap, dict) and snap:
                    md.append(f"  - State snapshot keys: `{', '.join(list(snap.keys())[:20])}`")
        
        md.append("\n---")
        
        # Executive Summary
        md.append("## Executive Summary")
        if classification == "Tier 1 Analysis Only":
            md.append("This alert was triaged by Tier 1 and deemed non-critical or resolved without escalation.")
            md.append(f"**Recommendation:** {self._format_recommendations_field(data.get('recommended_actions'))}")
        else:
            md.append(f"A confirmed security incident was detected. Severity validated as **{final_severity}**.")
            md.append(
                f"**Analyst recommendations (Tier 2/1):** "
                f"{self._format_recommendations_field(data.get('recommended_actions'))}"
            )
            if execution_log:
                md.append(
                    f"**Automated response:** {len(execution_log)} sandbox action(s) recorded — "
                    "see *Actions executed* above for host, status, and effects."
                )
        
        md.append("\n---")
        
        # Tier 1 Details
        md.append("## Tier 1 Analysis (Triage)")
        md.append(f"- **Initial Severity:** {tier1.get('severity', 'N/A')}")
        md.append(f"- **False Positive:** {tier1.get('false_positive', 'N/A')}")
        md.append(f"- **Triage Assessment:**\n> {tier1.get('triage_response', 'No details provided.')}")
        
        # Tier 2 Details (if applicable)
        if data.get('escalated_to_tier2'):
            md.append("\n## Tier 2 Analysis (Deep Dive)")
            md.append(f"- **Validated Severity:** {tier2.get('validated_severity', 'N/A')}")
            md.append(f"- **Classification:** {tier2.get('incident_classification', 'N/A')}")
            md.append("- **Data sources used:** Tier 1 enriched alert, workflow HexStrike enrichment, and flow/log context in this report.")
            md.append(f"- **Analysis:**\n> {tier2.get('full_report', 'See summary above.')}")
            
        # Tier 3 Details (if applicable)
        if data.get('escalated_to_tier3'):
            md.append("\n## Tier 3 Analysis (Response Planning)")
            md.append(f"- **Response Plan:**\n> {tier3.get('response_plan', 'Pending...')}")
            md.append(f"- **Credible Threat for War Room:** {tier3.get('credible_threat', False)}")

        # Remediation Details (table view; narrative already in Actions executed)
        enforced_rules = remediation.get('enforced_rules', [])
        execution_log = remediation.get('execution_log', [])
        if enforced_rules:
            md.append("\n## Automated Remediation (Enforced)")
            md.append("| Action | Target | Reason | Status |")
            md.append("| :--- | :--- | :--- | :--- |")
            status_index = {}
            for entry in execution_log:
                key = f"{entry.get('action', '')}:{entry.get('target', '')}"
                status_index[key] = entry.get("status", "UNKNOWN")

            for rule in enforced_rules:
                action = rule.get('action', 'Unknown')
                target = rule.get('target', 'N/A')
                reason = rule.get('reason', 'Automatic response')
                key = f"{action}:{target}"
                status = status_index.get(key, "UNKNOWN")
                md.append(f"| **{action}** | `{target}` | {reason} | {status} |")

        # Include full actionable rule execution ledger for forensic completeness
        if execution_log:
            md.append("\n### ACTIONABLE_RULES Execution Ledger")
            md.append("| Action | Target | Execution | Auto Pilot | Dry Run |")
            md.append("| :--- | :--- | :--- | :--- | :--- |")
            for entry in execution_log:
                md.append(
                    f"| {entry.get('action', 'N/A')} | `{entry.get('target', 'N/A')}` | "
                    f"{entry.get('status', 'UNKNOWN')} | {entry.get('auto_pilot', False)} | {entry.get('dry_run', False)} |"
                )

        # HexStrike Forensic Intelligence section (required for escalated incidents)
        hexstrike = data.get("hexstrike_enrichment", {}) or {}
        if hexstrike:
            analysis = hexstrike.get("analysis", {}) if isinstance(hexstrike, dict) else {}
            reputation = hexstrike.get("reputation", {}) if isinstance(hexstrike, dict) else {}
            recommended = analysis.get("recommended_tools_outputs", analysis.get("recommended_tools", "N/A")) if isinstance(analysis, dict) else "N/A"
            open_services = analysis.get("open_services", analysis.get("services", analysis.get("ports", "N/A"))) if isinstance(analysis, dict) else "N/A"
            port_scan = analysis.get("port_scan_results", analysis.get("scan_results", analysis.get("nmap", "N/A"))) if isinstance(analysis, dict) else "N/A"
            rep_score = reputation.get("score", reputation.get("reputation_score", "N/A")) if isinstance(reputation, dict) else "N/A"
            abuse = reputation.get("abuse_category", reputation.get("category", "N/A")) if isinstance(reputation, dict) else "N/A"

            md.append("\n## HexStrike Forensic Intelligence")
            md.append("Structured enrichment (avoids `[object Object]` stringification):\n")
            md.append(f"```json\n{json.dumps(hexstrike, indent=2, default=str)[:12000]}\n```")
            md.append("\n**Highlights:**")
            md.append(f"- **Port scan / scan summary:** `{json.dumps(port_scan, default=str)[:2000]}`")
            md.append(f"- **IP reputation score:** `{rep_score}`")
            md.append(f"- **Abuse category:** `{abuse}`")
            md.append(f"- **Open services / ports:** `{json.dumps(open_services, default=str)[:2000]}`")
            md.append(f"- **Recommended tool outputs:** `{json.dumps(recommended, default=str)[:2000]}`")

        # War Room Details (if applicable)
        if data.get('war_room_triggered'):
            md.append("\n## War Room Simulation")
            md.append("### Red Team (Attacker Simulation)")
            md.append(f"> {war_room.get('red_team_plan', {}).get('attack_plan', 'Simulation data unavailable')}")
            
            md.append("\n### Blue Team (Defense Strategy)")
            md.append(f"> {war_room.get('blue_team_plan', {}).get('defense_plan', 'Defense data unavailable')}")
            
            md.append("\n### Purple Team (Outcome & Improvements)")
            md.append(f"> {war_room.get('purple_team_report', {}).get('analysis_report', 'Report unavailable')}")

        md.append("\n---")
        md.append("*Generated by Agentic SOC System*")
        
        return "\n".join(md)
