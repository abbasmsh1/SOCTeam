import os
from datetime import datetime
from typing import Dict, Any
import json
from ...utils.Logger import setup_logger

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

    def _format_markdown(self, data: Dict[str, Any]) -> str:
        """Formats the data into a Markdown string."""
        
        tier1 = data.get('tier1_analysis', {})
        tier2 = data.get('tier2_analysis', {})
        tier3 = data.get('tier3_analysis', {})
        war_room = data.get('war_room_analysis', {})
        
        final_severity = data.get('final_severity', 'Unknown')
        classification = data.get('incident_classification', 'Unknown')
        
        md = []
        md.append(f"# Security Incident Report")
        md.append(f"**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        md.append(f"**Final Severity:** {final_severity}")
        md.append(f"**Classification:** {classification}")
        md.append(f"**Workflow Version:** {data.get('workflow_version', '1.0')}")
        md.append("\n---")
        
        # Executive Summary
        md.append("## Executive Summary")
        if classification == "Tier 1 Analysis Only":
            md.append("This alert was triaged by Tier 1 and deemed non-critical or resolved without escalation.")
            md.append(f"**Recommendation:** {data.get('recommended_actions', 'None')}")
        else:
            md.append(f"A confirmed security incident was detected. Severity validated as **{final_severity}**.")
            md.append(f"**Primary Action:** {data.get('recommended_actions', 'See details below')}")
        
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
            md.append(f"- **Enriched Context:**")
            md.append(f"  - _Checked Historical Logs & Threat Intel_")
            md.append(f"- **Analysis:**\n> {tier2.get('full_report', 'See summary above.')}")
            
        # Tier 3 Details (if applicable)
        if data.get('escalated_to_tier3'):
            md.append("\n## Tier 3 Analysis (Response Planning)")
            md.append(f"- **Response Plan:**\n> {tier3.get('response_plan', 'Pending...')}")
            md.append(f"- **Credible Threat for War Room:** {tier3.get('credible_threat', False)}")

        # Remediation Details
        remediation = data.get('remediation', {})
        enforced_rules = remediation.get('enforced_rules', [])
        if enforced_rules:
            md.append("\n## Automated Remediation (Enforced)")
            md.append("| Action | Target | Reason | Status |")
            md.append("| :--- | :--- | :--- | :--- |")
            for rule in enforced_rules:
                action = rule.get('action', 'Unknown')
                target = rule.get('target', 'N/A')
                reason = rule.get('reason', 'Automatic response')
                md.append(f"| **{action}** | `{target}` | {reason} | Applied (Simulated) |")

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
