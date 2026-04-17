import os
import sys
import time
from unittest.mock import MagicMock, patch

# Ensure project root is in path
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from Implementation.src.Agents.SOCWorkflow import SOCWorkflow

def test_soc_workflow_forensic_tracking():
    """
    Verifies that the SOCWorkflow correctly identifies forensic requirements
    and updates the state status.
    """
    # Initialize workflow with fake key
    workflow = SOCWorkflow(api_key="fake")
    
    # Mock all agents to control the flow
    workflow.tier1_analyst = MagicMock()
    workflow.tier1_analyst.process.return_value = {
        "forensic_status": "COLLECTING",
        "severity": "High",
        "false_positive": False,
        "escalate": True,
        "enriched_alert": {"SourceIP": "1.2.3.4"}
    }
    
    workflow.tier2_analyst = MagicMock()
    workflow.tier2_analyst.process.return_value = {
        "forensic_status": "INVESTIGATING",
        "validated_severity": "High",
        "full_report": "Forensic investigation needed."
    }
    
    workflow.tier3_analyst = MagicMock()
    workflow.tier3_analyst.process.return_value = {
        "forensic_status": "INVESTIGATING",
        "response_plan": "Remediate and collect more logs."
    }
    
    workflow.red_agent = MagicMock()
    workflow.red_agent.process.return_value = {"war_room_result": {}}
    
    workflow.remediation_executor = MagicMock()
    workflow.remediation_executor.process.return_value = {"remediation_status": "COMPLETED"}

    # Mock the background forensic execution to avoid actual sleep/threading complexity in unit test
    # but still verify it's called.
    with patch.object(workflow, '_execute_forensic_background', wraps=workflow._execute_forensic_background) as mock_forensic:
        alert = {"SourceIP": "1.2.3.4", "Attack": "DDOS"}
        final_state = workflow.run_full_triage(alert)
        
        # Check if the forensic background task was triggered
        assert mock_forensic.called
        
        # Verify the forensic_status was captured in the final state
        assert "forensic_status" in final_state
        assert final_state["forensic_status"] == "INVESTIGATING"
        
        print("SOC Workflow Forensic Tracking Test Passed!")

if __name__ == "__main__":
    test_soc_workflow_forensic_tracking()
