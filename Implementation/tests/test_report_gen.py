
import sys
import os
from datetime import datetime

# Add project root to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.Agents.ReportGeneratorAgent import ReportGeneratorAgent

def test_report_generation():
    print("Testing ReportGeneratorAgent...")
    
    # Initialize
    try:
        agent = ReportGeneratorAgent()
        print(f"Agent initialized. Output dir: {agent.output_dir}")
        
        # Check if dir exists
        if os.path.exists(agent.output_dir):
            print("✅ Output directory exists.")
        else:
            print("❌ Output directory DOES NOT exist. (It should have been created)")
            
    except Exception as e:
        print(f"❌ Failed to initialize agent: {e}")
        return

    # Create dummy result
    dummy_result = {
        "timestamp": datetime.now().isoformat(),
        "final_severity": "High",
        "incident_classification": "Test Incident",
        "workflow_version": "TEST_1.0",
        "tier1_analysis": {
            "severity": "High",
            "triage_response": "This is a test triage."
        },
        "escalated_to_tier2": True,
        "tier2_analysis": {
            "validated_severity": "High",
            "full_report": "This is a test investigation."
        }
    }
    
    # Generate report
    try:
        report_path = agent.generate_report(dummy_result)
        if report_path and os.path.exists(report_path):
            print(f"✅ Report generated successfully: {report_path}")
            
            # Read content to verify
            with open(report_path, 'r') as f:
                content = f.read()
                print("\n--- Content Preview ---")
                print(content[:200] + "...")
                print("-----------------------")
        else:
            print("❌ Report generation returned path but file not found or empty path.")
            
    except Exception as e:
        print(f"❌ Report generation failed: {e}")

if __name__ == "__main__":
    test_report_generation()
