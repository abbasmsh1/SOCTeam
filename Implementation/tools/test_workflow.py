import os
import sys
from datetime import datetime

# Add project root to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))

from Implementation.src.Agents.SOCWorkflow import SOCWorkflow

def main():
    print("🧪 Starting Standalone SOC Workflow Test...")
    api_key = os.getenv("MISTRAL_API_KEY")
    if not api_key:
        print("⚠️ MISTRAL_API_KEY not found in environment!")
    else:
        print(f"✅ MISTRAL_API_KEY found (length: {len(api_key)})")

    workflow = SOCWorkflow(api_key=api_key)
    
    test_alert = {
        "SourceIP": "1.2.3.4",
        "DestinationIP": "10.0.0.5",
        "SourcePort": 1234,
        "DestinationPort": 80,
        "Protocol": 6,
        "Attack": "DDOS",
        "Severity": "CRITICAL",
        "confidence": 0.99
    }
    
    input_data = {
        "alert_data": test_alert,
        "current_status": "Manual Test",
        "context_logs": "Testing workflow escalation and report generation",
        "current_incidents": "N/A"
    }
    
    print("\n🚀 Executing Workflow...")
    try:
        result = workflow.process(input_data)
        print("\n✅ Workflow Complete!")
        print(f"Final Severity: {result.get('final_severity')}")
        print(f"Escalated to Tier 2: {result.get('escalated_to_tier2')}")
        print(f"Report Path: {result.get('report_path')}")
        
        if result.get('report_path') and os.path.exists(result.get('report_path')):
            print(f"🎉 SUCCESS: Report exists at {result.get('report_path')}")
        else:
            print("❌ FAILURE: Report not found at the expected path.")
            
    except Exception as e:
        print(f"❌ ERROR: {e}")

if __name__ == "__main__":
    main()
