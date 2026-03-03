"""
Priority Flow Test Script
Selects DDoS and Botnet flows from the dataset and runs them through the SOC workflow.
Verifies rule generation and automated remediation execution.
"""

import pandas as pd
import requests
import json
import time
import os
import sys
from dotenv import load_dotenv

# Load environment
load_dotenv()

API_URL = "http://localhost:6050"
API_KEY = "ids-secret-key"

def run_priority_test():
    print("=== SOC Priority Flow Test (DDoS & Botnets) ===")
    
    # 1. Load dataset
    csv_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'Data', 'dataset_subset.csv')
    if not os.path.exists(csv_path):
        print(f"Error: Dataset not found at {csv_path}")
        return
    
    df = pd.read_csv(csv_path)
    
    # 2. Select high-priority samples
    # We'll take 2 DDoS and 2 Bot samples
    priority_flows = pd.concat([
        df[df['Attack'] == 'DDoS'].head(2),
        df[df['Attack'] == 'Bot'].head(2)
    ])
    
    print(f"Selected {len(priority_flows)} high-priority flows for testing.")
    
    results = []
    
    # 3. Process each flow
    for idx, row in priority_flows.iterrows():
        flow_data = row.to_dict()
        attack_type = flow_data.get('Attack', 'Unknown')
        
        print(f"\n--- Testing {attack_type} Flow (Index {idx}) ---")
        
        # Prepare request
        payload = {
            "id": f"test-{idx}",
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "Attack": attack_type,
            "Label": int(flow_data.get('Label', 1)),
            "SourceIP": "192.168.1.100", # Simulated IP
            "DestinationIP": "10.0.0.5",
            "SourcePort": int(flow_data.get('Source Port', 0)),
            "DestinationPort": int(flow_data.get('Destination Port', 0)),
            "Protocol": flow_data.get('Protocol', 'TCP'),
            "FlowDuration": float(flow_data.get('Flow Duration', 0)),
            "RawFlow": flow_data # Pass the full row data
        }
        
        headers = {
            "X-API-Key": API_KEY,
            "Content-Type": "application/json"
        }
        
        try:
            print("Sending to SOC Workflow...")
            start_time = time.time()
            response = requests.post(f"{API_URL}/workflow/process", json=payload, headers=headers, timeout=120)
            duration = time.time() - start_time
            
            if response.status_code == 200:
                result = response.json()
                final_res = result.get("final_result", {})
                severity = final_res.get("final_severity", "Unknown")
                
                # Check for remediation
                remediation = final_res.get("remediation", {})
                execution_status = remediation.get("remediation_status", "NOT_RUN")
                
                # Check for rules (if war room triggered)
                war_room = final_res.get("war_room_analysis", {})
                blue_plan = war_room.get("blue_team_plan", {})
                has_code = bool(blue_plan.get("generated_defensive_code", {}).get("final_code"))
                
                print(f"Result: Success (Duration: {duration:.2f}s)")
                print(f"Severity: {severity}")
                print(f"Rule Generated: {'YES' if has_code else 'NO'}")
                print(f"Remediation Executed: {execution_status}")
                
                # Check for actionable rules
                rules = remediation.get("enforced_rules", [])
                if rules:
                    print(f"Enforced Rules: {json.dumps(rules, indent=2)}")
                
                results.append({
                    "type": attack_type,
                    "status": "PASS",
                    "severity": severity,
                    "remediation": execution_status,
                    "has_rules": has_code
                })
            else:
                print(f"Error: Status {response.status_code} - {response.text}")
                results.append({"type": attack_type, "status": "FAIL", "error": response.text})
                
        except Exception as e:
            print(f"Exception: {e}")
            results.append({"type": attack_type, "status": "ERROR", "error": str(e)})

    # 4. Final Summary
    print("\n" + "="*40)
    print("FINAL TEST SUMMARY")
    print("="*40)
    for res in results:
        print(f"[{res['status']}] {res['type']}: Severity={res.get('severity')}, Remediation={res.get('remediation')}")
    
    # Check remediation log
    log_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "Reports", "remediation_log.json")
    if os.path.exists(log_path):
        with open(log_path, 'r') as f:
            logs = json.load(f)
            print(f"\nRemediation Log checking: Found {len(logs)} entries in {log_path}")

if __name__ == "__main__":
    run_priority_test()
