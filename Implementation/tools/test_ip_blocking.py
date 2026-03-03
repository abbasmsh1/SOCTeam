import requests
import json
import time
import os

API_URL = "http://127.0.0.1:6050"
API_KEY = "ids-secret-key"

def test_ip_blocking():
    print("=== SOC IP Blocking Verification Test ===")
    
    # Simulate a critical DDoS flow
    target_ip = "192.168.1.99"
    payload = {
        "id": "critical-ddos-test",
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "Attack": "DDoS",
        "Label": 1,
        "SourceIP": target_ip,
        "DestinationIP": "10.0.0.5",
        "SourcePort": 443,
        "DestinationPort": 443,
        "Protocol": "UDP",
        "FlowDuration": 1000.0,
        "RawFlow": {"Attack": "DDoS", "Flow Duration": 1000.0, "Total Fwd Packets": 10000}
    }
    
    headers = {
        "X-API-Key": API_KEY,
        "Content-Type": "application/json"
    }
    
    print(f"Sending CRITICAL DDoS flow from {target_ip}...")
    try:
        response = requests.post(f"{API_URL}/workflow/process", json=payload, headers=headers, timeout=120)
        
        if response.status_code == 200:
            result = response.json()
            with open("temp_debug_res.json", "w") as f:
                json.dump(result, f, indent=2)
            
            # The workflow returns the state directly or the final_result dict
            print(f"\n[DEBUG] Raw Response saved to temp_debug_res.json")
            
            # Navigate the actual response schema
            remediation = result.get("remediation_result", {})
            rules = remediation.get("enforced_rules", [])
            
            if not rules:
                # Try final_result nesting if backend is wrapping it
                final_res = result.get("final_result", {})
                remediation = final_res.get("remediation", final_res.get("remediation_result", {}))
                rules = remediation.get("enforced_rules", [])
            
            print(f"Workflow processed successfully.")
            if rules:
                print(f"SUCCESS: System generated actionable rules:")
                print(json.dumps(rules, indent=2))
                
                # Check if our target_ip is in the rules
                is_blocked = any(rule.get("action") == "BLOCK_IP" and rule.get("target") == target_ip for rule in rules)
                if is_blocked:
                    print(f"VERIFIED: IP {target_ip} was targeted for BLOCK_IP action.")
                else:
                    print(f"WARNING: IP {target_ip} was NOT specifically targeted for blocking, but rules were generated.")
            else:
                print("FAILURE: No actionable rules were generated for this critical threat.")
        else:
            print(f"ERROR: {response.status_code} - {response.text}")

    except Exception as e:
        print(f"EXCEPTION: {e}")

if __name__ == "__main__":
    test_ip_blocking()
