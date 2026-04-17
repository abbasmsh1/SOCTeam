import sys
import os
import time

# Add repo root to path for absolute imports
repo_root = os.path.join(os.path.dirname(__file__), "..")
sys.path.append(repo_root)

# Add src to path for local imports
sys.path.append(os.path.join(os.path.dirname(__file__), "src"))

from Agents.AutoSOCRuleGenerator import AutoSOCRuleGenerator
from Agents.DefensiveActionSandbox import DefensiveActionSandbox

def run_demo():
    print("="*60)
    print(" AGENTIC SOC AUTOMATION: AUTONOMOUS FIREWALL DEMO")
    print("="*60)
    
    # 1. Reset Sandbox
    print("\n[DEMO] Resetting security sandbox state...")
    sandbox = DefensiveActionSandbox()
    sandbox.clear_sandbox()
    
    soc = AutoSOCRuleGenerator()
    
    # Scenario 1: SMB Worm / Lateral Movement
    smb_threat = (
        "INCIDENT ALERT: Host 192.168.1.45 (Dev-Subnet) is attempting SMB enumeration "
        "across the entire 172.16.5.0/24 (Server-Subnet) via Port 445. "
        "Activity matches signatures for 'EternalBlue' exploitation attempts."
    )
    
    # Scenario 2: Web Exfiltration / SQLi
    sqli_threat = (
        "CRITICAL: Web application Firewall (WAF) detected multiple SQL Injection attempts "
        "on the patient_records endpoint from Source IP 203.0.113.12. "
        "The attacker is using 'UNION SELECT' techniques to dump credit card numbers."
    )

    print("\n" + "#"*40)
    print(" EXECUTING SCENARIO 1: LATERAL MOVEMENT")
    print("#"*40)
    soc.process_threat(smb_threat)
    
    print("\n" + "="*40)
    print(" [PAUSE] 3 seconds for analysis...")
    time.sleep(3)
    print("="*40 + "\n")
    
    print("\n" + "#"*40)
    print(" EXECUTING SCENARIO 2: DATA EXFILTRATION")
    print("#"*40)
    soc.process_threat(sqli_threat)
    
    print("\n" + "="*60)
    print(" DEMO COMPLETE")
    print("="*60)
    print("\n[INSTRUCTION] Run the Firewall Visualizer to see the autonomous policies:")
    print(" python src/Agents/FirewallSandboxViewer.py")
    print("="*60)

if __name__ == "__main__":
    run_demo()
