import requests
import json
import sys
import time
from datetime import datetime

HEXSTRIKE_URL = "http://localhost:8888"

def print_banner():
    print("""
    \033[91m
    ╔═╗╦  ╦  ╔═╗╔╦╗╔═╗  ╦ ╦╔═╗╦ ╦╔═╗╔╦╗╦═╗╦╦╔═╔═╗
    ║ ║║  ║  ╠═╣║║║╠═╣  ╠═╣║╣ ╚╦╝╚═╗ ║ ╠╦╝║╠╩╗║╣ 
    ╚═╝╩═╝╩═╝╩ ╩╩ ╩╩ ╩  ╩ ╩╚═╝ ╩ ╚═╝ ╩ ╩╚═╩╩ ╩╚═╝
    \033[0m\033[97mAI-Powered Autonomous Penetration Testing Bridge\033[0m
    """)

def analyze_target(target):
    print(f"[*] \033[94mRequesting AI Intelligence Report for: {target}\033[0m")
    try:
        response = requests.post(f"{HEXSTRIKE_URL}/api/intelligence/analyze-target", 
                               json={"target": target}, timeout=120)
        if response.status_code == 200:
            data = response.json()
            report = data.get("intelligence_report", "No report generated.")
            profile = data.get("target_profile", {})
            
            print("\n\033[92m[+] Intelligence Report Received:\033[0m")
            print("-" * 60)
            print(report)
            print("-" * 60)
            return profile
        else:
            print(f"\033[91m[-] Server error: {response.status_code}\033[0m")
            return None
    except Exception as e:
        print(f"\033[91m[-] Error connecting to HexStrike: {e}\033[0m")
        return None

def select_tools(target, profile, objective="comprehensive"):
    print(f"\n[*] \033[94mSelecting optimal tools for objective: {objective}\033[0m")
    try:
        response = requests.post(f"{HEXSTRIKE_URL}/api/intelligence/select-tools", 
                               json={
                                   "target": target,
                                   "profile": profile,
                                   "objective": objective
                               })
        if response.status_code == 200:
            tools = response.json().get("recommended_tools", [])
            print(f"\033[92m[+] Recommended Tools ({len(tools)}):\033[0m")
            for tool in tools:
                print(f"  - {tool['tool']} (Success Prob: {tool.get('success_probability', 0.5):.2f})")
            return tools
        return []
    except Exception as e:
        print(f"[-] Error selecting tools: {e}")
        return []

def main():
    print_banner()
    if len(sys.argv) < 2:
        target = input("Enter target URL or IP: ")
    else:
        target = sys.argv[1]

    profile = analyze_target(target)
    if not profile:
        return

    tools = select_tools(target, profile)
    
    if tools:
        proceed = input(f"\nProceed with autonomous execution? (y/N): ")
        if proceed.lower() == 'y':
            print("\n\033[93m[*] Starting autonomous sequence...\033[0m")
            # In a real implementation, we would loop through and call tool execution endpoints
            print("[!] Sequence ready. (Execution phase simulated for safety)")
    
if __name__ == "__main__":
    main()
