import os
import json
import time
from datetime import datetime

class FirewallSandboxViewer:
    def __init__(self):
        # Align with DefensiveActionSandbox pathing
        base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
        self.state_path = os.path.join(base_dir, "Reports", "sandbox_state.json")
        
    def _load_data(self):
        if not os.path.exists(self.state_path):
            return {}, []
        try:
            with open(self.state_path, "r") as f:
                data = json.load(f)
                return data.get("blocked_ips", {}), data.get("firewall_rules", [])
        except:
            return {}, []

    def clear_screen(self):
        os.system('cls' if os.name == 'nt' else 'clear')

    def display_live(self):
        """Displays a premium table of active firewall rules."""
        try:
            while True:
                self.clear_screen()
                blocked_ips, rules = self._load_data()
                
                print("="*110)
                print(f" AGENTIC FIREWALL SANDBOX - LIVE MONITOR | {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
                print("="*110)
                
                # --- Blocked IPs Section ---
                print("\n [SECTION] BLOCKED IP ENTITIES")
                print("-" * 110)
                if not blocked_ips:
                    print(" No IPs currently blocked.")
                else:
                    print(f"{'IP ADDRESS':<18} | {'DURATION':<10} | {'ADDED AT':<25} | {'REASON'}")
                    print("-" * 110)
                    for ip, info in blocked_ips.items():
                        print(f"{ip:<18} | {info.get('duration'):<10} | {info.get('added_at'):<25} | {info.get('reason')}")
                
                # --- Firewall Rules Section ---
                print("\n [SECTION] GRANULAR FIREWALL RULES")
                print("-" * 110)
                if not rules:
                    print(" No firewall rules active.")
                else:
                    # Table Header
                    header = f"{'PRIO':<6} | {'ACTION':<8} | {'PROTOCOL':<8} | {'SRC IP':<18} | {'PORT':<8} | {'REASON'}"
                    print(header)
                    print("-" * 110)
                    
                    # Sort by priority
                    sorted_rules = sorted(rules, key=lambda x: x.get('priority', 100))
                    
                    for r in sorted_rules:
                        prio = r.get('priority', '-')
                        act = r.get('action_type', r.get('action', 'DENY'))
                        proto = r.get('protocol', 'ANY')
                        src = r.get('src_ip', 'ANY')
                        port = r.get('port', 'ANY')
                        reason = r.get('reason', 'N/A')
                        
                        # Highlighting for DENY rules
                        act_str = f"[{act}]" if act == "DENY" else f" {act} "
                        
                        print(f"{prio:<6} | {act_str:<8} | {proto:<8} | {src:<18} | {port:<8} | {reason}")
                
                print("\n" + "="*110)
                print(" [CTRL+C to Exit] | Monitoring sandbox_state.json for updates...")
                
                time.sleep(2)
        except KeyboardInterrupt:
            print("\nExiting Monitor.")

if __name__ == "__main__":
    viewer = FirewallSandboxViewer()
    viewer.display_live()
