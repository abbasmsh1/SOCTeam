import os
import json
import time
from datetime import datetime
from DefensiveActionSandbox import DefensiveActionSandbox

# Premium Crimson Theme Constants
CRIMSON = "\033[38;5;124m"
RED = "\033[91m"
RESET = "\033[0m"
GRAY = "\033[90m"
CYAN = "\033[96m"
WHITE = "\033[97m"
BOLD = "\033[1m"
    def __init__(self):
        # Align with DefensiveActionSandbox pathing
        base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
        self.state_path = os.path.join(base_dir, "Reports", "sandbox_state.json")
        self.engine = DefensiveActionSandbox()
        
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
                blocked_ips, sandbox_rules = self._load_data()
                live_rules = self.engine.get_live_firewall_rules()
                
                # --- Header ---
                print(f"{CRIMSON}╔" + "═"*118 + "╗")
                print(f"║ {WHITE}{BOLD}HEXSTRIKE AI {CRIMSON}║ {RED}ACTIVE FIREWALL RULES & SANDBOX MONITOR {CRIMSON}║ {GRAY}{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} {CRIMSON}║")
                print(f"╚" + "═"*118 + f"╝{RESET}")
                
                # --- Blocked IPs Section ---
                print(f"\n {CRIMSON}{RESET}{BOLD}{WHITE} SECTION: BLOCKED ENTITIES (SANDBOX) {RESET}")
                print(f"{GRAY}─" * 120)
                if not blocked_ips:
                    print(f" {GRAY}No IPs currently blocked in sandbox.{RESET}")
                else:
                    print(f" {BOLD}{WHITE}{'IP ADDRESS':<20} │ {'DURATION':<12} │ {'ADDED AT':<28} │ {'REASON'}{RESET}")
                    print(f"{GRAY}─" * 120)
                    for ip, info in blocked_ips.items():
                        print(f" {CYAN}{ip:<20} {RESET}│ {GRAY}{info.get('duration'):<12} {RESET}│ {info.get('added_at'):<28} │ {info.get('reason')}")
                
                # --- Live System Rules Section ---
                print(f"\n {RED}{RESET}{BOLD}{WHITE} SECTION: LIVE WINDOWS FIREWALL STATUS (ENABLED) {RESET}")
                print(f"{GRAY}═" * 120)
                if not live_rules:
                    print(f" {GRAY}Analyzing system rules... (Wait or check permissions){RESET}")
                else:
                    print(f" {BOLD}{WHITE}{'DISPLAY NAME':<50} │ {'ACTION':<10} │ {'DIR':<10} │ {'PROTO':<10} │ {'PORT'}{RESET}")
                    print(f"{GRAY}─" * 120)
                    # Limit to top 15 live rules to avoid overflow
                    for r in live_rules[:15]:
                        name = (r.get('DisplayName') or "Unknown")[:48]
                        act = r.get('Action', 'Unknown')
                        direct = r.get('Direction', 'Unknown')
                        proto = r.get('Protocol', 'ANY')
                        port = r.get('LocalPort', 'ANY')
                        
                        act_color = RED if act == "Block" else CYAN
                        print(f" {WHITE}{name:<50} {RESET}│ {act_color}{act:<10} {RESET}│ {GRAY}{direct:<10} {RESET}│ {proto:<10} │ {port}")
                    if len(live_rules) > 15:
                        print(f"{GRAY}... and {len(live_rules)-15} more rules active on host.{RESET}")

                # --- Sandbox Granular Rules ---
                print(f"\n {CRIMSON}{RESET}{BOLD}{WHITE} SECTION: SANDBOXED GRANULAR POLICIES {RESET}")
                print(f"{GRAY}─" * 120)
                if not sandbox_rules:
                    print(f" {GRAY}No simulated firewall rules active.{RESET}")
                else:
                    print(f" {BOLD}{WHITE}{'PRIO':<6} │ {'ACTION':<10} │ {'PROTOCOL':<10} │ {'SRC IP':<18} │ {'PORT':<10} │ {'REASON'}{RESET}")
                    print(f"{GRAY}─" * 120)
                    sorted_rules = sorted(sandbox_rules, key=lambda x: x.get('priority', 100))
                    for r in sorted_rules:
                        prio = r.get('priority', '-')
                        act = r.get('action_type', r.get('action', 'DENY'))
                        proto = r.get('protocol', 'ANY')
                        src = r.get('src_ip', 'ANY')
                        port = r.get('port', 'ANY')
                        reason = r.get('reason', 'N/A')
                        
                        act_color = RED if act == "DENY" else CYAN
                        print(f" {WHITE}{prio:<6} {RESET}│ {act_color}{act:<10} {RESET}│ {GRAY}{proto:<10} {RESET}│ {src:<18} │ {port:<10} │ {reason}")
                
                print(f"\n{CRIMSON}═" * 120 + f"{RESET}")
                print(f" {BOLD}{WHITE}[SYSTEM STATUS]{RESET} {CRIMSON}RUNNING{RESET} | {GRAY}Refresh: 2s | CTRL+C to Exit{RESET}")
                
                time.sleep(2)
        except KeyboardInterrupt:
            print(f"\n{RED}Monitoring Interrupted. Exiting SOC Sandbox Viewer.{RESET}")

if __name__ == "__main__":
    viewer = FirewallSandboxViewer()
    viewer.display_live()
