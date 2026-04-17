"""
Security Team Agent
===================
Unified agent supporting Red Team (offensive), Blue Team (defensive),
and Purple Team (analysis) roles within the SOC workflow.

Each role has distinct capabilities:
  - Red Team: Performs reconnaissance, vulnerability scanning, and
              generates attack plans using Hexstrike-AI tools.
  - Blue Team: Conducts security assessments and proposes defensive
               measures with actionable rule enforcement.
  - Purple Team: Coordinates Red/Blue exercises and evaluates outcomes.
"""

from Implementation.src.Agents.BaseAgent import BaseAgent
from Implementation.src.Agents.runtime_compat import MessagesState, StateGraph
from typing import Dict, Any, List, Optional, Literal
import json
import logging
import datetime

logger = logging.getLogger(__name__)

# Supported team roles for the SecurityTeamAgent
TeamRole = Literal["red", "blue", "purple"]


class SecurityTeamAgent(BaseAgent):
    """
    Unified Security Team Agent with role-based behavior.

    Modes:
    - red:    Offensive security (attack simulation, vulnerability discovery)
    - blue:   Defensive security (threat response, security assessment)
    - purple: Coordination and analysis (red/blue exercise evaluation)
    """

    # Temperature settings per role – creative for attacks, analytical for coordination
    TEMPERATURE_MAP = {
        "red": 0.4,     # Creative for attack strategies
        "blue": 0.3,    # Balanced for defense
        "purple": 0.2,  # Analytical for coordination
    }

    # Roles that can use Hexstrike tools for real security scanning
    HEXSTRIKE_ENABLED_ROLES = {"red", "blue"}

    # Keywords that trigger automatic code generation via DevSecOps
    CODE_GENERATION_KEYWORDS = [
        "script", "code", "python", "bash", "shell", "exploit", "payload",
        "firewall rule", "patch",
    ]

    def __init__(
        self,
        role: TeamRole = "red",
        api_key: Optional[str] = None,
        hexstrike_url: Optional[str] = None,
    ):
        """
        Initialize Security Team Agent.

        Args:
            role:           Team role (red, blue, or purple).
            api_key:        Mistral API key for LLM inference.
            hexstrike_url:  Hexstrike-AI MCP server URL for tool execution.
        """
        self.role = role

        super().__init__(
            agent_name=f"{role.capitalize()}TeamAgent",
            temperature=self.TEMPERATURE_MAP[role],
            api_key=api_key,
            hexstrike_url=hexstrike_url,
            enable_hexstrike=(role in self.HEXSTRIKE_ENABLED_ROLES),
        )

        # Initialize DevSecOps workflow for code generation (red/blue teams only)
        self.devsecops = None
        if role in self.HEXSTRIKE_ENABLED_ROLES:
            try:
                from Implementation.src.Agents.DevSecOpsWorkflow import DevSecOpsWorkflow
                self.devsecops = DevSecOpsWorkflow(api_key=api_key)
            except Exception as e:
                logger.warning(f"DevSecOps workflow not available: {e}")

    # ──────────────────────────────────────────────────────────────
    # LangGraph Workflow
    # ──────────────────────────────────────────────────────────────

    def _create_graph(self) -> StateGraph:
        """Create a single-node LangGraph workflow based on the agent's role."""
        workflow = StateGraph(MessagesState)
        node_name = f"{self.role}_team"
        workflow.add_node(node_name, self._process_node)
        workflow.set_entry_point(node_name)
        workflow.set_finish_point(node_name)
        return workflow

    def _process_node(self, state: MessagesState) -> Dict[str, Any]:
        """Process node – delegates to the role-specific system prompt."""
        system_message = self._get_system_message()
        return self._call_model(state, system_message)

    # ──────────────────────────────────────────────────────────────
    # System Prompts (per role)
    # ──────────────────────────────────────────────────────────────

    def _get_system_message(self) -> str:
        """Return the system message for the active role."""
        prompt_map = {
            "red": self._get_red_team_prompt,
            "blue": self._get_blue_team_prompt,
            "purple": self._get_purple_team_prompt,
        }
        return prompt_map[self.role]()

    def _get_red_team_prompt(self) -> str:
        """Red Team system prompt – offensive security capabilities."""
        if self.hexstrike:
            tools_info = """
        Available via Hexstrike-AI MCP:
        - Network Recon: nmap, rustscan, masscan
        - Subdomain Enum: amass, subfinder
        - Web Vuln Scanning: nuclei, sqlmap, nikto, wpscan
        - Directory Fuzzing: gobuster, feroxbuster, ffuf
        - Password Attacks: hydra
        - AI Intelligence: analyze_target, select_tools
        """
        else:
            tools_info = "WARNING: Hexstrike-AI tools unavailable."

        return f"""You are the Red Team Lead (Attacker).
        Your goal is to identify weaknesses in the system by simulating sophisticated attacks.
        
        Capabilities:
        1. Analyze system architecture for potential attack vectors.
        2. Generate attack strategies (e.g., SQLi, XSS, Phishing, Privilege Escalation).
        3. Create proof-of-concept payloads.
        4. Execute real security tools via Hexstrike-AI.
        
        {tools_info}
        
        When you need to generate specific attack code (e.g., a Python script to exploit a vuln), 
        clearly state the requirements for the DevSecOps team.
        """

    def _get_blue_team_prompt(self) -> str:
        """Blue Team system prompt – defensive security capabilities."""
        if self.hexstrike:
            tools_info = """
        Available via Hexstrike-AI MCP:
        - Vulnerability Scanning: nuclei, trivy
        - Container Security: kube-hunter, trivy
        - Security Assessment: AI intelligence tools
        - Network Analysis: nmap (defensive scans)
        """
        else:
            tools_info = "WARNING: Hexstrike-AI tools unavailable."

        return f"""You are the Blue Team Lead (Defender).
        Your goal is to protect the system by analyzing threats and proposing robust, automated defensive measures.
        
        Capabilities & Expanded Action Library:
        1. [BLOCK_IP]: Complete drops for confirmed malicious sources.
        2. [RATE_LIMIT]: Throttle traffic (PPS) for suspicious sources.
        3. [ISOLATE_HOST]: Quarantine internal infected nodes (Critical for Botnets/C&C).
        4. [TCP_RESET]: Immediately kill active malicious sessions.
        5. [ENRICH_TARGET]: Trigger an automated intelligence scan (Nuclei/Nmap) via Hexstrike.
        6. [RESET_PASSWORD]: Force password reset for compromised accounts.
        7. [TUNE_SIEM]: Adjust detection rules to reduce false positives or catch new variants.
        
        Playbook Strategies:
        - DDoS/Flooding: Use BLOCK_IP for top offenders + RATE_LIMIT on the target port/protocol.
        - Botnet/Infiltration: Use ISOLATE_HOST on internal IPs + TCP_RESET on external C2 links.
        - Bruteforce: Use BLOCK_IP with a temporary duration (e.g., "1h") + RESET_PASSWORD for targeted accounts.
        - Unknown/Suspicious: Use ENRICH_TARGET to gather more intel before escalation.
        - SIEM/Detection Issues: Use TUNE_SIEM to suggest rule modifications.
        
        CRITICAL: Every defensive response MUST include a structured rule block:
        [ACTIONABLE_RULES]
        [
          {{"action": "BLOCK_IP", "target": "SOURCE_IP", "reason": "DDoS detection", "duration": "permanent"}},
          {{"action": "RATE_LIMIT", "target": "PORT_OR_IP", "limit": "50/s", "reason": "Abnormal volume"}},
          {{"action": "ENRICH_TARGET", "target": "IP_TO_SCAN", "reason": "Requires intelligence gathering"}},
          {{"action": "RESET_PASSWORD", "target": "USERNAME", "reason": "Compromised credentials"}},
          {{"action": "TUNE_SIEM", "target": "RULE_NAME", "reason": "High false positive rate"}}
        ]
        [/ACTIONABLE_RULES]
        
        Clearly state the reasoning for your chosen playbook and specify if requirements should be sent to the DevSecOps team for custom patching.
        """

    def _get_purple_team_prompt(self) -> str:
        """Purple Team system prompt – coordination and exercise evaluation."""
        return """You are the Purple Team Lead (Coordinator).
        Your goal is to maximize the effectiveness of the security posture by coordinating Red (Attack) and Blue (Defense) teams.
        
        Capabilities:
        1. Analyze the outcome of Red vs Blue exercises.
        2. Identify gaps where Blue failed to stop Red.
        3. Identify gaps where Red failed to find vulnerabilities.
        4. Generate "Lessons Learned" and actionable recommendations.
        """

    # ──────────────────────────────────────────────────────────────
    # Processing Logic (per role)
    # ──────────────────────────────────────────────────────────────

    def process(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Process input based on agent role.

        Args:
            input_data: Role-specific input data.

        Returns:
            Role-specific output dictionary.
        """
        handler_map = {
            "red": self._process_red_team,
            "blue": self._process_blue_team,
            "purple": self._process_purple_team,
        }
        return handler_map[self.role](input_data)

    def _process_red_team(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Red Team processing pipeline.

        Phases:
          1. Reconnaissance – port scanning, subdomain enumeration, AI analysis.
          2. Vulnerability Scanning – Nuclei, directory fuzzing.
          3. AI Attack Planning – generate a full attack plan via LLM.
          4. (Optional) Code generation via DevSecOps if the plan requires scripts.
        """
        target_info = input_data.get("target_info", {})
        target = target_info.get("target", target_info.get("domain", target_info.get("ip", "")))

        recon_results: Dict[str, Any] = {}
        vuln_scan_results: Dict[str, Any] = {}
        attack_plan = "LLM disabled."
        generated_code = None

        # ── Phase 1: Reconnaissance ──
        if self.hexstrike and target:
            logger.info(f"Red Team: Starting reconnaissance on {target}")
            try:
                # AI-driven target analysis
                recon_results["ai_analysis"] = self.hexstrike.analyze_target(target, "comprehensive")

                # Port scanning (enabled by default)
                if target_info.get("scan_ports", True):
                    logger.info("Executing port scan...")
                    recon_results["port_scan"] = self.hexstrike.rustscan_scan(target)

                # Subdomain enumeration (only for domain targets, not IPs)
                if "." in target and not target.replace(".", "").isdigit():
                    logger.info("Executing subdomain enumeration...")
                    recon_results["subdomains"] = self.hexstrike.subfinder_enum(target)

            except Exception as e:
                logger.error(f"Reconnaissance error: {e}")
                recon_results["error"] = str(e)

        # ── Phase 2: Vulnerability Scanning ──
        if self.hexstrike and target_info.get("vuln_scan", True):
            logger.info("Red Team: Starting vulnerability scanning")
            try:
                if target_info.get("web_target", True):
                    target_url = target if target.startswith("http") else f"http://{target}"
                    logger.info(f"Scanning {target_url} with Nuclei...")
                    vuln_scan_results["nuclei"] = self.hexstrike.nuclei_scan(
                        target_url,
                        severity=target_info.get("severity_filter", "critical,high"),
                    )

                    # Optional directory fuzzing
                    if target_info.get("fuzz_directories", False):
                        logger.info("Fuzzing directories...")
                        vuln_scan_results["directory_fuzz"] = self.hexstrike.gobuster_scan(target_url)

            except Exception as e:
                logger.error(f"Vulnerability scan error: {e}")
                vuln_scan_results["error"] = str(e)

        # ── Phase 3: AI Attack Planning ──
        prompt = f"""Target Info: {json.dumps(target_info, indent=2)}
        
        Reconnaissance Results: {json.dumps(recon_results, indent=2)}
        Vulnerability Scan Results: {json.dumps(vuln_scan_results, indent=2)}
        
        Based on the reconnaissance and vulnerability scan results, propose a detailed attack plan.
        If code is needed (e.g., an exploit script), specify the requirements."""

        attack_plan = self._stream_with_config(prompt)

        # ── Phase 4: Code Generation (if the plan mentions scripts/exploits) ──
        if attack_plan and self.devsecops:
            if any(kw in attack_plan.lower() for kw in self.CODE_GENERATION_KEYWORDS):
                logger.info("Red Team requesting code generation...")
                code_reqs = f"Generate code based on this attack plan: {attack_plan}"
                generated_code = self.devsecops.run(
                    requirements=code_reqs,
                    context=f"Target: {target_info}",
                )

        return {
            "attack_plan": attack_plan or "Error generating plan",
            "reconnaissance": recon_results,
            "vulnerability_scans": vuln_scan_results,
            "generated_attack_code": generated_code,
            "timestamp": datetime.datetime.utcnow().isoformat(),
        }

    def _process_blue_team(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Blue Team processing pipeline.

        Phases:
          1. Security Assessment – vulnerability and container scanning.
          2. Defense Planning – generate a defensive plan via LLM.
          3. (Optional) Code generation via DevSecOps for patches/scripts.
        """
        threat_info = input_data.get("threat_info", {})
        system_state = input_data.get("system_state", "Standard Configuration")
        system_target = input_data.get("system_target", None)

        security_assessment: Dict[str, Any] = {}
        defense_plan = "LLM disabled."
        generated_code = None

        # ── Phase 1: Security Assessment ──
        if self.hexstrike and system_target:
            logger.info(f"Blue Team: Starting security assessment on {system_target}")
            try:
                # Vulnerability scanning (enabled by default)
                if input_data.get("scan_vulnerabilities", True):
                    target_url = system_target if system_target.startswith("http") else f"http://{system_target}"
                    logger.info(f"Scanning {target_url} for vulnerabilities...")
                    security_assessment["vulnerability_scan"] = self.hexstrike.nuclei_scan(
                        target_url,
                        severity=input_data.get("severity_filter", "critical,high,medium"),
                    )

                # Container security (opt-in)
                if input_data.get("container_scan", False):
                    container_target = input_data.get("container_image", system_target)
                    logger.info(f"Scanning container {container_target} with Trivy...")
                    security_assessment["container_scan"] = self.hexstrike.trivy_scan(container_target, "image")

                # AI intelligence analysis
                logger.info("Analyzing target with AI intelligence...")
                security_assessment["ai_analysis"] = self.hexstrike.analyze_target(system_target, "comprehensive")

            except Exception as e:
                logger.error(f"Security assessment error: {e}")
                security_assessment["error"] = str(e)

        # ── Phase 2: Defense Planning ──
        prompt = f"""Threat Detected: {json.dumps(threat_info, indent=2)}
        System State: {system_state}
        Security Assessment Results: {json.dumps(security_assessment, indent=2)}
        
        Based on the threat information and security assessment, propose a comprehensive defense plan.
        If code is needed (e.g., a patch or script), specify the requirements."""

        defense_plan = self._stream_with_config(prompt)

        # ── Phase 3: Code Generation (if the plan mentions patches/scripts) ──
        if defense_plan and self.devsecops:
            if any(kw in defense_plan.lower() for kw in self.CODE_GENERATION_KEYWORDS):
                logger.info("Blue Team requesting code generation...")
                code_reqs = f"Generate code based on this defense plan: {defense_plan}"
                generated_code = self.devsecops.run(
                    requirements=code_reqs,
                    context=f"Threat: {threat_info}",
                )

        return {
            "defense_plan": defense_plan or "Error generating plan",
            "security_assessment": security_assessment,
            "generated_defensive_code": generated_code,
            "timestamp": datetime.datetime.utcnow().isoformat(),
        }

    def _process_purple_team(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Purple Team analysis – evaluates Red vs Blue exercise outcomes
        and generates a comprehensive lessons-learned report.
        """
        red_output = input_data.get("red_output", {})
        blue_output = input_data.get("blue_output", {})

        prompt = f"""Analyze this War Game Exercise:
        
        Red Team (Attacker) Plan & Output:
        {json.dumps(red_output, indent=2)}
        
        Blue Team (Defender) Plan & Output:
        {json.dumps(blue_output, indent=2)}
        
        Provide a comprehensive report:
        1. Who won? (Did the attack succeed?)
        2. What were the key vulnerabilities?
        3. How effective were the defenses?
        4. Recommendations for improvement."""

        report = self._stream_with_config(prompt)

        return {
            "analysis_report": report or "Error generating analysis",
            "timestamp": datetime.datetime.utcnow().isoformat(),
        }
