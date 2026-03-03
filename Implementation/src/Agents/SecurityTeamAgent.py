"""
Security Team Agent
Unified agent supporting Red Team (offensive), Blue Team (defensive), and Purple Team (analysis) roles.
"""

from Implementation.src.Agents.BaseAgent import BaseAgent, AgentConfig
from langgraph.graph import StateGraph, MessagesState, START, END
from typing import Dict, Any, List, Optional, Literal
import json
import logging
import datetime

logger = logging.getLogger(__name__)

TeamRole = Literal["red", "blue", "purple"]


class SecurityTeamAgent(BaseAgent):
    """
    Unified Security Team Agent with role-based behavior.
    
    Modes:
    - red: Offensive security (attack simulation, vulnerability discovery)
    - blue: Defensive security (threat response, security assessment)
    - purple: Coordination and analysis (red/blue exercise evaluation)
    """
    
    def __init__(
        self,
        role: TeamRole = "red",
        api_key: Optional[str] = None,
        hexstrike_url: Optional[str] = None
    ):
        """
        Initialize Security Team Agent.
        
        Args:
            role: Team role (red, blue, or purple)
            api_key: Mistral API key
            hexstrike_url: Hexstrike-AI MCP server URL
        """
        self.role = role
        
        # Temperature settings per role
        temperature_map = {
            "red": 0.4,    # Creative for attack strategies
            "blue": 0.3,   # Balanced for defense
            "purple": 0.2  # Analytical for coordination
        }
        
        # Enable Hexstrike for red and blue teams
        enable_hexstrike = role in ["red", "blue"]
        
        super().__init__(
            agent_name=f"{role.capitalize()}TeamAgent",
            temperature=temperature_map[role],
            api_key=api_key,
            hexstrike_url=hexstrike_url,
            enable_hexstrike=enable_hexstrike
        )
        
        # Initialize DevSecOps workflow for code generation (red/blue teams)
        self.devsecops = None
        if role in ["red", "blue"]:
            try:
                from Implementation.src.Agents.DevSecOpsWorkflow import DevSecOpsWorkflow
                self.devsecops = DevSecOpsWorkflow(api_key=api_key)
            except Exception as e:
                logger.warning(f"DevSecOps workflow not available: {e}")
    
    def _create_graph(self) -> StateGraph:
        """Create workflow graph based on role."""
        workflow = StateGraph(MessagesState)
        node_name = f"{self.role}_team"
        workflow.add_node(node_name, self._process_node)
        try:
            workflow.set_entry_point(node_name)
        except:
            workflow.add_edge("__start__", node_name)
        try:
            workflow.set_finish_point(node_name)
        except:
            workflow.add_edge(node_name, "__end__")
        return workflow
    
    def _process_node(self, state: MessagesState) -> Dict[str, Any]:
        """Process node that delegates to role-specific logic."""
        system_message = self._get_system_message()
        return self._call_model(state, system_message)
    
    def _get_system_message(self) -> str:
        """Get system message based on role."""
        if self.role == "red":
            return self._get_red_team_prompt()
        elif self.role == "blue":
            return self._get_blue_team_prompt()
        else:  # purple
            return self._get_purple_team_prompt()
    
    def _get_red_team_prompt(self) -> str:
        """Red Team system prompt."""
        tools_info = ""
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
        """Blue Team system prompt."""
        tools_info = ""
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
        Your goal is to protect the system by analyzing threats and proposing robust defensive measures.
        
        Capabilities:
        1. Analyze logs and system configurations.
        2. Identify vulnerabilities through proactive scanning.
        3. Propose specific remediation steps (e.g., firewall rules, patches, configuration changes).
        4. Execute real security assessment tools via Hexstrike-AI.
        
        {tools_info}
        
        CRITICAL: When proposing firewall rules or IP blocking, you MUST include a structured rule block in your response like this:
        [ACTIONABLE_RULES]
        [
          {{"action": "BLOCK_IP", "target": "SOURCE_IP_HERE", "reason": "DDoS detection", "duration": "permanent"}},
          {{"action": "FILTER_TRAFFIC", "target": "PORT_HERE", "reason": "Abnormal volume"}}
        ]
        [/ACTIONABLE_RULES]
        
        When you need to generate specific code (e.g., a Python script to patch a vuln, or a shell script for iptables), 
        clearly state the requirements for the DevSecOps team.
        """
    
    def _get_purple_team_prompt(self) -> str:
        """Purple Team system prompt."""
        return """You are the Purple Team Lead (Coordinator).
        Your goal is to maximize the effectiveness of the security posture by coordinating Red (Attack) and Blue (Defense) teams.
        
        Capabilities:
        1. Analyze the outcome of Red vs Blue exercises.
        2. Identify gaps where Blue failed to stop Red.
        3. Identify gaps where Red failed to find vulnerabilities.
        4. Generate "Lessons Learned" and actionable recommendations.
        """
    
    def process(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Process input based on agent role.
        
        Args:
            input_data: Role-specific input data
            
        Returns:
            Role-specific output
        """
        if self.role == "red":
            return self._process_red_team(input_data)
        elif self.role == "blue":
            return self._process_blue_team(input_data)
        else:  # purple
            return self._process_purple_team(input_data)
    
    def _process_red_team(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        """Red Team processing with reconnaissance and vulnerability scanning."""
        target_info = input_data.get("target_info", {})
        target = target_info.get("target", target_info.get("domain", target_info.get("ip", "")))
        
        recon_results = {}
        vuln_scan_results = {}
        attack_plan = "LLM disabled."
        generated_code = None
        
        # Phase 1: Reconnaissance
        if self.hexstrike and target:
            logger.info(f"Red Team: Starting reconnaissance on {target}")
            
            try:
                # AI-driven target analysis
                ai_analysis = self.hexstrike.analyze_target(target, "comprehensive")
                recon_results["ai_analysis"] = ai_analysis
                
                # Port scanning
                if target_info.get("scan_ports", True):
                    logger.info("Executing port scan...")
                    port_scan = self.hexstrike.rustscan_scan(target)
                    recon_results["port_scan"] = port_scan
                
                # Subdomain enumeration
                if "." in target and not target.replace(".", "").isdigit():
                    logger.info("Executing subdomain enumeration...")
                    subdomains = self.hexstrike.subfinder_enum(target)
                    recon_results["subdomains"] = subdomains
                
            except Exception as e:
                logger.error(f"Reconnaissance error: {e}")
                recon_results["error"] = str(e)
        
        # Phase 2: Vulnerability Scanning
        if self.hexstrike and target_info.get("vuln_scan", True):
            logger.info("Red Team: Starting vulnerability scanning")
            
            try:
                if target_info.get("web_target", True):
                    target_url = target if target.startswith("http") else f"http://{target}"
                    logger.info(f"Scanning {target_url} with Nuclei...")
                    nuclei_results = self.hexstrike.nuclei_scan(
                        target_url,
                        severity=target_info.get("severity_filter", "critical,high")
                    )
                    vuln_scan_results["nuclei"] = nuclei_results
                    
                    if target_info.get("fuzz_directories", False):
                        logger.info("Fuzzing directories...")
                        dir_fuzz = self.hexstrike.gobuster_scan(target_url)
                        vuln_scan_results["directory_fuzz"] = dir_fuzz
                
            except Exception as e:
                logger.error(f"Vulnerability scan error: {e}")
                vuln_scan_results["error"] = str(e)
        
        # Phase 3: AI Attack Planning
        prompt = f"""Target Info: {json.dumps(target_info, indent=2)}
        
        Reconnaissance Results: {json.dumps(recon_results, indent=2)}
        Vulnerability Scan Results: {json.dumps(vuln_scan_results, indent=2)}
        
        Based on the reconnaissance and vulnerability scan results, propose a detailed attack plan.
        If code is needed (e.g., an exploit script), specify the requirements."""
        
        attack_plan = self._stream_with_config(prompt)
        
        # Code generation if needed
        if attack_plan and self.devsecops:
            keywords = ["script", "code", "python", "bash", "shell", "exploit", "payload"]
            if any(k in attack_plan.lower() for k in keywords):
                logger.info("Red Team requesting code generation...")
                code_reqs = f"Generate code based on this attack plan: {attack_plan}"
                devsecops_result = self.devsecops.run(requirements=code_reqs, context=f"Target: {target_info}")
                generated_code = devsecops_result
        
        return {
            "attack_plan": attack_plan or "Error generating plan",
            "reconnaissance": recon_results,
            "vulnerability_scans": vuln_scan_results,
            "generated_attack_code": generated_code,
            "timestamp": datetime.datetime.utcnow().isoformat()
        }
    
    def _process_blue_team(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        """Blue Team processing with security assessment."""
        threat_info = input_data.get("threat_info", {})
        system_state = input_data.get("system_state", "Standard Configuration")
        system_target = input_data.get("system_target", None)
        
        security_assessment = {}
        defense_plan = "LLM disabled."
        generated_code = None
        
        # Phase 1: Security Assessment
        if self.hexstrike and system_target:
            logger.info(f"Blue Team: Starting security assessment on {system_target}")
            
            try:
                # Vulnerability scanning
                if input_data.get("scan_vulnerabilities", True):
                    target_url = system_target if system_target.startswith("http") else f"http://{system_target}"
                    logger.info(f"Scanning {target_url} for vulnerabilities...")
                    nuclei_results = self.hexstrike.nuclei_scan(
                        target_url,
                        severity=input_data.get("severity_filter", "critical,high,medium")
                    )
                    security_assessment["vulnerability_scan"] = nuclei_results
                
                # Container security
                if input_data.get("container_scan", False):
                    container_target = input_data.get("container_image", system_target)
                    logger.info(f"Scanning container {container_target} with Trivy...")
                    trivy_results = self.hexstrike.trivy_scan(container_target, "image")
                    security_assessment["container_scan"] = trivy_results
                
                # AI analysis
                logger.info("Analyzing target with AI intelligence...")
                ai_analysis = self.hexstrike.analyze_target(system_target, "comprehensive")
                security_assessment["ai_analysis"] = ai_analysis
                
            except Exception as e:
                logger.error(f"Security assessment error: {e}")
                security_assessment["error"] = str(e)
        
        # Phase 2: Defense Planning
        prompt = f"""Threat Detected: {json.dumps(threat_info, indent=2)}
        System State: {system_state}
        Security Assessment Results: {json.dumps(security_assessment, indent=2)}
        
        Based on the threat information and security assessment, propose a comprehensive defense plan.
        If code is needed (e.g., a patch or script), specify the requirements."""
        
        defense_plan = self._stream_with_config(prompt)
        
        # Code generation if needed
        if defense_plan and self.devsecops:
            keywords = ["script", "code", "python", "bash", "shell", "firewall rule", "patch"]
            if any(k in defense_plan.lower() for k in keywords):
                logger.info("Blue Team requesting code generation...")
                code_reqs = f"Generate code based on this defense plan: {defense_plan}"
                devsecops_result = self.devsecops.run(requirements=code_reqs, context=f"Threat: {threat_info}")
                generated_code = devsecops_result
        
        return {
            "defense_plan": defense_plan or "Error generating plan",
            "security_assessment": security_assessment,
            "generated_defensive_code": generated_code,
            "timestamp": datetime.datetime.utcnow().isoformat()
        }
    
    def _process_purple_team(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        """Purple Team analysis of Red/Blue exercises."""
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
            "timestamp": datetime.datetime.utcnow().isoformat()
        }
