import os
import re

AGENT_DIR = r"e:\IMT\2nd Sem\Project\Implementation\src\Agents"

# Helper loop
for filename in os.listdir(AGENT_DIR):
    if not filename.endswith("Agent.py") and filename != "BaseAgent.py":
        continue

    filepath = os.path.join(AGENT_DIR, filename)
    with open(filepath, "r", encoding="utf-8") as f:
        content = f.read()

    # Step 1: Add imports for ToolNode and tools_condition
    if "from langgraph.prebuilt import ToolNode, tools_condition" not in content:
        content = re.sub(
            r"(from langgraph\.graph import StateGraph[^\n]+)",
            r"\1\nfrom langgraph.prebuilt import ToolNode, tools_condition\nfrom .HexstrikeClient import HexstrikeClient\nfrom .HexstrikeTools import get_hexstrike_tools",
            content
        )

    # Step 2: Initialize tools and tracer in __init__ for independent agents
    if "Code" in filename or "PurpleTeamAgent" in filename or "ReportGenerator" in filename or "RemediationAgent" in filename:
        tracer_code = """
        try:
            import agentlightning as agl
            agl.setup_logging(apply_to=[__name__])
            self.tracer = agl.AgentOpsTracer()
        except ImportError:
            self.tracer = None

        try:
            self.hexstrike = HexstrikeClient(base_url=config.get('hexstrike_url', 'http://localhost:8888'))
            self.tools = get_hexstrike_tools(self.hexstrike)
        except Exception:
            self.hexstrike = None
            self.tools = []
"""
        if "self.llm = ChatMistralAI" in content and "self.tools =" not in content:
            content = content.replace("self.llm = ChatMistralAI", tracer_code + "\n        self.llm = ChatMistralAI")
        
        # Bind tools
        if "if api_key:" in content and "self.llm = self.llm.bind_tools(self.tools)" not in content:
            content = content.replace("if api_key:", "if api_key and self.tools:\n            self.llm = getattr(self.llm, 'bind_tools', lambda x: self.llm)(self.tools)\n\n        if api_key:")

        # Add ToolNode in _create_graph
        if "_create_graph" in content:
            def add_tools(m):
                # find the agent node name
                node_match = re.search(r'workflow\.add_node\("([^"]+)",', m.group(0))
                if not node_match: return m.group(0)
                node_name = node_match.group(1)
                
                new_str = m.group(0).replace(
                    f'workflow.set_finish_point("{node_name}")',
                    f'workflow.add_node("tools", ToolNode(self.tools))\n        workflow.add_conditional_edges("{node_name}", tools_condition)\n        workflow.add_edge("tools", "{node_name}")'
                )
                new_str = new_str.replace(
                    f'workflow.add_edge("{node_name}", "__end__")',
                    f'workflow.add_node("tools", ToolNode(self.tools))\n        workflow.add_conditional_edges("{node_name}", tools_condition)\n        workflow.add_edge("tools", "{node_name}")'
                )
                return new_str
            
            content = re.sub(r'def _create_graph\(self\).*?return workflow', add_tools, content, flags=re.DOTALL)

    # Step 3: BaseAgent modification
    if filename == "BaseAgent.py" and "self.tools =" not in content:
        # Add tools load
        tool_init = """
        try:
            from .HexstrikeClient import HexstrikeClient
            from .HexstrikeTools import get_hexstrike_tools
            url = hexstrike_url or self.config.get("hexstrike_url", "http://localhost:8888")
            self.hexstrike = HexstrikeClient(base_url=url)
            self.tools = get_hexstrike_tools(self.hexstrike)
        except Exception as exc:
            logger.warning("Failed to load hexstrike tools: %s", exc)
            self.tools = []
"""
        content = content.replace("self.hexstrike = None\n        if enable_hexstrike:", tool_init + "\n        if enable_hexstrike:")
        
        # Bind tools
        bind_str = """
        if self.tools and self.llm:
            try:
                self.llm = self.llm.bind_tools(self.tools)
            except AttributeError:
                pass
"""
        content = content.replace("self.memory = MemorySaver() if self.api_key else None", bind_str + "\n        self.memory = MemorySaver() if self.api_key else None")

    # Step 4: Agents inheriting from BaseAgent (SecurityTeamAgent, TierAnalystAgent)
    if "BaseAgent" in content and filename not in ["BaseAgent.py"]:
        if "_create_graph" in content:
            def add_tools_base(m):
                node_match = re.search(r'workflow\.add_node\(([^,]+),', m.group(0))
                if not node_match: return m.group(0)
                node_name = node_match.group(1).replace('f"', '').replace('"', '')
                
                # Depending on how the string is formatted
                replacement = f"""        try:
            workflow.add_node("tools", ToolNode(self.tools))
            workflow.add_conditional_edges({node_match.group(1)}, tools_condition)
            workflow.add_edge("tools", {node_match.group(1)})
        except Exception as e:
            logger.warning(f"Could not add tools to graph: {{e}}")"""

                new_str = m.group(0).replace(
                    f'workflow.set_finish_point({node_match.group(1)})',
                    replacement
                )
                new_str = new_str.replace(
                    f'workflow.add_edge({node_match.group(1)}, "__end__")',
                    replacement
                )
                return new_str
            
            content = re.sub(r'def _create_graph\(self\).*?return workflow', add_tools_base, content, flags=re.DOTALL)

    with open(filepath, "w", encoding="utf-8") as f:
        f.write(content)

print("Done updating agents.")
