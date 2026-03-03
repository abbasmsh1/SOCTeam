from mcp.server.fastmcp import FastMCP
from Implementation.src.Agents.SOCWorkflow import SOCWorkflow
import json
import os
from typing import Dict, Any

# Initialize FastMCP server
mcp = FastMCP("SOC-Agent-Server")

# Initialize SOC Workflow
# Note: In a real deployment, API key should be handled securely, possibly passed via env var to the server process
api_key = os.getenv("MISTRAL_API_KEY")
soc_workflow = SOCWorkflow(api_key=api_key)

@mcp.tool()
def analyze_alert(alert_data: Dict[str, Any], current_status: str = "Normal") -> str:
    """
    Analyze a security alert using the multi-tier SOC agent workflow.
    
    Args:
        alert_data: Dictionary containing alert details (SourceIP, DestinationIP, Label, etc.)
        current_status: Current system status context
        
    Returns:
        JSON string containing the full analysis report
    """
    if not soc_workflow.app:
        return json.dumps({"error": "SOC Workflow not initialized (missing API key?)"})
    
    input_data = {
        "alert_data": alert_data,
        "current_status": current_status
    }
    
    result = soc_workflow.process(input_data)
    return json.dumps(result, indent=2)

@mcp.tool()
def get_system_status() -> str:
    """
    Get the current status of the SOC system.
    """
    return "SOC System Online. Agents: Tier 1, Tier 2, Tier 3 ready."

if __name__ == "__main__":
    # Run the server
    mcp.run()
