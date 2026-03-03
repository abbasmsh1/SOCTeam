import os
import sys
import argparse
import uvicorn
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Dict, Any, Optional

# Add project root to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))

from Implementation.utils.Logger import setup_logger

logger = setup_logger("AgentServer")

app = FastAPI(title="SOC Agent Microservice")

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class AgentRequest(BaseModel):
    input_data: Dict[str, Any]

# Global configuration
agent_type = None
api_key = None
agent_instance = None

def get_agent():
    """Lazy initialize the agent instance."""
    global agent_instance, agent_type, api_key
    if agent_instance is not None:
        return agent_instance
        
    logger.info(f"Lazy initializing {agent_type} agent...")
    if agent_type == "tier1":
        from Implementation.src.Agents.LegacyCompat import Tier1Analyst
        agent_instance = Tier1Analyst(api_key=api_key)
    elif agent_type == "tier2":
        from Implementation.src.Agents.LegacyCompat import Tier2Analyst
        agent_instance = Tier2Analyst(api_key=api_key)
    elif agent_type == "tier3":
        from Implementation.src.Agents.LegacyCompat import Tier3Analyst
        agent_instance = Tier3Analyst(api_key=api_key)
    elif agent_type == "warroom":
        from Implementation.src.Agents.WarRoomWorkflow import WarRoomWorkflow
        agent_instance = WarRoomWorkflow(api_key=api_key)
    elif agent_type == "reporter":
        from Implementation.src.Agents.ReportGeneratorAgent import ReportGeneratorAgent
        agent_instance = ReportGeneratorAgent()
    elif agent_type == "remediation":
        from Implementation.src.Agents.RemediationAgent import RemediationAgent
        agent_instance = RemediationAgent()
    
    logger.info(f"{agent_type} agent initialized.")
    return agent_instance

@app.post("/process")
async def process_request(request: AgentRequest):
    """Generic endpoint for agents that have a process() method."""
    agent = get_agent()
    if not agent:
        raise HTTPException(status_code=500, detail="Agent not initialized")
    if not hasattr(agent, "process"):
        raise HTTPException(status_code=400, detail="This agent does not support the process() method")
        
    try:
        result = agent.process(request.input_data)
        return result
    except Exception as e:
        logger.error(f"Agent processing failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/run_simulation")
async def run_simulation(request: AgentRequest):
    """Specific endpoint for War Room Workflow."""
    agent = get_agent()
    if not agent:
        raise HTTPException(status_code=500, detail="Agent not initialized")
    if not hasattr(agent, "run_simulation"):
        raise HTTPException(status_code=400, detail="This agent does not support the run_simulation() method")
        
    try:
        result = agent.run_simulation(request.input_data)
        return result
    except Exception as e:
        logger.error(f"War room simulation failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/generate_report")
async def generate_report(request: AgentRequest):
    """Specific endpoint for Report Generator."""
    agent = get_agent()
    if not agent:
        raise HTTPException(status_code=500, detail="Agent not initialized")
    if not hasattr(agent, "generate_report"):
        raise HTTPException(status_code=400, detail="This agent does not support the generate_report() method")
        
    try:
        report_path = agent.generate_report(request.input_data)
        return {"report_path": report_path}
    except Exception as e:
        logger.error(f"Report generation failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/health")
def health_check():
    return {
        "status": "healthy", 
        "initialized": agent_instance is not None,
        "agent_type": agent_type
    }

def main():
    global agent_type, api_key
    
    parser = argparse.ArgumentParser(description="Run a SOC Agent as a Microservice")
    parser.add_argument("--agent", type=str, required=True, 
                        choices=["tier1", "tier2", "tier3", "warroom", "reporter", "remediation"], 
                        help="Which agent to run")
    parser.add_argument("--port", type=int, required=True, help="Port to run the specific agent on")
    parser.add_argument("--api-key", type=str, default=None, help="Optional API key override")
    
    args = parser.parse_args()
    agent_type = args.agent
    
    from dotenv import load_dotenv
    load_dotenv()
    api_key = args.api_key or os.getenv("MISTRAL_API_KEY")
    
    logger.info(f"Starting uvicorn server for {agent_type} on port {args.port} (Immediate bind enabled)")
    uvicorn.run(app, host="0.0.0.0", port=args.port)

if __name__ == "__main__":
    main()
