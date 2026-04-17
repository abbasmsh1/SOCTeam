try:
    import requests
except ImportError:  # pragma: no cover - optional in unit tests
    requests = None
import logging
from typing import Dict, Any

logger = logging.getLogger(__name__)

class RemoteAgentClient:
    """
    HTTP Client wrapper that talks to a remotely hosted agent via FastAPI.
    Replace local in-memory agent instantiations with this class.
    """
    def __init__(self, endpoint_url: str):
        """
        Initialize the remote client.
        
        Args:
            endpoint_url: The base URL of the agent microservice (e.g., "http://localhost:6051")
        """
        self.endpoint_url = endpoint_url.rstrip('/')
        
    def process(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        """Call the /process endpoint."""
        return self._make_request("/process", input_data)
        
    def run_simulation(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        """Call the /run_simulation endpoint."""
        return self._make_request("/run_simulation", input_data)
        
    def generate_report(self, input_data: Dict[str, Any]) -> str:
        """Call the /generate_report endpoint and return string path."""
        result = self._make_request("/generate_report", input_data)
        return result.get("report_path", "")
        
    def _make_request(self, path: str, data: Dict[str, Any]) -> Dict[str, Any]:
        if requests is None:
            logger.error("requests dependency is not installed")
            return {}
        try:
            response = requests.post(
                f"{self.endpoint_url}{path}", 
                json={"input_data": data},
                timeout=300 # Agents can take a while to think
            )
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to communicate with remote agent at {self.endpoint_url}: {e}")
            if hasattr(e, 'response') and e.response is not None:
                logger.error(f"Response: {e.response.text}")
            # Ensure we return empty dict on failure for graceful degradation
            return {}
