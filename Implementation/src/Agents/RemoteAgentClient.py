try:
    import requests
except ImportError:  # pragma: no cover - optional in unit tests
    requests = None
import logging
from typing import Any, Callable, Dict, Optional

logger = logging.getLogger(__name__)

class RemoteAgentClient:
    """
    HTTP Client wrapper that talks to a remotely hosted agent via FastAPI.

    If `local_factory` is provided, the client falls back to an in-process
    agent whenever the remote returns an error, times out, or produces an
    empty response. That way TIER*_URL can be set without forcing the
    microservices to be up — the monolith keeps working either way.
    """
    def __init__(self, endpoint_url: str, local_factory: Optional[Callable[[], Any]] = None):
        self.endpoint_url = endpoint_url.rstrip('/')
        self._local_factory = local_factory
        self._local_instance: Any = None

    def _local(self):
        if self._local_factory is None:
            return None
        if self._local_instance is None:
            try:
                self._local_instance = self._local_factory()
            except Exception as exc:
                logger.error("Local agent factory failed: %s", exc)
                self._local_instance = None
        return self._local_instance

    def process(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        return self._with_fallback("/process", input_data, "process")

    def run_simulation(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        return self._with_fallback("/run_simulation", input_data, "run_simulation")

    def generate_report(self, input_data: Dict[str, Any]) -> str:
        result = self._with_fallback("/generate_report", input_data, "generate_report")
        if isinstance(result, str):
            return result
        return result.get("report_path", "") if isinstance(result, dict) else ""

    def _with_fallback(self, path: str, data: Dict[str, Any], method: str) -> Any:
        remote_result = self._make_request(path, data)
        if remote_result:
            return remote_result
        local = self._local()
        if local is None or not hasattr(local, method):
            return remote_result
        logger.info("Remote %s failed or empty; falling back to local agent for %s", self.endpoint_url, method)
        try:
            return getattr(local, method)(data)
        except Exception as exc:
            logger.error("Local fallback for %s failed: %s", method, exc)
            return {}

    def _make_request(self, path: str, data: Dict[str, Any]) -> Dict[str, Any]:
        if requests is None:
            logger.error("requests dependency is not installed")
            return {}
        try:
            response = requests.post(
                f"{self.endpoint_url}{path}",
                json={"input_data": data},
                timeout=300
            )
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to communicate with remote agent at {self.endpoint_url}: {e}")
            if hasattr(e, 'response') and e.response is not None:
                logger.error(f"Response: {e.response.text}")
            return {}
