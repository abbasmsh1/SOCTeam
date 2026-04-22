"""
gRPC TierAgent client skeleton — drop-in replacement for RemoteAgentClient
once the stubs are generated.

Usage (after `python -m grpc_tools.protoc ...`):
    from Implementation.src.Agents.grpc.tier_agent_client import GrpcTierClient
    client = GrpcTierClient("127.0.0.1:7051", tier="tier1",
                            local_factory=lambda: Tier1Analyst(api_key=key))
    result = client.process({"alert_data": {...}})

Same fallback semantics as RemoteAgentClient — if the remote is unreachable,
drop to the local in-process analyst.
"""

from __future__ import annotations

import logging
import os
from typing import Any, Callable, Dict, Optional

logger = logging.getLogger(__name__)


class GrpcTierClient:
    def __init__(self, endpoint: str, tier: str, local_factory: Optional[Callable[[], Any]] = None,
                 timeout_sec: float = 15.0):
        self.endpoint = endpoint
        self.tier = tier
        self.timeout_sec = timeout_sec
        self._local_factory = local_factory
        self._local_instance: Any = None
        self._stub = None

    def _ensure_stub(self):
        if self._stub is not None:
            return self._stub
        try:
            import grpc  # type: ignore
            from . import tier_agent_pb2_grpc  # type: ignore
            channel = grpc.insecure_channel(self.endpoint)
            self._stub = tier_agent_pb2_grpc.TierAgentStub(channel)
        except Exception as exc:
            logger.error("Failed to open gRPC channel to %s: %s", self.endpoint, exc)
            self._stub = None
        return self._stub

    def _local(self):
        if self._local_factory is None:
            return None
        if self._local_instance is None:
            self._local_instance = self._local_factory()
        return self._local_instance

    def process(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        import json as _json
        try:
            stub = self._ensure_stub()
            if stub is not None:
                from . import tier_agent_pb2  # type: ignore
                req = tier_agent_pb2.ProcessRequest(
                    tier=self.tier,
                    alert_id=input_data.get("alert_id") or os.urandom(4).hex(),
                    payload_json=_json.dumps(input_data, default=str),
                )
                resp = stub.Process(req, timeout=self.timeout_sec)
                if resp.result_json:
                    return _json.loads(resp.result_json)
        except Exception as exc:
            logger.warning("gRPC process failed (%s); falling back to local: %s", self.endpoint, exc)

        local = self._local()
        if local is not None:
            return local.process(input_data)
        return {}
