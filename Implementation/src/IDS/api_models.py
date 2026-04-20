"""
Pydantic request/response models for the IDS FastAPI layer.

Kept intentionally permissive (Config.extra = "allow") because the backend
historically accepted a heterogeneous mix of NetFlow / CICFlowMeter / manual
JSON. The models validate the fields we actually read while letting the rest
pass through untouched.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Union

try:
    from pydantic import BaseModel, Field, ConfigDict
    _PYDANTIC_V2 = True
except ImportError:
    from pydantic import BaseModel, Field  # type: ignore
    ConfigDict = None  # type: ignore
    _PYDANTIC_V2 = False


class _Permissive(BaseModel):
    """Base model that tolerates extra fields (heterogeneous flow payloads)."""
    if _PYDANTIC_V2:
        model_config = ConfigDict(extra="allow")  # type: ignore[assignment]
    else:
        class Config:
            extra = "allow"


class FlowRecord(_Permissive):
    """A single flow record submitted to /predict or /soc/auto-rules."""
    # Common spellings the codebase already handles
    PROTOCOL: Optional[Union[int, float, str]] = None
    Protocol: Optional[str] = None
    IN_BYTES: Optional[Union[int, float]] = None
    IN_PKTS: Optional[Union[int, float]] = None
    FLOW_DURATION_MILLISECONDS: Optional[Union[int, float]] = None
    TCP_FLAGS: Optional[Union[int, float]] = None
    MIN_TTL: Optional[Union[int, float]] = None
    MAX_TTL: Optional[Union[int, float]] = None
    # Endpoint variants
    SourceIP: Optional[str] = Field(default=None, alias="Source IP")
    DestinationIP: Optional[str] = Field(default=None, alias="Destination IP")
    IPV4_SRC_ADDR: Optional[str] = None
    IPV4_DST_ADDR: Optional[str] = None
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None


class AutoRuleRequest(_Permissive):
    """Payload accepted by /soc/auto-rules.

    Either a full flow-style detection dict *or* a free-form `description`.
    """
    prediction: Optional[str] = None
    confidence: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    description: Optional[str] = None


class LiveEvent(_Permissive):
    """Payload for POST /events/add."""
    SourceIP: Optional[str] = None
    DestinationIP: Optional[str] = None
    Attack: Optional[str] = None
    Protocol: Optional[str] = None
    confidence: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    severity: Optional[str] = None


class AlertData(_Permissive):
    """Payload for POST /workflow/process (SOC alert)."""
    Attack: Optional[str] = None
    SourceIP: Optional[str] = None
    DestinationIP: Optional[str] = None
    confidence: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    severity: Optional[str] = None


def to_plain_dict(model: BaseModel) -> Dict[str, Any]:
    """Dump a pydantic model to a dict compatible with v1 and v2."""
    if _PYDANTIC_V2 and hasattr(model, "model_dump"):
        return model.model_dump(by_alias=True, exclude_none=False)
    return model.dict(by_alias=True, exclude_none=False)  # type: ignore[attr-defined]
