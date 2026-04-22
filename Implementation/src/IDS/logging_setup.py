"""
Structured logging for the IDS backend.

Emits JSON lines to stdout when `IDS_JSON_LOGS=true`, otherwise falls back
to the existing plaintext format. A `contextvars.ContextVar` carries
alert/workflow/request ids across async calls — set via
`set_log_context(**fields)` at the entry point of each workflow.

No external dependency: uses `logging` + `contextvars` + `json`.
"""

from __future__ import annotations

import contextvars
import json
import logging
import os
import sys
import time
from typing import Any, Dict

_log_context: contextvars.ContextVar[Dict[str, Any]] = contextvars.ContextVar(
    "ids_log_context", default={}
)


def set_log_context(**fields: Any) -> contextvars.Token:
    """Merge these fields into the current log context. Returns a Token for reset()."""
    current = _log_context.get()
    merged = {**current, **{k: v for k, v in fields.items() if v is not None}}
    return _log_context.set(merged)


def clear_log_context(token: contextvars.Token) -> None:
    _log_context.reset(token)


class JSONFormatter(logging.Formatter):
    """One-line JSON per log record with merged context vars."""

    _STANDARD = {
        "name", "msg", "args", "levelname", "levelno", "pathname", "filename",
        "module", "exc_info", "exc_text", "stack_info", "lineno", "funcName",
        "created", "msecs", "relativeCreated", "thread", "threadName",
        "processName", "process", "message",
    }

    def format(self, record: logging.LogRecord) -> str:
        payload: Dict[str, Any] = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(record.created))
                  + f".{int(record.msecs):03d}Z",
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        # Any non-standard attrs set via logger.info(msg, extra={...})
        for k, v in record.__dict__.items():
            if k not in self._STANDARD and not k.startswith("_"):
                try:
                    json.dumps(v)
                    payload[k] = v
                except (TypeError, ValueError):
                    payload[k] = str(v)
        ctx = _log_context.get()
        if ctx:
            payload["ctx"] = ctx
        return json.dumps(payload, default=str)


def configure_logging() -> None:
    """Install the JSON formatter onto the root logger if IDS_JSON_LOGS=true."""
    if os.getenv("IDS_JSON_LOGS", "false").lower() not in ("1", "true", "yes"):
        return
    root = logging.getLogger()
    for h in list(root.handlers):
        root.removeHandler(h)
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JSONFormatter())
    root.addHandler(handler)
    root.setLevel(os.getenv("IDS_LOG_LEVEL", "INFO").upper())
