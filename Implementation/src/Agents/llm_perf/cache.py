"""
LLM response cache.

Deterministic wrapper around any langchain-compatible chat model. Hashes the
(model_name, messages, temperature) tuple. Identical inputs return the cached
AIMessage in microseconds instead of 15-30 seconds.

Why this is safe:
  - We only cache responses where temperature == 0 OR explicit opt-in. At
    higher temperatures the LLM is non-deterministic by design and caching
    would hide variability.
  - Entries have a TTL (default 1h). Set to 0 to disable the time dimension.
  - The cache is per-process in-memory. For cross-restart persistence, set
    IDS_LLM_CACHE_DIR to a writable directory — misses then fall through to
    disk before hitting the model.

Wrapping is transparent: `CachingLLM(inner)` exposes `invoke`, `bind_tools`,
and `.content` in the response, so upstream code doesn't change.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import pickle
import threading
import time
from collections import OrderedDict
from typing import Any, Callable, Dict, Iterable, List, Optional

logger = logging.getLogger(__name__)


class _LRU:
    def __init__(self, max_size: int = 256) -> None:
        self._data: "OrderedDict[str, tuple[float, Any]]" = OrderedDict()
        self._max = max_size
        self._lock = threading.RLock()
        self.hits = 0
        self.misses = 0

    def get(self, key: str, ttl_sec: float) -> Optional[Any]:
        with self._lock:
            item = self._data.get(key)
            if not item:
                self.misses += 1
                return None
            ts, value = item
            if ttl_sec > 0 and (time.time() - ts) > ttl_sec:
                self._data.pop(key, None)
                self.misses += 1
                return None
            # LRU bump
            self._data.move_to_end(key)
            self.hits += 1
            return value

    def put(self, key: str, value: Any) -> None:
        with self._lock:
            self._data[key] = (time.time(), value)
            self._data.move_to_end(key)
            while len(self._data) > self._max:
                self._data.popitem(last=False)

    def clear(self) -> None:
        with self._lock:
            self._data.clear()
            self.hits = 0
            self.misses = 0

    def stats(self) -> Dict[str, Any]:
        with self._lock:
            total = self.hits + self.misses
            return {
                "size": len(self._data),
                "hits": self.hits,
                "misses": self.misses,
                "hit_rate": round(self.hits / total, 4) if total else 0.0,
            }


_GLOBAL_LRU = _LRU(max_size=int(os.getenv("IDS_LLM_CACHE_SIZE", "512")))
_TTL_SEC = float(os.getenv("IDS_LLM_CACHE_TTL_SEC", "3600"))
_CACHE_DIR = os.getenv("IDS_LLM_CACHE_DIR", "").strip()  # optional disk backing


def get_cache_stats() -> Dict[str, Any]:
    return _GLOBAL_LRU.stats()


def clear_cache() -> None:
    _GLOBAL_LRU.clear()


def _key(model: str, messages: Iterable[Any], temperature: float) -> str:
    """Stable key for (model, messages, temperature) triple."""
    norm: List[Dict[str, Any]] = []
    for m in messages:
        if isinstance(m, dict):
            norm.append({"role": m.get("role"), "content": str(m.get("content", ""))})
        elif hasattr(m, "content"):
            role = getattr(m, "type", getattr(m, "role", "msg"))
            norm.append({"role": str(role), "content": str(m.content)})
        else:
            norm.append({"role": "msg", "content": str(m)})
    payload = json.dumps(
        {"model": model, "temp": round(float(temperature or 0), 4), "msgs": norm},
        sort_keys=True,
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _disk_get(key: str) -> Optional[Any]:
    if not _CACHE_DIR:
        return None
    path = os.path.join(_CACHE_DIR, key[:2], key + ".pkl")
    if not os.path.exists(path):
        return None
    try:
        with open(path, "rb") as f:
            ts, value = pickle.load(f)
        if _TTL_SEC > 0 and (time.time() - ts) > _TTL_SEC:
            return None
        return value
    except Exception:
        return None


def _disk_put(key: str, value: Any) -> None:
    if not _CACHE_DIR:
        return
    try:
        sub = os.path.join(_CACHE_DIR, key[:2])
        os.makedirs(sub, exist_ok=True)
        path = os.path.join(sub, key + ".pkl")
        tmp = path + ".tmp"
        with open(tmp, "wb") as f:
            pickle.dump((time.time(), value), f, protocol=pickle.HIGHEST_PROTOCOL)
        os.replace(tmp, path)
    except Exception:
        pass


class CachingLLM:
    """Proxy around a langchain chat model that memoises `.invoke(messages)`."""

    def __init__(
        self,
        inner: Any,
        model_name: str,
        temperature: float = 0.0,
        min_cache_temp: float = 0.3,
    ):
        self._inner = inner
        self._model_name = model_name or "unknown"
        self._temperature = float(temperature or 0)
        # Caching only kicks in when temperature is low enough that the LLM is
        # meaningfully deterministic. Higher temps are pass-through.
        self._cache_enabled = (
            os.getenv("IDS_LLM_CACHE", "true").lower() in ("1", "true", "yes")
            and self._temperature <= min_cache_temp
        )

    def __getattr__(self, name: str) -> Any:
        # Transparently forward anything we haven't intercepted (e.g. bind_tools)
        return getattr(self._inner, name)

    def bind_tools(self, tools):
        """Keep the cache wrapper after tool binding."""
        bound = self._inner.bind_tools(tools) if hasattr(self._inner, "bind_tools") else self._inner
        return CachingLLM(bound, self._model_name, self._temperature)

    def invoke(self, messages: Any, *args, **kwargs) -> Any:
        if not self._cache_enabled:
            return self._inner.invoke(messages, *args, **kwargs)

        key = _key(self._model_name, messages if isinstance(messages, list) else [messages], self._temperature)

        # In-memory
        cached = _GLOBAL_LRU.get(key, ttl_sec=_TTL_SEC)
        if cached is not None:
            return cached
        # Disk
        cached = _disk_get(key)
        if cached is not None:
            _GLOBAL_LRU.put(key, cached)
            return cached

        response = self._inner.invoke(messages, *args, **kwargs)
        try:
            _GLOBAL_LRU.put(key, response)
            _disk_put(key, response)
        except Exception as exc:
            logger.debug("LLM cache store failed: %s", exc)
        return response

    # Some callers call the model like a function (via LCEL pipelines)
    def __call__(self, *args, **kwargs):
        if hasattr(self._inner, "__call__"):
            return self._inner(*args, **kwargs)
        return self.invoke(*args, **kwargs)
