"""
Ollama keep-alive warmer.

Ollama unloads models from VRAM/RAM when no requests have arrived for a few
minutes (default 5). The next call pays a 10-30 s reload cost — which is
visible every time a burst of SOC alerts arrives "after hours".

This module pings the Ollama `/api/generate` endpoint with `keep_alive=-1`
every N seconds (default 120) to keep the model resident. Cost: one trivial
generation per cycle, ~50 ms.

Lifecycle:
    warmer = OllamaWarmer(model="llama3.2", base_url="http://localhost:11434")
    warmer.start()
    ...
    warmer.stop()

Safe no-ops when:
    - IDS_LLM_WARMER=false
    - provider is not ollama (checked via LLM_PROVIDER env)
    - Ollama is unreachable (logged once, then silent retries)
"""

from __future__ import annotations

import logging
import os
import threading
import time
from typing import Optional

logger = logging.getLogger(__name__)


class OllamaWarmer:
    def __init__(
        self,
        model: Optional[str] = None,
        base_url: Optional[str] = None,
        interval_sec: float = 120.0,
    ) -> None:
        self.model = model or os.getenv("LLM_MODEL", "llama3.2")
        self.base_url = (base_url or os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")).rstrip("/")
        self.interval_sec = max(30.0, float(interval_sec))
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._enabled = (
            os.getenv("IDS_LLM_WARMER", "true").lower() in ("1", "true", "yes")
            and (os.getenv("LLM_PROVIDER", "ragarenn").lower() == "ollama")
        )
        self._warned_unreachable = False

    def start(self) -> None:
        if not self._enabled:
            logger.info("[warmer] disabled (IDS_LLM_WARMER or provider != ollama)")
            return
        if self._thread and self._thread.is_alive():
            return
        self._thread = threading.Thread(
            target=self._loop, name="ollama-warmer", daemon=True,
        )
        self._thread.start()
        logger.info("[warmer] started model=%s interval=%ss", self.model, self.interval_sec)

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=5)

    def _loop(self) -> None:
        # Ping immediately so the first real call benefits on startup
        self._ping()
        while not self._stop.wait(self.interval_sec):
            self._ping()

    def _ping(self) -> None:
        try:
            import requests
            r = requests.post(
                f"{self.base_url}/api/generate",
                json={
                    "model": self.model,
                    "prompt": "ok",
                    "stream": False,
                    "keep_alive": -1,  # stay resident indefinitely
                    "options": {"num_predict": 1, "temperature": 0},
                },
                timeout=15,
            )
            if r.status_code == 200:
                self._warned_unreachable = False
            else:
                if not self._warned_unreachable:
                    logger.warning("[warmer] non-200 from Ollama: %s", r.status_code)
                    self._warned_unreachable = True
        except Exception as exc:
            if not self._warned_unreachable:
                logger.warning("[warmer] Ollama unreachable: %s", exc)
                self._warned_unreachable = True
