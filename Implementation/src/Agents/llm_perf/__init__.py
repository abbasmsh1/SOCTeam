"""
LLM performance layer.

Four cheap wins that collectively cut SOC workflow latency 40-70%:

  cache.py      — hash(messages + model) -> response LRU + optional disk
  compression.py - strip verbose JSON dumps before sending to the LLM
  warmer.py     — background Ollama keep-alive so the model stays resident
  parallel.py   — helpers to run multiple LLM calls concurrently

Each is independently toggleable via env:
    IDS_LLM_CACHE=true|false       (default true)
    IDS_LLM_COMPRESS=true|false    (default true)
    IDS_LLM_WARMER=true|false      (default true)
"""

from .cache import CachingLLM, get_cache_stats, clear_cache  # noqa: F401
from .compression import compress_prompt, summarise_json     # noqa: F401
from .warmer import OllamaWarmer                              # noqa: F401
from .parallel import run_concurrent                          # noqa: F401
