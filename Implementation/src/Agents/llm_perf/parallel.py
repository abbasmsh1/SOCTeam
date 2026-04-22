"""
Concurrent execution helper for independent LLM calls.

LangGraph nodes are sync, so we use a thread pool rather than asyncio.
The typical win: Red team + Blue team in the War Room workflow are
independent — running them in parallel roughly halves that step's wall
time (each Ollama round-trip is ~15-25s at llama3.2 sizes).

Usage:
    red, blue = run_concurrent([
        lambda: red_team_node(state),
        lambda: blue_team_node(state),
    ])

Errors in one branch do not cancel the others; the first exception is
re-raised after all futures complete so nothing is silently dropped.
"""

from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Callable, List, Optional, Sequence

logger = logging.getLogger(__name__)


def run_concurrent(
    callables: Sequence[Callable[[], Any]],
    timeout: float = 120.0,
    max_workers: Optional[int] = None,
) -> List[Any]:
    """
    Run independent callables concurrently and return results in order.

    - timeout is per-future (not aggregate).
    - If any callable raises, its exception is captured and the first one
      encountered is re-raised after all workers finish.
    - Preserves input order so callers can unpack like tuples.
    """
    if not callables:
        return []
    n = len(callables)
    workers = max_workers or n

    results: List[Any] = [None] * n
    errors: List[Optional[BaseException]] = [None] * n

    with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="llm-par") as ex:
        future_to_idx = {ex.submit(fn): i for i, fn in enumerate(callables)}
        for fut in as_completed(future_to_idx, timeout=timeout * n):
            idx = future_to_idx[fut]
            try:
                results[idx] = fut.result(timeout=timeout)
            except BaseException as exc:  # noqa: BLE001
                errors[idx] = exc
                logger.warning("[parallel] branch %d failed: %s", idx, exc)

    for err in errors:
        if err is not None:
            raise err
    return results
