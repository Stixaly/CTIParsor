"""Process-wide counters for what the LLM stages actually got back (ADR-0060).

Every LLM failure in Stage 3 is caught and turned into an empty result, so that
one bad chunk never fails a report.  The price: a provider that refuses every
call, a model that answers nothing, or JSON that never parses all look exactly
like a model that found nothing.  These counters keep the four apart:

* provider_calls / provider_failures — the request itself (HTTP error, 404 on
  the model name, timeout after retries);
* provider_at_ceiling — answers the provider stopped at the output-token
  ceiling (finish_reason "length") instead of letting them end;
* extraction_ok / extraction_empty / extraction_invalid / extraction_provider_failed
  — one per Stage 3 extraction call, by what came back;
* rel_verification_* / ttp_verification_* — Stages 3d and 3f.  A 3d failure
  holds its claims for review (ADR-0082, `rel_verification_held` counts every
  held claim); a 3f verify-mode failure keeps its claims unverified.

The orchestrator reads a snapshot before and after Stage 3 and reports the
difference in the stage report.  Thread-safe: Stage 3 runs chunks in parallel.
"""
from __future__ import annotations

import threading
from typing import Any

_lock = threading.Lock()
_stats: dict[str, Any] = {"last_error": ""}
_local = threading.local()


def bump(key: str, n: int = 1) -> None:
    with _lock:
        _stats[key] = _stats.get(key, 0) + n


def record_call(error: str | None = None, *, at_ceiling: bool = False) -> None:
    """One provider request; `error` when it failed, `at_ceiling` when the
    provider stopped its answer at the output-token ceiling.  Both are also
    remembered per thread, so the caller can tell a failed request from an
    empty answer, and an answer that was cut from one that ended."""
    with _lock:
        _stats["provider_calls"] = _stats.get("provider_calls", 0) + 1
        if error is not None:
            _stats["provider_failures"] = _stats.get("provider_failures", 0) + 1
            _stats["last_error"] = error[:300]
        if at_ceiling:
            _stats["provider_at_ceiling"] = _stats.get("provider_at_ceiling", 0) + 1
    _local.last_failed = error is not None
    _local.last_at_ceiling = at_ceiling


def reset_last_call() -> None:
    """Forget this thread's last request, before making a new one."""
    _local.last_failed = False
    _local.last_at_ceiling = False


def last_call_failed() -> bool:
    """Did this thread's most recent provider request fail?"""
    return bool(getattr(_local, "last_failed", False))


def last_call_at_ceiling() -> bool:
    """Did the provider stop this thread's most recent answer at the
    output-token ceiling?"""
    return bool(getattr(_local, "last_at_ceiling", False))


def snapshot() -> dict[str, Any]:
    with _lock:
        return dict(_stats)


def delta(before: dict[str, Any], after: dict[str, Any]) -> dict[str, int]:
    """Counts added between two snapshots (numeric keys only)."""
    return {k: v - before.get(k, 0) for k, v in after.items()
            if isinstance(v, int) and v - before.get(k, 0)}
