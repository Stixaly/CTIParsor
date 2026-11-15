"""Memory limit of the container this process runs in, read from cgroup.

Advisory only: nothing here sets a limit.  The worker uses it to warn when
WORKER_MAX_CONCURRENT asks for more reports than the container can hold
(ADR-0037).  A limit that cannot be read is no limit at all: the functions
return None and never raise.
"""
from __future__ import annotations

from pathlib import Path

from api.logging_config import get_logger

logger = get_logger(__name__)

CGROUP_ROOT = Path("/sys/fs/cgroup")
# Peak memory of one running report, measured in ADR-0037 (mostly GLiNER).
# GB here is Docker's unit (the "g" of CTI_WORKER_MEMORY): GiB.
REPORT_MEMORY_GB = 4.4
_GIB = 1024**3
# cgroup v1 writes "no limit" as a page-aligned number near 2**63: any value this large is unlimited.
_V1_UNLIMITED_FROM = 1 << 50


def memory_limit_bytes(root: Path = CGROUP_ROOT) -> int | None:
    """The container's memory limit in bytes, or None when there is none or it cannot be read.

    cgroup v2 first (`memory.max`, where "max" means unlimited), then cgroup v1
    (`memory/memory.limit_in_bytes`).  `root` is the cgroup mount point.
    """
    v2 = _read(root / "memory.max")
    if v2 is not None:
        return _parse(v2)
    v1 = _read(root / "memory" / "memory.limit_in_bytes")
    if v1 is not None:
        return _parse(v1)
    logger.debug("No cgroup memory limit readable under %s", root)
    return None


def warn_if_memory_short(max_concurrent: int, *, root: Path = CGROUP_ROOT) -> None:
    """Log a warning when the container limit is below `max_concurrent` reports (ADR-0037).

    Warns only: `max_concurrent` is the operator's value and is never changed.
    No limit, or a limit that cannot be read, is silence.
    """
    limit = memory_limit_bytes(root)
    if limit is None:
        return
    needed = max_concurrent * REPORT_MEMORY_GB * _GIB
    if limit < needed:
        logger.warning(
            "WORKER_MAX_CONCURRENT=%d needs about %.1f GB for its reports (ADR-0037), but the container's "
            "memory limit is %.1f GB: the OOM killer may stop a report. Lower WORKER_MAX_CONCURRENT or "
            "raise the container's memory limit.",
            max_concurrent, needed / _GIB, limit / _GIB,
        )


def _read(path: Path) -> str | None:
    try:
        return path.read_text(encoding="ascii").strip()
    except (OSError, ValueError):
        return None


def _parse(raw: str) -> int | None:
    try:
        value = int(raw)
    except ValueError:  # "max" (cgroup v2: no limit) or anything that is not a number
        return None
    if value <= 0 or value >= _V1_UNLIMITED_FROM:
        return None
    return value
