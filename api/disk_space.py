"""Refuse new uploads while the disk under the uploads directory is nearly full (ADR-0097 item 20).

`UPLOAD_MIN_FREE_MB` (default 1024) is the free space an upload needs before
any byte of it is written.  The check reads the disk that holds
`uploads_dir()` (api/paths.py).  A value of 0 turns the check off.
"""
from __future__ import annotations

import shutil
from pathlib import Path

from fastapi import HTTPException

from api.paths import uploads_dir
from pipeline.env_flags import env_int

_MIB = 1024 * 1024


def upload_min_free_mb() -> int:
    """The free disk space, in MB, that an upload needs: UPLOAD_MIN_FREE_MB, 1024 by default."""
    return env_int("UPLOAD_MIN_FREE_MB", default=1024)


def _existing_ancestor(path: Path) -> Path:
    """The directory `shutil.disk_usage` can read: `uploads_dir()` may not exist yet."""
    candidate = path
    while not candidate.exists() and candidate != candidate.parent:
        candidate = candidate.parent
    return candidate


def refuse_if_disk_is_short() -> None:
    """Raise 507 when the free space under the uploads directory is below the minimum."""
    minimum_mb = upload_min_free_mb()
    free_mb = shutil.disk_usage(_existing_ancestor(uploads_dir())).free // _MIB
    if free_mb < minimum_mb:
        raise HTTPException(
            507,
            f"Insufficient Storage: {free_mb} MB free where uploads are stored, at least {minimum_mb} MB "
            f"is needed (UPLOAD_MIN_FREE_MB). Free disk space, or lower UPLOAD_MIN_FREE_MB, then retry.",
        )
