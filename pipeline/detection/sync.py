"""Networked fetch of a corpus's local git clone (ADR-0006).

The ONLY place CTIParsor shells out to `git`. Shared by the CLI
(scripts/sync_corpora.py, which streams progress) and the settings API
"redownload" action (which captures output). Uses ambient git authentication
(SSH agent / credential.helper) — no credentials are stored or handled here, so
private corpora are intentionally CLI-only (see api/routes/settings.py).
"""
from __future__ import annotations

import subprocess
from pathlib import Path


def git_command(corpus: dict) -> list[str] | None:
    """The git command to fetch one corpus: `clone --depth 1` when the local
    `path` is missing, else `pull --ff-only`. Returns None when the corpus has no
    `git` remote (its path is managed manually)."""
    remote = corpus.get("git")
    if not remote:
        return None
    path = Path(corpus.get("path", ""))
    if path.exists():
        return ["git", "-C", str(path), "pull", "--ff-only"]
    path.parent.mkdir(parents=True, exist_ok=True)
    return ["git", "clone", "--depth", "1", remote, str(path)]


def sync_corpus(corpus: dict, *, timeout: int = 900) -> tuple[bool, str]:
    """Clone/pull one corpus, capturing output. Returns (ok, detail) where detail
    is git's message on success or the failure reason. Used by the API; the CLI
    streams instead (it builds the command with git_command directly)."""
    cmd = git_command(corpus)
    if cmd is None:
        return False, "no git remote — this corpus's path is managed manually"
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except (FileNotFoundError, subprocess.TimeoutExpired) as e:
        return False, str(e)
    if proc.returncode != 0:
        return False, (proc.stderr or proc.stdout or "git failed").strip()[:1000]
    return True, (proc.stdout or proc.stderr or "ok").strip()[:1000]
