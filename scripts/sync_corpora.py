#!/usr/bin/env python3
"""Fetch/update local clones of detection-rule corpuses (ADR-0006).

For each corpus in detection_corpora.yaml that has a `git:` remote, clone it (if
the local `path` is missing) or `git pull` it (if present). Uses your ambient git
authentication (SSH agent / credential.helper) — no credentials are stored here.

This is the ONLY networked step; build_detection_index.py is fully offline after.

Usage:
    python scripts/sync_corpora.py [--config detection_corpora.yaml]
"""
from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from pipeline.detection.registry import load_corpora  # noqa: E402
from pipeline.detection.sync import git_command  # noqa: E402


def _run(cmd: list[str]) -> bool:
    print("  $ " + " ".join(cmd))
    try:
        subprocess.run(cmd, check=True)
        return True
    except (subprocess.CalledProcessError, FileNotFoundError) as e:
        print(f"  ! failed: {e}")
        return False


def main() -> int:
    ap = argparse.ArgumentParser(description="Sync local clones of detection-rule corpuses.")
    ap.add_argument("--config", default=str(_ROOT / "detection_corpora.yaml"))
    args = ap.parse_args()

    corpora = load_corpora(args.config)
    if not corpora:
        print(f"[sync] no enabled corpora in {args.config}.")
        return 0

    ok = 0
    for corpus in corpora:
        name = corpus.get("name", "?")
        path = Path(corpus.get("path", ""))
        cmd = git_command(corpus)
        if cmd is None:
            print(f"[sync] {name}: no git remote — assuming '{path}' is managed manually — skipped")
            continue
        print(f"[sync] {name} → {path}")
        ok += int(_run(cmd))

    print(f"[sync] {ok}/{len(corpora)} corpora synced. Now run: python scripts/build_detection_index.py")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
