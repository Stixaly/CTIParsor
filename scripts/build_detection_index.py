#!/usr/bin/env python3
"""Build the detection-rule store from local corpus clones (ADR-0006).

Reads detection_corpora.yaml, parses each enabled corpus with its adapter, and
upserts the rules into the SQLite detection_rules / rule_techniques tables.

Run scripts/sync_corpora.py first to fetch/update the local clones. This script
is offline — it only reads local files.

Usage:
    python scripts/build_detection_index.py [--config detection_corpora.yaml]
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from api.db import get_conn, init_db  # noqa: E402
from pipeline.detection.builder import rebuild_store  # noqa: E402
from pipeline.detection.registry import load_corpora  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser(description="Build the detection-rule store from local corpus clones.")
    ap.add_argument("--config", default=str(_ROOT / "detection_corpora.yaml"))
    args = ap.parse_args()

    init_db()
    conn = get_conn()

    if not load_corpora(args.config):
        print(f"[build] no enabled corpora in {args.config} (or its .local overlay) — nothing to do.")
        print("[build] run scripts/sync_corpora.py first to fetch the clones.")
        return 0

    summary = rebuild_store(conn, args.config)
    for name, n in summary["written"].items():
        print(f"[build] {name}: {n} rules")
    if summary["skipped"]:
        print(f"[build] skipped (missing clone / unknown adapter): {', '.join(summary['skipped'])}")

    print("─" * 50)
    for row in summary["counts"]:
        print(f"  {row['corpus']:<28} {row['rules']:>6} rules  ({row['license']})")
    print(f"[build] done — {summary['total']} rules across {len(summary['written'])} corpora.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
