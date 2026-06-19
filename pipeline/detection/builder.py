"""Rebuild the detection-rule store from local corpus clones (ADR-0006/0007).

Shared by the CLI (scripts/build_detection_index.py) and the settings API so the
ingest logic lives in one place.
"""
from __future__ import annotations

import sqlite3
from pathlib import Path

from pipeline.detection.registry import _ADAPTERS, load_corpora
from pipeline.detection.store import corpus_counts, replace_corpus_rules


def rebuild_store(conn: sqlite3.Connection, config_path: str | Path) -> dict:
    """Parse every enabled corpus's local clone and replace its rules in the store.

    Returns a summary: rules written per corpus, corpora skipped (missing clone /
    unknown adapter), the grand total, and current per-corpus counts.
    """
    written: dict[str, int] = {}
    skipped: list[str] = []
    for corpus in load_corpora(config_path):
        name = corpus.get("name", "?")
        adapter = _ADAPTERS.get(corpus.get("adapter", ""))
        root = Path(corpus.get("path", ""))
        if adapter is None or not root.exists():
            skipped.append(name)
            continue
        rules = list(adapter.parse(root, corpus=name, license=corpus.get("license", "unknown")))
        written[name] = replace_corpus_rules(conn, name, rules)
    return {
        "written": written,
        "skipped": skipped,
        "total": sum(written.values()),
        "counts": corpus_counts(conn),
    }
