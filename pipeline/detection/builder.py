"""Rebuild the detection-rule store from local corpus clones (ADR-0006/0007).

Shared by the CLI (scripts/build_detection_index.py) and the settings API so the
ingest logic lives in one place.
"""
from __future__ import annotations

import sqlite3
from pathlib import Path

from pipeline.detection.dedup import dedupe_store
from pipeline.detection.registry import _ADAPTERS, corpus_root, load_corpora
from pipeline.detection.store import corpus_counts, replace_corpus_rules


def rebuild_store(conn: sqlite3.Connection, config_path: str | Path) -> dict:
    """Parse every enabled corpus's local clone and replace its rules in the store,
    then run the cross-corpus dedup pass (ADR-0010).

    Returns a summary: rules written per corpus, corpora skipped (missing clone /
    unknown adapter), the grand total, the dedup result, and per-corpus counts
    (each now carrying a `canonical` figure alongside the raw `rules` total).
    """
    written: dict[str, int] = {}
    skipped: list[str] = []
    priority: dict[str, int] = {}
    for corpus in load_corpora(config_path):
        name = corpus.get("name", "?")
        priority[name] = int(corpus.get("priority", 1000))
        adapter = _ADAPTERS.get(corpus.get("adapter", ""))
        root = corpus_root(corpus)
        if adapter is None or not root.exists():
            skipped.append(name)
            continue
        rules = list(adapter.parse(root, corpus=name, license=corpus.get("license", "unknown")))
        written[name] = replace_corpus_rules(conn, name, rules)

    # Cross-corpus dedup runs once the whole store is rebuilt — it can't be done
    # per corpus (replace_corpus_rules sees only one corpus at a time).
    dedup = dedupe_store(conn, priority)
    return {
        "written": written,
        "skipped": skipped,
        "total": sum(written.values()),
        "dedup": dedup,
        "counts": corpus_counts(conn),
    }
