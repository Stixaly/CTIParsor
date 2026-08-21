#!/usr/bin/env python3
"""Report which pipeline stages and optional components are available.

Backs `make check`. This lives in a file rather than in a Makefile heredoc
because GNU Make runs every recipe line in its own shell, so the multi-line
heredoc it used to be never executed at all — `make check` failed with
"missing separator" from the day it was written.

Exit code 0 when every stage is available, 1 when something needs setup.
"""
from __future__ import annotations

import sqlite3
import sys
from pathlib import Path

GREEN = "\033[0;32m"
YELLOW = "\033[1;33m"
NC = "\033[0m"


def chk_import(name: str) -> bool:
    try:
        __import__(name)
        return True
    except ImportError:
        return False


def chk_file(path: str) -> bool:
    return Path(path).exists()


def detection_store() -> tuple[int, int] | None:
    """(rule count, rules with no recorded body size), or None if not built.

    The detection store is optional and lives in the database rather than on
    disk, so report what is actually in it — "the file exists" would say
    nothing, and a store that was ingested but never backfilled renders every
    size as 0 B in the coverage UI without failing anywhere (ADR-0022).
    """
    try:
        conn = sqlite3.connect("file:cti_stix.db?mode=ro", uri=True)
        names = {
            r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
        }
        if "detection_rules" not in names:
            return None
        total = conn.execute("SELECT COUNT(*) FROM detection_rules").fetchone()[0]
        if not total:
            return None
        if "rule_bytes" not in names:
            return total, total
        unmeasured = conn.execute(
            "SELECT COUNT(*) FROM detection_rules d WHERE NOT EXISTS "
            "(SELECT 1 FROM rule_bytes b WHERE b.rule_id = d.id)"
        ).fetchone()[0]
        return total, unmeasured
    except sqlite3.Error:
        return None


rows: list[tuple[str, bool, str]] = [
    ("Stage 1  — Document ingestion",      chk_import("pdfplumber"),   "pip install pdfplumber"),
    ("Stage 2  — Regex IoC extraction",    chk_import("iocextract"),   "pip install iocextract"),
    ("Stage 2b — Gazetteer NER",
     chk_file("pipeline/data/gazetteer.json"), "make mitre"),
    ("Stage 2c — Semantic TTP detection",
     chk_import("sentence_transformers"), "pip install sentence-transformers"),
    ("Stage 2c — Embedding cache",
     chk_file("pipeline/data/mitre_embeddings.npy"), "make build-indexes"),
    ("Stage 2d — CyNER NER",               chk_import("transformers"), "pip install transformers"),
    ("Stage 3  — LLM enrichment",
     chk_import("anthropic") or chk_import("openai"), "pip install anthropic"),
    ("Stage 3c — MITRE TTP normalization",
     chk_file("pipeline/data/mitre_index.json"), "make mitre"),
    ("Stage 4  — STIX bundle generation",  chk_import("stix2"),        "pip install stix2"),
    ("Stage 5  — STIX validation",
     chk_import("stix2validator"), "pip install stix2-validator"),
    ("Web API  — FastAPI backend",         chk_import("fastapi"),      "pip install fastapi"),
]

_store = detection_store()
rows.append((
    "Coverage  — detection-rule store" + (f" ({_store[0]:,} rules)" if _store else ""),
    _store is not None,
    "make corpora && make detection-index",
))
if _store and _store[1]:
    rows.append((
        f"Coverage  — rule sizes ({_store[1]:,} rules unmeasured)",
        False,
        "make backfill-rules",
    ))

all_ok = True
for label, ok, fix in rows:
    if ok:
        print(f"  {GREEN}✔{NC}  {label}")
    else:
        print(f"  {YELLOW}–{NC}  {label}   →  {fix}")
        all_ok = False

print()
if all_ok:
    print(f"  {GREEN}All pipeline stages available.{NC}")
else:
    print(f"  {YELLOW}Some stages need additional setup (see above).{NC}")

sys.exit(0 if all_ok else 1)
