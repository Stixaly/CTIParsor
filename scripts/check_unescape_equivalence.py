"""A/B the unescape refactor on real corpus data.

The stored `rule_atoms` answer the wrong question — they reflect whenever
`build_rule_atoms.py` last ran, not the commit under test. This compares the
OLD `_unescape_content` / `_unescape_literal` bodies (pasted verbatim below,
straight from git) against the shared `textutil.unescape` the modules now call,
over every string literal the real corpus actually contains.
"""
from __future__ import annotations

import os
import sqlite3
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pipeline.detection.suricata_atoms import _SURICATA_ESCAPES, _unescape_content, parse_options
from pipeline.detection.yara_atoms import _YARA_ESCAPES, _unescape_literal, split_rules


def old_unescape(value: str, table: dict[str, str]) -> str:
    """The pre-refactor body, identical in both modules bar the table name."""
    if not isinstance(value, str):
        return ""
    parts: list[str] = []
    i = 0
    n = len(value)
    while i < n:
        if value[i] == "\\" and i + 1 < n:
            nxt = value[i + 1]
            if nxt in table:
                parts.append(table[nxt])
            else:
                parts.append("\\")
                parts.append(nxt)
            i += 2
        else:
            parts.append(value[i])
            i += 1
    return "".join(parts)


def main() -> int:
    db = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "cti_stix.db")
    conn = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    try:
        checked = 0
        mismatches: list[tuple[str, str, str, str]] = []

        # --- Suricata: every content: option value in the corpus -------------
        rows = conn.execute(
            "SELECT id, raw FROM detection_rules WHERE format='suricata' AND raw != ''"
        ).fetchall()
        for rule_id, raw in rows:
            if not isinstance(raw, str):
                continue
            o, c = raw.find("("), raw.rfind(")")
            if o == -1 or c <= o:
                continue
            for key, value in parse_options(raw[o + 1:c]):
                if not isinstance(value, str) or not value:
                    continue
                checked += 1
                new = _unescape_content(value)
                old = old_unescape(value, _SURICATA_ESCAPES)
                if new != old:
                    mismatches.append((rule_id, value, old, new))
        print(f"suricata: {len(rows)} rules, {checked} option values checked")

        # --- YARA: every text string literal in the corpus -------------------
        before = checked
        rows = conn.execute(
            "SELECT id, raw FROM detection_rules WHERE format='yara' AND raw != ''"
        ).fetchall()
        for rule_id, raw in rows:
            if not isinstance(raw, str):
                continue
            try:
                rules = split_rules(raw)
            except Exception:
                continue
            for r in rules:
                for _ident, kind, value in r.strings:
                    if kind != "text" or not isinstance(value, str) or not value:
                        continue
                    checked += 1
                    new = _unescape_literal(value)
                    old = old_unescape(value, _YARA_ESCAPES)
                    if new != old:
                        mismatches.append((rule_id, value, old, new))
        print(f"yara:     {len(rows)} rules, {checked - before} string literals checked")

        print(f"\nTOTAL: {checked} real literals, {len(mismatches)} mismatches")
        for rule_id, value, old, new in mismatches[:10]:
            print(f"  {rule_id}\n    in : {value!r}\n    old: {old!r}\n    new: {new!r}")
        if not mismatches:
            print("OK - the refactor is a no-op on every literal the corpus contains.")
        return 1 if mismatches else 0
    finally:
        conn.close()


if __name__ == "__main__":
    sys.exit(main())
