#!/usr/bin/env python3
"""Measure the two Stage 2c recall caps on real reports -- ADR-0023 Phase 2.

Stage 2c discards sentences at two points before a single embedding is computed:
the TTP keyword allow-list decides which sentences are embedded at all, and
_MAX_CANDIDATES strided-samples whatever survives.  Neither was instrumented, so
neither could be priced against a baseline.  This script loads no model.

Usage:
  python scripts/probe_ttp_recall_caps.py
  python scripts/probe_ttp_recall_caps.py --dir corpora/reports --show-dropped 6
  python scripts/probe_ttp_recall_caps.py --gate-off
"""
import argparse
import os
import sqlite3
import sys
from pathlib import Path

_ROOT = Path(__file__).parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from pipeline.stage2c_ttp_semantic import (  # noqa: E402
    _MAX_CANDIDATES,
    sentence_gate_stats,
)


def load_reports_from_db(db_path: Path) -> list[tuple[str, str]]:
    """Load reports from SQLite database."""
    reports = []
    if not db_path.exists():
        print(f"Warning: Database {db_path} not found.", file=sys.stderr)
        return reports

    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT id, original_filename, report_text FROM jobs")
        rows = cursor.fetchall()
        conn.close()

        for row in rows:
            job_id, filename, report_text = row
            if isinstance(report_text, str) and report_text:
                reports.append((filename or f"job_{job_id}", report_text))

    except Exception as e:
        print(f"Error reading database: {e}", file=sys.stderr)

    return reports


def load_reports_from_dir(dir_path: Path) -> list[tuple[str, str]]:
    """Load reports from directory."""
    reports = []
    if not dir_path.exists():
        return reports

    for ext in ["*.txt", "*.md"]:
        for file_path in dir_path.glob(ext):
            try:
                text = file_path.read_text(encoding="utf-8")
                reports.append((file_path.name, text))
            except Exception as e:
                print(f"Error reading {file_path}: {e}", file=sys.stderr)

    return reports


def print_table(reports: list[tuple[str, str]], show_dropped: int = 0):
    """Print the measurement table."""
    total_sent = 0
    total_kept = 0
    total_scored = 0
    total_drop_kw = 0
    total_drop_cap = 0

    # Header
    print(f"{'report':<30} {'sent':>8} {'kept':>8} {'scored':>8} "
          f"{'drop_kw':>8} {'drop_cap':>8} {'kept%':>7} {'scored%':>7}")

    for filename, text in reports:
        stats = sentence_gate_stats(text)

        sent = stats["sentences_total"]
        kept = stats["kept_by_keyword"]
        scored = stats["scored"]
        drop_kw = stats["dropped_by_keyword"]
        drop_cap = stats["dropped_by_cap"]

        kept_pct = (kept / sent * 100) if sent > 0 else 0.0
        scored_pct = (scored / sent * 100) if sent > 0 else 0.0

        print(f"{filename[:30]:<30} {sent:>8} {kept:>8} {scored:>8} "
              f"{drop_kw:>8} {drop_cap:>8} {kept_pct:>7.1f} {scored_pct:>7.1f}")

        total_sent += sent
        total_kept += kept
        total_scored += scored
        total_drop_kw += drop_kw
        total_drop_cap += drop_cap

        if show_dropped > 0:
            # Get dropped sentences
            from pipeline.stage2c_ttp_semantic import _has_ttp_keyword, _split_sentences
            sentences = _split_sentences(text)
            dropped = [s for s in sentences if not _has_ttp_keyword(s)]
            for i, s in enumerate(dropped[:show_dropped]):
                print(f"  Dropped: {s[:110]}")

    # Total line
    total_kept_pct = (total_kept / total_sent * 100) if total_sent > 0 else 0.0
    total_scored_pct = (total_scored / total_sent * 100) if total_sent > 0 else 0.0

    print(f"{'TOTAL':<30} {total_sent:>8} {total_kept:>8} {total_scored:>8} "
          f"{total_drop_kw:>8} {total_drop_cap:>8} "
          f"{total_kept_pct:>7.1f} {total_scored_pct:>7.1f}")

    # Conclusion
    pct_drop_kw = (total_drop_kw / total_sent * 100) if total_sent > 0 else 0.0
    print(f"\nKeyword gate discards {total_drop_kw} of {total_sent} sentences "
          f"({pct_drop_kw:.1f}%) before any embedding is computed.")
    print(f"Candidate cap (_MAX_CANDIDATES={_MAX_CANDIDATES}) discards a further "
          f"{total_drop_cap} sentence(s).")

    return total_scored


def main():
    parser = argparse.ArgumentParser(description="Probe TTP recall caps")
    parser.add_argument("--db", type=str, default="cti_stix.db", help="Path to SQLite DB")
    parser.add_argument("--dir", type=str, default=None, help="Directory with .txt/.md files")
    parser.add_argument("--show-dropped", type=int, default=0, help="Show N dropped sentences")
    parser.add_argument("--gate-off", action="store_true", help="Run with keyword gate off")

    args = parser.parse_args()

    reports = []

    # Load from DB
    if args.db != "none":
        db_path = Path(args.db)
        reports.extend(load_reports_from_db(db_path))

    # Load from dir
    if args.dir:
        dir_path = Path(args.dir)
        reports.extend(load_reports_from_dir(dir_path))

    if not reports:
        print("No reports found.", file=sys.stderr)
        sys.exit(1)

    if args.gate_off:
        print("gate ON")
        on_scored = print_table(reports, args.show_dropped)

        # Set gate off
        prev_val = os.environ.get("TTP_KEYWORD_GATE")
        os.environ["TTP_KEYWORD_GATE"] = "off"
        try:
            print("\ngate OFF")
            off_scored = print_table(reports, args.show_dropped)
        finally:
            if prev_val is not None:
                os.environ["TTP_KEYWORD_GATE"] = prev_val
            else:
                os.environ.pop("TTP_KEYWORD_GATE", None)

        print(f"\nGate ON scored {on_scored} sentences; gate OFF scored "
              f"{off_scored} — the gate is worth {off_scored - on_scored} "
              f"additional sentences of retrieval surface.")
    else:
        print_table(reports, args.show_dropped)


if __name__ == "__main__":
    main()
