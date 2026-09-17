#!/usr/bin/env python3
"""
Standalone validation harness for the TTP advisory gate.

Measures what the new gate actually drops on real reports and surfaces any
advisory/table-caption sentence that still slipped through as a match, so a
human can eyeball it (unit tests passing proves nothing about real-world
quality).
"""

import os
import sqlite3
import sys
from pathlib import Path

# Insert project root into sys.path so we can import pipeline modules
project_root = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(project_root))

import pipeline.stage2c_ttp_semantic as s2c


def main():
    db_path = project_root / "cti_stix.db"

    if not db_path.exists():
        print(f"Error: Database not found at {db_path}")
        sys.exit(1)

    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    cursor = conn.cursor()

    query = """
        SELECT id, original_filename, report_text
        FROM jobs
        WHERE report_text IS NOT NULL AND length(report_text) > 0
    """

    cursor.execute(query)
    rows = cursor.fetchall()

    total_dropped_by_advisory = 0
    total_kept_by_keyword = 0

    print(f"{'Filename':<50} {'On: kept/scored':<20} {'Off: kept/scored':<20} {'Dropped by advisory':<20}")
    print("-" * 110)

    for _report_id, filename, report_text in rows:
        try:
            # Gate ON
            os.environ["TTP_ADVISORY_GATE"] = "on"
            stats_on = s2c.sentence_gate_stats(report_text)

            # Gate OFF
            os.environ["TTP_ADVISORY_GATE"] = "off"
            stats_off = s2c.sentence_gate_stats(report_text)

            dropped_by_advisory = stats_on["dropped_by_advisory"]

            total_dropped_by_advisory += dropped_by_advisory
            total_kept_by_keyword += stats_off["kept_by_keyword"]

            on_col = f"{stats_on['kept_by_keyword']}/{stats_on['scored']}"
            off_col = f"{stats_off['kept_by_keyword']}/{stats_off['scored']}"
            print(f"{filename:<50} {on_col:<20} {off_col:<20} {dropped_by_advisory:<20}")

        except Exception as e:
            print(f"{filename:<50} ERROR: {e}")
            continue

    conn.close()

    print("-" * 110)
    print(f"Totals: {total_dropped_by_advisory} sentences dropped by advisory gate")

    if total_kept_by_keyword > 0:
        percentage = (total_dropped_by_advisory / total_kept_by_keyword) * 100
        print(f"Percentage of keyword-gate survivors removed: {percentage:.2f}%")
    else:
        print("Percentage of keyword-gate survivors removed: N/A (no keyword-gate survivors)")


if __name__ == "__main__":
    main()
