#!/usr/bin/env python3
"""
Validation harness for artifact-based detection coverage.

Usage:
    python scripts/validate_artifact_coverage.py [--db cti_stix.db]
"""

import argparse
import sqlite3
import sys
import time
from pathlib import Path

# Add project root to sys.path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from pipeline.detection.artifacts import coverage_for_job


def main():
    parser = argparse.ArgumentParser(description="Validate artifact coverage")
    parser.add_argument("--db", default="cti_stix.db", help="Path to SQLite database")
    args = parser.parse_args()

    # Connect read-only
    conn = sqlite3.connect(f"file:{args.db}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row

    # Get all jobs
    cursor = conn.execute(
        "SELECT id, original_filename FROM jobs ORDER BY created_at"
    )
    jobs = cursor.fetchall()

    if not jobs:
        print("No jobs found in database.")
        conn.close()
        return

    # Aggregate stats
    total_artifacts = 0
    total_covered = 0
    total_weak = 0
    total_uncovered = 0
    total_excluded = 0
    tier_stats = {1: {"artifacts": 0, "covered": 0}, 2: {"artifacts": 0, "covered": 0},
                  3: {"artifacts": 0, "covered": 0}, 4: {"artifacts": 0, "covered": 0}}

    for job in jobs:
        job_id = job["id"]
        filename = job["original_filename"]

        print(f"\n=== Report: {filename} (job: {job_id}) ===")

        # Time the coverage calculation
        start_time = time.time()
        result = coverage_for_job(conn, job_id)
        elapsed = time.time() - start_time

        # Print totals
        totals = result["totals"]
        print(f"Totals: artifacts={totals['artifacts']} covered={totals['covered']} "
              f"weak={totals['weak']} uncovered={totals['uncovered']} "
              f"excluded={totals['excluded']}")

        # Print by tier
        print("\nBy Tier:")
        for tier_info in result["by_tier"]:
            tier = tier_info["tier"]
            label = tier_info["label"]
            artifacts = tier_info["artifacts"]
            covered = tier_info["covered"]
            weak = tier_info["weak"]
            uncovered = tier_info["uncovered"]
            print(f"  tier {tier} {label:<12} artifacts={artifacts}  "
                  f"covered={covered}  weak={weak}  uncovered={uncovered}")

            # Update aggregate stats
            tier_stats[tier]["artifacts"] += artifacts
            tier_stats[tier]["covered"] += covered

        # Update aggregate stats
        total_artifacts += totals["artifacts"]
        total_covered += totals["covered"]
        total_weak += totals["weak"]
        total_uncovered += totals["uncovered"]
        total_excluded += totals["excluded"]

        # Print all artifacts
        print("\nArtifacts:")
        print(f"  {'score':<6} {'tier':<12} {'class':<10} {'df':<6} {'excluded':<12} {'display':<50} {'evidence'}")
        print("  " + "-" * 100)

        for artifact in result["artifacts"]:
            score = artifact["score"]
            tier_label = artifact["tier_label"]
            artifact_class = artifact["class"]
            df = artifact["df"]
            excluded = artifact["excluded"] or "-"
            display = artifact["display"][:50]

            # Get first evidence if score > 0
            evidence_str = ""
            if score > 0 and artifact["evidence"]:
                first_ev = artifact["evidence"][0]
                evidence_str = f"<- {first_ev['corpus']}/{first_ev['field']}"

            print(f"  {score:<6} {tier_label:<12} {artifact_class:<10} {df:<6} "
                  f"{excluded:<12} {display:<50} {evidence_str}")

        # Print timing
        print(f"\nTime: {elapsed:.3f}s")

    # Print aggregate summary
    print("\n" + "=" * 80)
    print("AGGREGATE SUMMARY")
    print("=" * 80)
    print(f"Total artifacts: {total_artifacts}")
    print(f"Covered (score >= 2): {total_covered}")
    print(f"Weak (score == 1): {total_weak}")
    print(f"Uncovered (score == 0): {total_uncovered}")
    print(f"Excluded: {total_excluded}")

    print("\nCoverage by Tier:")
    for tier in [1, 2, 3, 4]:
        stats = tier_stats[tier]
        artifacts = stats["artifacts"]
        covered = stats["covered"]
        pct = (covered / artifacts * 100) if artifacts > 0 else 0.0
        print(f"  Tier {tier}: {artifacts} artifacts, {covered} covered ({pct:.1f}%)")

    conn.close()


if __name__ == "__main__":
    main()
