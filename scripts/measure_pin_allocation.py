#!/usr/bin/env python3
"""Measure pin-edge allocation under sequential vs fair-share policies.

This read-only harness replays every stored job under its real relationship
policy, first in legacy ``sequential`` mode (first-come-first-served) and then
in ``fair-share`` mode, and prints the per-rule allocation table plus the
delta between the two modes.

Usage:
    python scripts/measure_pin_allocation.py [--db cti_stix.db] [--job JOB_ID]

The database is opened strictly read-only; neither the database nor the
filesystem is modified.
"""

from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from pathlib import Path

_ROOT = Path(__file__).parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from models.schemas import EntityType, RawEntity  # noqa: E402
from pipeline.stage3_llm import LLMEnrichmentResult  # noqa: E402
from pipeline.stage4_stix_mapping import build_stix_bundle  # noqa: E402


def _open_ro(db_path: str) -> sqlite3.Connection:
    """Open the SQLite database strictly in read-only mode via a URI."""
    return sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)


def _load_policy(conn: sqlite3.Connection) -> dict:
    """Load the relationship policy from the database.

    Returns the parsed policy dict, or a safe default if the row is absent
    or the JSON is unreadable.
    """
    row = conn.execute(
        "SELECT policy_json FROM relationship_policy WHERE id = 1"
    ).fetchone()
    if row is None or not row[0]:
        return {"version": 1, "global": "enforce", "rules": []}
    try:
        parsed = json.loads(row[0])
        if isinstance(parsed, dict):
            return parsed
    except Exception:
        pass
    return {"version": 1, "global": "enforce", "rules": []}


def _job_ids(conn: sqlite3.Connection) -> list[str]:
    """Return job ids that have a stored LLM result, ordered by creation time."""
    rows = conn.execute(
        "SELECT id FROM jobs WHERE llm_result_json IS NOT NULL ORDER BY created_at"
    ).fetchall()
    return [r[0] for r in rows]


def _rebuild(
    conn: sqlite3.Connection, job_id: str, policy: dict
) -> tuple[object, str] | None:
    """Rebuild the STIX bundle for a job under the given policy.

    Returns a ``(bundle, filename)`` tuple, or ``None`` if the job cannot be
    replayed.
    """
    row = conn.execute(
        "SELECT id, original_filename, report_text, llm_result_json "
        "FROM jobs WHERE id = ?", (job_id,),
    ).fetchone()
    if row is None:
        return None
    job_id_val, filename, report_text, llm_raw = row
    if not llm_raw:
        return None
    try:
        llm_result = LLMEnrichmentResult.model_validate_json(llm_raw)
    except Exception:
        try:
            llm_result = LLMEnrichmentResult.model_validate(json.loads(llm_raw))
        except Exception:
            return None
    raw_entities: list[RawEntity] = []
    for value, etype, context, confidence, mitre_id, source in conn.execute(
        "SELECT value, entity_type, context, confidence, mitre_id, source "
        "FROM entities WHERE job_id = ?", (job_id_val,),
    ):
        try:
            raw_entities.append(RawEntity(
                value=value, entity_type=EntityType(etype),
                context=context or "", confidence=confidence if confidence is not None else 1.0,
                mitre_id=mitre_id, source=source or "ioc",
            ))
        except Exception:
            continue
    bundle = build_stix_bundle(
        raw_entities, llm_result, filename or job_id_val,
        report_text=report_text or "", original_filename=filename or "",
        relationship_policy=policy,
    )
    return bundle, (filename or job_id_val)


def _pin_stats_of(bundle: object) -> dict | None:
    """Extract the ``x_synthesis_stats["pin"]`` dict from the bundle's Report.

    Returns ``None`` if the Report is missing, the custom property is absent
    (e.g. a bundle produced by an older version), or the ``pin`` key is not
    present. Never raises.
    """
    for obj in bundle.objects:  # type: ignore[union-attr]
        if getattr(obj, "type", None) != "report":
            continue
        stats = None
        if hasattr(obj, "get"):
            stats = obj.get("x_synthesis_stats")
        else:
            stats = getattr(obj, "x_synthesis_stats", None)
        if not isinstance(stats, dict):
            return None
        pin = stats.get("pin")
        if isinstance(pin, dict):
            return pin
        return None
    return None


def _print_table(title: str, stats: dict) -> None:
    """Print the per-rule allocation table for a given mode."""
    budget = stats.get("budget", 0)
    mode = stats.get("mode", "fair-share")
    total_emitted = stats.get("total_emitted", 0)
    total_candidates = stats.get("total_candidates", 0)
    total_truncated = stats.get("total_truncated", 0)
    # `blocked` is absent on bundles built before ADR-0027 — treat as optional.
    total_blocked = stats.get("total_blocked", 0)
    print(f"{title}  budget={budget} mode={mode}  "
          f"emitted={total_emitted}/{total_candidates} truncated={total_truncated} "
          f"blocked={total_blocked}")
    print(f"{'cand':>6} {'emit':>6} {'trunc':>6} {'blockd':>7}  rule")
    for rule in stats.get("rules", []):
        cand = rule.get("candidates", 0)
        emit = rule.get("emitted", 0)
        trunc = rule.get("truncated", 0)
        blocked = rule.get("blocked", 0)
        name = rule.get("rule", "")
        print(f"{cand:>6} {emit:>6} {trunc:>6} {blocked:>7}  {name}")


def main() -> int:
    """Entry point: replay jobs and compare sequential vs fair-share allocation."""
    parser = argparse.ArgumentParser(
        description="Measure pin-edge allocation under sequential vs fair-share."
    )
    parser.add_argument("--db", default="cti_stix.db",
                        help="Path to the SQLite database (default: cti_stix.db)")
    parser.add_argument("--job", default=None,
                        help="Restrict measurement to a single job id")
    args = parser.parse_args()

    conn = _open_ro(args.db)
    try:
        policy = _load_policy(conn)
        if args.job is not None:
            job_ids = [args.job]
        else:
            job_ids = _job_ids(conn)

        for job_id in job_ids:
            print(f"=== job {job_id} ===")

            # Sequential mode
            pol_seq = dict(policy)
            pol_seq["pin_budget_mode"] = "sequential"
            result_seq = _rebuild(conn, job_id, pol_seq)
            if result_seq is None:
                print(f"  WARNING: could not replay job {job_id}; skipping.")
                continue
            bundle_seq, _ = result_seq
            stats_seq = _pin_stats_of(bundle_seq)
            if stats_seq is None:
                print(f"  WARNING: no pin stats for job {job_id} (sequential).")
                continue
            _print_table("SEQUENTIAL", stats_seq)

            # Fair-share mode
            pol_fs = dict(policy)
            pol_fs["pin_budget_mode"] = "fair-share"
            result_fs = _rebuild(conn, job_id, pol_fs)
            if result_fs is None:
                print(f"  WARNING: could not replay job {job_id}; skipping.")
                continue
            bundle_fs, _ = result_fs
            stats_fs = _pin_stats_of(bundle_fs)
            if stats_fs is None:
                print(f"  WARNING: no pin stats for job {job_id} (fair-share).")
                continue
            _print_table("FAIR-SHARE", stats_fs)

            # Delta: count rules that go from 0 emitted to >0 emitted
            seq_rules = {r.get("rule"): r.get("emitted", 0)
                         for r in stats_seq.get("rules", [])}
            fs_rules = {r.get("rule"): r.get("emitted", 0)
                        for r in stats_fs.get("rules", [])}
            seq_served = sum(1 for v in seq_rules.values() if v > 0)
            fs_served = sum(1 for v in fs_rules.values() if v > 0)
            newly_served = sum(
                1 for rule, v in fs_rules.items()
                if v > 0 and seq_rules.get(rule, 0) == 0
            )
            print(f"DELTA  regles servies: sequential={seq_served} "
                  f"fair-share={fs_served} (+{newly_served} sorties du silence)")
            print()
    finally:
        conn.close()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
