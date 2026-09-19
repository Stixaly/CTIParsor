#!/usr/bin/env python3
"""Propose — and with --apply, store — deny / promote rules grown from the
analysts' accept/reject decisions (ADR-0052).

Reads the job store (`DATABASE_URL`, as the API does)
and lists every (value, entity_type) the analysts keep rejecting (a `deny`
candidate: the stages stop proposing it) or keep accepting / typed in by
hand while no gazetteer knows it (a `promote` candidate: the Stage 2b
gazetteer learns it).  Nothing is written without --apply, and --apply
stores CANDIDATES: a row acts only once a person activates it
(PATCH /api/overrides/{id}, or --activate-all here for an operator who
wants the cron to be the person).

Usage:
    python -m scripts.promote_overrides                  # report only
    python -m scripts.promote_overrides --apply          # store as candidates
    python -m scripts.promote_overrides --apply --activate-all
    python -m scripts.promote_overrides --min-rejections 5 --min-jobs 3
    python -m scripts.promote_overrides --json
"""
from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from api.db import get_conn, init_db, now_iso  # noqa: E402
from pipeline.promotion import (  # noqa: E402
    DEFAULT_MIN_ACCEPTS,
    DEFAULT_MIN_JOBS,
    DEFAULT_MIN_REJECTIONS,
    DEFAULT_SHARE,
    Candidate,
    activate_all_candidates,
    apply_candidates,
    propose,
)


def _logs_to_stderr() -> None:
    """stdout is the report (a JSON document with --json); api.logging_config
    logs to stdout by default, so its console handler is moved off it."""
    for handler in logging.getLogger().handlers:
        if isinstance(handler, logging.StreamHandler) and getattr(handler, "stream", None) is sys.stdout:
            handler.setStream(sys.stderr)


def _print_table(candidates: list[Candidate]) -> None:
    if not candidates:
        print("No (value, entity_type) meets the deny or promote rule — nothing to propose.")
        return
    header = f"{'action':<8}{'entity_type':<14}{'term':<40}{'acc':>5}{'rej':>5}{'jobs':>5}  in store"
    print(header)
    print("-" * len(header))
    for c in candidates:
        print(f"{c.action:<8}{c.entity_type:<14}{c.display[:38]:<40}{c.accepted_count:>5}"
              f"{c.rejected_count:>5}{c.job_count:>5}  {c.existing_status or 'new'}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Grow the deny / promote lists from analyst decisions.")
    parser.add_argument("--min-rejections", type=int, default=DEFAULT_MIN_REJECTIONS,
                        help=f"rejections a deny candidate needs (default {DEFAULT_MIN_REJECTIONS})")
    parser.add_argument("--min-accepts", type=int, default=DEFAULT_MIN_ACCEPTS,
                        help=f"accepts a promote candidate needs (default {DEFAULT_MIN_ACCEPTS})")
    parser.add_argument("--min-jobs", type=int, default=DEFAULT_MIN_JOBS,
                        help=f"distinct reports either needs (default {DEFAULT_MIN_JOBS})")
    parser.add_argument("--share", type=float, default=DEFAULT_SHARE,
                        help=f"share of reviews that must agree (default {DEFAULT_SHARE})")
    parser.add_argument("--apply", action="store_true", help="store the candidates (status: candidate)")
    parser.add_argument("--activate-all", action="store_true",
                        help="with --apply: also activate every candidate row in the store")
    parser.add_argument("--json", action="store_true", help="print the candidates as JSON instead of a table")
    args = parser.parse_args()

    if min(args.min_rejections, args.min_accepts, args.min_jobs) < 1:
        parser.error("--min-rejections, --min-accepts and --min-jobs must be positive")
    if not 0.0 < args.share <= 1.0:
        parser.error("--share must be in (0, 1]")
    if args.activate_all and not args.apply:
        parser.error("--activate-all needs --apply")

    _logs_to_stderr()
    init_db()
    conn = get_conn()
    candidates = propose(conn, min_rejections=args.min_rejections, min_accepts=args.min_accepts,
                         min_jobs=args.min_jobs, share=args.share)
    written = apply_candidates(conn, candidates, now_iso()) if args.apply else 0
    activated = activate_all_candidates(conn, now_iso()) if args.activate_all else 0

    if args.json:
        print(json.dumps({"applied": args.apply, "written": written, "activated": activated,
                          "candidates": [c.as_dict() for c in candidates]}, indent=2))
    else:
        _print_table(candidates)
        if args.apply:
            print(f"\n{written} candidate row(s) written" + (f", {activated} activated." if args.activate_all
                                                            else "; activate them with PATCH /api/overrides/{id}."))
        elif candidates:
            print("\nDry run — re-run with --apply to store the candidates.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
