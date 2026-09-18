#!/usr/bin/env python3
"""Propose — and with --apply, store — NER confidence cutoffs calibrated from
the analysts' accept/reject decisions (ADR-0051).

Reads the job store (`DATABASE_URL` or `CTIPARSOR_DB_PATH`, as the API does),
fits an isotonic curve of P(accepted | score) per (source, entity_type) and
prints, for each, the cutoff at which the calibrated precision reaches the
target, next to the cutoff in force today.  Nothing is written without
--apply; the same report is served by POST /api/thresholds/recalibrate.

Usage:
    python -m scripts.calibrate_thresholds                 # report only
    python -m scripts.calibrate_thresholds --apply         # store the proposals
    python -m scripts.calibrate_thresholds --target-precision 0.85 --min-samples 100
    python -m scripts.calibrate_thresholds --json          # machine-readable
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from api.db import get_conn, init_db, now_iso  # noqa: E402
from pipeline.calibration import (  # noqa: E402
    DEFAULT_MIN_SAMPLES,
    DEFAULT_TARGET_PRECISION,
    Proposal,
    apply_proposals,
    calibrate,
)


def _fmt(x: float | None) -> str:
    return "  -  " if x is None else f"{x:.3f}"


def _print_table(proposals: list[Proposal]) -> None:
    if not proposals:
        print("No decided CyNER/GLiNER entities in the store — nothing to calibrate.")
        return
    header = (f"{'source':<8}{'entity_type':<16}{'n':>6}{'acc':>6}{'rej':>6}"
              f"{'current':>9}{'P@cur':>7}{'proposed':>10}{'P@prop':>8}{'R@prop':>8}  status")
    print(header)
    print("-" * len(header))
    for p in proposals:
        print(f"{p.source:<8}{p.entity_type:<16}{p.sample_size:>6}{p.accepted:>6}{p.rejected:>6}"
              f"{p.current:>9.3f}{_fmt(p.precision_at_current):>7}{_fmt(p.proposed):>10}"
              f"{_fmt(p.precision_at_proposed):>8}{_fmt(p.recall_at_proposed):>8}  {p.status}"
              + (f" (data says {p.unclamped:.3f})" if p.status == "above_auto_accept" else ""))


def main() -> int:
    parser = argparse.ArgumentParser(description="Calibrate NER confidence cutoffs from analyst decisions.")
    parser.add_argument("--target-precision", type=float, default=DEFAULT_TARGET_PRECISION,
                        help=f"calibrated precision a cutoff must reach (default {DEFAULT_TARGET_PRECISION})")
    parser.add_argument("--min-samples", type=int, default=DEFAULT_MIN_SAMPLES,
                        help=f"decisions needed before a cutoff is proposed (default {DEFAULT_MIN_SAMPLES})")
    parser.add_argument("--apply", action="store_true", help="store the proposals in model_thresholds")
    parser.add_argument("--json", action="store_true", help="print the proposals as JSON instead of a table")
    args = parser.parse_args()

    if not 0.0 < args.target_precision <= 1.0:
        parser.error("--target-precision must be in (0, 1]")
    if args.min_samples < 1:
        parser.error("--min-samples must be a positive integer")

    init_db()
    conn = get_conn()
    proposals = calibrate(conn, target_precision=args.target_precision, min_samples=args.min_samples)
    written = apply_proposals(conn, proposals, now_iso()) if args.apply else 0

    if args.json:
        print(json.dumps({"applied": args.apply, "written": written,
                          "proposals": [p.as_dict() for p in proposals]}, indent=2))
    else:
        _print_table(proposals)
        if args.apply:
            print(f"\n{written} cutoff(s) written to model_thresholds.")
        elif any(p.proposed is not None for p in proposals):
            print("\nDry run — re-run with --apply to store the proposals.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
