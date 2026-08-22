"""Audit edge provenance in STIX bundles.

This script measures the proportion of relationship edges that carry a
provenance label (``x_evidence_label``) and which label is used. It is the
before/after metric for ADR-0024: on a real report, 872 of 1140 edges were
unlabelled.

The script is READ-ONLY. It does not re-execute anything, does not modify
anything, and does not call any model or API.

Usage:
    python scripts/audit_edge_provenance.py --db cti_stix.db
    python scripts/audit_edge_provenance.py --db cti_stix.db --job 42 --show-unlabelled 5
"""

import argparse
import json
import sqlite3
import sys
from collections import Counter
from pathlib import Path


def _load_jobs(db_path: Path) -> list[tuple[str, str, dict | None, dict | None]]:
    """Return (job_id, filename, bundle, run_config) for every job with a bundle."""
    if not db_path.exists():
        print(f"Error: database file not found: {db_path}", file=sys.stderr)
        sys.exit(1)

    conn = sqlite3.connect(db_path)
    try:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT id, original_filename, bundle_json, run_config_json FROM jobs"
        )
        rows = cursor.fetchall()
    finally:
        conn.close()

    jobs: list[tuple[str, str, dict | None, dict | None]] = []
    for row in rows:
        job_id, filename, bundle_json, run_config_json = row
        if bundle_json is None or not isinstance(bundle_json, str):
            continue
        bundle_json = bundle_json.strip()
        if not bundle_json:
            continue
        try:
            bundle = json.loads(bundle_json)
        except (json.JSONDecodeError, TypeError):
            print(
                f"Warning: job {job_id}: bundle_json is not valid JSON; skipping.",
                file=sys.stderr,
            )
            continue
        if not isinstance(bundle, dict) or "objects" not in bundle:
            print(
                f"Warning: job {job_id}: bundle missing 'objects' key; skipping.",
                file=sys.stderr,
            )
            continue
        if not isinstance(bundle["objects"], list):
            print(
                f"Warning: job {job_id}: 'objects' is not a list; skipping.",
                file=sys.stderr,
            )
            continue

        run_config: dict | None = None
        if run_config_json is not None and isinstance(run_config_json, str):
            run_config_json = run_config_json.strip()
            if run_config_json:
                try:
                    run_config = json.loads(run_config_json)
                except (json.JSONDecodeError, TypeError):
                    run_config = None

        jobs.append((job_id, filename, bundle, run_config))
    return jobs


def _edge_stats(bundle: dict) -> dict:
    """Count relationship objects by evidence label and by synthesis source."""
    objects: list = bundle.get("objects", [])
    if not isinstance(objects, list):
        objects = []

    # Build id -> type index once per bundle (O(n) instead of O(n*m)).
    id_to_type: dict[str, str] = {}
    for obj in objects:
        if isinstance(obj, dict) and "id" in obj and "type" in obj:
            id_to_type[obj["id"]] = obj["type"]

    total = 0
    labelled = 0
    policy_pinned = 0
    inferred = 0
    by_label: Counter[str] = Counter()
    verb_counter: Counter[str] = Counter()
    pair_counter: Counter[str] = Counter()

    for obj in objects:
        if not isinstance(obj, dict):
            continue
        if obj.get("type") != "relationship":
            continue
        total += 1

        # Evidence label
        if "x_evidence_label" in obj:
            labelled += 1
            label = obj["x_evidence_label"]
            if isinstance(label, str):
                by_label[label] += 1
            else:
                by_label[str(label)] += 1

        # Synthesis source flags
        if "x_policy_rule" in obj:
            policy_pinned += 1
        if "x_inference_rule" in obj:
            inferred += 1

        # Relationship type (verb)
        rel_type = obj.get("relationship_type")
        if isinstance(rel_type, str):
            verb_counter[rel_type] += 1

        # Source/target type pair
        src_ref = obj.get("source_ref")
        tgt_ref = obj.get("target_ref")
        src_type = id_to_type.get(src_ref, "?") if isinstance(src_ref, str) else "?"
        tgt_type = id_to_type.get(tgt_ref, "?") if isinstance(tgt_ref, str) else "?"
        pair_counter[f"{src_type}->{tgt_type}"] += 1

    unlabelled = total - labelled
    top_verbs = verb_counter.most_common(5)
    top_pairs = pair_counter.most_common(5)

    return {
        "total": total,
        "labelled": labelled,
        "unlabelled": unlabelled,
        "by_label": dict(by_label),
        "policy_pinned": policy_pinned,
        "inferred": inferred,
        "top_verbs": top_verbs,
        "top_pairs": top_pairs,
    }


def _format_pct(part: int, whole: int) -> str:
    """Return percentage string with one decimal; 0.0 if whole is 0."""
    if whole == 0:
        return "0.0"
    return f"{(part / whole) * 100:.1f}"


def _print_job_block(
    job_id: str,
    filename: str,
    run_config: dict | None,
    stats: dict,
    show_unlabelled: int,
    bundle: dict,
) -> None:
    """Print the per-job audit block."""
    sep = "=" * 64
    print(sep)
    print(filename[:60])

    if run_config is not None:
        rc_str = "recorded"
    else:
        rc_str = "ABSENT - bundle predates ADR-0024, not attributable"

    total = stats["total"]
    labelled = stats["labelled"]
    unlabelled = stats["unlabelled"]
    by_label = stats["by_label"]
    policy_pinned = stats["policy_pinned"]
    inferred = stats["inferred"]
    top_verbs = stats["top_verbs"]
    top_pairs = stats["top_pairs"]

    print(f"  job        : {job_id}")
    print(f"  run config : {rc_str}")
    print(f"  edges      : {total}")
    print(f"  labelled   : {labelled} ({_format_pct(labelled, total)}%)")
    print(f"  unlabelled : {unlabelled} ({_format_pct(unlabelled, total)}%)")

    # by_label sorted by count descending
    if by_label:
        sorted_labels = sorted(by_label.items(), key=lambda x: x[1], reverse=True)
        label_str = ", ".join(f"{k}={v}" for k, v in sorted_labels)
    else:
        label_str = "(none)"
    print(f"  by label   : {label_str}")

    print(f"  policy-pin : {policy_pinned}    inferred: {inferred}")

    if top_verbs:
        verb_str = ", ".join(f"{v}={c}" for v, c in top_verbs)
    else:
        verb_str = "(none)"
    print(f"  top verbs  : {verb_str}")

    if top_pairs:
        pair_str = ", ".join(f"{p}={c}" for p, c in top_pairs)
    else:
        pair_str = "(none)"
    print(f"  top pairs  : {pair_str}")

    # Show unlabelled edges if requested
    if show_unlabelled > 0 and unlabelled > 0:
        objects: list = bundle.get("objects", [])
        if not isinstance(objects, list):
            objects = []
        id_to_type: dict[str, str] = {}
        for obj in objects:
            if isinstance(obj, dict) and "id" in obj and "type" in obj:
                id_to_type[obj["id"]] = obj["type"]

        shown = 0
        for obj in objects:
            if shown >= show_unlabelled:
                break
            if not isinstance(obj, dict):
                continue
            if obj.get("type") != "relationship":
                continue
            if "x_evidence_label" in obj:
                continue
            src_ref = obj.get("source_ref")
            tgt_ref = obj.get("target_ref")
            src_type = id_to_type.get(src_ref, "?") if isinstance(src_ref, str) else "?"
            tgt_type = id_to_type.get(tgt_ref, "?") if isinstance(tgt_ref, str) else "?"
            verb = obj.get("relationship_type", "?")
            if not isinstance(verb, str):
                verb = str(verb)
            print(f"    {src_type} --{verb}--> {tgt_type}")
            shown += 1


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Audit edge provenance in STIX bundles (read-only)."
    )
    parser.add_argument(
        "--db",
        type=Path,
        default=Path("cti_stix.db"),
        help="Path to the SQLite database (default: cti_stix.db)",
    )
    parser.add_argument(
        "--job",
        type=str,
        default=None,
        help="Restrict to a single job_id",
    )
    parser.add_argument(
        "--show-unlabelled",
        type=int,
        default=0,
        help="Print up to N unlabelled edges per job",
    )
    args = parser.parse_args()

    jobs = _load_jobs(args.db)

    if args.job is not None:
        jobs = [j for j in jobs if j[0] == args.job]

    if not jobs:
        print("Error: no jobs with a bundle found.", file=sys.stderr)
        sys.exit(1)

    t_total = 0
    t_labelled = 0
    t_unlabelled = 0
    n_jobs = 0

    for job_id, filename, bundle, run_config in jobs:
        stats = _edge_stats(bundle)
        _print_job_block(job_id, filename, run_config, stats, args.show_unlabelled, bundle)
        t_total += stats["total"]
        t_labelled += stats["labelled"]
        t_unlabelled += stats["unlabelled"]
        n_jobs += 1

    t_pct = (t_labelled / t_total) * 100 if t_total > 0 else 0.0
    print(
        f"\nTOTAL across {n_jobs} bundle(s): {t_total} edges, "
        f"{t_labelled} labelled ({t_pct:.1f}%), {t_unlabelled} unlabelled."
    )
    if t_unlabelled > 0:
        print(
            "Unlabelled edges carry no provenance: a materialised assumption is "
            "indistinguishable from an extracted fact. See ADR-0024."
        )


if __name__ == "__main__":
    main()
