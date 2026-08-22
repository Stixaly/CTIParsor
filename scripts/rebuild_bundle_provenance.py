"""Rebuild a STIX bundle in memory and audit edge provenance.

This script proves that bundle edges carry an ``x_evidence_label`` and that
the policy-pin materialisation respects its cap. It reconstructs a bundle
from data already stored in the database under a given relationship policy,
then counts edges by label. It writes nothing: neither to the database nor
to disk. It is a measurement, not a migration.

The database is opened strictly read-only.

Usage:
    python scripts/rebuild_bundle_provenance.py --job JOB_ID
    python scripts/rebuild_bundle_provenance.py --job JOB_ID \
        --pin malware:uses:attack-pattern --max-pinned 200
"""

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


def _load_job(conn, job_id: str) -> tuple[list, object, str, str] | None:
    """Return (raw_entities, llm_result, report_text, filename) or None."""
    cur = conn.execute(
        "SELECT id, original_filename, report_text, llm_result_json "
        "FROM jobs WHERE id = ?",
        (job_id,),
    )
    row = cur.fetchone()
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

    cur = conn.execute(
        "SELECT value, entity_type, context, confidence, mitre_id, source "
        "FROM entities WHERE job_id = ?",
        (job_id_val,),
    )
    raw_entities: list[RawEntity] = []
    for r in cur.fetchall():
        try:
            etype = EntityType(r[1])
        except (ValueError, TypeError):
            continue
        raw_entities.append(
            RawEntity(
                value=r[0],
                entity_type=etype,
                context=r[2] or "",
                confidence=r[3] if r[3] is not None else 0.0,
                mitre_id=r[4],
                source=r[5] or "",
            )
        )

    return raw_entities, llm_result, report_text or "", filename or ""


def _label_census(bundle) -> dict[str, int]:
    """Count relationship objects by x_evidence_label; unlabelled ones under
    the literal key '(unlabelled)'."""
    census: dict[str, int] = {}
    for obj in list(bundle.objects):
        if getattr(obj, "type", "") != "relationship":
            continue
        label = getattr(obj, "x_evidence_label", None)
        key = label if label else "(unlabelled)"
        census[key] = census.get(key, 0) + 1
    return census


def _pinned_count(bundle) -> int:
    """Count relationship objects carrying x_policy_rule."""
    n = 0
    for obj in list(bundle.objects):
        if getattr(obj, "type", "") != "relationship":
            continue
        if getattr(obj, "x_policy_rule", None) is not None:
            n += 1
    return n


def _parse_pin(spec: str) -> dict:
    parts = spec.split(":")
    if len(parts) != 3 or not all(p.strip() for p in parts):
        print(
            f"error: --pin must be 'src:verb:tgt' with three non-empty parts, "
            f"got: {spec!r}",
            file=sys.stderr,
        )
        sys.exit(2)
    return {
        "src": parts[0].strip(),
        "verb": parts[1].strip(),
        "tgt": parts[2].strip(),
        "mode": "pin",
        "enabled": True,
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Rebuild a STIX bundle in memory and audit edge provenance."
    )
    parser.add_argument("--db", type=Path, default=Path("cti_stix.db"))
    parser.add_argument("--job", required=True)
    parser.add_argument("--pin", action="append", default=None)
    parser.add_argument("--max-pinned", type=int, default=200)
    args = parser.parse_args()

    rules = []
    if args.pin:
        for spec in args.pin:
            rules.append(_parse_pin(spec))

    policy = {
        "version": 1,
        "global": "enforce",
        "max_pinned_edges": args.max_pinned,
        "rules": rules,
    }

    db_path = args.db
    if not db_path.exists():
        print(f"error: database not found: {db_path}", file=sys.stderr)
        sys.exit(1)

    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    try:
        loaded = _load_job(conn, args.job)
        if loaded is None:
            print(
                f"error: job {args.job!r} not found or not replayable",
                file=sys.stderr,
            )
            sys.exit(1)

        raw_entities, llm_result, report_text, filename = loaded
        bundle = build_stix_bundle(
            raw_entities,
            llm_result,
            filename,
            report_text=report_text,
            original_filename=filename,
            relationship_policy=policy,
        )

        census = _label_census(bundle)
        pinned = _pinned_count(bundle)
        total = sum(census.values())

        print(f"job        : {args.job}")
        print(f"report     : {filename[:60]}")
        print(f"entities   : {len(raw_entities)}")
        print(
            f"policy     : {len(rules)} pinned rule(s), "
            f"max_pinned_edges={args.max_pinned}"
        )
        print()
        print(f"{'label':<16} {'count':>8}")
        print("-" * 26)
        for label, n in sorted(census.items(), key=lambda kv: -kv[1]):
            print(f"{label:<16} {n:>8}")
        print("-" * 26)
        print(f"{'total':<16} {total:>8}")
        print()
        print(f"edges carrying x_policy_rule : {pinned}")
        cap_ok = pinned <= args.max_pinned
        print(f"cap respected                : {'YES' if cap_ok else 'NO'}")
        print()

        unlabelled = census.get("(unlabelled)", 0)
        if unlabelled == 0:
            print("Every shipped edge carries provenance.")
        else:
            print(f"{unlabelled} edge(s) still carry no x_evidence_label.")
    finally:
        conn.close()


if __name__ == "__main__":
    main()
