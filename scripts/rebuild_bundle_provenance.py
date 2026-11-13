"""Rebuild a STIX bundle in memory and audit edge provenance.

This script proves that bundle edges carry an ``x_evidence_label`` and that
the policy-pin materialisation respects its cap. It reconstructs a bundle
from data already stored in the database under a given relationship policy,
then counts edges by label. It writes nothing: neither to the database nor
to disk. It is a measurement, not a migration.

The bundle is built from the same rows and decisions as the worker's finalize
(see _load_job): a rejected entity stays out, and the named objects come as
the product's do.

This script reads DATABASE_URL the same way the API does; the connection it
gets back is never written to.

Usage:
    python scripts/rebuild_bundle_provenance.py --job JOB_ID
    python scripts/rebuild_bundle_provenance.py --job JOB_ID \
        --pin malware:uses:attack-pattern --max-pinned 200
"""

import argparse
import json
import sys
from pathlib import Path

_ROOT = Path(__file__).parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from api.db import get_conn, init_db  # noqa: E402
from api.db_backend import DBConnection  # noqa: E402
from models.schemas import EntityType, RawEntity  # noqa: E402
from pipeline.decisions import SHIPS  # noqa: E402
from pipeline.named_entities import stored_row_source, with_named_entities  # noqa: E402
from pipeline.overrides import without_denied  # noqa: E402
from pipeline.stage3_llm import LLMEnrichmentResult  # noqa: E402
from pipeline.stage4_stix_mapping import build_stix_bundle  # noqa: E402

# The entity types the worker's finalize hands to build_stix_bundle as raw
# entities (api/worker.py, re_run_final_stages: _RAW_ENTITY_TYPES).  The named
# types come in through the LLM lists instead, via with_named_entities.
_RAW_ENTITY_TYPES = frozenset({
    EntityType.IPV4, EntityType.IPV6, EntityType.DOMAIN,
    EntityType.URL, EntityType.EMAIL, EntityType.MD5,
    EntityType.SHA1, EntityType.SHA256, EntityType.MAC_ADDR,
    EntityType.ASN, EntityType.FILE, EntityType.REGISTRY_KEY,
    EntityType.MUTEX, EntityType.NETWORK_TRAFFIC,
    EntityType.USER_ACCOUNT,
    EntityType.CVE,
    EntityType.TECHNIQUE, EntityType.TACTIC,
    EntityType.PROCEDURE, EntityType.TTP,
    EntityType.INFRASTRUCTURE, EntityType.INTRUSION_SET,
    EntityType.LOCATION, EntityType.IDENTITY,
    EntityType.CAMPAIGN, EntityType.INCIDENT,
})


def _load_job(conn: DBConnection, job_id: str) -> tuple[list, object, str, str] | None:
    """Return (raw_entities, llm_result, report_text, filename) or None.

    The bundle inputs are built as the worker's finalize builds them
    (api/worker.py, re_run_final_stages), so the bundle is the product's: only
    the rows that ship (pipeline.decisions.SHIPS), a rejected entity stays out;
    the deny list applies; the analyst's rejections filter the LLM's JSON
    fields; the named lists come through with_named_entities.  The worker is
    the reference: keep the two in step.  Graph completion and the saved
    relationships are not rebuilt here (the relationships stay the JSON's).
    """
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

    # Columns: value, entity_type, context, confidence, mitre_id, source, accepted, decision_origin
    rows = conn.execute(
        "SELECT value, entity_type, context, confidence, mitre_id, source, accepted, decision_origin "
        f"FROM entities WHERE job_id = ? AND {SHIPS}",
        (job_id_val,),
    ).fetchall()
    rejected_rows = conn.execute(
        "SELECT value, entity_type, mitre_id FROM entities WHERE job_id = ? AND accepted = 0",
        (job_id_val,),
    ).fetchall()

    llm_result = without_denied(llm_result)

    # The analyst's rejections, for the JSON-blob fields (worker: rejected_* sets).
    rejected_ttp_names: set[str] = set()
    rejected_ttp_mitre: set[str] = set()
    rejected_locations: set[str] = set()
    rejected_identities: set[str] = set()
    rejected_campaigns: set[str] = set()
    for value, et, mid in rejected_rows:
        val = value.lower().strip()
        mid = (mid or "").lower().strip()
        if et in ("technique", "tactic", "procedure", "ttp"):
            rejected_ttp_names.add(val)
            if mid:
                rejected_ttp_mitre.add(mid)
        elif et == "location":
            rejected_locations.add(val)
        elif et == "identity":
            rejected_identities.add(val)
        elif et == "campaign":
            rejected_campaigns.add(val)

    _ttp_types = ("technique", "tactic", "procedure", "ttp")
    shipped_ttp_names = {(r[0] or "").lower().strip() for r in rows if r[1] in _ttp_types}
    shipped_ttp_mitre = {(r[4] or "").lower().strip() for r in rows if r[1] in _ttp_types and r[4]}
    filtered_ttps = [
        t for t in llm_result.ttps
        if t.technique_name.lower() not in rejected_ttp_names
        and (not t.mitre_id or t.mitre_id.lower() not in rejected_ttp_mitre)
        and (t.technique_name.lower().strip() in shipped_ttp_names
             or (t.mitre_id or "").lower().strip() in shipped_ttp_mitre)
    ]

    campaign_name = llm_result.campaign_name
    shipped_campaigns = {(r[0] or "").lower().strip() for r in rows if r[1] == "campaign"}
    if campaign_name and (campaign_name.lower().strip() in rejected_campaigns
                          or campaign_name.lower().strip() not in shipped_campaigns):
        campaign_name = None

    named = with_named_entities(
        LLMEnrichmentResult(campaign_name=campaign_name),
        ((r[1], r[0], stored_row_source(r[5], r[6], r[7])) for r in rows),
    )
    campaign_name = named.llm_result.campaign_name

    raw_entities: list[RawEntity] = []
    for r in rows:
        try:
            etype = EntityType(r[1])
        except (ValueError, TypeError):
            continue
        if etype not in _RAW_ENTITY_TYPES:
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
    raw_entities = [e for e in raw_entities if named.keeps(e)]

    filtered_countries = [
        c for c in llm_result.targeted_countries if c.lower().strip() not in rejected_locations
    ]
    filtered_sectors = [
        s for s in llm_result.targeted_sectors if s.lower().strip() not in rejected_identities
    ]
    llm_result = llm_result.model_copy(update={
        "malware_families": named.llm_result.malware_families,
        "threat_actors": named.llm_result.threat_actors,
        "tools": named.llm_result.tools,
        "ttps": filtered_ttps,
        "campaign_name": campaign_name,
        "targeted_countries": filtered_countries,
        "targeted_sectors": filtered_sectors,
    })

    return raw_entities, llm_result, report_text or "", filename or ""


def _build_bundle(raw_entities: list, llm_result, filename: str, report_text: str, policy: dict):
    """Stage 4 on the inputs of _load_job, as a pipeline run builds its bundle."""
    return build_stix_bundle(
        raw_entities,
        llm_result,
        filename,
        report_text=report_text,
        original_filename=filename,
        relationship_policy=policy,
    )


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
    parser.add_argument("--job", required=True)
    parser.add_argument("--pin", action="append", default=None)
    parser.add_argument("--max-pinned", type=int, default=200)
    args = parser.parse_args()

    # The policy is built from the --pin options only: global enforce, and the cap on
    # pinned edges. The bundle is rebuilt in memory from the stored job, not read back from
    # the store.
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

    init_db()
    conn = get_conn()
    loaded = _load_job(conn, args.job)
    if loaded is None:
        print(
            f"error: job {args.job!r} not found or not replayable",
            file=sys.stderr,
        )
        sys.exit(1)

    raw_entities, llm_result, report_text, filename = loaded
    bundle = _build_bundle(raw_entities, llm_result, filename, report_text, policy)

    # The census counts the shipped edges by evidence label. The pinned count and the cap are
    # checked against the policy's max_pinned_edges.
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


if __name__ == "__main__":
    main()
