"""
READ-ONLY replay harness for ADR-0013 Stage 4b graph completion.

This script opens the SQLite database in read-only mode and replays the
graph-completion inference engines over STIX bundles that were already
stored for real jobs.  The reconstructed graph is approximate: it is
rebuilt from the entities and relationships tables, not from the
original STIX bundle.  The script never writes to the database.
"""

import argparse
import sqlite3
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from pipeline.stage4b_graph_completion import complete_graph

_TYPE_MAP = {
    "threat_actor":  "threat-actor",
    "malware":       "malware",
    "tool":          "tool",
    "campaign":      "campaign",
    "technique":     "attack-pattern",
    "ttp":           "attack-pattern",
    "identity":      "identity",
    "vulnerability": "vulnerability",
}


def load_job_graph(conn, job_id: str) -> list:
    """Rebuild a minimal STIX object list for one job from stored entities and relationships."""
    import stix2

    objects = []
    by_name = {}

    # Step A — entities
    cur = conn.execute(
        "SELECT DISTINCT value, entity_type, mitre_id FROM entities "
        "WHERE job_id=? AND (accepted IS NULL OR accepted=1)",
        (job_id,),
    )
    for row in cur.fetchall():
        value = row["value"]
        entity_type = row["entity_type"]
        mitre_id = row["mitre_id"]

        if not isinstance(value, str) or not value:
            continue

        et = entity_type.lower() if isinstance(entity_type, str) else ""
        stix_type = _TYPE_MAP.get(et)
        if stix_type is None:
            continue

        try:
            if stix_type == "threat-actor":
                obj = stix2.ThreatActor(name=value, allow_custom=True)
            elif stix_type == "malware":
                obj = stix2.Malware(name=value, is_family=False, allow_custom=True)
            elif stix_type == "tool":
                obj = stix2.Tool(name=value, allow_custom=True)
            elif stix_type == "campaign":
                obj = stix2.Campaign(name=value, allow_custom=True)
            elif stix_type == "identity":
                obj = stix2.Identity(name=value, allow_custom=True)
            elif stix_type == "vulnerability":
                obj = stix2.Vulnerability(name=value, allow_custom=True)
            elif stix_type == "attack-pattern":
                if isinstance(mitre_id, str) and mitre_id:
                    obj = stix2.AttackPattern(
                        name=value,
                        allow_custom=True,
                        external_references=[{
                            "source_name": "mitre-attack",
                            "external_id": mitre_id,
                        }],
                    )
                else:
                    obj = stix2.AttackPattern(name=value, allow_custom=True)
            else:
                continue
        except Exception:
            continue

        objects.append(obj)
        by_name[value.lower()] = obj

    # Step B — relationships
    cur = conn.execute(
        "SELECT source_value, relationship_type, target_value FROM relationships WHERE job_id=?",
        (job_id,),
    )
    for row in cur.fetchall():
        source = row["source_value"]
        relationship_type = row["relationship_type"]
        target = row["target_value"]

        if not isinstance(relationship_type, str) or not relationship_type:
            continue

        src = by_name.get(source.lower()) if isinstance(source, str) else None
        tgt = by_name.get(target.lower()) if isinstance(target, str) else None
        if src is None or tgt is None:
            continue

        try:
            rel = stix2.Relationship(
                relationship_type=relationship_type,
                source_ref=src.id,
                target_ref=tgt.id,
                allow_custom=True,
            )
        except Exception:
            continue

        objects.append(rel)

    return objects


def summarise(objects: list) -> dict:
    """Count nodes and edges in a list of STIX objects."""
    nodes = 0
    edges = 0
    for obj in objects:
        try:
            t = obj.get("type")
        except Exception:
            t = getattr(obj, "type", "")
        if t == "relationship":
            edges += 1
        else:
            nodes += 1
    return {"nodes": nodes, "edges": edges}


def added_edges(before: list, after: list) -> list[dict]:
    """Compute relationships present in `after` but not in `before`."""
    def _key(obj):
        try:
            return (obj.get("source_ref"), obj.get("relationship_type"), obj.get("target_ref"))
        except Exception:
            return (getattr(obj, "source_ref", None),
                    getattr(obj, "relationship_type", None),
                    getattr(obj, "target_ref", None))

    before_keys = set()
    for obj in before:
        try:
            if obj.get("type") == "relationship":
                before_keys.add(_key(obj))
        except Exception:
            if getattr(obj, "type", "") == "relationship":
                before_keys.add(_key(obj))

    # Build id -> display name map from `after`
    id_to_name = {}
    for obj in after:
        try:
            t = obj.get("type")
        except Exception:
            t = getattr(obj, "type", "")
        if t != "relationship":
            try:
                name = obj.get("name") or obj.id
            except Exception:
                name = getattr(obj, "id", "")
            id_to_name[obj.id] = name

    result = []
    for obj in after:
        try:
            t = obj.get("type")
        except Exception:
            t = getattr(obj, "type", "")
        if t != "relationship":
            continue
        k = _key(obj)
        if k in before_keys:
            continue
        src_id = k[0]
        tgt_id = k[2]
        verb = k[1]
        src_name = id_to_name.get(src_id, src_id)
        tgt_name = id_to_name.get(tgt_id, tgt_id)
        try:
            rule = obj.get("x_inference_rule") or ""
        except Exception:
            rule = ""
        try:
            label = obj.get("x_evidence_label") or ""
        except Exception:
            label = ""
        try:
            confidence = obj.get("confidence") or 0
        except Exception:
            confidence = 0
        result.append({
            "src": src_name,
            "verb": verb,
            "tgt": tgt_name,
            "rule": rule,
            "label": label,
            "confidence": confidence,
        })
    return result


def main() -> int:
    """Replay graph completion over stored jobs and report added edges."""
    parser = argparse.ArgumentParser(description="Read-only replay harness for ADR-0013 Stage 4b graph completion.")
    parser.add_argument("--db", default="cti_stix.db", help="Path to SQLite database")
    parser.add_argument("--limit", default=6, type=int, help="Number of jobs to replay")
    parser.add_argument("--show", default=10, type=int, help="Added edges to print per job")
    args = parser.parse_args()

    conn = sqlite3.connect(f"file:{args.db}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row

    cur = conn.execute(
        "SELECT id, original_filename FROM jobs ORDER BY rowid DESC LIMIT ?",
        (args.limit,),
    )
    jobs = cur.fetchall()

    rule_counter = Counter()
    verb_counter = Counter()
    total_edges_added = 0
    jobs_replayed = 0

    for job in jobs:
        job_id = job["id"]
        original_filename = job["original_filename"]

        objects = load_job_graph(conn, job_id)
        if len(objects) < 2:
            print("  (too small, skipped)")
            continue

        before = list(objects)

        try:
            completion = complete_graph(objects, policy=None)
        except Exception as e:
            print(f"  {e}")
            continue

        jobs_replayed += 1
        before_summary = summarise(before)
        after_summary = summarise(objects)

        # Read the CompletionStats the stage returns; reconstructing the counts
        # by inspecting x_inference_rule cannot work — that field carries the
        # composed rule ("transitive:uses+uses"), not the engine name.
        stats = {
            "reference": completion.reference_added,
            "transitive": completion.transitive_added,
            "long_distance": completion.long_distance_added,
            "skipped_not_suggested": completion.skipped_not_suggested,
            "capped": completion.capped,
        }

        added = added_edges(before, objects)
        total_edges_added += len(added)

        for edge in added:
            if edge["rule"]:
                rule_counter[edge["rule"]] += 1
            if edge["verb"]:
                verb_counter[edge["verb"]] += 1

        print(f"=== {original_filename} ===")
        print(f"  before : {before_summary['nodes']} nodes / {before_summary['edges']} edges")
        print(f"  after  : {after_summary['nodes']} nodes / {after_summary['edges']} edges")
        print(
            f"  stats  : reference=+{stats['reference']} "
            f"transitive=+{stats['transitive']} "
            f"long_distance=+{stats['long_distance']} "
            f"skipped_not_suggested={stats['skipped_not_suggested']} "
            f"capped={stats['capped']}"
        )
        print(f"  added  : {len(added)}")

        if not added:
            print("    (none)")
        else:
            for edge in added[:args.show]:
                conf = edge["confidence"]
                label = edge["label"]
                src = edge["src"]
                verb = edge["verb"]
                tgt = edge["tgt"]
                rule = edge["rule"]
                print(f"    {conf:3d}  {label:8s}  {src} --{verb}--> {tgt}   [{rule}]")

    print()
    print("=== totals ===")
    print(f"jobs replayed : {jobs_replayed}")
    print(f"edges added   : {total_edges_added}")
    print("by rule:")
    if rule_counter:
        for rule, count in sorted(rule_counter.items(), key=lambda x: (-x[1], x[0])):
            print(f"  {rule} : {count}")
    else:
        print("  (none)")
    print("by verb:")
    if verb_counter:
        for verb, count in sorted(verb_counter.items(), key=lambda x: (-x[1], x[0])):
            print(f"  {verb} : {count}")
    else:
        print("  (none)")

    conn.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
