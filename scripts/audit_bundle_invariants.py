from __future__ import annotations

import argparse
import json
import re
import sqlite3
import sys
from collections import Counter
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

# STIX 2.1 common relationship types, plus the ones this pipeline
# emits.  Anything outside this set is not necessarily wrong -- STIX
# allows custom types -- but it should be a deliberate choice, so it
# is surfaced rather than assumed.
KNOWN_RELATIONSHIP_TYPES: frozenset[str] = frozenset({
    "uses", "targets", "indicates", "mitigates", "attributed-to",
    "variant-of", "impersonates", "delivers", "compromises",
    "originates-from", "investigates", "remediates", "located-at",
    "based-on", "communicates-with", "consists-of", "controls",
    "has", "hosts", "owns", "authored-by", "beacons-to",
    "exfiltrates-to", "downloads", "drops", "exploits",
    "characterizes", "av-analysis-of", "static-analysis-of",
    "dynamic-analysis-of", "related-to", "derived-from",
    "duplicate-of", "part-of", "resolves-to", "belongs-to",
})

_FAULTY_JOBS: dict[str, set[str]] = {}


@dataclass
class Finding:
    name: str
    severity: str
    count: int
    total: int
    jobs: int
    detail: str
    status: str


def _sample(items: list[str], n: int = 3) -> str:
    """Return up to n items joined by comma, each truncated to 60 chars."""
    return ", ".join(str(i)[:60] for i in items[:n])


def _objects(bundle: dict) -> list[dict]:
    """Return the objects list from a bundle dict, or empty list."""
    objs = bundle.get("objects")
    return objs if isinstance(objs, list) else []


def _load_bundles(conn: sqlite3.Connection) -> list[tuple[str, str]]:
    """Load raw bundle JSON strings for all jobs with non-empty bundle_json."""
    cur = conn.execute("SELECT id, bundle_json FROM jobs WHERE bundle_json IS NOT NULL AND bundle_json != ''")
    return [(row[0], row[1]) for row in cur.fetchall()]


def check_bundle_parses(raw: list[tuple[str, str]]) -> tuple[Finding, list[tuple[str, dict]]]:
    """Validate that each bundle parses as valid STIX bundle structure."""
    faulty: set[str] = set()
    examples: list[str] = []
    count = 0
    parsed: list[tuple[str, dict]] = []
    for job_id, text in raw:
        try:
            data = json.loads(text)
            if not isinstance(data, dict):
                raise ValueError("root not dict")
            if data.get("type") != "bundle":
                raise ValueError("type != bundle")
            if not isinstance(data.get("objects"), list):
                raise ValueError("objects not list")
            parsed.append((job_id, data))
        except Exception as e:
            count += 1
            faulty.add(job_id)
            if len(examples) < 3:
                examples.append(f"{job_id}: {e}")
    _FAULTY_JOBS["check_bundle_parses"] = faulty
    detail = _sample(examples) if examples else "all bundles parsed"
    status = "FAIL" if count > 0 else "OK"
    return Finding("check_bundle_parses", "error", count, len(raw), len(faulty), detail[:200], status), parsed


def check_object_id_unique(bundles: list[tuple[str, dict]]) -> Finding:
    """Check for duplicate object IDs within each bundle."""
    try:
        faulty: set[str] = set()
        examples: list[str] = []
        count = 0
        total = 0
        for job_id, bundle in bundles:
            ids = [o.get("id") for o in _objects(bundle) if isinstance(o, dict)]
            total += len(ids)
            seen: set[str] = set()
            dups: set[str] = set()
            for i in ids:
                if i in seen:
                    dups.add(i)
                seen.add(i)
            if dups:
                count += len(dups)
                faulty.add(job_id)
                if len(examples) < 3:
                    examples.append(f"{job_id}: {_sample(list(dups))}")
        _FAULTY_JOBS["check_object_id_unique"] = faulty
        detail = _sample(examples) if examples else "no duplicates"
        status = "FAIL" if count > 0 else "OK"
        return Finding("check_object_id_unique", "error", count, total, len(faulty), detail[:200], status)
    except Exception as e:
        return Finding("check_object_id_unique", "error", 0, 0, 0, str(e)[:200], "SKIP")


def check_object_id_format(bundles: list[tuple[str, dict]]) -> Finding:
    """Check object ID format and type prefix consistency."""
    try:
        faulty: set[str] = set()
        examples: list[str] = []
        malformed = 0
        type_mismatch = 0
        total = 0
        id_re = re.compile(r'^[a-z0-9-]+--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')
        for job_id, bundle in bundles:
            for obj in _objects(bundle):
                if not isinstance(obj, dict):
                    continue
                total += 1
                oid = obj.get("id")
                otype = obj.get("type")
                if not isinstance(oid, str) or not id_re.match(oid):
                    malformed += 1
                    faulty.add(job_id)
                    if len(examples) < 3:
                        examples.append(f"{job_id}: malformed {oid}")
                    continue
                prefix = oid.split("--")[0]
                if prefix != otype:
                    type_mismatch += 1
                    faulty.add(job_id)
                    if len(examples) < 3:
                        examples.append(f"{job_id}: {prefix} != {otype}")
        count = malformed + type_mismatch
        _FAULTY_JOBS["check_object_id_format"] = faulty
        detail = f"malformed={malformed} type_mismatch={type_mismatch}"
        status = "FAIL" if count > 0 else "OK"
        return Finding("check_object_id_format", "error", count, total, len(faulty), detail[:200], status)
    except Exception as e:
        return Finding("check_object_id_format", "error", 0, 0, 0, str(e)[:200], "SKIP")


def check_relationship_refs_resolve(bundles: list[tuple[str, dict]]) -> Finding:
    """Check that relationship source/target refs resolve within bundle."""
    try:
        faulty: set[str] = set()
        examples: list[str] = []
        dangling_source = 0
        dangling_target = 0
        total = 0
        for job_id, bundle in bundles:
            ids = {o.get("id") for o in _objects(bundle) if isinstance(o, dict)}
            for obj in _objects(bundle):
                if not isinstance(obj, dict) or obj.get("type") != "relationship":
                    continue
                total += 1
                src = obj.get("source_ref")
                tgt = obj.get("target_ref")
                if src not in ids:
                    dangling_source += 1
                    faulty.add(job_id)
                    if len(examples) < 3:
                        examples.append(f"{job_id}: src={src}")
                if tgt not in ids:
                    dangling_target += 1
                    faulty.add(job_id)
                    if len(examples) < 3:
                        examples.append(f"{job_id}: tgt={tgt}")
        count = dangling_source + dangling_target
        _FAULTY_JOBS["check_relationship_refs_resolve"] = faulty
        detail = f"dangling_source={dangling_source} dangling_target={dangling_target}"
        status = "FAIL" if count > 0 else "OK"
        return Finding("check_relationship_refs_resolve", "error", count, total, len(faulty), detail[:200], status)
    except Exception as e:
        return Finding("check_relationship_refs_resolve", "error", 0, 0, 0, str(e)[:200], "SKIP")


def check_relationship_no_self_loop(bundles: list[tuple[str, dict]]) -> Finding:
    """Check for self-loop relationships (source_ref == target_ref)."""
    try:
        faulty: set[str] = set()
        examples: list[str] = []
        count = 0
        total = 0
        for job_id, bundle in bundles:
            for obj in _objects(bundle):
                if not isinstance(obj, dict) or obj.get("type") != "relationship":
                    continue
                total += 1
                if obj.get("source_ref") == obj.get("target_ref"):
                    count += 1
                    faulty.add(job_id)
                    if len(examples) < 3:
                        examples.append(f"{job_id}: {obj.get('id')}")
        _FAULTY_JOBS["check_relationship_no_self_loop"] = faulty
        detail = _sample(examples) if examples else "no self-loops"
        status = "FAIL" if count > 0 else "OK"
        return Finding("check_relationship_no_self_loop", "error", count, total, len(faulty), detail[:200], status)
    except Exception as e:
        return Finding("check_relationship_no_self_loop", "error", 0, 0, 0, str(e)[:200], "SKIP")


def check_relationship_no_duplicates(bundles: list[tuple[str, dict]]) -> Finding:
    """Check for duplicate relationship triplets within a bundle."""
    try:
        faulty: set[str] = set()
        examples: list[str] = []
        count = 0
        total = 0
        for job_id, bundle in bundles:
            triplets: Counter[tuple[str, str, str]] = Counter()
            for obj in _objects(bundle):
                if not isinstance(obj, dict) or obj.get("type") != "relationship":
                    continue
                total += 1
                key = (obj.get("source_ref", ""), obj.get("relationship_type", ""), obj.get("target_ref", ""))
                triplets[key] += 1
            for key, n in triplets.items():
                if n > 1:
                    count += n - 1
                    faulty.add(job_id)
                    if len(examples) < 3:
                        examples.append(f"{job_id}: {key[0]}->{key[2]} x{n}")
        _FAULTY_JOBS["check_relationship_no_duplicates"] = faulty
        detail = _sample(examples) if examples else "no duplicates"
        status = "FAIL" if count > 0 else "OK"
        return Finding("check_relationship_no_duplicates", "warn", count, total, len(faulty), detail[:200], status)
    except Exception as e:
        return Finding("check_relationship_no_duplicates", "warn", 0, 0, 0, str(e)[:200], "SKIP")


def check_created_by_ref_resolves(bundles: list[tuple[str, dict]]) -> Finding:
    """Check that created_by_ref points to a valid identity object."""
    try:
        faulty: set[str] = set()
        examples: list[str] = []
        count = 0
        total = 0
        for job_id, bundle in bundles:
            ids = {o.get("id"): o.get("type") for o in _objects(bundle) if isinstance(o, dict)}
            for obj in _objects(bundle):
                if not isinstance(obj, dict) or "created_by_ref" not in obj:
                    continue
                total += 1
                ref = obj.get("created_by_ref")
                if ref not in ids or ids[ref] != "identity":
                    count += 1
                    faulty.add(job_id)
                    if len(examples) < 3:
                        examples.append(f"{job_id}: {ref}")
        _FAULTY_JOBS["check_created_by_ref_resolves"] = faulty
        detail = _sample(examples) if examples else "all refs valid"
        status = "FAIL" if count > 0 else "OK"
        return Finding("check_created_by_ref_resolves", "error", count, total, len(faulty), detail[:200], status)
    except Exception as e:
        return Finding("check_created_by_ref_resolves", "error", 0, 0, 0, str(e)[:200], "SKIP")


def check_marking_refs_resolve(bundles: list[tuple[str, dict]]) -> Finding:
    """Check that object_marking_refs point to valid marking-definition objects."""
    try:
        faulty: set[str] = set()
        examples: list[str] = []
        count = 0
        total = 0
        for job_id, bundle in bundles:
            ids = {o.get("id"): o.get("type") for o in _objects(bundle) if isinstance(o, dict)}
            for obj in _objects(bundle):
                if not isinstance(obj, dict) or "object_marking_refs" not in obj:
                    continue
                refs = obj.get("object_marking_refs")
                if not isinstance(refs, list):
                    continue
                for ref in refs:
                    total += 1
                    if ref not in ids or ids[ref] != "marking-definition":
                        count += 1
                        faulty.add(job_id)
                        if len(examples) < 3:
                            examples.append(f"{job_id}: {ref}")
        _FAULTY_JOBS["check_marking_refs_resolve"] = faulty
        detail = _sample(examples) if examples else "all refs valid"
        status = "FAIL" if count > 0 else "OK"
        return Finding("check_marking_refs_resolve", "error", count, total, len(faulty), detail[:200], status)
    except Exception as e:
        return Finding("check_marking_refs_resolve", "error", 0, 0, 0, str(e)[:200], "SKIP")


def check_report_object_refs_resolve(bundles: list[tuple[str, dict]]) -> Finding:
    """Check that report object_refs resolve within the bundle."""
    try:
        faulty: set[str] = set()
        examples: list[str] = []
        count = 0
        total = 0
        for job_id, bundle in bundles:
            ids = {o.get("id") for o in _objects(bundle) if isinstance(o, dict)}
            for obj in _objects(bundle):
                if not isinstance(obj, dict) or obj.get("type") != "report":
                    continue
                refs = obj.get("object_refs")
                if not isinstance(refs, list):
                    continue
                for ref in refs:
                    total += 1
                    if ref not in ids:
                        count += 1
                        faulty.add(job_id)
                        if len(examples) < 3:
                            examples.append(f"{job_id}: {ref}")
        _FAULTY_JOBS["check_report_object_refs_resolve"] = faulty
        detail = _sample(examples) if examples else "all refs valid"
        status = "FAIL" if count > 0 else "OK"
        return Finding("check_report_object_refs_resolve", "error", count, total, len(faulty), detail[:200], status)
    except Exception as e:
        return Finding("check_report_object_refs_resolve", "error", 0, 0, 0, str(e)[:200], "SKIP")


def check_indicator_pattern_wellformed(bundles: list[tuple[str, dict]]) -> Finding:
    """Check indicator patterns are well-formed STIX patterns."""
    try:
        faulty: set[str] = set()
        examples: list[str] = []
        missing = 0
        unbracketed = 0
        unbalanced = 0
        no_comparison = 0
        total = 0
        for job_id, bundle in bundles:
            for obj in _objects(bundle):
                if not isinstance(obj, dict) or obj.get("type") != "indicator":
                    continue
                total += 1
                pat = obj.get("pattern")
                if not isinstance(pat, str) or not pat.strip():
                    missing += 1
                    faulty.add(job_id)
                    if len(examples) < 3:
                        examples.append(f"{job_id}: missing")
                    continue
                if not pat.startswith("[") or not pat.endswith("]"):
                    unbracketed += 1
                    faulty.add(job_id)
                    if len(examples) < 3:
                        examples.append(f"{job_id}: unbracketed")
                    continue
                depth = 0
                in_str = False
                balanced = True
                for ch in pat:
                    if ch == "'" and not in_str:
                        in_str = True
                    elif ch == "'" and in_str:
                        in_str = False
                    elif not in_str:
                        if ch == "[":
                            depth += 1
                        elif ch == "]":
                            depth -= 1
                            if depth < 0:
                                balanced = False
                                break
                if not balanced or depth != 0:
                    unbalanced += 1
                    faulty.add(job_id)
                    if len(examples) < 3:
                        examples.append(f"{job_id}: unbalanced")
                    continue
                if "=" not in pat:
                    no_comparison += 1
                    faulty.add(job_id)
                    if len(examples) < 3:
                        examples.append(f"{job_id}: no_comparison")
        count = missing + unbracketed + unbalanced + no_comparison
        _FAULTY_JOBS["check_indicator_pattern_wellformed"] = faulty
        detail = f"missing={missing} unbracketed={unbracketed} unbalanced={unbalanced} no_comparison={no_comparison}"
        status = "FAIL" if count > 0 else "OK"
        return Finding("check_indicator_pattern_wellformed", "error", count, total, len(faulty), detail[:200], status)
    except Exception as e:
        return Finding("check_indicator_pattern_wellformed", "error", 0, 0, 0, str(e)[:200], "SKIP")


def check_indicator_required_fields(bundles: list[tuple[str, dict]]) -> Finding:
    """Check indicators have required fields: pattern_type, valid_from."""
    try:
        faulty: set[str] = set()
        examples: list[str] = []
        count = 0
        total = 0
        for job_id, bundle in bundles:
            for obj in _objects(bundle):
                if not isinstance(obj, dict) or obj.get("type") != "indicator":
                    continue
                total += 1
                issues = []
                if "pattern_type" not in obj:
                    issues.append("no_pattern_type")
                elif obj.get("pattern_type") != "stix":
                    issues.append("bad_pattern_type")
                if "valid_from" not in obj:
                    issues.append("no_valid_from")
                if issues:
                    count += 1
                    faulty.add(job_id)
                    if len(examples) < 3:
                        examples.append(f"{job_id}: {','.join(issues)}")
        _FAULTY_JOBS["check_indicator_required_fields"] = faulty
        detail = _sample(examples) if examples else "all fields present"
        status = "FAIL" if count > 0 else "OK"
        return Finding("check_indicator_required_fields", "warn", count, total, len(faulty), detail[:200], status)
    except Exception as e:
        return Finding("check_indicator_required_fields", "warn", 0, 0, 0, str(e)[:200], "SKIP")


def check_timestamps_parse(bundles: list[tuple[str, dict]]) -> Finding:
    """Check that all timestamp fields parse as valid ISO 8601."""
    try:
        faulty: set[str] = set()
        examples: list[str] = []
        count = 0
        total = 0
        ts_keys = {"created", "modified", "valid_from", "first_seen", "last_seen", "published"}
        for job_id, bundle in bundles:
            for obj in _objects(bundle):
                if not isinstance(obj, dict):
                    continue
                for key in ts_keys:
                    if key not in obj:
                        continue
                    total += 1
                    val = obj.get(key)
                    if not isinstance(val, str):
                        count += 1
                        faulty.add(job_id)
                        if len(examples) < 3:
                            examples.append(f"{job_id}: {key} not str")
                        continue
                    try:
                        datetime.fromisoformat(val.replace("Z", "+00:00"))
                    except ValueError:
                        count += 1
                        faulty.add(job_id)
                        if len(examples) < 3:
                            examples.append(f"{job_id}: {key}={val}")
        _FAULTY_JOBS["check_timestamps_parse"] = faulty
        detail = _sample(examples) if examples else "all timestamps valid"
        status = "FAIL" if count > 0 else "OK"
        return Finding("check_timestamps_parse", "error", count, total, len(faulty), detail[:200], status)
    except Exception as e:
        return Finding("check_timestamps_parse", "error", 0, 0, 0, str(e)[:200], "SKIP")


def check_modified_not_before_created(bundles: list[tuple[str, dict]]) -> Finding:
    """Check that modified timestamp is not before created timestamp."""
    try:
        faulty: set[str] = set()
        examples: list[str] = []
        count = 0
        total = 0
        for job_id, bundle in bundles:
            for obj in _objects(bundle):
                if not isinstance(obj, dict):
                    continue
                if "created" not in obj or "modified" not in obj:
                    continue
                total += 1
                try:
                    c = datetime.fromisoformat(obj["created"].replace("Z", "+00:00"))
                    m = datetime.fromisoformat(obj["modified"].replace("Z", "+00:00"))
                except (ValueError, AttributeError):
                    continue
                if m < c:
                    count += 1
                    faulty.add(job_id)
                    if len(examples) < 3:
                        examples.append(f"{job_id}: {obj.get('id')}")
        _FAULTY_JOBS["check_modified_not_before_created"] = faulty
        detail = _sample(examples) if examples else "all timestamps ordered"
        status = "FAIL" if count > 0 else "OK"
        return Finding("check_modified_not_before_created", "warn", count, total, len(faulty), detail[:200], status)
    except Exception as e:
        return Finding("check_modified_not_before_created", "warn", 0, 0, 0, str(e)[:200], "SKIP")


def check_confidence_range(bundles: list[tuple[str, dict]]) -> Finding:
    """Check that confidence values are integers in range 0-100."""
    try:
        faulty: set[str] = set()
        examples: list[str] = []
        count = 0
        total = 0
        for job_id, bundle in bundles:
            for obj in _objects(bundle):
                if not isinstance(obj, dict) or "confidence" not in obj:
                    continue
                total += 1
                val = obj.get("confidence")
                if not isinstance(val, int) or isinstance(val, bool) or not (0 <= val <= 100):
                    count += 1
                    faulty.add(job_id)
                    if len(examples) < 3:
                        examples.append(f"{job_id}: {val}")
        _FAULTY_JOBS["check_confidence_range"] = faulty
        detail = _sample(examples) if examples else "all in range"
        status = "FAIL" if count > 0 else "OK"
        return Finding("check_confidence_range", "error", count, total, len(faulty), detail[:200], status)
    except Exception as e:
        return Finding("check_confidence_range", "error", 0, 0, 0, str(e)[:200], "SKIP")


def check_orphan_objects(bundles: list[tuple[str, dict]]) -> Finding:
    """Check for objects not referenced by any report or relationship."""
    try:
        faulty: set[str] = set()
        examples: list[str] = []
        count = 0
        total = 0
        for job_id, bundle in bundles:
            objs = _objects(bundle)
            referenced: set[str] = set()
            for obj in objs:
                if not isinstance(obj, dict):
                    continue
                if obj.get("type") == "report":
                    refs = obj.get("object_refs")
                    if isinstance(refs, list):
                        referenced.update(refs)
                elif obj.get("type") == "relationship":
                    if obj.get("source_ref"):
                        referenced.add(obj["source_ref"])
                    if obj.get("target_ref"):
                        referenced.add(obj["target_ref"])
            for obj in objs:
                if not isinstance(obj, dict):
                    continue
                otype = obj.get("type")
                if otype in ("report", "identity", "marking-definition"):
                    continue
                total += 1
                oid = obj.get("id")
                if oid not in referenced:
                    count += 1
                    faulty.add(job_id)
                    if len(examples) < 3:
                        examples.append(f"{job_id}: {oid}")
        _FAULTY_JOBS["check_orphan_objects"] = faulty
        detail = _sample(examples) if examples else "no orphans"
        status = "FAIL" if count > 0 else "OK"
        return Finding("check_orphan_objects", "warn", count, total, len(faulty), detail[:200], status)
    except Exception as e:
        return Finding("check_orphan_objects", "warn", 0, 0, 0, str(e)[:200], "SKIP")


def check_relationship_type_known(bundles: list[tuple[str, dict]]) -> Finding:
    """Check that relationship types are from the known vocabulary."""
    try:
        faulty: set[str] = set()
        unknown: Counter[str] = Counter()
        total = 0
        for job_id, bundle in bundles:
            for obj in _objects(bundle):
                if not isinstance(obj, dict) or obj.get("type") != "relationship":
                    continue
                total += 1
                rtype = obj.get("relationship_type")
                if rtype not in KNOWN_RELATIONSHIP_TYPES:
                    unknown[rtype] += 1
                    faulty.add(job_id)
        count = sum(unknown.values())
        _FAULTY_JOBS["check_relationship_type_known"] = faulty
        if unknown:
            detail = ", ".join(f"{k}={v}" for k, v in sorted(unknown.items())[:5])
        else:
            detail = "all known"
        status = "FAIL" if count > 0 else "OK"
        return Finding("check_relationship_type_known", "info", count, total, len(faulty), detail[:200], status)
    except Exception as e:
        return Finding("check_relationship_type_known", "info", 0, 0, 0, str(e)[:200], "SKIP")


def run_all(bundles: list[tuple[str, dict]]) -> list[Finding]:
    """Run all invariant checks and return findings."""
    _FAULTY_JOBS.clear()
    checks = [
        check_object_id_unique,
        check_object_id_format,
        check_relationship_refs_resolve,
        check_relationship_no_self_loop,
        check_relationship_no_duplicates,
        check_created_by_ref_resolves,
        check_marking_refs_resolve,
        check_report_object_refs_resolve,
        check_indicator_pattern_wellformed,
        check_indicator_required_fields,
        check_timestamps_parse,
        check_modified_not_before_created,
        check_confidence_range,
        check_orphan_objects,
        check_relationship_type_known,
    ]
    return [c(bundles) for c in checks]


def main(argv: list[str] | None = None) -> int:
    """Main entry point for the audit script."""
    parser = argparse.ArgumentParser(description="Audit STIX bundle invariants")
    parser.add_argument("db", nargs="?", default="cti_stix.db", help="Path to SQLite database")
    parser.add_argument("--job", action="append", default=[], help="Filter by job ID prefix (repeatable)")
    args = parser.parse_args(argv)

    db_path = Path(args.db)
    if not db_path.exists():
        print(f"Database not found: {db_path}", file=sys.stderr)
        return 2

    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    try:
        raw = _load_bundles(conn)
        if args.job:
            raw = [(jid, txt) for jid, txt in raw if any(jid.startswith(p) for p in args.job)]
        finding_parse, bundles = check_bundle_parses(raw)
        findings = [finding_parse] + run_all(bundles)
    finally:
        conn.close()

    print(f"{'STATUS':<6} {'SEVERITY':<8} {'NAME':<30} {'COUNT/TOTAL':<15} {'JOBS':<5} DETAIL")
    print("-" * 100)
    for f in findings:
        print(f"{f.status:<6} {f.severity:<8} {f.name:<30} {f.count}/{f.total:<14} {f.jobs:<5} {f.detail}")

    print()
    print("per job:")
    job_stats: dict[str, dict[str, int]] = {}
    for job_id, bundle in bundles:
        objs = _objects(bundle)
        n_objs = len(objs)
        n_rels = sum(1 for o in objs if isinstance(o, dict) and o.get("type") == "relationship")
        n_inds = sum(1 for o in objs if isinstance(o, dict) and o.get("type") == "indicator")
        job_stats[job_id] = {"objects": n_objs, "rels": n_rels, "indicators": n_inds}

    for job_id in sorted(job_stats):
        stats = job_stats[job_id]
        problems = sum(1 for name, faulty in _FAULTY_JOBS.items() if job_id in faulty)
        print(
            f"{job_id:<8}  objects={stats['objects']}  rels={stats['rels']}  "
            f"indicators={stats['indicators']}  problems={problems}"
        )

    ok = sum(1 for f in findings if f.status == "OK")
    fail = sum(1 for f in findings if f.status == "FAIL")
    skip = sum(1 for f in findings if f.status == "SKIP")
    print(f"\n{len(findings)} invariants — {ok} OK, {fail} FAIL, {skip} SKIP")

    if any(f.status == "FAIL" and f.severity == "error" for f in findings):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
