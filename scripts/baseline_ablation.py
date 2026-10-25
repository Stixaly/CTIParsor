"""
Recovery and duplicates of the baseline reconciliation (ADR-0090, lot 7: measures
A3 and A2 on the real reports, and the external control on the fixtures).

    python scripts/baseline_ablation.py [--db DSN] [--ratio 0.30] [--seed 20261025]
                                        [--out output/baseline_ablation.json] [--jobs ID ...]
    python scripts/baseline_ablation.py --fixture FILE --fixture-db DSN --fixture-job ID
                                        [--seeds 5] [--seed 20261025] [--ratio 0.30] [--out ...]

Each job of the measurement database is its own baseline: its CTIParsor bundle
(`bundle_json`) is given back as the baseline of the same document, its index
(`intake`) gives the entries, the job's extractions are reconciled against it
(`reconcile`, Stage 3r), and every row is checked against the objects the mapping
ledger says it became (`bundle_ledger_json`).

The unit of the ablation is the index entry: an observable, its Indicator(s) and
the based-on between them are one entry.  An entry leaves whole when it is drawn,
but an entry that keeps one of its objects stays: an Indicator stating two
observable types is held by two entries, and when one is drawn the other's
observable survives in the ablated bundle.

- A2, the round trip: the bundle as it is.  Every row that maps to an object of a
  kept entry should come back `matched`; a `new` row that designates a kept entry
  is a duplicate (target: none).
- A3, the ablation: round(ratio x candidate entries) entries are drawn with a seed
  fixed per job and removed with every object they hold, the relationships that
  touch those objects and their references in the Report.  Recovery is the share
  of removed entries that a `new` row comes back to, over the removed entries some
  row reaches.  The duplicate rate is the `new` rows that designate a kept entry,
  over all `new` rows (target: at most 1 %).
- A row whose ledger key maps to several objects is an `ambiguous` ledger key: it
  is counted apart, neither as a duplicate nor as a recovery.
- A `matched` row is a mismatch when its entry is not the entry of its original
  object.
- A reachable removed entry that no row came back to is listed (`not_recovered`)
  with the rows that reach it and their status and entry.

Fixture mode: the baseline is a bundle file (a fixture, not a measured job) and
the rows are one job's extraction, read from --fixture-db.  A fixture has no
mapping ledger, so the original of a row is the entry it matches when reconciled
against the WHOLE fixture; the candidates are the entries some row matches in that
run; then the same ablation, once per seed (--seeds seeds, from --seed on).  The
round trip does not depend on the seed and is run once.

Read only: the connections are opened read-only and only SELECTs run.  No LLM and
no network.  The JSON written to --out is the evidence ADR-0090 cites.  Exit 0,
or 2 when the data cannot be read.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import random
import re
import sys
from collections import Counter
from collections.abc import Iterable, Mapping, Sequence
from collections.abc import Set as AbstractSet
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

# The pipeline is imported from the repo root, however the script was invoked.
_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))
from models.schemas import EntityType, RawEntity  # noqa: E402
from pipeline import baseline_stix as bs  # noqa: E402
from pipeline.stage3_llm import LLMEnrichmentResult  # noqa: E402

DEFAULT_DB = "postgresql://ctiparsor:ctitest@127.0.0.1:5433/ctiparsor_measure"
DEFAULT_RATIO = 0.30
DEFAULT_SEED = 20261025
DEFAULT_OUT = _ROOT / "output" / "baseline_ablation.json"
UNIT = "index entry (an object set: SCO, Indicators, based-on)"
ROUNDING = "round(ratio x candidate entries), Python round()"
# Objects no extraction is about: an entry holding only these is never drawn.
_NOT_CANDIDATES = frozenset({"report", "identity", "marking-definition"})
# Rows the pipeline did not write: the analyst's own, and the baseline's.
_NOT_PIPELINE_SOURCES = frozenset({"manual", bs.SOURCE})
_COUNTED = ("rows", "new", "matched", "duplicates", "ambiguous", "unmapped_new", "other_new", "matched_unmapped",
            "mismatch", "recovered", "reachable", "reachable_not_recovered", "removed_objects")
_DETAILS = ("duplicates", "ambiguous", "mismatch", "unmapped_new", "other_new", "not_recovered")
_SHOWN = 5                      # examples printed per kind, the JSON keeps them all


# ── Ledger, index and draw ──────────────────────────────────────────────────

def row_originals(ledger: Mapping[str, Any], objects: Mapping[str, dict]) -> dict[tuple[str, str], frozenset[str]]:
    """{row key: the bundle objects the ledger says the row became}.  An entry
    counts when it is not dropped and names an object of the bundle; the key is
    `_row_key`'s, the one `reconcile` files its rows under."""
    out: dict[tuple[str, str], set[str]] = {}
    for entry in ledger.get("entities") or []:
        stix_id = entry.get("stix_id")
        if entry.get("outcome") == "dropped" or stix_id not in objects:
            continue
        out.setdefault(bs._row_key(entry["entity_type"], entry["value"]), set()).add(stix_id)
    return {key: frozenset(ids) for key, ids in out.items()}


def fixture_originals(rec: bs.Reconciliation) -> dict[tuple[str, str], frozenset[str]]:
    """{row key: its original} for a fixture, which has no ledger: the entry a row
    matches when reconciled against the whole fixture, named by its entry id (the
    observable's SCO, the Indicator or SDO that stands alone, or `<indicator>#<type>`
    for the observable of a compound Indicator); `owners` resolves it to its entry."""
    return {key: frozenset({entry_id}) for key, (state, entry_id) in rec.entity_status.items()
            if state == bs.MATCHED and entry_id is not None}


def owners(index: bs.BaselineIndex) -> dict[str, set[str]]:
    """{object id: the ids of the entries that hold it}.  An entry also answers to
    its own id: for the observable of a compound Indicator the id is `<indicator>#<type>`,
    which is no object of the bundle (a fixture's original names the entry by it)."""
    out: dict[str, set[str]] = {}
    for entry in index.entries:
        for oid in (*entry.object_ids, entry.entry_id):
            out.setdefault(oid, set()).add(entry.entry_id)
    return out


def candidate_entries(index: bs.BaselineIndex, originals: Mapping[tuple[str, str], frozenset[str]],
                      objects: Mapping[str, dict]) -> list[str]:
    """The entry ids, sorted, that hold an object some row became (the report,
    identities and marking-definitions aside)."""
    mapped = {oid for ids in originals.values() for oid in ids if objects[oid].get("type") not in _NOT_CANDIDATES}
    return sorted(entry.entry_id for entry in index.entries if mapped.intersection(entry.object_ids))


def matched_entries(index: bs.BaselineIndex, originals: Mapping[tuple[str, str], frozenset[str]]) -> list[str]:
    """The entry ids, sorted, that some row's original names (the report, identities
    and marking-definitions aside): the fixture's candidates."""
    named = {oid for ids in originals.values() for oid in ids}
    return sorted(e.entry_id for e in index.entries if e.entry_id in named and e.stix_type not in _NOT_CANDIDATES)


def draw(job_id: str, candidate_ids: Sequence[str], ratio: float, seed: int) -> set[str]:
    """round(ratio x candidates) of `candidate_ids`, drawn with a generator seeded by
    `seed` and the job id: the same job gives the same draw on every run."""
    count = round(ratio * len(candidate_ids))
    rng = random.Random(seed ^ int.from_bytes(hashlib.sha256(job_id.encode()).digest(), "big"))
    return set(rng.sample(list(candidate_ids), count))


def removed_objects(index: bs.BaselineIndex, drawn: AbstractSet[str]) -> set[str]:
    """Every object of the drawn entries: an entry leaves whole."""
    by_id = {entry.entry_id: entry for entry in index.entries}
    return {oid for eid in drawn for oid in by_id[eid].object_ids}


def ablate(bundle: Mapping[str, Any], removed: AbstractSet[str]) -> dict:
    """A copy of `bundle` without the `removed` objects, the relationships that end
    on one of them, and the references to any of those in the Report's object_refs.
    The input is not changed."""
    data = copy.deepcopy(dict(bundle))
    gone = set(removed)
    dropped_rels: set[str] = set()
    kept = []
    for obj in data["objects"]:
        if obj.get("id") in gone:
            continue
        if obj.get("type") == "relationship" and (obj.get("source_ref") in gone or obj.get("target_ref") in gone):
            dropped_rels.add(obj.get("id"))
            continue
        kept.append(obj)
    data["objects"] = kept
    absent = gone | dropped_rels
    for obj in kept:
        if obj.get("type") == "report" and isinstance(obj.get("object_refs"), list):
            obj["object_refs"] = [ref for ref in obj["object_refs"] if ref not in absent]
    return data


# ── Classification ──────────────────────────────────────────────────────────

def classify(status: Mapping[tuple[str, str], tuple[str, str | None]],
             originals: Mapping[tuple[str, str], frozenset[str]], index: bs.BaselineIndex,
             drawn: AbstractSet[str], remaining: bs.BaselineIndex) -> dict[str, Any]:
    """Counts of one reconciliation against the entries its rows came from.

    `status` is `Reconciliation.entity_status`; `originals` the ledger's objects per
    row key; `index` the FULL index (before the removal), whose entries say which
    object belongs to which entry; `drawn` the removed entry ids; `remaining` the
    index of the ABLATED bundle, whose entries are the kept ones.  An entry can keep
    an object of a drawn entry (an Indicator stating two observable types is held
    by two entries): it is kept, and only the objects that left are gone.

    A `new` row with one original is a duplicate when that object is still in the
    ablated bundle, and recovers the drawn entries that held it; a `new` row with
    several originals is an ambiguous ledger key, and one with no entry at all is
    unmapped.  A `matched` row is a mismatch when its entry is not an entry of its
    original object.  A reachable entry no row came back to is listed with the rows
    that reach it.
    """
    by_id = {entry.entry_id: entry for entry in index.entries}
    owned_by = owners(index)
    still_held = owners(remaining)
    drawn = set(drawn)
    gone = removed_objects(index, drawn)
    counts: Counter[str] = Counter({"rows": len(status), "removed_objects": len(gone)})
    by_type: dict[str, Counter[str]] = {name: Counter() for name in ("removed", "reachable", "recovered", "new",
                                                                     "duplicates")}
    for eid in drawn:
        by_type["removed"][by_id[eid].stix_type] += 1
    reachable: set[str] = set()
    recovered: set[str] = set()
    reaching: dict[str, list[dict]] = {}
    details: dict[str, list[dict]] = {name: [] for name in _DETAILS}
    for key, (state, entry_id) in status.items():
        mapped = originals.get(key, frozenset())
        expected = set().union(*(owned_by.get(oid, set()) for oid in mapped))
        reached = expected & drawn
        reachable |= reached
        row = {"row": list(key)}
        for eid in reached:
            reaching.setdefault(eid, []).append({**row, "status": state, "entry_id": entry_id,
                                                 "originals": sorted(mapped)})
        if state == bs.NEW:
            counts["new"] += 1
            by_type["new"][key[0]] += 1
            if not mapped:
                counts["unmapped_new"] += 1
                details["unmapped_new"].append(row)
            elif len(mapped) > 1:
                counts["ambiguous"] += 1
                details["ambiguous"].append({**row, "originals": sorted(mapped)})
            else:
                (oid,) = mapped
                ents = owned_by.get(oid, set())
                recovered |= ents & drawn
                survivors = still_held.get(oid, set())
                if survivors:
                    counts["duplicates"] += 1
                    by_type["duplicates"][key[0]] += 1
                    details["duplicates"].append({**row, "original": oid, "entry_id": sorted(survivors)[0]})
                elif not ents & drawn:
                    counts["other_new"] += 1
                    details["other_new"].append({**row, "original": oid})
        elif state == bs.MATCHED:
            counts["matched"] += 1
            if not mapped:
                counts["matched_unmapped"] += 1
            elif entry_id not in expected:
                counts["mismatch"] += 1
                details["mismatch"].append({**row, "entry_id": entry_id, "original": sorted(mapped),
                                            "entry_of_original": sorted(expected)})
    for eid in recovered:
        by_type["recovered"][by_id[eid].stix_type] += 1
    for eid in reachable:
        by_type["reachable"][by_id[eid].stix_type] += 1
    not_recovered = sorted(reachable - recovered)
    details["not_recovered"] = [{"entry_id": eid, "stix_type": by_id[eid].stix_type, "value": by_id[eid].value,
                                 "rows": reaching[eid]} for eid in not_recovered]
    counts["recovered"] = len(recovered)
    counts["reachable"] = len(reachable)
    counts["reachable_not_recovered"] = len(not_recovered)
    return {**{name: counts[name] for name in _COUNTED}, "by_type": {k: dict(v) for k, v in by_type.items()},
            "details": details}


def _derive(counts: Mapping[str, Any]) -> dict[str, Any]:
    """`counts` with its two rates: the recovery over the reachable removed entries,
    and the duplicates over the `new` rows (None when the denominator is zero)."""
    recovery = counts["recovered"] / counts["reachable"] if counts["reachable"] else None
    rate = counts["duplicates"] / counts["new"] if counts["new"] else None
    return {**counts, "recovery": recovery, "duplicate_rate": rate}


def _total(runs: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    """The sum of the counters of `runs`, with the rates of the sum."""
    runs = list(runs)
    total: dict[str, Any] = {name: sum(run[name] for run in runs) for name in _COUNTED}
    total["removed"] = sum(run["removed"] for run in runs)
    by_type: dict[str, Counter[str]] = {}
    for run in runs:
        for name, values in run["by_type"].items():
            by_type.setdefault(name, Counter()).update(values)
    total["by_type"] = {k: dict(v) for k, v in by_type.items()}
    return _derive(total)


# ── Jobs ────────────────────────────────────────────────────────────────────

def raw_rows(entities: Iterable[Mapping[str, Any]]) -> tuple[list[RawEntity], int]:
    """The entity rows the pipeline wrote, as RawEntity, and how many were skipped
    because their type is not one RawEntity knows."""
    out: list[RawEntity] = []
    skipped = 0
    for row in entities:
        if row["source"] in _NOT_PIPELINE_SOURCES:
            continue
        try:
            out.append(RawEntity(value=row["value"], entity_type=EntityType(row["entity_type"]),
                                 mitre_id=row["mitre_id"], source=row["source"]))
        except ValueError:
            skipped += 1
    return out, skipped


def _explain(dup: Mapping[str, Any], rows_by_key: Mapping[tuple[str, str], tuple[str, str, str | None]],
             index: bs.BaselineIndex) -> dict[str, Any]:
    """A duplicate with its kept entry and why the matcher did not take it, read from
    the keys of the row and of the entry (the ablated index the run matched against)."""
    row_type, folded = dup["row"]
    _type, value, mitre = rows_by_key.get((row_type, folded), (row_type, folded, None))
    entry = next((e for e in index.entries if e.entry_id == dup["entry_id"]), None)
    strong, weak = bs.keys_for_row(row_type, value, mitre)
    if entry is None:
        reason = "its kept entry is not in the ablated index"
    elif not strong and weak:
        carriers = sum(1 for e in index.entries if weak & e.weak_keys)
        reason = f"name only, no strong key: {carriers} entries carry this name, lookup_weak finds none"
    elif not strong & entry.keys:
        reason = f"no shared key: row {sorted(strong)[:2]} vs entry {sorted(entry.keys)[:2]}"
    else:
        found = index.lookup(strong, bs.ENTITY_TO_STIX.get(row_type))
        if found is bs.AMBIGUOUS:
            reason = "shared key, but several entries match and none has the row's type"
        elif found is None:
            reason = "shared key, but the lookup finds no entry"
        elif found.entry_id != entry.entry_id:
            reason = f"shared key, but the lookup resolves to {found.entry_id}"
        else:
            reason = "shared key resolves to the kept entry: check, reconcile did not match it"
    return {**dup, "value": value, "kept_value": entry.value if entry else None,
            "kept_type": entry.stix_type if entry else None, "reason": reason}


def measure(bundle: Mapping[str, Any], drawn: AbstractSet[str], full: bs.BaselineIndex,
            originals: Mapping[tuple[str, str], frozenset[str]],
            rows: Sequence[RawEntity], llm: LLMEnrichmentResult, text: str) -> dict[str, Any]:
    """Reconcile the job's rows against the bundle without the drawn entries."""
    gone = removed_objects(full, drawn)
    data = ablate(bundle, gone)
    index, _intake, _bundle = bs.intake(json.dumps(data).encode(), validate=False)
    rec = bs.reconcile(rows, llm, text, index)
    counts = classify(rec.entity_status, originals, full, drawn, index)
    rows_by_key: dict[tuple[str, str], tuple[str, str, str | None]] = {}
    for row in rows:
        rows_by_key.setdefault(bs._row_key(row.entity_type.value, row.value),
                               (row.entity_type.value, row.value, row.mitre_id))
    counts["details"]["duplicates"] = [_explain(d, rows_by_key, index) for d in counts["details"]["duplicates"]]
    return {**counts, "removed": len(drawn)}


def run_job(job: Mapping[str, Any], entities: Sequence[Mapping[str, Any]], ratio: float, seed: int) -> dict[str, Any]:
    """Both runs of one job: the ablation and the round trip.  Raises ValueError,
    KeyError or TypeError when the stored data of the job cannot be read."""
    bundle = json.loads(job["bundle_json"])
    ledger = json.loads(job["bundle_ledger_json"])
    llm = LLMEnrichmentResult.model_validate_json(job["llm_result_json"])
    if not job["report_text"]:
        raise ValueError("no report_text")
    objects = {o["id"]: o for o in bundle["objects"] if isinstance(o, dict) and isinstance(o.get("id"), str)}
    originals = row_originals(ledger, objects)
    full, _intake, _bundle = bs.intake(json.dumps(bundle).encode(), validate=False)
    cands = candidate_entries(full, originals, objects)
    drawn = draw(job["id"], cands, ratio, seed)
    rows, skipped_rows = raw_rows(entities)
    ablation = measure(bundle, drawn, full, originals, rows, llm, job["report_text"])
    round_trip = measure(bundle, set(), full, originals, rows, llm, job["report_text"])
    return {"id": job["id"], "filename": job["original_filename"], "candidates": len(cands),
            "removed_entry_ids": sorted(drawn), "removed_object_ids": sorted(removed_objects(full, drawn)),
            "raw_rows": len(rows), "skipped_rows": skipped_rows,
            "ablation": _derive(ablation), "round_trip": _derive(round_trip)}


def run_fixture(bundle_raw: bytes, job: Mapping[str, Any], entities: Sequence[Mapping[str, Any]], ratio: float,
                seeds: Sequence[int]) -> dict[str, Any]:
    """The fixture as the baseline and one job's extraction as the rows: the round
    trip once, the ablation once per seed.  Raises ValueError (and the like) when
    the fixture or the job cannot be read."""
    if not job["report_text"]:
        raise ValueError("no report_text")
    if job["llm_result_json"] is None:
        raise ValueError("no llm_result_json")
    bundle = json.loads(bundle_raw)
    full, _intake, _bundle = bs.intake(bundle_raw, validate=False)
    llm = LLMEnrichmentResult.model_validate_json(job["llm_result_json"])
    text = job["report_text"]
    rows, skipped_rows = raw_rows(entities)
    originals = fixture_originals(bs.reconcile(rows, llm, text, full))
    cands = matched_entries(full, originals)
    round_trip = measure(bundle, set(), full, originals, rows, llm, text)
    runs = []
    for seed in seeds:
        drawn = draw(job["id"], cands, ratio, seed)
        runs.append({"seed": seed, "removed_entry_ids": sorted(drawn),
                     "removed_object_ids": sorted(removed_objects(full, drawn)),
                     "ablation": _derive(measure(bundle, drawn, full, originals, rows, llm, text))})
    return {"candidates": len(cands), "matched_in_full": len(originals), "raw_rows": len(rows),
            "skipped_rows": skipped_rows, "round_trip": _derive(round_trip), "runs": runs}


def load_jobs(dsn: str) -> tuple[list[dict], dict[str, list[dict]]]:
    """Every job and every entity row of the database, read in one read-only session."""
    import psycopg

    with psycopg.connect(dsn, options="-c default_transaction_read_only=on") as conn:
        jobs = conn.execute("SELECT id, original_filename, bundle_json, bundle_ledger_json, llm_result_json, "
                            "report_text FROM jobs ORDER BY id").fetchall()
        rows = conn.execute("SELECT job_id, value, entity_type, mitre_id, source FROM entities ORDER BY id").fetchall()
    entities: dict[str, list[dict]] = {}
    for job_id, value, entity_type, mitre_id, source in rows:
        entities.setdefault(job_id, []).append({"value": value, "entity_type": entity_type,
                                                "mitre_id": mitre_id, "source": source})
    keys = ("id", "original_filename", "bundle_json", "bundle_ledger_json", "llm_result_json", "report_text")
    return [dict(zip(keys, row, strict=True)) for row in jobs], entities


def load_fixture_job(dsn: str, job_id: str) -> tuple[dict, list[dict]]:
    """One job and its entity rows, read in one read-only session: the extraction a
    fixture run replays.  Raises ValueError when the job is not in the database."""
    import psycopg

    with psycopg.connect(dsn, options="-c default_transaction_read_only=on") as conn:
        job = conn.execute("SELECT id, original_filename, llm_result_json, report_text FROM jobs WHERE id = %s",
                           (job_id,)).fetchone()
        rows = conn.execute("SELECT value, entity_type, mitre_id, source FROM entities WHERE job_id = %s ORDER BY id",
                            (job_id,)).fetchall()
    if job is None:
        raise ValueError(f"no job {job_id} in this database")
    keys = ("id", "original_filename", "llm_result_json", "report_text")
    return dict(zip(keys, job, strict=True)), [dict(zip(("value", "entity_type", "mitre_id", "source"), row,
                                                         strict=True)) for row in rows]


# ── Output ──────────────────────────────────────────────────────────────────

def _pct(value: float | None) -> str:
    return "-" if value is None else f"{100 * value:.1f} %"


def _cell(text: str) -> str:
    return text.replace("|", "\\|").replace("\n", " ")


_HEADER = ["| job | file | candidate entries | removed entries | reachable | recovered | recovery | new | duplicates | "
           "duplicate rate | ambiguous | unmapped new | matched | mismatch |",
           "|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|"]


def _row_line(label: str, filename: str, candidates_n: int, run: Mapping[str, Any]) -> str:
    return (f"| {label} | {_cell(filename[:40])} | {candidates_n} | {run['removed']} | {run['reachable']} | "
            f"{run['recovered']} | {_pct(run['recovery'])} | {run['new']} | {run['duplicates']} | "
            f"{_pct(run['duplicate_rate'])} | {run['ambiguous']} | {run['unmapped_new']} | {run['matched']} | "
            f"{run['mismatch']} |")


def _table(results: Sequence[Mapping[str, Any]], run_name: str, total: Mapping[str, Any]) -> list[str]:
    lines = list(_HEADER)
    lines += [_row_line(r["id"][:8], r["filename"] or "", r["candidates"], r[run_name]) for r in results]
    lines.append(_row_line("**total**", "", sum(r["candidates"] for r in results), total))
    return lines


def _duplicate_lines(job: str, dups: Sequence[Mapping[str, Any]]) -> list[str]:
    return [f"- {job} {d['row'][0]} \"{_cell(str(d['value']))}\": original {d['original']}; kept entry "
            f"{d['kept_type']} \"{_cell(str(d['kept_value']))}\" ({d['entry_id']}); {d['reason']}" for d in dups]


def _or_none(lines: list[str]) -> list[str]:
    """The lines, or the word "none" when there are none."""
    return lines or ["none"]


def _type_tables(total: Mapping[str, Any]) -> list[str]:
    """Two tables: the removed entries by the STIX type of their entry (removed,
    reachable, recovered), and the new rows by the entity type of the row (new,
    duplicates).  The two counts do not share a key, so they do not share a table."""
    by_type = total["by_type"]
    lines = ["### Removed entries by STIX type", "",
             "`removed`, `reachable` and `recovered` count the removed entries by the STIX type of their entry.", "",
             "| STIX type | removed | reachable | recovered | recovery |", "|---|---:|---:|---:|---:|"]
    for name in sorted({t for key in ("removed", "reachable", "recovered") for t in by_type.get(key, {})}):
        reachable = by_type.get("reachable", {}).get(name, 0)
        recovered = by_type.get("recovered", {}).get(name, 0)
        rate = _pct(recovered / reachable) if reachable else "-"
        lines.append(f"| {name} | {by_type.get('removed', {}).get(name, 0)} | {reachable} | {recovered} | {rate} |")
    lines += ["", "### New rows by entity type", "",
              "`new` and `duplicates` count the rows by their entity type.", "",
              "| entity type | new | duplicates | duplicate rate |", "|---|---:|---:|---:|"]
    for name in sorted({t for key in ("new", "duplicates") for t in by_type.get(key, {})}):
        new = by_type.get("new", {}).get(name, 0)
        dups = by_type.get("duplicates", {}).get(name, 0)
        lines.append(f"| {name} | {new} | {dups} | {_pct(dups / new) if new else '-'} |")
    return lines


def _not_recovered_lines(labelled: Sequence[tuple[str, Mapping[str, Any]]]) -> list[str]:
    """The reachable removed entries no row came back to: the run, the entry, its type
    and value, and the rows that reach it with their status and entry."""
    items = [(label, e) for label, run in labelled for e in run["details"]["not_recovered"]]
    if not items:
        return ["none"]
    lines = ["| run | entry | type | value | rows that reach it: row, status, entry |", "|---|---|---|---|---|"]
    for label, e in items:
        reach = []
        for r in e["rows"]:
            text = f"{r['row'][0]} \"{_cell(r['row'][1])}\": {r['status']}"
            text += f" {r['entry_id']}" if r["entry_id"] else ""
            text += " (ambiguous)" if len(r["originals"]) > 1 else ""
            reach.append(text)
        lines.append(f"| {label} | {e['entry_id']} | {e['stix_type']} | {_cell(str(e['value']))} | "
                     f"{_cell('; '.join(reach))} |")
    return lines


def _detail_md(labelled: Sequence[tuple[str, Mapping[str, Any]]], total: Mapping[str, Any]) -> list[str]:
    """The ablation's detail, shared by both modes: the two type tables, the reachable
    entries no row came back to, the duplicates with their kept entry and reason,
    the ambiguous keys, the mismatches and the unmapped rows."""
    lines = [*_type_tables(total), "", "### Reachable, not recovered, ablation", ""]
    lines += _not_recovered_lines(labelled) + ["", "### Duplicates, ablation", ""]
    dups = [line for label, run in labelled for line in _duplicate_lines(label, run["details"]["duplicates"])]
    lines += _or_none(dups)
    lines += ["", "### Ambiguous ledger keys, ablation", ""]
    lines += _or_none([f"- {label} {a['row'][0]} \"{_cell(a['row'][1])}\": originals {', '.join(a['originals'])}"
                       for label, run in labelled for a in run["details"]["ambiguous"]])
    mismatches = [(label, m) for label, run in labelled for m in run["details"]["mismatch"]]
    lines += ["", f"Mismatches, ablation: {total['mismatch']} (matched rows whose entry is not an entry of their "
              "original object).", ""]
    lines += [f"- {label} {m['row'][0]} \"{_cell(m['row'][1])}\": matched {m['entry_id']}, original {m['original']}, "
              f"its entry {m['entry_of_original']}" for label, m in mismatches[:_SHOWN]]
    lines += ["", f"Unmapped new rows, ablation: {total['unmapped_new']}. New rows whose object is in no kept nor "
              f"removed entry: {total['other_new']}. Matched rows without a ledger original: "
              f"{total['matched_unmapped']}.", ""]
    return lines


def render(results: Sequence[Mapping[str, Any]], totals: Mapping[str, Any], skipped: Sequence[tuple[str, str]],
           ratio: float, seed: int, out: Path) -> str:
    """The Markdown report of the ledger mode: both runs per job and in total, the
    detail, the round trip's duplicates, the skips."""
    ablation, round_trip = totals["ablation"], totals["round_trip"]
    lines = [f"## A3: ablation, {ratio:.0%} of the candidate entries removed (seed {seed})", ""]
    lines += _table(results, "ablation", ablation) + ["", "## A2: round trip, nothing removed", ""]
    lines += _table(results, "round_trip", round_trip) + [""]
    lines += _detail_md([(r["id"][:8], r["ablation"]) for r in results], ablation)
    lines += ["### Duplicates, round trip", ""]
    dups = [line for r in results for line in _duplicate_lines(r["id"][:8], r["round_trip"]["details"]["duplicates"])]
    lines += _or_none(dups)
    lines += ["", f"Round trip: mismatches {round_trip['mismatch']}, unmapped new {round_trip['unmapped_new']}, "
              f"matched without a ledger original {round_trip['matched_unmapped']}.", ""]
    if skipped:
        lines += ["Jobs not run:", ""] + [f"- {jid[:8]}: {reason}" for jid, reason in skipped] + [""]
    lines.append(f"JSON: {out}")
    return "\n".join(lines)


def render_fixture(case: Mapping[str, Any], seeds: Sequence[int], ratio: float, out: Path) -> str:
    """The Markdown report of the fixture mode: one row per seed and the sum, the
    round trip, then the same detail as the ledger mode."""
    runs = case["runs"]
    labelled = [(f"seed {run['seed']}", run["ablation"]) for run in runs]
    total = _total(run["ablation"] for run in runs)
    lines = [f"## Fixture: {ratio:.0%} of the candidate entries removed, seeds "
             f"{', '.join(str(s) for s in seeds)}", "",
             f"{case['candidates']} candidate entries (entries some row matches in the full fixture), "
             f"{case['matched_in_full']} rows matched in the full fixture, {case['raw_rows']} rows read, "
             f"{case['skipped_rows']} skipped (type unknown to RawEntity).", ""]
    lines += list(_HEADER) + [_row_line(label, "", case["candidates"], run) for label, run in labelled]
    lines.append(_row_line("**total**", "", case["candidates"], total))
    lines += ["", "## A2: round trip, nothing removed", ""]
    lines += list(_HEADER) + [_row_line("round trip", "", case["candidates"], case["round_trip"])]
    lines += [""] + _detail_md(labelled, total)
    rt = case["round_trip"]
    lines += ["### Duplicates, round trip", ""]
    lines += _or_none(_duplicate_lines("round trip", rt["details"]["duplicates"]))
    lines += ["", f"Round trip: mismatches {rt['mismatch']}, unmapped new {rt['unmapped_new']}, "
              f"matched without an original {rt['matched_unmapped']}.", "", f"JSON: {out}"]
    return "\n".join(lines)


def _dsn_label(dsn: str) -> str:
    """The DSN without its credentials."""
    return re.sub(r"://[^@/]*@", "://", dsn)


def _write_json(out: Path, evidence: Mapping[str, Any]) -> bool:
    try:
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(evidence, indent=2, ensure_ascii=False), encoding="utf-8")
    except OSError as exc:
        print(f"cannot write {out}: {exc}", file=sys.stderr)
        return False
    return True


def _fixture_main(args: argparse.Namespace) -> int:
    seeds = [args.seed + i for i in range(args.seeds)]
    try:
        raw = args.fixture.read_bytes()
        job, entities = load_fixture_job(args.fixture_db, args.fixture_job)
        case = run_fixture(raw, job, entities, args.ratio, seeds)
    except Exception as exc:  # noqa: BLE001 — no driver, no job, a fixture that is not a bundle: all "cannot be read"
        print(f"cannot run the fixture: {type(exc).__name__}: {str(exc)[:300]}", file=sys.stderr)
        return 2
    out = args.out or _ROOT / "output" / f"baseline_ablation_{args.fixture.stem}.json"
    evidence = {
        "mode": "fixture", "fixture": str(args.fixture), "fixture_sha256": hashlib.sha256(raw).hexdigest(),
        "fixture_database": _dsn_label(args.fixture_db), "job": job["id"],
        "original_filename": job["original_filename"],
        "generated_at": datetime.now(UTC).isoformat(timespec="seconds"), "ratio": args.ratio, "seeds": seeds,
        "unit": UNIT, "rounding": ROUNDING, "case": case,
        "totals": {"ablation": _total(run["ablation"] for run in case["runs"]), "round_trip": case["round_trip"]},
    }
    if not _write_json(out, evidence):
        return 2
    print(render_fixture({**case, "filename": job["original_filename"]}, seeds, args.ratio, out))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Baseline reconciliation: recovery and duplicates (ADR-0090, A2, A3)")
    parser.add_argument("--db", default=DEFAULT_DB, help="PostgreSQL DSN of the measurement database (read only)")
    parser.add_argument("--ratio", type=float, default=DEFAULT_RATIO, help="share of the candidate entries removed")
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED, help="seed of the removal draw (first of --seeds)")
    parser.add_argument("--seeds", type=int, default=1, help="fixture mode only: how many seeds, from --seed on")
    parser.add_argument("--out", type=Path, default=None, help="JSON evidence file")
    parser.add_argument("--jobs", action="append", default=[], help="job id prefix (repeatable)")
    parser.add_argument("--fixture", type=Path, help="fixture mode: the baseline is this bundle file")
    parser.add_argument("--fixture-db", help="fixture mode: the DSN holding the job's extraction (read only)")
    parser.add_argument("--fixture-job", help="fixture mode: the job whose extraction is replayed")
    args = parser.parse_args(argv)
    if not 0 <= args.ratio < 1:
        parser.error("--ratio must be in [0, 1)")
    if args.fixture is not None:
        if not args.fixture_db or not args.fixture_job:
            parser.error("--fixture needs --fixture-db and --fixture-job")
        if args.seeds < 1:
            parser.error("--seeds must be at least 1")
        return _fixture_main(args)
    if args.fixture_db or args.fixture_job or args.seeds != 1:
        parser.error("--fixture-db, --fixture-job and --seeds apply to --fixture only")

    try:
        jobs, entities = load_jobs(args.db)
    except Exception as exc:  # noqa: BLE001 — no driver, refused connection, no table or column: all "cannot be read"
        print(f"cannot read the database: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2
    if args.jobs:
        jobs = [j for j in jobs if any(j["id"].startswith(p) for p in args.jobs)]

    results: list[dict[str, Any]] = []
    skipped: list[tuple[str, str]] = []
    for job in jobs:
        if job["bundle_json"] is None or job["bundle_ledger_json"] is None or job["llm_result_json"] is None:
            skipped.append((job["id"], "bundle_json, bundle_ledger_json or llm_result_json is missing"))
            continue
        try:
            results.append(run_job(job, entities.get(job["id"], []), args.ratio, args.seed))
        except (ValueError, KeyError, TypeError) as exc:
            skipped.append((job["id"], f"{type(exc).__name__}: {str(exc)[:300]}"))

    totals = {
        "ablation": _total(r["ablation"] for r in results),
        "round_trip": _total(r["round_trip"] for r in results),
    }
    out = args.out or DEFAULT_OUT
    evidence = {
        "database": _dsn_label(args.db), "generated_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "ratio": args.ratio, "seed": args.seed, "unit": UNIT, "rounding": ROUNDING,
        "jobs": results, "skipped": [{"id": jid, "reason": reason} for jid, reason in skipped], "totals": totals,
    }
    if not _write_json(out, evidence):
        return 2
    print(render(results, totals, skipped, args.ratio, args.seed, out))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
