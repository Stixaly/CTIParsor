"""The API path stores Stage 2's type-conflict losers for the finalize ledger (issue #397).

The CLI run keeps what `resolve_type_conflicts` dropped (`RunResult.resolved_away`)
and records it as `dropped / outranked_type`.  The worker's finalize rebuilds
from stored rows, so `extraction_ready` stores the losers in
`jobs.resolved_types_json` (migration 15) and finalize hands them to
`with_named_entities`.  The bundle is the same with or without them.
"""
from __future__ import annotations

import json
import time

import pytest

from models.schemas import EntityType, RawEntity
from pipeline.orchestrator import Document, Hooks, RunOptions, run_document
from pipeline.stage3_llm import LLMEnrichmentResult

_TEXT = "Snake was used against France in 2024."
_LOSER = {"value": "Snake", "entity_type": "malware", "source": "cyner"}
_OUTRANKED = {
    "value": "Snake", "entity_type": "malware", "outcome": "dropped", "reason": "outranked_type",
    "sources": ["cyner"], "kept_types": ["tool"], "kept_sources": ["gazetteer"],
}


def _job(db, job_id: str, resolved_types_json: str | None):
    """A finalizable job whose stored rows hold "Snake" as a tool."""
    from api import worker
    from api.paths import uploads_dir

    uploads_dir().mkdir(parents=True, exist_ok=True)
    with db.get_conn() as conn:
        conn.execute(
            "INSERT INTO jobs (id, original_filename, status, report_text, llm_result_json, "
            "resolved_types_json, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?)",
            (job_id, "report.txt", "reviewing", _TEXT, LLMEnrichmentResult().model_dump_json(),
             resolved_types_json, db.now_iso(), db.now_iso()))
        conn.commit()
    worker._save_entities(job_id, [RawEntity(value="Snake", entity_type=EntityType.TOOL, source="gazetteer")],
                          LLMEnrichmentResult(), _TEXT)
    return job_id


def _finalize(db, job_id: str):
    from api import worker

    assert worker.re_run_final_stages(job_id, quick=True)
    with db.get_conn() as conn:
        row = conn.execute("SELECT bundle_json, bundle_ledger_json FROM jobs WHERE id=?", (job_id,)).fetchone()
    ledger = json.loads(row["bundle_ledger_json"])
    outranked = [e for e in ledger["entities"] if e.get("reason") == "outranked_type"]
    return row["bundle_json"], outranked


def _shipped(bundle_json: str):
    return {(o["type"], o.get("name")) for o in json.loads(bundle_json)["objects"]}


# ── Finalize reads the stored losers ─────────────────────────────────────────

def test_finalize_ledger_records_the_stored_loser_and_the_bundle_is_the_same_issue_397(temp_db):
    with_loser = _job(temp_db, "j-with", json.dumps([_LOSER]))
    control = _job(temp_db, "j-null", None)

    bundle, outranked = _finalize(temp_db, with_loser)
    control_bundle, control_outranked = _finalize(temp_db, control)

    assert outranked == [_OUTRANKED]
    assert control_outranked == []                               # NULL: a job run before migration 15
    assert ("tool", "Snake") in _shipped(bundle)
    assert ("malware", "Snake") not in _shipped(bundle)
    assert _shipped(bundle) == _shipped(control_bundle)


def test_a_rejected_winner_leaves_no_outranked_entry_issue_397(temp_db):
    job = _job(temp_db, "j-rejected", json.dumps([_LOSER]))
    with temp_db.get_conn() as conn:
        conn.execute("UPDATE entities SET accepted=0 WHERE job_id=? AND value='Snake'", (job,))
        conn.commit()

    _, outranked = _finalize(temp_db, job)

    assert outranked == []


def test_a_losing_type_the_analyst_brought_back_is_not_reported_dropped_issue_397(temp_db):
    # Stage 2 dropped Snake/malware; the analyst then adds Snake as malware.  The
    # stored row ships (or is outranked like any row): the stored loser must not
    # make the ledger say malware was dropped while the bundle holds it.
    from api import worker

    job = _job(temp_db, "j-back", json.dumps([_LOSER]))
    worker._save_entities(job, [RawEntity(value="Snake", entity_type=EntityType.TOOL, source="gazetteer"),
                                RawEntity(value="Snake", entity_type=EntityType.MALWARE, source="analyst")],
                          LLMEnrichmentResult(), _TEXT)

    bundle, outranked = _finalize(temp_db, job)

    shipped = _shipped(bundle)
    for entry in outranked:
        assert (entry["entity_type"], entry["value"]) not in shipped
    assert [e for e in outranked if e["entity_type"] == "malware" and e["sources"] == ["cyner"]] == []


def test_resolved_away_skips_a_type_a_stored_row_holds_again_issue_397():
    from pipeline.named_entities import with_named_entities

    loser = RawEntity(value="Snake", entity_type=EntityType.MALWARE, source="cyner")
    back = with_named_entities(LLMEnrichmentResult(), [("tool", "Snake", "gazetteer"), ("malware", "Snake", "analyst")],
                               resolved_away=[loser])
    control = with_named_entities(LLMEnrichmentResult(), [("tool", "Snake", "gazetteer")], resolved_away=[loser])

    assert back.resolved_away == ()
    assert [(o.value, o.entity_type) for o in control.resolved_away] == [("Snake", "malware")]


@pytest.mark.parametrize("stored", [
    "not json", '{"value": "Snake"}',
    json.dumps([{"value": "Snake", "entity_type": "not_a_type", "source": "cyner"}, "junk", {"value": "x"}]),
])
def test_unreadable_losers_are_skipped_and_finalize_succeeds_issue_397(temp_db, stored):
    job = _job(temp_db, "j-bad", stored)

    bundle, outranked = _finalize(temp_db, job)

    assert outranked == []
    assert ("tool", "Snake") in _shipped(bundle)


# ── The worker stores them ───────────────────────────────────────────────────

def _bare_job(db, job_id="j1"):
    with db.get_conn() as conn:
        conn.execute("INSERT INTO jobs (id, original_filename, status, created_at, updated_at) "
                     "VALUES (?,?,?,?,?)", (job_id, "r.txt", "processing", db.now_iso(), db.now_iso()))
        conn.commit()


def _stored(db, job_id="j1"):
    with db.get_conn() as conn:
        return conn.execute("SELECT resolved_types_json FROM jobs WHERE id=?", (job_id,)).fetchone()[
            "resolved_types_json"]


def test_extraction_ready_stores_the_losers_issue_397(temp_db):
    from api import worker

    _bare_job(temp_db)
    hooks = worker._WorkerHooks("j1", None, time.monotonic())
    hooks.type_conflicts_resolved([RawEntity(value="Snake", entity_type=EntityType.MALWARE, source="cyner")])

    hooks.extraction_ready([], LLMEnrichmentResult(), "")

    assert json.loads(_stored(temp_db)) == [_LOSER]


class _Baseline:
    """A Stage 3r reconciliation whose baseline holds `held` (type, value) pairs."""

    def __init__(self, *held):
        self.held = set(held)

    def entity(self, entity_type, value):
        from pipeline import baseline_stix
        return (baseline_stix.MATCHED, "malware--1") if (entity_type, value) in self.held else ("new", None)


def test_extraction_ready_stores_a_loser_the_baseline_holds_as_baseline_stix_issue_397(temp_db, monkeypatch):
    # Enrich mode: the CLI ledger gives such a loser the source `baseline_stix`
    # (baseline_holds); the stored loser carries it, so a finalize says the same.
    from api import worker

    _bare_job(temp_db)
    hooks = worker._WorkerHooks("j1", None, time.monotonic())
    hooks.reconciliation = _Baseline(("malware", "Snake"))
    hooks.type_conflicts_resolved([RawEntity(value="Snake", entity_type=EntityType.MALWARE, source="cyner"),
                                   RawEntity(value="Turla", entity_type=EntityType.MALWARE, source="cyner")])
    # _save_entities reads the reconciliation's other methods: not under test here.
    monkeypatch.setattr(worker, "_save_entities", lambda *a, **k: None)

    hooks.extraction_ready([], LLMEnrichmentResult(), "")

    assert json.loads(_stored(temp_db)) == [
        {"value": "Snake", "entity_type": "malware", "source": "baseline_stix"},
        {"value": "Turla", "entity_type": "malware", "source": "cyner"},    # control: not in the baseline
    ]


def test_extraction_ready_stores_an_empty_list_when_stage_2_dropped_nothing_issue_397(temp_db):
    from api import worker

    _bare_job(temp_db)

    worker._WorkerHooks("j1", None, time.monotonic()).extraction_ready([], LLMEnrichmentResult(), "")

    assert _stored(temp_db) == "[]"                              # not NULL: the job ran after migration 15


def test_a_run_hands_the_hook_the_losers_before_extraction_ready_issue_397(monkeypatch):
    import pipeline.stage2b_gazetteer as gaz
    import pipeline.stage2d_cyner as cyner
    for module in ("pipeline.stage2c_ttp_semantic", "pipeline.stage2d_cyner", "pipeline.stage2e_gliner"):
        monkeypatch.setattr(f"{module}._SKIP_HEAVY", True)
    monkeypatch.setattr(gaz, "available", lambda: True)
    monkeypatch.setattr(gaz, "match_gazetteer_traced", lambda text: (
        [RawEntity(value="Snake", entity_type=EntityType.TOOL, source="gazetteer")], []))
    monkeypatch.setattr(cyner, "cyner_available", lambda: True)
    monkeypatch.setattr(cyner, "extract_cyner_entities", lambda text: [
        RawEntity(value="Snake", entity_type=EntityType.MALWARE, source="cyner")])
    calls: list = []

    class Recording(Hooks):
        def type_conflicts_resolved(self, resolved_away):
            calls.append(("resolved", [(e.value, e.entity_type.value) for e in resolved_away]))

        def extraction_ready(self, entities, llm_result, text):
            calls.append(("ready", [(e.value, e.entity_type.value) for e in entities]))

    options = RunOptions(disabled=frozenset({"2f", "3"}), consensus=False, document_relations=False,
                         llm_parallelism=1, verify_relationships=False, verify_ttps=False)
    run_document(Document(text=_TEXT), options, Recording())

    assert calls[0] == ("resolved", [("Snake", "malware")])
    assert calls[1][0] == "ready" and ("Snake", "malware") not in calls[1][1]
