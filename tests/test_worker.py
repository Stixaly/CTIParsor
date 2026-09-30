"""api/worker.py — what the job store sees when a run fails, is reclaimed or
crashes, the hooks' guards, the subprocess watcher, and the finalize rebuild's
reading of the reviewer's decisions.  The pipeline itself is faked where the
test is about the worker, not about what a real run extracts."""
from __future__ import annotations

import json
import os
import threading
from types import SimpleNamespace

import pytest

import api.worker as worker
from models.schemas import EntityType, RawEntity
from pipeline.orchestrator import RunAborted
from pipeline.stage3_llm import LLMEnrichmentResult, RelationshipExtracted, TTPExtracted


@pytest.fixture()
def db(temp_db, tmp_path, monkeypatch):
    monkeypatch.setattr(worker, "_ROOT", tmp_path)
    (tmp_path / "uploads").mkdir()
    return temp_db


def _job(db, job_id: str = "j1", *, worker_id: str | None = None, status: str = "processing", **cols) -> str:
    ts = db.now_iso()
    fields = {"id": job_id, "original_filename": "APT report.txt", "status": status,
              "created_at": ts, "updated_at": ts, "worker_id": worker_id, **cols}
    with db.get_conn() as conn:
        conn.execute(f"INSERT INTO jobs ({', '.join(fields)}) VALUES ({', '.join('?' for _ in fields)})",
                     tuple(fields.values()))
        conn.commit()
    return job_id


def _row(db, job_id: str = "j1") -> dict:
    with db.get_conn() as conn:
        return dict(conn.execute("SELECT * FROM jobs WHERE id=?", (job_id,)).fetchone())


def _events(db, job_id: str = "j1") -> list[tuple[str, dict]]:
    with db.get_conn() as conn:
        rows = conn.execute("SELECT event_type, data FROM progress_events WHERE job_id=? ORDER BY id",
                            (job_id,)).fetchall()
    return [(r["event_type"], json.loads(r["data"])) for r in rows]


def _entities(db, job_id: str = "j1") -> list[dict]:
    with db.get_conn() as conn:
        return [dict(r) for r in conn.execute(
            "SELECT * FROM entities WHERE job_id=? ORDER BY entity_type, value", (job_id,)).fetchall()]


# ── _finalize_job ────────────────────────────────────────────────────────────

def test_an_unowned_job_takes_its_status_without_a_bundle(db):
    _job(db)
    assert worker._finalize_job("j1", "failed", None) is True
    assert _row(db)["status"] == "failed" and _row(db)["bundle_json"] is None


# ── _save_entities ───────────────────────────────────────────────────────────

_REPORT = "APT29 used spearphishing links. The operators ran Mimikatz and PsExec."


def test_llm_names_tools_and_ttps_are_saved_with_their_evidence(db):
    _job(db)
    llm = LLMEnrichmentResult(
        tools=["Mimikatz", "PsExec"],
        campaign_name="Dark Halo",
        ttps=[
            TTPExtracted(technique_name="Phishing", mitre_id="T1566.002",
                         evidence_text="APT29 used spearphishing links.", evidence_label="observed"),
            TTPExtracted(technique_name="Credential Dumping", mitre_id="T1003",
                         evidence_text="They dumped LSASS memory.", evidence_label="observed"),
            TTPExtracted(technique_name="Lateral Movement", evidence_label="assessed",
                         evidence_text="nowhere in the report"),
        ],
    )
    raw = [
        RawEntity(value="Phishing", entity_type=EntityType.TTP, mitre_id="T1566", source="semantic"),  # parent
        RawEntity(value="Spearphishing Link", entity_type=EntityType.TTP, mitre_id="t1566.002"),       # same id
        RawEntity(value="Exploitation", entity_type=EntityType.TTP, mitre_id="T1203", source="semantic"),
        RawEntity(value="185.220.101.45", entity_type=EntityType.IPV4),
    ]

    worker._save_entities("j1", raw, llm, report_text=_REPORT)

    rows = {(r["value"], r["entity_type"]): r for r in _entities(db)}
    assert set(rows) == {
        ("Mimikatz", "tool"), ("PsExec", "tool"), ("Dark Halo", "campaign"), ("185.220.101.45", "ipv4"),
        ("Exploitation", "ttp"), ("Phishing", "ttp"), ("Credential Dumping", "ttp"), ("Lateral Movement", "ttp"),
    }
    phishing = rows[("Phishing", "ttp")]
    assert phishing["source"] == "llm" and phishing["evidence_label"] == "observed"
    assert _REPORT[phishing["evidence_start"]:phishing["evidence_end"]] == "APT29 used spearphishing links."
    dumping = rows[("Credential Dumping", "ttp")]
    assert dumping["evidence_label"] == "inferred" and dumping["evidence_start"] is None     # unlocatable: demoted
    assert rows[("Lateral Movement", "ttp")]["evidence_label"] == "assessed"                # not demoted further
    assert rows[("Exploitation", "ttp")]["source"] == "semantic"


def test_a_quote_that_cannot_be_located_never_fails_the_save(db, monkeypatch):
    _job(db)

    def broken(quote, text):
        raise ValueError("pathological input")

    monkeypatch.setattr("pipeline.evidence_span.locate", broken)
    llm = LLMEnrichmentResult(ttps=[TTPExtracted(technique_name="Phishing", evidence_text="x",
                                                 evidence_label="reported")])
    worker._save_entities("j1", [], llm, report_text=_REPORT)
    (row,) = _entities(db)
    assert row["evidence_label"] == "inferred" and row["evidence_start"] is None


def test_denied_llm_names_are_not_saved(db, monkeypatch):
    _job(db)
    monkeypatch.setattr("pipeline.overrides.is_denied", lambda value, etype: value == "Cobalt Strike")
    worker._save_entities("j1", [], LLMEnrichmentResult(tools=["Cobalt Strike", "Rclone"]), report_text="")
    assert [r["value"] for r in _entities(db)] == ["Rclone"]


# ── Hooks ────────────────────────────────────────────────────────────────────

def test_the_timeout_hook_stops_a_run_past_the_limit(monkeypatch):
    monkeypatch.setattr(worker, "_MAX_JOB_TIMEOUT", 5)
    hooks = worker._WorkerHooks("j1", None, started=worker.time.monotonic() - 10)
    with pytest.raises(TimeoutError, match="Job timeout exceeded"):
        hooks.check_timeout()
    monkeypatch.setattr(worker, "_MAX_JOB_TIMEOUT", 0)                 # 0 = unlimited
    hooks.check_timeout()


def test_figure_spans_are_recorded_after_the_text(db, monkeypatch):
    _job(db)
    saved = []
    monkeypatch.setattr("pipeline.figure_store.save_spans",
                        lambda job_id, spans, provider: saved.append((job_id, spans, provider)) or len(spans))

    worker._WorkerHooks("j1", None, 0.0).text_ready("the text", [{"start": 0}], "anthropic")

    assert _row(db)["report_text"] == "the text"
    assert saved == [("j1", [{"start": 0}], "anthropic")]


def test_a_reclaimed_job_is_abandoned_before_its_entities_are_saved(db):
    _job(db, worker_id="w2")
    with pytest.raises(RunAborted):
        worker._WorkerHooks("j1", "w1", 0.0).extraction_ready([], LLMEnrichmentResult(tools=["X"]), "")
    assert _entities(db) == []


def test_run_config_and_stage_report_failures_never_fail_the_job(db, monkeypatch, caplog):
    _job(db)

    def boom(policy):
        raise RuntimeError("manifest unavailable")

    monkeypatch.setattr("api.run_config.build_run_config", boom)
    worker._WorkerHooks("j1", None, 0.0).policy_used({"rules": []})
    worker._record_stage_report("missing-job-is-fine", [{"stage": "1"}])     # nothing to update

    def down():
        raise ConnectionError("database is down")

    monkeypatch.setattr(worker, "get_conn", down)
    worker._record_stage_report("j1", [{"stage": "1"}])
    assert "run-config] not recorded" in caplog.text and "stage report not recorded" in caplog.text


def test_an_unreadable_policy_means_building_without_one(monkeypatch, caplog):
    def broken():
        raise RuntimeError("relationship_policy: permission denied")

    monkeypatch.setattr("api.db.load_relationship_policy", broken)
    assert worker._load_policy() is None
    assert "building without one" in caplog.text


# ── _run_pipeline's terminal states ─────────────────────────────────────────

class _Result:
    def __init__(self, bundle=None, ledger=None):
        self.bundle, self.ledger = bundle, ledger

    def stage_report(self):
        return [{"stage": "1", "status": "ran"}]


class _Bundle:
    def serialize(self, pretty):
        return '{"type": "bundle"}'


def _run(monkeypatch, outcome, *, during=None):
    def run_document(document, options, hooks):
        if during:
            during()
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome

    monkeypatch.setattr(worker, "run_document", run_document)
    worker._run_pipeline("j1", str(worker._ROOT / "uploads" / "j1.txt"), "APT report.txt")


def _reclaim(db, new_owner: str = "w2"):
    with db.get_conn() as conn:
        conn.execute("UPDATE jobs SET worker_id=? WHERE id='j1'", (new_owner,))
        conn.commit()


def test_a_run_without_a_bundle_is_failed(db, monkeypatch):
    _job(db)
    _run(monkeypatch, _Result(bundle=None))
    assert _row(db)["status"] == "failed"
    ((event, data),) = [e for e in _events(db) if e[0] == "done"]
    assert data["status"] == "failed" and "produced no bundle" in data["error"]
    assert json.loads(_row(db)["run_config_json"])["stage_report"] == [{"stage": "1", "status": "ran"}]


def test_a_run_past_its_timeout_is_failed(db, monkeypatch):
    _job(db)
    _run(monkeypatch, TimeoutError("Job timeout exceeded: 1900s > 1800s"))
    assert _row(db)["status"] == "failed"
    assert _events(db)[-1] == ("done", {"status": "failed", "error": "Job timeout exceeded: 1900s > 1800s"})


def test_an_aborted_run_writes_nothing(db, monkeypatch):
    _job(db, status="processing")
    _run(monkeypatch, RunAborted())
    assert _row(db)["status"] == "processing" and not [e for e in _events(db) if e[0] == "done"]


def test_a_run_whose_job_was_reclaimed_discards_its_bundle(db, monkeypatch):
    _job(db, worker_id="w1")
    _run(monkeypatch, _Result(bundle=_Bundle()), during=lambda: _reclaim(db))

    assert _row(db)["bundle_json"] is None and _row(db)["status"] == "processing"
    assert not [e for e in _events(db) if e[0] == "done"]


def test_a_failed_backup_does_not_fail_a_finished_run(db, monkeypatch, caplog):
    _job(db)

    def backup_fails():
        raise OSError("backup volume full")

    monkeypatch.setattr(worker, "backup_db", backup_fails)
    _run(monkeypatch, _Result(bundle=_Bundle(), ledger={"entities": []}))

    row = _row(db)
    assert row["status"] == "for_review" and json.loads(row["bundle_ledger_json"]) == {"entities": []}
    assert _events(db)[-1] == ("done", {"status": "for_review"})
    assert "Database backup failed" in caplog.text


# ── The subprocess ───────────────────────────────────────────────────────────

def test_the_subprocess_caps_native_threads_before_running(monkeypatch):
    for var in ("OMP_NUM_THREADS", "MKL_NUM_THREADS", "OPENBLAS_NUM_THREADS", "TOKENIZERS_PARALLELISM"):
        monkeypatch.setenv(var, "x")          # recorded, so teardown removes what setdefault adds
        monkeypatch.delenv(var)
    monkeypatch.setenv("OMP_NUM_THREADS", "8")                        # an operator's choice stays
    ran = []
    monkeypatch.setattr(worker, "_run_pipeline", lambda *args: ran.append(args))

    worker._subprocess_entry("j1", "/u/j1.pdf", "r.pdf")

    assert ran == [("j1", "/u/j1.pdf", "r.pdf")]
    assert (os.environ["OMP_NUM_THREADS"], os.environ["MKL_NUM_THREADS"],
            os.environ["TOKENIZERS_PARALLELISM"]) == ("8", "2", "false")


def test_the_upload_is_found_by_job_id(db):
    assert worker._upload_path_for("j1") is None
    (worker._ROOT / "uploads" / "j1.pdf").write_bytes(b"%PDF")
    assert worker._upload_path_for("j1").endswith("uploads/j1.pdf")


def test_an_unreadable_uploads_directory_is_no_upload(monkeypatch, caplog):
    class _Broken:
        def __truediv__(self, other):
            raise PermissionError("uploads: permission denied")

    monkeypatch.setattr(worker, "_ROOT", _Broken())
    assert worker._upload_path_for("j1") is None
    assert "Failed to resolve upload path" in caplog.text


class _FakeProcess:
    exit_code: int | None = 0
    on_join = None

    def __init__(self, target, args, daemon, name):
        self.target, self.args, self.name = target, args, name
        self.pid, self.exitcode = 4242, None

    def start(self):
        pass

    def join(self):
        if _FakeProcess.on_join:
            _FakeProcess.on_join()
        self.exitcode = _FakeProcess.exit_code


def _spawn(monkeypatch, exit_code, on_exit=None, on_join=None) -> threading.Event:
    _FakeProcess.exit_code = exit_code
    monkeypatch.setattr(_FakeProcess, "on_join", staticmethod(on_join) if on_join else None)
    done = threading.Event()
    monkeypatch.setattr(worker.mp, "get_context", lambda method: SimpleNamespace(Process=_FakeProcess))

    def exit_hook(job_id):
        done.set()
        if on_exit:
            on_exit(job_id)

    proc = worker._spawn_job("j1", "/u/j1.txt", "r.txt", exit_hook)
    assert (proc.target, proc.args, proc.name) == (worker._subprocess_entry, ("j1", "/u/j1.txt", "r.txt"),
                                                   "pipeline-j1")
    assert done.wait(5)
    return done


def test_a_clean_exit_only_frees_the_slot(db, monkeypatch):
    _job(db, worker_id="w1")
    _spawn(monkeypatch, 0)
    assert _row(db)["status"] == "processing" and _events(db) == []


@pytest.mark.parametrize("code,reason", [
    (-9, "SIGKILL (OS out-of-memory killer)"),
    (-11, "SIGSEGV"),
    (3, "exit code 3"),
    (None, "unknown (process has no exit code)"),
])
def test_a_crashed_subprocess_fails_its_job(db, monkeypatch, code, reason):
    _job(db, worker_id="w1")
    _spawn(monkeypatch, code)

    assert _row(db)["status"] == "failed"
    ((event, data),) = _events(db)
    assert event == "done" and reason in data["error"] and "SKIP_HEAVY_MODELS=1" in data["error"]


def test_a_crash_on_a_reclaimed_job_leaves_the_new_owner_alone(db, monkeypatch):
    """The lease expired while the starved subprocess was still alive, another
    worker took the job, then the OOM killer ended this one."""
    _job(db, worker_id="w1")
    _spawn(monkeypatch, -9, on_join=lambda: _reclaim(db))
    assert _row(db)["status"] == "processing" and _row(db)["worker_id"] == "w2"
    assert _events(db) == []


def test_the_watcher_survives_a_store_error_and_a_failing_exit_hook(db, monkeypatch, caplog):
    _job(db)

    def store_down(*a, **kw):
        raise ConnectionError("database is down")

    def exit_hook_fails(job_id):
        raise RuntimeError("slot accounting bug")

    monkeypatch.setattr(worker, "_finalize_job", store_down)
    _spawn(monkeypatch, -6, on_exit=exit_hook_fails)

    for _ in range(50):                                   # the hook raised after setting the event
        if "on_exit hook failed" in caplog.text:
            break
        threading.Event().wait(0.02)
    assert "Could not update job j1 status" in caplog.text
    assert "on_exit hook failed for job j1" in caplog.text


def test_a_loop_that_cannot_be_kicked_leaves_the_job_queued(db, monkeypatch, caplog):
    from api import queue_loop

    _job(db, status="uploaded")
    monkeypatch.setenv("CTIPARSOR_ROLE", "all")

    def cannot_start():
        raise RuntimeError("thread limit reached")

    monkeypatch.setattr(queue_loop, "start_embedded", cannot_start)
    assert worker.run_pipeline_async("j1", "/x", "r.txt") == "queued"
    assert "Could not kick the queue loop" in caplog.text


# ── Finalize: re_run_final_stages ────────────────────────────────────────────

def _entity(db, job_id, value, etype, *, accepted=1, mitre_id=None, source="llm"):
    with db.get_conn() as conn:
        conn.execute("INSERT INTO entities (id, job_id, value, entity_type, accepted, mitre_id, source) "
                     "VALUES (?,?,?,?,?,?,?)",
                     (f"{job_id}-{etype}-{value}", job_id, value, etype, accepted, mitre_id, source))
        conn.commit()


def _objects(bundle_json: str, stix_type: str) -> list[str]:
    return sorted(o.get("name", o.get("value", "")) for o in json.loads(bundle_json)["objects"]
                  if o["type"] == stix_type)


def test_finalize_of_an_unknown_job_is_none(db):
    assert worker.re_run_final_stages("nope") is None


def test_finalize_applies_every_reviewer_rejection_to_the_llm_blob(db):
    llm = LLMEnrichmentResult(
        ttps=[TTPExtracted(technique_name="Phishing", mitre_id="T1566"),
              TTPExtracted(technique_name="Obfuscation", mitre_id="T1027"),
              TTPExtracted(technique_name="Masquerading", mitre_id="T1036")],
        campaign_name="Dark Halo", targeted_countries=["France", "Germany"],
        targeted_sectors=["energy", "finance"],
    )
    _job(db, report_text="APT29 used Mimikatz. Mimikatz again.", llm_result_json=llm.model_dump_json())
    _entity(db, "j1", "APT29", "threat_actor")
    _entity(db, "j1", "apt29", "threat_actor")                     # the same actor twice: one SDO
    _entity(db, "j1", "Mimikatz", "tool")
    _entity(db, "j1", "mimikatz", "tool")
    _entity(db, "j1", "SUNBURST", "malware")
    _entity(db, "j1", "Rclone", "tool", accepted=0)                # rejected
    _entity(db, "j1", "Phishing", "technique", accepted=0)                  # rejected by name
    _entity(db, "j1", "whatever", "ttp", accepted=0, mitre_id="T1027")      # rejected by id
    _entity(db, "j1", "Dark Halo", "campaign", accepted=0)
    _entity(db, "j1", "Germany", "location", accepted=0)
    _entity(db, "j1", "finance", "identity", accepted=0)
    _entity(db, "j1", "Some Group", "no-such-type")                # unknown type: skipped
    _entity(db, "j1", "185.220.101.45", "ipv4")
    with db.get_conn() as conn:                                     # a row pydantic refuses: skipped
        conn.execute("INSERT INTO entities (id, job_id, value, entity_type, accepted, confidence) "
                     "VALUES ('bad', 'j1', '10.0.0.1', 'ipv4', 1, NULL)")
        conn.commit()

    bundle = worker.re_run_final_stages("j1", skip_rescan=False)

    assert _objects(bundle, "threat-actor") == ["APT29"]
    assert _objects(bundle, "tool") == ["Mimikatz"]
    assert _objects(bundle, "attack-pattern") == ["Masquerading"]
    assert _objects(bundle, "campaign") == []
    assert "Germany" not in _objects(bundle, "location") and "France" in _objects(bundle, "location")
    assert _objects(bundle, "ipv4-addr") == ["185.220.101.45"]
    row = _row(db)
    assert row["status"] == "completed" and json.loads(row["bundle_ledger_json"])
    assert (worker._ROOT / "output" / "APT_report_j1_bundle.json").exists()


def test_finalize_survives_a_corrupt_llm_blob_and_an_unreadable_anchor(db, monkeypatch):
    _job(db, status="reviewing", llm_result_json="{not json", report_text="APT29 used SUNBURST.")
    _entity(db, "j1", "APT29", "threat_actor")

    def anchor_fails(path, text):
        raise ValueError("bad sidecar")

    monkeypatch.setattr("pipeline.stage1_ingestion.extract_anchor", anchor_fails)
    bundle = worker.re_run_final_stages("j1", skip_rescan=True)

    assert _objects(bundle, "threat-actor") == ["APT29"]
    assert _row(db)["status"] == "reviewing"                      # the quick rebuild leaves it alone


def test_finalize_reads_relationship_dates_old_and_new(db):
    """ADR-0063 rows carry `times_json`; a row written before it has only
    start_time: kept as a legacy date, never re-interpreted."""
    text = "APT29 used SUNBURST in 2020. APT29 targeted SolarWinds."
    _job(db, report_text=text)
    for value, etype in [("APT29", "threat_actor"), ("SUNBURST", "malware"), ("SolarWinds", "identity")]:
        _entity(db, "j1", value, etype)
    dated = RelationshipExtracted(source_value="APT29", relationship_type="uses", target_value="SUNBURST",
                                  evidence_text="APT29 used SUNBURST in 2020.",
                                  times=[{"role": "within", "time_text": "in 2020", "value": "2020"}])
    dated = LLMEnrichmentResult(relationships=[dated])
    from pipeline.stage3_llm import check_relationship_times
    worker._save_entities("j1", [], check_relationship_times(dated, text, None))
    with db.get_conn() as conn:
        conn.execute("INSERT INTO relationships (id, job_id, source_value, relationship_type, target_value, "
                     "evidence_text, start_time) VALUES ('legacy', 'j1', 'APT29', 'targets', 'SolarWinds', "
                     "'APT29 targeted SolarWinds.', '2021-01-01T00:00:00Z')")
        conn.commit()

    bundle = json.loads(worker.re_run_final_stages("j1", skip_rescan=True))

    rels = {o["relationship_type"]: o for o in bundle["objects"] if o["type"] == "relationship"}
    assert [a["time_text"] for a in rels["uses"]["x_temporal_assertions"]] == ["in 2020"]
    assert rels["targets"]["x_temporal_assertions"]              # the legacy date survives


# ── The lexicon re-scan ──────────────────────────────────────────────────────

def test_the_rescan_skips_indicators_short_names_and_absent_names(db):
    _job(db)
    for value, etype in [("185.220.101.45", "ipv4"), ("Emo", "malware"), ("NotInText", "malware"),
                         ("GREYVIBE", "malware")]:
        _entity(db, "j1", value, etype)
    _entity(db, "j1", "Unreviewed", "malware", accepted=None)

    text = "GREYVIBE was seen. greyvibe_loader is not a match; later GREYVIBE again. Emo 185.220.101.45"
    assert worker._lexicon_rescan("j1", text) == 0
    assert worker._lexicon_rescan("j1", "") == 0
    assert len(_entities(db)) == 5                                  # nothing duplicated
