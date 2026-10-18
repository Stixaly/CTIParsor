"""Which build of a job's bundle is stored (ADR-0086).

`re_run_final_stages` reads the job's rows, maps them without holding the
lock, then writes.  Two finalizes of one job overlap whenever the review page's
auto-finalize (4 s after an edit) meets the Finalize button, and the one that
read the rows first may finish last."""
from __future__ import annotations

import json
import logging
import re
import threading
from contextlib import contextmanager
from pathlib import Path

import pytest

import api.worker as worker
from api.db_backend import PgConnection
from api.paths import output_dir, uploads_dir
from pipeline.bundle_revisions import git_rev_of
from pipeline.stage5_validation import INVALID, VALIDATED, ValidationResult, export_path


@pytest.fixture()
def db(temp_db):
    uploads_dir().mkdir(parents=True)        # under tmp_path (conftest)
    return temp_db


def _job(db, job_id: str = "j1", *, status: str = "reviewing", **cols) -> str:
    ts = db.now_iso()
    fields = {"id": job_id, "original_filename": "APT report.txt", "status": status,
              "created_at": ts, "updated_at": ts, **cols}
    with db.get_conn() as conn:
        conn.execute(f"INSERT INTO jobs ({', '.join(fields)}) VALUES ({', '.join('?' for _ in fields)})",
                     tuple(fields.values()))
        conn.commit()
    return job_id


def _entity(db, job_id, value, etype, *, accepted=1, source="llm"):
    with db.get_conn() as conn:
        conn.execute("INSERT INTO entities (id, job_id, value, entity_type, accepted, source) "
                     "VALUES (?,?,?,?,?,?)",
                     (f"{job_id}-{etype}-{value}", job_id, value, etype, accepted, source))
        conn.commit()


def _row(db, job_id: str = "j1") -> dict:
    with db.get_conn() as conn:
        return dict(conn.execute("SELECT * FROM jobs WHERE id=?", (job_id,)).fetchone())


def _names(bundle_json: str, stix_type: str) -> list[str]:
    return sorted(o["name"] for o in json.loads(bundle_json)["objects"] if o["type"] == stix_type)


class _HeldBuild:
    """Stands in for `api.worker.build_bundle`: the first call waits, after the
    rows were read, until the test releases it."""

    def __init__(self, real):
        self.real = real
        self.entered = threading.Event()
        self.release = threading.Event()
        self._calls = 0
        self._guard = threading.Lock()

    def __call__(self, *args, **kwargs):
        with self._guard:
            self._calls += 1
            first = self._calls == 1
        if first:
            self.entered.set()
            assert self.release.wait(60), "the held build was never released"
        return self.real(*args, **kwargs)


def _in_thread(db, target) -> tuple[threading.Thread, list[BaseException]]:
    errors: list[BaseException] = []

    def run():
        try:
            target()
        except BaseException as exc:     # noqa: BLE001 — handed to the test thread
            errors.append(exc)
        finally:
            db.reset_connections()       # this thread's own connection

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    return thread, errors


def test_a_slow_finalize_does_not_publish_over_a_newer_one(db, monkeypatch):
    """A reads the rows, the analyst decides again, B reads and publishes, then
    A finishes: the stored bundle must stay B's, built from the newer rows."""
    _job(db, report_text="APT29 used SUNBURST.")
    _entity(db, "j1", "APT29", "threat_actor")
    held = _HeldBuild(worker.build_bundle)
    monkeypatch.setattr(worker, "build_bundle", held)

    slow, errors = _in_thread(db, lambda: worker.re_run_final_stages("j1", quick=True))
    assert held.entered.wait(60)                         # A has read its rows: APT29 alone
    _entity(db, "j1", "SUNBURST", "malware")             # the analyst's next decision
    assert _names(worker.re_run_final_stages("j1", quick=True), "malware") == ["SUNBURST"]   # B

    held.release.set()
    slow.join(60)
    assert not slow.is_alive() and not errors

    row = _row(db)
    assert _names(row["bundle_json"], "malware") == ["SUNBURST"]
    assert "SUNBURST" in row["bundle_ledger_json"]       # the ledger is B's too


# ── Which build is stored ────────────────────────────────────────────────────

def _stage5(monkeypatch, refuses=lambda text: []):
    """Stage 5's validation stands in: INVALID with the errors `refuses(bundle
    text)` returns, if any.  It writes nothing: the export file is written by
    the real `export_bundle`, under tmp_path (conftest)."""
    def fake(text):
        errors = refuses(text)
        return ValidationResult(INVALID if errors else VALIDATED, errors)

    monkeypatch.setattr("pipeline.stage5_validation.validate_bundle", fake)


def _outcome(call):
    """What a finalize gave: its bundle, or the BundleInvalidError it raised."""
    try:
        return call()
    except worker.BundleInvalidError as exc:
        return exc


def _overlap(db, monkeypatch, *, a_quick: bool, b_quick: bool, status: str = "reviewing", edit: bool = True):
    """A reads the rows (APT29 alone) and is held; the analyst adds SUNBURST
    (unless `edit` is off); B builds and publishes; A is released and finishes.
    Returns what A gave, then what B gave."""
    _job(db, status=status, report_text="APT29 used SUNBURST.")
    _entity(db, "j1", "APT29", "threat_actor")
    held = _HeldBuild(worker.build_bundle)
    monkeypatch.setattr(worker, "build_bundle", held)

    a: list = []
    slow, errors = _in_thread(db, lambda: a.append(_outcome(lambda: worker.re_run_final_stages("j1", quick=a_quick))))
    assert held.entered.wait(60)
    if edit:
        _entity(db, "j1", "SUNBURST", "malware")
    b = _outcome(lambda: worker.re_run_final_stages("j1", quick=b_quick))

    held.release.set()
    slow.join(60)
    assert not slow.is_alive() and not errors
    return a[0], b


def _kind(row: dict) -> str:
    return json.loads(row["bundle_build_json"])["kind"]


def test_the_stored_row_is_the_newer_builds_in_every_column(db, monkeypatch):
    _stage5(monkeypatch)
    a, b = _overlap(db, monkeypatch, a_quick=True, b_quick=False)     # B is the full one: its kind, the status

    row = _row(db)
    assert _names(row["bundle_json"], "malware") == ["SUNBURST"] and row["bundle_json"] == b == a
    assert "SUNBURST" in row["bundle_ledger_json"]
    assert row["bundle_validation"] == "validated"
    assert _kind(row) == "finalize"                                   # A's record would say "quick"
    assert row["bundle_review_revision"] == row["review_revision"] == 2
    assert row["status"] == "completed"


def test_a_manual_finalize_that_loses_the_race_completes_the_job_with_the_newer_bundle(db, monkeypatch):
    _stage5(monkeypatch)
    a, b = _overlap(db, monkeypatch, a_quick=False, b_quick=True)

    row = _row(db)
    assert _names(a, "malware") == ["SUNBURST"] and a == b == row["bundle_json"]
    assert row["status"] == "completed"
    assert _kind(row) == "quick"                                      # B's build stands


@pytest.mark.parametrize(("quick", "status", "expected"), [
    (True, "reviewing", "reviewing"), (True, "completed", "completed"), (False, "reviewing", "completed")])
def test_a_refused_builds_own_verdict_acts_on_nothing(db, monkeypatch, quick, status, expected):
    """A, built from APT29 alone, is the one the schemas refuse: no error, the
    stored valid verdict stays, and the status follows the stored bundle."""
    _stage5(monkeypatch, lambda text: [] if _names(text, "malware") else ["no malware"])
    a, b = _overlap(db, monkeypatch, a_quick=quick, b_quick=True, status=status)

    row = _row(db)
    assert isinstance(a, str) and a == b == row["bundle_json"]
    assert (row["bundle_validation"], row["bundle_validation_errors"]) == ("validated", None)
    assert row["status"] == expected


@pytest.mark.parametrize("quick", [True, False])
def test_a_refused_build_reports_the_stored_invalid_verdict_not_its_own(db, monkeypatch, quick):
    """B, built from the newer rows, is the one the schemas refuse.  A, valid
    on its own, raises with the STORED errors and completes nothing."""
    _stage5(monkeypatch, lambda text: ["SUNBURST is refused"] if _names(text, "malware") else [])
    a, b = _overlap(db, monkeypatch, a_quick=quick, b_quick=True, status="completed")

    for raised in (a, b):
        assert isinstance(raised, worker.BundleInvalidError) and raised.errors == ["SUNBURST is refused"]
    row = _row(db)
    assert (row["bundle_validation"], json.loads(row["bundle_validation_errors"])) == (
        "invalid", ["SUNBURST is refused"])
    assert row["status"] == "for_review"                              # B retired the job; A did not complete it


def test_two_builds_from_the_same_rows_both_publish(db, monkeypatch):
    _stage5(monkeypatch)
    a, b = _overlap(db, monkeypatch, a_quick=False, b_quick=True, edit=False)

    assert isinstance(a, str) and isinstance(b, str)
    row = _row(db)
    assert row["bundle_json"] == a                                    # same rows: the last writer wins
    assert _kind(row) == "finalize" and row["status"] == "completed"
    assert row["bundle_review_revision"] == row["review_revision"] == 1
    assert worker.bundle_output_path("j1", "APT_report").read_text(encoding="utf-8") == a   # its file too


def test_a_build_from_newer_rows_replaces_the_stored_one(db, monkeypatch):
    _stage5(monkeypatch)
    _job(db, report_text="APT29 used SUNBURST.")
    _entity(db, "j1", "APT29", "threat_actor")
    worker.re_run_final_stages("j1", quick=True)
    assert _row(db)["bundle_review_revision"] == 1

    _entity(db, "j1", "SUNBURST", "malware")
    worker.re_run_final_stages("j1", quick=True)
    row = _row(db)
    assert _names(row["bundle_json"], "malware") == ["SUNBURST"] and row["bundle_review_revision"] == 2
    assert worker.bundle_output_path("j1", "APT_report").read_text(encoding="utf-8") == row["bundle_json"]


def test_a_job_deleted_while_it_is_built_is_not_an_error(db, monkeypatch):
    from api.routes.jobs import _delete_job

    _stage5(monkeypatch)
    _job(db, report_text="APT29 used SUNBURST.")
    _entity(db, "j1", "APT29", "threat_actor")
    held = _HeldBuild(worker.build_bundle)
    monkeypatch.setattr(worker, "build_bundle", held)

    a: list = []
    slow, errors = _in_thread(db, lambda: a.append(_outcome(lambda: worker.re_run_final_stages("j1"))))
    assert held.entered.wait(60)
    assert _delete_job("j1")
    held.release.set()
    slow.join(60)

    assert not slow.is_alive() and not errors
    assert isinstance(a[0], str)                                      # nothing stored, nothing raised
    assert list(output_dir().glob("*j1*")) == []                      # and no orphan export file


# ── The export file ──────────────────────────────────────────────────────────

def test_a_refused_build_writes_no_export_file(db, monkeypatch):
    """A, built from APT29 alone, is refused and finishes last: the file stays
    B's, the build that published."""
    _stage5(monkeypatch)
    a, b = _overlap(db, monkeypatch, a_quick=True, b_quick=True)

    path = worker.bundle_output_path("j1", "APT_report")
    assert path.read_text(encoding="utf-8") == _row(db)["bundle_json"] == b == a
    assert _names(b, "malware") == ["SUNBURST"]


def test_an_export_that_cannot_be_written_publishes_nothing(db, monkeypatch):
    _stage5(monkeypatch)

    def full(content, path):
        raise OSError("disk full")

    monkeypatch.setattr("pipeline.stage5_validation._write_file", full)
    _job(db, report_text="APT29 used SUNBURST.")
    _entity(db, "j1", "APT29", "threat_actor")

    with pytest.raises(OSError, match="disk full"):
        worker.re_run_final_stages("j1", quick=False)

    row = _row(db)
    assert (row["bundle_json"], row["bundle_build_json"], row["bundle_review_revision"]) == (None, None, None)
    assert row["status"] == "reviewing"


def test_a_published_invalid_build_writes_only_the_invalid_file(db, monkeypatch):
    _stage5(monkeypatch, lambda text: ["bad"])
    _job(db, report_text="APT29 used SUNBURST.")
    _entity(db, "j1", "APT29", "threat_actor")

    with pytest.raises(worker.BundleInvalidError):
        worker.re_run_final_stages("j1", quick=False)

    path = worker.bundle_output_path("j1", "APT_report")
    invalid = export_path(str(path), ValidationResult(INVALID))
    assert Path(invalid).read_text(encoding="utf-8") == _row(db)["bundle_json"]
    assert not path.exists()


@pytest.mark.parametrize(("stored", "errors"), [
    ("not json {", []), ('{"a": 1}', []), (None, []), ('[1, "kept", null]', ["kept"]), ('["bad"]', ["bad"])])
def test_a_damaged_stored_verdict_does_not_turn_a_refused_build_into_a_500(db, monkeypatch, stored, errors):
    _stage5(monkeypatch)
    _job(db, report_text="APT29 used SUNBURST.")
    _entity(db, "j1", "APT29", "threat_actor")
    with db.get_conn() as conn:
        conn.execute("UPDATE jobs SET bundle_json='{}', bundle_validation='invalid', bundle_validation_errors=?, "
                     "bundle_review_revision = review_revision + 1", (stored,))

    with pytest.raises(worker.BundleInvalidError) as raised:
        worker.re_run_final_stages("j1")

    assert raised.value.errors == errors
    assert _row(db)["status"] == "reviewing"                          # the stored verdict is invalid: not completed


# ── The snapshot ─────────────────────────────────────────────────────────────

def test_every_read_of_the_rows_is_inside_the_snapshot(db, monkeypatch):
    """Not just the snapshot itself: nothing fails if a query of the job's rows
    drifts back out of the REPEATABLE READ block, so the call site is watched."""
    _stage5(monkeypatch)
    _job(db, report_text="APT29 used SUNBURST.")
    _entity(db, "j1", "APT29", "threat_actor")
    _entity(db, "j1", "Sofacy", "threat_actor", accepted=0)           # a rejected row: its own query
    state = {"snapshot": False, "recording": True}
    reads: list[tuple[str, bool]] = []
    real_transaction, real_execute, real_build = worker.transaction, PgConnection.execute, worker.build_bundle

    @contextmanager
    def watched(conn, *, snapshot=False):
        with real_transaction(conn, snapshot=snapshot) as inner:
            state["snapshot"] = snapshot
            try:
                yield inner
            finally:
                state["snapshot"] = False

    def recording(self, sql, params=None):
        if state["recording"] and re.match(r"\s*SELECT.* FROM (jobs|entities|relationships)\b", sql, re.DOTALL):
            reads.append((sql, state["snapshot"]))
        return real_execute(self, sql, params)

    def build(*args, **kwargs):
        state["recording"] = False                                    # everything that reads the rows is before this
        return real_build(*args, **kwargs)

    monkeypatch.setattr(worker, "transaction", watched)
    monkeypatch.setattr(PgConnection, "execute", recording)
    monkeypatch.setattr(worker, "build_bundle", build)

    worker.re_run_final_stages("j1", quick=True)

    tables = {re.search(r"FROM (\w+)", sql).group(1) for sql, _ in reads}
    assert tables == {"jobs", "entities", "relationships"}
    assert any("accepted=0" in sql for sql, _ in reads)               # the rejected rows
    outside = [sql for sql, inside in reads if not inside]
    assert outside == []


@pytest.mark.parametrize("quick", [True, False])
def test_a_build_record_that_cannot_be_built_never_fails_the_finalize(db, monkeypatch, caplog, quick):
    _stage5(monkeypatch)

    def broken():
        raise RuntimeError("data directory unreadable")

    monkeypatch.setattr("api.run_config.build_manifest", broken)
    _job(db, report_text="APT29 used SUNBURST.")
    _entity(db, "j1", "APT29", "threat_actor")

    with caplog.at_level(logging.WARNING, logger="api.worker"):
        bundle = worker.re_run_final_stages("j1", quick=quick)

    row = _row(db)
    build = json.loads(row["bundle_build_json"])
    assert row["bundle_json"] == bundle and row["bundle_review_revision"] == 1      # published all the same
    assert row["status"] == ("reviewing" if quick else "completed")
    assert build["kind"] == ("quick" if quick else "finalize") and build["built_at"]
    assert build["error"] == "RuntimeError: data directory unreadable"
    assert "git_rev" not in build and git_rev_of(row["bundle_build_json"]) is None   # freshness: the run's revision
    assert "build record not built" in caplog.text

def test_a_snapshot_reads_one_state_and_refuses_writes(db):
    import psycopg

    _job(db)
    _entity(db, "j1", "APT29", "threat_actor")
    conn = db.get_conn()

    def count() -> int:
        return conn.execute("SELECT count(*) AS n FROM entities").fetchone()["n"]

    with db.transaction(conn, snapshot=True):
        assert count() == 1
        other, errors = _in_thread(db, lambda: _entity(db, "j1", "SUNBURST", "malware"))
        other.join(60)
        assert not errors
        assert count() == 1                                           # a commit after the first read is not seen
    assert count() == 2

    with pytest.raises(psycopg.errors.ReadOnlySqlTransaction):
        with db.transaction(conn, snapshot=True):
            conn.execute("DELETE FROM entities")
    assert count() == 2


# ── review_revision ──────────────────────────────────────────────────────────

_NEW_ROW = {
    "entities": "INSERT INTO entities (id, job_id, value, entity_type) VALUES ('x1', ?, 'APT29', 'threat_actor')",
    "relationships": "INSERT INTO relationships (id, job_id, source_value, relationship_type, target_value) "
                     "VALUES ('x1', ?, 'APT29', 'uses', 'SUNBURST')",
}


def _revision(db, job_id: str = "j1") -> int:
    return _row(db, job_id)["review_revision"]


@pytest.mark.parametrize("table", ["entities", "relationships"])
def test_every_write_to_a_jobs_rows_bumps_its_revision(db, table):
    _job(db)
    _job(db, "j2")
    conn = db.get_conn()
    assert _revision(db) == 0

    conn.execute(_NEW_ROW[table], ("j1",))
    assert (_revision(db), _revision(db, "j2")) == (1, 0)             # INSERT, and only that job's

    conn.execute(f"UPDATE {table} SET accepted=1 WHERE id='x1'")
    assert _revision(db) == 2                                         # UPDATE

    conn.execute(f"UPDATE {table} SET job_id='j2' WHERE id='x1'")
    assert (_revision(db), _revision(db, "j2")) == (3, 1)             # moved: both jobs

    conn.execute(f"DELETE FROM {table} WHERE id='x1'")
    assert (_revision(db), _revision(db, "j2")) == (3, 2)             # DELETE


def test_a_change_through_the_api_bumps_the_revision(db, temp_db_client):
    _job(db, status="for_review")
    made = temp_db_client.post("/api/jobs/j1/entities", json={"value": "SUNBURST", "entity_type": "malware"}).json()
    assert _revision(db) == 1

    assert temp_db_client.patch(f"/api/jobs/j1/entities/{made['id']}", json={"accepted": True}).status_code == 200
    assert _revision(db) > 1


def test_deleting_a_job_with_rows_still_works(db):
    from api.routes.jobs import _delete_job

    for job_id in ("j1", "j2"):
        _job(db, job_id)
        db.get_conn().execute(_NEW_ROW["entities"].replace("'x1'", f"'{job_id}-e'"), (job_id,))
        db.get_conn().execute(_NEW_ROW["relationships"].replace("'x1'", f"'{job_id}-r'"), (job_id,))

    def rows(job_id: str) -> int:
        return sum(db.get_conn().execute(f"SELECT count(*) AS n FROM {t} WHERE job_id=?", (job_id,)).fetchone()["n"]
                   for t in ("entities", "relationships"))

    assert _delete_job("j1")                                          # the children first, then the job
    assert rows("j1") == 0 and _row(db, "j2")["id"] == "j2" and rows("j2") == 2 and _revision(db, "j2") == 2

    db.get_conn().execute("DELETE FROM jobs WHERE id='j2'")           # the foreign keys cascade through the trigger
    assert rows("j2") == 0


# ── The record of the build ──────────────────────────────────────────────────

@pytest.mark.parametrize(("quick", "kind"), [(True, "quick"), (False, "finalize")])
def test_a_finalize_records_what_built_its_bundle(db, monkeypatch, quick, kind):
    _stage5(monkeypatch)
    policy = {"global": "enforce", "rules": []}
    loaded: list = []
    passed: list = []
    real = worker.build_bundle
    monkeypatch.setattr(worker, "_load_policy", lambda: loaded.append(1) or policy)
    monkeypatch.setattr(worker, "build_bundle", lambda *a, **kw: passed.append(kw["policy"]) or real(*a, **kw))
    monkeypatch.setattr("api.run_config._resolve_git_rev", lambda: "abc1234")
    monkeypatch.setenv("STIX_TLP", "amber")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-secret-value")
    _job(db, report_text="APT29 used SUNBURST.")
    _entity(db, "j1", "APT29", "threat_actor")

    worker.re_run_final_stages("j1", quick=quick)

    row = _row(db)
    build = json.loads(row["bundle_build_json"])
    assert set(build) == {"kind", "built_at", "git_rev", "policy", "env", "manifest"}
    assert build["kind"] == kind and re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", build["built_at"])
    assert build["git_rev"] == "abc1234"
    assert build["policy"] == policy and passed == [policy] and len(loaded) == 1     # read once, used for both
    assert build["env"]["STIX_TLP"] == "amber"
    assert set(build["manifest"]) == {"llm", "models", "data", "packages"}
    assert row["bundle_review_revision"] == row["review_revision"] == 1
    assert "sk-secret-value" not in row["bundle_build_json"]


# ── The run's own write ──────────────────────────────────────────────────────

@pytest.mark.parametrize("owner", [None, "w1"])
def test_a_runs_bundle_is_stored_with_its_build_and_the_revision_it_followed(db, owner):
    _job(db, worker_id=owner)
    _entity(db, "j1", "APT29", "threat_actor")
    _entity(db, "j1", "SUNBURST", "malware")

    assert worker._finalize_job("j1", "for_review", owner, bundle_json="{}", build_json='{"kind": "run"}')
    row = _row(db)
    assert (row["bundle_build_json"], row["bundle_review_revision"]) == ('{"kind": "run"}', 2)
    assert row["review_revision"] == 2

    assert worker._finalize_job("j1", "for_review", owner, bundle_json="{}")      # a bundle with no build to name
    assert _row(db)["bundle_build_json"] is None
    assert worker._finalize_job("j1", "failed", owner)                           # no bundle: the record stays
    assert _row(db)["bundle_review_revision"] == 2


def test_a_finalize_that_read_the_rows_before_the_runs_write_is_refused(db, monkeypatch):
    _stage5(monkeypatch)
    _job(db, report_text="APT29 used SUNBURST.")
    _entity(db, "j1", "APT29", "threat_actor")
    held = _HeldBuild(worker.build_bundle)
    monkeypatch.setattr(worker, "build_bundle", held)

    a: list = []
    slow, errors = _in_thread(db, lambda: a.append(worker.re_run_final_stages("j1", quick=True)))
    assert held.entered.wait(60)
    _entity(db, "j1", "SUNBURST", "malware")                                     # the analyst decides again
    assert worker._finalize_job("j1", "for_review", None, bundle_json="{}", build_json='{"kind": "run"}')

    held.release.set()
    slow.join(60)
    assert not slow.is_alive() and not errors
    assert a == ["{}"] and _row(db)["bundle_json"] == "{}"                       # the run's bundle stands


def test_a_finalize_is_refused_when_the_stored_bundle_is_from_newer_rows(db, monkeypatch):
    _stage5(monkeypatch)
    _job(db, report_text="APT29 used SUNBURST.")
    _entity(db, "j1", "APT29", "threat_actor")
    with db.get_conn() as conn:
        conn.execute("UPDATE jobs SET bundle_json='{}', bundle_review_revision = review_revision + 1")

    assert worker.re_run_final_stages("j1") == "{}"
    row = _row(db)
    assert (row["bundle_json"], row["status"]) == ("{}", "completed")             # the stored bundle stands
