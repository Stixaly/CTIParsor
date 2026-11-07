"""A finalize publishes only the bundle built from the job's current review (#499).

`re_run_final_stages` reads the rows at the job's `review_revision`, builds
the bundle without the lock, then publishes it.  A decision that lands in
between bumps the revision: the build is stale, and it must not be published
as the job's bundle.  The finalize builds again from the rows as they now
stand.  The build is held by the same stand-in as in tests/test_bundle_builds.py."""
from __future__ import annotations

import json
import threading

import pytest

import api.worker as worker
from api.paths import uploads_dir


@pytest.fixture()
def db(temp_db):
    uploads_dir().mkdir(parents=True, exist_ok=True)     # under tmp_path (conftest)
    return temp_db


def _job(db, job_id: str = "j1", *, status: str = "for_review", **cols) -> None:
    ts = db.now_iso()
    fields = {"id": job_id, "original_filename": "APT report.txt", "status": status,
              "created_at": ts, "updated_at": ts, **cols}
    with db.get_conn() as conn:
        conn.execute(f"INSERT INTO jobs ({', '.join(fields)}) VALUES ({', '.join('?' for _ in fields)})",
                     tuple(fields.values()))
        conn.commit()


def _entity(db, job_id: str, value: str, etype: str) -> None:
    with db.get_conn() as conn:
        conn.execute("INSERT INTO entities (id, job_id, value, entity_type, accepted, source) "
                     "VALUES (?,?,?,?,1,'llm')", (f"{job_id}-{etype}-{value}", job_id, value, etype))
        conn.commit()


def _row(db, job_id: str = "j1") -> dict:
    with db.get_conn() as conn:
        return dict(conn.execute("SELECT * FROM jobs WHERE id=?", (job_id,)).fetchone())


def _names(bundle_json: str, stix_type: str) -> list[str]:
    return sorted(o["name"] for o in json.loads(bundle_json)["objects"] if o["type"] == stix_type)


class _HeldBuild:
    """Stands in for `api.worker.build_bundle`: the first call waits, after the
    rows were read, until the test releases it.  Later calls run at once."""

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


@pytest.mark.parametrize("quick", [False, True], ids=["finalize", "auto-finalize"])
def test_a_finalize_overtaken_by_a_decision_publishes_the_rebuilt_bundle(db, monkeypatch, quick):
    """(#499) The finalize reads `APT29` at revision 1 and is held in the build.
    The analyst adds SUNBURST (revision 2).  Released, the finalize must not
    publish its revision-1 bundle: the stored bundle carries SUNBURST at revision
    2, and the finalize returns that bundle.  Before the fix, the publish
    guard compared only the stored build's revision: the stored bundle had no
    SUNBURST, `bundle_review_revision == 1` while `review_revision == 2`."""
    _job(db, report_text="APT29 used SUNBURST.")
    _entity(db, "j1", "APT29", "threat_actor")
    held = _HeldBuild(worker.build_bundle)
    monkeypatch.setattr(worker, "build_bundle", held)

    result: list[str | None] = []
    errors: list[BaseException] = []

    def finalize():
        try:
            result.append(worker.re_run_final_stages("j1", quick=quick))
        except BaseException as exc:      # noqa: BLE001 — handed to the test thread
            errors.append(exc)
        finally:
            db.reset_connections()        # this thread's own connection

    slow = threading.Thread(target=finalize, daemon=True)
    slow.start()
    assert held.entered.wait(60)          # the rows are read: APT29 alone, at revision 1
    _entity(db, "j1", "SUNBURST", "malware")
    held.release.set()
    slow.join(60)
    assert not slow.is_alive() and not errors

    row = _row(db)
    assert row["review_revision"] == 2
    assert _names(row["bundle_json"], "malware") == ["SUNBURST"]
    assert row["bundle_review_revision"] == 2
    assert _names(result[0], "malware") == ["SUNBURST"]
    assert row["status"] == ("for_review" if quick else "completed")


def test_a_finalize_overtaken_at_every_build_stops_and_publishes_nothing(db, monkeypatch):
    """(#499) A decision lands during every build: the finalize builds again a
    bounded number of times, then raises FinalizeOvertaken (409 at the API)
    instead of looping, and no stale bundle is published."""
    _job(db, report_text="APT29 used SUNBURST.")
    _entity(db, "j1", "APT29", "threat_actor")
    real = worker.build_bundle
    calls: list[int] = []

    def build_then_decide(*args, **kwargs):
        out = real(*args, **kwargs)
        calls.append(1)
        with db.get_conn() as conn:       # a decision lands before the publish
            conn.execute("UPDATE jobs SET review_revision = COALESCE(review_revision, 0) + 1 WHERE id='j1'")
            conn.commit()
        return out

    monkeypatch.setattr(worker, "build_bundle", build_then_decide)
    with pytest.raises(worker.FinalizeOvertaken):
        worker.re_run_final_stages("j1")
    assert len(calls) == worker._MAX_REBUILDS + 1
    assert _row(db)["bundle_json"] is None
