"""GET /api/relationship-policy/last-run — synthesis accounting of the newest bundle.

The endpoint feeds the Policy page's per-rule badges (ADR-0026).  Its input is a
raw database column holding a serialised STIX bundle, so the parsing half is
tested directly and exhaustively: a corrupt or pre-ADR-0026 bundle must produce
`available: false`, never an exception, because a settings page that 500s is
worse than one that says "no data".
"""

import json

from api.routes.policy import _extract_synthesis_stats

# ── Fixtures for the parser ───────────────────────────────────────────────────

_PIN = {
    "budget": 200,
    "mode": "fair-share",
    "total_candidates": 313,
    "total_emitted": 200,
    "total_truncated": 113,
    "rules": [
        {"rule": "malware uses attack-pattern",
         "candidates": 273, "emitted": 160, "truncated": 113},
    ],
}
_COMPLETION = {
    "aliases_merged": 0, "reference_added": 0, "transitive_added": 200,
    "long_distance_added": 0, "skipped_not_suggested": 0,
    "capped": True, "notes": [],
}
_STATS = {"pin": _PIN, "completion": _COMPLETION}


def _bundle(*objects: dict) -> str:
    return json.dumps({"type": "bundle", "id": "bundle--x", "objects": list(objects)})


def _report(**extra) -> dict:
    return {"type": "report", "id": "report--x", "name": "r", **extra}


# ── _extract_synthesis_stats ──────────────────────────────────────────────────

def test_extract_returns_stats_from_report_object():
    raw = _bundle({"type": "indicator", "id": "indicator--1"},
                  _report(x_synthesis_stats=_STATS))
    assert _extract_synthesis_stats(raw) == _STATS


def test_extract_returns_none_on_invalid_json():
    assert _extract_synthesis_stats("{not json") is None


def test_extract_returns_none_on_empty_string():
    assert _extract_synthesis_stats("") is None


def test_extract_returns_none_on_none():
    assert _extract_synthesis_stats(None) is None


def test_extract_returns_none_when_objects_missing():
    assert _extract_synthesis_stats('{"type": "bundle"}') is None


def test_extract_returns_none_when_objects_not_a_list():
    assert _extract_synthesis_stats('{"objects": "oops"}') is None


def test_extract_returns_none_when_top_level_not_a_dict():
    assert _extract_synthesis_stats('["oops"]') is None


def test_extract_skips_non_dict_objects():
    """A bundle whose object list holds junk must not raise."""
    raw = json.dumps({"objects": ["oops", None, 42, _report(x_synthesis_stats=_STATS)]})
    assert _extract_synthesis_stats(raw) == _STATS


def test_extract_returns_none_when_no_report():
    assert _extract_synthesis_stats(_bundle({"type": "indicator", "id": "i--1"})) is None


def test_extract_returns_none_when_property_absent():
    """A bundle built before ADR-0026 carries no x_synthesis_stats."""
    assert _extract_synthesis_stats(_bundle(_report())) is None


def test_extract_returns_none_when_property_not_a_dict():
    assert _extract_synthesis_stats(_bundle(_report(x_synthesis_stats="oops"))) is None


# ── The endpoint, against a real isolated database ────────────────────────────

_KEYS = {"job_id", "filename", "created_at", "pin", "completion", "available"}


def _insert_job(temp_db, job_id: str, created_at: str, bundle_json: str | None) -> None:
    with temp_db.get_conn() as conn:
        conn.execute(
            "INSERT INTO jobs (id, original_filename, status, bundle_json, "
            "created_at, updated_at) VALUES (?, ?, 'for_review', ?, ?, ?)",
            (job_id, f"{job_id}.pdf", bundle_json, created_at, created_at),
        )
        conn.commit()


def test_last_run_on_empty_database(temp_db_client):
    r = temp_db_client.get("/api/relationship-policy/last-run")
    assert r.status_code == 200
    body = r.json()
    assert set(body) == _KEYS
    assert body["available"] is False
    assert body["job_id"] is None
    assert body["pin"] is None


def test_last_run_returns_pin_stats(temp_db, temp_db_client):
    _insert_job(temp_db, "job-a", "2026-08-23T09:00:00",
                _bundle(_report(x_synthesis_stats=_STATS)))
    body = temp_db_client.get("/api/relationship-policy/last-run").json()
    assert set(body) == _KEYS
    assert body["available"] is True
    assert body["job_id"] == "job-a"
    assert body["filename"] == "job-a.pdf"
    assert body["pin"] == _PIN
    assert body["completion"] == _COMPLETION


def test_last_run_reports_unavailable_for_pre_adr_bundle(temp_db, temp_db_client):
    """The newest bundle predates the feature: say so, don't scan backwards."""
    _insert_job(temp_db, "job-old", "2026-08-23T09:00:00", _bundle(_report()))
    body = temp_db_client.get("/api/relationship-policy/last-run").json()
    assert body["available"] is False
    assert body["pin"] is None
    # The job is still identified, so the UI can say *when* the last run was.
    assert body["job_id"] == "job-old"
    assert body["filename"] == "job-old.pdf"


def test_last_run_examines_only_the_newest_job(temp_db, temp_db_client):
    """Deliberate: an older bundle carrying stats must NOT be used as a fallback.

    Locks the latency decision — the endpoint parses exactly one bundle_json.
    """
    _insert_job(temp_db, "job-old", "2026-08-20T09:00:00",
                _bundle(_report(x_synthesis_stats=_STATS)))
    _insert_job(temp_db, "job-new", "2026-08-23T09:00:00", _bundle(_report()))
    body = temp_db_client.get("/api/relationship-policy/last-run").json()
    assert body["job_id"] == "job-new"
    assert body["available"] is False


def test_last_run_ignores_jobs_without_a_bundle(temp_db, temp_db_client):
    _insert_job(temp_db, "job-done", "2026-08-20T09:00:00",
                _bundle(_report(x_synthesis_stats=_STATS)))
    _insert_job(temp_db, "job-pending", "2026-08-23T09:00:00", None)
    body = temp_db_client.get("/api/relationship-policy/last-run").json()
    assert body["job_id"] == "job-done"
    assert body["available"] is True


def test_last_run_survives_a_corrupt_bundle(temp_db, temp_db_client):
    _insert_job(temp_db, "job-bad", "2026-08-23T09:00:00", "{not json")
    r = temp_db_client.get("/api/relationship-policy/last-run")
    assert r.status_code == 200
    body = r.json()
    assert body["available"] is False
    assert body["job_id"] == "job-bad"
