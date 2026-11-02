"""Five API defects from the issue tracker: #259, #260, #263, #264, #266."""
from __future__ import annotations

import json

import pytest

from api.worker import _upload_path_for


@pytest.fixture()
def uploads(tmp_path, monkeypatch):
    folder = tmp_path / "uploads"
    folder.mkdir(exist_ok=True)
    monkeypatch.setenv("CTIPARSOR_UPLOADS_DIR", str(folder))
    return folder


@pytest.fixture()
def job(temp_db) -> str:
    ts = temp_db.now_iso()
    with temp_db.get_conn() as conn:
        conn.execute("INSERT INTO jobs (id, original_filename, status, created_at, updated_at) "
                     "VALUES ('j1', 'r.pdf', 'for_review', ?, ?)", (ts, ts))
        conn.commit()
    return "j1"


_ENTITY = {"value": "WellMess", "entity_type": "malware"}
_REL = {"source_value": "APT29", "relationship_type": "uses", "target_value": "WellMess"}


def _post_json(client, url: str, body: dict):
    # httpx's json= refuses NaN and Infinity while encoding; the server's parser takes
    # them, and that is the input under test, so the body is sent as text.
    return client.post(url, content=json.dumps(body), headers={"Content-Type": "application/json"})


# ── #259: a URL capture is ingested from its .txt, not its .pdf ─────────────

def test_a_url_capture_is_read_from_its_text(uploads):
    (uploads / "j1.pdf").write_bytes(b"%PDF-1.4")
    (uploads / "j1.txt").write_text("APT29 used WellMess.", encoding="utf-8")
    assert _upload_path_for("j1") == str(uploads / "j1.txt")


def test_a_simple_upload_is_read_from_its_only_file(uploads):
    (uploads / "j2.pdf").write_bytes(b"%PDF-1.4")
    (uploads / "j3.md").write_text("# Report", encoding="utf-8")
    assert _upload_path_for("j2") == str(uploads / "j2.pdf")
    assert _upload_path_for("j3") == str(uploads / "j3.md")
    assert _upload_path_for("j4") is None


def test_the_source_viewer_still_gets_the_capture_pdf(temp_db_client, job, uploads):
    (uploads / "j1.pdf").write_bytes(b"%PDF-1.4 archive")
    (uploads / "j1.txt").write_text("APT29 used WellMess.", encoding="utf-8")
    r = temp_db_client.get("/api/jobs/j1/source")
    assert r.status_code == 200
    assert r.content == b"%PDF-1.4 archive"


# ── #260: Origin: null is refused only without Sec-Fetch-Site ───────────────

def test_a_null_origin_without_fetch_metadata_is_refused(temp_db_client, job):
    r = temp_db_client.post("/api/jobs/j1/entities", json=_ENTITY, headers={"Origin": "null"})
    assert r.status_code == 403
    assert "origin" in r.json()["detail"]


@pytest.mark.parametrize("site", ["same-origin", "none"])
def test_a_null_origin_vouched_by_fetch_metadata_is_served(temp_db_client, job, site):
    # nginx's Referrer-Policy: no-referrer makes a same-origin POST send Origin: null.
    r = temp_db_client.post("/api/jobs/j1/entities", json=_ENTITY,
                            headers={"Origin": "null", "Sec-Fetch-Site": site})
    assert r.status_code == 200


def test_a_request_with_no_origin_at_all_is_served(temp_db_client, job):
    # curl and scripts send neither header.
    assert temp_db_client.post("/api/jobs/j1/entities", json=_ENTITY).status_code == 200


# ── #263: listing the children of an unknown job is a 404 ───────────────────

@pytest.mark.parametrize("collection", ["entities", "relationships"])
def test_listing_an_unknown_job_is_not_found(temp_db_client, collection):
    r = temp_db_client.get(f"/api/jobs/nope/{collection}")
    assert r.status_code == 404
    assert r.json() == {"detail": "Job not found"}


@pytest.mark.parametrize("collection", ["entities", "relationships"])
def test_listing_a_job_with_no_rows_is_an_empty_list(temp_db_client, job, collection):
    assert temp_db_client.get(f"/api/jobs/j1/{collection}").json() == []


# ── #264: confidence is a probability, [0, 1] ───────────────────────────────

@pytest.mark.parametrize("confidence", [-0.1, 1.5, float("nan"), float("inf"), float("-inf")])
def test_an_entity_confidence_outside_zero_to_one_is_refused(temp_db_client, job, confidence):
    r = _post_json(temp_db_client, "/api/jobs/j1/entities", {**_ENTITY, "confidence": confidence})
    assert r.status_code == 422


@pytest.mark.parametrize("confidence", [-0.1, 1.5, float("nan"), float("inf"), float("-inf")])
def test_a_relationship_confidence_outside_zero_to_one_is_refused(temp_db_client, job, confidence):
    r = _post_json(temp_db_client, "/api/jobs/j1/relationships", {**_REL, "confidence": confidence})
    assert r.status_code == 422


@pytest.mark.parametrize("confidence", [0, 0.5, 1])
def test_the_bounds_and_the_middle_are_accepted(temp_db_client, job, confidence):
    r = _post_json(temp_db_client, "/api/jobs/j1/entities", {**_ENTITY, "confidence": confidence})
    assert r.status_code == 200
    assert r.json()["confidence"] == confidence
    r = _post_json(temp_db_client, "/api/jobs/j1/relationships", {**_REL, "confidence": confidence})
    assert r.status_code == 200
    assert r.json()["confidence"] == confidence


# ── #266: a relationship is read back within its own job ────────────────────

def test_a_relationship_patched_through_another_job_is_not_found(temp_db_client, temp_db, job):
    ts = temp_db.now_iso()
    with temp_db.get_conn() as conn:
        conn.execute("INSERT INTO jobs (id, original_filename, status, created_at, updated_at) "
                     "VALUES ('j2', 'other.pdf', 'for_review', ?, ?)", (ts, ts))
        conn.commit()
    rid = temp_db_client.post("/api/jobs/j1/relationships", json=_REL).json()["id"]

    r = temp_db_client.patch(f"/api/jobs/j2/relationships/{rid}", json={"evidence_label": "observed"})
    assert r.status_code == 404
    assert temp_db_client.get("/api/jobs/j1/relationships").json()[0]["evidence_label"] == "reported"
