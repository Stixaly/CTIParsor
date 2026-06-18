"""Relationships route tests (P1-c).

Exercises the HTTP contract for evidence_label on create / read / patch, against
an isolated temp database (see `temp_db_client` in conftest). The pre-existing
test_api_routes.py covers the read-only / contract endpoints; this file covers
the relationship CRUD that now carries graded evidence.
"""


def _make_job(temp_db, job_id="job-rel"):
    with temp_db.get_conn() as conn:
        conn.execute(
            "INSERT INTO jobs (id, original_filename, status, report_text, created_at, updated_at) "
            "VALUES (?,?,?,?,?,?)",
            (job_id, "r.txt", "reviewing", "APT29 used WellMess.", temp_db.now_iso(), temp_db.now_iso()),
        )
        conn.commit()
    return job_id


def test_create_relationship_stores_and_returns_evidence_label(temp_db, temp_db_client):
    job_id = _make_job(temp_db)
    resp = temp_db_client.post(
        f"/api/jobs/{job_id}/relationships",
        json={
            "source_value": "APT29",
            "relationship_type": "uses",
            "target_value": "WellMess",
            "confidence": 0.9,
            "evidence_text": "APT29 used WellMess.",
            "evidence_label": "observed",
        },
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["evidence_label"] == "observed"

    # And it round-trips through GET
    listed = temp_db_client.get(f"/api/jobs/{job_id}/relationships").json()
    assert listed and listed[0]["evidence_label"] == "observed"


def test_create_relationship_defaults_label_to_reported(temp_db, temp_db_client):
    job_id = _make_job(temp_db, job_id="job-rel-default")
    resp = temp_db_client.post(
        f"/api/jobs/{job_id}/relationships",
        json={"source_value": "A", "relationship_type": "uses", "target_value": "B"},
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["evidence_label"] == "reported"


def test_create_relationship_coerces_unknown_label(temp_db, temp_db_client):
    # POST accepts any string but stores a safe value (unknown → reported),
    # so a bad label can never poison the bundle.
    job_id = _make_job(temp_db, job_id="job-rel-bad-create")
    resp = temp_db_client.post(
        f"/api/jobs/{job_id}/relationships",
        json={"source_value": "A", "relationship_type": "uses", "target_value": "B",
              "evidence_label": "super-duper-sure"},
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["evidence_label"] == "reported"


def test_patch_rejects_unknown_evidence_label(temp_db, temp_db_client):
    job_id = _make_job(temp_db, job_id="job-rel-patch")
    created = temp_db_client.post(
        f"/api/jobs/{job_id}/relationships",
        json={"source_value": "A", "relationship_type": "uses", "target_value": "B"},
    ).json()
    rid = created["id"]

    bad = temp_db_client.patch(
        f"/api/jobs/{job_id}/relationships/{rid}",
        json={"evidence_label": "bogus"},
    )
    assert bad.status_code == 400

    good = temp_db_client.patch(
        f"/api/jobs/{job_id}/relationships/{rid}",
        json={"evidence_label": "assessed"},
    )
    assert good.status_code == 200, good.text
    assert good.json()["evidence_label"] == "assessed"
