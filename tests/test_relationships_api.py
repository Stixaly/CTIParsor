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


# ── start_time / stop_time (STIX 2.1 SRO Sec 5.1.2) ────────────────────────────

def test_create_relationship_stores_start_stop_time(temp_db, temp_db_client):
    job_id = _make_job(temp_db, job_id="job-rel-dates-create")
    resp = temp_db_client.post(
        f"/api/jobs/{job_id}/relationships",
        json={
            "source_value": "APT29", "relationship_type": "uses", "target_value": "WellMess",
            "start_time": "2022-11-04", "stop_time": "2023-03-01",
        },
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["start_time"].startswith("2022-11-04")
    assert body["stop_time"].startswith("2023-03-01")

    listed = temp_db_client.get(f"/api/jobs/{job_id}/relationships").json()
    assert listed[0]["start_time"].startswith("2022-11-04")


def test_create_relationship_accepts_start_time_only(temp_db, temp_db_client):
    """A relationship with only one bound (no stop_time yet) must not be forced
    to supply the other — both are independently optional per STIX 2.1."""
    job_id = _make_job(temp_db, job_id="job-rel-dates-start-only")
    resp = temp_db_client.post(
        f"/api/jobs/{job_id}/relationships",
        json={
            "source_value": "A", "relationship_type": "uses", "target_value": "B",
            "start_time": "2022-11-04",
        },
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["start_time"].startswith("2022-11-04")
    assert body["stop_time"] is None


def test_create_relationship_rejects_stop_before_start(temp_db, temp_db_client):
    job_id = _make_job(temp_db, job_id="job-rel-dates-bad-order")
    resp = temp_db_client.post(
        f"/api/jobs/{job_id}/relationships",
        json={
            "source_value": "A", "relationship_type": "uses", "target_value": "B",
            "start_time": "2023-06-01", "stop_time": "2023-01-01",
        },
    )
    assert resp.status_code == 400


def test_create_relationship_rejects_unparseable_date(temp_db, temp_db_client):
    job_id = _make_job(temp_db, job_id="job-rel-dates-garbage")
    resp = temp_db_client.post(
        f"/api/jobs/{job_id}/relationships",
        json={
            "source_value": "A", "relationship_type": "uses", "target_value": "B",
            "start_time": "sometime last spring",
        },
    )
    assert resp.status_code == 400


def test_patch_sets_and_clears_dates(temp_db, temp_db_client):
    job_id = _make_job(temp_db, job_id="job-rel-dates-patch")
    created = temp_db_client.post(
        f"/api/jobs/{job_id}/relationships",
        json={"source_value": "A", "relationship_type": "uses", "target_value": "B"},
    ).json()
    rid = created["id"]
    assert created["start_time"] is None

    patched = temp_db_client.patch(
        f"/api/jobs/{job_id}/relationships/{rid}",
        json={"start_time": "2022-01-01", "stop_time": "2022-06-01"},
    )
    assert patched.status_code == 200, patched.text
    assert patched.json()["start_time"].startswith("2022-01-01")
    assert patched.json()["stop_time"].startswith("2022-06-01")

    # Patching only one bound must validate against the OTHER bound already stored.
    bad_order = temp_db_client.patch(
        f"/api/jobs/{job_id}/relationships/{rid}",
        json={"start_time": "2022-12-01"},   # now later than the stored stop_time
    )
    assert bad_order.status_code == 400

    # An explicit empty string clears the bound.
    cleared = temp_db_client.patch(
        f"/api/jobs/{job_id}/relationships/{rid}",
        json={"start_time": "", "stop_time": ""},
    )
    assert cleared.status_code == 200, cleared.text
    assert cleared.json()["start_time"] is None
    assert cleared.json()["stop_time"] is None
