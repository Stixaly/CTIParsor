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


# ── ADR-0063 — the analyst's precision is kept ───────────────────────────────

def test_an_analyst_month_stays_a_month(temp_db, temp_db_client):
    job_id = _make_job(temp_db, job_id="job-rel-month")
    body = temp_db_client.post(
        f"/api/jobs/{job_id}/relationships",
        json={"source_value": "A", "relationship_type": "uses", "target_value": "B",
              "start_time": "March 2023", "stop_time": "2023"},
    ).json()
    assert (body["start_time"], body["stop_time"]) == ("2023-03", "2023")
    listed = temp_db_client.get(f"/api/jobs/{job_id}/relationships").json()[0]
    assert [(t["role"], t["value"], t["precision"], t["origin"], t["status"])
            for t in listed["times"]] == [("start", "2023-03", "month", "analyst", "verified"),
                                          ("end", "2023", "year", "analyst", "verified")]


def test_an_ambiguous_analyst_date_is_refused(temp_db, temp_db_client):
    job_id = _make_job(temp_db, job_id="job-rel-ambiguous")
    resp = temp_db_client.post(
        f"/api/jobs/{job_id}/relationships",
        json={"source_value": "A", "relationship_type": "uses", "target_value": "B",
              "start_time": "03/04/2023"},
    )
    assert resp.status_code == 400
    assert "numeric_order" in resp.text


def test_order_is_judged_on_windows_not_strings(temp_db, temp_db_client):
    """A start in June and an end in March contradict; a start and an end
    both in 2023 do not; two equal instants do (STIX stop > start)."""
    job_id = _make_job(temp_db, job_id="job-rel-windows")
    url = f"/api/jobs/{job_id}/relationships"
    base = {"source_value": "A", "relationship_type": "uses", "target_value": "B"}
    assert temp_db_client.post(url, json={**base, "start_time": "2023-06",
                                          "stop_time": "2023-03"}).status_code == 400
    assert temp_db_client.post(url, json={**base, "start_time": "2023",
                                          "stop_time": "2023"}).status_code == 200
    same = "2023-06-01T10:00:00Z"
    assert temp_db_client.post(url, json={**base, "start_time": same,
                                          "stop_time": same}).status_code == 400


def test_an_analyst_bound_replaces_the_models_and_keeps_its_windows(temp_db, temp_db_client):
    """Setting a start replaces the start assertions; the model's `within`
    dates stay."""
    from pipeline.temporal import TemporalAssertion, times_to_json
    job_id = _make_job(temp_db, job_id="job-rel-replace")
    rid = temp_db_client.post(
        f"/api/jobs/{job_id}/relationships",
        json={"source_value": "A", "relationship_type": "uses", "target_value": "B"},
    ).json()["id"]
    llm_times = [TemporalAssertion(role="start", time_text="since 2021", value="2021",
                                   precision="year", status="verified"),
                 TemporalAssertion(role="within", time_text="in 2022", value="2022",
                                   precision="year", status="verified")]
    with temp_db.get_conn() as conn:
        conn.execute("UPDATE relationships SET times_json=? WHERE id=?",
                     (times_to_json(llm_times), rid))
        conn.commit()
    patched = temp_db_client.patch(f"/api/jobs/{job_id}/relationships/{rid}",
                                   json={"start_time": "2021-05"}).json()
    assert [(t["role"], t["value"], t["origin"]) for t in patched["times"]] == [
        ("within", "2022", "llm"), ("start", "2021-05", "analyst")]


def test_patching_a_legacy_row_folds_its_columns_into_assertions(temp_db, temp_db_client):
    job_id = _make_job(temp_db, job_id="job-rel-legacy")
    rid = temp_db_client.post(
        f"/api/jobs/{job_id}/relationships",
        json={"source_value": "A", "relationship_type": "uses", "target_value": "B"},
    ).json()["id"]
    with temp_db.get_conn() as conn:
        conn.execute("UPDATE relationships SET times_json=NULL, "
                     "stop_time='2023-01-01T00:00:00+00:00' WHERE id=?", (rid,))
        conn.commit()
    listed = temp_db_client.get(f"/api/jobs/{job_id}/relationships").json()[0]
    assert [(t["role"], t["origin"], t["status"]) for t in listed["times"]] == [
        ("end", "legacy", "unresolved")]
    patched = temp_db_client.patch(f"/api/jobs/{job_id}/relationships/{rid}",
                                   json={"start_time": "2022"}).json()
    assert [(t["role"], t["origin"]) for t in patched["times"]] == [
        ("end", "legacy"), ("start", "analyst")]
    row = temp_db.get_conn().execute(
        "SELECT start_time, stop_time FROM relationships WHERE id=?", (rid,)).fetchone()
    assert (row["start_time"], row["stop_time"]) == (None, None)


# ── POST /relationships/bulk — a review group in one call (ADR-0065) ─────────

def _pipeline_rel(temp_db, job_id, rel_id, src, tgt):
    """A row as the worker stores it: accepted, by the pipeline's default."""
    with temp_db.get_conn() as conn:
        conn.execute(
            "INSERT INTO relationships (id, job_id, source_value, relationship_type, "
            "target_value, confidence, accepted, decision_origin) VALUES (?,?,?,?,?,?,?,?)",
            (rel_id, job_id, src, "uses", tgt, 0.8, 1, "default"),
        )
        conn.commit()


def _state(temp_db, rel_id):
    with temp_db.get_conn() as conn:
        row = conn.execute(
            "SELECT accepted, decision_origin FROM relationships WHERE id=?", (rel_id,)
        ).fetchone()
    return row["accepted"], row["decision_origin"]


def test_bulk_decides_every_listed_row_as_human_bulk_and_journals_it(temp_db, temp_db_client):
    job_id = _make_job(temp_db, job_id="job-bulk")
    for i, src in enumerate(["APT29", "Cozy Bear", "NOBELIUM"]):
        _pipeline_rel(temp_db, job_id, f"b{i}", src, "WellMess")
    resp = temp_db_client.post(f"/api/jobs/{job_id}/relationships/bulk",
                               json={"ids": ["b0", "b1"], "action": "reject"})
    assert resp.status_code == 200, resp.text
    assert resp.json() == {"updated": 2, "action": "reject"}
    assert _state(temp_db, "b0") == (0, "human_bulk")
    assert _state(temp_db, "b1") == (0, "human_bulk")
    assert _state(temp_db, "b2") == (1, "default")          # not listed, untouched
    with temp_db.get_conn() as conn:
        journal = conn.execute(
            "SELECT target_id, previous, accepted, origin FROM review_decisions "
            "WHERE job_id=? AND target_kind='relationship' ORDER BY target_id", (job_id,)
        ).fetchall()
    assert [(r["target_id"], r["previous"], r["accepted"], r["origin"]) for r in journal] == [
        ("b0", 1, 0, "human_bulk"), ("b1", 1, 0, "human_bulk")]


def test_bulk_accept_turns_a_default_row_into_a_decision(temp_db, temp_db_client):
    job_id = _make_job(temp_db, job_id="job-bulk-accept")
    _pipeline_rel(temp_db, job_id, "a0", "APT29", "WellMess")
    resp = temp_db_client.post(f"/api/jobs/{job_id}/relationships/bulk",
                               json={"ids": ["a0"], "action": "accept"})
    assert resp.status_code == 200, resp.text
    assert _state(temp_db, "a0") == (1, "human_bulk")


def test_bulk_never_touches_another_jobs_rows(temp_db, temp_db_client):
    mine = _make_job(temp_db, job_id="job-bulk-mine")
    other = _make_job(temp_db, job_id="job-bulk-other")
    _pipeline_rel(temp_db, other, "o0", "APT29", "WellMess")
    resp = temp_db_client.post(f"/api/jobs/{mine}/relationships/bulk",
                               json={"ids": ["o0"], "action": "reject"})
    assert resp.status_code == 200, resp.text
    assert resp.json()["updated"] == 0
    assert _state(temp_db, "o0") == (1, "default")


def test_bulk_refuses_a_bad_action_or_no_ids(temp_db, temp_db_client):
    job_id = _make_job(temp_db, job_id="job-bulk-bad")
    url = f"/api/jobs/{job_id}/relationships/bulk"
    assert temp_db_client.post(url, json={"ids": ["x"], "action": "delete"}).status_code == 400
    assert temp_db_client.post(url, json={"ids": [], "action": "accept"}).status_code == 400
    assert temp_db_client.post("/api/jobs/no-such-job/relationships/bulk",
                               json={"ids": ["x"], "action": "accept"}).status_code == 404
