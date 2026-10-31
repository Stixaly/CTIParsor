"""scripts/browser_e2e_db.py: the database of the browser journey (ADR-0094 item 4)."""
from __future__ import annotations

import json
import os

import psycopg
import pytest

from scripts import browser_e2e_db as e2e


def test_the_seeded_bundle_is_one_stage_5_refuses():
    from pipeline.stage5_validation import INVALID, validate_bundle

    result = validate_bundle(e2e.refused_bundle(), quiet=True)

    assert result.status == INVALID
    assert any("not a lang!" in e for e in result.errors)


def test_the_refused_report_is_stored_as_the_worker_stores_one_and_not_served(temp_db_client, temp_db):
    job_id = e2e.write_refused_report()

    job = temp_db_client.get(f"/api/jobs/{job_id}").json()
    assert (job["original_filename"], job["status"]) == (e2e.REFUSED_FILENAME, "for_review")
    resp = temp_db_client.get(f"/api/jobs/{job_id}/bundle")
    assert resp.status_code == 409
    detail = resp.json()["detail"]
    assert detail["validation"] == "invalid" and any("not a lang!" in e for e in detail["errors"])
    # A completed review is refused the same way: the journey's 409 is the product's.
    assert temp_db_client.patch(f"/api/jobs/{job_id}", json={"status": "completed"}).status_code == 409


def _row(name: str, *stages: tuple[str, str], status: str = "for_review") -> dict:
    report = [{"stage": s, "status": st, "reason": ""} for s, st in stages]
    return {"original_filename": name, "status": status,
            "run_config_json": json.dumps({"stage_report": report}) if report else None}


def test_a_disabled_stage_that_ran_is_a_problem():
    said: list[str] = []
    rows = [_row("a.txt", ("1", "ran"), ("2d", "skipped"), ("3", "ran")), _row("b.txt", status="failed")]

    problems = e2e.stage_problems(rows, {"2d", "3"}, said.append)

    assert problems == ["a.txt: stage 3 ran, but PIPELINE_DISABLED_STAGES turns it off"]
    assert "b.txt (failed):" in said and "  no stage report: the pipeline did not run to its end" in said


def test_a_journey_where_no_report_ran_is_a_problem():
    assert e2e.stage_problems([_row("b.txt", status="failed")], set(), lambda _: None) == [
        "no report ran through the pipeline"]
    assert e2e.stage_problems([_row("a.txt", ("1", "ran"), ("3", "skipped"))], {"3"}, lambda _: None) == []


def test_it_touches_only_the_databases_it_made(capsys):
    with pytest.raises(e2e.Unusable):
        e2e.database("postgresql://u:p@127.0.0.1:5432/ctiparsor")
    assert e2e.main(["drop", "postgresql://u:p@127.0.0.1:5432/ctiparsor"]) == 2
    assert e2e.main(["seed"]) == 2
    assert "needs the URL" in capsys.readouterr().err


def test_create_then_drop():
    if not (os.environ.get("CTIPARSOR_TEST_DATABASE_URL") or "").strip():
        pytest.fail("CTIPARSOR_TEST_DATABASE_URL is required")
    url = e2e.create()
    assert e2e.database(url).startswith(e2e.PREFIX)
    with psycopg.connect(url, connect_timeout=10) as conn:
        row = conn.execute("SELECT current_database()").fetchone()
        assert row is not None and row[0] == e2e.database(url)
    e2e.drop(url)
    with pytest.raises(psycopg.OperationalError):
        psycopg.connect(url, connect_timeout=10)


def test_without_a_server_it_cannot_run(monkeypatch, capsys):
    monkeypatch.delenv("CTIPARSOR_TEST_DATABASE_URL", raising=False)
    assert e2e.main(["create"]) == 2
    assert "CTIPARSOR_TEST_DATABASE_URL is not set" in capsys.readouterr().err
