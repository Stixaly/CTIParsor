"""A NUL in a job id in the URL answers 404, as an unknown id does (issue #386).

PostgreSQL refuses a NUL in a text parameter (psycopg DataError), so before the
fix `GET /api/jobs/j1%00x/entities` was a 500 instead of "Job not found".
"""
from __future__ import annotations

import pytest


def _job(temp_db, job_id: str) -> None:
    temp_db.get_conn().execute(
        "INSERT INTO jobs (id, original_filename, status, created_at, updated_at) VALUES (?,?,?,?,?)",
        (job_id, "a.txt", "uploaded", "2026-01-01T00:00:00+00:00", "2026-01-01T00:00:00+00:00"),
    )


def test_a_nul_in_the_job_id_is_a_404_not_a_500_issue_386(temp_db, temp_db_client):
    _job(temp_db, "j1")
    resp = temp_db_client.get("/api/jobs/j1%00x/entities")
    assert resp.status_code == 404
    assert resp.json()["detail"] == "Job not found"


@pytest.mark.parametrize("path", [
    "/api/jobs/j1%00x/relationships",
    "/api/jobs/%00/entities",
])
def test_a_nul_in_a_job_scoped_path_is_refused_like_an_unknown_job_issue_386(temp_db_client, path):
    resp = temp_db_client.get(path)
    assert resp.status_code == 404


def test_a_nul_in_the_progress_path_is_refused_issue_386(temp_db, temp_db_client):
    _job(temp_db, "j1")
    resp = temp_db_client.get("/api/jobs/j1%00x/progress")
    assert resp.status_code == 404


def test_control_an_existing_job_still_answers_issue_386(temp_db, temp_db_client):
    _job(temp_db, "j1")
    assert temp_db_client.get("/api/jobs/j1/entities").status_code == 200
    assert temp_db_client.get("/api/jobs/j2/entities").status_code == 404
    assert temp_db_client.get("/api/jobs/%ED%A0%80/entities").status_code == 404


def test_a_nul_in_any_job_route_is_a_404_issue_386(temp_db_client):
    # Routes that do not go through require_job (job read, bundle, source)
    # are covered by the middleware in api/main.py.
    for path in ("/api/jobs/j1%00x", "/api/jobs/j1%00x/bundle", "/api/jobs/j1%00x/source"):
        assert temp_db_client.get(path).status_code == 404, path
