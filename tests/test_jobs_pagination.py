"""GET /api/jobs: optional keyset pagination (ADR-0097 item 20).

Without `limit` the response is the whole list, as before.  With `limit`, the
pages follow created_at DESC, id DESC; X-Next-Cursor carries the cursor of the
next page and is absent on the last one.
"""

from __future__ import annotations

import base64
import json

import pytest


def _add(db, job_id: str, created_at: str) -> None:
    with db.get_conn() as conn:
        conn.execute(
            "INSERT INTO jobs (id, original_filename, status, created_at, updated_at) VALUES (?,?,?,?,?)",
            (job_id, f"{job_id}.pdf", "for_review", created_at, created_at),
        )
        conn.commit()


def _walk(client, limit: int) -> tuple[list[str], int]:
    """Every id of every page, and the number of pages."""
    ids: list[str] = []
    pages = 0
    params: dict = {"limit": limit}
    while True:
        resp = client.get("/api/jobs", params=params)
        assert resp.status_code == 200
        pages += 1
        ids += [job["id"] for job in resp.json()]
        cursor = resp.headers.get("X-Next-Cursor")
        if cursor is None:
            return ids, pages
        params = {"limit": limit, "cursor": cursor}


@pytest.fixture()
def jobs(temp_db):
    """Seven jobs; three share a created_at, so the id is what orders them."""
    stamps = {
        "a": "2026-01-01T00:00:00+00:00",
        "b": "2026-01-02T00:00:00+00:00",
        "c": "2026-01-02T00:00:00+00:00",
        "d": "2026-01-02T00:00:00+00:00",
        "e": "2026-01-03T00:00:00+00:00",
        "f": "2026-01-04T00:00:00+00:00",
        "g": "2026-01-04T00:00:00+00:00",
    }
    for job_id, created_at in stamps.items():
        _add(temp_db, job_id, created_at)
    return stamps


def test_without_params_the_whole_list_is_returned_as_before(temp_db_client, jobs):
    resp = temp_db_client.get("/api/jobs")

    assert resp.status_code == 200
    assert "X-Next-Cursor" not in resp.headers
    body = resp.json()
    assert len(body) == len(jobs)
    assert set(body[0]) == {"id", "original_filename", "status", "tlp_level", "pap_level", "pipeline_mode",
                            "created_at", "updated_at"}
    assert [job["created_at"] for job in body] == sorted((job["created_at"] for job in body), reverse=True)


def test_pages_keep_the_order_across_ties(temp_db_client, jobs):
    expected = sorted(jobs, key=lambda j: (jobs[j], j), reverse=True)

    for limit in (1, 2, 3, 6):
        ids, _ = _walk(temp_db_client, limit)
        assert ids == expected, f"limit {limit}"


def test_a_page_has_at_most_limit_jobs_and_the_last_page_has_no_cursor(temp_db_client, jobs):
    first = temp_db_client.get("/api/jobs", params={"limit": 5})
    assert len(first.json()) == 5 and "X-Next-Cursor" in first.headers

    second = temp_db_client.get("/api/jobs", params={"limit": 5, "cursor": first.headers["X-Next-Cursor"]})
    assert len(second.json()) == 2 and "X-Next-Cursor" not in second.headers


def test_a_limit_at_the_size_of_the_list_gives_one_page_without_a_cursor(temp_db_client, jobs):
    resp = temp_db_client.get("/api/jobs", params={"limit": len(jobs)})

    assert len(resp.json()) == len(jobs)
    assert "X-Next-Cursor" not in resp.headers


def test_a_cursor_names_the_job_it_comes_after_not_a_position(temp_db_client, temp_db, jobs):
    first = temp_db_client.get("/api/jobs", params={"limit": 2})
    cursor = first.headers["X-Next-Cursor"]
    _add(temp_db, "zz", "2026-02-01T00:00:00+00:00")       # a newer job arrives between the two requests

    second = temp_db_client.get("/api/jobs", params={"limit": 2, "cursor": cursor})

    seen = [job["id"] for job in first.json()] + [job["id"] for job in second.json()]
    assert "zz" not in seen
    assert len(seen) == len(set(seen))


@pytest.mark.parametrize("cursor", [
    "not-a-cursor!",
    base64.urlsafe_b64encode(b"not json").decode(),
    base64.urlsafe_b64encode(json.dumps(["2026-01-01"]).encode()).decode(),
    base64.urlsafe_b64encode(json.dumps([1, 2]).encode()).decode(),
    base64.urlsafe_b64encode(json.dumps({"a": 1}).encode()).decode(),
    "",
])
def test_a_malformed_cursor_is_a_400(temp_db_client, jobs, cursor):
    resp = temp_db_client.get("/api/jobs", params={"limit": 2, "cursor": cursor})

    assert resp.status_code == 400
    assert resp.json()["detail"] == "malformed cursor"


def test_a_cursor_without_a_limit_is_a_400(temp_db_client, jobs):
    first = temp_db_client.get("/api/jobs", params={"limit": 2})

    resp = temp_db_client.get("/api/jobs", params={"cursor": first.headers["X-Next-Cursor"]})

    assert resp.status_code == 400


@pytest.mark.parametrize("limit", [0, 501, -1])
def test_a_limit_outside_1_to_500_is_refused(temp_db_client, jobs, limit):
    assert temp_db_client.get("/api/jobs", params={"limit": limit}).status_code == 422


def test_the_limit_of_500_is_accepted(temp_db_client, jobs):
    assert temp_db_client.get("/api/jobs", params={"limit": 500}).status_code == 200
