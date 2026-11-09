"""GET /api/jobs: a forged cursor holding content PostgreSQL cannot store is a 400, never a 500 (#618)."""

from __future__ import annotations

import base64
import json

import pytest


def _forged(*fields: str) -> str:
    """A cursor as _encode_cursor would write it, but with arbitrary field values."""
    return base64.urlsafe_b64encode(json.dumps(list(fields)).encode("utf-8")).rstrip(b"=").decode("ascii")


@pytest.fixture()
def jobs(temp_db):
    for job_id, created_at in (("a", "2026-01-01T00:00:00+00:00"), ("b", "2026-01-02T00:00:00+00:00")):
        with temp_db.get_conn() as conn:
            conn.execute(
                "INSERT INTO jobs (id, original_filename, status, created_at, updated_at) VALUES (?,?,?,?,?)",
                (job_id, f"{job_id}.pdf", "for_review", created_at, created_at),
            )
            conn.commit()


@pytest.mark.parametrize("cursor", [
    _forged("2024-01-01T00:00:00", "a\u0000b"),        # NUL in the id
    _forged("2024-01-01T00:00:00", "a\ud800b"),        # lone UTF-16 surrogate in the id
    _forged("2024-01-01T00:00:00\u0000", "abc"),       # NUL in created_at
    _forged("2024-01-01T00:00:00\udc00", "abc"),       # lone surrogate in created_at
])
def test_a_forged_cursor_with_unstorable_text_is_a_400(temp_db_client, jobs, cursor):
    resp = temp_db_client.get("/api/jobs", params={"limit": 2, "cursor": cursor})

    assert resp.status_code == 400
    assert resp.json()["detail"] == "malformed cursor"


def test_a_well_formed_cursor_with_plain_text_still_pages(temp_db_client, jobs):
    resp = temp_db_client.get("/api/jobs", params={"limit": 2, "cursor": _forged("2026-01-02T00:00:00+00:00", "c")})

    assert resp.status_code == 200
