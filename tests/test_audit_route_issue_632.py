"""GET /api/audit with a cursor or a filter that holds a NUL byte or a lone UTF-16 surrogate (#632).

PostgreSQL cannot store either, so the value must be refused before it reaches SQL: a 400, not a 500.
"""
from __future__ import annotations

import base64
import json

from .test_audit import _seed_records


def _cursor(value) -> str:
    """A cursor as _encode_cursor writes one, for an arbitrary decoded value."""
    raw = json.dumps(value, separators=(",", ":")).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def test_a_cursor_whose_time_holds_a_nul_is_a_400(auth_client, make_user, sign_in, temp_db):
    headers = sign_in(make_user("admin"))
    _seed_records(temp_db)
    response = auth_client.get("/api/audit", params={"cursor": _cursor(["2026-01-01\x00", 1])}, headers=headers)
    assert response.status_code == 400
    assert response.json()["detail"] == "malformed cursor"


def test_a_cursor_whose_time_holds_a_lone_surrogate_is_a_400(auth_client, make_user, sign_in, temp_db):
    headers = sign_in(make_user("admin"))
    _seed_records(temp_db)
    response = auth_client.get("/api/audit", params={"cursor": _cursor(["2026-01-01\ud800", 1])}, headers=headers)
    assert response.status_code == 400
    assert response.json()["detail"] == "malformed cursor"


def test_a_cursor_whose_time_is_not_an_iso_time_is_a_400(auth_client, make_user, sign_in, temp_db):
    headers = sign_in(make_user("admin"))
    _seed_records(temp_db)
    response = auth_client.get("/api/audit", params={"cursor": _cursor(["not a time", 1])}, headers=headers)
    assert response.status_code == 400


def test_a_user_or_route_filter_holding_a_nul_is_a_400(auth_client, make_user, sign_in, temp_db):
    headers = sign_in(make_user("admin"))
    _seed_records(temp_db)
    for params in ({"user": "admin\x00"}, {"route": "/api/\x00"}):
        response = auth_client.get("/api/audit", params=params, headers=headers)
        assert response.status_code == 400, params
        assert response.json()["detail"] == "user/route holds a character that cannot be stored"


def test_a_real_next_page_cursor_still_pages_after_the_fix(auth_client, make_user, sign_in, temp_db):
    headers = sign_in(make_user("admin"))
    _seed_records(temp_db)
    first = auth_client.get("/api/audit", params={"limit": 3}, headers=headers)
    assert first.status_code == 200
    cursor = first.headers["X-Next-Cursor"]
    # The cursor's time is the stored text of the last record of the page, unchanged by the check.
    assert json.loads(base64.urlsafe_b64decode(cursor + "=" * (-len(cursor) % 4)))[0] == first.json()[-1]["at"]
    second = auth_client.get("/api/audit", params={"limit": 3, "cursor": cursor}, headers=headers)
    assert second.status_code == 200
    assert [item["id"] for item in second.json()] == [item["id"] for item in
                                                      auth_client.get("/api/audit", params={"limit": 7},
                                                                      headers=headers).json()[3:6]]
    assert second.json()[0]["at"] <= first.json()[-1]["at"]
