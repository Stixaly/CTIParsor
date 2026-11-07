"""Issue #526: a NUL byte or a lone surrogate in a rule id is a 422, not a 500.

PostgreSQL refuses such a text at the query (a psycopg.DataError), as #495 and
#525 found for the other request bodies. Pydantic refuses it first, with the
same status it gives any other invalid input.
"""
import json

import pytest

_BAD_IDS = ["sig:a\x00", "\x00", "sig:\ud800"]


def _post_json(client, url, body):
    # Sent as text: the test client cannot encode a lone surrogate itself, and
    # json.dumps escapes it, as a real client's body would carry it.
    return client.post(url, content=json.dumps(body), headers={"content-type": "application/json"})


@pytest.mark.parametrize("bad", _BAD_IDS)
def test_rule_lookup_refuses_a_bad_rule_id_with_422_issue_526(temp_db_client, bad):
    resp = _post_json(temp_db_client, "/api/rules/lookup", {"rule_ids": ["sig:ok", bad]})
    assert resp.status_code == 422, resp.text


@pytest.mark.parametrize("bad", _BAD_IDS)
def test_detections_export_refuses_a_bad_rule_id_with_422_issue_526(temp_db, temp_db_client, bad):
    conn = temp_db.get_conn()
    conn.execute(
        "INSERT INTO jobs (id, original_filename, status, created_at, updated_at) "
        "VALUES (?,?,?,?,?)", ("j526", "r.txt", "reviewing", temp_db.now_iso(), temp_db.now_iso()),
    )
    conn.commit()

    resp = _post_json(temp_db_client, "/api/jobs/j526/detections/export", {"rule_ids": ["sig:ok", bad]})
    assert resp.status_code == 422, resp.text
