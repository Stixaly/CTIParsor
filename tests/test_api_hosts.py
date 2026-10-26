"""The API refuses an unknown Host and a cross-site write (audit B 8.2.1).

Reproduced by the audit: `GET /api/jobs` with `Host: attacker.example`
answered 200 (DNS rebinding: a hostile page pointing its own name at
127.0.0.1 then reads and edits everything as same-origin), and a multipart
`POST /api/upload` with `Origin: http://attacker.example` created a job
(CSRF: no preflight on a "simple" request).  Neither must get past the
middleware; curl, scripts and the app's own page must not notice it.
"""
from __future__ import annotations

import io

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from api import main as api_main

_FILE = {"file": ("r.txt", io.BytesIO(b"APT29 used WellMess against 185.220.101.45."), "text/plain")}


@pytest.fixture()
def client(temp_db_client, monkeypatch):
    api_main.limiter.reset()
    monkeypatch.setattr("api.worker.run_pipeline_async", lambda *a, **k: "started")
    return temp_db_client


def test_a_foreign_host_header_is_refused(client):
    assert client.get("/api/health", headers={"Host": "attacker.example"}).status_code == 400
    assert client.get("/api/jobs", headers={"Host": "attacker.example"}).status_code == 400


def test_the_configured_hosts_are_served(client):
    assert client.get("/api/health").status_code == 200                                   # testserver
    assert client.get("/api/health", headers={"Host": "localhost:8000"}).status_code == 200
    assert client.get("/api/health", headers={"Host": "127.0.0.1"}).status_code == 200


def test_a_cross_origin_upload_is_refused(client):
    r = client.post("/api/upload", files=_FILE, headers={"Origin": "http://attacker.example"})
    assert r.status_code == 403
    assert "origin" in r.json()["detail"]


def test_an_origin_that_does_not_parse_is_refused(client):
    r = client.post("/api/upload", files=_FILE, headers={"Origin": "http://["})
    assert r.status_code == 403
    assert "origin" in r.json()["detail"]


def test_a_request_the_browser_marks_cross_site_is_refused(client):
    r = client.post("/api/upload", files=_FILE, headers={"Sec-Fetch-Site": "cross-site"})
    assert r.status_code == 403


def test_the_apps_own_page_and_scripts_are_not_affected(client):
    # The app's page: same-origin Origin, or the header Sec-Fetch-Site: same-origin.
    assert client.post("/api/upload", files=_FILE, headers={"Origin": "http://localhost:8000"}).status_code == 200
    assert client.post("/api/upload", files=_FILE,
                       headers={"Origin": "http://localhost:5173", "Sec-Fetch-Site": "same-origin"}).status_code == 200
    # curl and scripts send neither header.
    assert client.post("/api/upload", files=_FILE).status_code == 200


def test_reads_are_not_origin_checked(client):
    """GET never mutates; the same-origin policy already keeps the answer from
    a foreign page.  Only the Host check applies."""
    assert client.get("/api/health", headers={"Origin": "http://attacker.example"}).status_code == 200


@pytest.mark.parametrize("raw,expected", [
    ("localhost, 127.0.0.1", ["localhost", "127.0.0.1"]),
    ("  ", ["localhost", "127.0.0.1", "[::1]"]),
    ("CTI.Example.ORG", ["cti.example.org"]),
])
def test_allowed_hosts_is_read_from_the_environment(monkeypatch, raw, expected):
    monkeypatch.setenv("API_ALLOWED_HOSTS", raw)
    assert api_main.allowed_hosts() == expected


@pytest.fixture()
def spa(tmp_path):
    (tmp_path / "index.html").write_text("<html><body>app</body></html>", encoding="utf-8")
    app = FastAPI()
    app.mount("/", api_main._SPAStaticFiles(directory=str(tmp_path), html=True), name="static")
    return TestClient(app)


def test_an_unknown_api_path_is_a_json_404_not_the_spa_entry_point(spa):
    for path in ["/api", "/api/nope"]:
        r = spa.get(path)
        assert r.status_code == 404
        assert r.json() == {"detail": "Not Found"}


def test_a_client_route_falls_back_to_index_html(spa):
    r = spa.get("/jobs/123")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/html")
    assert "app" in r.text
