"""Tests for GET /metrics and the alert rules (ADR-0097 item 18).

Locks: the Prometheus text format (0.0.4) parses back with HELP and TYPE for
every family; each metric matches a seeded database; the endpoint answers
when the database is down; only loopback clients get it (403 otherwise); the
backup metrics come from the status file and are absent without it; and every
alert in docs/monitoring/ctiparsor.rules.yml has a summary and a runbook whose
section exists in docs/operations.md.
"""

from __future__ import annotations

import json
import re
from collections import namedtuple
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

import pytest
import yaml

import api.routes.metrics as metrics

ROOT = Path(__file__).resolve().parent.parent
RULES = ROOT / "docs" / "monitoring" / "ctiparsor.rules.yml"
OPERATIONS = ROOT / "docs" / "operations.md"

_SAMPLE = re.compile(r"^([a-zA-Z_:][a-zA-Z0-9_:]*)(?:\{(.*)\})? (\S+)$")
_LABEL = re.compile(r'(\w+)="((?:[^"\\]|\\.)*)"')
_ESCAPE = re.compile(r"\\(.)")
_UNESCAPE = {"n": "\n"}


def parse(text: str):
    """A small parser for the exposition format: (HELP texts, TYPEs, samples)."""
    helps: dict[str, str] = {}
    types: dict[str, str] = {}
    samples: list[tuple[str, dict[str, str], float]] = []
    for line in text.splitlines():
        if line.startswith("# HELP "):
            name, _, help_text = line[len("# HELP ") :].partition(" ")
            helps[name] = help_text
        elif line.startswith("# TYPE "):
            name, kind = line[len("# TYPE ") :].split(" ")
            types[name] = kind
        elif not line or line.startswith("#"):
            continue
        else:
            match = _SAMPLE.match(line)
            assert match, f"not a sample line: {line!r}"
            labels = {
                key: _ESCAPE.sub(lambda m: _UNESCAPE.get(m.group(1), m.group(1)), value)
                for key, value in _LABEL.findall(match.group(2) or "")
            }
            samples.append((match.group(1), labels, float(match.group(3))))
    return helps, types, samples


def _value(samples, name: str, **labels: str) -> float:
    matches = [v for n, lab, v in samples if n == name and lab == labels]
    assert len(matches) == 1, f"{name}{labels}: {matches}"
    return matches[0]


def _insert_job(db, job_id: str, status: str, created_at: str, *, worker_id=None, heartbeat_at=None) -> None:
    conn = db.get_conn()
    conn.execute(
        "INSERT INTO jobs (id, original_filename, status, created_at, updated_at, worker_id, heartbeat_at) "
        "VALUES (?,?,?,?,?,?,?)",
        (job_id, f"{job_id}.txt", status, created_at, created_at, worker_id, heartbeat_at),
    )
    conn.commit()


def _insert_loop(db, worker_id: str, *, heartbeat_at: str | None = None) -> None:
    now = db.now_iso()
    db.get_conn().execute(
        "INSERT INTO worker_heartbeats (worker_id, role, max_concurrent, app_version, started_at, heartbeat_at) "
        "VALUES (?,?,?,?,?,?)",
        (worker_id, "worker", 1, "0.2.0", now, heartbeat_at or now),
    )


@pytest.fixture()
def loopback_client(temp_db, monkeypatch, tmp_path):
    """A client whose requests come from 127.0.0.1, with no backup status file."""
    from fastapi.testclient import TestClient

    import api.main

    monkeypatch.setenv("BACKUP_STATUS_FILE", str(tmp_path / "no-such-status.json"))
    monkeypatch.setenv("CTIPARSOR_STATE_DIR", str(tmp_path / "state"))
    with patch("api.main.init_db"), patch("api.queue_loop.start_embedded"):
        with TestClient(api.main.app, client=("127.0.0.1", 50000)) as client:
            yield client


def test_renderer_escapes_labels_and_help():
    family = metrics.Family("ctiparsor_example", "Help with a \\ and a\nnewline.")
    family.add(3, path='a "quoted"\\ value\n')
    text = metrics.render([family])
    helps, types, samples = parse(text)
    # The HELP text is escaped on the wire: a backslash doubles, a newline becomes \n.
    assert helps["ctiparsor_example"] == "Help with a \\\\ and a\\nnewline."
    assert types["ctiparsor_example"] == "gauge"
    assert samples == [("ctiparsor_example", {"path": 'a "quoted"\\ value\n'}, 3.0)]


def test_values_render_as_integers_floats_and_specials():
    family = metrics.Family("ctiparsor_values", "Values.")
    family.add(12)
    family.add(0.5, kind="fraction")
    family.add(float("inf"), kind="inf")
    text = metrics.render([family])
    assert "ctiparsor_values 12\n" in text
    assert 'ctiparsor_values{kind="fraction"} 0.5' in text
    assert 'ctiparsor_values{kind="inf"} +Inf' in text


@pytest.mark.parametrize(
    ("host", "expected"),
    [
        ("127.0.0.1", True),
        ("127.1.2.3", True),
        ("::1", True),
        ("::ffff:127.0.0.1", True),
        ("10.0.0.5", False),
        ("172.18.0.1", False),
        ("::2", False),
        ("testclient", False),
        ("", False),
        (None, False),
    ],
)
def test_only_loopback_clients_are_loopback(host, expected):
    assert metrics._is_loopback(host) is expected


def test_non_loopback_client_gets_403(temp_db_client):
    resp = temp_db_client.get("/metrics")
    assert resp.status_code == 403
    assert "loopback" in resp.json()["detail"]


_TOKEN = "canary-0f9e8d7c6b5a4938-metrics-token"


def test_right_token_from_a_non_loopback_address_is_accepted(temp_db_client, monkeypatch):
    monkeypatch.setenv("METRICS_TOKEN", _TOKEN)
    resp = temp_db_client.get("/metrics", headers={"Authorization": f"Bearer {_TOKEN}"})
    assert resp.status_code == 200
    _, _, samples = parse(resp.text)
    assert _value(samples, "ctiparsor_database_up") == 1


def test_wrong_token_from_a_non_loopback_address_gets_403(temp_db_client, monkeypatch):
    monkeypatch.setenv("METRICS_TOKEN", _TOKEN)
    resp = temp_db_client.get("/metrics", headers={"Authorization": "Bearer not-the-token"})
    assert resp.status_code == 403
    assert _TOKEN not in resp.text


def test_missing_token_from_a_non_loopback_address_gets_403(temp_db_client, monkeypatch):
    monkeypatch.setenv("METRICS_TOKEN", _TOKEN)
    resp = temp_db_client.get("/metrics")
    assert resp.status_code == 403


def test_a_wrong_token_is_refused_even_from_loopback(loopback_client, monkeypatch):
    monkeypatch.setenv("METRICS_TOKEN", _TOKEN)
    resp = loopback_client.get("/metrics", headers={"Authorization": "Bearer not-the-token"})
    assert resp.status_code == 403


def test_loopback_needs_no_token_when_one_is_configured(loopback_client, monkeypatch):
    monkeypatch.setenv("METRICS_TOKEN", _TOKEN)
    assert loopback_client.get("/metrics").status_code == 200


def test_a_non_bearer_authorization_header_does_not_count(temp_db_client, monkeypatch):
    monkeypatch.setenv("METRICS_TOKEN", _TOKEN)
    resp = temp_db_client.get("/metrics", headers={"Authorization": f"Basic {_TOKEN}"})
    assert resp.status_code == 403


def test_empty_token_setting_keeps_the_loopback_rule(temp_db_client, monkeypatch):
    monkeypatch.setenv("METRICS_TOKEN", "")
    resp = temp_db_client.get("/metrics", headers={"Authorization": "Bearer "})
    assert resp.status_code == 403


def test_the_token_never_reaches_the_logs(temp_db_client, monkeypatch, caplog):
    import logging

    monkeypatch.setenv("METRICS_TOKEN", _TOKEN)
    caplog.set_level(logging.DEBUG)
    good = temp_db_client.get("/metrics", headers={"Authorization": f"Bearer {_TOKEN}"})
    bad = temp_db_client.get("/metrics", headers={"Authorization": "Bearer not-the-token"})
    assert good.status_code == 200
    assert bad.status_code == 403
    assert _TOKEN not in caplog.text
    assert _TOKEN not in good.text and _TOKEN not in bad.text


def test_metrics_is_left_out_of_the_schema(temp_db_client):
    import api.main

    assert "/metrics" not in api.main.app.openapi()["paths"]


def test_seeded_database_is_reflected(loopback_client, temp_db):
    now = temp_db.now_iso()
    _insert_job(temp_db, "u1", "uploaded", now)
    _insert_job(temp_db, "q-old", "queued", "2020-01-01T00:00:00+00:00")
    _insert_job(temp_db, "q-new", "queued", now)
    _insert_job(temp_db, "p1", "processing", now, worker_id="busy-w", heartbeat_at=now)
    _insert_job(temp_db, "f1", "failed", now)
    _insert_job(temp_db, "f2", "failed", now)
    _insert_job(temp_db, "c1", "completed", now)
    _insert_loop(temp_db, "busy-w", heartbeat_at=now)
    _insert_loop(temp_db, "idle-w", heartbeat_at=now)
    old = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
    _insert_loop(temp_db, "stale-w", heartbeat_at=old)

    resp = loopback_client.get("/metrics")
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/plain; version=0.0.4")
    helps, types, samples = parse(resp.text)

    assert _value(samples, "ctiparsor_database_up") == 1
    assert _value(samples, "ctiparsor_jobs", status="queued") == 2
    assert _value(samples, "ctiparsor_jobs", status="processing") == 1
    assert _value(samples, "ctiparsor_jobs", status="failed") == 2
    assert _value(samples, "ctiparsor_jobs", status="for_review") == 0
    assert _value(samples, "ctiparsor_failed_jobs") == 2
    assert _value(samples, "ctiparsor_oldest_queued_job_age_seconds") > 1000000
    assert _value(samples, "ctiparsor_workers", state="busy") == 1
    assert _value(samples, "ctiparsor_workers", state="idle") == 1
    assert _value(samples, "ctiparsor_workers", state="stale") == 1

    for name, _, _ in samples:
        assert name.startswith("ctiparsor_")
        assert name in helps and name in types, name


def test_empty_queue_has_zero_oldest_age_and_no_workers(loopback_client):
    helps, _, samples = parse(loopback_client.get("/metrics").text)
    assert _value(samples, "ctiparsor_oldest_queued_job_age_seconds") == 0
    assert _value(samples, "ctiparsor_workers", state="busy") == 0
    assert _value(samples, "ctiparsor_workers", state="idle") == 0
    assert _value(samples, "ctiparsor_workers", state="stale") == 0


def test_database_down_still_answers(loopback_client, monkeypatch):
    def unreachable():
        raise RuntimeError("connection refused")

    monkeypatch.setattr(metrics, "get_conn", unreachable)
    resp = loopback_client.get("/metrics")
    assert resp.status_code == 200
    _, _, samples = parse(resp.text)
    assert _value(samples, "ctiparsor_database_up") == 0
    names = {name for name, _, _ in samples}
    assert "ctiparsor_jobs" not in names
    assert "ctiparsor_workers" not in names
    assert "ctiparsor_state_dir_free_bytes" in names


def test_disk_metrics_come_from_the_filesystem(loopback_client, monkeypatch):
    Usage = namedtuple("Usage", "total used free")
    monkeypatch.setattr(metrics.shutil, "disk_usage", lambda path: Usage(total=100_000, used=60_000, free=40_000))
    _, _, samples = parse(loopback_client.get("/metrics").text)
    assert _value(samples, "ctiparsor_state_dir_free_bytes") == 40_000
    assert _value(samples, "ctiparsor_state_dir_total_bytes") == 100_000


def test_backup_metrics_present_from_the_status_file(loopback_client, monkeypatch, tmp_path):
    success = datetime(2026, 11, 7, 2, 30, tzinfo=timezone.utc)
    status = tmp_path / "status.json"
    status.write_text(
        json.dumps(
            {
                "last_attempt": "2026-11-08T02:31:00+00:00",
                "last_success": success.isoformat(),
                "ok": False,
                "error": "pg_dump failed",
                "file": None,
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("BACKUP_STATUS_FILE", str(status))
    _, _, samples = parse(loopback_client.get("/metrics").text)
    assert _value(samples, "ctiparsor_backup_last_attempt_ok") == 0
    assert _value(samples, "ctiparsor_backup_last_success_timestamp_seconds") == success.timestamp()


def test_backup_success_metric_absent_until_a_backup_succeeds(loopback_client, monkeypatch, tmp_path):
    status = tmp_path / "status.json"
    status.write_text(
        json.dumps({"last_attempt": None, "last_success": None, "ok": True, "error": None, "file": None}),
        encoding="utf-8",
    )
    monkeypatch.setenv("BACKUP_STATUS_FILE", str(status))
    _, _, samples = parse(loopback_client.get("/metrics").text)
    assert _value(samples, "ctiparsor_backup_last_attempt_ok") == 1
    assert all(name != "ctiparsor_backup_last_success_timestamp_seconds" for name, _, _ in samples)


def test_backup_metrics_absent_without_a_status_file(loopback_client):
    _, _, samples = parse(loopback_client.get("/metrics").text)
    assert all(not name.startswith("ctiparsor_backup") for name, _, _ in samples)


def test_backup_metrics_absent_from_a_malformed_status_file(loopback_client, monkeypatch, tmp_path):
    status = tmp_path / "status.json"
    status.write_text("{not json", encoding="utf-8")
    monkeypatch.setenv("BACKUP_STATUS_FILE", str(status))
    resp = loopback_client.get("/metrics")
    assert resp.status_code == 200
    _, _, samples = parse(resp.text)
    assert all(not name.startswith("ctiparsor_backup") for name, _, _ in samples)


def _rule_documents():
    return yaml.safe_load(RULES.read_text(encoding="utf-8"))["groups"][0]["rules"]


def _operations_anchors() -> set[str]:
    anchors = set()
    for line in OPERATIONS.read_text(encoding="utf-8").splitlines():
        if line.startswith("#"):
            title = line.lstrip("#").strip().lower()
            slug = re.sub(r"[^\w\- ]", "", title).replace(" ", "-")
            anchors.add(slug)
    return anchors


def test_every_alert_has_a_summary_and_a_runbook():
    rules = _rule_documents()
    assert rules, "no alert rules"
    for rule in rules:
        assert "alert" in rule and "expr" in rule, rule
        assert rule["annotations"].get("summary"), rule["alert"]
        assert rule["annotations"].get("runbook"), rule["alert"]


def test_every_runbook_points_to_an_existing_section():
    anchors = _operations_anchors()
    for rule in _rule_documents():
        target = rule["annotations"]["runbook"]
        path, _, anchor = target.partition("#")
        assert path == "docs/operations.md", rule["alert"]
        assert anchor in anchors, f"{rule['alert']}: no section #{anchor}"


def test_rules_only_use_metrics_the_endpoint_exports(loopback_client, monkeypatch, tmp_path):
    status = tmp_path / "status.json"
    status.write_text(
        json.dumps({"last_attempt": None, "last_success": "2026-11-07T02:30:00+00:00", "ok": True}),
        encoding="utf-8",
    )
    monkeypatch.setenv("BACKUP_STATUS_FILE", str(status))
    _, _, samples = parse(loopback_client.get("/metrics").text)
    exported = {name for name, _, _ in samples}
    for rule in _rule_documents():
        used = set(re.findall(r"ctiparsor_[a-z_]+", rule["expr"]))
        assert used <= exported, f"{rule['alert']} uses {used - exported}"
