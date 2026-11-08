"""Response models of the settings, thresholds, policy and ingest routes (ADR-0094 item 1).

Every operation of the four route files declares a response model in the OpenAPI
schema, and each one returns what its function returns: a read is compared with
the route function's own output, a write with the literal value it stores.  No
response changes (ADR-0094 item 1: describe what exists).
"""
from __future__ import annotations

import json
from unittest.mock import MagicMock, patch
from uuid import uuid4

import pytest
from fastapi.encoders import jsonable_encoder

import api.main
import api.routes.policy as policy_mod
import api.routes.settings as settings_mod
import api.routes.thresholds as thresholds_mod
import pipeline.thresholds as thresholds
from api.db import get_conn, now_iso
from pipeline import web_capture

_METHODS = {"get", "post", "put", "patch", "delete"}
_PREFIXES = (
    "/api/settings/",
    "/api/thresholds",
    "/api/relationship-policy",
    "/api/ingest/text",
    "/api/ingest/url",
)
_OPERATIONS = {
    ("GET", "/api/settings/corpora"),
    ("GET", "/api/settings/formats"),
    ("POST", "/api/settings/corpora"),
    ("DELETE", "/api/settings/corpora/{name}"),
    ("PATCH", "/api/settings/corpora/{name}"),
    ("POST", "/api/settings/corpora/{name}/sync"),
    ("POST", "/api/settings/corpora/rebuild"),
    ("GET", "/api/thresholds"),
    ("POST", "/api/thresholds/recalibrate"),
    ("PUT", "/api/thresholds/{source}/{entity_type}"),
    ("DELETE", "/api/thresholds/{source}/{entity_type}"),
    ("GET", "/api/relationship-policy/last-run"),
    ("GET", "/api/relationship-policy"),
    ("PUT", "/api/relationship-policy"),
    ("POST", "/api/ingest/text"),
    ("POST", "/api/ingest/url"),
}

_RULE = """\
title: PowerShell Encoded Command
id: aaaa1111-bbbb-2222-cccc-333333333333
detection:
  selection:
    Image|endswith: '\\powershell.exe'
  condition: selection
level: high
logsource:
  category: process_creation
tags:
  - attack.t1059.001
"""

_FULL_POLICY = {
    "version": 1,
    "global": "auto",
    "rules": [{"src": "threat-actor", "verb": "uses", "tgt": "malware", "mode": "pin", "enabled": True}],
    "max_pinned_edges": 50,
    "pin_budget_mode": "sequential",
    "pin_evidence": {"mode": "cartesian", "window": 0},
    "completion": {"transitive": False, "alias": True, "semantic_alias": False, "max_new_edges": 10},
    "temporal_export": {"mode": "day"},
}


# ── The schema ────────────────────────────────────────────────────────────────

def _operations() -> dict[tuple[str, str], dict]:
    found: dict[tuple[str, str], dict] = {}
    for path, item in api.main.app.openapi()["paths"].items():
        if not path.startswith(_PREFIXES):
            continue
        for method, op in item.items():
            if method in _METHODS:
                found[(method.upper(), path)] = op
    return found


def test_the_four_route_files_have_their_sixteen_operations():
    assert set(_operations()) == _OPERATIONS


@pytest.mark.parametrize(("method", "path"), sorted(_OPERATIONS))
def test_every_operation_declares_its_response(method, path):
    schema = _operations()[(method, path)]["responses"]["200"]["content"]["application/json"]["schema"]
    assert schema, f"{method} {path} has no 200 schema"


# ── settings ──────────────────────────────────────────────────────────────────

@pytest.fixture()
def corpora(temp_db, temp_db_client, tmp_path, monkeypatch):
    """A committed registry with one public corpus, cloned locally; no network."""
    clone = tmp_path / "corpora" / "demo"
    clone.mkdir(parents=True)
    (clone / "r.yml").write_text(_RULE, encoding="utf-8")
    cfg = tmp_path / "detection_corpora.yaml"
    cfg.write_text(
        "corpora:\n  - name: demo\n    adapter: sigma\n"
        "    git: https://github.com/org/demo.git\n"
        f"    path: {clone.as_posix()}\n    license: DRL-1.1\n    enabled: true\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(settings_mod, "_CONFIG", cfg)
    monkeypatch.setattr(settings_mod, "validate_url", lambda url: url)
    return cfg


def test_list_corpora_and_formats_are_what_the_functions_return(temp_db_client, corpora):
    body = temp_db_client.get("/api/settings/corpora").json()
    assert body == jsonable_encoder(settings_mod.list_corpora())
    assert body["corpora"][0]["git"] == "https://github.com/org/demo.git"
    formats = temp_db_client.get("/api/settings/formats")
    assert formats.status_code == 200
    assert formats.json() == jsonable_encoder(settings_mod.list_formats())


def test_an_unset_optional_key_stays_absent(temp_db_client, corpora):
    """`tarball` is not in the registry: the response must not add it as null."""
    [demo] = temp_db_client.get("/api/settings/corpora").json()["corpora"]
    assert "tarball" not in demo and "subdir" not in demo and "priority" not in demo


def test_create_corpus_returns_the_corpora_after_the_change(temp_db_client, corpora):
    resp = temp_db_client.post("/api/settings/corpora", json={
        "name": "extra", "git": "https://github.com/org/extra.git", "license": "Apache-2.0"})
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert list(body) == ["ok", "warning", "corpora"]
    assert body["ok"] is True and body["warning"] is None
    assert body["corpora"] == jsonable_encoder(settings_mod._with_counts())


def test_create_corpus_for_an_unbuilt_adapter_carries_a_warning(temp_db_client, corpora, monkeypatch):
    monkeypatch.setattr(settings_mod, "_ADAPTERS", {})
    resp = temp_db_client.post("/api/settings/corpora", json={
        "name": "later", "adapter": "yara", "git": "https://github.com/org/later.git"})
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["warning"] and "'yara' has no parser" in body["warning"]
    later = next(c for c in body["corpora"] if c["name"] == "later")
    assert later["adapter_available"] is False
    assert body["corpora"] == jsonable_encoder(settings_mod._with_counts())


def test_patch_and_delete_return_the_corpora_after_the_change(temp_db_client, corpora):
    resp = temp_db_client.patch("/api/settings/corpora/demo", json={"enabled": False})
    assert resp.status_code == 200
    assert resp.json() == {"ok": True, "corpora": jsonable_encoder(settings_mod._with_counts())}
    assert resp.json()["corpora"][0]["enabled"] is False

    resp = temp_db_client.delete("/api/settings/corpora/demo")
    assert resp.status_code == 200
    assert resp.json() == {"ok": True, "corpora": jsonable_encoder(settings_mod._with_counts())}


def test_sync_returns_its_summary_and_rebuild_matches_its_function(temp_db_client, corpora, monkeypatch):
    monkeypatch.setattr(settings_mod, "clone_mismatch", lambda corpus: None)
    monkeypatch.setattr(settings_mod, "sync_corpus", lambda corpus, **kwargs: (True, "cloned demo"))

    resp = temp_db_client.post("/api/settings/corpora/demo/sync")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert list(body) == ["ok", "detail", "rules", "file_errors", "corpora"]
    assert body["ok"] is True and body["detail"] == "cloned demo"
    assert body["rules"] == 1 and body["file_errors"] == []
    assert body["corpora"] == jsonable_encoder(settings_mod._with_counts())

    rebuilt = temp_db_client.post("/api/settings/corpora/rebuild")
    assert rebuilt.status_code == 200, rebuilt.text
    assert rebuilt.json() == jsonable_encoder(settings_mod.rebuild_corpora())
    assert set(rebuilt.json()) == {
        "written", "skipped", "skip_reasons", "removed", "file_errors",
        "total", "dedup", "rule_text", "counts",
    }


# ── thresholds ────────────────────────────────────────────────────────────────

@pytest.fixture(autouse=True)
def _fresh_thresholds():
    thresholds.reload()
    yield
    thresholds.reload()


def _seed_split(db) -> None:
    """640 gliner/malware decisions: 50 % accepted below 0.60, 95 % above."""
    conn = db.get_conn()
    now = db.now_iso()
    conn.execute(
        "INSERT INTO jobs (id, original_filename, status, created_at, updated_at) VALUES (?,?,?,?,?)",
        ("job-t", "r.pdf", "for_review", now, now),
    )
    rows = []
    for s in range(40, 60):
        rows += [(s / 100, 1), (s / 100, 0)]
    for s in range(60, 90):
        rows += [(s / 100, 1)] * 19 + [(s / 100, 0)]
    conn.executemany(
        "INSERT INTO entities (id, job_id, value, entity_type, context, confidence, accepted, source, "
        "decision_origin) VALUES (?,?,?,?,?,?,?,?,?)",
        [(str(uuid4()), "job-t", f"e{i}", "malware", "", conf, acc, "gliner", "human")
         for i, (conf, acc) in enumerate(rows)],
    )
    conn.commit()


def test_get_thresholds_is_what_the_function_returns(temp_db_client, temp_db):
    resp = temp_db_client.get("/api/thresholds")
    assert resp.status_code == 200
    assert resp.json() == jsonable_encoder(thresholds_mod.get_thresholds())


def test_recalibrate_dry_run_and_apply_return_the_proposals(temp_db_client, temp_db):
    _seed_split(temp_db)
    dry = temp_db_client.post("/api/thresholds/recalibrate", json={"min_samples": 100})
    assert dry.status_code == 200, dry.text
    assert dry.json() == jsonable_encoder(
        thresholds_mod.recalibrate(thresholds_mod.RecalibrateIn(min_samples=100)))

    applied = temp_db_client.post("/api/thresholds/recalibrate", json={"min_samples": 100, "apply": True})
    assert applied.status_code == 200, applied.text
    body = applied.json()
    assert body["applied"] is True and body["written"] == 1
    assert body["proposals"] == dry.json()["proposals"]
    assert body["proposals"][0]["status"] == "ok"


def test_put_and_delete_a_threshold(temp_db_client, temp_db):
    put = temp_db_client.put("/api/thresholds/gliner/malware", json={"threshold": 0.5})
    assert put.status_code == 200
    assert put.json() == {"source": "gliner", "entity_type": "malware", "threshold": 0.5, "origin": "manual"}

    listed = temp_db_client.get("/api/thresholds")
    assert listed.json() == jsonable_encoder(thresholds_mod.get_thresholds())
    assert listed.json()["rows"][0]["origin"] == "manual"

    deleted = temp_db_client.delete("/api/thresholds/gliner/malware")
    assert deleted.status_code == 200
    assert deleted.json() == {
        "deleted": {"source": "gliner", "entity_type": "malware"},
        "default": thresholds_mod.stage_default("gliner"),
    }


# ── relationship policy ───────────────────────────────────────────────────────

def test_the_factory_policy_is_served_until_one_is_stored(temp_db_client, temp_db):
    assert temp_db_client.get("/api/relationship-policy").json() == {
        "version": 1, "global": "enforce", "rules": [],
    }


def test_a_full_policy_round_trips_unchanged(temp_db_client, temp_db):
    assert temp_db_client.put("/api/relationship-policy", json=_FULL_POLICY).json() == _FULL_POLICY
    assert temp_db_client.get("/api/relationship-policy").json() == _FULL_POLICY


def test_an_optional_key_the_policy_omits_stays_absent(temp_db_client, temp_db):
    """A policy without `completion` or `rules` must not gain them as null."""
    assert temp_db_client.put("/api/relationship-policy", json={"rules": []}).json() == {"rules": []}
    assert temp_db_client.get("/api/relationship-policy").json() == {"rules": []}


def test_a_policy_keeps_keys_and_versions_the_put_does_not_check(temp_db_client, temp_db):
    body = {"version": "beta", "custom": {"kept": [1, 2]}, "rules": []}
    assert temp_db_client.put("/api/relationship-policy", json=body).json() == body
    assert temp_db_client.get("/api/relationship-policy").json() == body


def test_last_run_on_an_empty_store(temp_db_client, temp_db):
    assert temp_db_client.get("/api/relationship-policy/last-run").json() == {
        "job_id": None, "filename": None, "created_at": None,
        "pin": None, "completion": None, "available": False,
    }


def test_last_run_returns_the_synthesis_stats_of_the_newest_bundle(temp_db_client, temp_db):
    stats = {"pin": {"budget": 200, "rules": []}, "completion": {"aliases_merged": 1}}
    bundle = {"type": "bundle", "id": "bundle--1", "objects": [
        {"type": "report", "id": "report--1", "x_synthesis_stats": stats}]}
    conn = get_conn()
    now = now_iso()
    conn.execute(
        "INSERT INTO jobs (id, original_filename, status, created_at, updated_at, bundle_json) "
        "VALUES (?,?,?,?,?,?)",
        ("job-p", "report.pdf", "done", now, now, json.dumps(bundle)),
    )
    conn.commit()
    resp = temp_db_client.get("/api/relationship-policy/last-run")
    assert resp.status_code == 200
    assert resp.json() == jsonable_encoder(policy_mod.get_last_run())
    assert resp.json()["available"] is True and resp.json()["pin"] == stats["pin"]


# ── ingest ────────────────────────────────────────────────────────────────────

@pytest.fixture()
def ingest_client(temp_db_client, tmp_path, monkeypatch):
    """The worker stubbed out, uploads in tmp_path, the rate limiter reset per test."""
    api.main.limiter.reset()
    monkeypatch.setenv("CTIPARSOR_UPLOADS_DIR", str(tmp_path))
    with patch("api.worker.run_pipeline_async", MagicMock(return_value="started")) as spawn:
        temp_db_client.spawn = spawn  # type: ignore[attr-defined]
        yield temp_db_client


def test_pasted_text_returns_the_job(ingest_client):
    resp = ingest_client.post("/api/ingest/text", json={
        "text": "APT29 deployed SUNBURST against SolarWinds targets and contacted 185.220.101.45.",
        "title": "Report",
    })
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert list(body) == ["job_id", "filename", "status"]
    assert body["filename"].endswith(".txt")
    assert body["status"] == "processing"


def test_a_queued_job_is_reported_as_queued(ingest_client):
    ingest_client.spawn.return_value = "queued"
    resp = ingest_client.post("/api/ingest/text", json={
        "text": "APT29 deployed SUNBURST against SolarWinds targets and contacted 185.220.101.45.",
    })
    assert resp.status_code == 200, resp.text
    assert resp.json()["status"] == "queued"


def test_a_captured_url_returns_the_job_and_the_capture_fields(ingest_client, tmp_path, monkeypatch):
    monkeypatch.setattr(web_capture, "_PLAYWRIGHT_AVAILABLE", True)
    monkeypatch.setattr(web_capture, "validate_url", lambda u: u)

    def _fake(url, dest, **kwargs):
        dest.write_bytes(b"%PDF-1.4 fake")
        return web_capture.CaptureResult(
            pdf_path=dest,
            final_url="https://thedfirreport.com/a/",
            title="Threat Actor Toolkit",
            bytes_written=13,
            js_enabled=False,
            blocked_requests=7,
            rendered_chars=42,
            dom_text="APT29 contacted 185.220.101.45 for command and control.",
        )

    monkeypatch.setattr(web_capture, "capture_url_to_pdf", _fake)
    resp = ingest_client.post("/api/ingest/url", json={"url": "https://thedfirreport.com/a/"})
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body == {
        "job_id": body["job_id"],
        "filename": "threat-actor-toolkit.pdf",
        "status": "processing",
        "source_url": "https://thedfirreport.com/a/",
        "blocked_requests": 7,
        "rendered_chars": 42,
    }
    assert (tmp_path / f"{body['job_id']}.pdf").exists()


def test_a_policy_stored_before_the_put_checks_still_reads(temp_db, temp_db_client):
    # A body the PUT would refuse today (wrong types, a rule that is not an
    # object) may sit in the database from an older release: GET returns it
    # as stored instead of failing on the response model.
    legacy = {"version": "1", "global": 1, "rules": ["src->uses->tgt"],
              "max_pinned_edges": "ten", "completion": {"transitive": "yes", "max_new_edges": 2.5},
              "pin_evidence": {"window": "3"}}
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO relationship_policy (id, policy_json) VALUES (1, ?) "
            "ON CONFLICT (id) DO UPDATE SET policy_json = excluded.policy_json",
            (json.dumps(legacy),),
        )
        conn.commit()
    r = temp_db_client.get("/api/relationship-policy")
    assert r.status_code == 200
    assert r.json() == legacy
