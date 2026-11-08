"""The stage report in GET /api/jobs/{id} and GET /api/llm/egress (ADR-0097 work item 16).

No network and no LLM: the egress route reads the environment only.
"""
import json

import pytest

from pipeline import egress


@pytest.fixture(autouse=True)
def _egress_open():
    """The real rule, not conftest's allow-all (same name: it overrides that fixture)."""


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for var in ("LLM_LOCAL_HOSTS", "STIX_TLP", "VLLM_BASE_URL", "ANTHROPIC_BASE_URL", "VISION_PROVIDER",
                "NO_PROXY", "no_proxy",
                *(v for p in ("HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY") for v in (p, p.lower()))):
        monkeypatch.delenv(var, raising=False)
    egress._WARNED.clear()


def _provider(monkeypatch, name, vllm_url=None):
    monkeypatch.setattr("pipeline.stage3_llm._PROVIDER", name)
    monkeypatch.setenv("LLM_PROVIDER", name)
    if vllm_url:
        monkeypatch.setenv("VLLM_BASE_URL", vllm_url)


def _insert(temp_db, job_id, run_config):
    with temp_db.get_conn() as conn:
        conn.execute(
            "INSERT INTO jobs (id, original_filename, status, run_config_json, created_at, updated_at) "
            "VALUES (?,'r.txt','for_review',?,?,?)",
            (job_id, None if run_config is None else json.dumps(run_config),
             temp_db.now_iso(), temp_db.now_iso()))
        conn.commit()


# ── stages in GET /api/jobs/{id} ─────────────────────────────────────────────

def test_stages_come_back_as_stored_with_a_label(temp_db_client, temp_db):
    refusal = {"tlp": "AMBER", "provider": "anthropic", "host": "api.anthropic.com",
               "local": False, "allowed": False}
    report = [
        {"stage": "2", "status": "ran", "reason": "", "seconds": 0.1, "counts": {"iocs": 3}},
        {"stage": "3", "status": "skipped", "reason": "TLP:AMBER forbids sending the report to anthropic",
         "seconds": 0.0, "counts": {}, "egress": refusal},
    ]
    _insert(temp_db, "st1", {"stage_report": report, "stages": {"other": 1}})

    stages = temp_db_client.get("/api/jobs/st1").json()["stages"]

    assert [s["stage"] for s in stages] == ["2", "3"]
    assert [s["label"] for s in stages] == ["regex IoCs", "LLM enrichment"]
    assert stages[1]["status"] == "skipped"
    assert stages[1]["reason"].startswith("TLP:AMBER forbids")
    assert stages[1]["egress"] == refusal
    assert "egress" not in stages[0]                 # unset stays absent
    assert stages[0]["counts"] == {"iocs": 3}        # stored extras pass through


@pytest.mark.parametrize("run_config", [None, {}, {"stages": {}}, {"stage_report": "oops"}])
def test_stages_are_absent_without_a_stored_report(temp_db_client, temp_db, run_config):
    _insert(temp_db, "st2", run_config)
    assert "stages" not in temp_db_client.get("/api/jobs/st2").json()


# ── GET /api/llm/egress ──────────────────────────────────────────────────────

@pytest.mark.parametrize("tlp", ["CLEAR", "GREEN"])
def test_open_levels_may_go_to_anthropic(temp_db_client, monkeypatch, tlp):
    _provider(monkeypatch, "anthropic")
    body = temp_db_client.get("/api/llm/egress", params={"tlp": tlp}).json()
    assert body["tlp"] == tlp
    assert body["text"]["allowed"] is True
    assert body["text"]["provider"] == "anthropic"


@pytest.mark.parametrize("tlp", ["AMBER", None])
def test_amber_and_the_default_marking_are_refused_to_anthropic(temp_db_client, monkeypatch, tlp):
    _provider(monkeypatch, "anthropic")
    body = temp_db_client.get("/api/llm/egress", params={"tlp": tlp} if tlp else None).json()
    assert body["tlp"] == "AMBER"                    # no STIX_TLP: the default marking
    text = body["text"]
    assert (text["allowed"], text["local"], text["host"]) == (False, False, "api.anthropic.com")
    assert text["reason"].startswith("TLP:AMBER forbids sending the report to anthropic")
    assert body["figures"]["allowed"] is False       # VISION_PROVIDER=auto follows the text provider


def test_the_default_marking_follows_stix_tlp(temp_db_client, monkeypatch):
    _provider(monkeypatch, "anthropic")
    monkeypatch.setenv("STIX_TLP", "GREEN")
    body = temp_db_client.get("/api/llm/egress").json()
    assert (body["tlp"], body["text"]["allowed"]) == ("GREEN", True)


def test_a_local_vllm_takes_an_amber_report(temp_db_client, monkeypatch):
    _provider(monkeypatch, "vllm", "http://127.0.0.1:8000")
    body = temp_db_client.get("/api/llm/egress", params={"tlp": "AMBER"}).json()
    assert body["text"] == {"tlp": "AMBER", "provider": "vllm", "host": "127.0.0.1",
                            "local": True, "allowed": True, "reason": ""}
    assert body["figures"]["allowed"] is True


def test_figures_are_null_when_no_vision_backend_is_named(temp_db_client, monkeypatch):
    _provider(monkeypatch, "anthropic")
    monkeypatch.setenv("VISION_PROVIDER", "none")
    body = temp_db_client.get("/api/llm/egress", params={"tlp": "AMBER"}).json()
    assert body["figures"] is None


def test_an_invalid_tlp_is_a_400(temp_db_client):
    resp = temp_db_client.get("/api/llm/egress", params={"tlp": "PURPLE"})
    assert resp.status_code == 400
    assert "TLP" in resp.json()["detail"]


def test_the_operations_declare_their_models():
    import api.main

    paths = api.main.app.openapi()["paths"]
    assert "EgressPreview" in json.dumps(paths["/api/llm/egress"]["get"]["responses"]["200"])
    assert "StageRecord" in json.dumps(api.main.app.openapi()["components"]["schemas"]["JobDetail"])
