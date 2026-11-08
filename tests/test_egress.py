"""pipeline/egress.py — the TLP egress policy (ADR-0097): which providers may
receive a report's content, and the refusal in the stage report.

No network and no LLM: every provider call is a mock that fails if reached.
"""
import ast
import json
import logging
from pathlib import Path
from types import SimpleNamespace

import pytest

from pipeline import egress
from pipeline.orchestrator import Document, RunOptions, StageRequired, run_document


@pytest.fixture(autouse=True)
def _egress_open():
    """The real rule, not conftest's allow-all (same name: it overrides that fixture)."""


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for var in ("LLM_LOCAL_HOSTS", "STIX_TLP", "VLLM_BASE_URL", "OLLAMA_BASE_URL",
                "LMSTUDIO_BASE_URL", "ANTHROPIC_BASE_URL", "NO_PROXY", "no_proxy",
                *(v for p in ("HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY") for v in (p, p.lower()))):
        monkeypatch.delenv(var, raising=False)
    egress._WARNED.clear()


# ── The rule ─────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("provider", ["anthropic", "gemini", "mistral", "vllm", "ollama", "lmstudio"])
@pytest.mark.parametrize("tlp", ["CLEAR", "GREEN"])
def test_open_levels_go_to_any_provider(tlp, provider, monkeypatch):
    monkeypatch.setenv("VLLM_BASE_URL", "https://llm.example.com")
    assert egress.decide(tlp, provider).allowed


@pytest.mark.parametrize("tlp", ["AMBER", "AMBER+STRICT", "RED"])
@pytest.mark.parametrize("provider", ["anthropic", "gemini", "mistral"])
def test_hosted_providers_never_get_a_marked_report(tlp, provider):
    d = egress.decide(tlp, provider)
    assert (d.allowed, d.local) == (False, False)
    assert d.reason.startswith(f"TLP:{tlp} forbids sending the report to {provider} (")
    assert d.reason.endswith("only a local provider may process it (ADR-0097)")


@pytest.mark.parametrize("tlp", ["AMBER", "AMBER+STRICT", "RED"])
@pytest.mark.parametrize("provider", ["vllm", "ollama", "lmstudio"])
def test_a_local_kind_on_its_default_url_is_local(tlp, provider):
    d = egress.decide(tlp, provider)
    assert (d.allowed, d.local, d.host) == (True, True, "localhost")


@pytest.mark.parametrize("url,host,local", [
    ("http://127.0.0.1:8000", "127.0.0.1", True),
    ("http://10.1.2.3:8000", "10.1.2.3", True),
    ("http://192.168.0.29:8000", "192.168.0.29", True),
    ("http://172.16.0.5", "172.16.0.5", True),
    ("http://8.8.8.8:8000", "8.8.8.8", False),
    ("http://[::1]:8000", "::1", True),
    ("http://[fd00::5]:8000", "fd00::5", True),
    ("http://[2001:4860:4860::8888]:8000", "2001:4860:4860::8888", False),
    ("http://llm.example.com:8000", "llm.example.com", False),
    ("http://LocalHost:8000", "localhost", True),
    ("http://ollama:11434", "ollama", True),
    ("192.168.0.29:8000", "192.168.0.29", True),
])
def test_the_host_of_the_base_url_decides(url, host, local, monkeypatch):
    monkeypatch.setenv("VLLM_BASE_URL", url)
    assert egress.provider_host("vllm") == host
    d = egress.decide("RED", "vllm")
    assert (d.local, d.allowed) == (local, local)


def test_a_declared_name_is_local_and_matching_ignores_case(monkeypatch):
    monkeypatch.setenv("OLLAMA_BASE_URL", "http://gpu-box.corp.internal:11434")
    assert not egress.decide("AMBER", "ollama").allowed
    monkeypatch.setenv("LLM_LOCAL_HOSTS", "GPU-Box.corp.internal, other")
    assert egress.decide("AMBER", "ollama").allowed


def test_llm_local_hosts_replaces_the_default_list(monkeypatch):
    monkeypatch.setenv("OLLAMA_BASE_URL", "http://ollama:11434")
    assert egress.decide("AMBER", "ollama").allowed
    monkeypatch.setenv("LLM_LOCAL_HOSTS", "localhost")
    assert not egress.decide("AMBER", "ollama").allowed


def test_no_dns_lookup_a_name_outside_the_list_is_external(monkeypatch):
    def refuse(*args, **kwargs):
        raise AssertionError("a lookup was made")
    monkeypatch.setattr("socket.getaddrinfo", refuse)
    monkeypatch.setenv("VLLM_BASE_URL", "http://intranet-gpu:8000")
    assert not egress.decide("AMBER", "vllm").allowed


def test_only_the_host_is_kept_from_a_url_with_credentials(monkeypatch):
    monkeypatch.setenv("VLLM_BASE_URL", "http://user:s3cret@10.0.0.7:8000/v1?key=abc")
    d = egress.decide("AMBER", "vllm")
    assert d.host == "10.0.0.7"
    assert "s3cret" not in json.dumps(d.record()) and "user" not in json.dumps(d.record())


@pytest.mark.parametrize("url", [
    "http://169.254.169.254/latest", "http://[fe80::1]:8000", "http://0.0.0.0:8000", "http://[::]:8000",
    "http://127.0.0.1\\@evil.example.com:8000", "http://127.0.0.1 :8000", "http://127.0.0.1\x01:8000",
])
def test_link_local_unspecified_and_odd_urls_are_external(url, monkeypatch):
    monkeypatch.setenv("VLLM_BASE_URL", url)
    d = egress.decide("AMBER", "vllm")
    assert (d.local, d.allowed) == (False, False)


def test_a_trailing_dot_is_dropped(monkeypatch):
    monkeypatch.setenv("VLLM_BASE_URL", "http://localhost.:8000")
    assert egress.provider_host("vllm") == "localhost" and egress.decide("RED", "vllm").allowed
    monkeypatch.setenv("VLLM_BASE_URL", "http://gpu.corp:8000")
    monkeypatch.setenv("LLM_LOCAL_HOSTS", "GPU.corp.")
    assert egress.decide("RED", "vllm").allowed


def test_an_entry_with_a_colon_is_ignored_once_with_a_warning(monkeypatch, caplog):
    monkeypatch.setenv("VLLM_BASE_URL", "http://gpu.corp:8000")
    monkeypatch.setenv("LLM_LOCAL_HOSTS", "gpu.corp:8000,localhost")
    with caplog.at_level(logging.WARNING, logger="pipeline.egress"):
        assert not egress.decide("RED", "vllm").allowed
        egress.decide("RED", "vllm")
    warnings = [r for r in caplog.records if "gpu.corp:8000" in r.getMessage()]
    assert len(warnings) == 1 and "ignored" in warnings[0].getMessage()


def test_a_proxy_makes_a_private_host_external_unless_no_proxy_covers_it(monkeypatch):
    monkeypatch.setenv("VLLM_BASE_URL", "http://10.0.0.7:8000")
    monkeypatch.setenv("https_proxy", "http://proxy.corp:3128")
    d = egress.decide("AMBER", "vllm")
    assert (d.local, d.allowed) == (False, False)
    assert "a proxy is configured for 10.0.0.7" in d.reason
    for covers, allowed in (("10.0.0.7", True), ("10.0.0.0/24", True), ("*", True), ("other,.corp", False)):
        monkeypatch.setenv("NO_PROXY", covers)
        assert egress.decide("AMBER", "vllm").allowed == allowed, covers
    monkeypatch.setenv("VLLM_BASE_URL", "http://gpu.lab.corp:8000")
    monkeypatch.setenv("LLM_LOCAL_HOSTS", "gpu.lab.corp")
    monkeypatch.setenv("NO_PROXY", "other,.corp")
    assert egress.decide("AMBER", "vllm").allowed                 # a domain suffix
    monkeypatch.setenv("NO_PROXY", "lab.corp.example")
    assert not egress.decide("AMBER", "vllm").allowed


def test_a_proxy_does_not_matter_to_an_open_level(monkeypatch):
    monkeypatch.setenv("ALL_PROXY", "http://proxy.corp:3128")
    assert egress.decide("GREEN", "anthropic").allowed


def test_anthropic_host_follows_its_base_url(monkeypatch):
    assert egress.provider_host("anthropic") == "api.anthropic.com"
    monkeypatch.setenv("ANTHROPIC_BASE_URL", "https://key:secret@gateway.corp:8443/v1")
    assert egress.provider_host("anthropic") == "gateway.corp"
    assert not egress.decide("AMBER", "anthropic").allowed


def test_a_bad_marking_names_its_setting(monkeypatch):
    with pytest.raises(ValueError, match="report's TLP marking is refused"):
        egress.effective_tlp("PURPLE")
    monkeypatch.setenv("STIX_TLP", "PURPLE")
    with pytest.raises(ValueError, match="STIX_TLP is refused"):
        egress.effective_tlp(None)


# ── The effective TLP ────────────────────────────────────────────────────────

def test_an_unmarked_report_is_amber():
    assert egress.effective_tlp(None) == egress.effective_tlp("") == "AMBER"


def test_an_unmarked_report_takes_stix_tlp(monkeypatch):
    monkeypatch.setenv("STIX_TLP", "GREEN")
    assert egress.effective_tlp(None) == "GREEN"


def test_a_report_marking_wins_over_stix_tlp(monkeypatch):
    monkeypatch.setenv("STIX_TLP", "GREEN")
    assert egress.effective_tlp("tlp:white") == "CLEAR"
    assert egress.effective_tlp("TLP:AMBER+STRICT") == "AMBER+STRICT"


# ── The orchestrator ─────────────────────────────────────────────────────────

def _opts(**kw) -> RunOptions:
    kw.setdefault("disabled", frozenset({"2f"}))
    kw.setdefault("verify_relationships", False)
    kw.setdefault("verify_ttps", False)
    return RunOptions(consensus=False, document_relations=False, llm_parallelism=1, **kw)


@pytest.fixture(autouse=True)
def _no_heavy_models(monkeypatch):
    for module in ("pipeline.stage2c_ttp_semantic", "pipeline.stage2d_cyner", "pipeline.stage2e_gliner"):
        monkeypatch.setattr(f"{module}._SKIP_HEAVY", True)


@pytest.fixture()
def no_call(monkeypatch):
    """Every way Stage 3 reaches a provider fails the test, and counts as called."""
    import pipeline.stage3_llm as s3
    calls: list[str] = []

    def boom(*args, **kwargs):
        calls.append("called")
        raise AssertionError("a provider was reached")

    monkeypatch.setattr(s3, "_provider_ready", lambda provider=None: True)
    monkeypatch.setattr(s3, "_call_llm", boom)
    monkeypatch.setattr(s3, "enrich_chunk", boom)
    monkeypatch.setattr(s3, "enrich_document_relations", boom)
    return calls


def test_an_amber_report_is_not_sent_to_anthropic(no_call, sample_cti_text, monkeypatch):
    import pipeline.stage3_llm as s3
    monkeypatch.setattr(s3, "_PROVIDER", "anthropic")

    result = run_document(Document(text=sample_cti_text), _opts())

    reason = ("TLP:AMBER forbids sending the report to anthropic (api.anthropic.com): "
              "only a local provider may process it (ADR-0097)")
    assert (result.outcome("3").status, result.outcome("3").reason) == ("skipped", reason)
    for sid in ("3d", "3f", "3e", "3doc"):
        assert result.outcome(sid).status == "skipped"
    assert no_call == []
    assert result.llm_result is not None and result.bundle is not None
    record = next(s for s in result.stage_report() if s["stage"] == "3")
    assert record["egress"] == {"tlp": "AMBER", "provider": "anthropic", "host": "api.anthropic.com",
                                "local": False, "allowed": False}
    json.dumps(result.stage_report())


def test_an_amber_report_is_sent_to_vllm_on_loopback(mock_llm, sample_cti_text, monkeypatch):
    import pipeline.stage3_llm as s3
    monkeypatch.setattr(s3, "_PROVIDER", "vllm")
    monkeypatch.setattr(s3, "_provider_ready", lambda provider=None: True)
    monkeypatch.setenv("VLLM_BASE_URL", "http://127.0.0.1:8000")

    result = run_document(Document(text=sample_cti_text, tlp_level="TLP:AMBER"), _opts())

    assert result.outcome("3").status == "ran" and mock_llm.call_count > 0
    record = next(s for s in result.stage_report() if s["stage"] == "3")
    assert record["egress"] == {"tlp": "AMBER", "provider": "vllm", "host": "127.0.0.1",
                                "local": True, "allowed": True}


def test_a_green_report_may_go_to_anthropic(mock_llm, sample_cti_text, monkeypatch):
    import pipeline.stage3_llm as s3
    monkeypatch.setattr(s3, "_PROVIDER", "anthropic")
    monkeypatch.setattr(s3, "_provider_ready", lambda provider=None: True)

    result = run_document(Document(text=sample_cti_text, tlp_level="GREEN"), _opts())

    assert result.outcome("3").status == "ran" and mock_llm.call_count > 0


def test_a_required_stage_3_fails_with_the_reason(no_call, sample_cti_text, monkeypatch):
    import pipeline.stage3_llm as s3
    monkeypatch.setattr(s3, "_PROVIDER", "mistral")

    with pytest.raises(StageRequired) as err:
        run_document(Document(text=sample_cti_text, tlp_level="RED"), _opts(required={"3"}))

    assert err.value.outcome.stage == "3"
    assert "TLP:RED forbids sending the report to mistral" in err.value.outcome.reason
    assert no_call == []


def test_the_second_provider_of_consensus_is_refused_alone(mock_llm, sample_cti_text, monkeypatch):
    import pipeline.stage3_llm as s3
    monkeypatch.setattr(s3, "_PROVIDER", "vllm")
    monkeypatch.setattr(s3, "_provider_ready", lambda provider=None: True)
    monkeypatch.setenv("VLLM_BASE_URL", "http://127.0.0.1:8000")
    monkeypatch.setenv("CONSENSUS_PROVIDER", "gemini")

    opts = RunOptions(disabled=frozenset({"2f"}), verify_relationships=False, verify_ttps=False,
                      consensus=True, document_relations=False, llm_parallelism=1)
    result = run_document(Document(text=sample_cti_text), opts)

    assert result.outcome("3").status == "ran"
    assert result.outcome("3e").status == "skipped"
    assert "forbids sending the report to gemini" in result.outcome("3e").reason
    assert all(call.kwargs.get("provider") != "gemini" for call in mock_llm.call_args_list)


@pytest.fixture()
def vision(monkeypatch, tmp_path):
    """A PDF, a probe that counts its calls, and an empty figure reader."""
    from pipeline import vlm
    probes: list[int] = []

    def probe():
        probes.append(1)
        return SimpleNamespace(name="anthropic", model="m")

    monkeypatch.setenv("VISION_PROVIDER", "anthropic")
    monkeypatch.setattr(vlm, "get_backend", probe)
    monkeypatch.setattr("pipeline.stage1f_figures.read_figures", lambda *a, **k: [])
    vlm.reset_backend_cache()
    pdf = tmp_path / "report.pdf"
    pdf.write_bytes(b"%PDF-1.4\n")
    yield pdf, probes
    vlm.reset_backend_cache()


def test_an_amber_report_sends_no_figure_to_an_external_vision_provider(vision, sample_cti_text):
    pdf, probes = vision

    result = run_document(Document(text=sample_cti_text, figure_pdf=pdf), _opts())

    outcome = result.outcome("1f")
    assert outcome.status == "skipped"
    assert outcome.reason.startswith("TLP:AMBER forbids sending the report to anthropic")
    assert probes == []
    assert outcome.details["egress"]["allowed"] is False
    json.dumps(result.stage_report())


def test_under_auto_the_figures_follow_the_text_provider(vision, sample_cti_text, monkeypatch):
    pdf, probes = vision
    monkeypatch.setenv("VISION_PROVIDER", "")
    monkeypatch.setenv("LLM_PROVIDER", "mistral")

    result = run_document(Document(text=sample_cti_text, figure_pdf=pdf, tlp_level="RED"), _opts())

    assert result.outcome("1f").reason.startswith("TLP:RED forbids sending the report to mistral")
    assert probes == []


def test_a_green_report_may_have_its_figures_read_externally(vision, sample_cti_text):
    pdf, probes = vision

    result = run_document(Document(text=sample_cti_text, figure_pdf=pdf, tlp_level="GREEN"), _opts())

    assert result.outcome("1f").status == "ran" and probes == [1]
    record = next(s for s in result.stage_report() if s["stage"] == "1f")
    assert record["egress"]["allowed"] is True


# ── The guard on _call_llm ───────────────────────────────────────────────────

#: (file, enclosing function) of every reference to _call_llm, each behind the decision:
#: Stage 3's functions run only after the orchestrator's (and the consensus provider's)
#: check; Stage 4c's inferer is built only when build_bundle's check allows it.
_GATED_CALL_LLM = {
    ("pipeline/stage3_llm.py", "enrich_chunk"),
    ("pipeline/stage3_llm.py", "_verify_call"),
    ("pipeline/stage3_llm.py", "_ttp_verify_call"),
    ("pipeline/stage3_llm.py", "_select_call"),
    ("pipeline/stage3_llm.py", "enrich_document_relations"),
    ("pipeline/stage4c_long_distance.py", "default_long_distance_inferer"),
}


def test_every_reference_to_call_llm_is_a_known_gated_path():
    """A new way to reach _call_llm sends report text to a provider: it must be gated
    by the egress decision, then added to _GATED_CALL_LLM."""
    root = Path(__file__).resolve().parents[1]
    found: set[tuple[str, str]] = set()

    def walk(node, func, rel):
        for child in ast.iter_child_nodes(node):
            name = child.name if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)) else func
            if ((isinstance(child, ast.Name) and child.id == "_call_llm")
                    or (isinstance(child, ast.Attribute) and child.attr == "_call_llm")
                    or (isinstance(child, ast.alias) and child.name == "_call_llm")):
                found.add((rel, name))
            walk(child, name, rel)

    for folder in ("pipeline", "api"):
        for path in sorted((root / folder).rglob("*.py")):
            walk(ast.parse(path.read_text(encoding="utf-8")), "<module>", path.relative_to(root).as_posix())

    assert found == _GATED_CALL_LLM


# ── Stage 4 and the worker ───────────────────────────────────────────────────

_LONG_DISTANCE = {"completion": {"long_distance": True}}


def _build(tlp_level):
    from models.schemas import EntityType, RawEntity
    from pipeline.orchestrator import build_bundle
    from pipeline.stage3_llm import LLMEnrichmentResult

    return build_bundle(
        [RawEntity(value="185.220.101.45", entity_type=EntityType.IPV4)], LLMEnrichmentResult(),
        report_name="r", report_text="x", original_filename="r.txt", source_hash=None,
        source_bytes=None, policy=_LONG_DISTANCE, tlp_level=tlp_level, pap_level=None)


@pytest.fixture()
def inferer_calls(monkeypatch):
    import pipeline.stage3_llm as s3
    calls: list[dict] = []
    monkeypatch.setattr(s3, "_PROVIDER", "anthropic")
    monkeypatch.setattr("pipeline.stage4c_long_distance.default_long_distance_inferer",
                        lambda policy: calls.append(policy))
    return calls


def test_build_bundle_builds_no_long_distance_inferer_for_an_amber_report(inferer_calls):
    _build("AMBER")
    _build(None)
    assert inferer_calls == []


def test_build_bundle_builds_it_for_a_green_report(inferer_calls):
    _build("GREEN")
    assert inferer_calls == [_LONG_DISTANCE]


@pytest.fixture()
def db(temp_db):
    from api.paths import uploads_dir
    uploads_dir().mkdir(parents=True)
    return temp_db


def _job(db, **cols):
    ts = db.now_iso()
    fields = {"id": "j1", "original_filename": "r.txt", "status": "reviewing", "pipeline_mode": "full",
              "report_text": "APT29 used SUNBURST.", "created_at": ts, "updated_at": ts, **cols}
    with db.get_conn() as conn:
        conn.execute(f"INSERT INTO jobs ({', '.join(fields)}) VALUES ({', '.join('?' for _ in fields)})",
                     tuple(fields.values()))
        conn.execute("INSERT INTO entities (id, job_id, value, entity_type, accepted, source) "
                     "VALUES ('e1', 'j1', 'APT29', 'threat_actor', 1, 'llm')")
        conn.commit()


@pytest.mark.parametrize("tlp,expected", [("AMBER", []), ("TLP:GREEN", [_LONG_DISTANCE])])
def test_a_finalize_passes_the_jobs_marking_to_the_decision(db, monkeypatch, inferer_calls, tlp, expected):
    import api.worker as worker
    from pipeline.stage5_validation import VALIDATED, ValidationResult

    monkeypatch.setattr(worker, "_load_policy", lambda: _LONG_DISTANCE)
    monkeypatch.setattr("pipeline.stage5_validation.validate_bundle",
                        lambda text: ValidationResult(VALIDATED, []))
    _job(db, tlp_level=tlp)

    assert worker.re_run_final_stages("j1", quick=True) is not None
    assert inferer_calls == expected


@pytest.mark.parametrize("job_tlp,stix_tlp", [("PURPLE", None), (None, "PURPLE")])
def test_a_bad_marking_fails_the_job_with_a_readable_message(db, monkeypatch, job_tlp, stix_tlp):
    import api.worker as worker
    from api.paths import uploads_dir

    if stix_tlp:
        monkeypatch.setenv("STIX_TLP", stix_tlp)
    _job(db, status="processing", tlp_level=job_tlp)

    worker._run_pipeline("j1", str(uploads_dir() / "j1.txt"), "r.txt")

    with db.get_conn() as conn:
        assert conn.execute("SELECT status FROM jobs WHERE id='j1'").fetchone()["status"] == "failed"
        data = conn.execute("SELECT data FROM progress_events WHERE job_id='j1' AND event_type='done'"
                            ).fetchone()["data"]
    error = json.loads(data)["error"]
    assert "TLP" in error and "PURPLE" in error and "Traceback" not in error
