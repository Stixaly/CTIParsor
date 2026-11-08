"""pipeline/egress.py — the TLP egress policy (ADR-0097): which providers may
receive a report's content, and the refusal in the stage report.

No network and no LLM: every provider call is a mock that fails if reached.
"""
import json
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
                "LMSTUDIO_BASE_URL"):
        monkeypatch.delenv(var, raising=False)


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
