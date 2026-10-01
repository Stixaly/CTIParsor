"""Stage 3 — the provider plumbing and the paths test_stage3.py does not reach:
client construction, provider diagnostics, the Anthropic and OpenAI-compatible
calls with their retries, dispatch, JSON repair of a truncated answer, and the
branches of enrich_chunk / enrich_all_chunks / enrich_document_relations.

No request leaves the process: clients are fakes, retries do not sleep.
"""
from __future__ import annotations

import json
import logging
from types import SimpleNamespace

import anthropic
import httpx
import pytest

from models.schemas import EntityType, RawEntity
from pipeline import llm_stats
from pipeline import stage3_llm as s3

_REQUEST = httpx.Request("POST", "https://api.example.test/v1")


def _timeout() -> anthropic.APITimeoutError:
    return anthropic.APITimeoutError(request=_REQUEST)


def _auth_error() -> anthropic.AuthenticationError:
    return anthropic.AuthenticationError("invalid x-api-key", response=httpx.Response(401, request=_REQUEST),
                                         body=None)


@pytest.fixture()
def no_sleep(monkeypatch):
    """Tenacity waits 2-10 s between attempts; nothing here should."""
    for fn in (s3._call_anthropic_impl, s3._call_openai_compatible_impl):
        monkeypatch.setattr(fn.retry, "sleep", lambda seconds: None)


def _delta(before: dict) -> dict:
    return llm_stats.delta(before, llm_stats.snapshot())


# ── Clients ──────────────────────────────────────────────────────────────────

class _FakeOpenAI:
    made: list[dict] = []

    def __init__(self, api_key, base_url):
        self.api_key, self.base_url = api_key, base_url
        _FakeOpenAI.made.append({"api_key": api_key, "base_url": base_url})


@pytest.fixture()
def openai_sdk(monkeypatch):
    _FakeOpenAI.made = []
    monkeypatch.setattr(s3, "_OPENAI_SDK_AVAILABLE", True)
    monkeypatch.setattr(s3, "_OpenAIClient", _FakeOpenAI)
    for name in ("_mistral_client", "_ollama_client", "_gemini_client", "_lmstudio_client", "_vllm_client",
                 "_anthropic_client"):
        monkeypatch.setattr(s3, name, None)
    return _FakeOpenAI


@pytest.mark.parametrize("getter,env,base_url", [
    (s3._get_mistral_client, {"MISTRAL_API_KEY": " mk "}, "https://api.mistral.ai/v1"),
    (s3._get_gemini_client, {"GEMINI_API_KEY": "gk"}, "https://generativelanguage.googleapis.com/v1beta/openai/"),
    (s3._get_ollama_client, {"OLLAMA_BASE_URL": "http://gpu:11434/"}, "http://gpu:11434/v1"),
    (s3._get_lmstudio_client, {"LMSTUDIO_BASE_URL": "http://box:1234"}, "http://box:1234/v1"),
    (s3._get_vllm_client, {"VLLM_BASE_URL": "http://vllm:8000/"}, "http://vllm:8000/v1"),
])
def test_openai_compatible_clients_are_built_once(openai_sdk, monkeypatch, getter, env, base_url):
    for key, value in env.items():
        monkeypatch.setenv(key, value)

    first = getter()

    assert first is getter()                                   # cached, not rebuilt
    assert openai_sdk.made == [{"api_key": first.api_key, "base_url": base_url}]
    if "MISTRAL_API_KEY" in env:
        assert first.api_key == "mk"                          # stripped


@pytest.mark.parametrize("getter,key", [(s3._get_mistral_client, "MISTRAL_API_KEY"),
                                        (s3._get_gemini_client, "GEMINI_API_KEY")])
def test_a_hosted_client_needs_its_key(openai_sdk, monkeypatch, getter, key):
    monkeypatch.delenv(key, raising=False)
    assert getter() is None and openai_sdk.made == []


@pytest.mark.parametrize("getter", [s3._get_mistral_client, s3._get_gemini_client, s3._get_ollama_client,
                                    s3._get_lmstudio_client, s3._get_vllm_client])
def test_without_the_openai_sdk_there_is_no_client(openai_sdk, monkeypatch, getter):
    monkeypatch.setenv("MISTRAL_API_KEY", "k")
    monkeypatch.setenv("GEMINI_API_KEY", "k")
    monkeypatch.setattr(s3, "_OPENAI_SDK_AVAILABLE", False)
    assert getter() is None


def test_the_anthropic_client_needs_a_key_and_is_cached(openai_sdk, monkeypatch):
    built = []
    monkeypatch.setattr(s3.anthropic, "Anthropic", lambda api_key: built.append(api_key) or object())

    monkeypatch.setenv("ANTHROPIC_API_KEY", "  ")
    assert s3._get_anthropic_client() is None

    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant")
    client = s3._get_anthropic_client()
    assert client is s3._get_anthropic_client() and built == ["sk-ant"]


# ── Provider diagnostics ─────────────────────────────────────────────────────

@pytest.mark.parametrize("provider,sdk,env,level,message", [
    ("anthropic", True, {}, logging.WARNING, "ANTHROPIC_API_KEY not set"),
    ("gemini", False, {}, logging.WARNING, "requires the 'openai' package"),
    ("gemini", True, {}, logging.WARNING, "GEMINI_API_KEY not set"),
    ("gemini", True, {"GEMINI_API_KEY": "k", "GEMINI_MODEL": "gemini-x"}, logging.INFO, "model: gemini-x"),
    ("mistral", False, {}, logging.WARNING, "requires the 'openai' package"),
    ("mistral", True, {}, logging.WARNING, "MISTRAL_API_KEY not set"),
    ("mistral", True, {"MISTRAL_API_KEY": "k"}, logging.INFO, "model: mistral-small-latest"),
    ("ollama", False, {}, logging.WARNING, "requires the 'openai' package"),
    ("ollama", True, {"OLLAMA_MODEL": "qwen3"}, logging.INFO, "model: qwen3"),
    ("lmstudio", False, {}, logging.WARNING, "requires the 'openai' package"),
    ("lmstudio", True, {}, logging.INFO, "endpoint: http://localhost:1234"),
    ("vllm", False, {}, logging.WARNING, "requires the 'openai' package"),
    ("vllm", True, {"VLLM_ENABLE_THINKING": "true"}, logging.INFO, "thinking: on"),
    ("gpt", True, {}, logging.WARNING, "Unknown LLM_PROVIDER='gpt'"),
])
def test_diagnostics_say_what_is_missing(monkeypatch, caplog, provider, sdk, env, level, message):
    for key in ("ANTHROPIC_API_KEY", "GEMINI_API_KEY", "MISTRAL_API_KEY", "VLLM_ENABLE_THINKING"):
        monkeypatch.delenv(key, raising=False)
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    monkeypatch.setattr(s3, "_PROVIDER", provider)
    monkeypatch.setattr(s3, "_OPENAI_SDK_AVAILABLE", sdk)

    with caplog.at_level(logging.INFO, logger="pipeline.stage3_llm"):
        s3._get_provider_diagnostics()

    assert [(r.levelno, message in r.getMessage()) for r in caplog.records] == [(level, True)]


def test_the_anthropic_key_silences_the_anthropic_warning(monkeypatch, caplog):
    monkeypatch.setattr(s3, "_PROVIDER", "anthropic")
    with caplog.at_level(logging.INFO, logger="pipeline.stage3_llm"):
        s3._get_provider_diagnostics()
    assert caplog.records == []


# ── Anthropic calls ──────────────────────────────────────────────────────────

class _Messages:
    def __init__(self, *outcomes):
        self.outcomes = list(outcomes)
        self.calls: list[dict] = []

    def create(self, **kwargs):
        self.calls.append(kwargs)
        outcome = self.outcomes.pop(0)
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome


def _anthropic(monkeypatch, *outcomes) -> _Messages:
    messages = _Messages(*outcomes)
    monkeypatch.setattr(s3, "_get_anthropic_client", lambda: SimpleNamespace(messages=messages))
    return messages


def _answer(*texts: str):
    return SimpleNamespace(content=[SimpleNamespace(type="text", text=t) for t in texts],
                           usage=SimpleNamespace(output_tokens=7))


def test_an_anthropic_answer_is_joined_and_the_system_prompt_cached(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_MODEL", "claude-test")
    messages = _anthropic(monkeypatch, _answer(' {"a": ', '1} '))

    assert s3._call_anthropic_impl("SYSTEM", "USER") == '{"a": 1}'
    call = messages.calls[0]
    assert call["model"] == "claude-test" and call["messages"] == [{"role": "user", "content": "USER"}]
    assert call["system"] == [{"type": "text", "text": "SYSTEM", "cache_control": {"type": "ephemeral"}}]


def test_an_empty_anthropic_content_list_is_an_empty_answer(monkeypatch):
    _anthropic(monkeypatch, SimpleNamespace(content=[], usage=None))
    assert s3._call_anthropic_impl("s", "u") == ""


def test_no_anthropic_client_means_no_call(monkeypatch):
    monkeypatch.setattr(s3, "_get_anthropic_client", lambda: None)
    assert s3._call_anthropic_impl("s", "u") == ""


def test_a_transient_anthropic_error_is_retried_then_succeeds(monkeypatch, no_sleep):
    messages = _anthropic(monkeypatch, _timeout(), anthropic.APIConnectionError(request=_REQUEST), _answer("ok"))
    before = llm_stats.snapshot()

    assert s3._call_anthropic("s", "u") == "ok"
    assert len(messages.calls) == 3
    assert _delta(before) == {"provider_calls": 1}


def test_anthropic_timeouts_on_every_attempt_are_one_recorded_failure(monkeypatch, no_sleep, caplog):
    messages = _anthropic(monkeypatch, *[_timeout() for _ in range(s3._MAX_RETRIES)])
    before = llm_stats.snapshot()

    assert s3._call_anthropic("s", "u") == ""
    assert len(messages.calls) == s3._MAX_RETRIES
    assert _delta(before) == {"provider_calls": 1, "provider_failures": 1}
    assert llm_stats.last_call_failed() is True
    assert "raise LLM_TIMEOUT" in caplog.text


@pytest.mark.parametrize("error,logged", [
    (_auth_error(), "Invalid Anthropic API key"),
    (ValueError("404 model not found"), "Anthropic (0.0s): 404 model not found"),
])
def test_a_permanent_anthropic_error_is_not_retried(monkeypatch, no_sleep, caplog, error, logged):
    messages = _anthropic(monkeypatch, error)
    before = llm_stats.snapshot()

    assert s3._call_anthropic("s", "u") == ""
    assert len(messages.calls) == 1
    assert _delta(before) == {"provider_calls": 1, "provider_failures": 1}
    assert logged in caplog.text


def test_a_retry_error_is_reported_as_retries_exhausted(monkeypatch):
    from tenacity import RetryError

    def exhausted(system, user):
        raise RetryError(last_attempt=None)                    # type: ignore[arg-type]

    monkeypatch.setattr(s3, "_call_anthropic_impl", exhausted)
    before = llm_stats.snapshot()
    assert s3._call_anthropic("s", "u") == ""
    assert "failed after 3 retries" in llm_stats.snapshot()["last_error"]
    assert _delta(before) == {"provider_calls": 1, "provider_failures": 1}


# ── OpenAI-compatible calls ──────────────────────────────────────────────────

class _Completions:
    def __init__(self, *outcomes):
        self.outcomes = list(outcomes)
        self.calls: list[dict] = []

    def create(self, **kwargs):
        self.calls.append(kwargs)
        outcome = self.outcomes.pop(0)
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome


def _client(*outcomes):
    completions = _Completions(*outcomes)
    return SimpleNamespace(chat=SimpleNamespace(completions=completions)), completions


def _choice(content):
    return SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(content=content))],
                           usage=SimpleNamespace(completion_tokens=3))


def test_an_openai_compatible_answer_is_stripped(monkeypatch):
    client, completions = _client(_choice("  {}  "))
    assert s3._call_openai_compatible(client, "m", "SYS", "USR", "Mistral", sampling={"temperature": 0}) == "{}"
    call = completions.calls[0]
    assert call["messages"] == [{"role": "system", "content": "SYS"}, {"role": "user", "content": "USR"}]
    assert call["temperature"] == 0 and call["extra_body"] is None


@pytest.mark.parametrize("response", [SimpleNamespace(choices=[], usage=None), _choice(None)])
def test_no_choices_or_null_content_is_an_empty_answer(response):
    client, _ = _client(response)
    assert s3._call_openai_compatible(client, "m", "s", "u", "Gemini") == ""


def test_no_client_is_an_empty_answer():
    assert s3._call_openai_compatible_impl(None, "m", "s", "u", "Ollama") == ""


def test_an_openai_compatible_connection_error_is_retried(no_sleep):
    client, completions = _client(ConnectionError("reset"), _choice("ok"))
    assert s3._call_openai_compatible(client, "m", "s", "u", "Ollama") == "ok"
    assert len(completions.calls) == 2


@pytest.mark.parametrize("error,logged", [
    (RuntimeError("Request timed out."), "Ollama timed out after"),
    (RuntimeError("Error code: 404 - model not found"), "Ollama ("),
])
def test_an_openai_compatible_failure_is_recorded(no_sleep, caplog, error, logged):
    client, completions = _client(error)
    before = llm_stats.snapshot()

    assert s3._call_openai_compatible(client, "m", "s", "u", "Ollama") == ""
    assert len(completions.calls) == 1
    assert _delta(before) == {"provider_calls": 1, "provider_failures": 1}
    assert logged in caplog.text


def test_openai_compatible_retries_exhausted(monkeypatch):
    from tenacity import RetryError

    def exhausted(*a, **kw):
        raise RetryError(last_attempt=None)                    # type: ignore[arg-type]

    monkeypatch.setattr(s3, "_call_openai_compatible_impl", exhausted)
    assert s3._call_openai_compatible(object(), "m", "s", "u", "vLLM") == ""
    assert llm_stats.snapshot()["last_error"].startswith("vLLM failed after 3 retries")


# ── Dispatch ─────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("provider,getter,model_env,model,label", [
    ("gemini", "_get_gemini_client", "GEMINI_MODEL", "gemini-2.5-pro", "Gemini"),
    ("mistral", "_get_mistral_client", "MISTRAL_MODEL", "mistral-small-latest", "Mistral"),
    ("ollama", "_get_ollama_client", "OLLAMA_MODEL", "llama3.2", "Ollama"),
    ("lmstudio", "_get_lmstudio_client", "LMSTUDIO_MODEL", "lmstudio-model", "LMStudio"),
])
def test_each_provider_is_called_with_its_model_and_a_sanitised_prompt(monkeypatch, provider, getter,
                                                                       model_env, model, label):
    monkeypatch.delenv(model_env, raising=False)
    monkeypatch.delenv("LLM_SEED", raising=False)
    monkeypatch.setenv("LLM_TEMPERATURE", "0")
    client = object()
    seen = []
    monkeypatch.setattr(s3, getter, lambda: client)
    monkeypatch.setattr(s3, "_call_openai_compatible",
                        lambda c, m, sys, usr, lbl, sampling: seen.append((c, m, usr, lbl, sampling)) or "{}")

    assert s3._call_llm("SYS", "Report\x00 <b>text</b>", provider=provider.upper()) == "{}"
    assert seen == [(client, model, "Report text", label, {"temperature": 0.0})]


def test_an_unknown_provider_returns_nothing(monkeypatch):
    monkeypatch.setattr(s3, "_call_anthropic", lambda *a: pytest.fail("no call"))
    assert s3._call_llm("s", "u", provider="gpt-9") == ""
    assert s3._provider_ready("gpt-9") is False


# ── JSON repair ──────────────────────────────────────────────────────────────

_TRUNCATED = (
    '{"threat_actors": ["APT29"], "malware_families": ["SUNBURST"], "relationships": ['
    '{"source_value": "APT29", "relationship_type": "uses", "target_value": "SUNBURST", '
    '"evidence_text": "APT29 used \\"SUNBURST\\" against',
)


def test_a_response_cut_mid_string_is_closed_and_parsed():
    result = s3._parse_llm_response("".join(_TRUNCATED))
    assert result is not None
    assert result.threat_actors == ["APT29"] and result.malware_families == ["SUNBURST"]
    assert [r.target_value for r in result.relationships] == ["SUNBURST"]


@pytest.mark.parametrize("tail", [
    ', "confidence": 0.',                    # dangling number
    ', "confid',                             # dangling key
    ', {"source_value": "APT29", "relat',    # dangling object
    ',',                                     # dangling comma
])
def test_dangling_fragments_are_dropped_before_closing(tail):
    text = '{"tools": ["Mimikatz"], "ttps": [{"technique_name": "Phishing", "mitre_id": "T1566"}' + tail
    result = s3._parse_llm_response(text)
    assert result is not None and result.tools == ["Mimikatz"]
    assert [t.mitre_id for t in result.ttps] == ["T1566"]


@pytest.mark.parametrize("prefix", ["", "```json\n", "Here is the extraction:\n"])
def test_a_complete_nested_object_is_not_taken_for_a_truncated_answer(prefix):
    """Regression: the first *decodable* "{" was the answer, so a response cut
    after one complete TTP came back as that TTP's dict — an empty result that
    lost the whole chunk."""
    text = (prefix + '{"tools": ["Mimikatz"], "campaign_name": "SolarWinds", "ttps": ['
            '{"technique_name": "Phishing", "mitre_id": "T1566"}, {"technique_name": "Val')

    result = s3._parse_llm_response(text)

    assert result is not None and result.tools == ["Mimikatz"]
    assert result.campaign_name == "SolarWinds"                   # repaired, not only salvaged
    assert [t.mitre_id for t in result.ttps] == ["T1566"]


def test_prose_braces_before_the_answer_are_still_skipped():
    text = 'Fields {as requested}: {"threat_actors": ["APT29"]}'
    assert s3._parse_llm_response(text).threat_actors == ["APT29"]


def test_a_truncated_bare_list_is_not_an_answer():
    assert s3._parse_llm_response('["APT29", "FIN') is None


def test_nothing_to_close_is_no_repair():
    assert s3._try_complete_truncated_json('{"a": [1, 2]} trailing') is None


def test_complete_items_are_salvaged_when_the_object_cannot_be_closed():
    """A missing comma defeats the repair; the complete list items survive."""
    text = ('{"threat_actors": ["APT29", "FIN7"] "tools": ["Mimikatz", {"name": "Cobalt Strike"}, "Ps'
            'Exec"], "ttps": [{"technique_name": "Phishing"}, {"technique_name": "Inc')

    result = s3._parse_llm_response(text)

    assert result is not None
    assert result.threat_actors == ["APT29", "FIN7"]
    assert result.tools == ["Mimikatz", "Cobalt Strike", "PsExec"]
    assert [t.technique_name for t in result.ttps] == ["Phishing"]


def test_array_items_keep_escaped_quotes_and_nested_structures():
    text = '["a \\"quoted\\" b", {"k": [1, {"x": "}"}]}, [2, 3], "cut'
    assert s3._extract_complete_array_items(text, 1) == [
        '"a \\"quoted\\" b"', '{"k": [1, {"x": "}"}]}', "[2, 3]"]
    assert s3._extract_complete_array_items('["a", "b"], "next": 1', 1) == ['"a"', '"b"']


def test_unsalvageable_items_are_skipped():
    assert s3._try_extract_complete_items('{"tools": [{"bad": tru}, ') is None


def test_a_payload_that_fails_the_schema_after_normalisation_is_none(caplog):
    assert s3._parse_llm_response('{"threat_actors": "APT29", "campaign_name": ["x"]}') is None
    assert "schema validation failed" in caplog.text


def test_normalisation_takes_evidence_and_label_aliases_and_drops_junk():
    out = s3._normalize_llm_json({
        "ttps": ["T1566", {"technique": "Phishing", "technique_id": "T1566", "quote": "sent lures",
                           "evidence_grade": "observed"}],
        "relationships": ["junk", {"source": "APT29", "relation": "uses", "target": "X",
                                   "evidence_label": "CONFIRMED"}],
    })
    assert out["ttps"] == [{"technique_name": "Phishing", "mitre_id": "T1566", "evidence_text": "sent lures",
                            "evidence_label": "observed"}]
    (rel,) = out["relationships"]
    assert (rel["source_value"], rel["relationship_type"], rel["target_value"], rel["evidence_label"]) == (
        "APT29", "uses", "X", "reported")


# ── enrich_chunk branches ────────────────────────────────────────────────────

_TEXT = ("APT29 deployed SUNBURST against SolarWinds customers and contacted 185.220.101.45 "
         "over HTTPS. The actor used spearphishing (T1566.001) for initial access.")

_ANSWER = json.dumps({
    "threat_actors": ["APT29"], "malware_families": ["SUNBURST"],
    "ttps": [{"technique_name": "Spearphishing Attachment", "mitre_id": "T1566.001",
              "evidence_text": "The actor used spearphishing (T1566.001) for initial access."}],
    "relationships": [{"source_value": "APT29", "relationship_type": "uses", "target_value": "SUNBURST",
                       "evidence_text": "APT29 deployed SUNBURST against SolarWinds customers"}],
})


def _llm(monkeypatch, *answers):
    calls: list[tuple[str, str, str | None]] = []
    replies = list(answers)

    def call(system, user, provider=None, max_prompt_length=None):
        calls.append((system, user, provider))
        reply = replies.pop(0) if replies else ""
        return reply() if callable(reply) else reply

    monkeypatch.setattr(s3, "_call_llm", call)
    return calls


def test_the_prompt_summarises_iocs_named_entities_and_semantic_ttps(monkeypatch):
    calls = _llm(monkeypatch, _ANSWER)
    iocs = [RawEntity(value=f"10.0.0.{i}", entity_type=EntityType.IPV4) for i in range(33)]
    iocs.append(RawEntity(value="APT29", entity_type=EntityType.THREAT_ACTOR))    # not an IoC
    gazetteer = [RawEntity(value="Phishing", entity_type=EntityType.TECHNIQUE, mitre_id="T1566",
                           source="gazetteer")]
    cyner = [RawEntity(value="SUNBURST", entity_type=EntityType.MALWARE, confidence=0.931, source="cyner"),
             RawEntity(value="phishing", entity_type=EntityType.TECHNIQUE, source="cyner")]
    semantic = [RawEntity(value="Spearphishing Attachment", entity_type=EntityType.TECHNIQUE,
                          mitre_id="T1566.001", confidence=0.7, source="semantic"),
                RawEntity(value="no id", entity_type=EntityType.TECHNIQUE, source="semantic")]

    s3.enrich_chunk(_TEXT, iocs, gazetteer_entities=gazetteer, cyner_entities=cyner,
                    semantic_ttp_entities=semantic, doc_context="  APT29 → SUNBURST  ",
                    verify_rels=False, verify_ttps_on=False)

    prompt = calls[0][1]
    assert "... and 3 more IoCs" in prompt and "[threat_actor] APT29\n" not in prompt.split("Named")[0][:0]
    assert "- [technique] Phishing (T1566)" in prompt
    assert "- [malware] SUNBURST [CyNER conf=0.93]" in prompt
    assert "- [technique] phishing" not in prompt                  # CyNER duplicate of a gazetteer hit
    assert "Spearphishing Attachment (T1566.001) — conf=0.70" in prompt and "no id" not in prompt
    assert "APT29 → SUNBURST" in prompt


def test_an_oversized_prompt_is_truncated(monkeypatch):
    calls = _llm(monkeypatch, _ANSWER)
    monkeypatch.setattr(s3, "_MAX_PROMPT_LENGTH", 400)
    s3.enrich_chunk(_TEXT, [], verify_rels=False, verify_ttps_on=False)
    assert len(calls[0][1]) == 400


def test_a_prompt_below_the_minimum_is_not_sent(monkeypatch):
    calls = _llm(monkeypatch, _ANSWER)
    monkeypatch.setattr(s3, "_MIN_PROMPT_LENGTH", 10 ** 9)
    assert s3.enrich_chunk(_TEXT, []) == s3.LLMEnrichmentResult() and calls == []


def test_a_failed_request_and_an_empty_answer_are_counted_apart(monkeypatch):
    def failed():
        s3._record_call("HTTP 500")
        return ""

    _llm(monkeypatch, failed, "")
    before = llm_stats.snapshot()

    assert s3.enrich_chunk(_TEXT, []) == s3.LLMEnrichmentResult()
    assert s3.enrich_chunk(_TEXT, []) == s3.LLMEnrichmentResult()

    counts = _delta(before)
    assert counts["extraction_provider_failed"] == 1 and counts["extraction_empty"] == 1


def test_an_oversized_answer_is_cut_to_the_response_limit(monkeypatch):
    _llm(monkeypatch, _ANSWER + " " * 50)
    monkeypatch.setattr(s3, "_MAX_RESPONSE_LENGTH", len(_ANSWER))
    result = s3.enrich_chunk(_TEXT, [], verify_rels=False, verify_ttps_on=False)
    assert result.threat_actors == ["APT29"]


def test_relationship_and_ttp_verification_run_on_the_same_provider(monkeypatch):
    calls = _llm(monkeypatch, _ANSWER, "verify-rel", "verify-ttp")
    seen: dict = {}

    def verify_relationships(text, result, call, enabled, **kw):
        seen["rel"] = call("S3d", "U3d")
        return result

    def verify_ttps(text, result, call, corroborated, enabled, **kw):
        seen["ttp"] = call("S3f", "U3f")
        seen["corroborated"] = corroborated
        return result

    monkeypatch.setattr("pipeline.stage3d_verify.verify_relationships", verify_relationships)
    monkeypatch.setattr("pipeline.stage3f_ttp_verify.verify_ttps", verify_ttps)
    semantic = [RawEntity(value="x", entity_type=EntityType.TECHNIQUE, mitre_id="t1566.001", confidence=0.99)]

    result = s3.enrich_chunk(_TEXT, [], semantic_ttp_entities=semantic, provider="anthropic",
                             verify_rels=True, verify_ttps_on=True)

    assert result.relationships and seen["rel"] == "verify-rel" and seen["ttp"] == "verify-ttp"
    assert seen["corroborated"] == {"T1566.001"}
    assert [c[2] for c in calls] == ["anthropic"] * 3


def test_the_corroboration_floor_falls_back_when_stage2c_cannot_say(monkeypatch):
    import sys

    monkeypatch.setitem(sys.modules, "pipeline.stage2c_ttp_semantic", None)
    entities = [RawEntity(value="a", entity_type=EntityType.TECHNIQUE, mitre_id="T1", confidence=0.63),
                RawEntity(value="b", entity_type=EntityType.TECHNIQUE, mitre_id="T2", confidence=0.61),
                RawEntity(value="c", entity_type=EntityType.TECHNIQUE, confidence=0.99)]
    assert s3.corroborated_ttp_ids(entities) == {"T1"}


def test_a_relationship_without_dates_is_left_as_is(monkeypatch):
    dated = s3.RelationshipExtracted(source_value="APT29", relationship_type="uses", target_value="SUNBURST",
                                     times=[{"role": "within", "time_text": "in 2020"}])
    plain = s3.RelationshipExtracted(source_value="APT29", relationship_type="targets", target_value="Orion")
    result = s3.check_relationship_times(s3.LLMEnrichmentResult(relationships=[dated, plain]),
                                         "APT29 used SUNBURST in 2020.", None)
    assert result.relationships[1] == plain and result.relationships[0].times[0].status


# ── enrich_all_chunks with the document-level pass ──────────────────────────

def test_the_document_pass_gets_every_known_entity_once(monkeypatch):
    monkeypatch.setenv("ENABLE_DOCUMENT_LEVEL_RELATIONS", "true")
    _llm(monkeypatch, json.dumps({"threat_actors": ["APT29", "Dukes"], "tools": ["Mimikatz"]}),
         json.dumps({"malware_families": ["SUNBURST"]}))
    monkeypatch.setattr("pipeline.stage3b_validate.validate_llm_result", lambda result, text, **kw: result)
    captured = {}

    def doc_pass(full_text, known, document_time=None):
        captured["text"], captured["known"] = full_text, [(e.value, e.entity_type) for e in known]
        return s3.LLMEnrichmentResult(relationships=[s3.RelationshipExtracted(
            source_value="APT29", relationship_type="uses", target_value="SUNBURST")])

    monkeypatch.setattr(s3, "enrich_document_relations", doc_pass)
    gazetteer = [RawEntity(value="APT29", entity_type=EntityType.THREAT_ACTOR, source="gazetteer")]
    cyner = [RawEntity(value="SUNBURST", entity_type=EntityType.MALWARE, source="cyner")]
    per_chunk = [[RawEntity(value="185.220.101.45", entity_type=EntityType.IPV4)],
                 [RawEntity(value="185.220.101.45", entity_type=EntityType.IPV4)]]

    merged = s3.enrich_all_chunks([_TEXT, _TEXT + " Part two."], per_chunk,
                                  gazetteer_entities=gazetteer, cyner_entities=cyner)

    assert captured["text"] == f"{_TEXT}\n\n{_TEXT} Part two."
    assert captured["known"] == [
        ("APT29", EntityType.THREAT_ACTOR), ("SUNBURST", EntityType.MALWARE),
        ("185.220.101.45", EntityType.IPV4), ("Dukes", EntityType.THREAT_ACTOR), ("Mimikatz", EntityType.TOOL)]
    assert [(r.source_value, r.target_value) for r in merged.relationships] == [("APT29", "SUNBURST")]
    assert "APT29" not in merged.threat_actors                     # the gazetteer already has it


# ── enrich_document_relations branches ───────────────────────────────────────

_ENTITIES = [RawEntity(value="APT29", entity_type=EntityType.THREAT_ACTOR),
             RawEntity(value="SUNBURST", entity_type=EntityType.MALWARE)]


def test_the_document_pass_cuts_an_oversized_answer_and_verifies(monkeypatch):
    answer = json.dumps({"relationships": [{"source_value": "APT29", "relationship_type": "uses",
                                            "target_value": "SUNBURST",
                                            "evidence_text": "APT29 deployed SUNBURST against SolarWinds customers"}]})
    calls = _llm(monkeypatch, answer + "\n" * 40, "verified")
    monkeypatch.setattr(s3, "_MAX_RESPONSE_LENGTH", len(answer))
    monkeypatch.setattr("pipeline.stage3d_verify.verify_enabled", lambda: True)
    seen = []

    def verify_relationships(text, result, call, **kw):
        seen.append((text, call("S", "U")))
        return result

    monkeypatch.setattr("pipeline.stage3d_verify.verify_relationships", verify_relationships)

    result = s3.enrich_document_relations(_TEXT, _ENTITIES, provider="anthropic")

    assert [r.target_value for r in result.relationships] == ["SUNBURST"]
    assert seen == [(_TEXT, "verified")] and [c[2] for c in calls] == ["anthropic", "anthropic"]
