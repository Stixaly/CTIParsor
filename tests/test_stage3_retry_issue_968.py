"""Issue #968 — which Stage 3 provider errors are retried, and how long to wait.

openai's timeout and connection errors are not builtin ConnectionError or
TimeoutError subclasses, so they were never retried; a 429 or a 5xx was not
either.  The retry now follows _is_retryable, Retry-After is obeyed (capped),
and every new attempt is counted in llm_stats.  No request leaves the process
and no retry sleeps.
"""
from __future__ import annotations

from types import SimpleNamespace

import anthropic
import httpx
import pytest

from pipeline import llm_stats
from pipeline import stage3_llm as s3

openai = pytest.importorskip("openai")   # not in the light CI job (requirements-ci.lock.txt)

_REQUEST = httpx.Request("POST", "http://x")


def _status(code: int, headers: dict | None = None) -> httpx.Response:
    return httpx.Response(code, headers=headers, request=_REQUEST)


@pytest.fixture()
def no_sleep(monkeypatch):
    for fn in (s3._call_anthropic_impl, s3._call_openai_compatible_impl):
        monkeypatch.setattr(fn.retry, "sleep", lambda seconds: None)


@pytest.fixture(autouse=True)
def _forget_the_last_call():
    llm_stats.reset_last_call()


def _delta(before: dict) -> dict:
    return llm_stats.delta(before, llm_stats.snapshot())


def _client(*outcomes):
    """A chat.completions fake: each outcome is raised when it is an exception."""
    calls: list[dict] = []

    def create(**kwargs):
        calls.append(kwargs)
        outcome = outcomes[len(calls) - 1]
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome

    return SimpleNamespace(chat=SimpleNamespace(completions=SimpleNamespace(create=create))), calls


def _choice(content: str):
    message = SimpleNamespace(content=content)
    return SimpleNamespace(choices=[SimpleNamespace(message=message, finish_reason="stop")], usage=None)


def _retry_state(exc: BaseException | None):
    outcome = SimpleNamespace(exception=lambda: exc)
    return SimpleNamespace(outcome=outcome, attempt_number=1)


# ── Which errors are retried ─────────────────────────────────────────────────

def test_an_openai_timeout_is_retried_then_answered(no_sleep):
    client, calls = _client(openai.APITimeoutError(request=_REQUEST), _choice("ok"))
    before = llm_stats.snapshot()

    assert s3._call_openai_compatible(client, "m", "s", "u", "vLLM") == "ok"
    assert len(calls) == 2
    assert _delta(before) == {"provider_calls": 1, "provider_retries": 1}


def test_an_openai_connection_error_is_retried(no_sleep):
    client, calls = _client(openai.APIConnectionError(request=_REQUEST), _choice("ok"))
    assert s3._call_openai_compatible(client, "m", "s", "u", "Ollama") == "ok"
    assert len(calls) == 2


def test_an_openai_rate_limit_is_retried_then_answered(no_sleep):
    error = openai.RateLimitError("slow down", response=_status(429), body=None)
    client, calls = _client(error, _choice("ok"))
    before = llm_stats.snapshot()

    assert s3._call_openai_compatible(client, "m", "s", "u", "Mistral") == "ok"
    assert len(calls) == 2
    assert _delta(before) == {"provider_calls": 1, "provider_retries": 1}


def test_an_openai_server_error_is_retried_then_answered(no_sleep):
    error = openai.InternalServerError("down", response=_status(503), body=None)
    client, calls = _client(error, _choice("ok"))
    before = llm_stats.snapshot()

    assert s3._call_openai_compatible(client, "m", "s", "u", "vLLM") == "ok"
    assert len(calls) == 2
    assert _delta(before) == {"provider_calls": 1, "provider_retries": 1}


def test_an_anthropic_server_error_is_retried_then_answered(monkeypatch, no_sleep):
    error = anthropic.InternalServerError("down", response=_status(529), body=None)
    messages_calls: list[dict] = []
    answer = SimpleNamespace(content=[SimpleNamespace(type="text", text="ok")],
                             usage=SimpleNamespace(output_tokens=1), stop_reason="end_turn")

    def create(**kwargs):
        messages_calls.append(kwargs)
        if len(messages_calls) == 1:
            raise error
        return answer

    monkeypatch.setattr(s3, "_get_anthropic_client", lambda: SimpleNamespace(messages=SimpleNamespace(create=create)))
    before = llm_stats.snapshot()

    assert s3._call_anthropic("s", "u") == "ok"
    assert len(messages_calls) == 2
    assert _delta(before) == {"provider_calls": 1, "provider_retries": 1}


@pytest.mark.parametrize("code", [408, 409, 429, 500, 502, 503, 504])
def test_retried_status_codes(code):
    assert s3._is_retryable(openai.APIStatusError("x", response=_status(code), body=None)) is True
    assert s3._is_retryable(anthropic.APIStatusError("x", response=_status(code), body=None)) is True


@pytest.mark.parametrize("code", [400, 401, 403, 404, 413, 422])
def test_other_client_errors_are_not_retried(code):
    assert s3._is_retryable(openai.APIStatusError("x", response=_status(code), body=None)) is False
    assert s3._is_retryable(anthropic.APIStatusError("x", response=_status(code), body=None)) is False


def test_a_bad_request_is_not_retried(no_sleep):
    error = openai.BadRequestError("bad", response=_status(400), body=None)
    client, calls = _client(error, _choice("never reached"))
    before = llm_stats.snapshot()

    assert s3._call_openai_compatible(client, "m", "s", "u", "vLLM") == ""
    assert len(calls) == 1
    assert _delta(before) == {"provider_calls": 1, "provider_failures": 1}


def test_builtin_connection_and_timeout_errors_are_still_retried():
    assert s3._is_retryable(ConnectionError("reset")) is True
    assert s3._is_retryable(TimeoutError("slow")) is True
    assert s3._is_retryable(ValueError("404 model not found")) is False


# ── How long to wait ────────────────────────────────────────────────────────

def test_retry_after_sets_the_wait():
    error = openai.RateLimitError("slow down", response=_status(429, {"retry-after": "5"}), body=None)
    assert s3._call_openai_compatible_impl.retry.wait(_retry_state(error)) == 5.0


def test_retry_after_is_capped_at_30_seconds():
    error = openai.RateLimitError("slow down", response=_status(429, {"retry-after": "999"}), body=None)
    assert s3._call_openai_compatible_impl.retry.wait(_retry_state(error)) == 30.0


@pytest.mark.parametrize("headers", [{}, {"retry-after": "Wed, 21 Oct 2026 07:28:00 GMT"}, {"retry-after": "-3"}])
def test_without_a_usable_retry_after_the_exponential_wait_is_kept(headers):
    error = openai.RateLimitError("slow down", response=_status(429, headers), body=None)
    state = _retry_state(error)
    assert s3._call_openai_compatible_impl.retry.wait(state) == s3._RETRY_WAIT(state)


def test_an_error_without_a_response_keeps_the_exponential_wait():
    error = openai.InternalServerError("down", response=_status(503), body=None)
    error.response = None
    state = _retry_state(error)
    assert s3._call_openai_compatible_impl.retry.wait(state) == s3._RETRY_WAIT(state)


# ── Counting and stopping ────────────────────────────────────────────────────

def test_repeated_failures_stop_after_max_retries(no_sleep):
    client, calls = _client(*[openai.APITimeoutError(request=_REQUEST) for _ in range(s3._MAX_RETRIES)])
    before = llm_stats.snapshot()

    assert s3._call_openai_compatible(client, "m", "s", "u", "vLLM") == ""
    assert len(calls) == s3._MAX_RETRIES
    assert _delta(before) == {"provider_calls": 1, "provider_failures": 1, "provider_retries": s3._MAX_RETRIES - 1}


def test_the_total_retry_bound_leaves_room_for_a_retry_after_a_timeout():
    """tenacity checks the bound once an attempt has failed: a bound at or below
    LLM_TIMEOUT would forbid a retry after an attempt that timed out."""
    from pipeline import stage3_llm
    assert stage3_llm._RETRY_MAX_DELAY > stage3_llm._LLM_TIMEOUT
