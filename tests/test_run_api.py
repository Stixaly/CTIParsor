from __future__ import annotations

import pytest

import run_api


def test_host_defaults_to_loopback(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("API_HOST", raising=False)
    assert run_api._resolve_host() == "127.0.0.1"


def test_host_blank_falls_back_to_loopback(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("API_HOST", "   ")
    assert run_api._resolve_host() == "127.0.0.1"


def test_host_is_stripped(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("API_HOST", " 0.0.0.0 ")
    assert run_api._resolve_host() == "0.0.0.0"


def test_port_defaults_to_8000(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("API_PORT", raising=False)
    assert run_api._resolve_port() == 8000


def test_port_is_parsed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("API_PORT", "9001")
    assert run_api._resolve_port() == 9001


@pytest.mark.parametrize("value", ["abc", "0", "65536", "-1"])
def test_invalid_port_aborts(monkeypatch: pytest.MonkeyPatch, value: str) -> None:
    monkeypatch.setenv("API_PORT", value)
    with pytest.raises(SystemExit):
        run_api._resolve_port()


def test_workers_default_is_one(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("API_WORKERS", raising=False)
    assert run_api._resolve_workers() == 1


@pytest.mark.parametrize("value", ["0", "abc"])
def test_invalid_workers_aborts(monkeypatch: pytest.MonkeyPatch, value: str) -> None:
    monkeypatch.setenv("API_WORKERS", value)
    with pytest.raises(SystemExit):
        run_api._resolve_workers()


@pytest.mark.parametrize(
    "host",
    ["127.0.0.1", "localhost", "LOCALHOST", "::1", "127.0.1.1", " 127.0.0.1 "],
)
def test_loopback_is_not_exposed(host: str) -> None:
    assert run_api.is_exposed(host) is False


@pytest.mark.parametrize("host", ["0.0.0.0", "::", "192.168.1.10", "10.0.0.5"])
def test_wildcard_and_lan_are_exposed(host: str) -> None:
    assert run_api.is_exposed(host) is True


def test_no_warning_when_loopback() -> None:
    assert run_api.exposure_warning("127.0.0.1", 8000) == []


def test_warning_names_host_port_and_missing_auth() -> None:
    lines = run_api.exposure_warning("0.0.0.0", 8000)
    assert lines
    text = "\n".join(lines)
    assert "0.0.0.0:8000" in text
    assert "no authentication" in text


def test_worker_warning_silent_for_one() -> None:
    assert run_api._worker_warning(1) == []
    assert run_api._worker_warning(0) == []


def test_worker_warning_mentions_the_multiplier() -> None:
    text = "\n".join(run_api._worker_warning(4))
    assert "WORKER_MAX_CONCURRENT" in text
    assert "4" in text
