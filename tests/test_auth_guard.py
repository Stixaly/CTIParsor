"""AUTH_MODE and the start guard: authentication off beyond loopback, OIDC without
its settings and a bad value are refused at start (ADR-0097, Network posture)."""
from __future__ import annotations

from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

import run_api
from api.auth import config

_OIDC = {"OIDC_ISSUER_URL": "https://idp.example/realms/cti", "OIDC_CLIENT_ID": "ctiparsor"}


@pytest.mark.parametrize("host", ["127.0.0.1", "127.0.1.1", "localhost", "LOCALHOST", "::1", "[::1]", " 127.0.0.1 "])
def test_authentication_off_on_loopback_starts(monkeypatch, host):
    monkeypatch.setenv("AUTH_MODE", "off")
    config.check_startup(host)


@pytest.mark.parametrize("host", ["0.0.0.0", "::", "192.168.1.10", "10.0.0.5", "cti.example.org", "8.8.8.8"])
def test_authentication_off_beyond_loopback_is_refused_naming_both_settings(monkeypatch, host):
    monkeypatch.setenv("AUTH_MODE", "off")
    with pytest.raises(config.AuthConfigError) as exc:
        config.check_startup(host)
    assert "AUTH_MODE=off" in str(exc.value) and "API_HOST" in str(exc.value)


def test_the_mode_defaults_to_off(monkeypatch):
    monkeypatch.delenv("AUTH_MODE", raising=False)
    assert config.auth_mode() == "off" and not config.enabled()
    monkeypatch.setenv("AUTH_MODE", "  ")
    assert config.auth_mode() == "off"


@pytest.mark.parametrize("host", ["127.0.0.1", "0.0.0.0", "192.168.1.10", "::"])
def test_local_accounts_start_on_any_bind(monkeypatch, host):
    monkeypatch.setenv("AUTH_MODE", "local")
    config.check_startup(host)


@pytest.mark.parametrize("mode", ["Local", "LOCAL", "oidc", "both", "off"])
def test_the_mode_is_case_insensitive(monkeypatch, mode):
    monkeypatch.setenv("AUTH_MODE", mode)
    assert config.auth_mode() == mode.lower()


@pytest.mark.parametrize("value", ["on", "true", "1", "ldap", "none"])
def test_a_value_that_is_not_a_mode_is_refused_not_read_as_off(monkeypatch, value):
    monkeypatch.setenv("AUTH_MODE", value)
    with pytest.raises(config.AuthConfigError, match="AUTH_MODE"):
        config.check_startup("127.0.0.1")


@pytest.mark.parametrize("mode", ["oidc", "both"])
def test_oidc_modes_need_the_oidc_settings(monkeypatch, mode):
    monkeypatch.setenv("AUTH_MODE", mode)
    for name in _OIDC:
        monkeypatch.delenv(name, raising=False)
    with pytest.raises(config.AuthConfigError, match="OIDC_ISSUER_URL"):
        config.check_startup("127.0.0.1")
    monkeypatch.setenv("OIDC_ISSUER_URL", _OIDC["OIDC_ISSUER_URL"])
    with pytest.raises(config.AuthConfigError):                    # the client id is missing
        config.check_startup("127.0.0.1")
    monkeypatch.setenv("OIDC_CLIENT_ID", _OIDC["OIDC_CLIENT_ID"])
    config.check_startup("0.0.0.0")


@pytest.mark.parametrize("value", ["0", "-1", "abc", "inf", "nan"])
def test_a_bad_session_lifetime_is_refused(monkeypatch, value):
    monkeypatch.setenv("AUTH_MODE", "local")
    monkeypatch.setenv("SESSION_TTL_HOURS", value)
    with pytest.raises(config.AuthConfigError, match="SESSION_TTL_HOURS"):
        config.check_startup("127.0.0.1")


def test_the_session_lifetime_defaults_to_twelve_hours(monkeypatch):
    monkeypatch.delenv("SESSION_TTL_HOURS", raising=False)
    assert config.session_ttl_hours() == 12
    monkeypatch.setenv("SESSION_TTL_HOURS", "0.5")
    assert config.session_ttl_hours() == 0.5


# ── The two entry points ─────────────────────────────────────────────────────

def test_run_api_refuses_to_start_with_authentication_off_beyond_loopback(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "postgresql://u@h/d")
    monkeypatch.setenv("API_HOST", "0.0.0.0")
    monkeypatch.setenv("AUTH_MODE", "off")
    with patch("run_api.uvicorn.run") as serve, patch("run_api.load_dotenv"):
        with pytest.raises(SystemExit) as exc:
            run_api.main()
    assert "AUTH_MODE" in str(exc.value) and "API_HOST" in str(exc.value)
    serve.assert_not_called()


@pytest.mark.parametrize(("mode", "host"), [("off", "127.0.0.1"), ("local", "127.0.0.1"), ("local", "0.0.0.0")])
def test_run_api_starts_when_the_mode_allows_the_bind(monkeypatch, capsys, mode, host):
    monkeypatch.setenv("DATABASE_URL", "postgresql://u@h/d")
    monkeypatch.setenv("API_HOST", host)
    monkeypatch.setenv("AUTH_MODE", mode)
    with patch("run_api.uvicorn.run") as serve, patch("run_api.load_dotenv"), \
            patch("run_api.role_banner", return_value=[]):
        assert run_api.main() == 0
    serve.assert_called_once()
    assert f"AUTH_MODE={mode}" in capsys.readouterr().out


def test_the_exposure_warning_depends_on_the_mode(monkeypatch):
    monkeypatch.setenv("AUTH_MODE", "local")
    text = "\n".join(run_api.exposure_warning("0.0.0.0", 8000))
    assert "AUTH_MODE=local" in text and "no authentication" not in text
    monkeypatch.setenv("AUTH_MODE", "off")
    assert "no authentication" in "\n".join(run_api.exposure_warning("0.0.0.0", 8000))


def test_the_app_refuses_to_start_with_authentication_off_beyond_loopback(temp_db, monkeypatch):
    import api.main

    monkeypatch.setenv("API_HOST", "0.0.0.0")
    monkeypatch.setenv("AUTH_MODE", "off")
    with patch("api.main.init_db"), patch("api.queue_loop.start_embedded"):
        with pytest.raises(config.AuthConfigError, match="AUTH_MODE=off"):
            with TestClient(api.main.app):
                pass


def test_the_app_starts_with_local_accounts_on_any_bind(temp_db, monkeypatch, caplog):
    import api.main

    monkeypatch.setenv("API_HOST", "0.0.0.0")
    monkeypatch.setenv("AUTH_MODE", "local")
    with caplog.at_level("INFO"), patch("api.main.init_db"), patch("api.queue_loop.start_embedded"):
        with TestClient(api.main.app) as client:
            assert client.get("/api/health").status_code == 200
    assert "authentication: AUTH_MODE=local" in caplog.text


def test_the_app_says_at_start_that_it_runs_without_authentication(temp_db, caplog):
    import api.main

    with caplog.at_level("WARNING"), patch("api.main.init_db"), patch("api.queue_loop.start_embedded"):
        with TestClient(api.main.app):
            pass
    assert "authentication is OFF" in caplog.text


# ── The published address (Docker) ───────────────────────────────────────────

def test_a_published_loopback_address_lets_the_container_bind_everywhere(monkeypatch):
    monkeypatch.setenv("AUTH_MODE", "off")
    monkeypatch.setenv("API_PUBLISHED_HOST", "127.0.0.1")
    config.check_startup("0.0.0.0")


def test_a_published_address_beyond_loopback_is_refused_naming_cti_bind(monkeypatch):
    monkeypatch.setenv("AUTH_MODE", "off")
    monkeypatch.setenv("API_PUBLISHED_HOST", "0.0.0.0")
    with pytest.raises(config.AuthConfigError, match="CTI_BIND"):
        config.check_startup("0.0.0.0")
    monkeypatch.setenv("AUTH_MODE", "local")
    config.check_startup("0.0.0.0")


def test_without_a_published_address_api_host_decides(monkeypatch):
    monkeypatch.setenv("AUTH_MODE", "off")
    monkeypatch.delenv("API_PUBLISHED_HOST", raising=False)
    with pytest.raises(config.AuthConfigError, match="API_HOST"):
        config.check_startup("0.0.0.0")


def test_the_app_starts_in_a_container_published_on_loopback(temp_db, monkeypatch):
    import api.main

    monkeypatch.setenv("AUTH_MODE", "off")
    monkeypatch.setenv("API_HOST", "0.0.0.0")
    monkeypatch.setenv("API_PUBLISHED_HOST", "127.0.0.1")
    with patch("api.main.init_db"), patch("api.queue_loop.start_embedded"):
        with TestClient(api.main.app) as client:
            assert client.get("/api/health").status_code == 200


def test_run_api_judges_the_published_address(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "postgresql://u@h/d")
    monkeypatch.setenv("API_HOST", "0.0.0.0")
    monkeypatch.setenv("AUTH_MODE", "off")
    monkeypatch.setenv("API_PUBLISHED_HOST", "0.0.0.0")
    with patch("run_api.uvicorn.run") as serve, patch("run_api.load_dotenv"):
        with pytest.raises(SystemExit, match="CTI_BIND"):
            run_api.main()
    serve.assert_not_called()


def test_compose_passes_the_publication_address_with_the_ports_default():
    import re
    from pathlib import Path

    import yaml

    compose = yaml.safe_load((Path(__file__).parent.parent / "compose.yaml").read_text(encoding="utf-8"))
    app = compose["services"]["app"]
    passed = app["environment"]["API_PUBLISHED_HOST"]
    published = next(p for p in app["ports"] if p.endswith(":8000"))
    default = re.match(r"\$\{CTI_BIND:-([^}]+)\}", published).group(1)
    assert passed == "${CTI_BIND:-" + default + "}" and default == "127.0.0.1"
