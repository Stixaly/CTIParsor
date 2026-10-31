"""The CLI and configuration extractors of scripts/contract.py (ADR-0094 item 1).

main.py's arguments, the stage ids, the container commands of
docker/entrypoint.sh and `make db-upgrade`; the variables of .env.example and
the Compose layout.  Made-up inputs for the parsing, and the real files for
what docs/support-policy.md promises about them.  The real surfaces are
compared with contract/cli.json and contract/config.json by
tests/test_contract.py.
"""
from __future__ import annotations

import argparse
import re

import pytest

from scripts import contract as c

# ── main.py's arguments ──────────────────────────────────────────────────────


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("file", nargs="?")
    group.add_argument("--input-dir")
    parser.add_argument("--policy", default="db", choices=["none", "db"])
    parser.add_argument("--disable-stage", action="append", default=[])
    parser.add_argument("-q", "--quiet", action="store_true")
    return parser


def test_each_argument_but_help_is_an_entry():
    assert c.parser_entries(_parser()) == {
        "main.py file": {"action": "store", "nargs": "?", "required": False, "choices": None, "default": None,
                         "type": None, "const": None,
                         "group": {"members": ["--input-dir", "file"], "required": True}},
        "main.py --input-dir": {"action": "store", "nargs": None, "required": False, "choices": None,
                                "default": None, "type": None, "const": None,
                                "group": {"members": ["--input-dir", "file"], "required": True}},
        "main.py --policy": {"action": "store", "nargs": None, "required": False, "choices": ["db", "none"],
                             "default": "db", "type": None, "const": None, "group": None},
        "main.py --disable-stage": {"action": "append", "nargs": None, "required": False, "choices": None,
                                    "default": [], "type": None, "const": None, "group": None},
        "main.py -q|--quiet": {"action": "store_true", "nargs": 0, "required": False, "choices": None,
                               "default": False, "type": None, "const": True, "group": None},
    }


def test_the_type_and_the_const_of_an_argument():
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--limit", type=int, default=5)
    parser.add_argument("--mode", action="store_const", const="fast")
    parser.add_argument("--when", type=lambda text: text)
    entries = c.parser_entries(parser)
    assert (entries["main.py --limit"]["type"], entries["main.py --limit"]["const"]) == ("int", None)
    assert (entries["main.py --mode"]["type"], entries["main.py --mode"]["const"]) == (None, "fast")
    assert entries["main.py --when"]["type"] == "<lambda>"


@pytest.mark.parametrize(("kwargs", "kind"), [
    ({}, "store"), ({"action": "store_const", "const": 1}, "store_const"), ({"action": "store_true"}, "store_true"),
    ({"action": "store_false"}, "store_false"), ({"action": "append"}, "append"),
    ({"action": "append_const", "const": 1}, "append_const"), ({"action": "count"}, "count"),
    ({"action": "extend", "nargs": "+"}, "extend"), ({"action": argparse.BooleanOptionalAction}, "boolean_optional"),
])
def test_the_action_kind_is_argparse_name(kwargs, kind):
    parser = argparse.ArgumentParser(add_help=False)
    assert c._action_kind(parser.add_argument("--x", **kwargs)) == kind


def test_the_real_cli():
    entries = c.extract_cli()
    group = {"members": ["--input-dir", "file"], "required": True}
    assert entries["main.py file"]["group"] == entries["main.py --input-dir"]["group"] == group
    assert {k for k in entries if k.startswith("main.py ")} == {
        "main.py file", "main.py --input-dir", "main.py --output", "main.py --output-dir",
        "main.py --disable-stage", "main.py --require-stage", "main.py --policy", "main.py --no-llm"}
    assert entries["main.py --policy"]["default"] == "db"
    assert entries["main.py --no-llm"]["const"] is True and entries["main.py --output"]["type"] is None
    from pipeline.orchestrator import STAGES
    assert {k for k in entries if k.startswith("stage ")} == {f"stage {s}" for s in STAGES}
    assert entries["stage 1"] == entries["stage 3r"] == {"can_disable": False}
    assert entries["stage 3"] == {"can_disable": True}
    assert entries["make db-upgrade"] == {}


# ── docker/entrypoint.sh and the Makefile ────────────────────────────────────

def test_the_container_commands_and_bootstrap_options():
    text = (c.ROOT / "docker" / "entrypoint.sh").read_text(encoding="utf-8")
    assert c.entrypoint_entries(text) == {
        "entrypoint serve": {}, "entrypoint worker": {}, "entrypoint bootstrap": {}, "entrypoint cli": {},
        "entrypoint check": {}, "entrypoint bootstrap --no-models": {}, "entrypoint bootstrap --no-corpora": {},
        "entrypoint bootstrap --strict": {}}


_SCRIPT = """bootstrap() {
    while [ $# -gt 0 ]; do
        case "$1" in
            --fast)  fast=true ;;
            *)       exit 2 ;;
        esac
    done
}

cmd="${1:-serve}"
case "$cmd" in
    serve)  exec python run_api.py ;;
    *)      exec "$cmd" "$@" ;;
esac
"""


def test_a_command_or_an_option_removed_is_no_longer_an_entry():
    assert c.entrypoint_entries(_SCRIPT) == {"entrypoint serve": {}, "entrypoint bootstrap --fast": {}}


@pytest.mark.parametrize("text", [
    _SCRIPT.replace('case "$cmd" in', 'case "$command" in'),           # the dispatch is not found
    _SCRIPT.replace("bootstrap() {", "boot() {"),
    _SCRIPT.replace("    serve)  exec python run_api.py ;;\n", ""),   # no command left
])
def test_a_script_the_parser_cannot_read_fails(text):
    with pytest.raises(c.ExtractError):
        c.entrypoint_entries(text)


def test_make_db_upgrade():
    assert c.make_entries("db-upgrade: .secrets/db_password\n\tbash scripts/db_upgrade.sh\n") == {
        "make db-upgrade": {}}
    assert c.make_entries("db-upgrade-later:\n\ttrue\n") == {}


# ── .env.example ─────────────────────────────────────────────────────────────

_ENV = """# CONVENTIONS
#   KEY=value     a setting to review
#   # KEY=value   optional: the value shown is the default used when unset
LLM_PROVIDER=anthropic
GEMINI_API_KEY=
# LLM_SEED=13
# Pass it on the command line:
#   CTI_GIT_REV=$(git rev-parse --short HEAD) docker compose build
# CTI_GIT_REV=
# TTP_MODE=select retrieval (ADR-0072; recall measured on AnnoCTR dev).
# SKIP_HEAVY_MODELS=
TTP_RETRIEVAL_EXCLUDE_CITED=x
# LLM_SEED=7
"""


def test_set_and_shown_variables():
    assert c.env_entries(_ENV) == {
        "env LLM_PROVIDER": {"set": True, "values": ["anthropic"]},
        "env GEMINI_API_KEY": {"set": True, "values": [""]},
        "env LLM_SEED": {"set": False, "values": ["13", "7"]},
        "env CTI_GIT_REV": {"set": False, "values": [""]},
    }


def test_the_real_env_example():
    text = (c.ROOT / ".env.example").read_text(encoding="utf-8")
    entries = c.env_entries(text)
    set_lines = {m.group(1) for m in re.finditer(r"^([A-Z][A-Z0-9_]*)=", text, re.M)}
    assert {f"env {name}" for name in set_lines - c.UNSTABLE_VARIABLES} <= set(entries)
    assert entries["env STIX_TLP"] == {"set": True, "values": ["amber"]}
    assert entries["env CTI_GIT_REV"] == {"set": False, "values": [""]}         # not the build command
    assert entries["env TTP_MODE"] == {"set": False, "values": ["select"]}      # not the section heading
    assert "env KEY" not in entries                                             # not the conventions
    assert "env SKIP_HEAVY_MODELS" not in entries and "env TTP_RETRIEVAL_EXCLUDE_CITED" not in entries


# The commented lines of .env.example that look like a variable but are prose:
# the conventions' example, a command line, a sub-heading.
_ENV_PROSE = frozenset({
    "#   KEY=value     a setting to review",
    "#   CTI_GIT_REV=$(git rev-parse --short HEAD) docker compose build",
    "# TTP_MODE=select retrieval (ADR-0072; recall measured on AnnoCTR dev).",
})


def test_every_commented_variable_is_read_or_named_as_prose():
    """A commented line that looks like a variable is read by env_entries
    (`# NAME=value`: one space, no blank in the value) or is one of the prose
    lines above.  A variable written another way would drop out of the
    contract without a word."""
    lines = (c.ROOT / ".env.example").read_text(encoding="utf-8").splitlines()
    entries = c.env_entries("\n".join(lines))
    missed = []
    for line in lines:
        if not re.match(r"^#\s*[A-Z][A-Z0-9_]*=", line) or line in _ENV_PROSE:
            continue
        shown = c._ENV_SHOWN.match(line)
        name = shown.group(1) if shown else None
        if name is None or (f"env {name}" not in entries and name not in c.UNSTABLE_VARIABLES):
            missed.append(line)
    assert missed == []
    assert _ENV_PROSE <= set(lines)          # a prose line that is gone leaves this list


# ── compose.yaml ─────────────────────────────────────────────────────────────

_COMPOSE = """
name: demo
x-base: &base
  image: app
services:
  app:
    <<: *base
    volumes: [cti-state:/app/state, ./.secrets/db_password:/run/secrets/db_password:ro]
  ollama:
    profiles: [ollama]
    volumes:
      - type: volume
        source: ollama-models
        target: /root/.ollama
  dev:
    <<: *base
    profiles: [dev]
    volumes: [.:/app, cti-state:/app/state, dev-cache:/cache]
volumes:
  cti-state: {}
  ollama-models: {}
  dev-cache: {}
  spare: {name: shared-spare}
"""


def test_services_profiles_and_volumes():
    assert c.compose_entries(_COMPOSE) == {
        "compose project": {"name": "demo"},
        "compose service app": {"profiles": []},
        "compose service ollama": {"profiles": ["ollama"]},
        "compose volume cti-state": {},          # the dev service uses it too: still kept
        "compose volume ollama-models": {},
        "compose volume spare": {"name": "shared-spare"},     # declared, used by no one: kept
    }                                            # dev and dev-cache: the dev profile


def test_a_compose_file_without_a_project_name():
    assert c.compose_entries("services:\n  app: {}\n") == {
        "compose project": {"name": None}, "compose service app": {"profiles": []}}


def test_the_real_compose_layout():
    entries = c.compose_entries((c.ROOT / "compose.yaml").read_text(encoding="utf-8"))
    for service in ("app", "worker", "postgres", "capture-proxy"):
        assert entries[f"compose service {service}"] == {"profiles": []}
    for profile in ("bootstrap", "ollama", "proxy"):
        assert entries[f"compose service {profile}"] == {"profiles": [profile]}
    for volume in ("cti-state", "cti-cache", "pg-data-18"):
        assert f"compose volume {volume}" in entries
    assert "compose service dev" not in entries and "compose service frontend-dev" not in entries
    assert "compose volume frontend-node-modules" not in entries
    assert entries["compose project"] == {"name": "ctiparsor"}
    assert entries["compose volume pg-data-18"] == {}


def test_the_config_surface_is_both():
    entries = c.extract_config()
    assert "env STIX_TLP" in entries and "compose service app" in entries


def test_a_compose_file_without_a_service_fails(monkeypatch):
    monkeypatch.setattr(c, "compose_entries", lambda text: {"compose project": {"name": "ctiparsor"}})
    with pytest.raises(c.ExtractError, match="no service"):
        c.extract_config()
