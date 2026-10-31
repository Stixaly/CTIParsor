"""The stable contract is recorded, and the code still matches it (ADR-0094 item 1).

contract/*.json holds what docs/support-policy.md promises: the operations of
the OpenAPI schema with their parameters, bodies and responses; main.py's
arguments, the stage ids, the container commands and `make db-upgrade`; the
variables of .env.example and the Compose layout; the STIX custom properties
and the ids of deterministic objects.  `python scripts/contract.py check`
fails on any difference; this file runs it in the fast-tests job.  After a
deliberate change, `make contract` records it (`ACCEPT_BREAKING=1` for a
breaking one, which needs a major version and a CHANGELOG entry).
"""
from __future__ import annotations

import copy
import os
import subprocess
import sys
from pathlib import Path

import pytest

from scripts import contract as c

ROOT = Path(__file__).resolve().parent.parent


def test_the_code_matches_the_recorded_contract():
    """The command CI's reviewers and `make contract` users run, as they run it."""
    done = subprocess.run([sys.executable, "scripts/contract.py", "check"], cwd=ROOT, env=dict(os.environ),
                          capture_output=True, text=True, timeout=900)
    assert done.returncode == 0, done.stdout[-6000:] + done.stderr[-3000:]


@pytest.mark.parametrize("surface", c.SURFACES)
def test_a_recorded_file_is_as_write_leaves_it(surface):
    """No hand edit: each file is the canonical dump of its own entries."""
    entries = c.load_reference(surface)
    assert entries, f"contract/{surface}.json is missing or empty: run `make contract`"
    assert c.reference_path(surface).read_text(encoding="utf-8") == c.dump(surface, entries)


@pytest.mark.parametrize(("surface", "key"), [
    ("openapi", "POST /api/baselines/inspect response:200.sha256"),    # a response field
    ("openapi", "GET /api/jobs/{} param:path:0"),                        # a parameter
    ("cli", "main.py --input-dir"),                                      # a CLI argument
    ("cli", "entrypoint bootstrap --strict"),                            # a container command's option
    ("config", "env STIX_TLP"),                                          # an environment variable
    ("config", "compose volume pg-data-18"),
    ("config", "compose project"),                                       # the project's name
    ("stix", "property vulnerability x_cvss_v3_score"),                  # a STIX custom property
])
def test_a_deliberate_removal_is_breaking(surface, key):
    recorded = c.load_reference(surface)
    assert recorded is not None and key in recorded
    current = copy.deepcopy(recorded)
    del current[key]
    diffs = c.diff_entries(surface, recorded, current, c.RULES[surface])
    assert [(d.severity, d.key, d.what) for d in diffs] == [("breaking", key, "removed")]


def test_a_renamed_field_a_changed_type_and_a_field_made_required_are_breaking():
    recorded = c.load_reference("openapi")
    assert recorded is not None
    current = copy.deepcopy(recorded)
    current["POST /api/baselines/inspect response:200.sha_256"] = current.pop(
        "POST /api/baselines/inspect response:200.sha256")
    current["POST /api/baselines/inspect response:200.bundle_id"]["types"] = ["null", "string"]
    current["POST /api/ingest/text body.tlp_level"]["required"] = True
    diffs = c.diff_entries("openapi", recorded, current, c.RULES["openapi"])
    assert sorted((d.severity, d.key) for d in diffs) == [
        ("breaking", "POST /api/baselines/inspect response:200.bundle_id"),
        ("breaking", "POST /api/baselines/inspect response:200.sha256"),
        ("breaking", "POST /api/ingest/text body.tlp_level"),
        ("compatible", "POST /api/baselines/inspect response:200.sha_256"),
    ]


def test_write_refuses_a_removal_from_the_real_contract(tmp_path, monkeypatch):
    recorded = {surface: c.load_reference(surface) for surface in c.SURFACES}
    contract_dir = tmp_path / "contract"
    contract_dir.mkdir()
    for surface in c.SURFACES:
        (contract_dir / f"{surface}.json").write_bytes(c.reference_path(surface).read_bytes())
    current = copy.deepcopy(recorded)
    del current["cli"]["main.py --no-llm"]
    monkeypatch.setattr(c, "CONTRACT_DIR", contract_dir)
    monkeypatch.setattr(c, "EXTRACTORS", {surface: (lambda s=surface: current[s]) for surface in c.SURFACES})
    before = {p.name: p.read_bytes() for p in contract_dir.iterdir()}
    assert c.main(["write"]) == 1
    assert {p.name: p.read_bytes() for p in contract_dir.iterdir()} == before
