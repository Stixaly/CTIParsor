"""Stage 4 in full mode does not change (ADR-0090, invariant I1).

Each scenario of tests/fixtures/stage4_reference/scenarios/ is built with the
current Stage 4 and reduced to a canonical form (tests/stage4_reference.py:
build-time stamps and stix2's random ids replaced by stable names).  The
canonical form is frozen in tests/fixtures/stage4_reference/expected/; a
change to the bundle or to the mapping ledger of any scenario fails here and
names the first object that moved.

Regenerate only for a deliberate change of the output:

    UPDATE_STAGE4_REFERENCE=1 pytest tests/test_stage4_reference.py

and commit the new expected files with the change that made them, together
with a `BUNDLE_AFFECTING` entry (pipeline/bundle_revisions.py, CONTRIBUTING.md).
Regenerating to make a red test green, without such a change, defeats the test.
"""
from __future__ import annotations

import contextlib
import difflib
import importlib
import json
import os
import random
import re
import subprocess
import sys
import uuid
import warnings
from datetime import timedelta
from pathlib import Path

import pytest
import stix2

from tests import stage4_reference as ref

UPDATE = os.environ.get("UPDATE_STAGE4_REFERENCE") == "1"
ROOT = Path(__file__).resolve().parent.parent


@contextlib.contextmanager
def _stage4_defaults():
    """The shipped ATT&CK release, no TLP or author override and the benign
    filter on, whatever the developer's shell or `.env` says; the loaders'
    caches forgotten around the block (a track test may have filled them).
    pipeline.stage3_llm is imported first: it loads `.env`, and what it
    injects (STIX_TLP...) must be removed after, not before."""
    importlib.import_module("pipeline.stage3_llm")
    patch = pytest.MonkeyPatch()
    try:
        for key in ref.ENV_PINNED:
            patch.delenv(key, raising=False)
        ref.forget_attack_caches()
        yield
    finally:
        ref.forget_attack_caches()
        patch.undo()


@pytest.fixture()
def stage4_defaults():
    with _stage4_defaults():
        yield


@pytest.fixture(scope="module")
def builds():
    """name -> (bundle JSON, ledger, time before, time after), each built once."""
    with _stage4_defaults():
        yield {name: ref.build(ref.load_scenario(name)) for name in ref.scenario_names()}


@pytest.fixture(scope="module")
def forms(builds):
    """name -> canonical form."""
    return {name: ref.canonical(*raw) for name, raw in builds.items()}


def _raw(builds, name):
    """A build of `name` a test may alter."""
    text, ledger, t0, t1 = builds[name]
    return text, json.loads(json.dumps(ledger)), t0, t1


def _first_difference(expected: dict, actual: dict) -> str:
    """Where `actual` leaves `expected`: the first object that differs (type and
    canonical id) with a short diff, else the first ledger part that differs."""
    def key(o):
        return (o["type"], o["id"])

    def lines(value):
        return json.dumps(value, sort_keys=True, indent=1).splitlines()

    old = {key(o): o for o in expected["objects"]}
    new = {key(o): o for o in actual["objects"]}
    for k in sorted(set(old) | set(new)):
        if old.get(k) == new.get(k):
            continue
        what = "missing from the build" if k not in new else "not in the reference" if k not in old else "differs"
        diff = difflib.unified_diff(lines(old.get(k)), lines(new.get(k)), "reference", "build", lineterm="", n=1)
        return f"first object that moved: {k[0]} {k[1]} ({what})\n" + "\n".join(list(diff)[:40])
    for part in sorted(set(expected["ledger"]) | set(actual["ledger"])):
        if expected["ledger"].get(part) != actual["ledger"].get(part):
            diff = difflib.unified_diff(lines(expected["ledger"].get(part)), lines(actual["ledger"].get(part)),
                                        "reference", "build", lineterm="", n=1)
            return f"objects are identical; ledger[{part!r}] differs\n" + "\n".join(list(diff)[:40])
    return "no difference found"


def _check_against_reference(name: str, actual: dict) -> None:
    """Fails with the first difference, not with pytest's rendering of two 70 KB dicts."""
    expected = json.loads(ref.expected_path(name).read_text(encoding="utf-8"))
    if ref.dump(actual) != ref.dump(expected):
        pytest.fail(f"{name}: Stage 4's output is no longer the reference.\n" + _first_difference(expected, actual),
                    pytrace=False)


@pytest.mark.parametrize("name", ref.scenario_names())
def test_full_mode_output_is_the_reference(forms, name):
    path = ref.expected_path(name)
    if UPDATE:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(ref.dump(forms[name]), encoding="utf-8")
        warnings.warn(f"UPDATE_STAGE4_REFERENCE: rewrote {path}", stacklevel=1)
        return
    assert path.is_file(), f"{path} is missing: UPDATE_STAGE4_REFERENCE=1 writes it"
    _check_against_reference(name, forms[name])


def test_every_scenario_has_a_reference_and_the_other_way_round():
    assert set(ref.scenario_names()) == {p.stem for p in ref.EXPECTED.glob("*.json")}


# ── The scenarios exercise the paths they are named for ──────────────────────

def _of(canon, type_):
    return [o for o in canon["objects"] if o["type"] == type_]


def test_apt_report_covers_the_observables_and_the_edge_decisions(forms):
    c = forms["apt_report"]
    types = {o["type"] for o in c["objects"]}
    assert {"ipv4-addr", "domain-name", "url", "file", "windows-registry-key", "mutex", "email-addr",
            "vulnerability", "campaign", "location", "identity", "attack-pattern", "indicator",
            "threat-actor", "malware", "tool", "course-of-action"} <= types
    assert [o["name"] for o in _of(c, "threat-actor")] == ["APT29"]
    outcomes = {(e["outcome"], e.get("reason")) for e in c["ledger"]["relationships"]}
    assert {("emitted", None), ("merged", None), ("dropped", "self_loop"),
            ("dropped", "unresolved_target"), ("dropped", "observable_to_attack_pattern")} <= outcomes
    origins = {v["origin"] for v in c["ledger"]["objects"].values()}
    assert {"completion_reference", "completion_transitive", "ioc_association", "targeted_location"} <= origins
    assert any(o.get("x_temporal_assertions") for o in _of(c, "relationship"))


def test_apt_report_covers_the_source_the_anchor_and_the_cve_metadata(forms):
    scenario = ref.load_scenario("apt_report")
    c = forms["apt_report"]
    (artifact,) = _of(c, "artifact")
    assert artifact["hashes"] == {"SHA-256": scenario["source_hash"]} and artifact["payload_bin"]
    (report,) = _of(c, "report")
    assert {"source_name": "original_document", "description": "Original CTI report: midnight_frost.pdf",
            "hashes": {"SHA-256": scenario["source_hash"]}} in report["external_references"]
    assert report["x_source_published"] == scenario["document_anchor"]
    assert c["ledger"]["objects"][artifact["id"]]["origin"] == "source_artifact"

    ioc_indicators = [o for o in _of(c, "indicator") if o["pattern_type"] == "stix"]
    assert ioc_indicators and {o["valid_from"] for o in ioc_indicators} == {"2026-02-27T00:00:00Z"}
    bases = [v["valid_from_basis"] for v in c["ledger"]["objects"].values() if v["origin"] == "ioc_indicator"]
    assert bases and set(bases) == {"report_published"}

    (vulnerability,) = _of(c, "vulnerability")
    meta = scenario["cve_metadata"]["CVE-2023-23397"]
    assert vulnerability["description"] == meta["description"]
    assert vulnerability["x_cvss_v3_score"] == meta["cvss_score"]
    assert vulnerability["x_cvss_v3_vector"] == meta["cvss_vector"]


def test_long_distance_scenario_ships_the_edge_the_stub_answered(forms):
    c = forms["long_distance"]
    (edge,) = [o for o in _of(c, "relationship") if o.get("x_inference_rule") == "long-distance"]
    assert edge["relationship_type"] == "related-to" and edge["x_evidence_text"].startswith("Frost Spider staged")
    (report,) = _of(c, "report")
    assert report["x_synthesis_stats"]["completion"]["long_distance_added"] == 1
    assert any(v["origin"] == "completion_long_distance" for v in c["ledger"]["objects"].values())


def test_policy_pin_rewrites_a_verb_and_pins_an_edge(forms):
    c = forms["policy_pin"]
    changes = [ch for e in c["ledger"]["relationships"] for ch in e["changes"]]
    assert any(ch.get("reason") == "policy_pin" for ch in changes)
    assert any(o.get("x_policy_rule") for o in _of(c, "relationship"))
    assert any(r["reason"] == "alias_merge" for r in c["ledger"]["removed"])


def test_embedded_rules_scenario_ships_four_formats_and_drops_one_rule(forms):
    c = forms["embedded_rules"]
    formats = {o["pattern_type"] for o in _of(c, "indicator")}
    assert {"yara", "sigma", "suricata", "snort", "stix"} <= formats
    assert [r["reason"] for r in c["ledger"]["removed"]] == ["rule_does_not_compile"]
    assert any(v["origin"] == "embedded_rule_title" for v in c["ledger"]["objects"].values())


def test_minimal_scenario_is_observables_and_indicators_only(forms):
    c = forms["minimal"]
    assert len(_of(c, "indicator")) == 2 and len(_of(c, "relationship")) == 2
    assert not c["ledger"]["relationships"]


# ── The canonical form itself ────────────────────────────────────────────────

def test_two_builds_of_a_scenario_have_the_same_canonical_form(forms, stage4_defaults):
    assert ref.canonical_build(ref.load_scenario("apt_report")) == forms["apt_report"]


def test_canonical_form_names_only_the_random_ids_and_the_build_time(forms):
    text = json.dumps(forms["apt_report"])
    assert ref.BUILD_TIME in text
    assert "relationship--R1" in text and "report--R1" in text
    for match in re.finditer(r"\b([a-z][a-z0-9-]*)--([0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12})\b", text):
        if match.group(1) in ref.RANDOM_TYPES:
            assert uuid.UUID(match.group(2)).version != 4, match.group(0)
    # the markings are the standard ones, not stand-ins
    for marking in (stix2.TLP_AMBER, stix2.TLP_GREEN, stix2.TLP_RED):
        assert marking.id in json.dumps([forms[n] for n in forms])
    assert "marking-definition--R" not in json.dumps([forms[n] for n in forms])


def _random_ids(text):
    types = "|".join(sorted(ref.RANDOM_TYPES))
    return sorted({m.group(0) for m in re.finditer(
        rf"\b(?:{types})--[0-9a-f]{{8}}-[0-9a-f]{{4}}-4[0-9a-f]{{3}}-[89ab][0-9a-f]{{3}}-[0-9a-f]{{12}}\b", text)})


def test_canonical_form_ignores_object_order_and_the_value_of_random_ids(builds):
    text, ledger, t0, t1 = _raw(builds, "policy_pin")      # has ids only the ledger knows (alias merge)
    before = ref.canonical(text, ledger, t0, t1)

    bundle = json.loads(text)
    random.Random(7).shuffle(bundle["objects"])
    for key in ("entities", "relationships", "removed"):
        random.Random(7).shuffle(ledger[key])
    shuffled = json.dumps(bundle) + "\x00" + json.dumps(ledger)
    renamed = _random_ids(shuffled)
    assert len(renamed) > 10
    for old in renamed:
        shuffled = shuffled.replace(old, f"{old.split('--')[0]}--{uuid.uuid4()}")
    new_bundle, new_ledger = shuffled.split("\x00")
    assert ref.canonical(new_bundle, json.loads(new_ledger), t0, t1) == before


def _changed(builds, scenario, edit):
    """(canonical form as built, canonical form after `edit(bundle, ledger)`)."""
    text, ledger, t0, t1 = _raw(builds, scenario)
    before = ref.canonical(text, ledger, t0, t1)
    bundle = json.loads(text)
    edit(bundle, ledger)
    return before, ref.canonical(json.dumps(bundle), ledger, t0, t1)


def test_canonical_form_sees_a_changed_verb(builds):
    def edit(bundle, ledger):
        next(o for o in bundle["objects"] if o["type"] == "relationship")["relationship_type"] = "mitigates"
    before, after = _changed(builds, "apt_report", edit)
    assert before != after


def test_canonical_form_sees_a_changed_property_value(builds):
    def edit(bundle, ledger):
        next(o for o in bundle["objects"] if o["type"] == "malware")["name"] = "SUNBURST2"
    before, after = _changed(builds, "apt_report", edit)
    assert before != after


def test_canonical_form_sees_a_rewired_reference(builds):
    def edit(bundle, ledger):
        rel = next(o for o in bundle["objects"] if o["type"] == "relationship")
        rel["target_ref"] = "malware--00000000-0000-5000-8000-000000000000"
    before, after = _changed(builds, "apt_report", edit)
    assert before != after


def test_canonical_form_sees_a_changed_ledger_outcome(builds):
    text, ledger, t0, t1 = _raw(builds, "apt_report")
    before = ref.canonical(text, ledger, t0, t1)
    ledger["relationships"][0]["outcome"] = "dropped"
    assert ref.canonical(text, ledger, t0, t1) != before


def test_canonical_form_sees_a_swapped_tlp_marking(builds):
    text, ledger, t0, t1 = _raw(builds, "minimal")          # TLP:RED
    before = ref.canonical(text, ledger, t0, t1)
    assert stix2.TLP_RED.id in text and stix2.TLP_RED.id in json.dumps(ledger)
    swapped = text.replace(stix2.TLP_RED.id, stix2.TLP_GREEN.id)
    swapped_ledger = json.loads(json.dumps(ledger).replace(stix2.TLP_RED.id, stix2.TLP_GREEN.id))
    assert ref.canonical(swapped, swapped_ledger, t0, t1) != before


def test_canonical_form_only_replaces_stamps_near_the_build(builds):
    text, ledger, t0, t1 = _raw(builds, "minimal")
    day = timedelta(days=1)
    assert ref.canonical(text, ledger, t0, t1) != ref.canonical(text, ledger, t0 + day, t1 + day)


def test_random_objects_that_cannot_be_told_apart_are_refused():
    def sro():
        return {"type": "relationship", "id": f"relationship--{uuid.uuid4()}", "relationship_type": "uses",
                "source_ref": "malware--00000000-0000-5000-8000-000000000001",
                "target_ref": "tool--00000000-0000-5000-8000-000000000002"}

    with pytest.raises(AssertionError, match="indistinguishable"):
        ref._label_random_ids([sro(), sro()], {})


# ── Same output whatever the hash seed ───────────────────────────────────────

def test_output_does_not_depend_on_the_hash_seed(tmp_path):
    """A process per seed builds every scenario; both are compared to each
    other and to the frozen references."""
    def run(seed: str) -> dict:
        out = tmp_path / f"seed{seed}.json"
        env = {**os.environ, "PYTHONHASHSEED": seed, "SKIP_HEAVY_MODELS": "1"}
        for key in ref.ENV_PINNED:
            env.pop(key, None)
        done = subprocess.run([sys.executable, "-m", "tests.stage4_reference", str(out)], cwd=ROOT, env=env,
                              capture_output=True, text=True, timeout=600)
        assert done.returncode == 0, done.stderr[-2000:]
        return json.loads(out.read_text(encoding="utf-8"))

    first, second = run("0"), run("1")
    assert set(first) == set(second) == set(ref.scenario_names())
    for name in first:
        if first[name] != second[name]:
            pytest.fail(f"{name}: seeds 0 and 1 differ.\n" + _first_difference(first[name], second[name]),
                        pytrace=False)
        if not UPDATE:
            _check_against_reference(name, first[name])
