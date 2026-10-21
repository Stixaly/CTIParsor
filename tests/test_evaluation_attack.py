"""The evaluation against a chosen ATT&CK release (evaluation/attack.py and
__main__.py, ADR-0087): the bundle that maps the gold, the diff between two
releases, and the split of two runs' differences into taxonomy and system
effects.  Mini-bundles and a fake installation in tmp_path: no ATT&CK download,
no AnnoCTR, no model."""
import hashlib
import json
import os
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from evaluation import __main__ as ev
from evaluation import annoctr, attack
from pipeline import attack_data

# ── A fake installation: two ATT&CK releases ────────────────────────────────

# 19.2 -> 20.0.  T1002 is renamed, T1003 gets a sub-technique, T1004 is revoked
# (by the new T1099), T1005 has another description, T1006 more procedures,
# T1007 another tactic, a sub-technique of T1008 is deprecated; T1001 is untouched.
_OLD = {"T1001": {}, "T1002": {"name": "Old name"}, "T1003": {}, "T1003.002": {}, "T1004": {},
        "T1005": {"description": "before"}, "T1006": {}, "T1007": {}, "T1008": {},
        "T1008.001": {}, "T1008.002": {}}
_NEW = {"T1001": {}, "T1002": {"name": "New name"}, "T1003": {}, "T1003.001": {}, "T1003.002": {},
        "T1004": {"flags": {"revoked": True}}, "T1005": {"description": "after"}, "T1006": {},
        "T1007": {"tactics": ["discovery", "collection"]}, "T1008": {},
        "T1008.001": {"flags": {"x_mitre_deprecated": True}}, "T1008.002": {}, "T1099": {}}
_OLD_INDEX = ["T1001", "T1002", "T1003", "T1003.002", "T1004", "T1005", "T1006", "T1007",
              "T1008", "T1008.001", "T1008.002"]
_NEW_INDEX = ["T1001", "T1002", "T1003", "T1003.001", "T1003.002", "T1005", "T1006", "T1007",
              "T1008", "T1008.002", "T1099"]


def _bundle(path, version, techniques, procedures=None, revoked_by=(), source="mitre-attack", indent=None):
    """techniques: id -> {name, description, tactics, flags}; procedures: id -> number
    of `uses` relationships with a description; revoked_by: (old id, new id) pairs."""
    stix = {tid: f"attack-pattern--{n}" for n, tid in enumerate(techniques)}
    objects = [{"type": "x-mitre-collection", "id": "x-mitre-collection--0", "x_mitre_version": version,
                "modified": "2026-01-01"}]
    for tid, t in techniques.items():
        objects.append({"type": "attack-pattern", "id": stix[tid], "name": t.get("name", tid),
                        "description": t.get("description", "text"), "modified": "2026-01-01",
                        "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": ph}
                                              for ph in t.get("tactics", ["discovery"])],
                        "external_references": [{"source_name": source, "external_id": tid}],
                        **t.get("flags", {})})
    for tid, n in (procedures or {}).items():
        objects += [{"type": "relationship", "id": f"relationship--{tid}-{i}", "relationship_type": "uses",
                     "source_ref": "intrusion-set--0", "target_ref": stix[tid], "description": f"procedure {i}"}
                    for i in range(n)]
    objects += [{"type": "relationship", "relationship_type": "revoked-by",
                 "source_ref": stix[old], "target_ref": stix[new]} for old, new in revoked_by]
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"type": "bundle", "objects": objects}, indent=indent), encoding="utf-8")
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _track(directory, manifest, index):
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "attack_manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    (directory / "mitre_index.json").write_text(
        json.dumps({"techniques": [{"id": i} for i in index]}), encoding="utf-8")


@pytest.fixture()
def world(tmp_path, monkeypatch):
    """data/ with the attack-stix-data bundles of 19.2 and 20.0 and the mitre/cti copy
    of 19.2 (same content, other bytes); a default track 19.2 and a track 20.0 under
    pipeline/data/; the evaluation pointed at both."""
    data, pipeline_data = tmp_path / "data", tmp_path / "pipeline" / "data"
    sha = {}
    for version, techniques, procedures, revoked_by in (
            ("19.2", _OLD, {"T1006": 1}, ()),
            ("20.0", _NEW, {"T1006": 2, "T1099": 1}, [("T1004", "T1099")])):
        folder = data / "attack-stix" / f"v{version}"
        sha[version] = _bundle(folder / "enterprise-attack.json", version, techniques, procedures, revoked_by)
        _bundle(folder / "mobile-attack.json", version, {"T1409": {}})
        ics = {"T0807": {} if version == "19.2" else {"flags": {"x_mitre_deprecated": True}}}
        _bundle(folder / "ics-attack.json", version, ics, source="mitre-ics-attack")
    sha["cti"] = _bundle(data / "enterprise-attack.json", "19.2", _OLD, {"T1006": 1}, indent=1)
    assert sha["cti"] != sha["19.2"]
    _track(pipeline_data, {"release": "19.2", "track": "default", "sources": [
        {"domain": "enterprise-attack", "sha256": sha["cti"],
         "equivalent_release_asset": {"sha256": sha["19.2"], "collection_version": "19.2"}},
        {"domain": "mobile-attack", "sha256": None}]}, _OLD_INDEX)
    _track(pipeline_data / "attack" / "20.0", {"release": "20.0", "track": "release", "sources": [
        {"domain": "enterprise-attack", "sha256": sha["20.0"]}]}, _NEW_INDEX)

    monkeypatch.delenv("ATTACK_RELEASE", raising=False)
    monkeypatch.setattr(attack_data, "DATA_DIR", pipeline_data)
    monkeypatch.setattr(attack_data, "TRACKS_DIR", pipeline_data / "attack")
    monkeypatch.setattr(ev, "DATA", data)
    monkeypatch.setattr(ev, "OUT", data / "eval")
    attack_data.reset()
    yield SimpleNamespace(data=data, out=data / "eval", sha=sha)
    attack_data.reset()


# ── Catalogue.for_release ────────────────────────────────────────────────────

def test_for_release_finds_the_bundle_by_its_hash(world, monkeypatch):
    default = attack.Catalogue.for_release(data_dir=world.data)
    assert default.bundle_sha256 == world.sha["cti"]                       # the mitre/cti copy
    assert default.summary()["release"] == "19.2"
    assert default.pipeline_ids == set(_OLD_INDEX)
    for spelling in ("", "19.2", "v19.2"):
        assert attack.Catalogue.for_release(spelling, data_dir=world.data).bundle_sha256 == world.sha["cti"]

    new = attack.Catalogue.for_release("20.0", data_dir=world.data)
    assert new.bundle_sha256 == world.sha["20.0"] and new.summary()["release"] == "20.0"
    assert new.pipeline_ids == set(_NEW_INDEX)
    assert new.resolve("T1004").canonical == "T1099"          # revoked in 20.0 only
    assert default.resolve("T1004").canonical == "T1004"

    attack_data.reset()                                                    # a process keeps its first release
    monkeypatch.setenv("ATTACK_RELEASE", "20.0")                           # None = what the process selected
    assert attack.Catalogue.for_release(data_dir=world.data).summary()["release"] == "20.0"
    with pytest.raises(attack_data.UnknownAttackRelease):
        attack.Catalogue.for_release("21.0", data_dir=world.data)


def test_a_replaced_default_bundle_never_maps_the_gold_in_its_place(world):
    # `scripts/download_attack.py` once fetched the newest bundle into this name.
    _bundle(world.data / "enterprise-attack.json", "20.0", _NEW)
    cat = attack.Catalogue.for_release(data_dir=world.data)
    assert cat.bundle_sha256 == world.sha["19.2"]                          # the release asset instead
    assert cat.resolve("T1004").canonical == "T1004"

    asset = world.data / "attack-stix" / "v19.2" / "enterprise-attack.json"
    asset.write_text(asset.read_text(encoding="utf-8") + "\n ", encoding="utf-8")
    with pytest.raises(FileNotFoundError, match=r"download_attack\.py --release 19\.2"):
        attack.Catalogue.for_release(data_dir=world.data)


def test_a_track_bundle_with_the_wrong_hash_is_refused(world):
    asset = world.data / "attack-stix" / "v20.0" / "enterprise-attack.json"
    asset.write_text(asset.read_text(encoding="utf-8") + "\n ", encoding="utf-8")
    with pytest.raises(FileNotFoundError, match=r"download_attack\.py --release 20\.0"):
        attack.Catalogue.for_release("20.0", data_dir=world.data)
    asset.unlink()
    with pytest.raises(FileNotFoundError, match="is missing"):
        attack.Catalogue.for_release("20.0", data_dir=world.data)


def test_a_release_names_a_directory_and_nothing_else():
    assert attack.release_version("v19.2") == "19.2"
    for bad in ("../x", "19.2/..", "latest", ""):
        with pytest.raises(ValueError):
            attack.release_dir(bad)


# ── release_diff, release_change ─────────────────────────────────────────────

def _diff(world):
    return attack.release_diff(attack.release_dir("19.2", world.data), attack.release_dir("20.0", world.data))


def test_release_diff_lists_what_changed_technique_by_technique(world):
    diff = _diff(world)
    e = diff["enterprise-attack"]

    assert e["active"] == {"old": 11, "new": 11}               # T1004 and T1008.001 out, T1003.001 and T1099 in
    assert e["new_ids"] == ["T1003.001", "T1099"] and e["new_active"] == ["T1003.001", "T1099"]
    assert e["no_longer_active"] == {
        "T1004": {"status": "revoked", "revoked_by": "T1099", "name": "T1004"},
        "T1008.001": {"status": "deprecated", "revoked_by": None, "name": "T1008.001"}}
    assert e["renamed"] == {"T1002": ["Old name", "New name"]}
    assert e["description_changed"] == ["T1005"]
    assert e["tactics_changed"] == {"T1007": [["discovery"], ["collection", "discovery"]]}
    assert e["procedures"] == {"old": 1, "new": 3, "techniques_with_more": 2, "techniques_with_fewer": 0}
    assert e["more_procedures"] == ["T1006", "T1099"]
    assert e["new_revoked_by"] == {"T1004": "T1099"}
    assert e["new_active_names"] == {"T1003.001": "T1003.001", "T1099": "T1099"}
    assert e["tactics"]["same"] is True
    assert e["collections"] == {"old": [["19.2", "2026-01-01"]], "new": [["20.0", "2026-01-01"]]}

    assert diff["mobile-attack"]["new_active"] == [] and diff["mobile-attack"]["no_longer_active"] == {}
    assert list(diff["ics-attack"]["no_longer_active"]) == ["T0807"]       # another domain, its own source name
    json.dumps(diff)


def test_release_change_gives_each_parent_the_first_reason_that_applies(world):
    why = attack.release_change(_diff(world))

    assert why("T1099") == "new_technique"
    assert why("T1003") == why("T1003.002") == "new_subtechnique"          # a new sub-technique, parent active in both
    assert why("T1004") == "status_changed" and why("T1008") == "status_changed"   # revoked; a deprecated sub
    assert [why(t) for t in ("T1002", "T1005", "T1006", "T1007")] == ["content_changed"] * 4
    assert why("T1001") == why("t1001.004") == "unchanged"
    assert why("T0807") == "status_changed"                                 # any domain
    assert why("T1409") == "unchanged"


def test_a_parent_revoked_with_a_new_sub_technique_is_a_status_change():
    diff = {"d": {"new_active": ["T2000.001"], "no_longer_active": {"T2000": {}}, "renamed": {},
                  "description_changed": [], "tactics_changed": {}, "more_procedures": []}}
    assert attack.release_change(diff)("T2000") == "status_changed"


# ── Fake runs ────────────────────────────────────────────────────────────────

def _annoctr_docs(gold):
    return [annoctr.AnnoctrDoc(doc_id, "dev", "vendor", "2021-01-01", f"text of {doc_id}",
                               frozenset({"general", "cyber"}),
                               techniques=[annoctr.Mention(label=t, surface=t, kind=k) for t, k in ids])
            for doc_id, ids in gold.items()]


# AnnoCTR's ids are those of 2022: T1004 was revoked since.
_GOLD = {"d1": [("T1001", "explicit"), ("T1002", "explicit"), ("T1004", "implicit")],
         "d2": [("T1003.002", "explicit"), ("T1005", "explicit")],
         "d3": [("T1008.002", "explicit"), ("T1006", "explicit"), ("T1007", "explicit")],
         "d4": [("T1001", "explicit")]}

_EMOTET = {"type": "malware", "value": "Emotet", "source": "gazetteer", "confidence": 0.9, "mitre_id": "S0367"}
_FOO = {"type": "malware", "value": "Foo", "source": "llm", "confidence": None, "mitre_id": None}
_APT99 = {"type": "threat_actor", "value": "APT99", "source": "gazetteer", "confidence": 0.9, "mitre_id": "G9999"}

# doc -> (technique ids, candidates, entities).  Run A is the 19.2 pipeline, B the 20.0 one.
_RUN_A = {"d1": (["T1001", "T1004"], ["T1001", "T1002"], [_EMOTET, _FOO]),
          "d2": (["T1005"], ["T1005"], [_EMOTET]),
          "d3": (["T1007", "T1008.002"], ["T1007", "T1008.002"], []),
          "d4": (["T1001"], ["T1001"], [])}
_RUN_B = {"d1": (["T1001", "T1002", "T1099"], ["T1001", "T1002"], [_EMOTET]),
          "d2": (["T1003.001", "T1005"], ["T1003.001", "T1005"], [_EMOTET, _APT99]),
          "d3": (["T1006", "T1099"], ["T1006", "T1099"], []),
          "d4": ([], ["T1001"], [])}


def _write_run(world, name, release, records, with_source=True, modified=()):
    """A run as `cmd_run` writes it; `release` None = from before the manifest recorded one;
    `modified`: the files its attack block says no longer matched their manifest."""
    manifest = {"llm": {"model": "fake"}}
    if release:
        manifest["attack"] = {"release": release, "modified_files": list(modified)}
    run = world.out / "runs" / name
    (run / "docs").mkdir(parents=True)
    (run / "run.json").write_text(json.dumps({
        "name": name, "split": "dev", "disabled": ["1f", "4", "5"], "required": ["3"], "consensus": False,
        "document_relations": False, "ttp_mode": "select", "manifest": manifest}), encoding="utf-8")
    for doc_id, (ttp_ids, candidates, entities) in records.items():
        entities = [e if with_source else {k: v for k, v in e.items() if k != "source"} for e in entities]
        (run / "docs" / f"{doc_id}.json").write_text(json.dumps({
            "doc_id": doc_id, "seconds": 1.0, "stages": [], "ttp_ids": ttp_ids, "ttps": [], "ttp_review": [],
            "ttp_candidates": candidates, "entities": entities, "relations": [], "rel_review": [],
            "bundle_relations": None}), encoding="utf-8")


@pytest.fixture()
def runs(world, monkeypatch):
    monkeypatch.setattr(annoctr, "load", lambda *a, **k: _annoctr_docs(_GOLD))
    _write_run(world, "run-a", "19.2", _RUN_A)
    _write_run(world, "run-b", "20.0", _RUN_B)
    return world


def _cli(monkeypatch, *argv):
    monkeypatch.setattr(ev, "load_dotenv", lambda *a, **k: False)         # never the developer's .env
    monkeypatch.setattr(sys, "argv", ["evaluation", *argv])
    ev.main()


def _read(path):
    return json.loads(path.read_text(encoding="utf-8"))


def test_a_run_ran_on_the_release_its_manifest_names_else_on_the_default(world):
    assert ev.run_release({"manifest": {"attack": {"release": "20.0"}}}) == "20.0"
    assert ev.run_release({"manifest": {"llm": {}}}) == "19.2"
    assert ev.run_release({}) == "19.2"


# ── score, compare, ttp-errors, prepare ──────────────────────────────────────

def test_score_maps_the_gold_with_the_runs_release_unless_told_otherwise(runs, monkeypatch):
    _cli(monkeypatch, "score", "--name", "run-b")
    own = _read(runs.out / "runs" / "run-b" / "score.json")
    assert own["attack_mapping"]["release"] == "20.0"
    assert own["attack_mapping"]["bundle_sha256"] == runs.sha["20.0"][:16]
    assert own["ttp"]["technique_micro"]["tp"] == 6 and own["ttp"]["technique_micro"]["fp"] == 1

    _cli(monkeypatch, "score", "--name", "run-b", "--attack-release", "19.2")
    other = _read(runs.out / "runs" / "run-b" / "score-attack-19.2.json")
    assert other["attack_mapping"]["release"] == "19.2"
    # T1099 and T1003.001 do not exist for a 19.2 gold: out of scope, not false positives.
    assert {k: other["ttp"]["technique_micro"][k] for k in ("tp", "fp", "fn")} == {"tp": 4, "fp": 0, "fn": 5}
    assert _read(runs.out / "runs" / "run-b" / "score.json") == own        # the run's own score is not touched

    _cli(monkeypatch, "score", "--name", "run-a")
    assert _read(runs.out / "runs" / "run-a" / "score.json")["attack_mapping"]["release"] == "19.2"


def test_an_old_run_without_an_attack_block_is_scored_on_the_default_track(world, monkeypatch):
    monkeypatch.setattr(annoctr, "load", lambda *a, **k: _annoctr_docs(_GOLD))
    _write_run(world, "old-run", None, _RUN_A)
    _cli(monkeypatch, "score", "--name", "old-run")
    assert _read(world.out / "runs" / "old-run" / "score.json")["attack_mapping"]["release"] == "19.2"


def test_the_llm_health_counts_answers_stopped_at_the_output_ceiling(world, monkeypatch):
    monkeypatch.setattr(annoctr, "load", lambda *a, **k: _annoctr_docs(_GOLD))
    _write_run(world, "ceiling-run", "19.2", _RUN_A)
    doc = world.out / "runs" / "ceiling-run" / "docs" / "d1.json"
    record = _read(doc)
    record["stages"] = [
        {"stage": "3", "status": "ran", "counts": {"provider_calls": 4, "provider_at_ceiling": 2}},
        {"stage": "3f", "status": "ran", "counts": {"ok": 1, "truncated": 1, "at_ceiling": 2}}]
    doc.write_text(json.dumps(record), encoding="utf-8")

    _cli(monkeypatch, "score", "--name", "ceiling-run")
    health = _read(world.out / "runs" / "ceiling-run" / "score.json")["llm_health"]
    assert {k: health[k] for k in ("provider_at_ceiling", "3f_at_ceiling", "3f_truncated")} == {
        "provider_at_ceiling": 2, "3f_at_ceiling": 2, "3f_truncated": 1}


def test_ttp_errors_follow_the_same_rule_as_score(runs, monkeypatch):
    _cli(monkeypatch, "ttp-errors", "--name", "run-a")
    assert _read(runs.out / "runs" / "run-a" / "ttp-errors.json")["attack_mapping"]["release"] == "19.2"
    _cli(monkeypatch, "ttp-errors", "--name", "run-a", "--attack-release", "v20.0")
    other = _read(runs.out / "runs" / "run-a" / "ttp-errors-attack-20.0.json")
    assert other["attack_mapping"]["release"] == "20.0"


def test_compare_refuses_runs_of_two_releases_unless_the_gold_mapping_is_named(runs, monkeypatch):
    with pytest.raises(SystemExit) as exc:
        _cli(monkeypatch, "compare", "--a", "run-a", "--b", "run-b", "--resamples", "20")
    assert "run-a ran on ATT&CK 19.2 and run-b on 20.0" in str(exc.value) and "--attack-release" in str(exc.value)
    assert not (runs.out / "compare").exists()

    _cli(monkeypatch, "compare", "--a", "run-a", "--b", "run-b", "--resamples", "20", "--attack-release", "20.0")
    out = _read(runs.out / "compare" / "run-a__vs__run-b__ttp__attack-20.0.json")
    assert out["attack_mapping"]["release"] == "20.0" and out["documents"] == 4
    assert out["results"]["f1"]["observed_diff"] == -0.05                  # 0.80 -> 0.75


def test_compare_of_two_runs_on_one_release_needs_no_option(runs, monkeypatch):
    _write_run(runs, "run-a2", "19.2", _RUN_A)
    _cli(monkeypatch, "compare", "--a", "run-a", "--b", "run-a2", "--resamples", "20")
    out = _read(runs.out / "compare" / "run-a__vs__run-a2__ttp.json")
    assert out["attack_mapping"]["release"] == "19.2" and out["results"]["f1"]["observed_diff"] == 0


def test_prepare_writes_one_mapping_per_release(world, monkeypatch):
    monkeypatch.setattr(annoctr, "load", lambda *a, **k: _annoctr_docs(_GOLD))
    _cli(monkeypatch, "prepare")
    default = _read(world.out / "attack-mapping.json")
    assert default["catalogue"]["release"] == "19.2"
    assert {r["gold_id"]: r["canonical"] for r in default["rows"]}["T1004"] == "T1004"

    monkeypatch.setenv("ATTACK_RELEASE", "20.0")                           # prepare ignores it unless asked
    _cli(monkeypatch, "prepare")
    assert _read(world.out / "attack-mapping.json") == default

    _cli(monkeypatch, "prepare", "--attack-release", "20.0")
    other = _read(world.out / "attack-mapping-20.0.json")
    assert other["catalogue"]["release"] == "20.0"
    assert {r["gold_id"]: r["canonical"] for r in other["rows"]}["T1004"] == "T1099"


def test_attack_diff_writes_the_diff_of_two_releases(world, monkeypatch, capsys):
    _cli(monkeypatch, "attack-diff", "--old", "19.2", "--new", "v20.0")
    assert _read(world.out / "attack-diff-19.2-20.0.json") == json.loads(json.dumps(_diff(world)))
    printed = capsys.readouterr().out
    assert "enterprise-attack" in printed and "T1099" in printed


# ── release-effect ───────────────────────────────────────────────────────────

def _effect(monkeypatch, *extra):
    _cli(monkeypatch, "release-effect", "--a", "run-a", "--b", "run-b", "--old", "19.2", "--new", "20.0", *extra)


def test_release_effect_splits_the_differences_by_what_the_release_changed(runs, monkeypatch, capsys):
    _effect(monkeypatch, "--attack-release", "20.0")
    r = _read(runs.out / "compare" / "run-a__vs__run-b__release-effect.json")

    # Parent level, gold mapped with 20.0 (T1004 is T1099 there):
    #   d1  A {T1001 T1099}        B {T1001 T1002 T1099}   gold {T1001 T1002 T1099}
    #   d2  A {T1005}              B {T1003 T1005}         gold {T1003 T1005}
    #   d3  A {T1007 T1008}        B {T1006 T1099}         gold {T1006 T1007 T1008}
    #   d4  A {T1001}              B {}                    gold {T1001}
    assert r["attack_mapping"]["release"] == "20.0" and r["documents"] == 4
    assert r["releases"] == {"a": "19.2", "b": "20.0", "old": "19.2", "new": "20.0"}
    assert r["f1_micro"] == {"a": 0.8, "b": 0.75}                          # tp 6 fp 0 fn 3 / tp 6 fp 1 fn 3
    assert r["delta_total"] == {"tp": 0, "fp": 1, "fn": 0}

    c = r["classes"]
    assert {k: (v["ids"], v["n_ids"], v["n_differences"], v["delta_tp"], v["delta_fp"], v["delta_fn"])
            for k, v in c.items()} == {
        "new_technique": (["T1099"], 1, 1, 0, 1, 0),                       # d3: B only, not gold
        "new_subtechnique": (["T1003"], 1, 1, 1, 0, -1),                   # d2: B only, gold
        "status_changed": (["T1008"], 1, 1, -1, 0, 1),                     # d3: A only, gold
        "content_changed": (["T1002", "T1006", "T1007"], 3, 3, 1, 0, -1),  # +T1002 +T1006 -T1007
        "unchanged": (["T1001"], 1, 1, -1, 0, 1)}                          # d4: A only, gold
    assert sum(v["delta_tp"] for v in c.values()) == r["delta_total"]["tp"]
    assert sum(v["delta_fp"] for v in c.values()) == r["delta_total"]["fp"]
    assert sum(v["delta_fn"] for v in c.values()) == r["delta_total"]["fn"]
    # A with only that class taken from B:
    assert {k: v["f1_hybrid"] for k, v in c.items()} == {
        "new_technique": 0.75, "new_subtechnique": 0.875, "status_changed": 0.7143,
        "content_changed": 0.875, "unchanged": 0.7143}

    # The source is recorded, so the gazetteer's own entities are compared (d1's differ only by an LLM name).
    assert r["entities_compared"] == "entities whose source is the gazetteer"
    detail = {d["doc_id"]: d for d in r["documents_detail"]}
    assert sorted(detail) == ["d1", "d2", "d3", "d4"]
    assert detail["d1"]["gazetteer_entities"] is None and detail["d1"]["candidates"] is None
    assert detail["d2"]["gazetteer_entities"] == {
        "only_a": [], "only_b": [["threat_actor", "apt99", "G9999"]]}
    assert detail["d2"]["candidates"] == {"only_a": [], "only_b": ["T1003.001"]}
    assert detail["d3"]["gazetteer_entities"] is None
    assert detail["d3"]["candidates"] == {"only_a": ["T1007", "T1008.002"], "only_b": ["T1006", "T1099"]}
    assert detail["d4"]["gazetteer_entities"] is None and detail["d4"]["candidates"] is None
    assert detail["d3"]["ttp_differences"] == [
        {"id": "T1006", "class": "content_changed", "in": "b", "gold": True},
        {"id": "T1007", "class": "content_changed", "in": "a", "gold": True},
        {"id": "T1008", "class": "status_changed", "in": "a", "gold": True},
        {"id": "T1099", "class": "new_technique", "in": "b", "gold": False}]
    assert (r["documents_with_ttp_difference"], r["documents_gazetteer_differs"],
            r["documents_candidates_differ"], r["documents_ttp_difference_and_upstream_difference"]) == (4, 1, 2, 2)

    printed = capsys.readouterr().out
    assert "new_subtechnique" in printed and "0.8750" in printed


def test_release_effect_with_the_old_mapping_sees_a_revoked_technique(runs, monkeypatch):
    _effect(monkeypatch, "--attack-release", "19.2")
    r = _read(runs.out / "compare" / "run-a__vs__run-b__release-effect.json")
    assert r["attack_mapping"]["release"] == "19.2"
    # d1 under 19.2: A {T1001 T1004}, B {T1001 T1002} (T1099 does not exist for it), gold {T1001 T1002 T1004}
    assert r["classes"]["status_changed"]["ids"] == ["T1004", "T1008"]
    assert r["classes"]["new_technique"]["ids"] == []                      # nothing new is in a 19.2 mapping


def test_release_effect_needs_a_mapping_when_the_runs_differ(runs, monkeypatch):
    with pytest.raises(SystemExit, match="--attack-release"):
        _effect(monkeypatch)
    _write_run(runs, "run-b2", "19.2", _RUN_B)
    _cli(monkeypatch, "release-effect", "--a", "run-a", "--b", "run-b2", "--old", "19.2", "--new", "20.0")
    r = _read(runs.out / "compare" / "run-a__vs__run-b2__release-effect.json")
    assert r["attack_mapping"]["release"] == "19.2"


def test_release_effect_falls_back_to_the_named_entity_types_when_the_runs_record_no_source(world, monkeypatch):
    monkeypatch.setattr(annoctr, "load", lambda *a, **k: _annoctr_docs(_GOLD))
    _write_run(world, "run-a", "19.2", _RUN_A, with_source=False)
    _write_run(world, "run-b", "20.0", _RUN_B, with_source=False)
    _effect(monkeypatch, "--attack-release", "20.0")
    r = _read(world.out / "compare" / "run-a__vs__run-b__release-effect.json")

    assert "no entity source" in r["entities_compared"]
    detail = {d["doc_id"]: d for d in r["documents_detail"]}
    assert detail["d1"]["gazetteer_entities"] == {"only_a": [["malware", "foo", None]], "only_b": []}
    assert r["documents_gazetteer_differs"] == 2                           # d1 (an LLM name now counts) and d2


def test_release_effect_takes_the_releases_the_runs_ran_on(runs, monkeypatch):
    _cli(monkeypatch, "release-effect", "--a", "run-a", "--b", "run-b", "--attack-release", "20.0")
    r = _read(runs.out / "compare" / "run-a__vs__run-b__release-effect.json")
    assert r["releases"] == {"a": "19.2", "b": "20.0", "old": "19.2", "new": "20.0"}
    assert r["classes"]["new_technique"]["ids"] == ["T1099"]

    _cli(monkeypatch, "release-effect", "--a", "run-a", "--b", "run-b", "--attack-release", "20.0",
         "--old", "v19.2", "--new", "20.0")                                # given, and the same
    assert _read(runs.out / "compare" / "run-a__vs__run-b__release-effect.json") == r


@pytest.mark.parametrize("old, new, wrong", [("20.0", None, "--old 20.0 but run-a ran on ATT&CK 19.2"),
                                             (None, "19.2", "--new 19.2 but run-b ran on ATT&CK 20.0"),
                                             ("19.2", "19.2", "--new 19.2 but run-b ran on ATT&CK 20.0")])
def test_release_effect_refuses_an_option_that_is_not_the_release_of_its_run(runs, monkeypatch, old, new, wrong):
    extra = [*(["--old", old] if old else []), *(["--new", new] if new else [])]
    with pytest.raises(SystemExit, match=wrong):
        _cli(monkeypatch, "release-effect", "--a", "run-a", "--b", "run-b", "--attack-release", "20.0", *extra)
    assert not (runs.out / "compare").exists()


def test_release_effect_of_two_runs_on_one_release_needs_old_and_new(runs, monkeypatch):
    _write_run(runs, "run-a2", "19.2", _RUN_A)
    for extra in ([], ["--old", "19.2"], ["--new", "20.0"]):
        with pytest.raises(SystemExit, match="run-a and run-a2 both ran on ATT&CK 19.2: pass --old and --new"):
            _cli(monkeypatch, "release-effect", "--a", "run-a", "--b", "run-a2", *extra)
    assert not (runs.out / "compare").exists()

    _cli(monkeypatch, "release-effect", "--a", "run-a", "--b", "run-a2", "--old", "19.2", "--new", "20.0")
    r = _read(runs.out / "compare" / "run-a__vs__run-a2__release-effect.json")
    assert r["releases"] == {"a": "19.2", "b": "19.2", "old": "19.2", "new": "20.0"}


# ── A run resumes on the release it began with ───────────────────────────────

@pytest.fixture()
def fake_pipeline(runs, monkeypatch):
    """`run` and `inhouse-run` with the pipeline faked: the names of the documents it ran."""
    ran: list[str] = []

    class Result:
        def stage_report(self):
            return []

    def run_document(document, options):
        ran.append(document.original_filename)
        return Result()

    def run_file(path, disabled):
        ran.append(path.name)
        return Result()

    monkeypatch.setenv("TTP_RETRIEVAL_EXCLUDE_CITED", "none")                  # annoctr_cited_exclusions reads data
    monkeypatch.setattr("pipeline.orchestrator.run_document", run_document)
    monkeypatch.setattr("api.run_config.build_manifest", lambda: {"attack": attack_data.describe()})
    monkeypatch.setattr(ev, "_predictions", lambda result: {"ttp_ids": []})
    monkeypatch.setattr(ev, "_run_file", run_file)
    monkeypatch.setattr(ev.inhouse, "load", lambda: [
        SimpleNamespace(doc_id=f"h{i}", source=Path(f"h{i}.txt")) for i in (1, 2)])
    return SimpleNamespace(ran=ran, out=runs.out)


_COMMANDS = [("run", "runs", "d1"), ("inhouse-run", "inhouse-runs", "h1")]


def _docs_of(out, kind, name):
    return sorted(p.name for p in (out / kind / name / "docs").glob("*.json"))


def _begin(out, kind, name, release, done=()):
    """A run that began: its run.json, and the documents already recorded."""
    run_dir = out / kind / name
    (run_dir / "docs").mkdir(parents=True)
    manifest = {"attack": {"release": release}} if release else {"llm": {}}
    (run_dir / "run.json").write_text(json.dumps({"name": name, "split": "dev", "manifest": manifest}),
                                      encoding="utf-8")
    for doc_id in done:
        (run_dir / "docs" / f"{doc_id}.json").write_text(json.dumps({"doc_id": doc_id}), encoding="utf-8")
    return run_dir


@pytest.mark.parametrize("command, kind, first", _COMMANDS)
def test_an_unknown_release_stops_a_new_run_before_any_document(fake_pipeline, monkeypatch, command, kind, first):
    monkeypatch.setenv("ATTACK_RELEASE", "21.0")
    with pytest.raises(attack_data.UnknownAttackRelease, match="21.0"):
        _cli(monkeypatch, command, "--name", "fresh")
    assert fake_pipeline.ran == [] and not (fake_pipeline.out / kind / "fresh").exists()


@pytest.mark.parametrize("command, kind, first", _COMMANDS)
def test_an_unknown_release_does_not_turn_the_documents_left_into_errors(
        fake_pipeline, monkeypatch, command, kind, first):
    """The error used to be caught per document: every remaining one was recorded as failed, a
    resume skipped them, and the command exited with 0."""
    _begin(fake_pipeline.out, kind, "half", "19.2", done=[first])
    before = _docs_of(fake_pipeline.out, kind, "half")

    monkeypatch.setenv("ATTACK_RELEASE", "21.0")
    with pytest.raises(attack_data.UnknownAttackRelease):
        _cli(monkeypatch, command, "--name", "half")

    assert fake_pipeline.ran == [] and _docs_of(fake_pipeline.out, kind, "half") == before == [f"{first}.json"]


@pytest.mark.parametrize("command, kind, first", _COMMANDS)
def test_an_unknown_release_raised_inside_the_loop_stops_the_run_too(
        fake_pipeline, monkeypatch, command, kind, first):
    def broken(*args, **kwargs):
        raise attack_data.UnknownAttackRelease("the track went away")

    monkeypatch.setattr("pipeline.orchestrator.run_document", broken)
    monkeypatch.setattr(ev, "_run_file", broken)
    with pytest.raises(attack_data.UnknownAttackRelease, match="went away"):
        _cli(monkeypatch, command, "--name", "fresh")
    assert _docs_of(fake_pipeline.out, kind, "fresh") == []


@pytest.mark.parametrize("command, kind, first", _COMMANDS)
def test_a_run_resumes_only_on_the_release_it_began_with(fake_pipeline, monkeypatch, command, kind, first):
    run_dir = _begin(fake_pipeline.out, kind, "half", "19.2")
    began = (run_dir / "run.json").read_text(encoding="utf-8")

    monkeypatch.setenv("ATTACK_RELEASE", "20.0")
    with pytest.raises(SystemExit, match=r"half began on ATT&CK 19.2 and ATTACK_RELEASE selects 20.0: "
                                         r"resume it with ATTACK_RELEASE=19.2"):
        _cli(monkeypatch, command, "--name", "half")
    assert fake_pipeline.ran == [] and _docs_of(fake_pipeline.out, kind, "half") == []

    attack_data.reset()
    for spelling in ("", "v19.2"):                                 # the same release, however it is written
        monkeypatch.setenv("ATTACK_RELEASE", spelling)
        _cli(monkeypatch, command, "--name", "half")
        assert fake_pipeline.ran
        fake_pipeline.ran.clear()
        for doc in (run_dir / "docs").glob("*.json"):
            doc.unlink()
    assert (run_dir / "run.json").read_text(encoding="utf-8") == began               # not rewritten


@pytest.mark.parametrize("command, kind, first", _COMMANDS)
def test_a_run_from_before_the_manifest_named_a_release_resumes_on_the_default_track(
        fake_pipeline, monkeypatch, command, kind, first):
    _begin(fake_pipeline.out, kind, "old", None)

    monkeypatch.setenv("ATTACK_RELEASE", "20.0")
    with pytest.raises(SystemExit, match="old began on ATT&CK 19.2 and ATTACK_RELEASE selects 20.0"):
        _cli(monkeypatch, command, "--name", "old")
    assert fake_pipeline.ran == []

    attack_data.reset()
    monkeypatch.delenv("ATTACK_RELEASE")
    _cli(monkeypatch, command, "--name", "old")
    assert fake_pipeline.ran


@pytest.mark.parametrize("command, kind, first", _COMMANDS)
def test_a_new_run_records_the_release_it_runs_on(fake_pipeline, monkeypatch, command, kind, first):
    monkeypatch.setenv("ATTACK_RELEASE", "v20.0")
    _cli(monkeypatch, command, "--name", "fresh")
    meta = _read(fake_pipeline.out / kind / "fresh" / "run.json")
    assert meta["manifest"]["attack"]["release"] == "20.0" and fake_pipeline.ran


def test_inhouse_score_maps_with_the_release_of_the_run(world, monkeypatch):
    seen = []
    monkeypatch.setattr(ev.inhouse, "load", lambda: [])
    monkeypatch.setattr(ev, "_canonical_fn", lambda release=None: (seen.append(release), (None, None))[1])
    for name, release in (("in-new", "20.0"), ("in-old", None)):
        run_dir = world.out / "inhouse-runs" / name
        (run_dir / "docs").mkdir(parents=True)
        manifest = {"attack": {"release": release}} if release else {"llm": {}}
        (run_dir / "run.json").write_text(json.dumps({"name": name, "manifest": manifest}), encoding="utf-8")
        _cli(monkeypatch, "inhouse-score", "--name", name)
    assert seen == ["20.0", "19.2"]


# ── The environment file, before any ATT&CK file is read ─────────────────────

def test_main_reads_the_env_file_before_the_release_is_resolved(tmp_path, monkeypatch):
    """A variable of .env reaches ATTACK_RELEASE as it does for main.py; one already set wins."""
    (tmp_path / ".env").write_text("ATTACK_RELEASE=20.0\nATTACK_TEST_SET_BOTH=from-env-file\n", encoding="utf-8")
    monkeypatch.setattr(ev, "_ROOT", tmp_path)
    monkeypatch.setenv("ATTACK_RELEASE", "x")                  # so that monkeypatch removes what load_dotenv sets
    monkeypatch.delenv("ATTACK_RELEASE")
    monkeypatch.setenv("ATTACK_TEST_SET_BOTH", "from-the-shell")
    seen = []
    monkeypatch.setattr(ev, "cmd_score", lambda args: seen.append(
        (attack_data.requested(), attack_data.current().version, os.getenv("ATTACK_TEST_SET_BOTH"))))
    monkeypatch.setattr(sys, "argv", ["evaluation", "score", "--name", "whatever"])

    ev.main()

    assert seen == [("20.0", "20.0", "from-the-shell")]


# ── A run whose ATT&CK files were modified says so ───────────────────────────

def test_a_run_on_modified_files_is_scored_with_a_warning_and_the_report_says_so(runs, monkeypatch, capsys):
    _write_run(runs, "mod-a", "19.2", _RUN_A, modified=["gazetteer.json", "mitre_embeddings_manifest.json "
                                                        "(not in the manifest)"])
    _write_run(runs, "mod-b", "20.0", _RUN_B, modified=["mitre_index.json"])
    files = ["gazetteer.json", "mitre_embeddings_manifest.json (not in the manifest)"]

    _cli(monkeypatch, "score", "--name", "mod-a")
    captured = capsys.readouterr()
    assert "WARNING: mod-a ran on ATT&CK 19.2 files that differ from its manifest" in captured.err
    assert "gazetteer.json" in captured.err and "(not in the manifest)" in captured.err
    assert "WARNING" not in captured.out
    assert _read(runs.out / "runs" / "mod-a" / "score.json")["attack_modified_files"] == files

    _cli(monkeypatch, "ttp-errors", "--name", "mod-a")
    assert "WARNING: mod-a" in capsys.readouterr().err
    assert _read(runs.out / "runs" / "mod-a" / "ttp-errors.json")["attack_modified_files"] == files

    _cli(monkeypatch, "compare", "--a", "mod-a", "--b", "mod-b", "--resamples", "20", "--attack-release", "20.0")
    err = capsys.readouterr().err
    assert "WARNING: mod-a" in err and "WARNING: mod-b" in err
    assert _read(runs.out / "compare" / "mod-a__vs__mod-b__ttp__attack-20.0.json")["attack_modified_files"] == {
        "a": files, "b": ["mitre_index.json"]}

    _cli(monkeypatch, "release-effect", "--a", "mod-a", "--b", "mod-b", "--attack-release", "20.0")
    err = capsys.readouterr().err
    assert "WARNING: mod-a" in err and "WARNING: mod-b" in err
    assert _read(runs.out / "compare" / "mod-a__vs__mod-b__release-effect.json")["attack_modified_files"] == {
        "a": files, "b": ["mitre_index.json"]}


def test_a_run_on_unmodified_files_is_scored_without_a_warning_or_a_new_key(runs, monkeypatch, capsys):
    _write_run(runs, "old-run", None, _RUN_A)                  # before the manifest said anything
    for name in ("run-a", "old-run"):
        _cli(monkeypatch, "score", "--name", name)
        _cli(monkeypatch, "ttp-errors", "--name", name)
        assert "WARNING" not in capsys.readouterr().err
        assert "attack_modified_files" not in _read(runs.out / "runs" / name / "score.json")
        assert "attack_modified_files" not in _read(runs.out / "runs" / name / "ttp-errors.json")
    _cli(monkeypatch, "compare", "--a", "run-a", "--b", "old-run", "--resamples", "20")
    _cli(monkeypatch, "release-effect", "--a", "run-a", "--b", "old-run", "--old", "19.2", "--new", "20.0")
    assert "WARNING" not in capsys.readouterr().err
    for path in (runs.out / "compare").glob("*.json"):
        assert "attack_modified_files" not in _read(path)
