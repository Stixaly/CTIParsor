"""pipeline/attack_data.py — the ATT&CK release the loaders read (ADR-0087).

A fake track in tmp_path stands for pipeline/data/attack/20.0/ (TRACKS_DIR is
patched).  The loaders cache what they read, so every cache is emptied around
a test that changes track: nothing read from the fake one reaches another test.
The release a process fixes at its first use is forgotten with them
(`attack_data.reset`; tests/conftest.py does it around every test).
"""
from __future__ import annotations

import io
import json
import sys
from hashlib import sha256
from pathlib import Path

import numpy as np
import pytest

from api import run_config
from pipeline import aliases, attack_data, mitre_db, stage2b_gazetteer, ttp_retrieval
from pipeline import orchestrator as orch
from pipeline import stage2c_ttp_semantic as s2c
from pipeline import stage3f_ttp_select as s3f
from pipeline import stage4b_graph_completion as s4b

_DEFAULT = "19.2"          # the release the committed pipeline/data/ files match

# Every cache a loader fills from an ATT&CK file, or from another loader's.
_CACHES = (
    ("pipeline.mitre_db", "_load"), ("pipeline.mitre_db", "_revoked"),
    ("pipeline.aliases", "_load"), ("pipeline.aliases", "_load_techniques"),
    ("pipeline.stage2b_gazetteer", "_load"), ("pipeline.stage2b_gazetteer", "_build_automaton"),
    ("pipeline.stage2b_gazetteer", "_policy_index"),
    ("pipeline.stage2c_ttp_semantic", "_load_corpus"),
    ("pipeline.stage3c_mitre", "_load_index"), ("pipeline.stage3c_mitre", "_tactics_by_id"),
    ("pipeline.stage3f_ttp_select", "_definitions"),
    ("pipeline.stage4b_graph_completion", "_attack_pairs"),
    ("pipeline.ttp_retrieval", "_built_corpus"), ("pipeline.ttp_retrieval", "_production_retriever"),
    ("pipeline.detection.phases", "_technique_index"),
)

_INDEX = {
    "tactics": [{"id": "TA0001", "name": "Initial Access", "shortname": "initial-access"}],
    "techniques": [{"id": "T9999", "name": "Fake Technique", "description": "Only in the fake track."}],
}


def _clear_caches() -> None:
    attack_data.reset()
    for module, name in _CACHES:
        loaded = sys.modules.get(module)        # not imported yet: nothing cached
        if loaded is not None:
            getattr(loaded, name).cache_clear()


@pytest.fixture()
def clean_caches():
    _clear_caches()
    yield
    _clear_caches()


def _json(value) -> bytes:
    return json.dumps(value).encode("utf-8")


def _npy(array) -> bytes:
    buffer = io.BytesIO()
    np.save(buffer, array)
    return buffer.getvalue()


def _track(root: Path, version: str = "20.0", files: dict[str, bytes] | None = None, *,
           release: str | None = None) -> Path:
    """root/<version>/ holding a mitre_index.json and `files`, and the manifest
    that hashes them all (`release`: what the manifest claims, if not `version`)."""
    track = root / version
    track.mkdir(parents=True)
    contents = {"mitre_index.json": _json(_INDEX), **(files or {})}
    for name, content in contents.items():
        (track / name).write_bytes(content)
    manifest = {"release": release or version, "files": {n: sha256(c).hexdigest() for n, c in contents.items()},
                "sources": [{"domain": "enterprise-attack", "sha256": "ab" * 32}]}
    (track / attack_data.MANIFEST_NAME).write_bytes(_json(manifest))
    return track


@pytest.fixture()
def tracks(tmp_path, monkeypatch, clean_caches):
    """An empty TRACKS_DIR: a test writes the tracks it needs with `_track`."""
    root = tmp_path / "attack"
    root.mkdir()
    monkeypatch.setattr(attack_data, "TRACKS_DIR", root)
    return root


@pytest.fixture()
def track20(tracks):
    """A 20.0 track with an index of one technique; not selected."""
    return _track(tracks)


@pytest.fixture()
def select20(track20, monkeypatch):
    monkeypatch.setenv("ATTACK_RELEASE", "20.0")
    return track20


# ── Which release ────────────────────────────────────────────────────────────

@pytest.mark.parametrize("value", [None, "", "  ", "19.2", "v19.2", "V19.2", "default"])
def test_unset_empty_or_the_shipped_version_is_the_default_track(monkeypatch, value):
    if value is None:
        monkeypatch.delenv("ATTACK_RELEASE", raising=False)
    else:
        monkeypatch.setenv("ATTACK_RELEASE", value)
    rel = attack_data.current()
    assert (rel.version, rel.default, rel.directory) == (_DEFAULT, True, attack_data.DATA_DIR)


@pytest.mark.parametrize("value", ["21.0", "../data", "20.0/../x", "20.0.0.0", "latest"])
def test_an_unknown_release_is_refused_and_the_message_lists_the_available_ones(track20, monkeypatch, value):
    monkeypatch.setenv("ATTACK_RELEASE", value)
    with pytest.raises(attack_data.UnknownAttackRelease) as err:
        attack_data.current()
    assert isinstance(err.value, ValueError)
    assert f"available: {_DEFAULT}, 20.0" in str(err.value)


@pytest.mark.parametrize("value", ["v", "V", "vdefault", "v.", "vv20.0", "\u0662\u0660.\u0660",
                                   "v\u0662\u0660.\u0660", "\uff12\uff10.\uff10"])
def test_a_v_is_a_prefix_only_before_a_digit_and_only_ascii_digits_are_digits(tracks, monkeypatch, value):
    """"v" and "vdefault" were the default track; a directory named with Arabic-Indic or
    fullwidth digits (which `\\d` matches) would have been a track."""
    _track(tracks, "\u0662\u0660.\u0660", release="\u0662\u0660.\u0660")
    monkeypatch.setenv("ATTACK_RELEASE", value)
    with pytest.raises(attack_data.UnknownAttackRelease, match="no such ATT&CK release"):
        attack_data.current()
    assert attack_data.available() == [_DEFAULT]


@pytest.mark.parametrize("value, expected", [
    ("19.2", True), ("20", True), ("1.2.3", True),
    ("v19.2", False), ("", False), ("1.2.3.4", False), ("20.", False), (".0", False), ("20.0\n", False),
    (" 20.0", False), ("\u0662\u0660.\u0660", False)])
def test_is_version_takes_ascii_x_y_z_and_nothing_else(value, expected):
    assert attack_data.is_version(value) is expected


def test_a_track_directory_selects_its_release(select20):
    rel = attack_data.current()
    assert (rel.version, rel.default, rel.directory) == ("20.0", False, select20)
    assert attack_data.available() == [_DEFAULT, "20.0"]


def test_the_releases_are_listed_in_version_order_and_need_a_manifest(tracks):
    for version in ("20.0", "9.1"):
        _track(tracks, version)
    (tracks / "10.0").mkdir()                         # no manifest: not a track
    (tracks / "notes").mkdir()
    assert attack_data.available() == [_DEFAULT, "9.1", "20.0"]


def test_a_track_without_a_manifest_is_not_selectable(tracks, monkeypatch):
    (tracks / "20.0").mkdir()
    monkeypatch.setenv("ATTACK_RELEASE", "20.0")
    with pytest.raises(attack_data.UnknownAttackRelease, match="no such ATT&CK release"):
        attack_data.current()


def test_a_manifest_naming_another_release_is_refused(tracks, monkeypatch):
    _track(tracks, "20.0", release="20.1")
    monkeypatch.setenv("ATTACK_RELEASE", "20.0")
    with pytest.raises(attack_data.UnknownAttackRelease, match="says release '20.1'"):
        attack_data.current()


# ── One release per process ──────────────────────────────────────────────────

def test_release_resolves_a_value_without_touching_the_selection(track20):
    assert attack_data.release("v20.0").version == "20.0" and attack_data.release(" 20.0 ").directory == track20
    assert attack_data.release("").default is True
    assert attack_data.current().version == _DEFAULT              # fixes the process on the default track
    assert attack_data.release("20.0").version == "20.0"          # asking about another one is not a change
    with pytest.raises(attack_data.UnknownAttackRelease):
        attack_data.release("21.0")
    assert attack_data.current().version == _DEFAULT


def test_the_first_release_a_process_resolves_is_the_one_it_keeps(track20, monkeypatch):
    """.env is loaded when stage3_llm or api.db is imported: without this a process read the
    default track for Stage 2b and 2c, then 20.0 for the rest."""
    assert attack_data.current().version == _DEFAULT
    monkeypatch.setenv("ATTACK_RELEASE", "20.0")
    with pytest.raises(attack_data.UnknownAttackRelease) as err:
        attack_data.current()
    assert "ATTACK_RELEASE changed from 19.2 to 20.0 in this process; set it before the process starts" \
        in str(err.value)
    for call in (lambda: attack_data.resolve(attack_data.DATA_DIR / "mitre_index.json"),
                 attack_data.describe, attack_data.modified_files, mitre_db.get_techniques):
        with pytest.raises(attack_data.UnknownAttackRelease, match="changed from 19.2 to 20.0"):
            call()
    monkeypatch.delenv("ATTACK_RELEASE")
    assert attack_data.current().version == _DEFAULT


def test_the_same_version_written_another_way_is_not_a_change(track20, monkeypatch):
    for value in ("", "19.2", "v19.2", "V19.2", "default", " 19.2 "):
        monkeypatch.setenv("ATTACK_RELEASE", value)
        assert attack_data.current().version == _DEFAULT, value

    attack_data.reset()
    for value in ("v20.0", "20.0", " 20.0"):
        monkeypatch.setenv("ATTACK_RELEASE", value)
        assert attack_data.current().version == "20.0", value
    monkeypatch.setenv("ATTACK_RELEASE", "")
    with pytest.raises(attack_data.UnknownAttackRelease, match="changed from 20.0 to 19.2"):
        attack_data.current()


def test_reset_forgets_the_release_the_process_fixed(track20, monkeypatch):
    assert attack_data.current().version == _DEFAULT
    monkeypatch.setenv("ATTACK_RELEASE", "20.0")
    attack_data.reset()
    rel = attack_data.current()
    assert (rel.version, rel.directory) == ("20.0", track20)
    monkeypatch.delenv("ATTACK_RELEASE")
    with pytest.raises(attack_data.UnknownAttackRelease):
        attack_data.current()


def test_a_value_that_does_not_resolve_fixes_nothing(track20, monkeypatch):
    monkeypatch.setenv("ATTACK_RELEASE", "21.0")
    with pytest.raises(attack_data.UnknownAttackRelease, match="no such ATT&CK release"):
        attack_data.current()
    monkeypatch.setenv("ATTACK_RELEASE", "20.0")
    assert attack_data.current().version == "20.0"


def _boot_api():
    """Enter the API's lifespan with the database, the orphan requeue and the queue loop left out."""
    from unittest.mock import patch

    from fastapi.testclient import TestClient

    import api.main

    with patch("api.main.init_db"), patch("api.queue_loop.requeue_orphans"), \
            patch("api.queue_loop.start_embedded"):
        with TestClient(api.main.app):
            pass


def test_a_bad_release_stops_the_api_at_startup(monkeypatch):
    """As a bad STIX_TLP does (ADR-0073): at boot, not at the first run."""
    monkeypatch.setenv("ATTACK_RELEASE", "21.0")
    with pytest.raises(attack_data.UnknownAttackRelease):
        _boot_api()


def test_the_api_logs_the_release_it_runs(monkeypatch, caplog):
    monkeypatch.setenv("ATTACK_RELEASE", "v19.2")
    with caplog.at_level("INFO"):
        _boot_api()
    assert "[startup] ATT&CK release: 19.2" in caplog.text


def test_a_bad_release_stops_the_worker_at_startup(monkeypatch):
    from api import queue_loop

    monkeypatch.setattr(queue_loop, "setup_logging", lambda: None)     # it empties the root logger's handlers
    monkeypatch.setenv("ATTACK_RELEASE", "21.0")
    with pytest.raises(attack_data.UnknownAttackRelease):
        queue_loop.main(["--once"])


# ── resolve ──────────────────────────────────────────────────────────────────

def test_resolve_moves_the_attack_files_to_the_selected_track_and_leaves_the_rest(select20, tmp_path):
    data = attack_data.DATA_DIR
    assert attack_data.resolve(data / "mitre_index.json") == select20 / "mitre_index.json"
    assert attack_data.resolve(str(data / "attack_manifest.json")) == select20 / "attack_manifest.json"
    assert attack_data.resolve(data / "warninglists.json") == data / "warninglists.json"
    assert attack_data.resolve(data / "gazetteer_policy.json") == data / "gazetteer_policy.json"
    for elsewhere in (tmp_path / "mitre_index.json", tmp_path / "x" / "gazetteer.json"):
        assert attack_data.resolve(elsewhere) == elsewhere


def test_resolve_changes_nothing_on_the_default_track(monkeypatch):
    monkeypatch.delenv("ATTACK_RELEASE", raising=False)
    for name in attack_data.ATTACK_FILES | {attack_data.MANIFEST_NAME}:
        assert attack_data.resolve(attack_data.DATA_DIR / name) == attack_data.DATA_DIR / name


def test_every_loader_constant_names_a_file_a_track_replaces(select20):
    """A constant naming a file outside ATTACK_FILES, or outside pipeline/data,
    would keep its loader on the default release whatever is selected."""
    constants = (mitre_db._INDEX_PATH, mitre_db._REVOKED_PATH, aliases._GAZETTEER, aliases._MITRE_INDEX,
                 stage2b_gazetteer._INDEX_PATH, s2c._EMB_PATH, s2c._META_PATH, s2c._MANIFEST_PATH,
                 s4b._ATTACK_REL_PATH, ttp_retrieval.CORPUS_PATH, ttp_retrieval.EMBEDDINGS_PATH)
    for path in constants:
        assert attack_data.resolve(path) == select20 / path.name, path


# ── What the manifest of a track proves ──────────────────────────────────────

def test_a_rebuilt_file_is_reported_as_modified(select20):
    assert attack_data.modified_files() == []
    (select20 / "mitre_index.json").write_bytes(_json({"tactics": [], "techniques": []}))
    assert attack_data.modified_files() == ["mitre_index.json"]


def test_a_missing_file_is_reported_as_modified(tracks, monkeypatch):
    track = _track(tracks, files={"gazetteer.json": _json([])})
    (track / "gazetteer.json").unlink()
    monkeypatch.setenv("ATTACK_RELEASE", "20.0")
    assert attack_data.modified_files() == ["gazetteer.json"]


def test_a_file_the_manifest_does_not_know_is_reported_with_the_mention(select20):
    """A local mitre_embeddings_manifest.json would change Stage 2c's model and thresholds
    without a hash to differ."""
    (select20 / "mitre_embeddings_manifest.json").write_bytes(_json({"model": "m", "thresholds": {}}))
    (select20 / "notes.txt").write_text("not an ATT&CK file", encoding="utf-8")
    assert attack_data.modified_files() == ["mitre_embeddings_manifest.json (not in the manifest)"]

    (select20 / "mitre_index.json").write_bytes(_json({"tactics": [], "techniques": []}))
    assert attack_data.modified_files() == ["mitre_embeddings_manifest.json (not in the manifest)",
                                            "mitre_index.json"]
    assert attack_data.describe()["modified_files"] == attack_data.modified_files()


def test_a_file_of_the_default_track_outside_its_manifest_is_reported_too(tmp_path, monkeypatch):
    data = tmp_path / "data"
    data.mkdir()
    (data / "mitre_index.json").write_bytes(_json(_INDEX))
    (data / attack_data.MANIFEST_NAME).write_bytes(_json({"release": _DEFAULT, "files": {
        "mitre_index.json": sha256(_json(_INDEX)).hexdigest()}}))
    monkeypatch.setattr(attack_data, "DATA_DIR", data)
    monkeypatch.setattr(attack_data, "TRACKS_DIR", data / "attack")
    attack_data.reset()
    assert attack_data.modified_files() == []
    (data / "gazetteer.json").write_bytes(_json([]))
    (data / "warninglists.json").write_bytes(_json([]))                  # not an ATT&CK file
    assert attack_data.modified_files() == ["gazetteer.json (not in the manifest)"]


@pytest.mark.parametrize("version", attack_data.available())
def test_every_shipped_release_matches_its_manifest(monkeypatch, clean_caches, version):
    """Fails when someone rebuilds a shipped ATT&CK file without writing the
    manifest again: the release it claims would no longer be proven."""
    monkeypatch.setenv("ATTACK_RELEASE", version)
    modified = attack_data.modified_files()
    assert modified == [], (f"ATT&CK {version}: {modified} no longer match attack_manifest.json; "
                            "rebuild the manifest with the files (ADR-0087)")


# ── The run manifest ─────────────────────────────────────────────────────────

def test_the_run_manifest_records_the_default_release():
    manifest = run_config.build_manifest()
    attack = manifest["attack"]
    assert (attack["release"], attack["default"], attack["requested"]) == (_DEFAULT, True, None)
    assert attack["directory"] == "pipeline/data" and attack["modified_files"] == []
    assert attack["manifest_sha256"] and attack["manifest_sha256"] == manifest["data"]["attack_manifest.json"]
    assert "enterprise-attack" in attack["sources"]
    json.dumps(attack)


def test_the_run_manifest_says_how_a_track_was_built(tracks, monkeypatch):
    track = _track(tracks)
    manifest = json.loads((track / attack_data.MANIFEST_NAME).read_text(encoding="utf-8"))
    built_with = {"script": "scripts/build_attack_release.py", "git_rev": None,
                  "embedding_model": None, "embeddings": "skipped"}
    (track / attack_data.MANIFEST_NAME).write_bytes(_json({**manifest, "built_with": built_with}))

    assert run_config.build_manifest()["attack"]["built_with"] is None            # the default track
    attack_data.reset()
    monkeypatch.setenv("ATTACK_RELEASE", "20.0")
    assert run_config.build_manifest()["attack"]["built_with"] == built_with     # a --skip-embeddings track shows


def test_the_run_manifest_hashes_the_files_of_the_selected_track(select20):
    manifest = run_config.build_manifest()
    attack, data = manifest["attack"], manifest["data"]
    assert (attack["release"], attack["default"], attack["requested"]) == ("20.0", False, "20.0")
    assert data["mitre_index.json"] == sha256((select20 / "mitre_index.json").read_bytes()).hexdigest()[:16]
    assert data["attack_manifest.json"] == attack["manifest_sha256"]
    # A file the track lacks is missing, not the default one, and the other data is the shipped data.
    assert data["gazetteer.json"] is None
    assert data["warninglists.json"] == run_config._file_fingerprint(run_config._DATA_DIR / "warninglists.json")
    assert set(data) == set(run_config._DATA_FILES)


def test_the_release_setting_is_captured(monkeypatch):
    monkeypatch.setenv("ATTACK_RELEASE", "20.0")
    assert run_config.captured_env()["ATTACK_RELEASE"] == "20.0"
    monkeypatch.delenv("ATTACK_RELEASE")
    assert "ATTACK_RELEASE" not in run_config.captured_env()


def test_an_unknown_release_stops_the_manifest(tracks, monkeypatch):
    monkeypatch.setenv("ATTACK_RELEASE", "21.0")
    with pytest.raises(attack_data.UnknownAttackRelease):
        run_config.build_manifest()


# ── Stage 3 checkpoint and run ───────────────────────────────────────────────

def test_the_stage3_fingerprint_moves_with_the_release(track20, monkeypatch):
    from pipeline.stage3_llm import stage3_settings

    def settings_and_fingerprint():
        settings = stage3_settings(consensus=False, verify_rels=False, verify_ttps=False)
        return settings, orch.stage3_fingerprint(settings, {"chunks": ["one"], "doc_context": ""})

    settings, shipped = settings_and_fingerprint()
    assert settings["attack_release"] == _DEFAULT
    monkeypatch.setenv("ATTACK_RELEASE", "20.0")
    attack_data.reset()                 # a process keeps the release it began with
    settings, other = settings_and_fingerprint()
    assert settings["attack_release"] == "20.0" and other != shipped


def test_a_run_with_an_unknown_release_stops_before_its_first_stage(tracks, monkeypatch):
    def ingest(self):
        raise AssertionError("Stage 1 ran")
    monkeypatch.setattr(orch._Run, "ingest", ingest)
    monkeypatch.setenv("ATTACK_RELEASE", "21.0")
    options = orch.RunOptions(consensus=False, document_relations=False, verify_relationships=False,
                              verify_ttps=False, llm_parallelism=1)
    with pytest.raises(attack_data.UnknownAttackRelease):
        orch.run_document(orch.Document(text="APT29 used SUNBURST."), options)


def test_a_bundle_build_with_an_unknown_release_stops_before_stage4b(tracks, monkeypatch):
    """A finalize builds Stages 4-5 without run_document, and Stage 4b catches
    its own errors: an IPv4-only bundle used to build, its grounding failure
    left in a note.  Stage 4 now refuses first."""
    from models.schemas import EntityType, RawEntity
    from pipeline.stage3_llm import LLMEnrichmentResult
    from pipeline.stage4_stix_mapping import build_stix_bundle

    monkeypatch.setenv("ATTACK_RELEASE", "21.0")
    with pytest.raises(attack_data.UnknownAttackRelease):
        build_stix_bundle([RawEntity(value="203.0.113.7", entity_type=EntityType.IPV4, source="regex")],
                          LLMEnrichmentResult(), "ipv4_only", tlp_level="clear")


# ── The loaders ──────────────────────────────────────────────────────────────

_FAKE_GAZETTEER = [{"name": "fakegroup", "canonical": "Fake Group", "entity_type": "threat_actor",
                    "mitre_id": "G9999", "domain": "enterprise-attack"}]


def _loader_files() -> dict[str, bytes]:
    """A file for each loader beside the index; the corpus and the embeddings agree on one entry."""
    entry = {"id": "T9999", "name": "Fake Technique", "domain": "enterprise-attack"}
    return {
        "gazetteer.json": _json(_FAKE_GAZETTEER),
        "attack_revoked.json": _json({"revoked_by": {"T0001": "T9999"}, "names": {}}),
        "attack_relationships.json": _json({"pairs": [["G9999", "uses", "T9999"]]}),
        "mitre_embeddings.npy": _npy(np.ones((1, 4), dtype="float32")),
        "mitre_embeddings_meta.json": _json([entry]),
        "mitre_embeddings_manifest.json": _json({"model": s2c._TTP_EMBEDDING_MODEL,
                                                 "thresholds": {"high": 0.91, "medium": 0.81}}),
        "attack_retrieval_corpus.json": _json({"entries": [{**entry, "kind": "description", "text": "Fake.",
                                                            "urls": []}],
                                               "manifest": {"model": "m", "version": "v20"}}),
    }


@pytest.fixture()
def full_track20(tracks, monkeypatch):
    monkeypatch.delenv("TTP_HIGH_THRESHOLD", raising=False)
    monkeypatch.delenv("TTP_MEDIUM_THRESHOLD", raising=False)
    monkeypatch.delenv("TTP_SEMANTIC_DOMAINS", raising=False)
    monkeypatch.setattr(stage2b_gazetteer, "promoted_entries", list)    # no analyst rows from the store
    track = _track(tracks, files=_loader_files())
    monkeypatch.setenv("ATTACK_RELEASE", "20.0")
    return track


def test_mitre_db_reads_the_selected_track(select20):
    assert [t["id"] for t in mitre_db.get_techniques()] == ["T9999"]
    assert mitre_db.available() is True
    assert mitre_db.lookup_by_id("t9999")["name"] == "Fake Technique"


def test_mitre_db_reads_the_shipped_index_by_default(clean_caches):
    if not mitre_db.available():
        pytest.skip("pipeline/data/mitre_index.json not built")
    assert "T9999" not in {t["id"] for t in mitre_db.get_techniques()}
    assert mitre_db.lookup_by_id("T1566.001") is not None


def test_every_loader_reads_the_selected_track(full_track20):
    assert mitre_db.replacement_for("t0001") == "T9999"
    assert aliases.technique_name_for("T9999") == "Fake Technique"
    assert aliases.canonical_name("fakegroup", "threat-actor") == "Fake Group"
    assert aliases.mitre_id_for("Fake Group", "intrusion-set") == "G9999"
    assert [e["mitre_id"] for e in stage2b_gazetteer._load()] == ["G9999"]
    assert stage2b_gazetteer.available() is True
    assert s4b._attack_pairs() == {("G9999", "T9999"): "uses"}
    embeddings, meta = s2c._load_corpus()
    assert embeddings.shape == (1, 4) and [m["id"] for m in meta] == ["T9999"]
    assert s2c._thresholds() == (0.91, 0.81)
    corpus = ttp_retrieval.load_corpus("both")
    assert corpus.ids == ["T9999"] and corpus.version.startswith("v20")


def test_a_file_the_track_lacks_is_missing_not_the_shipped_one(select20):
    assert stage2b_gazetteer.available() is False
    assert stage2b_gazetteer._load() == []
    assert aliases.canonical_name("APT29") == "APT29"
    assert s4b._attack_pairs() == {}
    assert s2c._load_corpus() is None
    assert ttp_retrieval.load_corpus("both") is None


# The loaders resolve outside their try: most of them catch ValueError, which
# UnknownAttackRelease is, and would have run the stage on no data at all.
_LOADERS = {
    "mitre_db.get_techniques": mitre_db.get_techniques,
    "mitre_db.available": mitre_db.available,
    "mitre_db.replacement_for": lambda: mitre_db.replacement_for("T0001"),
    "aliases.canonical_name": lambda: aliases.canonical_name("APT29"),
    "aliases.technique_id_for": lambda: aliases.technique_id_for("Phishing"),
    "stage2b.load": stage2b_gazetteer._load,
    "stage2b.available": stage2b_gazetteer.available,
    "stage2c.load_corpus": s2c._load_corpus,
    "stage2c.thresholds": s2c._thresholds,
    "stage3f.definitions": s3f._definitions,
    "stage4b.attack_pairs": s4b._attack_pairs,
    "ttp_retrieval.load_corpus": lambda: ttp_retrieval.load_corpus("both"),
}


@pytest.mark.parametrize("call", _LOADERS.values(), ids=list(_LOADERS))
def test_a_loader_does_not_swallow_an_unknown_release(tracks, monkeypatch, call):
    monkeypatch.setenv("ATTACK_RELEASE", "21.0")
    with pytest.raises(attack_data.UnknownAttackRelease):
        call()
