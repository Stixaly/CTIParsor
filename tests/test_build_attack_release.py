"""scripts/build_attack_release.py: a release track built from small synthetic
bundles (ADR-0087), and every way the script refuses to build one.

The bundles hold a few techniques, a group, some software, `uses` and
`revoked-by` relationships in each of Enterprise, Mobile and ICS; nothing
reads the real ATT&CK files.  The encoder is a fake, or skipped.
"""
from __future__ import annotations

import hashlib
import json
import re
import subprocess
import sys
import types
from pathlib import Path

import pytest

from pipeline import attack_data
from scripts import build_attack_release as bar
from scripts import build_indexes

URL = "https://github.com/mitre-attack/attack-stix-data/releases/download/v20.0"


def ref(source: str, external_id: str) -> list[dict]:
    return [{"source_name": source, "external_id": external_id}]


def technique(key: str, external_id: str, name: str, source: str = "mitre-attack", **extra) -> dict:
    return {"type": "attack-pattern", "id": f"attack-pattern--{key}", "name": name,
            "description": f"{name} is how adversaries do it. (Citation: Some Report) More text follows.",
            "external_references": ref(source, external_id),
            "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "execution"}],
            "x_mitre_is_subtechnique": False, **extra}


def relationship(key: str, verb: str, source: str, target: str, description: str = "") -> dict:
    rel = {"type": "relationship", "id": f"relationship--{key}", "relationship_type": verb,
           "source_ref": source, "target_ref": target}
    return {**rel, "description": description} if description else rel


def collection(version: str, modified: str) -> dict:
    return {"type": "x-mitre-collection", "id": "x-mitre-collection--1", "x_mitre_version": version,
            "modified": modified, "name": "ATT&CK"}


def bundles(version: str = "20.0") -> dict[str, list[dict]]:
    enterprise = [
        collection(version, "2026-10-13T17:53:10.145Z"),
        {"type": "x-mitre-tactic", "id": "x-mitre-tactic--1", "name": "Execution",
         "x_mitre_shortname": "execution", "external_references": ref("mitre-attack", "TA0002")},
        technique("a", "T1059", "Command and Scripting Interpreter"),
        technique("b", "T1059.001", "PowerShell", x_mitre_is_subtechnique=True),
        technique("c", "T1001", "Old Technique", revoked=True),
        {"type": "intrusion-set", "id": "intrusion-set--g1", "name": "Test Group",
         "aliases": ["Test Group", "Group Alpha"], "external_references": ref("mitre-attack", "G0001")},
        {"type": "malware", "id": "malware--s1", "name": "TestMalware", "x_mitre_aliases": ["TestMalware"],
         "external_references": ref("mitre-attack", "S0001")},
        relationship("1", "uses", "intrusion-set--g1", "attack-pattern--b",
                     "Test Group ran encoded commands through PowerShell on victim hosts."),
        relationship("2", "uses", "malware--s1", "attack-pattern--a",
                     "TestMalware executes commands through the system shell interpreter."),
        relationship("3", "revoked-by", "attack-pattern--c", "attack-pattern--a"),
    ]
    mobile = [
        collection(version, "2026-10-13T17:54:40.393Z"),
        technique("m1", "T1400", "Mobile Thing", "mitre-mobile-attack"),
        technique("m2", "T1401", "Old Mobile Thing", "mitre-mobile-attack", revoked=True),
        {"type": "malware", "id": "malware--s2", "name": "MobileMalware", "x_mitre_aliases": ["MobileMalware"],
         "external_references": ref("mitre-mobile-attack", "S1000")},
        relationship("4", "uses", "malware--s2", "attack-pattern--m1",
                     "MobileMalware reads the address book of the device."),
        relationship("5", "revoked-by", "attack-pattern--m2", "attack-pattern--m1"),
    ]
    ics = [
        collection(version, "2026-10-13T17:54:18.154Z"),
        technique("i1", "T0800", "Industrial Thing", "mitre-ics-attack"),
    ]
    return {"enterprise-attack": enterprise, "mobile-attack": mobile, "ics-attack": ics}


CAPEC = {"id": "CAPEC-1", "name": "Accessing Functionality Not Properly Constrained by ACLs",
         "domain": "capec", "tactics": [], "is_subtechnique": False, "parent_id": None,
         "description": "In applications, particular access control is applied.",
         "shortname": "accessing-functionality-not-properly-constrained-by-acls"}


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def make_stix(root: Path, version: str = "20.0", collection_version: str | None = None) -> Path:
    """The three bundles and the release.json download_attack.py writes beside them."""
    stix = root / "stix"
    stix.mkdir()
    assets = []
    for domain, objects in bundles(collection_version or version).items():
        path = stix / f"{domain}.json"
        path.write_text(json.dumps({"type": "bundle", "id": "bundle--1", "objects": objects}), encoding="utf-8")
        assets.append({"name": path.name, "size": path.stat().st_size, "digest": f"sha256:{sha(path)}",
                       "url": f"{URL}/{path.name}"})
    (stix / "release.json").write_text(json.dumps({
        "repository": "mitre-attack/attack-stix-data", "tag": f"v{version}", "name": f"ATT&CK version {version}",
        "published_at": "2026-10-13T18:00:00Z", "html_url": "https://example.test/release",
        "fetched_at": "2026-10-18T10:00:00+00:00", "assets": assets}), encoding="utf-8")
    return stix


def make_capec_index(root: Path, n: int = 2) -> Path:
    path = root / "capec_index.json"
    capec = [{**CAPEC, "id": f"CAPEC-{i + 1}"} for i in range(n)]
    other = {**CAPEC, "id": "T9999", "domain": "enterprise-attack"}      # not CAPEC: not carried over
    path.write_text(json.dumps({"techniques": [*capec, other], "tactics": []}), encoding="utf-8")
    return path


@pytest.fixture
def env(monkeypatch, tmp_path):
    """The bundles, the CAPEC index and an output path, with the process
    environment (.env, the embedding model) kept out of the build."""
    monkeypatch.setattr("dotenv.load_dotenv", lambda *a, **k: False)
    monkeypatch.delenv("TTP_EMBEDDING_MODEL", raising=False)
    return types.SimpleNamespace(root=tmp_path, stix=make_stix(tmp_path), capec=make_capec_index(tmp_path),
                                 out=tmp_path / "attack" / "20.0")


def run(env, *extra: str, release: str = "20.0", skip: bool = True) -> int:
    argv = ["--release", release, "--stix-dir", str(env.stix), "--out-dir", str(env.out),
            "--capec-index", str(env.capec), *extra]
    return bar.main([*argv, "--skip-embeddings"] if skip else argv)


def track(out: Path) -> attack_data.Release:
    return attack_data.Release("20.0", out, False, json.loads((out / "attack_manifest.json").read_text("utf-8")))


def load(out: Path, name: str):
    return json.loads((out / name).read_text(encoding="utf-8"))


def test_the_files_of_a_track_are_built_from_the_three_domains(env, capsys):
    assert run(env) == 0

    assert sorted(p.name for p in env.out.iterdir()) == [
        "attack_manifest.json", "attack_relationships.json", "attack_retrieval_corpus.json",
        "attack_revoked.json", "gazetteer.json", "mitre_index.json"]

    techniques = {t["id"]: t for t in load(env.out, "mitre_index.json")["techniques"]}
    assert sorted(techniques) == ["CAPEC-1", "CAPEC-2", "T0800", "T1059", "T1059.001", "T1400"]   # not T1001, T9999
    assert techniques["T1059.001"]["parent_id"] == "T1059"
    assert techniques["T1400"]["domain"] == "mobile-attack"
    assert techniques["T0800"]["domain"] == "ics-attack"
    assert techniques["CAPEC-2"] == {**CAPEC, "id": "CAPEC-2"}                  # carried over as it was
    assert [t["id"] for t in load(env.out, "mitre_index.json")["tactics"]] == ["TA0002"]

    gazetteer = {e["name"]: e for e in load(env.out, "gazetteer.json")}
    assert gazetteer["group alpha"]["canonical"] == "Test Group"
    assert gazetteer["group alpha"]["mitre_id"] == "G0001"
    assert gazetteer["mobilemalware"]["domain"] == "mobile-attack"

    relationships = load(env.out, "attack_relationships.json")
    assert relationships["generated_from"] == ["enterprise-attack", "ics-attack", "mobile-attack"]
    assert ["G0001", "uses", "T1059.001"] in relationships["pairs"]
    assert ["S1000", "uses", "T1400"] in relationships["pairs"]

    summary = capsys.readouterr().out
    assert "retrieval corpus" in summary and "curated pairs" in summary
    assert "enterprise-attack" in summary and "mobile-attack" in summary and "ics-attack" in summary


def test_revoked_and_retrieval_are_enterprise_only(env):
    assert run(env) == 0

    revoked = load(env.out, "attack_revoked.json")
    assert revoked["revoked_by"] == {"T1001": "T1059"}               # not Mobile's T1401
    assert list(revoked["sources"]) == ["enterprise-attack.json"]

    corpus = load(env.out, "attack_retrieval_corpus.json")
    assert {e["domain"] for e in corpus["entries"]} == {"enterprise-attack"}
    assert {e["id"] for e in corpus["entries"]} == {"T1059", "T1059.001"}
    assert corpus["manifest"]["neutralise_names"] is True
    procedure = next(e for e in corpus["entries"] if e["kind"] == "procedure" and e["id"] == "T1059.001")
    assert "Test Group" not in procedure["text"]                     # the actor's name is a placeholder


def test_the_manifest_describes_the_track(env):
    assert run(env) == 0

    manifest = load(env.out, "attack_manifest.json")
    assert list(manifest) == ["release", "track", "built_at", "built_with", "sources", "capec",
                              "retrieval_domains", "revoked_domains", "exceptions", "files"]
    assert manifest["release"] == "20.0"
    assert manifest["track"] == "release"
    assert manifest["built_at"]
    assert list(manifest["built_with"]) == ["script", "git_rev", "embedding_model", "embeddings"]
    assert manifest["built_with"]["script"] == "scripts/build_attack_release.py"
    assert manifest["built_with"]["git_rev"] is None or re.fullmatch(r"[0-9a-f]{40}", manifest["built_with"]["git_rev"])
    assert manifest["built_with"]["embedding_model"] is None
    assert manifest["built_with"]["embeddings"] == "skipped"

    assert [list(s) for s in manifest["sources"]] == [
        ["domain", "file", "url", "sha256", "published_digest", "collection_version", "collection_modified"]] * 3
    assert [s["domain"] for s in manifest["sources"]] == ["enterprise-attack", "mobile-attack", "ics-attack"]
    enterprise = manifest["sources"][0]
    path = env.stix / "enterprise-attack.json"
    assert enterprise["file"] == "enterprise-attack.json"            # outside the repository: the name alone
    assert enterprise["url"] == f"{URL}/enterprise-attack.json"
    assert enterprise["sha256"] == sha(path)
    assert enterprise["published_digest"] == f"sha256:{sha(path)}"
    assert enterprise["collection_version"] == "20.0"
    assert enterprise["collection_modified"] == "2026-10-13T17:53:10.145Z"

    assert manifest["capec"] == {"carried_from": "capec_index.json", "sha256": sha(env.capec), "entries": 2}
    assert manifest["retrieval_domains"] == ["enterprise-attack"]
    assert manifest["revoked_domains"] == ["enterprise-attack"]
    assert manifest["exceptions"] == {"mitre_index.json (CAPEC)": (
        "the 2 CAPEC entries are the default track's, carried over: CAPEC is not part of ATT&CK, "
        "so the two tracks differ by ATT&CK only")}
    assert sorted(manifest["files"]) == sorted(p.name for p in env.out.iterdir() if p.name != "attack_manifest.json")
    assert all(sha(env.out / name) == digest for name, digest in manifest["files"].items())
    assert attack_data.modified_files(track(env.out)) == []
    assert str(env.root) not in (env.out / "attack_manifest.json").read_text(encoding="utf-8")


def test_a_path_is_written_from_the_repository_root_or_as_its_name_alone(tmp_path):
    assert bar._rel(bar._ROOT / "data" / "attack-stix" / "v20.0" / "ics-attack.json") == \
        "data/attack-stix/v20.0/ics-attack.json"
    assert bar._rel(tmp_path / "somewhere" / "ics-attack.json") == "ics-attack.json"


def test_the_git_revision_falls_back_on_the_build_stamp_when_git_cannot_say(monkeypatch):
    rev, stamp = "cd" * 20, "ab" * 20

    def git(returncode=0, stdout=f"{rev}\n", error=None):
        def run(*args, **kwargs):
            if error:
                raise error
            return types.SimpleNamespace(returncode=returncode, stdout=stdout)
        return run

    monkeypatch.setenv("CTIPARSOR_GIT_REV", f" {stamp}\n")
    monkeypatch.setattr(bar.subprocess, "run", git())
    assert bar._git_rev() == rev                                  # git wins over a stale variable
    for broken in (git(error=FileNotFoundError("git")), git(error=subprocess.TimeoutExpired("git", 10)),
                   git(returncode=128, stdout=""), git(stdout="\n")):
        monkeypatch.setattr(bar.subprocess, "run", broken)
        assert bar._git_rev() == stamp
    monkeypatch.delenv("CTIPARSOR_GIT_REV")
    assert bar._git_rev() is None
    monkeypatch.setenv("CTIPARSOR_GIT_REV", "  ")
    assert bar._git_rev() is None


def test_the_manifest_records_the_build_stamp_when_there_is_no_git(env, monkeypatch):
    def no_git(*args, **kwargs):
        raise FileNotFoundError("git")

    monkeypatch.setattr(bar.subprocess, "run", no_git)
    monkeypatch.setenv("CTIPARSOR_GIT_REV", "ab" * 20)
    assert run(env) == 0
    assert load(env.out, "attack_manifest.json")["built_with"]["git_rev"] == "ab" * 20


def test_a_track_attack_data_can_use_is_what_the_build_leaves(env):
    assert run(env) == 0

    assert not [p for p in env.out.parent.iterdir() if p.name != "20.0"]     # no .building, no .previous
    assert attack_data.modified_files(track(env.out)) == []
    (env.out / "gazetteer.json").write_text("[]", encoding="utf-8")           # a local rebuild is noticed
    assert attack_data.modified_files(track(env.out)) == ["gazetteer.json"]


def encoder(monkeypatch, model: str = "fake-model") -> list[str]:
    """A sentence_transformers whose model gives every text a vector of length 4."""
    np = pytest.importorskip("numpy")
    loaded: list[str] = []

    class Fake:
        def __init__(self, name):
            loaded.append(name)

        def encode(self, texts, batch_size=64, show_progress_bar=False, convert_to_numpy=True):
            return np.arange(len(texts) * 4, dtype=np.float32).reshape(len(texts), 4)

    module = types.ModuleType("sentence_transformers")
    module.SentenceTransformer = Fake       # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "sentence_transformers", module)
    monkeypatch.setenv("TTP_EMBEDDING_MODEL", model)
    return loaded


def test_the_default_model_is_built_without_an_embeddings_manifest(env, monkeypatch):
    np = pytest.importorskip("numpy")
    loaded = encoder(monkeypatch, "all-MiniLM-L6-v2")

    assert run(env, skip=False) == 0

    assert sorted(p.name for p in env.out.iterdir()) == sorted(
        [*attack_data.ATTACK_FILES - {"mitre_embeddings_manifest.json"}, "attack_manifest.json"])
    assert not (env.out / "mitre_embeddings_manifest.json").exists()    # the default track has none either
    index = load(env.out, "mitre_index.json")["techniques"]
    assert np.load(env.out / "mitre_embeddings.npy").shape == (len(index), 4)
    assert [m["id"] for m in load(env.out, "mitre_embeddings_meta.json")] == [t["id"] for t in index]
    corpus = load(env.out, "attack_retrieval_corpus.json")["entries"]
    assert np.load(env.out / "attack_retrieval_embeddings.npy").shape == (len(corpus), 4)
    assert set(loaded) == {"all-MiniLM-L6-v2"}

    manifest = load(env.out, "attack_manifest.json")
    assert manifest["built_with"]["embedding_model"] == "all-MiniLM-L6-v2"
    assert "embeddings" not in manifest["built_with"]
    assert set(manifest["files"]) == attack_data.ATTACK_FILES - {"mitre_embeddings_manifest.json"}
    assert attack_data.modified_files(track(env.out)) == []


def test_another_model_gets_the_embeddings_manifest_stage2c_reads(env, monkeypatch):
    """Without it Stage 2c would take the track's vectors for the default model's and its thresholds."""
    pytest.importorskip("numpy")
    loaded = encoder(monkeypatch)

    assert run(env, skip=False) == 0

    assert sorted(p.name for p in env.out.iterdir()) == sorted([*attack_data.ATTACK_FILES, "attack_manifest.json"])
    index = load(env.out, "mitre_index.json")["techniques"]
    assert load(env.out, "mitre_embeddings_manifest.json") == {
        "model": "fake-model", "dims": 4, "num_techniques": len(index),
        "thresholds": {"high": 0.62, "medium": 0.48}}
    assert set(loaded) == {"fake-model"}
    manifest = load(env.out, "attack_manifest.json")
    assert manifest["built_with"]["embedding_model"] == "fake-model"
    assert set(manifest["files"]) == set(attack_data.ATTACK_FILES)
    assert attack_data.modified_files(track(env.out)) == []


def test_another_model_without_an_encoder_leaves_no_embeddings_manifest(env, monkeypatch):
    monkeypatch.setenv("TTP_EMBEDDING_MODEL", "fake-model")

    assert run(env) == 0                                                  # --skip-embeddings

    assert not (env.out / "mitre_embeddings_manifest.json").exists()
    assert load(env.out, "attack_manifest.json")["built_with"]["embedding_model"] is None
    assert attack_data.modified_files(track(env.out)) == []


def test_without_an_encoder_there_is_no_track(env, monkeypatch, capsys):
    monkeypatch.setitem(sys.modules, "sentence_transformers", None)       # import fails

    assert run(env, skip=False) == 1

    assert "sentence-transformers" in capsys.readouterr().err
    assert not env.out.parent.exists() or not list(env.out.parent.iterdir())


def test_a_wrong_digest_in_release_json_is_refused_and_nothing_is_left(env, capsys):
    release = load(env.stix, "release.json")
    release["assets"][1]["digest"] = "sha256:" + "0" * 64
    (env.stix / "release.json").write_text(json.dumps(release), encoding="utf-8")

    assert run(env) == 1

    assert "mobile-attack.json" in capsys.readouterr().err
    assert not env.out.parent.exists()


def test_a_bundle_that_is_not_the_published_file_is_refused(env, capsys):
    path = env.stix / "ics-attack.json"
    path.write_text(path.read_text(encoding="utf-8") + " ", encoding="utf-8")

    assert run(env) == 1

    assert "ics-attack.json" in capsys.readouterr().err
    assert not env.out.parent.exists()


def test_a_release_json_without_a_digest_is_refused(env):
    release = load(env.stix, "release.json")
    del release["assets"][0]["digest"]
    (env.stix / "release.json").write_text(json.dumps(release), encoding="utf-8")

    assert run(env) == 1
    assert not env.out.parent.exists()


def test_a_collection_of_another_release_is_refused(tmp_path, env, capsys):
    other = tmp_path / "other"
    other.mkdir()
    env.stix = make_stix(other, version="20.0", collection_version="19.2")       # digests right, content 19.2

    assert run(env) == 1

    err = capsys.readouterr().err
    assert "19.2" in err and "20.0" in err
    assert not env.out.parent.exists()


def test_a_release_that_is_not_x_dot_y_is_refused(env, capsys):
    for release in ("v20.0", "20", "\u0662\u0660.\u0660"):           # the last in Arabic-Indic digits
        assert run(env, release=release) == 1
        assert "is not an ATT&CK release" in capsys.readouterr().err
    assert not env.out.parent.exists()


def test_a_missing_release_json_says_how_to_download(env, capsys):
    (env.stix / "release.json").unlink()

    assert run(env) == 1

    assert "python scripts/download_attack.py --release 20.0" in capsys.readouterr().err
    assert not env.out.parent.exists()


def test_a_missing_bundle_is_refused(env):
    (env.stix / "mobile-attack.json").unlink()

    assert run(env) == 1
    assert not env.out.parent.exists()


def test_an_index_without_capec_is_refused(env):
    env.capec.write_text(json.dumps({"techniques": [{**CAPEC, "id": "T1", "domain": "mobile-attack"}]}),
                         encoding="utf-8")

    assert run(env) == 1
    assert not env.out.parent.exists()


def test_an_existing_track_is_not_overwritten_without_force(env, capsys):
    assert run(env) == 0
    before = {p.name: p.read_bytes() for p in env.out.iterdir()}

    assert run(env) == 1

    assert "--force" in capsys.readouterr().err
    assert {p.name: p.read_bytes() for p in env.out.iterdir()} == before


def test_force_replaces_the_track(env):
    assert run(env) == 0
    make_capec_index(env.root, n=3)

    assert run(env, "--force") == 0

    assert load(env.out, "attack_manifest.json")["capec"]["entries"] == 3
    assert len([t for t in load(env.out, "mitre_index.json")["techniques"] if t["domain"] == "capec"]) == 3
    assert attack_data.modified_files(track(env.out)) == []
    assert [p.name for p in env.out.parent.iterdir()] == ["20.0"]


def test_a_failed_build_leaves_no_track_and_keeps_the_old_one(env, monkeypatch):
    def broken(*args, **kwargs):
        raise RuntimeError("the gazetteer builder broke")

    with monkeypatch.context() as m:
        m.setattr(build_indexes, "build_gazetteer", broken)
        with pytest.raises(RuntimeError):
            run(env)
    assert list(env.out.parent.iterdir()) == []          # no 20.0, no .building: attack_data finds nothing

    assert run(env) == 0
    before = {p.name: p.read_bytes() for p in env.out.iterdir()}
    with monkeypatch.context() as m:
        m.setattr(build_indexes, "build_gazetteer", broken)
        with pytest.raises(RuntimeError):
            run(env, "--force")
    assert {p.name: p.read_bytes() for p in env.out.iterdir()} == before
    assert [p.name for p in env.out.parent.iterdir()] == ["20.0"]


def test_the_builders_write_where_they_are_told_and_by_default_to_pipeline_data(tmp_path, monkeypatch):
    paths: dict[str, Path | None] = {"enterprise": make_stix(tmp_path) / "enterprise-attack.json"}
    builders = (build_indexes.build_mitre_index, build_indexes.build_gazetteer,
                build_indexes.build_attack_relationships, build_indexes.build_revoked)
    names = ["attack_relationships.json", "attack_revoked.json", "gazetteer.json", "mitre_index.json"]

    for build in builders:
        build(paths, tmp_path / "elsewhere")
    assert sorted(p.name for p in (tmp_path / "elsewhere").iterdir()) == names
    assert [t["id"] for t in load(tmp_path / "elsewhere", "mitre_index.json")["techniques"]] == ["T1059", "T1059.001"]

    monkeypatch.setattr(build_indexes, "_DATA_DIR", tmp_path / "default")
    for build in builders:
        build(paths)
    assert sorted(p.name for p in (tmp_path / "default").iterdir()) == names
    for name in names:
        assert (tmp_path / "default" / name).read_bytes() == (tmp_path / "elsewhere" / name).read_bytes()
