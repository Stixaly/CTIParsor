"""Retrieval covers the three ATT&CK domains (issue #979): the corpus the select path
searches, the revoked-technique table, and the domains Stage 2c reports as queried.

Small synthetic bundles, no encoder (embed=False, the retrievers are not built);
nothing reads the real ATT&CK files.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from pipeline import ttp_retrieval as tr
from pipeline.ttp_retrieval import TtpCandidate
from scripts import build_indexes

ALL = ["enterprise-attack", "ics-attack", "mobile-attack"]


def ref(source: str, external_id: str) -> list[dict]:
    return [{"source_name": source, "external_id": external_id}]


def technique(key: str, external_id: str, name: str, source: str = "mitre-attack", **extra) -> dict:
    return {"type": "attack-pattern", "id": f"attack-pattern--{key}", "name": name,
            "description": f"{name} is how adversaries do it. (Citation: Some Report) More text follows.",
            "external_references": ref(source, external_id), **extra}


def relationship(key: str, verb: str, source: str, target: str, description: str = "") -> dict:
    rel = {"type": "relationship", "id": f"relationship--{key}", "relationship_type": verb,
           "source_ref": source, "target_ref": target}
    return {**rel, "description": description} if description else rel


def write_bundle(path: Path, objects: list[dict]) -> Path:
    path.write_text(json.dumps({"type": "bundle", "id": "bundle--1", "objects": objects}), encoding="utf-8")
    return path


@pytest.fixture
def domains(tmp_path, monkeypatch) -> dict[str, Path]:
    """One bundle per domain, each with a technique and a `uses` example, and the
    process environment that could change the retrieval kept out."""
    monkeypatch.setattr("dotenv.load_dotenv", lambda *a, **k: False)
    for name in ("TTP_SEMANTIC_DOMAINS", "TTP_RETRIEVAL_CORPUS", "TTP_RETRIEVAL_EXCLUDE_CITED"):
        monkeypatch.delenv(name, raising=False)
    return {
        "enterprise": write_bundle(tmp_path / "enterprise-attack.json", [
            technique("a", "T1059", "Command and Scripting Interpreter"),
            {"type": "malware", "id": "malware--e", "name": "EnterpriseMalware",
             "external_references": ref("mitre-attack", "S0001")},
            relationship("1", "uses", "malware--e", "attack-pattern--a",
                         "EnterpriseMalware runs commands through the system shell."),
        ]),
        "mobile": write_bundle(tmp_path / "mobile-attack.json", [
            technique("m1", "T1400", "Mobile Thing", "mitre-mobile-attack"),
            {"type": "malware", "id": "malware--s2", "name": "MobileMalware",
             "external_references": ref("mitre-mobile-attack", "S1000")},
            relationship("2", "uses", "malware--s2", "attack-pattern--m1",
                         "MobileMalware reads the address book of the device."),
        ]),
        "ics": write_bundle(tmp_path / "ics-attack.json", [
            technique("i1", "T0800", "Industrial Thing", "mitre-ics-attack"),
        ]),
    }


def corpus_path(tmp_path: Path, domains: dict[str, Path]) -> Path:
    build_indexes.build_retrieval(domains, out_dir=tmp_path / "out", embed=False)
    return tmp_path / "out" / "attack_retrieval_corpus.json"


def test_the_corpus_holds_the_three_domains_and_names_each_entry(tmp_path, domains):
    path = corpus_path(tmp_path, domains)

    data = json.loads(path.read_text(encoding="utf-8"))
    assert {e["domain"] for e in data["entries"]} == set(ALL)
    assert {e["id"]: e["domain"] for e in data["entries"]} == {
        "T1059": "enterprise-attack", "T1400": "mobile-attack", "T0800": "ics-attack"}
    assert [s["bundle"] for s in data["manifest"]["sources"]] == [
        "enterprise-attack.json", "mobile-attack.json", "ics-attack.json"]


def test_the_select_domains_restrict_the_loaded_corpus(tmp_path, domains, monkeypatch):
    path = corpus_path(tmp_path, domains)
    absent = tmp_path / "absent.npy"
    tr._built_corpus.cache_clear()
    assert set(tr.load_corpus("both", path=path, emb_path=absent).domains) == set(ALL)

    monkeypatch.setenv("TTP_SEMANTIC_DOMAINS", "enterprise-attack")
    tr._built_corpus.cache_clear()
    only = tr.load_corpus("both", path=path, emb_path=absent)
    assert set(only.domains) == {"enterprise-attack"}
    assert set(only.ids) == {"T1059"}


def test_a_mobile_revoked_id_is_in_the_revoked_by_table(tmp_path):
    enterprise = write_bundle(tmp_path / "enterprise-attack.json", [
        technique("e1", "T1685", "Disable or Modify Tools"),
        technique("e2", "T1562", "Impair Defenses", revoked=True),
        relationship("1", "revoked-by", "attack-pattern--e2", "attack-pattern--e1"),
    ])
    mobile = write_bundle(tmp_path / "mobile-attack.json", [
        technique("m1", "T1400", "Mobile Thing", "mitre-mobile-attack"),
        technique("m2", "T1401", "Old Mobile Thing", "mitre-mobile-attack", revoked=True),
        relationship("2", "revoked-by", "attack-pattern--m2", "attack-pattern--m1"),
    ])

    build_indexes.build_revoked({"enterprise": enterprise, "mobile": mobile}, tmp_path / "out")

    built = json.loads((tmp_path / "out" / "attack_revoked.json").read_text(encoding="utf-8"))
    assert built["revoked_by"] == {"T1401": "T1400", "T1562": "T1685"}
    assert built["names"] == {"impair defenses": "T1685"}       # the names are Enterprise's only


def test_a_mobile_active_name_does_not_hide_a_revoked_enterprise_name_issue_464(tmp_path):
    # Enterprise T1562 "Impair Defenses" is revoked for T1685; Mobile T1629 bears the same name.
    enterprise = write_bundle(tmp_path / "enterprise-attack.json", [
        technique("e1", "T1685", "Disable or Modify Tools"),
        technique("e2", "T1562", "Impair Defenses", revoked=True),
        relationship("1", "revoked-by", "attack-pattern--e2", "attack-pattern--e1"),
    ])
    mobile = write_bundle(tmp_path / "mobile-attack.json", [
        technique("m1", "T1629", "Impair Defenses", "mitre-mobile-attack"),
    ])

    build_indexes.build_revoked({"enterprise": enterprise, "mobile": mobile}, tmp_path / "out")

    built = json.loads((tmp_path / "out" / "attack_revoked.json").read_text(encoding="utf-8"))
    assert built["names"]["impair defenses"] == "T1685"
    assert built["revoked_by"]["T1562"] == "T1685"

    # The control: naming Mobile's bundle among the names' bundles brings the masking back.
    build_indexes.build_revoked({"enterprise": enterprise, "mobile": mobile}, tmp_path / "masked",
                                names_from=("enterprise", "mobile"))
    masked = json.loads((tmp_path / "masked" / "attack_revoked.json").read_text(encoding="utf-8"))
    assert "impair defenses" not in masked["names"]
    assert masked["revoked_by"]["T1562"] == "T1685"


def test_retrieval_domains_are_the_domains_of_the_corpus_the_select_path_reads(tmp_path, domains,
                                                                             monkeypatch):
    path = corpus_path(tmp_path, domains)
    built = tr._built_corpus.__wrapped__(str(path), str(tmp_path / "absent.npy"))
    monkeypatch.setattr(tr, "_built_corpus", lambda p, e: built)
    assert tr.retrieval_domains() == ALL

    monkeypatch.setenv("TTP_SEMANTIC_DOMAINS", "enterprise-attack,mobile-attack")
    assert tr.retrieval_domains() == ["enterprise-attack", "mobile-attack"]

    monkeypatch.setattr(tr, "_built_corpus", lambda p, e: None)
    assert tr.retrieval_domains() == []


def test_stage_2c_reports_the_domains_it_queried(tmp_path, domains, monkeypatch, mock_llm_response,
                                                 sample_cti_text):
    monkeypatch.setenv("TTP_RETRIEVAL_DOMAINS", "all")      # every domain, whatever the report says
    from pipeline import stage3_llm as s3
    from pipeline import stage3f_ttp_select as sel
    from pipeline.orchestrator import Document, RunOptions, run_document

    path = corpus_path(tmp_path, domains)
    built = tr._built_corpus.__wrapped__(str(path), str(tmp_path / "absent.npy"))
    monkeypatch.setattr(tr, "_built_corpus", lambda p, e: built)
    monkeypatch.setattr(tr, "retrieval_available", lambda: True)
    monkeypatch.setattr(tr, "candidates_for_chunks", lambda chunks: [
        [TtpCandidate(attack_id="T1190", name="Exploit Public-Facing Application", sources=["bm25"],
                      passage="CVE-2020-10148 was exploited for initial access.")] for _ in chunks])

    def fake(system, user, provider=None, max_output_tokens=None):
        if system.startswith(sel._SELECT_SYSTEM):
            return '{"selected": []}'
        return json.dumps(mock_llm_response)
    monkeypatch.setattr(s3, "_call_llm", fake)

    result = run_document(Document(text=sample_cti_text, original_filename="r.txt"), RunOptions(
        consensus=False, document_relations=False, llm_parallelism=1, verify_relationships=False,
        ttp_mode="select", verify_ttps=True, disabled=frozenset({"2f", "4", "5"})))
    s2c = result.outcome("2c")
    assert s2c.status == "ran"
    assert s2c.details["retrieval_domains"] == ALL


# ── Which domains a report queries (TTP_RETRIEVAL_DOMAINS=auto) ──────────────

@pytest.mark.parametrize("text, expected", [
    ("Infamous Chisel targets Android devices; the Android implant reads SMS.", ALL[:1] + ["mobile-attack"]),
    ("The spyware reaches iOS and Android phones.", ALL[:1] + ["mobile-attack"]),
    ("One Android phone was seen.", ALL[:1]),                       # a single cue is no mobile report
    ("Cisco IOS XE and IOS routers were exploited.", ALL[:1]),      # Cisco IOS is not Apple iOS
    ("The ICS network: the PLC logic was changed over Modbus.", ALL[:1] + ["ics-attack"]),
    ("The physics of the attack and the topics it covers.", ALL[:1]),  # "ics" inside words
    ("An ordinary report about phishing and Cobalt Strike.", ALL[:1]),
])
def test_a_report_queries_mobile_or_ics_only_when_it_names_them(text, expected):
    assert list(tr.document_domains(text)) == expected


@pytest.mark.parametrize("setting, expected", [
    ("auto", ("enterprise-attack", "mobile-attack")),
    ("all", ()),
    ("ics-attack,enterprise-attack", ("enterprise-attack", "ics-attack")),
])
def test_the_setting_chooses_the_domain_set(monkeypatch, setting, expected):
    monkeypatch.setenv("TTP_RETRIEVAL_DOMAINS", setting)
    assert tr._query_domains(["An Android implant.", "The Android app."]) == expected


def test_candidates_are_retrieved_from_the_report_s_domains(monkeypatch):
    asked = []
    monkeypatch.setenv("TTP_RETRIEVAL_DOMAINS", "auto")
    monkeypatch.setattr(tr, "_current_retriever", lambda *a: asked.append(a[3]))
    assert tr.candidates_for_chunks(["The PLC and the HMI were reached over Modbus."]) == [[]]
    assert asked == [("enterprise-attack", "ics-attack")]


def test_an_explicit_domain_set_narrows_the_corpus(tmp_path, domains, monkeypatch):
    monkeypatch.setenv("TTP_SEMANTIC_DOMAINS", ",".join(ALL))
    path, absent = corpus_path(tmp_path, domains), tmp_path / "absent.npy"
    only = tr.load_corpus("both", path=path, emb_path=absent, domains=("enterprise-attack", "ics-attack"))
    assert set(only.domains) == {"enterprise-attack", "ics-attack"}


@pytest.mark.parametrize("text, expected", [
    ("The banking trojan ships as APKs; the smartphones it reaches...", ALL[:1] + ["mobile-attack"]),
    ("Pegasus reached iPhones and iPads.", ALL[:1] + ["mobile-attack"]),
    ("Operators watched the HMIs while the PLCs were reprogrammed.", ALL[:1] + ["ics-attack"]),
    # MDM and SMS-based MFA are enterprise topics, not a mobile report.
    ("The MDM covers mobile devices; MFA codes go to mobile phones.", ALL[:1]),
])
def test_plural_and_enterprise_mobile_wording(text, expected):
    assert list(tr.document_domains(text)) == expected


def test_a_domain_list_accepts_short_names_and_says_an_unknown_one(monkeypatch, caplog):
    monkeypatch.setenv("TTP_RETRIEVAL_DOMAINS", "enterprise,mobile,cloud")
    with caplog.at_level("WARNING"):
        assert tr._query_domains(["text"]) == ("enterprise-attack", "mobile-attack")
    assert "'cloud', not an ATT&CK domain" in caplog.text


def test_a_list_with_no_domain_queries_every_enabled_one(monkeypatch, caplog):
    monkeypatch.setenv("TTP_RETRIEVAL_DOMAINS", "cloud")
    with caplog.at_level("WARNING"):
        assert tr._query_domains(["text"]) == ()
    assert "names no ATT&CK domain" in caplog.text


def test_a_weak_mobile_cue_counts_only_beside_a_strong_one():
    """APT44's report: one Android, two "mobile devices" -> a mobile report."""
    assert "mobile-attack" in tr.document_domains(
        "Infamous Chisel targets Android. The unit collects from mobile devices and mobile devices again.")
    assert "mobile-attack" not in tr.document_domains("MDM enrols mobile devices; mobile phones get codes.")
