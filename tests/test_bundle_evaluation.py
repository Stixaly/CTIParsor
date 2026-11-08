"""Scoring the bundle the release exports (ADR-0094 item 6): evaluation/bundle.py,
inhouse.score_bundle, `inhouse-score --from bundle` and `inhouse-compare`.
Hand-written bundles in tmp_path: no pipeline run, no model."""
from __future__ import annotations

import hashlib
import json
import sys

import pytest

from evaluation import __main__ as ev
from evaluation import bundle, inhouse
from evaluation.metrics import Counts

U = "00000000-0000-4000-8000-0000000000{:02d}"


def _id(kind: str, n: int) -> str:
    return f"{kind}--{U.format(n)}"


def _rel(n: int, src: str, rtype: str, tgt: str) -> dict:
    return {"type": "relationship", "id": _id("relationship", n), "relationship_type": rtype,
            "source_ref": src, "target_ref": tgt}


def _indicator(n: int, pattern: str, pattern_type: str = "stix") -> dict:
    return {"type": "indicator", "id": _id("indicator", n), "pattern": pattern,
            "pattern_type": pattern_type, "name": f"ind{n}"}


# ── projection ───────────────────────────────────────────────────────────────

def test_each_sco_type_maps_to_its_gold_type_and_file_hashes_are_split():
    objs = [
        {"type": "ipv4-addr", "id": _id("ipv4-addr", 1), "value": "1.2.3.4"},
        {"type": "ipv6-addr", "id": _id("ipv6-addr", 2), "value": "2001:db8::1"},
        {"type": "domain-name", "id": _id("domain-name", 3), "value": "evil.com"},
        {"type": "url", "id": _id("url", 4), "value": "http://evil.com/x"},
        {"type": "email-addr", "id": _id("email-addr", 5), "value": "a@evil.com"},
        {"type": "mac-addr", "id": _id("mac-addr", 6), "value": "00:11:22:33:44:55"},
        {"type": "mutex", "id": _id("mutex", 7), "name": "Global\\m"},
        {"type": "windows-registry-key", "id": _id("windows-registry-key", 8), "key": "HKLM\\Software\\X"},
        {"type": "autonomous-system", "id": _id("autonomous-system", 9), "number": 15169},
        {"type": "file", "id": _id("file", 10), "name": "a.exe",
         "hashes": {"MD5": "a" * 32, "SHA-1": "b" * 40, "SHA-256": "c" * 64, "SSDEEP": "3:abc"}},
        {"type": "user-account", "id": _id("user-account", 11), "user_id": "ignored"},
        {"type": "vulnerability", "id": _id("vulnerability", 12), "name": "cve-2021-44228"},
        {"type": "vulnerability", "id": _id("vulnerability", 13), "name": "Log4Shell",
         "external_references": [{"source_name": "cve", "external_id": "CVE-2021-45046"}]},
    ]
    got = {(i["type"], i["value"]) for i in bundle.project({"objects": objs})["iocs"]}
    assert got == {("ipv4", "1.2.3.4"), ("ipv6", "2001:db8::1"), ("domain", "evil.com"),
                   ("url", "http://evil.com/x"), ("email", "a@evil.com"), ("mac_addr", "00:11:22:33:44:55"),
                   ("mutex", "Global\\m"), ("registry_key", "HKLM\\Software\\X"), ("asn", "AS15169"),
                   ("file", "a.exe"), ("md5", "a" * 32), ("sha1", "b" * 40), ("sha256", "c" * 64),
                   ("cve", "CVE-2021-44228"), ("cve", "CVE-2021-45046")}


def test_entities_techniques_and_aliases():
    objs = [
        {"type": "threat-actor", "id": _id("threat-actor", 1), "name": "APT29", "aliases": ["Cozy Bear"]},
        {"type": "intrusion-set", "id": _id("intrusion-set", 2), "name": "Nobelium",
         "x_mitre_aliases": ["UNC2452", "Nobelium"]},
        {"type": "malware", "id": _id("malware", 3), "name": "SUNBURST"},
        {"type": "tool", "id": _id("tool", 4), "name": "Mimikatz"},
        {"type": "campaign", "id": _id("campaign", 5), "name": "SolarWinds"},
        {"type": "identity", "id": _id("identity", 6), "name": "Not an entity"},
        {"type": "attack-pattern", "id": _id("attack-pattern", 7), "name": "Phishing",
         "external_references": [{"source_name": "mitre-attack", "external_id": "T1566"},
                                 {"source_name": "capec", "external_id": "CAPEC-98"}]},
        {"type": "attack-pattern", "id": _id("attack-pattern", 8), "name": "Spearphishing Attachment",
         "external_references": [{"source_name": "mitre-attack", "external_id": "t1566.001"}]},
        {"type": "attack-pattern", "id": _id("attack-pattern", 9), "name": "Again",
         "external_references": [{"source_name": "mitre-attack", "external_id": "T1566"}]},
    ]
    p = bundle.project({"objects": objs})
    assert p["entities"] == [
        {"type": "threat_actor", "forms": ["APT29", "Cozy Bear"]},
        {"type": "threat_actor", "forms": ["Nobelium", "UNC2452"]},
        {"type": "malware", "forms": ["SUNBURST"]},
        {"type": "tool", "forms": ["Mimikatz"]},
        {"type": "campaign", "forms": ["SolarWinds"]},
    ]
    assert p["techniques"] == ["T1566", "T1566.001"]


def test_indicators_a_stix_pattern_gives_iocs_and_indicated_rules_and_bad_patterns_are_named():
    sco = {"type": "domain-name", "id": _id("domain-name", 1), "value": "based.example"}
    objs = [
        sco,
        _indicator(2, "[ipv4-addr:value = '1.2.3.4' OR file:hashes.'SHA-256' = '" + "d" * 64 + "']"),
        _indicator(3, "[file:name = 'a.exe' AND file:hashes.MD5 = '" + "e" * 32 + "']"),
        _indicator(4, "rule x { condition: true }", "yara"),
        _indicator(5, "[ipv4-addr:value ="),
        _indicator(6, "[ipv4-addr:value LIKE '1.2.%']"),
        _rel(7, _id("indicator", 6), "based-on", sco["id"]),
    ]
    p = bundle.project({"objects": objs})
    pairs = {(i["type"], i["value"]) for i in p["iocs"]}
    assert pairs == {("domain", "based.example"), ("ipv4", "1.2.3.4"), ("sha256", "d" * 64),
                     ("file", "a.exe"), ("md5", "e" * 32)}
    indicated = {(i["type"], i["value"]) for i in p["indicated"]}
    assert indicated == pairs                     # the based-on SCO is indicated too
    by_id = {u["id"]: u for u in p["unsupported_patterns"]}
    assert set(by_id) == {_id("indicator", n) for n in (4, 5, 6)}
    assert by_id[_id("indicator", 4)]["reason"] == "rule pattern, not scored as an IoC"
    assert by_id[_id("indicator", 4)]["pattern_type"] == "yara"
    assert "does not parse" in by_id[_id("indicator", 5)]["reason"]
    assert by_id[_id("indicator", 6)]["reason"] == "no equality comparison"
    assert p["problems"] == []


def test_relation_ends_are_forms_and_a_missing_reference_is_a_problem():
    actor = {"type": "threat-actor", "id": _id("threat-actor", 1), "name": "APT29", "aliases": ["Cozy Bear"]}
    ttp = {"type": "attack-pattern", "id": _id("attack-pattern", 2), "name": "Phishing",
           "external_references": [{"source_name": "mitre-attack", "external_id": "T1566"}]}
    sco = {"type": "domain-name", "id": _id("domain-name", 3), "value": "evil.com"}
    objs = [actor, ttp, sco, _indicator(4, "[url:value = 'http://evil.com/a']"),
            _rel(5, actor["id"], "uses", ttp["id"]),
            _rel(6, _id("indicator", 4), "indicates", actor["id"]),
            _rel(7, _id("indicator", 4), "based-on", sco["id"]),
            _rel(8, actor["id"], "uses", _id("malware", 99))]
    p = bundle.project({"objects": objs})
    assert {"source": ["APT29", "Cozy Bear"], "type": "uses", "target": ["T1566", "Phishing"]} in p["relations"]
    assert {"source": ["http://evil.com/a", "evil.com"], "type": "indicates",
            "target": ["APT29", "Cozy Bear"]} in p["relations"]
    assert p["problems"] == [f"unresolved reference {_id('relationship', 8)} -> {_id('malware', 99)}"]
    assert all(r["target"] != [_id("malware", 99)] for r in p["relations"])


def test_indicated_keeps_values_with_no_ioc_type_while_iocs_stay_strict():
    acct = {"type": "user-account", "id": _id("user-account", 1), "user_id": "@lily"}
    objs = [acct, _indicator(2, "[user-account:account_login = 'bob']"),
            _indicator(3, "[user-account:user_id = 'x' AND ipv4-addr:value = '1.2.3.4']"),
            _rel(4, _id("indicator", 2), "based-on", acct["id"]),
            _rel(5, _id("indicator", 2), "indicates", _id("malware", 9))]
    p = bundle.project({"objects": objs})
    assert p["iocs"] == [{"type": "ipv4", "value": "1.2.3.4"}]
    assert {(i["type"], i["value"]) for i in p["indicated"]} == {
        ("user-account", "@lily"), ("user-account", "bob"), ("user-account", "x"), ("ipv4", "1.2.3.4")}
    assert p["unsupported_patterns"] == []                    # nothing to score as IoC, yet not unsupported


def test_a_gold_observable_indicated_through_a_user_account_is_counted(tmp_path):
    doc = _doc(tmp_path, {"layers": ["iocs"], "iocs": [],
                          "observables": [{"type": "handle", "value": "@lily", "why": "no-ioc-type"},
                                          {"type": "handle", "value": "bob", "why": "no-ioc-type"}]})
    objs = [{"type": "user-account", "id": _id("user-account", 1), "user_id": "@lily"},
            _indicator(2, "[user-account:account_login = 'bob']"),
            _indicator(3, "[user-account:user_id = 'zzz']"),
            _rel(4, _id("indicator", 3), "based-on", _id("user-account", 1))]
    s = inhouse.score_bundle(doc, bundle.project({"objects": objs}), lambda t: t)
    assert s["observables"]["as_indicator"] == 2 and s["iocs"].fp == 0


def test_a_pattern_beyond_the_bounds_is_not_parsed():
    nested = "[" + "(" * 80 + "ipv4-addr:value = '1.2.3.4'" + ")" * 80 + "]"
    many = "[" + " OR ".join("ipv4-addr:value = '1.2.3.4'" for _ in range(300)) + "]"
    quoted = "[url:value = '" + "(" * 100 + " OR " * 300 + "']"
    p = bundle.project({"objects": [_indicator(1, nested), _indicator(2, many), _indicator(3, quoted)]})
    assert [u["reason"] for u in p["unsupported_patterns"]] == ["pattern too complex"] * 2
    assert [i["value"] for i in p["iocs"]] == [quoted[len("[url:value = '"):-2]]


def test_a_malformed_bundle_is_a_problem_not_an_exception():
    assert bundle.project([])["problems"] == ["bundle root is not an object"]
    assert bundle.project({"objects": {}})["problems"] == ["bundle has no objects list"]
    objs = [{"type": "attack-pattern", "id": _id("attack-pattern", 1), "name": "P", "external_references": None},
            {"type": "malware", "id": _id("malware", 2), "name": "M", "aliases": "Other"},
            {"type": "vulnerability", "id": _id("vulnerability", 3), "name": "x", "external_references": 5},
            {"type": ["file"], "id": ["x"], "name": "ignored"},
            {"type": "relationship", "id": _id("relationship", 4), "relationship_type": "uses",
             "source_ref": ["bad"], "target_ref": _id("malware", 2)}]
    p = bundle.project({"objects": objs})
    assert p["techniques"] == [] and p["entities"] == [{"type": "malware", "forms": ["M"]}]
    assert p["problems"] == [f"unresolved reference {_id('relationship', 4)} -> ['bad']"]


def test_based_on_is_not_a_scored_relation():
    sco = {"type": "domain-name", "id": _id("domain-name", 1), "value": "evil.com"}
    objs = [sco, _indicator(2, "[domain-name:value = 'evil.com']"),
            _rel(3, _id("indicator", 2), "based-on", sco["id"]),
            _rel(4, _id("indicator", 2), "indicates", _id("malware", 5)),
            {"type": "malware", "id": _id("malware", 5), "name": "M"}]
    assert [r["type"] for r in bundle.project({"objects": objs})["relations"]] == ["indicates"]
    dangling = [*objs, _rel(6, _id("indicator", 2), "based-on", _id("file", 99))]
    assert len(bundle.project({"objects": dangling})["problems"]) == 1


# ── scoring ──────────────────────────────────────────────────────────────────

def _doc(tmp_path, gold):
    folder = tmp_path / "r1"
    folder.mkdir(exist_ok=True)
    (folder / "source.txt").write_text("report", encoding="utf-8")
    (folder / "gold.json").write_text(json.dumps({"status": "gold", **gold}), encoding="utf-8")
    [doc] = inhouse.load(tmp_path)
    return doc


def _projection(**kw):
    base = {"iocs": [], "indicated": [], "entities": [], "techniques": [], "relations": [],
            "unsupported_patterns": [], "problems": []}
    return {**base, **kw}


def test_an_alias_in_the_bundle_matches_the_gold_label_for_entities_and_relation_ends(tmp_path):
    doc = _doc(tmp_path, {"layers": ["entities", "relations"],
                          "entities": [{"type": "threat_actor", "value": "APT29", "aliases": ["Cozy Bear"]},
                                       {"type": "malware", "value": "WellMess"}],
                          "relations": [{"source": "APT29", "type": "uses", "target": "WellMess"}]})
    proj = _projection(
        entities=[{"type": "threat_actor", "forms": ["Cozy Bear"]}, {"type": "malware", "forms": ["WellMess"]}],
        relations=[{"source": ["Cozy Bear"], "type": "uses", "target": ["WellMess"]}])
    s = inhouse.score_bundle(doc, proj, lambda t: t)
    assert (s["entities"]["threat_actor"].tp, s["entities"]["malware"].tp) == (1, 1)
    assert (s["relations"]["strict"].tp, s["relations"]["strict"].fp, s["relations"]["strict"].fn) == (1, 0, 0)


def test_a_reversed_relation_is_a_miss_in_strict_and_a_hit_undirected(tmp_path):
    doc = _doc(tmp_path, {"layers": ["relations"],
                          "relations": [{"source": "APT29", "type": "uses", "target": "WellMess"}]})
    proj = _projection(relations=[{"source": ["WellMess"], "type": "uses", "target": ["APT29"]}])
    r = inhouse.score_bundle(doc, proj, lambda t: t)["relations"]
    assert (r["strict"].tp, r["strict"].fp, r["strict"].fn) == (0, 1, 1)
    assert r["undirected_untyped"].tp == 1


def test_every_entity_type_is_reported_and_one_without_gold_counts_its_predictions_as_fp(tmp_path):
    doc = _doc(tmp_path, {"layers": ["entities"], "entities": [{"type": "malware", "value": "WellMess"}]})
    s = inhouse.score_bundle(doc, _projection(
        entities=[{"type": "tool", "forms": ["Invented"]}]), lambda t: t)["entities"]
    assert set(s) == inhouse.ENTITY_LAYER_TYPES
    assert (s["tool"].fp, s["malware"].fn) == (1, 1)
    assert s["campaign"] == Counts() and s["threat_actor"] == Counts()


def test_a_gold_observable_the_bundle_indicates_is_counted_and_is_not_an_ioc_fp(tmp_path):
    doc = _doc(tmp_path, {"layers": ["iocs"], "iocs": [{"type": "domain", "value": "evil.com"}],
                          "observables": [{"type": "file", "value": "rundll32.exe", "why": "legitimate"},
                                          {"type": "file", "value": "kernel32.dll", "why": "legitimate"}]})
    both = [{"type": "domain", "value": "evil.com"}, {"type": "file", "value": "rundll32.exe"},
            {"type": "file", "value": "kernel32.dll"}]
    s = inhouse.score_bundle(doc, _projection(iocs=both, indicated=[both[1]]), lambda t: t)
    assert (s["iocs"].tp, s["iocs"].fp, s["iocs"].fn) == (1, 0, 0)
    assert s["observables"]["cases"] == 2 and s["observables"]["as_indicator"] == 1


def test_a_negative_technique_in_the_bundle_is_a_violation(tmp_path):
    doc = _doc(tmp_path, {"layers": ["techniques"], "techniques": [],
                          "negatives": [{"kind": "technique", "id": "T1547", "why": "negated"},
                                        {"kind": "technique", "id": "T1105", "why": "negated"}]})
    s = inhouse.score_bundle(doc, _projection(techniques=["T1547.001"], unsupported_patterns=[{}]),
                             lambda t: t)
    assert (s["negatives"]["cases"], s["negatives"]["violated"]) == (2, 1)
    assert s["unsupported_patterns"] == 1 and s["problems"] == []


# ── inhouse-score --from bundle ──────────────────────────────────────────────

GOLD = {"status": "gold", "layers": ["iocs", "entities"],
        "iocs": [{"type": "domain", "value": "evil.com"}],
        "entities": [{"type": "malware", "value": "WellMess"}]}
BUNDLE = {"type": "bundle", "id": _id("bundle", 1), "objects": [
    {"type": "domain-name", "id": _id("domain-name", 2), "value": "evil.com"},
    {"type": "malware", "id": _id("malware", 3), "name": "WellMess"}]}


@pytest.fixture()
def world(tmp_path, monkeypatch):
    """One gold report "h1" and an empty in-house run "r"."""
    root = tmp_path / "inhouse"
    (root / "h1").mkdir(parents=True)
    (root / "h1" / "source.txt").write_text("report", encoding="utf-8")
    (root / "h1" / "gold.json").write_text(json.dumps(GOLD), encoding="utf-8")
    load = inhouse.load
    monkeypatch.setattr(ev, "OUT", tmp_path / "eval")
    monkeypatch.setattr(ev.inhouse, "load", lambda: load(root))
    monkeypatch.setattr(ev, "_canonical_fn", lambda release=None: (lambda t: t, None))
    monkeypatch.setattr(ev, "load_dotenv", lambda *a, **k: False)
    run_dir = tmp_path / "eval" / "inhouse-runs" / "r"
    (run_dir / "docs").mkdir(parents=True)
    return run_dir


def _begin(run_dir, fmt=2):
    meta = {"name": "r", "manifest": {"attack": {"release": "19.2"}}}
    if fmt:
        meta["format"] = fmt
    (run_dir / "run.json").write_text(json.dumps(meta), encoding="utf-8")


def _record(run_dir, doc_id="h1", *, validation="validated", content=BUNDLE, sha=None, write=True, **extra):
    """A document record of a format-2 run, with its bundle on disk."""
    rel = f"bundles/{doc_id}.json"
    raw = content if isinstance(content, bytes) else json.dumps(content).encode()
    if write:
        (run_dir / "bundles").mkdir(exist_ok=True)
        (run_dir / rel).write_bytes(raw)
    rec = {"doc_id": doc_id, "ttp_ids": [], "entities": [], "relations": [], "validation": validation,
           "bundle_file": rel, "bundle_sha256": sha or hashlib.sha256(raw).hexdigest(), **extra}
    (run_dir / "docs" / f"{doc_id}.json").write_text(json.dumps(rec), encoding="utf-8")


def _cli(monkeypatch, *argv):
    monkeypatch.setattr(sys, "argv", ["evaluation", *argv])
    ev.main()


def test_a_clean_validated_bundle_is_scored_and_the_report_is_complete(world, monkeypatch, capsys):
    _begin(world)
    _record(world)
    _cli(monkeypatch, "inhouse-score", "--name", "r", "--from", "bundle")
    report = json.loads((world / "score-bundle.json").read_text(encoding="utf-8"))
    assert json.loads(capsys.readouterr().out) == report
    assert report["format"] == "inhouse-score/2" and report["source"] == "bundle"
    assert report["documents"] == 1 and report["documents_unscored"] == {}
    assert report["documents_failed"] == [] and report["documents_missing"] == []
    gold_bytes = json.dumps(GOLD).encode()
    assert report["gold"] == {"h1": hashlib.sha256(gold_bytes).hexdigest()}
    assert report["run_manifest"] == {"attack": {"release": "19.2"}}
    assert report["micro"]["iocs"]["tp"] == 1
    assert {k for k in report["micro"] if k.startswith("entity:")} == {
        f"entity:{t}" for t in inhouse.ENTITY_LAYER_TYPES}
    assert report["micro"]["entity:tool"]["tp"] == 0
    doc = report["per_document"]["h1"]
    assert doc["validation"] == "validated" and doc["unsupported_patterns"] == 0
    assert doc["entities"]["malware"]["tp"] == 1 and doc["iocs"]["tp"] == 1


def test_documents_that_cannot_be_scored_are_named_with_their_reason(tmp_path, monkeypatch, world, capsys):
    root = tmp_path / "inhouse"
    names = ["h2", "h3", "h4", "h5", "h6", "h7"]
    for n in names:
        (root / n).mkdir()
        (root / n / "source.txt").write_text("report", encoding="utf-8")
        (root / n / "gold.json").write_text(json.dumps(GOLD), encoding="utf-8")
    _begin(world)
    _record(world, "h1", validation="invalid")
    _record(world, "h2", sha="0" * 64)
    _record(world, "h3", write=False)
    _record(world, "h4", validation="unverified")
    _record(world, "h5", validation=None)
    _record(world, "h6", content=b"not json")
    # h7: a bundle with a dangling reference
    dangling = {"objects": [*BUNDLE["objects"], _rel(4, _id("malware", 3), "uses", _id("tool", 77))]}
    _record(world, "h7", content=dangling)
    with pytest.raises(SystemExit, match="incomplete in-house score"):
        _cli(monkeypatch, "inhouse-score", "--name", "r", "--from", "bundle")
    report = json.loads((world / "score-bundle.json").read_text(encoding="utf-8"))
    assert json.loads(capsys.readouterr().out) == report                     # printed before the exit
    assert report["documents_unscored"] == {
        "h1": "verdict invalid", "h2": "bundle changed since the run (sha256)", "h3": "bundle missing",
        "h4": "verdict unverified", "h5": "verdict unknown", "h6": "bundle is not JSON",
        "h7": "unresolved references: 1"}
    assert report["documents"] == 0 and report["per_document"] == {}


def test_an_error_record_is_failed_and_unscored(world, monkeypatch):
    _begin(world)
    (world / "docs" / "h1.json").write_text(json.dumps({"doc_id": "h1", "error": "RuntimeError: x"}),
                                            encoding="utf-8")
    with pytest.raises(SystemExit, match="failed on h1"):
        _cli(monkeypatch, "inhouse-score", "--name", "r", "--from", "bundle")
    report = json.loads((world / "score-bundle.json").read_text(encoding="utf-8"))
    assert report["documents_failed"] == ["h1"] and report["documents_unscored"] == {"h1": "processing error"}


def test_a_format_1_run_has_no_bundle_to_score(world, monkeypatch):
    _begin(world, fmt=None)
    _record(world)
    with pytest.raises(SystemExit, match="no bundle recorded"):
        _cli(monkeypatch, "inhouse-score", "--name", "r", "--from", "bundle")
    report = json.loads((world / "score-bundle.json").read_text(encoding="utf-8"))
    assert report["documents_unscored"] == {"h1": "no bundle recorded (format-1 run?)"}


def test_a_non_string_bundle_file_or_a_malformed_bundle_is_named(world, monkeypatch):
    root = world.parent.parent.parent / "inhouse"
    for n in ("h2", "h3"):
        (root / n).mkdir()
        (root / n / "source.txt").write_text("report", encoding="utf-8")
        (root / n / "gold.json").write_text(json.dumps(GOLD), encoding="utf-8")
    _begin(world)
    _record(world, "h1")
    rec = json.loads((world / "docs" / "h1.json").read_text(encoding="utf-8"))
    (world / "docs" / "h1.json").write_text(json.dumps({**rec, "bundle_file": 5}), encoding="utf-8")
    _record(world, "h2", content=[])
    _record(world, "h3", content={"objects": [{"type": "malware", "id": _id("malware", 1), "name": "M"}]})
    with pytest.raises(SystemExit):
        _cli(monkeypatch, "inhouse-score", "--name", "r", "--from", "bundle")
    report = json.loads((world / "score-bundle.json").read_text(encoding="utf-8"))
    assert report["documents_unscored"] == {
        "h1": "bundle missing", "h2": "bundle malformed: bundle root is not an object"}
    assert list(report["per_document"]) == ["h3"]


def test_a_bundle_outside_the_run_directory_is_missing(world, monkeypatch, tmp_path):
    _begin(world)
    _record(world)
    rec = json.loads((world / "docs" / "h1.json").read_text(encoding="utf-8"))
    (tmp_path / "elsewhere.json").write_text("{}", encoding="utf-8")
    rec["bundle_file"] = "../../../../elsewhere.json"
    (world / "docs" / "h1.json").write_text(json.dumps(rec), encoding="utf-8")
    with pytest.raises(SystemExit):
        _cli(monkeypatch, "inhouse-score", "--name", "r", "--from", "bundle")
    report = json.loads((world / "score-bundle.json").read_text(encoding="utf-8"))
    assert report["documents_unscored"] == {"h1": "bundle missing"}


def test_the_run_source_keeps_its_report_and_adds_the_new_keys(world, monkeypatch):
    _begin(world)
    (world / "docs" / "h1.json").write_text(json.dumps(
        {"doc_id": "h1", "ttp_ids": [], "relations": [],
         "entities": [{"type": "domain", "value": "evil.com"}, {"type": "malware", "value": "WellMess"}]}),
        encoding="utf-8")
    _cli(monkeypatch, "inhouse-score", "--name", "r")
    assert not (world / "score-bundle.json").exists()
    report = json.loads((world / "score.json").read_text(encoding="utf-8"))
    assert report["source"] == "run" and "documents_unscored" not in report
    assert report["micro"]["iocs"]["tp"] == 1 and report["micro"]["entity:malware"]["tp"] == 1
    assert report["micro"]["entity:campaign"]["tp"] == 0                    # all 4 types, even empty
    assert set(report["per_document"]["h1"]) >= {"layers", "iocs", "entities", "negatives"}


# ── inhouse-compare ──────────────────────────────────────────────────────────

def _scored(world, monkeypatch, name, malware):
    """Score a run whose bundle names `malware`, return the report's path."""
    run_dir = world.parent / name
    (run_dir / "docs").mkdir(parents=True)
    (run_dir / "run.json").write_text(json.dumps({"name": name, "format": 2}), encoding="utf-8")
    content = {"objects": [BUNDLE["objects"][0], {"type": "malware", "id": _id("malware", 3), "name": malware}]}
    _record(run_dir, content=content)
    _cli(monkeypatch, "inhouse-score", "--name", name, "--from", "bundle")
    return run_dir / "score-bundle.json"


def test_compare_gives_both_sides_and_the_delta(world, monkeypatch, capsys, tmp_path):
    a = _scored(world, monkeypatch, "a", "Other")
    b = _scored(world, monkeypatch, "b", "WellMess")
    capsys.readouterr()
    _cli(monkeypatch, "inhouse-compare", str(a), str(b))
    out = json.loads(capsys.readouterr().out)
    assert out["micro"]["entity:malware"]["f1"] == {"a": 0.0, "b": 1.0, "delta": 1.0}
    assert out["micro"]["iocs"]["f1"]["delta"] == 0.0
    assert out["per_document"]["h1"]["entity:malware"]["recall"]["delta"] == 1.0
    assert out["only_in_a"] == [] and out["only_in_b"] == []


def test_compare_micro_common_uses_only_the_documents_scored_on_both_sides(world, monkeypatch, capsys):
    root = world.parent.parent.parent / "inhouse"
    (root / "h2").mkdir()
    (root / "h2" / "source.txt").write_text("report", encoding="utf-8")
    (root / "h2" / "gold.json").write_text(json.dumps(GOLD), encoding="utf-8")
    wrong = {"objects": [BUNDLE["objects"][0], {"type": "malware", "id": _id("malware", 3), "name": "X"}]}
    for name, contents in (("a", {"h1": BUNDLE}), ("b", {"h1": wrong, "h2": BUNDLE})):
        run_dir = world.parent / name
        (run_dir / "docs").mkdir(parents=True)
        (run_dir / "run.json").write_text(json.dumps({"name": name, "format": 2}), encoding="utf-8")
        for doc_id, content in contents.items():
            _record(run_dir, doc_id, content=content)
        try:
            _cli(monkeypatch, "inhouse-score", "--name", name, "--from", "bundle")
        except SystemExit:
            assert name == "a"                                          # a has no result for h2
    capsys.readouterr()
    _cli(monkeypatch, "inhouse-compare", str(world.parent / "a" / "score-bundle.json"),
         str(world.parent / "b" / "score-bundle.json"))
    out = json.loads(capsys.readouterr().out)
    assert out["micro_comparable"] is False and out["only_in_b"] == ["h2"]
    assert out["micro_common"]["entity:malware"]["f1"] == {"a": 1.0, "b": 0.0, "delta": -1.0}   # h1 only
    assert out["micro"]["entity:malware"]["f1"]["b"] == 0.5                                      # h1 + h2


def test_inhouse_run_removes_the_bundle_files_of_an_earlier_attempt(world, monkeypatch):
    seen = {}

    class Result:
        validation = None

        def stage_report(self):
            return []

    def run_file(path, disabled, output_path=None):
        seen["stale"] = [p.name for p in (world / "bundles").glob("*")]
        return Result()

    monkeypatch.setattr("api.run_config.build_manifest", lambda: {"attack": {"release": "19.2"}})
    monkeypatch.setattr(ev, "_run_file", run_file)
    monkeypatch.setattr(ev, "_predictions", lambda result: {"ttp_ids": []})
    monkeypatch.setattr(ev, "_stay_on_the_release", lambda *a: None)
    (world / "bundles").mkdir()
    (world / "bundles" / "h1.json").write_text("{}", encoding="utf-8")
    (world / "bundles" / "h1_invalid.json").write_text("{}", encoding="utf-8")
    _cli(monkeypatch, "inhouse-run", "--name", "r")
    assert seen["stale"] == []
    rec = json.loads((world / "docs" / "h1.json").read_text(encoding="utf-8"))
    assert rec["bundle_file"] is None and rec["bundle_sha256"] is None and rec["validation"] is None


def test_compare_refuses_a_gold_that_changed_and_another_source(world, monkeypatch, capsys, tmp_path):
    a = _scored(world, monkeypatch, "a", "WellMess")
    b = _scored(world, monkeypatch, "b", "WellMess")
    report = json.loads(b.read_text(encoding="utf-8"))
    report["gold"]["h1"] = "0" * 64
    report["gold"]["h9"] = "1" * 64
    b.write_text(json.dumps(report), encoding="utf-8")
    capsys.readouterr()
    with pytest.raises(SystemExit) as exc:
        _cli(monkeypatch, "inhouse-compare", str(a), str(b))
    err = capsys.readouterr()
    assert exc.value.code == 2 and err.out == ""
    assert "h1 (hash differs)" in err.err and "h9 (only in B)" in err.err

    report["gold"] = json.loads(a.read_text(encoding="utf-8"))["gold"]
    report["source"] = "run"
    b.write_text(json.dumps(report), encoding="utf-8")
    with pytest.raises(SystemExit) as exc:
        _cli(monkeypatch, "inhouse-compare", str(a), str(b))
    assert exc.value.code == 2 and "different things" in capsys.readouterr().err

    report["format"] = "inhouse-score/1"
    b.write_text(json.dumps(report), encoding="utf-8")
    with pytest.raises(SystemExit) as exc:
        _cli(monkeypatch, "inhouse-compare", str(a), str(b))
    assert exc.value.code == 2 and "inhouse-score/2" in capsys.readouterr().err
