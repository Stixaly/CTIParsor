"""The evaluation protocol (evaluation/, ADR-0060) on tiny fixtures — no
AnnoCTR download, no ATT&CK bundle, no model."""
import json

import pytest

from evaluation import annoctr, attack, dedup, evidence, metrics
from evaluation.metrics import Counts

# ── AnnoCTR loading ──────────────────────────────────────────────────────────

def _mini_annoctr(root):
    text = ("Emotet bots received commands to download Trickbot. "
            "The actor used spearphishing attachments. Targets were banks in France.")
    doc = "zscaler_2021-05-01_emotet-trickbot"
    (root / "text" / "dev").mkdir(parents=True)
    (root / "text" / "dev" / f"{doc}.txt").write_text(text, encoding="utf-8")
    (root / "linking_mitre_only").mkdir()
    rows = [
        {"mention": "received commands to download Trickbot", "_context_left": "Emotet bots ",
         "_context_right": ".", "label_link": "https://attack.mitre.org/techniques/T1105",
         "label_title": "Ingress Tool Transfer", "entity_class": "CI", "entity_type": "TECHNIQUE",
         "document": doc},
        {"mention": "spearphishing attachments", "_context_left": "The actor used ",
         "_context_right": ".", "label_link": "https://attack.mitre.org/techniques/T1566/001",
         "label_title": "Spearphishing Attachment", "entity_class": "CE", "entity_type": "TECHNIQUE",
         "document": doc},
        {"mention": "Emotet", "_context_left": "", "_context_right": " bots", "label_link": "x",
         "label_title": "Emotet", "entity_class": "CE", "entity_type": "MALWARE", "document": doc},
        {"mention": "phishing", "_context_left": "", "_context_right": "", "label_link": "x",
         "label_title": "x", "entity_class": "CE", "entity_type": "TECHNIQUE", "document": "other"},
    ]
    (root / "linking_mitre_only" / "dev.jsonl").write_text(
        "\n".join(json.dumps(r) for r in rows), encoding="utf-8")
    (root / "ner_json").mkdir()
    (root / "ner_json" / "dev.json").write_text(json.dumps({
        "id": f"{doc}__s0002", "tokens": ["Targets", "were", "banks", "in", "France", "."],
        "ne_tags": ["O", "O", "B-SECTOR", "O", "B-LOC", "O"]}), encoding="utf-8")
    return doc, text


def test_annoctr_loads_techniques_with_kind_and_located_mentions(tmp_path):
    doc_id, text = _mini_annoctr(tmp_path)
    [doc] = annoctr.load(tmp_path, splits=("dev",))

    assert doc.doc_id == doc_id and doc.vendor == "zscaler" and doc.layers == {"general", "cyber"}
    assert doc.technique_kinds() == {"T1105": {"implicit"}, "T1566.001": {"explicit"}}
    m = next(m for m in doc.techniques if m.label == "T1105")
    assert text[m.start:m.end] == "received commands to download Trickbot"
    assert {(e.etype, e.label) for e in doc.entities.values()} == {
        ("malware", "Emotet"), ("identity", "banks"), ("location", "France")}
    assert doc.evaluable()["iocs"] is False and doc.evaluable()["ttp"] is True


def test_a_missing_corpus_says_how_to_get_it(tmp_path):
    with pytest.raises(FileNotFoundError, match="git clone"):
        annoctr.load(tmp_path / "nowhere")


# ── ATT&CK mapping ───────────────────────────────────────────────────────────

def _bundle(tmp_path):
    def ap(stix_id, tid, **kw):
        return {"type": "attack-pattern", "id": stix_id, "modified": "2026-01-01",
                "external_references": [{"source_name": "mitre-attack", "external_id": tid}], **kw}
    objs = [ap("a--1", "T1562", revoked=True), ap("a--2", "T1685"),
            ap("a--3", "T1086", x_mitre_deprecated=True), ap("a--4", "T1105"),
            {"type": "relationship", "relationship_type": "revoked-by",
             "source_ref": "a--1", "target_ref": "a--2"}]
    b = tmp_path / "enterprise.json"
    b.write_text(json.dumps({"objects": objs}), encoding="utf-8")
    idx = tmp_path / "index.json"
    idx.write_text(json.dumps({"techniques": [{"id": t} for t in ("T1685", "T1105", "T1437")]}),
                   encoding="utf-8")
    return attack.Catalogue(b, idx)


def test_revoked_ids_follow_revoked_by_and_both_sides_meet(tmp_path):
    cat = _bundle(tmp_path)
    assert cat.resolve("T1562").canonical == "T1685"
    assert cat.resolve("t1105").as_dict() == {"gold_id": "T1105", "status": "active",
                                              "canonical": "T1105", "in_pipeline": True}
    assert cat.resolve("T1086").canonical is None                 # deprecated: out of scope
    assert cat.resolve("T1437").status == "unknown" and cat.resolve("T1437").in_pipeline
    assert cat.resolve("T9999").canonical is None


# ── TTP scoring ──────────────────────────────────────────────────────────────

def test_ttp_scores_canonicalise_both_sides_and_split_explicit_from_implicit():
    canon = {"T1562": "T1685", "T1685": "T1685", "T1105": "T1105", "T1566.001": "T1566.001",
             "T1566": "T1566", "T1027": "T1027", "T1086": None}.get
    gold = {"T1562": {"explicit"}, "T1105": {"implicit"}, "T1566.001": {"explicit", "implicit"},
            "T1086": {"explicit"}}
    s = metrics.score_ttps({"T1685", "T1566", "T1027"}, gold, canon)

    assert s.dropped_gold == ["T1086"]
    # parents: gold {T1685, T1105, T1566}; pred {T1685, T1566, T1027}
    assert (s.technique.tp, s.technique.fp, s.technique.fn) == (2, 1, 1)
    # exact ids: T1566 is not T1566.001
    assert (s.subtechnique.tp, s.subtechnique.fp, s.subtechnique.fn) == (1, 2, 2)
    assert s.explicit_recall == (2, 2)          # T1685, T1566
    assert s.implicit_recall == (0, 1)          # T1105 only ever implicit


def test_per_document_average_differs_from_micro():
    docs = [Counts(9, 1, 0), Counts(0, 1, 1)]
    p, r = 9 / 11, 9 / 10                       # micro: tp 9, fp 2, fn 1
    assert metrics.micro(docs).f1 == pytest.approx(2 * p * r / (p + r))
    assert metrics.macro(docs)["f1"] == pytest.approx(round((2 * 0.9 * 1.0 / 1.9 + 0) / 2, 4))
    assert metrics.macro([Counts()])["documents"] == 0


# ── Entities ─────────────────────────────────────────────────────────────────

def test_entities_match_label_or_surface_one_to_one():
    gold = [("malware", "Emotet", {"Emotet", "Geodo"}), ("threat_actor", "APT29", {"Cozy Bear"})]
    pred = [("malware", "geodo"), ("malware", "Emotet"), ("threat_actor", "Cozy"),
            ("tool", "Mimikatz")]
    strict = metrics.score_entities(pred, gold)
    lenient = metrics.score_entities(pred, gold, lenient=True)

    assert (strict["malware"].tp, strict["malware"].fp) == (1, 1)     # one gold, two names
    assert (strict["threat_actor"].tp, strict["threat_actor"].fp, strict["threat_actor"].fn) == (0, 1, 1)
    assert lenient["threat_actor"].tp == 1
    assert strict["tool"].fp == 1


def test_relations_are_scored_with_type_and_direction():
    gold = {("APT29", "uses", "WellMess")}
    s = metrics.score_relations({("WellMess", "uses", "APT29")}, gold)
    assert s["strict"].tp == 0 and s["undirected_untyped"].tp == 1


# ── Paired bootstrap ─────────────────────────────────────────────────────────

def test_paired_bootstrap_sees_a_consistent_gain_and_no_gain():
    a = [Counts(5, 5, 5) for _ in range(30)]
    better = [Counts(8, 2, 2) for _ in range(30)]
    r = metrics.paired_bootstrap(a, better, n=500)
    assert r["observed_diff"] > 0 and r["ci95"][0] > 0 and r["p_not_better"] == 0.0
    same = metrics.paired_bootstrap(a, a, n=200)
    assert same["observed_diff"] == 0 and same["p_not_better"] == 1.0
    with pytest.raises(ValueError):
        metrics.paired_bootstrap(a, better[:5])


# ── Near-duplicates ──────────────────────────────────────────────────────────

def test_near_duplicates_catch_a_repost_and_an_excerpt_across_splits():
    base = " ".join(f"word{i}" for i in range(200))
    docs = {"a": ("train", base), "b": ("test", base + " extra words at the end"),
            "c": ("dev", " ".join(base.split()[:60])), "d": ("test", "entirely different text " * 20)}
    pairs = {(p["a"], p["b"]) for p in dedup.near_duplicates(docs)}
    assert ("a", "b") in pairs and ("a", "c") in pairs and ("b", "c") in pairs
    assert not any("d" in p for p in pairs)


# ── Evidence ─────────────────────────────────────────────────────────────────

def test_evidence_separates_existence_from_location():
    text = ("Intro paragraph about the campaign and its victims. "
            "The loader downloads the second stage payload from a remote server. "
            "Nothing else of note happened during the intrusion that week.")
    s = text.index("downloads the second")
    spans = {"T1105": [(s, s + 40)]}
    ttps = [
        {"mitre_id": "T1105", "evidence_text": "The loader downloads the second stage payload from a remote server."},
        {"mitre_id": "T1105", "evidence_text": "Nothing else of note happened during the intrusion that week."},
        {"mitre_id": "T1027", "evidence_text": "a sentence that is not in the document at all anywhere"},
    ]
    rows = evidence.check("d", text, ttps, spans, lambda t: t or None)
    summary = evidence.summarise(rows)
    assert summary["ttps_with_quote"] == 3 and summary["exists"] == pytest.approx(2 / 3, abs=1e-3)
    assert summary["correct_and_located"] == 2 and summary["on_annotated_passage"] == 0.5


# ── In-house set ─────────────────────────────────────────────────────────────

def _inhouse(tmp_path, gold):
    from evaluation import inhouse
    folder = tmp_path / "r1"
    folder.mkdir()
    (folder / "source.txt").write_text("report", encoding="utf-8")
    (folder / "gold.json").write_text(json.dumps(gold), encoding="utf-8")
    return inhouse


def test_inhouse_scores_only_annotated_layers_and_counts_negative_violations(tmp_path):
    gold = {"status": "gold", "layers": ["iocs", "techniques", "relations"],
            "iocs": [{"type": "domain", "value": "evil[.]com"}, {"type": "sha256", "value": "AB" * 32}],
            "entities": [{"type": "malware", "value": "Never scored"}],
            "techniques": [{"id": "T1105", "kind": "implicit"}],
            "relations": [{"source": "APT29", "type": "uses", "target": "WellMess"}],
            "negatives": [{"kind": "technique", "id": "T1547.001", "why": "negated"},
                          {"kind": "relation", "triple": ["APT29", "uses", "Mimikatz"], "why": "generic"}]}
    inhouse = _inhouse(tmp_path, gold)
    [doc] = inhouse.load(tmp_path)
    pred = {"entities": [{"type": "domain", "value": "EVIL.com"}, {"type": "malware", "value": "x"}],
            "ttp_ids": ["T1105", "T1547"],
            "relations": [{"source": "apt29", "type": "uses", "target": "mimikatz"}]}

    s = inhouse.score(doc, pred, lambda t: t)

    assert "entities" not in s                                   # not in `layers`
    assert (s["iocs"].tp, s["iocs"].fp, s["iocs"].fn) == (1, 0, 1)
    assert s["techniques"].technique.tp == 1
    assert s["relations"]["strict"].fn == 1
    assert s["negatives"] == {"cases": 2, "violated": 2, "violations": gold["negatives"]}


def test_a_pre_annotation_is_never_scored(tmp_path):
    inhouse = _inhouse(tmp_path, {"status": "pre-annotation", "layers": ["iocs"]})
    assert inhouse.load(tmp_path) == []
    assert len(inhouse.load(tmp_path, include_drafts=True)) == 1


def test_agreement_compares_layers_both_annotators_did():
    from evaluation import inhouse
    a = {"layers": ["iocs", "techniques"], "iocs": [{"type": "ipv4", "value": "1.2.3.4"}],
         "techniques": [{"id": "T1105"}, {"id": "T1566.001"}]}
    b = {"layers": ["techniques", "relations"], "techniques": [{"id": "T1566"}]}
    out = inhouse.agreement(a, b)
    assert set(out) == {"techniques"}
    assert (out["techniques"]["tp"], out["techniques"]["fn"]) == (1, 1)


# ── AnnoCTR's TimeML layer (ADR-0063) ────────────────────────────────────────

_TML = """<?xml version="1.0"?>
<TimeML><DCT><TIMEX3 functionInDocument="CREATION_TIME" tid="t0" value="2021-04-19">2021-04-19</TIMEX3></DCT>
<TEXT>A report i<TIMEX3 tid="t1" type="DATE" value="2019">n 2019.</TIMEX3> AT&amp;T saw it
<TIMEX3 tid="t2" type="DATE" value="2021-03">last month</TIMEX3>.</TEXT></TimeML>"""


def test_timeml_parse_keeps_offsets_and_the_dct():
    from evaluation.annoctr_time import parse_tml
    doc = parse_tml(_TML, "d1", "dev")
    assert doc is not None and doc.dct == "2021-04-19"
    assert [(t.text, t.value) for t in doc.timexes] == [("n 2019.", "2019"), ("last month", "2021-03")]
    for t in doc.timexes:
        assert doc.text[t.start:t.end] == t.text
    assert "AT&T" in doc.text


def test_timeml_score_repairs_a_shifted_span():
    from evaluation.annoctr_time import parse_tml, score
    doc = parse_tml(_TML, "d1", "dev")
    assert score([doc], repair_spans=False).exact == 1         # "n 2019." does not read
    repaired = score([doc], repair_spans=True)
    assert (repaired.exact, repaired.total) == (2, 2)
    assert repaired.relative_exact == 1                      # "last month" against the DCT
