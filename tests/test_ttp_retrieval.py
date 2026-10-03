"""pipeline/ttp_retrieval.py — candidate retrieval for the select path (ADR-0072).

No model: BM25 runs on its own, the dense half on a fake encoder whose vectors
are chosen by hand, so each fusion rule can be checked against a known order.
"""
from __future__ import annotations

import json

import numpy as np
import pytest

from pipeline import stage2c_ttp_semantic as s2c
from pipeline import ttp_retrieval as tr

# ── Passages keep their offsets and match Stage 2c's split ───────────────────

_TEXTS = [
    # hard-wrapped PDF text, doubled newlines, a list, a CRLF
    "The actor used spearphishing\n\nattachments to deliver the loader. It then\nran PowerShell to"
    " download a second stage.\n- Persistence via a scheduled task named Updater.\n"
    "1. Credentials were dumped from LSASS memory; the dump was exfiltrated.\r\nShort.",
    "A heading\n\nThe group deployed Cobalt Strike beacons across the network.  Lateral movement used"
    " stolen credentials over RDP!  Is this a question? Yes it is a question indeed.",
]


@pytest.mark.parametrize("text", _TEXTS)
def test_passages_are_the_stage2c_sentences(text, monkeypatch):
    monkeypatch.delenv("TTP_UNWRAP_LINES", raising=False)
    got = [p.text for p in tr.split_passages(text)]
    want = [" ".join(s.split()) for s in s2c._split_candidate_sentences(text)]
    assert got == want


@pytest.mark.parametrize("text", _TEXTS)
def test_every_passage_points_back_into_the_text(text):
    for p in tr.split_passages(text):
        assert " ".join(text[p.start:p.end].split()) == p.text


def test_passages_guard_bad_input():
    assert tr.split_passages(None) == []  # type: ignore[arg-type]
    assert tr.split_passages("") == []


def test_the_gates_are_stage2c_gates(monkeypatch):
    monkeypatch.delenv("TTP_ADVISORY_GATE", raising=False)
    ps = tr.split_passages("The actor exploited a VPN flaw to gain access. The weather was mild that day. "
                           "Disable macros in every Office installation to prevent infection.")
    kept = [p.text for p in tr.gate_passages(ps, keyword_gate=True)]
    assert kept == ["The actor exploited a VPN flaw to gain access."]
    assert len(tr.gate_passages(ps, keyword_gate=False)) == 2   # the advisory one still goes


# ── ATT&CK text cleaning and the corpus build ────────────────────────────────

def test_clean_keeps_link_labels_and_drops_citations_and_tags():
    raw = ("[APT28](https://attack.mitre.org/groups/G0007) has used <code>rundll32</code> "
           "to run [X-Agent](https://attack.mitre.org/software/S0161).(Citation: Vendor 2018)")
    assert tr.clean_attack_text(raw) == "APT28 has used rundll32 to run X-Agent."


def test_neutralised_names_become_placeholders():
    raw = ("[APT28](https://attack.mitre.org/groups/G0007) used [Mimikatz](https://attack.mitre.org/"
           "software/S0002) to dump credentials. Fancy Bear also ran Sofacy tools.")
    out = tr.clean_attack_text(raw, neutral_names=["APT28", "Fancy Bear"], neutralise=True)
    assert "APT28" not in out and "Mimikatz" not in out and "Fancy Bear" not in out
    assert out.startswith("The threat actor used the software to dump credentials.")
    assert "Sofacy" in out          # not a name of the source object: left alone


def _ref(ext_id):
    return [{"source_name": "mitre-attack", "external_id": ext_id}]


def _bundle():
    return [
        {"type": "attack-pattern", "id": "attack-pattern--a", "name": "Ingress Tool Transfer",
         "description": "Adversaries may transfer tools.(Citation: X)", "external_references": _ref("T1105")},
        {"type": "attack-pattern", "id": "attack-pattern--old", "name": "Old", "revoked": True,
         "description": "gone", "external_references": _ref("T1000")},
        {"type": "intrusion-set", "id": "intrusion-set--g", "name": "APT1", "aliases": ["Comment Crew"],
         "external_references": _ref("G0006")},
        {"type": "relationship", "id": "relationship--1", "relationship_type": "uses",
         "source_ref": "intrusion-set--g", "target_ref": "attack-pattern--a",
         "description": "[APT1](https://attack.mitre.org/groups/G0006) downloaded tools.(Citation: R)",
         "external_references": [{"source_name": "R", "url": "https://vendor.example/blog/apt1-report"}]},
        # the same example twice: one entry
        {"type": "relationship", "id": "relationship--2", "relationship_type": "uses",
         "source_ref": "intrusion-set--g", "target_ref": "attack-pattern--a",
         "description": "APT1 downloaded tools."},
        # a revoked target, a deprecated relationship, no description: none kept
        {"type": "relationship", "id": "relationship--3", "relationship_type": "uses",
         "source_ref": "intrusion-set--g", "target_ref": "attack-pattern--old",
         "description": "APT1 did an old thing worth twenty characters."},
        {"type": "relationship", "id": "relationship--4", "relationship_type": "uses",
         "x_mitre_deprecated": True, "source_ref": "intrusion-set--g", "target_ref": "attack-pattern--a",
         "description": "APT1 deprecated example sentence here."},
        {"type": "relationship", "id": "relationship--5", "relationship_type": "uses",
         "source_ref": "intrusion-set--g", "target_ref": "attack-pattern--a"},
    ]


def test_corpus_has_one_description_per_technique_and_distinct_procedures():
    entries = tr.build_corpus_entries(_bundle(), "enterprise-attack")
    kinds = [(e["id"], e["kind"]) for e in entries]
    assert kinds == [("T1105", "description"), ("T1105", "procedure")]
    proc = entries[1]
    assert proc["text"] == "APT1 downloaded tools."
    assert proc["source"] == "G0006"
    assert proc["urls"] == ["https://vendor.example/blog/apt1-report"]
    assert entries[0]["text"] == "Ingress Tool Transfer. Adversaries may transfer tools."


def test_neutralised_corpus_drops_the_actor_name():
    entries = tr.build_corpus_entries(_bundle(), "enterprise-attack", neutralise=True)
    assert entries[1]["text"] == "The threat actor downloaded tools."


# ── BM25 ─────────────────────────────────────────────────────────────────────

def test_bm25_ranks_the_matching_document_first_and_scores_no_overlap_zero():
    bm = tr.BM25(["adversaries dump credentials from lsass memory",
                  "adversaries schedule a task for persistence",
                  "the weather report"])
    s = bm.scores(["credential dumping of lsass"])[0]
    assert s.argmax() == 0
    assert s[2] == 0.0


def test_tokenize_strips_stopwords_and_suffixes():
    assert tr.tokenize("The actor downloaded the payloads") == ["actor", "download", "payload"]


# ── Retriever ────────────────────────────────────────────────────────────────

def _corpus(ids, texts, emb=None, kinds=None):
    n = len(ids)
    return tr.Corpus(ids=list(ids), names=[f"name-{i}" for i in ids], kinds=kinds or ["description"] * n,
                     domains=["enterprise-attack"] * n, texts=list(texts), urls=[[] for _ in ids],
                     embeddings=emb, model="fake", version="test")


class _Encoder:
    """Returns the vector registered for each text."""

    def __init__(self, vectors):
        self.vectors = vectors

    def encode(self, texts, **kw):
        return np.array([self.vectors[t] for t in texts], dtype=np.float32)


def test_k_counts_techniques_not_examples():
    # T1105 has three examples that all match; it still takes one slot.
    c = _corpus(["T1105", "T1105", "T1105", "T1566"],
                ["download tool file", "download payload file", "download file again", "phishing email file"])
    r = tr.Retriever(c, "bm25")
    row = r.rank(["download a file"], k=2)[0]
    assert [x.attack_id for x in row] == ["T1105", "T1566"]
    assert row[0].bm25_rank == 1 and row[0].fused_rank == 1
    assert row[0].example.startswith("download")


def test_dense_without_an_encoder_is_refused():
    with pytest.raises(ValueError):
        tr.Retriever(_corpus(["T1"], ["x"]), "dense")
    with pytest.raises(ValueError):
        tr.Retriever(_corpus(["T1"], ["x"]), "nonsense")


def _fusion_fixture():
    # Dense prefers A > B > C; BM25 matches only C ("lsass").
    emb = np.array([[1.0, 0.0], [0.8, 0.6], [0.0, 1.0]], dtype=np.float32)
    c = _corpus(["T1001", "T1002", "T1003"],
                ["alpha text", "beta text", "lsass memory credentials"], emb=emb)
    enc = _Encoder({"dump lsass": [1.0, 0.05]})
    return c, enc


def test_minrank_keeps_the_best_of_each_list():
    c, enc = _fusion_fixture()
    dense = [x.attack_id for x in tr.Retriever(c, "dense", enc).rank(["dump lsass"], k=3)[0]]
    assert dense == ["T1001", "T1002", "T1003"]
    fused = tr.Retriever(c, "minrank", enc).rank(["dump lsass"], k=2)[0]
    # T1003 is last for dense but first for BM25: min-rank puts it in the top 2
    assert {x.attack_id for x in fused} == {"T1001", "T1003"}
    t1003 = next(x for x in fused if x.attack_id == "T1003")
    assert t1003.bm25_rank == 1 and t1003.dense_rank == 3 and "bm25" in t1003.sources


def test_rrf_ranks_by_summed_reciprocal_ranks():
    c, enc = _fusion_fixture()
    row = tr.Retriever(c, "rrf", enc).rank(["dump lsass"], k=3)[0]
    assert row[0].attack_id in ("T1001", "T1003")
    assert {x.attack_id for x in row} == {"T1001", "T1002", "T1003"}


def test_passage_offsets_travel_with_the_candidates():
    c = _corpus(["T1105"], ["download file"])
    p = tr.Passage(10, 30, "download the file")
    cand = tr.Retriever(c, "bm25").rank([p], k=1)[0][0]
    assert (cand.start, cand.end, cand.passage) == (10, 30, "download the file")


def test_merge_by_technique_keeps_the_best_rank_and_all_sources():
    a = tr.TtpCandidate(attack_id="T1105", fused_rank=3, sources=["dense"])
    b = tr.TtpCandidate(attack_id="t1105", fused_rank=1, sources=["bm25"])
    c = tr.TtpCandidate(attack_id="T1566", fused_rank=2, sources=["dense"])
    out = tr.merge_by_technique([a, b, c])
    assert [x.attack_id for x in out] == ["t1105", "T1566"]
    assert out[0].sources == ["bm25", "dense"]
    assert len(tr.merge_by_technique([a, b, c], limit=1)) == 1


# ── Loading a built corpus ───────────────────────────────────────────────────

def _write_corpus(tmp_path):
    entries = [
        {"id": "T1566", "name": "Phishing", "kind": "description", "domain": "enterprise-attack",
         "text": "Phishing. Adversaries may send phishing messages.", "urls": []},
        {"id": "T1105", "name": "Ingress Tool Transfer", "kind": "procedure", "domain": "enterprise-attack",
         "text": "APT1 downloaded tools.", "urls": ["https://vendor.example/blog/scored-report-slug"]},
        {"id": "T1105", "name": "Ingress Tool Transfer", "kind": "procedure", "domain": "enterprise-attack",
         "text": "The loader fetched a second stage.", "urls": []},
        {"id": "T0800", "name": "ICS thing", "kind": "description", "domain": "ics-attack",
         "text": "ICS thing.", "urls": []},
    ]
    path = tmp_path / "corpus.json"
    path.write_text(json.dumps({"manifest": {"version": "v-test", "model": "fake"}, "entries": entries}))
    np.save(tmp_path / "emb.npy", np.eye(4, dtype=np.float32))
    return path, tmp_path / "emb.npy"


def test_load_corpus_filters_kind_domain_and_cited_reports(tmp_path, monkeypatch):
    tr._built_corpus.cache_clear()
    path, emb = _write_corpus(tmp_path)
    monkeypatch.setenv("TTP_SEMANTIC_DOMAINS", "enterprise-attack")
    both = tr.load_corpus("both", path=path, emb_path=emb)
    assert both.ids == ["T1105", "T1105", "T1566"]                 # sorted, ICS filtered out
    assert both.embeddings.shape == (3, 4)
    proc = tr.load_corpus("procedure", path=path, emb_path=emb, exclude_cited=["scored-report-slug"])
    assert proc.texts == ["The loader fetched a second stage."]
    assert "excl-" in proc.version and both.version == "v-test:both"
    with pytest.raises(ValueError):
        tr.load_corpus("everything", path=path)


def test_mismatched_embeddings_are_ignored_not_misaligned(tmp_path, monkeypatch):
    tr._built_corpus.cache_clear()
    path, _ = _write_corpus(tmp_path)
    bad = tmp_path / "bad.npy"
    np.save(bad, np.eye(2, dtype=np.float32))
    monkeypatch.setenv("TTP_SEMANTIC_DOMAINS", "all")
    c = tr.load_corpus("both", path=path, emb_path=bad)
    assert c.embeddings is None and len(c.ids) == 4


def test_missing_corpus_is_none(tmp_path):
    tr._built_corpus.cache_clear()
    assert tr.load_corpus("both", path=tmp_path / "absent.json") is None


def test_candidates_for_chunks_without_a_retriever_are_empty(monkeypatch):
    monkeypatch.setattr(tr, "_production_retriever", lambda *a: None)
    assert tr.candidates_for_chunks(["one", "two"]) == [[], []]


def test_candidates_for_chunks_merges_and_caps_per_chunk(monkeypatch):
    c = _corpus(["T1105", "T1566", "T1059"], ["download file tool", "phishing email attachment",
                                              "powershell command script"])
    monkeypatch.setattr(tr, "_production_retriever", lambda *a: tr.Retriever(c, "bm25"))
    monkeypatch.setenv("TTP_CANDIDATES_PER_PASSAGE", "2")
    monkeypatch.setenv("TTP_CANDIDATES_PER_CHUNK", "2")
    monkeypatch.setenv("TTP_KEYWORD_GATE", "false")
    out = tr.candidates_for_chunks(["The loader would download a tool file from the server. "
                                    "Then a phishing email attachment carried the payload.",
                                    "Nothing here."])
    assert len(out) == 2 and out[1] == []
    assert len(out[0]) == 2
    assert len({x.attack_id for x in out[0]}) == 2


def test_retrieval_is_unavailable_with_a_bad_setting(monkeypatch):
    monkeypatch.setenv("TTP_RETRIEVAL_METHOD", "magic")
    assert tr.retrieval_available() is False
    monkeypatch.setenv("TTP_RETRIEVAL_METHOD", "dense")
    monkeypatch.setenv("SKIP_HEAVY_MODELS", "1")
    assert tr.retrieval_available() is False
