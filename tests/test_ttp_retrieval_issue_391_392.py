"""pipeline/ttp_retrieval.py — #391 (stemming of "-ss" words) and #392 (bm25 zero scores).

No model: BM25 runs on its own; the rrf control uses the hand-made fake encoder of
test_ttp_retrieval.py.
"""
from __future__ import annotations

import numpy as np
import pytest

from pipeline import ttp_retrieval as tr

# ── #391: a word ending in "ss" keeps its "s" ────────────────────────────────


@pytest.mark.parametrize("singular, plural", [
    ("process", "processes"),
    ("access", "accesses"),
    ("address", "addresses"),
    ("bypass", "bypasses"),
])
def test_issue_391_singular_and_plural_share_a_stem(singular, plural):
    assert tr.tokenize(singular) == tr.tokenize(plural)


@pytest.mark.parametrize("word, stem", [
    ("process", "process"),
    ("access", "access"),
    ("processes", "process"),
    ("accesses", "access"),
    ("accessed", "access"),
    ("dumps", "dump"),
    ("downloaded", "download"),
    ("techniques", "techniqu"),
])
def test_issue_391_other_suffix_rules_are_unchanged(word, stem):
    assert tr._stem(word) == stem


# ── #392: bm25 alone emits no candidate with a zero score ────────────────────

def _corpus(ids, texts):
    n = len(ids)
    return tr.Corpus(ids=list(ids), names=[f"name-{i}" for i in ids], kinds=["description"] * n,
                     domains=["enterprise-attack"] * n, texts=list(texts), urls=[[] for _ in ids],
                     embeddings=None, model="fake", version="test")


_TEXTS = ["OS Credential Dumping: dump process memory",
          "Indicator Removal: delete files and logs",
          "Credentials from Password Stores: browser password store"]


def test_issue_392_no_shared_token_gives_no_candidate_in_bm25():
    r = tr.Retriever(_corpus(["T1003", "T1070", "T1555"], _TEXTS), "bm25")
    assert r.rank(["Completely unrelated sentence about weather."], k=3) == [[]]


def test_issue_392_one_hit_gives_one_candidate_in_bm25():
    r = tr.Retriever(_corpus(["T1003", "T1070", "T1555"], _TEXTS), "bm25")
    row = r.rank(["the adversary dumped process memory"], k=3)[0]
    assert [(x.attack_id, x.fused_rank) for x in row] == [("T1003", 1)]
    assert row[0].bm25_score > 0


def test_issue_392_rrf_still_fills_k_without_a_bm25_hit():
    # Control: rrf is unchanged, a passage with no shared token still gets k candidates.
    emb = np.array([[1.0, 0.0], [0.8, 0.6], [0.0, 1.0]], dtype=np.float32)
    c = _corpus(["T1003", "T1070", "T1555"], _TEXTS)
    c.embeddings = emb

    class _Enc:
        def encode(self, texts, **kw):
            return np.array([[0.0, 1.0] for _ in texts], dtype=np.float32)

    row = tr.Retriever(c, "rrf", _Enc()).rank(["Completely unrelated sentence about weather."], k=3)[0]
    assert len(row) == 3
