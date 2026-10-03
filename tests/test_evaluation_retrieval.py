"""evaluation/retrieval.py — the candidate-recall metrics (ADR-0072), on
hand-built documents whose answer is known."""
from __future__ import annotations

from evaluation import retrieval as rv

# Five passages; passage 2 is gated out.
SPANS = [(0, 10), (10, 20), (20, 30), (30, 40), (40, 50)]


def _doc(ranked, gold, kept=None, unlocated=()):
    kept = set(range(5)) - {2} if kept is None else kept
    return rv.DocRanking("d", 5, SPANS, kept, ranked, gold, set(unlocated), 1.0)


def test_passage_of_picks_the_largest_overlap():
    assert rv.passage_of(SPANS, 12, 14) == 1
    assert rv.passage_of(SPANS, 18, 29) == 2      # 2 chars in 1, 9 in 2
    assert rv.passage_of(SPANS, 60, 70) is None


def test_every_bucket():
    ranked = {0: ["T1059.001", "T1105"], 1: ["T1566"], 3: ["T1003"], 4: ["T1071"]}
    d = _doc(ranked, {
        "T1059": [(1, 5)],          # sub-technique ranked in its own passage: parent found
        "T1003": [(42, 45)],        # in passage 4; ranked in neighbour 3
        "T1071": [(12, 15)],        # in passage 1; ranked only in 4
        "T1486": [(31, 35)],        # passage 3 kept, never ranked
        "T1190": [(22, 25)],        # passage 2 gated out
        "T1027": [(70, 80)],        # outside every passage
    })
    assert rv.bucket(d, "T1059", 2) == rv.FOUND
    assert rv.bucket(d, "T1003", 2) == rv.NEIGHBOUR
    assert rv.bucket(d, "T1071", 2) == rv.ELSEWHERE
    assert rv.bucket(d, "T1486", 2) == rv.NOT_RANKED
    assert rv.bucket(d, "T1190", 2) == rv.GATED
    assert rv.bucket(d, "T1027", 2) == rv.NO_PASSAGE
    # exact level: the gold parent T1059 is not the ranked sub-technique
    assert rv.bucket(d, "T1059", 2, level="exact") == rv.NOT_RANKED


def test_k_truncates_each_passage_list():
    d = _doc({0: ["T1105", "T1059"]}, {"T1059": [(1, 5)]})
    assert rv.bucket(d, "T1059", 1) == rv.NOT_RANKED
    assert rv.bucket(d, "T1059", 2) == rv.FOUND


def test_recall_row_levels_and_units():
    d = _doc({0: ["T1059.001"], 1: ["T1566"], 3: [], 4: []},
             {"T1059": [(1, 5)], "T1566": [(32, 35)]}, unlocated={"T1486"})
    row = rv.recall_row([d], 1)
    # parent: T1059 in its passage; T1566 ranked in passage 1 only (elsewhere);
    # T1486 unlocated counts for the document recall only
    assert row["parent"]["passage_recall"] == 0.5
    assert row["parent"]["window_recall"] == 0.5
    assert row["parent"]["doc_recall"] == round(2 / 3, 4)
    assert row["parent"]["unique_ids_per_doc"] == 2.0
    assert row["exact"]["passage_recall"] == 0.0


def test_coverage_counts_mentions_in_kept_passages():
    d = _doc({}, {"T1059": [(1, 5), (22, 25)], "T1027": [(70, 80)]})
    c = rv.coverage([d])
    assert c["located_mentions"] == 3
    assert c["mentions_in_kept_passage"] == round(1 / 3, 4)
    assert c["mentions_outside_passages"] == 1
    assert c["kept_passages_per_doc"] == 4.0


def test_buckets_cover_every_located_gold_technique():
    d = _doc({0: ["T1059"]}, {"T1059": [(1, 5)], "T1190": [(22, 25)]})
    b = rv.buckets([d], 1)
    assert sum(b.values()) == 2 and b[rv.FOUND] == 1 and b[rv.GATED] == 1


def test_chunk_row_local_and_document_recall():
    d = rv.DocChunks(
        gold={"T1059.001": ["the actor ran powershell"], "T1486": ["files were encrypted"]},
        gold_ids={"T1059.001", "T1486", "T1190"},
        chunks=["intro. the actor ran powershell to fetch", "later files were encrypted by the payload"],
        candidates=[["T1059"], ["T1105", "T1190"]])
    row = rv.chunk_row([d])
    assert row["local_recall"] == 0.5          # T1059 in its chunk; T1486 never proposed
    assert row["doc_recall"] == round(2 / 3, 4)  # T1059 and T1190 somewhere
    assert row["candidates_per_chunk"] == 1.5 and row["chunks_per_doc"] == 2.0
