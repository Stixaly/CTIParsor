"""evaluation/retrieval.chunk_row — `local_recall` for a passage longer than a
chunk (#460): a passage counts when a chunk lies inside it, not only when the
passage fits in a chunk."""
from __future__ import annotations

from evaluation import retrieval as rv
from pipeline.stage1_ingestion import chunk_text
from pipeline.ttp_retrieval import split_passages


def _chunked(text: str) -> tuple[list[str], list[str]]:
    """(passages, whitespace-normalised chunks) of `text`, as the select path cuts it."""
    passages = [p.text for p in split_passages(text)]
    chunks = [" ".join(c.split()) for c in chunk_text(text, max_chars=3000)]
    return passages, chunks


def test_long_passage_is_found_in_the_chunks_it_covers_issue_460():
    # A Markdown table run without sentence punctuation: one passage of ~12 900
    # characters, cut into chunks of at most 3 400.
    rows = " ".join(f"| Actor {i} | uses T1059.001 PowerShell to run commands | 2019 |" for i in range(200))
    text = "Intro sentence about the campaign. " + rows + " End of report."
    passages, chunks = _chunked(text)
    long_passage = max(passages, key=len)
    assert len(long_passage) > max(len(c) for c in chunks)      # the case under test
    d = rv.DocChunks(gold={"T1059": [long_passage]}, gold_ids={"T1059"}, chunks=chunks,
                     candidates=[["T1059"] for _ in chunks])
    assert rv.chunk_row([d])["local_recall"] == 1.0


def test_sentence_passages_still_found_issue_460():
    # Control: passages that fit in a chunk keep the containment test.
    text = " ".join(f"Sentence {i} describes how the actor uses T1059 PowerShell for execution."
                    for i in range(300))
    passages, chunks = _chunked(text)
    p = next(p for p in passages if "T1059" in p)
    d = rv.DocChunks(gold={"T1059": [p]}, gold_ids={"T1059"}, chunks=chunks,
                     candidates=[["T1059"] for _ in chunks])
    assert rv.chunk_row([d])["local_recall"] == 1.0


def test_passage_sharing_no_text_with_the_candidate_chunk_is_not_found_issue_460():
    # The candidate chunk holds no text of the passage: still a miss.
    d = rv.DocChunks(gold={"T1059": ["alpha beta gamma delta epsilon"]}, gold_ids={"T1059"},
                     chunks=["intro about the campaign", "unrelated later text"],
                     candidates=[["T1059"], []])
    assert rv.chunk_row([d])["local_recall"] == 0.0
