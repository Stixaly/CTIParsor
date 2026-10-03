"""Candidate-retrieval recall on AnnoCTR (ADR-0072) — no LLM.

Retrieval caps every retrieve-then-select step: a technique the retriever
never proposes, no selector can choose.  For one configuration (corpus ×
retriever × keyword gate) and several k, this measures:

  doc recall      gold techniques found in the union of the passages' top-k
                  (the unit of the older `evaluation retrieval`)
  passage recall  ... in the top-k of a passage carrying an annotated mention
                  of that technique — what a per-passage selector sees
  window recall   ... in that passage or a neighbour (±1)
  gate coverage   annotated mentions whose passage survives the sentence gates

at parent level (primary, like the TTP score) and exact id, with the unique
candidate ids per document — the cost a selector pays — and an error bucket
per missed (document, technique), the retrieval half of the P0 error review.
"""
from __future__ import annotations

from dataclasses import dataclass, field

FOUND = "found in its passage"
NEIGHBOUR = "found in a neighbouring passage only"
ELSEWHERE = "found elsewhere in the document only"
NOT_RANKED = "passage kept, technique not in its top-k"
GATED = "passage dropped by the sentence gates"
NO_PASSAGE = "mention outside any passage (heading, short line)"
BUCKETS = (FOUND, NEIGHBOUR, ELSEWHERE, NOT_RANKED, GATED, NO_PASSAGE)


def parent(tid: str) -> str:
    return tid.split(".", 1)[0].upper()


@dataclass
class DocRanking:
    doc_id: str
    n_passages: int                                   # every passage of the document
    spans: list[tuple[int, int]]                      # (start, end) of every passage
    kept: set[int]                                    # passages surviving the gates
    ranked: dict[int, list[str]]                      # kept passage -> canonical ids, best first
    gold: dict[str, list[tuple[int, int]]]            # canonical gold id -> located mention spans
    gold_unlocated: set[str] = field(default_factory=set)
    seconds: float = 0.0


def passage_of(spans: list[tuple[int, int]], start: int, end: int) -> int | None:
    """Index of the passage that overlaps [start, end) the most, or None."""
    best, best_len = None, 0
    for i, (s, e) in enumerate(spans):
        if e <= start:
            continue
        if s >= end:
            break
        ov = min(e, end) - max(s, start)
        if ov > best_len:
            best, best_len = i, ov
    return best


def _ids_at(doc: DocRanking, idx: int, k: int, level: str) -> set[str]:
    ids = doc.ranked.get(idx, [])[:k]
    return {parent(t) for t in ids} if level == "parent" else set(ids)


def _gold_key(tid: str, level: str) -> str:
    return parent(tid) if level == "parent" else tid


def bucket(doc: DocRanking, gold_id: str, k: int, level: str = "parent") -> str:
    """Where retrieval lost — or found — one gold technique of one document."""
    key = _gold_key(gold_id, level)
    spans = [sp for g, sps in doc.gold.items() if _gold_key(g, level) == key for sp in sps]
    homes = [passage_of(doc.spans, s, e) for s, e in spans]
    homes_i = [h for h in homes if h is not None]
    if any(key in _ids_at(doc, h, k, level) for h in homes_i if h in doc.kept):
        return FOUND
    near = {q for h in homes_i for q in (h - 1, h + 1)} & doc.kept
    if any(key in _ids_at(doc, q, k, level) for q in near):
        return NEIGHBOUR
    if any(key in _ids_at(doc, q, k, level) for q in doc.kept):
        return ELSEWHERE
    if any(h in doc.kept for h in homes_i):
        return NOT_RANKED
    if homes_i:
        return GATED
    return NO_PASSAGE


def recall_row(docs: list[DocRanking], k: int) -> dict:
    """Recall at k over `docs`, parent level and exact id."""
    row: dict = {"k": k}
    for level in ("parent", "exact"):
        found_doc = gold_doc = 0
        found_p = found_w = gold_loc = 0
        cands = 0
        for d in docs:
            gold_all = {_gold_key(g, level) for g in d.gold} | {_gold_key(g, level) for g in d.gold_unlocated}
            union: set[str] = set()
            for i in d.kept:
                union |= _ids_at(d, i, k, level)
            found_doc += len(gold_all & union)
            gold_doc += len(gold_all)
            cands += len(union)
            for key in {_gold_key(g, level) for g in d.gold}:
                b = bucket(d, key, k, level)
                gold_loc += 1
                found_p += b == FOUND
                found_w += b in (FOUND, NEIGHBOUR)
        row[level] = {
            "doc_recall": round(found_doc / gold_doc, 4) if gold_doc else None,
            "passage_recall": round(found_p / gold_loc, 4) if gold_loc else None,
            "window_recall": round(found_w / gold_loc, 4) if gold_loc else None,
            "unique_ids_per_doc": round(cands / len(docs), 1) if docs else None,
        }
    return row


def coverage(docs: list[DocRanking]) -> dict:
    """Located mentions whose passage survives the gates; passages per document."""
    mentions = kept = no_passage = 0
    for d in docs:
        for spans in d.gold.values():
            for s, e in spans:
                mentions += 1
                h = passage_of(d.spans, s, e)
                if h is None:
                    no_passage += 1
                elif h in d.kept:
                    kept += 1
    n = len(docs) or 1
    return {
        "located_mentions": mentions,
        "mentions_in_kept_passage": round(kept / mentions, 4) if mentions else None,
        "mentions_outside_passages": no_passage,
        "unlocated_gold_ids": sum(len(d.gold_unlocated) for d in docs),
        "passages_per_doc": round(sum(d.n_passages for d in docs) / n, 1),
        "kept_passages_per_doc": round(sum(len(d.kept) for d in docs) / n, 1),
        "seconds_per_doc": round(sum(d.seconds for d in docs) / n, 2),
    }


def buckets(docs: list[DocRanking], k: int, level: str = "parent") -> dict[str, int]:
    out = dict.fromkeys(BUCKETS, 0)
    for d in docs:
        for key in {_gold_key(g, level) for g in d.gold}:
            out[bucket(d, key, k, level)] += 1
    return out


# ── What the selector actually sees: candidates per chunk ────────────────────

@dataclass
class DocChunks:
    """One document as the select path cuts it."""
    gold: dict[str, list[str]]        # canonical gold id -> passages (normalised) carrying a mention
    gold_ids: set[str]                # every canonical gold id, located or not
    chunks: list[str]                 # chunk texts, whitespace normalised
    candidates: list[list[str]]       # canonical candidate ids per chunk (merged, capped)


def chunk_row(docs: list[DocChunks]) -> dict:
    """Parent-level recall of the per-chunk candidate lists.

    local  a gold technique is in the list of a chunk that contains one of
           its annotated passages — the selector can choose it there;
    doc    it is in the list of some chunk of the document.
    """
    found_local = gold_local = found_doc = gold_doc = 0
    n_chunks = n_cands = 0
    for d in docs:
        sets = [{parent(t) for t in c} for c in d.candidates]
        union = set().union(*sets) if sets else set()
        gold_parents = {parent(g) for g in d.gold_ids}
        found_doc += len(gold_parents & union)
        gold_doc += len(gold_parents)
        by_parent: dict[str, list[str]] = {}
        for g, ps in d.gold.items():
            by_parent.setdefault(parent(g), []).extend(ps)
        for gp, passages in by_parent.items():
            gold_local += 1
            found_local += any(gp in sets[j] for j, ch in enumerate(d.chunks)
                               for p in passages if p and p in ch)
        n_chunks += len(d.chunks)
        n_cands += sum(len(c) for c in d.candidates)
    return {
        "local_recall": round(found_local / gold_local, 4) if gold_local else None,
        "doc_recall": round(found_doc / gold_doc, 4) if gold_doc else None,
        "candidates_per_chunk": round(n_cands / n_chunks, 1) if n_chunks else None,
        "chunks_per_doc": round(n_chunks / len(docs), 1) if docs else None,
    }
