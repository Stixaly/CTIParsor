"""Copies and near-copies across evaluation splits.

The official AnnoCTR split keeps every vendor on every side by design, and
that stays.  What must not happen is the same report — reposted, translated
back, lightly edited — on both sides, or in the retrieval corpus (Phase 4)
and the test set at once.  Word 5-gram shingles, compared two ways: Jaccard
(the two texts are mostly the same) and containment (one is mostly inside the
other, e.g. an excerpt).
"""
from __future__ import annotations

import re
from itertools import combinations

_WORD = re.compile(r"[a-z0-9]+")


def shingles(text: str, n: int = 5) -> set[tuple[str, ...]]:
    words = _WORD.findall(text.lower())
    return {tuple(words[i:i + n]) for i in range(max(0, len(words) - n + 1))}


def similarity(a: set, b: set) -> tuple[float, float]:
    """(Jaccard, containment of the smaller in the larger)."""
    if not a or not b:
        return 0.0, 0.0
    inter = len(a & b)
    return inter / len(a | b), inter / min(len(a), len(b))


def near_duplicates(docs: dict[str, tuple[str, str]], threshold: float = 0.5) -> list[dict]:
    """`docs`: id -> (group, text), where group is the split (or corpus) name.
    Every pair whose Jaccard or containment reaches `threshold`, most similar
    first; `cross` says whether the two sit in different groups."""
    sh = {d: shingles(t) for d, (_, t) in docs.items()}
    out = []
    for a, b in combinations(sorted(docs), 2):
        jac, cont = similarity(sh[a], sh[b])
        if max(jac, cont) >= threshold:
            out.append({"a": a, "b": b, "group_a": docs[a][0], "group_b": docs[b][0],
                        "cross": docs[a][0] != docs[b][0],
                        "jaccard": round(jac, 3), "containment": round(cont, 3)})
    return sorted(out, key=lambda r: -max(r["jaccard"], r["containment"]))
