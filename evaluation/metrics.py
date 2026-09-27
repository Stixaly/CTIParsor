"""Scores for one run, per document, and paired comparisons between runs.

Every metric here keeps per-document counts, so that two configurations can be
compared on the same documents (paired bootstrap) and a document-level average
can be reported next to the micro-average.
"""
from __future__ import annotations

import random
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field


@dataclass
class Counts:
    tp: int = 0
    fp: int = 0
    fn: int = 0

    def __add__(self, other: Counts) -> Counts:
        return Counts(self.tp + other.tp, self.fp + other.fp, self.fn + other.fn)

    @property
    def precision(self) -> float:
        return self.tp / (self.tp + self.fp) if self.tp + self.fp else 0.0

    @property
    def recall(self) -> float:
        return self.tp / (self.tp + self.fn) if self.tp + self.fn else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if p + r else 0.0

    def as_dict(self) -> dict:
        return {"tp": self.tp, "fp": self.fp, "fn": self.fn,
                "precision": round(self.precision, 4), "recall": round(self.recall, 4),
                "f1": round(self.f1, 4)}


def set_counts(pred: set, gold: set) -> Counts:
    return Counts(len(pred & gold), len(pred - gold), len(gold - pred))


def micro(per_doc: Iterable[Counts]) -> Counts:
    total = Counts()
    for c in per_doc:
        total = total + c
    return total


def macro(per_doc: list[Counts]) -> dict:
    """Mean of per-document P/R/F1.  A document with no gold and no prediction
    is left out (it has nothing to average)."""
    rows = [c for c in per_doc if c.tp + c.fp + c.fn]
    if not rows:
        return {"precision": 0.0, "recall": 0.0, "f1": 0.0, "documents": 0}
    return {"precision": round(sum(c.precision for c in rows) / len(rows), 4),
            "recall": round(sum(c.recall for c in rows) / len(rows), 4),
            "f1": round(sum(c.f1 for c in rows) / len(rows), 4),
            "documents": len(rows)}


# ── TTPs ─────────────────────────────────────────────────────────────────────

@dataclass
class TTPDocScore:
    technique: Counts                 # parent level (AnnoCTR's own granularity)
    subtechnique: Counts              # exact ids
    explicit_recall: tuple[int, int]  # (found, gold) for techniques annotated explicitly
    implicit_recall: tuple[int, int]  # (found, gold) for techniques only annotated implicitly
    dropped_gold: list[str] = field(default_factory=list)   # out of scope after mapping


def score_ttps(pred_ids: set[str], gold_kinds: dict[str, set[str]],
               canonical: Callable[[str], str | None]) -> TTPDocScore:
    """One document.  `gold_kinds`: gold id -> {"explicit", "implicit"};
    `canonical` maps any id (gold or predicted) onto the scoring taxonomy and
    returns None for one out of scope.  Both sides go through it: a gold T1562
    and a predicted T1562 must meet on the same current id."""
    gold: dict[str, set[str]] = {}
    dropped = []
    for gid, kinds in gold_kinds.items():
        c = canonical(gid)
        if c is None:
            dropped.append(gid)
        else:
            gold.setdefault(c, set()).update(kinds)
    pred = {c for p in pred_ids if (c := canonical(p)) is not None}

    def parents(ids: Iterable[str]) -> set[str]:
        return {i.split(".", 1)[0] for i in ids}

    gold_parent_kinds: dict[str, set[str]] = {}
    for gid, kinds in gold.items():
        gold_parent_kinds.setdefault(gid.split(".", 1)[0], set()).update(kinds)
    pred_parents = parents(pred)
    explicit = {t for t, k in gold_parent_kinds.items() if "explicit" in k}
    implicit = {t for t, k in gold_parent_kinds.items() if k == {"implicit"}}
    return TTPDocScore(
        technique=set_counts(pred_parents, set(gold_parent_kinds)),
        subtechnique=set_counts(pred, set(gold)),
        explicit_recall=(len(explicit & pred_parents), len(explicit)),
        implicit_recall=(len(implicit & pred_parents), len(implicit)),
        dropped_gold=dropped,
    )


# ── Named entities (document level) ──────────────────────────────────────────

def _norm(v: str) -> str:
    return " ".join(v.lower().split())


def score_entities(pred: list[tuple[str, str]], gold: list[tuple[str, str, set[str]]],
                   lenient: bool = False) -> dict[str, Counts]:
    """Per entity type, one document.  `pred`: (etype, value) the pipeline kept;
    `gold`: (etype, label, surface forms).  A prediction matches a gold entity
    of its type exactly when it equals the label or any surface form, partially
    when one contains the other.  One-to-one, exact pairs first.  Strict: a
    partial pair is a FP and a FN (as in tests/eval_pipeline.score_sample)."""
    pred = list(dict.fromkeys((t, _norm(v)) for t, v in pred))
    gold_sets = [(t, {_norm(label)} | {_norm(s) for s in surfaces}) for t, label, surfaces in gold]
    cands = []
    for pi, (pt, pv) in enumerate(pred):
        for gi, (gt, forms) in enumerate(gold_sets):
            if pt != gt:
                continue
            if pv in forms:
                cands.append((0, pi, gi, True))
            elif any(pv in f or f in pv for f in forms if f and pv):
                cands.append((1, pi, gi, False))
    cands.sort()
    used_p: set[int] = set()
    used_g: set[int] = set()
    out: dict[str, Counts] = {}
    for _, pi, gi, exact in cands:
        if pi in used_p or gi in used_g:
            continue
        used_p.add(pi)
        used_g.add(gi)
        c = out.setdefault(pred[pi][0], Counts())
        if exact or lenient:
            c.tp += 1
        else:
            c.fp += 1
            c.fn += 1
    for pi, (pt, _) in enumerate(pred):
        if pi not in used_p:
            out.setdefault(pt, Counts()).fp += 1
    for gi, (gt, _) in enumerate(gold_sets):
        if gi not in used_g:
            out.setdefault(gt, Counts()).fn += 1
    return out


# ── Relationships (in-house set) ─────────────────────────────────────────────

def score_relations(pred: set[tuple[str, str, str]], gold: set[tuple[str, str, str]]) -> dict[str, Counts]:
    """(source, type, target) triples.  `strict`: both entities, the type and
    the direction.  `undirected_untyped`: the two entities are linked at all —
    reported alongside to tell a wrong verb or direction from a missing edge."""
    def norm(t):
        return (_norm(t[0]), t[1].lower(), _norm(t[2]))
    p, g = {norm(t) for t in pred}, {norm(t) for t in gold}
    loose = lambda s: {frozenset((a, c)) for a, _, c in s}  # noqa: E731
    return {"strict": set_counts(p, g), "undirected_untyped": set_counts(loose(p), loose(g))}


# ── Paired bootstrap ─────────────────────────────────────────────────────────

def paired_bootstrap(a: list[Counts], b: list[Counts], metric: str = "f1",
                     n: int = 2000, seed: int = 13) -> dict:
    """Difference b − a of a micro-averaged metric, resampling DOCUMENTS with
    replacement and scoring both configurations on the same resample.

    `a[i]` and `b[i]` must be the same document.  Returns the observed
    difference, a 95% percentile interval, and the share of resamples where b
    is not better (a one-sided p-value estimate)."""
    if len(a) != len(b) or not a:
        raise ValueError("paired bootstrap needs the same, non-empty document list on both sides")
    rng = random.Random(seed)
    idx = range(len(a))

    def value(counts: list[Counts], sample: Iterable[int]) -> float:
        return float(getattr(micro(counts[i] for i in sample), metric))

    observed = value(b, idx) - value(a, idx)
    diffs = []
    for _ in range(n):
        s = [rng.randrange(len(a)) for _ in idx]
        diffs.append(value(b, s) - value(a, s))
    diffs.sort()
    lo, hi = diffs[int(0.025 * n)], diffs[int(0.975 * n) - 1]
    return {"metric": metric, "observed_diff": round(observed, 4),
            "ci95": [round(lo, 4), round(hi, 4)],
            "p_not_better": round(sum(1 for d in diffs if d <= 0) / n, 4),
            "documents": len(a), "resamples": n}
