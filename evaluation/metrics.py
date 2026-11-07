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


TTP_ERROR_CATEGORIES = ("found", "retrieved_not_selected", "never_retrieved",
                        "fp_from_candidates", "fp_outside_candidates")


def ttp_error_split(pred_ids: Iterable[str], gold_ids: Iterable[str], candidate_ids: Iterable[str],
                    review: dict[str, str], canonical: Callable[[str], str | None]
                    ) -> tuple[dict[str, list[str]], dict[str, int]]:
    """Where one document's parent-level technique errors come from (ADR-0072).

    Each gold parent is `found`, `retrieved_not_selected` (among the document's
    candidates or left for review, not shipped) or `never_retrieved`; each
    shipped parent that is not gold is `fp_from_candidates` or
    `fp_outside_candidates`.  Returns the parents in each category, and how
    often each review reason (`review`: item id -> reason) held back a gold one.

    The candidate list is the union over the report's chunks, so "retrieved"
    means retrieved for some chunk of the report, not necessarily the chunk
    that mentions the technique."""
    def parents(ids: Iterable[str]) -> set[str]:
        return {c.split(".", 1)[0] for i in ids if (c := canonical(i.upper())) is not None}

    gold, pred, cands = parents(gold_ids), parents(pred_ids), parents(candidate_ids)
    held: dict[str, str] = {}
    for rid, reason in review.items():
        for par in parents([rid]):
            held.setdefault(par, reason)
    split: dict[str, list[str]] = {k: [] for k in TTP_ERROR_CATEGORIES}
    reasons: dict[str, int] = {}
    for g in sorted(gold):
        if g in pred:
            split["found"].append(g)
        elif g in cands or g in held:
            split["retrieved_not_selected"].append(g)
            if g in held:
                reasons[held[g]] = reasons.get(held[g], 0) + 1
        else:
            split["never_retrieved"].append(g)
    for f in sorted(pred - gold):
        split["fp_from_candidates" if f in cands else "fp_outside_candidates"].append(f)
    return split, reasons


# ── Named entities (document level) ──────────────────────────────────────────

def _norm(v: str) -> str:
    return " ".join(v.lower().split())


def norm_forms(values: Iterable[str]) -> set[str]:
    """The normalised surface forms of one entity, for `score_entity_forms`."""
    return {_norm(v) for v in values}


def norm_triple(t) -> tuple[str, str, str]:
    """A (source, type, target) triple as the relation scores compare it."""
    return (_norm(t[0]), t[1].lower(), _norm(t[2]))


def _pair_weight(p: set[str], g: set[str], big: int) -> int:
    """`big` for an exact pair (a shared form), 1 for a partial one (a form
    contains another), 0 for none."""
    if p & g:
        return big
    return 1 if any(a in b or b in a for a in p for b in g if a and b) else 0


def _best_pairs(weight: list[list[int]]) -> list[tuple[int, int, int]]:
    """Maximum-weight one-to-one pairing of rows and columns (Hungarian method),
    so the total does not depend on the order of either side.  A weight of 0
    is no pair.  Returns (row, column, weight) for each pair made."""
    if not weight or not weight[0]:
        return []
    transposed = len(weight) > len(weight[0])
    w = [list(r) for r in zip(*weight, strict=True)] if transposed else weight
    n, m = len(w), len(w[0])
    cost = [[-x for x in row] for row in w]
    inf = sum(abs(x) for row in cost for x in row) + 1
    u = [0] * (n + 1)
    v = [0] * (m + 1)
    p = [0] * (m + 1)      # p[j]: the (1-based) row matched to column j, 0 if free
    way = [0] * (m + 1)
    for i in range(1, n + 1):
        p[0] = i
        j0 = 0
        minv = [inf] * (m + 1)
        used = [False] * (m + 1)
        while True:
            used[j0] = True
            i0, delta, j1 = p[j0], inf, 0
            for j in range(1, m + 1):
                if not used[j]:
                    cur = cost[i0 - 1][j - 1] - u[i0] - v[j]
                    if cur < minv[j]:
                        minv[j], way[j] = cur, j0
                    if minv[j] < delta:
                        delta, j1 = minv[j], j
            for j in range(m + 1):
                if used[j]:
                    u[p[j]] += delta
                    v[j] -= delta
                else:
                    minv[j] -= delta
            j0 = j1
            if p[j0] == 0:
                break
        while j0:
            j1 = way[j0]
            p[j0] = p[j1]
            j0 = j1
    pairs = []
    for j in range(1, m + 1):
        i, jj = p[j] - 1, j - 1
        if p[j] and w[i][jj] > 0:
            pairs.append((jj, i, w[i][jj]) if transposed else (i, jj, w[i][jj]))
    return pairs


def score_entity_forms(pred: list[tuple[str, set[str]]], gold: list[tuple[str, set[str]]],
                       lenient: bool = False) -> dict[str, Counts]:
    """`score_entities` on sets of normalised forms, for both sides: a pair is
    exact when the two sets share a form, partial when one form contains
    another.  The relation is symmetric, so swapping `pred` and `gold` swaps
    FP and FN and nothing else."""
    pred = list({(t, frozenset(f)): (t, f) for t, f in pred}.values())
    out: dict[str, Counts] = {}
    for etype in sorted({t for t, _ in pred} | {t for t, _ in gold}):
        ps = [f for t, f in pred if t == etype]
        gs = [f for t, f in gold if t == etype]
        # An exact pair outweighs any number of partial ones, so the matching
        # first maximises exact pairs, then the pairs of any kind.
        big = len(ps) + len(gs) + 1
        weight = [[_pair_weight(p, g, big) for g in gs] for p in ps]
        c = out.setdefault(etype, Counts())
        used_p: set[int] = set()
        used_g: set[int] = set()
        for pi, gi, w in _best_pairs(weight):
            used_p.add(pi)
            used_g.add(gi)
            if w == big or lenient:
                c.tp += 1
            else:
                c.fp += 1
                c.fn += 1
        c.fp += len(ps) - len(used_p)
        c.fn += len(gs) - len(used_g)
    return out


def score_entities(pred: list[tuple[str, str]], gold: list[tuple[str, str, set[str]]],
                   lenient: bool = False) -> dict[str, Counts]:
    """Per entity type, one document.  `pred`: (etype, value) the pipeline kept;
    `gold`: (etype, label, surface forms).  A prediction matches a gold entity
    of its type exactly when it equals the label or any surface form, partially
    when one contains the other.  One-to-one, maximising the exact pairs, then
    the pairs.  Strict: a partial pair is a FP and a FN (as in
    tests/eval_pipeline.score_sample)."""
    pred = list(dict.fromkeys((t, _norm(v)) for t, v in pred))
    gold_sets = [(t, {_norm(label)} | {_norm(s) for s in surfaces}) for t, label, surfaces in gold]
    return score_entity_forms([(t, {v}) for t, v in pred], gold_sets, lenient)


# ── Relationships (in-house set) ─────────────────────────────────────────────

def score_relations(pred: set[tuple[str, str, str]], gold: set[tuple[str, str, str]]) -> dict[str, Counts]:
    """(source, type, target) triples.  `strict`: both entities, the type and
    the direction.  `undirected_untyped`: the two entities are linked at all —
    reported alongside to tell a wrong verb or direction from a missing edge."""
    p, g = {norm_triple(t) for t in pred}, {norm_triple(t) for t in gold}
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
    rng = random.Random(seed)  # noqa: S311 — a reproducible resample, not a secret
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
