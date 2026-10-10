"""Does the evidence behind a technique hold up?  Three separate questions.

1. **exists** — the quote the model gave is in the document (evidence_span.locate).
2. **on the annotated passage** — for a correct technique, the quote overlaps a
   passage the annotators marked for that technique.  This checks location, not
   meaning: a quote can sit on the right sentence and still not say what the
   technique claims.
3. **supports the claim** — only a person can say.  `support_sample` draws a
   reproducible sample for review; `docs/eval/README.md` says how to fill it.
"""
from __future__ import annotations

import csv
import random
from dataclasses import dataclass
from pathlib import Path

# A quote this close to an annotated mention (in characters) counts as "near":
# the annotation marks a phrase, the model often quotes the sentence around it.
NEAR = 200


@dataclass
class EvidenceRow:
    doc_id: str
    technique: str          # canonical parent id
    correct: bool           # the technique is in the gold set
    quote: str
    located: tuple[int, int] | None
    on_passage: bool | None    # None: not located or not a correct technique
    near_passage: bool | None


def check(doc_id: str, text: str, ttps: list[dict], gold_spans: dict[str, list[tuple[int, int]]],
          canonical) -> list[EvidenceRow]:
    """`ttps`: [{"mitre_id", "evidence_text"}]; `gold_spans`: parent id -> located
    mention spans.  One row per predicted technique that carries a quote."""
    from pipeline.evidence_span import locate

    rows = []
    for t in ttps:
        quote = (t.get("evidence_text") or "").strip()
        cid = canonical(t.get("mitre_id") or "")
        if not quote or not cid:
            continue
        tech = cid.split(".", 1)[0]
        span = locate(quote, text)
        located = (span.start, span.end) if span else None
        spans = gold_spans.get(tech, [])
        correct = tech in gold_spans
        on = near = None
        if located and correct:
            on = any(located[0] < e and s < located[1] for s, e in spans)
            near = any(located[0] < e + NEAR and s - NEAR < located[1] for s, e in spans)
        rows.append(EvidenceRow(doc_id, tech, correct, quote, located, on, near))
    return rows


def summarise(rows: list[EvidenceRow]) -> dict:
    with_quote = len(rows)
    located = [r for r in rows if r.located]
    correct_located = [r for r in located if r.correct]

    def share(n: int, d: int) -> float | None:
        return round(n / d, 4) if d else None

    return {
        "ttps_with_quote": with_quote,
        "exists": share(len(located), with_quote),
        "correct_and_located": len(correct_located),
        "on_annotated_passage": share(sum(1 for r in correct_located if r.on_passage), len(correct_located)),
        "near_annotated_passage": share(sum(1 for r in correct_located if r.near_passage),
                                        len(correct_located)),
    }


def support_sample(rows: list[EvidenceRow], texts: dict[str, str], path: Path, n: int = 50,
                   seed: int = 7) -> int:
    """Write a CSV of `n` located quotes (correct and incorrect techniques mixed)
    for a person to judge: does the passage show the technique being USED?
    Negated or hypothetical mentions ("no persistence was observed", a defensive
    recommendation) are a "no"."""
    from pipeline.mitre_db import lookup_by_id

    def technique_name(tid: str) -> str:
        entry = lookup_by_id(tid)
        return (entry or {}).get("name", "")

    pool = [r for r in rows if r.located]
    rng = random.Random(seed)  # noqa: S311 — a reproducible sample, not a secret
    picked = rng.sample(pool, min(n, len(pool)))
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["doc_id", "technique", "technique_name", "in_gold", "quote", "context",
                    "supports_use (yes/no/unsure)", "note"])
        for r in picked:
            s, e = r.located  # type: ignore[misc]
            text = texts[r.doc_id]
            ctx = text[max(0, s - 300):min(len(text), e + 300)].replace("\n", " ")
            w.writerow([r.doc_id, r.technique, technique_name(r.technique), r.correct,
                        r.quote, ctx, "", ""])
    return len(picked)
