"""
Stage 3f, select mode — choose the techniques a passage shows, or none (ADR-0072).

Stage 3f's verify mode (`stage3f_ttp_verify`) checks the Stage 3 LLM's
techniques after the fact, trusts a high-confidence Stage 2c match without
asking, and keeps every claim when its call fails or cannot be parsed.  Stage
2c's matches reach the bundle with no check at all (Stage 3c seeds them), and
on AnnoCTR dev they are 55% of the predicted techniques at 0.16 precision.

Select mode inverts the contract.  Nothing becomes a technique without this
step:

  candidates  = the chunk's retrieved techniques (pipeline.ttp_retrieval)
              + the Stage 3 LLM's own proposals for the chunk
  selection   = one LLM call per chunk: pick the candidates the text shows
                being USED — several, or none — each with an exact quote
  validation  = code, not the model: JSON of the expected shape, an id that is
                one of the candidates, a quote found verbatim in the chunk, one
                entry per id.  A failed or unparseable call validates nothing:
                every candidate is returned for review, never kept by default.

A retrieved procedure example explains what a candidate looks like; the prompt
says it is never evidence of what happened in the report.  An exact quote only
proves the words exist — whether they support the technique is still judged by
a person on a sample (`python -m evaluation support-sample`).

Configuration:
  TTP_MODE=select                 — this path, the default (verify: the September baseline)
  TTP_SELECT_MIN_QUOTE_WORDS=3    — shorter quotes are returned for review
"""
from __future__ import annotations

import functools
import json
import re
from collections.abc import Callable, Sequence

from pydantic import BaseModel, Field

from api.logging_config import get_logger
from models.schemas import EvidenceLabel
from pipeline.env_flags import env_int
from pipeline.llm_parse import fit_text
from pipeline.regex_safety import compile_pattern
from pipeline.ttp_retrieval import TtpCandidate

logger = get_logger(__name__)

_ID_RE = compile_pattern(r"^T\d{4}(?:\.\d{3})?$")
_WS = compile_pattern(r"\s+")
_DEFINITION_CHARS = 180
_HINT_CHARS = 160
_MIN_RETRIEVED = 5      # retrieved candidates always offered, prompt limit or not

OK, FAILED, UNPARSED, NOTHING = "ok", "failed", "unparsed", "nothing_to_select"


class TtpReview(BaseModel):
    """A candidate nobody could decide: kept out of the bundle, shown to a person."""
    attack_id: str
    name: str = ""
    reason: str
    evidence_quote: str | None = None
    sources: list[str] = Field(default_factory=list)


class Selection(BaseModel):
    status: str                                   # ok | failed | unparsed | nothing_to_select
    selected: list = Field(default_factory=list)  # TTPExtracted, validated
    review: list[TtpReview] = Field(default_factory=list)
    rejected: int = 0                             # model answers that failed validation


_SELECT_SYSTEM = """\
You map a CTI report excerpt to MITRE ATT&CK techniques by choosing from a
fixed list of candidates.

Choose a candidate ONLY when a sentence of the excerpt describes the adversary
(or its malware/tool) actually USING that technique in the activity the report
covers.  Choose several when the excerpt shows several distinct behaviours.
Choose none when none is shown: an empty list is a correct and frequent answer.

Do NOT choose a candidate when the excerpt only:
- names a tool or malware without describing what it did;
- lists ATT&CK ids or names in a table or a list without describing behaviour;
- recommends a defence or a mitigation ("organisations should disable macros");
- describes a capability in general, a possibility, or what attackers "may" do;
- denies the action ("no data was exfiltrated");
- relies on what you know about the group or malware from outside this excerpt.

Parent or sub-technique: choose the sub-technique only when the excerpt shows
what distinguishes it (e.g. LSASS memory for T1003.001); otherwise the parent.

The "ATT&CK example" lines describe how a technique looked in OTHER reports.
They help you understand the candidate; they are never evidence for this one.

For each choice, evidence_quote is ONE passage COPIED CHARACTER FOR CHARACTER
from the excerpt (not paraphrased, not merged), and reason says which observed
behaviour matches the technique.  Return ONLY the JSON object, no markdown.
"""

_SELECT_USER_TEMPLATE = """\
Excerpt:
---
{text}
---

Candidates (choose only from these ids):
{candidates}

Return:
{{"selected": [{{"attack_id": "T1234.001", "evidence_quote": "exact passage from the excerpt",
                "reason": "observed behaviour"}}]}}
or {{"selected": []}} when the excerpt shows none of them."""


def ttp_mode() -> str:
    """TTP_MODE: "select" (default since docs/eval/baseline-2026-10.md) or "verify"."""
    import os

    mode = os.getenv("TTP_MODE", "select").strip().lower() or "select"
    if mode not in ("verify", "select"):
        logger.warning("TTP_MODE=%s is not verify or select — using select", mode)
        return "select"
    return mode


def _norm(s: str) -> str:
    return _WS.sub(" ", s).strip().lower()


@functools.lru_cache(maxsize=1)
def _definitions() -> dict[str, str]:
    try:
        from pipeline import mitre_db
        return {t["id"].upper(): (t.get("description") or "") for t in mitre_db.get_techniques()}
    except Exception:
        return {}


def _clip(s: str, n: int) -> str:
    s = _WS.sub(" ", s or "").strip()
    return s if len(s) <= n else s[: n - 1].rstrip() + "…"


def format_candidates(cands: Sequence[TtpCandidate]) -> str:
    """The numbered candidate list: id, name, definition, why it is proposed."""
    defs = _definitions()
    lines = []
    for c in cands:
        lines.append(f"- {c.attack_id} — {c.name or '(unnamed)'}: "
                     f"{_clip(defs.get(c.attack_id.upper(), ''), _DEFINITION_CHARS)}")
        if "llm" in c.sources:
            lines.append("    proposed by the extraction pass"
                         + (f' for: "{_clip(c.passage, _HINT_CHARS)}"' if c.passage else ""))
        elif c.passage:
            lines.append(f'    retrieved for: "{_clip(c.passage, _HINT_CHARS)}"')
        if c.example and c.example_kind == "procedure":
            lines.append(f"    ATT&CK example (other report, not evidence): {_clip(c.example, _HINT_CHARS)}")
    return "\n".join(lines)


def _fit_candidates(text: str, cands: list[TtpCandidate], max_chars: int | None) -> list[TtpCandidate]:
    """The candidates that fit in the prompt beside the whole text.

    The text is the evidence and is not cut for a candidate: past the limit
    the last retrieved candidates (the lowest ranked) are not offered, down to
    the LLM's own proposals and the best `_MIN_RETRIEVED` retrieved ones.  Only
    a text that alone outgrows the limit (never a Stage 1 chunk: ≤ 5,400
    characters against 32,000) is then cut by `fit_text`.
    """
    if max_chars is None:
        return cands
    budget = max_chars - len(_SELECT_USER_TEMPLATE.format(text=text, candidates=""))
    keep = list(cands)
    while len(format_candidates(keep)) > budget:
        retrieved = [i for i, c in enumerate(keep) if "llm" not in c.sources]
        if len(retrieved) <= _MIN_RETRIEVED:
            break
        keep.pop(retrieved[-1])
    return keep


def parse_selection(raw: str) -> list[dict] | None:
    """The `selected` list of the model's answer, or None when there is none.

    Accepts the object anywhere in the answer (a model may wrap it in a fence
    or a sentence) and a bare list; anything else is unparseable."""
    if not raw:
        return None
    decoder = json.JSONDecoder()
    i = 0
    while i < len(raw):
        if raw[i] not in "{[":
            i += 1
            continue
        try:
            obj, end = decoder.raw_decode(raw, i)
        except ValueError:
            i += 1
            continue
        if isinstance(obj, dict) and isinstance(obj.get("selected"), list):
            return [x for x in obj["selected"] if isinstance(x, dict)]
        if isinstance(obj, list) and all(isinstance(x, dict) for x in obj):
            return list(obj)
        # A complete value of another shape: never read a list nested in it
        # ({"chosen": []} is not an abstention).
        i = end
    return None


def select_ttps(
    text: str,
    candidates: Sequence[TtpCandidate],
    llm_fn: Callable[[str, str], str],
    *,
    llm_labels: dict[str, EvidenceLabel] | None = None,
    max_prompt_chars: int | None = None,
) -> Selection:
    """Ask the model which `candidates` the `text` shows; keep only what validates.

    `llm_labels` carries the Stage 3 LLM's evidence label for its own proposals,
    kept when a proposal is selected (a "gap" becomes "reported": the quote now
    exists).  Returns the selected techniques as TTPExtracted, the undecided
    candidates as TtpReview, and the call status.
    """
    from pipeline import llm_stats
    from pipeline.stage3_llm import TTPExtracted

    if not candidates:
        return Selection(status=NOTHING)
    offered = _fit_candidates(text, list(candidates), max_prompt_chars)
    if len(offered) < len(candidates):
        llm_stats.bump("ttp_selection_candidates_not_offered", len(candidates) - len(offered))
    by_id = {c.attack_id.upper(): c for c in offered}

    def review_all(reason: str) -> list[TtpReview]:
        return [TtpReview(attack_id=c.attack_id, name=c.name, reason=reason, sources=c.sources)
                for c in offered]

    prompt = fit_text(_SELECT_USER_TEMPLATE, text, max_prompt_chars,
                      candidates=format_candidates(offered))
    raw = llm_fn(_SELECT_SYSTEM, prompt)
    if not raw:
        llm_stats.bump("ttp_selection_failed")
        logger.warning("TTP selection call failed — %d candidates sent to review", len(offered))
        return Selection(status=FAILED, review=review_all("selection call failed"))
    items = parse_selection(raw)
    if items is None:
        llm_stats.bump("ttp_selection_unparsed")
        logger.warning("TTP selection answer unparseable — %d candidates sent to review", len(offered))
        return Selection(status=UNPARSED, review=review_all("selection answer unparseable"))
    llm_stats.bump("ttp_selection_ok")

    min_words = env_int("TTP_SELECT_MIN_QUOTE_WORDS", default=3)
    text_n = _norm(text)
    labels = {k.upper(): v for k, v in (llm_labels or {}).items()}
    selected: list = []
    review: list[TtpReview] = []
    seen: set[str] = set()
    rejected = 0
    for it in items:
        tid = str(it.get("attack_id") or it.get("id") or "").strip().upper()
        quote_raw, reason_raw = it.get("evidence_quote"), it.get("reason")
        quote = quote_raw if isinstance(quote_raw, str) else ""
        reason = reason_raw if isinstance(reason_raw, str) else ""
        if not _ID_RE.match(tid) or tid not in by_id:
            rejected += 1          # not one of the candidates: never a technique
            continue
        if tid in seen:
            continue
        seen.add(tid)
        cand = by_id[tid]
        q = quote.strip()
        if not q or len(q.split()) < min_words or _norm(q) not in text_n:
            rejected += 1
            review.append(TtpReview(attack_id=cand.attack_id, name=cand.name, sources=cand.sources,
                                    evidence_quote=q or None,
                                    reason="quote missing, too short or not found verbatim"))
            continue
        label = labels.get(tid, EvidenceLabel.REPORTED)
        if label == EvidenceLabel.GAP:
            label = EvidenceLabel.REPORTED
        selected.append(TTPExtracted(technique_name=cand.name or tid, mitre_id=cand.attack_id,
                                     description=reason.strip()[:500], evidence_text=q,
                                     evidence_label=label))
    if rejected:
        llm_stats.bump("ttp_selection_rejected", rejected)
    return Selection(status=OK, selected=selected, review=review, rejected=rejected)


def llm_proposals_as_candidates(ttps: Sequence) -> tuple[list[TtpCandidate], dict[str, EvidenceLabel], int]:
    """The Stage 3 LLM's techniques as candidates, ids resolved like Stage 3c.

    Returns (candidates, their evidence labels by id, proposals without an id).
    A proposal whose name and id resolve to no ATT&CK technique cannot be
    selected: the selector chooses ids."""
    from pipeline.stage3c_mitre import _resolve

    out: list[TtpCandidate] = []
    labels: dict[str, EvidenceLabel] = {}
    no_id = 0
    for t in ttps:
        name, tid, _ = _resolve(t.technique_name, t.mitre_id)
        if not tid or not re.match(r"^T\d{4}(\.\d{3})?$", tid.upper()):
            no_id += 1
            continue
        out.append(TtpCandidate(attack_id=tid.upper(), name=name, passage=t.evidence_text or "",
                                sources=["llm"], example=t.description or "", example_kind="llm"))
        labels[tid.upper()] = t.evidence_label
    return out, labels, no_id


def chunk_candidates(retrieved: Sequence[TtpCandidate], llm: Sequence[TtpCandidate]) -> list[TtpCandidate]:
    """The selector's candidate list for a chunk: the LLM's proposals first (never
    cut — a recall the LLM-only path had must not be lost to the cap), then the
    retrieved ones, one entry per id, provenance merged."""
    out: dict[str, TtpCandidate] = {}
    for c in list(llm) + list(retrieved):
        key = c.attack_id.upper()
        if key in out:
            inc = out[key]
            out[key] = inc.model_copy(update={
                "sources": sorted(set(inc.sources) | set(c.sources)),
                "example": inc.example if inc.example_kind == "procedure" else (c.example or inc.example),
                "example_kind": inc.example_kind if inc.example_kind == "procedure" else c.example_kind,
                "dense_rank": inc.dense_rank or c.dense_rank,
                "bm25_rank": inc.bm25_rank or c.bm25_rank,
                "fused_rank": inc.fused_rank or c.fused_rank,
            })
        else:
            out[key] = c
    return list(out.values())
