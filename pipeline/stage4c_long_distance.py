"""
Stage 4c — LLM-backed long-distance relation inferer (Stage 4b, step 3).

Injected into ``complete_graph(long_distance_infer=...)``.  Given a report's
central node and its topic node (chosen by Stage 4b from two disconnected
sub-graphs), it asks the LLM whether the *text itself* states a relationship
between them — and requires the model to **quote the exact supporting sentence**,
the same evidence bar Stage 3d applies to extracted relationships (aCTIon,
ADR-004 P3-A).  No quote ⟹ no edge, so a cross-sub-graph link is only proposed
when the report actually asserts it.

Kept in a separate module so the STIX mapping (Stage 4/4b) stays network-free
unless a caller explicitly opts in via the policy ``completion.long_distance``
flag.  The LLM client is bound lazily (``default_long_distance_inferer``) to
avoid importing the network layer at mapping-module load time.
"""
from __future__ import annotations

import json
from typing import Callable, Optional

from api.logging_config import get_logger
from models.schemas import STIX_RELATIONSHIP_TYPES
from pipeline.stage4b_graph_completion import InferredEdge

logger = get_logger(__name__)

_SYSTEM = """\
You are a strict CTI relationship extractor.

You are given a report and TWO entities from it.  Decide whether the report text
directly and unambiguously states a relationship between them.

Rules:
- Assert a relationship ONLY if a single sentence in the text clearly states it
  (not implied, not inferred from background knowledge, not paraphrased).
- Choose the verb from this exact list: {verbs}.
- "source" says which entity is the subject of the verb: "a" or "b".
- Quote the EXACT sentence that supports the relationship.
- If no sentence supports any relationship between them, set related=false.
- Return ONLY valid JSON, no surrounding text or markdown fences.
"""

_USER_TEMPLATE = """\
Report text:
---
{text}
---

Entity A: "{a_name}" (type: {a_type})
Entity B: "{b_name}" (type: {b_type})

Does the text state a relationship between A and B?

Return a single JSON object:
{{"related": true, "source": "a", "verb": "uses", "quote": "exact sentence from text"}}
or
{{"related": false, "source": null, "verb": null, "quote": null}}"""


def _name(obj) -> str:
    if hasattr(obj, "get"):
        return obj.get("name") or obj.get("value") or ""
    return getattr(obj, "name", "") or getattr(obj, "value", "") or ""


def _type(obj) -> str:
    if hasattr(obj, "get"):
        return obj.get("type") or ""
    return getattr(obj, "type", "") or ""


def _parse(raw: str) -> Optional[dict]:
    """Return the first valid JSON object in the response, or None."""
    decoder = json.JSONDecoder()
    for i, ch in enumerate(raw):
        if ch == "{":
            try:
                obj, _ = decoder.raw_decode(raw, i)
                if isinstance(obj, dict):
                    return obj
            except json.JSONDecodeError:
                continue
    return None


def build_long_distance_inferer(
    llm_fn: Callable[[str, str], str],
    *,
    max_chars: int = 6_000,
    confidence: float = 0.6,
) -> Callable[[object, object, str], Optional[InferredEdge]]:
    """Build the ``(central, topic, report_text) -> InferredEdge | None`` callable
    that Stage 4b's long-distance step invokes, bound to ``llm_fn``."""
    system = _SYSTEM.format(verbs=", ".join(sorted(STIX_RELATIONSHIP_TYPES)))

    def infer(central, topic, report_text) -> Optional[InferredEdge]:
        a_name, b_name = _name(central), _name(topic)
        if not a_name or not b_name:
            return None
        prompt = _USER_TEMPLATE.format(
            text=(report_text or "")[:max_chars],
            a_name=a_name, a_type=_type(central),
            b_name=b_name, b_type=_type(topic),
        )
        raw = llm_fn(system, prompt)
        if not raw:
            return None
        data = _parse(raw)
        if not data or not data.get("related"):
            return None

        verb = str(data.get("verb") or "").strip().lower()
        if verb not in STIX_RELATIONSHIP_TYPES:
            return None
        quote = str(data.get("quote") or "").strip()
        if not quote:
            return None   # evidence bar: a supporting sentence is mandatory

        # "source" picks which entity is the subject of the verb.
        if str(data.get("source") or "a").strip().lower() == "b":
            src_id, tgt_id = topic.id, central.id
        else:
            src_id, tgt_id = central.id, topic.id
        return InferredEdge(
            source_id=src_id, verb=verb, target_id=tgt_id,
            confidence=confidence, evidence_text=quote,
        )

    return infer


def default_long_distance_inferer(
    policy: Optional[dict],
) -> Optional[Callable[[object, object, str], Optional[InferredEdge]]]:
    """Return an inferer bound to the configured Stage 3 LLM provider, or None.

    Returns None (long-distance stays off) when the policy does not enable
    ``completion.long_distance`` or when the LLM provider is not ready — so
    callers can pass the result to ``build_stix_bundle`` unconditionally.
    """
    comp = (policy or {}).get("completion") or {}
    if not comp.get("long_distance"):
        return None
    # Lazy import: keep the network layer out of module import graph.
    from pipeline.stage3_llm import _call_llm, _provider_ready

    if not _provider_ready():
        logger.info(
            "[Stage 4c] completion.long_distance enabled but LLM provider not "
            "ready — long-distance prediction skipped."
        )
        return None
    return build_long_distance_inferer(lambda s, u: _call_llm(s, u))
