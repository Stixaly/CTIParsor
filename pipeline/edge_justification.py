"""
Why a relationship exists, written as Markdown: the `description` of each SRO
Stage 4 builds (ADR-0093).

A description is the sentence the report quotes for the link, when there is
one, then why the link exists, then its evidence grade and confidence.  OpenCTI
shows that text as GitHub-flavoured Markdown, so every value taken from the
report, the ledger or an object's name goes through `markdown_text` first.

No relationship id ever appears in it: those are random uuid4s, so the text
would change between two builds of the same job.  A premise with no name is
left out instead.
"""
from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from pipeline.bundle_ledger import _rel_origin_from_props
from pipeline.markdown_text import blockquote, escape_inline

# The `x_inference_rule` of an ATT&CK-reference edge: "attack-reference:G0016>S0002".
_REFERENCE_PREFIX = "attack-reference:"


def justify(sro: Mapping[str, Any], origin: Mapping[str, Any] | None,
            names: Mapping[str, str]) -> str:
    """The description of `sro`: its title, the quoted sentence, why the link
    exists, then the evidence, as Markdown blocks separated by a blank line.
    `origin` is the ledger entry for `sro`, or None; `names` maps the id of
    every object and relationship to its display name."""
    source = _label(sro["source_ref"], names)
    target = _label(sro["target_ref"], names)
    blocks = [f"**{source}** `{sro['relationship_type']}` **{target}**"]

    quote = _quote(sro)
    if quote is not None:
        blocks.append(blockquote(quote))

    why = _why(_kind(sro, origin), sro, origin or {}, names, (source, target))
    if why is not None:
        blocks.append(f"**Why:** {why}")

    evidence = _evidence(sro)
    if evidence is not None:
        blocks.append(evidence)
    return "\n\n".join(blocks)


def _kind(sro: Mapping[str, Any], origin: Mapping[str, Any] | None) -> str:
    """The origin the ledger recorded for `sro`.  When it recorded none, or
    "unknown", the origin the SRO's own properties give."""
    if origin is not None:
        recorded = origin.get("origin")
        if isinstance(recorded, str) and recorded and recorded != "unknown":
            return recorded
    # Same classification as the ledger uses for an SRO with no recorded origin.
    return _rel_origin_from_props(sro)


def _why(kind: str, sro: Mapping[str, Any], info: Mapping[str, Any],
         names: Mapping[str, str], subject: tuple[str, str]) -> str | None:
    """The Why sentence for an origin `kind`.  None when the origin has none, or
    when the ledger lacks a fact the sentence needs."""
    if kind == "extracted":
        if _quote(sro) is not None:
            return "The report states this link in the sentence quoted above."
        return ("A relationship row of this job (extracted from the report or added by an analyst), "
                "with no supporting sentence quoted.")
    if kind == "ioc_based_on":
        return "The indicator's pattern is built from this observable, which the report lists."
    if kind == "ioc_association":
        return _ioc_association(info)
    if kind == "embedded_rule_title":
        return _embedded_rule_title(info)
    if kind == "targeted_location":
        return _targeted_location(info, subject)
    if kind == "policy_pin":
        return _policy_pin(sro)
    if kind == "completion_reference":
        return _reference(sro)
    if kind == "completion_transitive":
        return _transitive(sro, names)
    if kind == "completion_long_distance":
        return "Inferred by the language model from the report; the quoted sentence was found in its text."
    return None


def _ioc_association(info: Mapping[str, Any]) -> str | None:
    ioc = _named(info.get("ioc_value"))
    if ioc is None:
        return None
    malware = _named(info.get("malware_name"))
    if malware is None:
        return f"The report associates the indicator value {ioc} with this malware."
    return f"The report associates the indicator value {ioc} with **{malware}**."


def _embedded_rule_title(info: Mapping[str, Any]) -> str | None:
    title = _named(info.get("title"))
    name = _named(info.get("name"))
    if title is None or name is None:
        return None
    return f"The detection rule **{title}**, quoted in the report, names **{name}** in its title."


def _targeted_location(info: Mapping[str, Any], subject: tuple[str, str]) -> str:
    # The ledger names the actor and the target; the titles stand in when it does not.
    actor = _named(info.get("actor")) or subject[0]
    target = _named(info.get("target")) or subject[1]
    return (f"The report names **{actor}** as a threat actor and **{target}** as a target. "
            "CTIParsor links every threat actor of the report to every target it names, "
            "so the report may not say that this actor targets this one.")


def _policy_pin(sro: Mapping[str, Any]) -> str | None:
    rule = sro.get("x_policy_rule")
    if not isinstance(rule, str) or not rule:
        return None
    text = (f"Added by the relationship policy rule {_rule_text(rule)}: "
            "the analyst's link model, not a claim the report makes.")
    pin = sro.get("x_pin_evidence")
    if pin == "cosentence":
        return text + " Both objects are named in one sentence of the report."
    if pin == "unanchorable":
        return text + " Whether the report names them together could not be checked."
    # "window:N": the closest sentences naming each are N sentences apart.
    if isinstance(pin, str) and pin.startswith("window:") and pin[len("window:"):].isdigit():
        n = int(pin[len("window:"):])
        return text + f" The report names them {n} sentence{'s' if n != 1 else ''} apart."
    return text


def _reference(sro: Mapping[str, Any]) -> str:
    rule = sro.get("x_inference_rule")
    if isinstance(rule, str) and rule.startswith(_REFERENCE_PREFIX):
        ids = rule[len(_REFERENCE_PREFIX):].split(">")
        if len(ids) == 2 and all(ids):
            return (f"MITRE ATT&CK records this link ({escape_inline(ids[0])} → {escape_inline(ids[1])}); "
                    "the report does not state it.")
    # A rule that does not read as two ids still says where the link comes from.
    return "MITRE ATT&CK records this link; the report does not state it."


def _transitive(sro: Mapping[str, Any], names: Mapping[str, str]) -> str:
    # A premise the names do not know is left out: its id is a random uuid4.
    named = [_named(names.get(pid)) for pid in sro.get("x_inferred_from", [])]
    premises = [p for p in named if p is not None]
    if not premises:
        return "Inferred by composing two links of this bundle. The report does not state it."
    joined = "; ".join(premises)
    return f"Inferred by composing two links of this bundle: {joined}. The report does not state it."


def _rule_text(rule: str) -> str:
    """A policy rule name in a code span, which keeps its characters as they are.
    A backtick would end the span, so such a name is escaped instead."""
    if "`" in rule:
        return escape_inline(rule)
    return f"`{rule}`"


def _evidence(sro: Mapping[str, Any]) -> str | None:
    """The evidence grade and the confidence on one line, or None when the SRO
    carries neither.  A bool counts as an int in Python, so it is not a confidence."""
    facts: list[str] = []
    label = sro.get("x_evidence_label")
    if isinstance(label, str) and label:
        facts.append(f"**Evidence:** {label}")
    confidence = sro.get("confidence")
    if isinstance(confidence, int) and not isinstance(confidence, bool):
        facts.append(f"**Confidence:** {confidence}/100")
    if not facts:
        return None
    return " · ".join(facts)


def _quote(sro: Mapping[str, Any]) -> str | None:
    """The sentence the report quotes for `sro`, or None when there is none."""
    text = sro.get("x_evidence_text")
    if isinstance(text, str) and text.strip():
        return text
    return None


def _label(ref: str, names: Mapping[str, str]) -> str:
    """The display name of `ref` as Markdown text, or its id when it has no name."""
    return escape_inline(names.get(ref) or ref)


def _named(value: Any) -> str | None:
    """`value` as Markdown text when it is a non-empty string, else None."""
    if isinstance(value, str) and value:
        return escape_inline(value)
    return None
