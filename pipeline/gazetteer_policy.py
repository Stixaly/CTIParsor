"""The gazetteer's ordinary-word policy (audit B 8.3.2).

`docs/gazetteer-ordinary-words.md` reviews 151 gazetteer forms that are also
ordinary words and gives each a decision:

- RETAIN: matched as before;
- CASE: matched when the text writes it with an initial capital ("Play",
  "PatchWork", "PLAY"), withheld in lowercase ("play a role");
- CONTEXT: matched only when the sentence names the object explicitly ("X,
  also known as Y", "Cuba ransomware", "Machete (S0409)", a command line).

And, for every form: an identity is never chosen by the order of the index.
23 forms name two MITRE objects ("snake": Turla and Uroburos; "play": the
actor and the ransomware); the matcher used to emit whichever came first.
Such a form is resolved only by an attached ATT&CK ID or an explicit alias
of one of the two.

The naming constructions are recognised by pipeline/gazetteer_context.py
(step 2).  The outcomes are the spec's:

- resolved: matched, one identity;
- unresolved: a named object may be there, its identity cannot be chosen
  (missing_context, ambiguous_identity);
- excluded: the occurrence fails the form's casing rule (case_mismatch), is
  another sense (conflicting_sense), is part of a URL or a file name
  (embedded), or the sentence names the other object of an ambiguous form
  (other_identity).

`GAZETTEER_POLICY` sets what Stage 2b does with them:

- shadow (default): emit exactly as before, and count what the policy would
  withhold (the stage report's `policy_*` counts) — the spec's shadow mode;
- apply: withhold every occurrence that is not resolved, before span
  claiming, so a later qualifying mention is still found.  For measurement
  (`scripts/measure_gazetteer_policy.py`) until the spec's acceptance gates
  pass on labelled data;
- off: no policy, no counts.

An analyst-promoted term (ADR-0052) is not judged: the spec leaves its
precedence to a later rule, so a promotion matches as it did.

The decisions are read from `pipeline/data/gazetteer_policy.json`, which
`scripts/build_gazetteer_policy.py` builds from the reviewed document.
"""
from __future__ import annotations

import functools
import json
import os
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path

from api.logging_config import get_logger
from pipeline import gazetteer_context

logger = get_logger(__name__)

_PATH = Path(__file__).parent / "data" / "gazetteer_policy.json"
MODES = ("off", "shadow", "apply")
DECISIONS = ("RETAIN", "CASE", "CONTEXT")


@dataclass(frozen=True)
class Judgement:
    outcome: str                 # resolved | unresolved | excluded
    reason: str | None = None    # case_mismatch | missing_context | ambiguous_identity | conflicting_sense
                                 # | embedded | other_identity
    decision: str | None = None  # the form's reviewed decision, None when it has none
    rule: str | None = None      # the construction that identified it (gazetteer_context)

    @property
    def withheld(self) -> bool:
        return self.outcome != "resolved"


RESOLVED = Judgement("resolved")


@dataclass(frozen=True)
class Occurrence:
    text: str
    start: int
    end: int
    name_key: str          # the gazetteer's lowercase match key
    identity: str          # the entry's ATT&CK ID (its canonical name when it has none)

    @property
    def surface(self) -> str:
        return self.text[self.start:self.end]


@dataclass(frozen=True)
class Index:
    """What the gazetteer says each form can be."""
    candidates: Mapping[str, Mapping[str, str]]   # name key -> {identity: entity type}
    names_by_id: Mapping[str, frozenset[str]]     # identity -> its name keys

    @property
    def ambiguous(self) -> frozenset[str]:
        return frozenset(name for name, ids in self.candidates.items() if len(ids) > 1)


def mode() -> str:
    value = (os.environ.get("GAZETTEER_POLICY") or "shadow").strip().lower()
    if value not in MODES:
        logger.warning(f"[gazetteer policy] GAZETTEER_POLICY={value!r} is not one of {MODES}; "
                       "shadow mode used")
        return "shadow"
    return value


@functools.lru_cache(maxsize=1)
def _policy() -> dict:
    try:
        data = json.loads(_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        logger.warning(f"[gazetteer policy] {_PATH.name} unreadable, no form has a decision: "
                       f"{type(exc).__name__}: {exc}")
        return {"version": None, "forms": {}}
    return data


def version() -> str | None:
    """The reviewed document's version, and the construction rules'."""
    doc, rules = _policy().get("version"), gazetteer_context.rules_version()
    return f"{doc}+{rules}" if doc and rules else doc


def decisions() -> dict[str, str]:
    return dict(_policy().get("forms", {}))


def _decision(name_key: str) -> str | None:
    return _policy().get("forms", {}).get(name_key)


def is_promoted(entry: dict) -> bool:
    """An entry an analyst promoted (pipeline/overrides.py), not one of the index's."""
    return entry.get("domain") == "override"


def identity(entry: dict) -> str:
    return entry.get("mitre_id") or entry["canonical"]


def build_index(entries: Iterable[dict]) -> Index:
    """The index's entries (promotions left out) by name and by identity."""
    candidates: dict[str, dict[str, str]] = {}
    names: dict[str, set[str]] = {}
    for e in entries:
        if not is_promoted(e):
            candidates.setdefault(e["name"], {})[identity(e)] = e["entity_type"]
            names.setdefault(identity(e), set()).add(e["name"])
    return Index(candidates, {i: frozenset(n) for i, n in names.items()})


def ambiguous_forms(entries: Iterable[dict]) -> frozenset[str]:
    """Match keys that name more than one MITRE object among the index's `entries`."""
    return build_index(entries).ambiguous


def judge(occ: Occurrence, index: Index) -> Judgement:
    """The policy's outcome for one occurrence of one gazetteer entry."""
    decision = _decision(occ.name_key)
    candidates = index.candidates.get(occ.name_key, {})
    ambiguous = len(candidates) > 1
    if decision == "CASE" and not occ.surface[:1].isupper():
        return Judgement("excluded", "case_mismatch", decision)
    if decision != "CONTEXT" and not ambiguous:
        return RESOLVED if decision is None else Judgement("resolved", None, decision)

    def anchor_ok(name: str, a0: int, a1: int, cid: str) -> bool:
        return _identified(Occurrence(occ.text, a0, a1, name, cid), index)

    ev = gazetteer_context.evidence(occ.text, occ.start, occ.end, occ.name_key, candidates,
                                    index.names_by_id, anchor_ok)
    if ev.excluded:
        return Judgement("excluded", ev.excluded, decision)
    if len(ev.ids) != 1:
        return Judgement("unresolved", "ambiguous_identity" if ambiguous or ev.ids else "missing_context",
                         decision)
    if occ.identity in ev.ids:
        return Judgement("resolved", None, decision, ev.rule)
    return Judgement("excluded", "other_identity", decision, ev.rule)


def _identified(anchor: Occurrence, index: Index) -> bool:
    """An alias's anchor is a name in its own right: capitalised if CASE,
    identified by a construction of its own if CONTEXT or ambiguous (but not
    by another alias)."""
    decision = _decision(anchor.name_key)
    candidates = index.candidates.get(anchor.name_key, {})
    if anchor.identity not in candidates:
        return False
    if decision == "CASE" and not anchor.surface[:1].isupper():
        return False
    if decision != "CONTEXT" and len(candidates) == 1:
        return not gazetteer_context.embedded(anchor.text, anchor.start, anchor.end)
    ev = gazetteer_context.evidence(anchor.text, anchor.start, anchor.end, anchor.name_key, candidates,
                                    index.names_by_id, None)
    return ev.ids == {anchor.identity}


def summary(trace: list[dict]) -> dict[str, int]:
    """Stage-report counts for a trace: how many emitted (shadow) or examined
    (apply) occurrences the policy withholds, by reason — an occurrence once,
    however many identities it could have been."""
    seen = {(item["start"], item["end"], item["reason"])
            for item in trace if item["outcome"] != "resolved"}
    counts: dict[str, int] = {}
    for _, _, reason in seen:
        counts[f"policy_{reason}"] = counts.get(f"policy_{reason}", 0) + 1
    return dict(sorted(counts.items()))
