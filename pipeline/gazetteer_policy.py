"""The gazetteer's ordinary-word policy, step 1 (audit B 8.3.2).

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

Step 1 implements the decisions that need no language analysis: RETAIN, CASE,
and the ambiguous forms.  A CONTEXT form has no recogniser for its naming
constructions yet, so it is `unresolved` (missing_context).  The outcomes are
the spec's:

- resolved: matched, one identity;
- unresolved: a named object may be there, its identity cannot be chosen;
- excluded: the occurrence fails the form's casing rule.

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
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

from api.logging_config import get_logger

logger = get_logger(__name__)

_PATH = Path(__file__).parent / "data" / "gazetteer_policy.json"
MODES = ("off", "shadow", "apply")
DECISIONS = ("RETAIN", "CASE", "CONTEXT")


@dataclass(frozen=True)
class Judgement:
    outcome: str                 # resolved | unresolved | excluded
    reason: str | None = None    # case_mismatch | missing_context | ambiguous_identity
    decision: str | None = None  # the form's reviewed decision, None when it has none

    @property
    def withheld(self) -> bool:
        return self.outcome != "resolved"


RESOLVED = Judgement("resolved")


def mode() -> str:
    import os

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
    return _policy().get("version")


def decisions() -> dict[str, str]:
    return dict(_policy().get("forms", {}))


def is_promoted(entry: dict) -> bool:
    """An entry an analyst promoted (pipeline/overrides.py), not one of the index's."""
    return entry.get("domain") == "override"


def ambiguous_forms(entries: Iterable[dict]) -> frozenset[str]:
    """Match keys that name more than one MITRE object among the index's `entries`."""
    ids: dict[str, set] = {}
    for e in entries:
        if not is_promoted(e):
            ids.setdefault(e["name"], set()).add(e.get("mitre_id") or e.get("canonical"))
    return frozenset(name for name, found in ids.items() if len(found) > 1)


def judge(name_key: str, surface: str, ambiguous: frozenset[str]) -> Judgement:
    """The policy's outcome for one occurrence: `name_key` is the gazetteer's
    lowercase match key, `surface` the text as the report wrote it."""
    decision = decisions().get(name_key)
    if name_key in ambiguous:
        return Judgement("unresolved", "ambiguous_identity", decision)
    if decision == "CASE" and not surface[:1].isupper():
        return Judgement("excluded", "case_mismatch", decision)
    if decision == "CONTEXT":
        return Judgement("unresolved", "missing_context", decision)
    return RESOLVED if decision is None else Judgement("resolved", None, decision)


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
