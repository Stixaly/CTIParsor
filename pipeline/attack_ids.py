"""What an ATT&CK identifier written in a report is, against the bundled release (#980).

A report may write `T1059.001`, a revoked `T1562`, a mistyped `T1999` or a
tactic `TA0001`.  Stage 2 extracts them with a regular expression; this module
says which of the four each one is, so that every path (Stage 2 extraction,
the stored entity rows, the Stage 4 attack-pattern) treats them the same way
as the techniques the model proposes (Stage 3c already replaces a revoked id).

- known: the bundled index holds the technique;
- revoked: the index no longer holds it, and `attack_revoked.json` names the
  technique that replaced it (and the index holds that one);
- tactic: a TA#### id, which names a tactic, not a technique: it gives no
  attack-pattern;
- unknown: neither.  A report may cite a technique newer than the bundled
  release, or mistype one: the analyst decides, so it is held for review.
  ATT&CK's deprecated techniques are not in the index either, so they land here.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Literal

from pipeline import aliases, attack_data, mitre_db

Status = Literal["known", "revoked", "tactic", "unknown"]

_TACTIC = re.compile(r"TA\d{4}", re.ASCII)


@dataclass(frozen=True)
class Resolution:
    written: str            # the id as the report writes it, upper-cased
    status: Status
    mitre_id: str           # the id to use: the successor for a revoked one, else `written`


def resolve(attack_id: str) -> Resolution:
    """Classify one ATT&CK id (any case) against the bundled release."""
    aid = (attack_id or "").strip().upper()
    if _TACTIC.fullmatch(aid):
        return Resolution(aid, "tactic", aid)
    if aliases.technique_name_for(aid):
        return Resolution(aid, "known", aid)
    successor = mitre_db.replacement_for(aid)
    if successor and aliases.technique_name_for(successor):
        return Resolution(aid, "revoked", successor.upper())
    return Resolution(aid, "unknown", aid)


def release_version() -> str:
    """The ATT&CK version the run reads ("19.2"), for the reasons given to the analyst."""
    try:
        return attack_data.current().version
    except attack_data.UnknownAttackRelease:
        return attack_data.requested() or "unknown"


def unknown_reason(attack_id: str) -> str:
    """The review reason of an id the bundled release does not hold."""
    return (f"identifier absent from ATT&CK {release_version()}: a newer technique, "
            "a deprecated one, or a typo")
