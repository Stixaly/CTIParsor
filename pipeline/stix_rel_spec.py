"""
STIX 2.1 suggested-relationship constraints.

Source of truth: the per-SDO "Relationships" summary tables and the Common
Relationships section (§3.7) of the OASIS *STIX Version 2.1* specification.

Why this exists
---------------
STIX 2.1 explicitly PERMITS relationships that are not in these tables
("Relationships are not restricted to those listed below"), and the default
stix2validator run therefore reports a non-listed edge as *valid*.  But the
spec's **strict / best-practice** check ({202}) flags any (source, verb, target)
triple that is not a *suggested* relationship for that object-type pair.

`rel_is_suggested()` lets the STIX mapper keep every emitted relationship within
the suggested model: a verb that is not suggested for a pair is downgraded to
the universal ``related-to`` (always valid between any two objects per §3.7)
instead of being emitted as a non-conformant edge.

The table below is transcribed verbatim from stix-v2.1-os; ``"*SCO*"`` is the
spec's "<All STIX Cyber-observable Objects>" wildcard.
"""
from __future__ import annotations

# All STIX 2.1 SCO (cyber-observable) types — §6.
SCO_TYPES: frozenset[str] = frozenset({
    "artifact", "autonomous-system", "directory", "domain-name", "email-addr",
    "email-message", "file", "ipv4-addr", "ipv6-addr", "mac-addr", "mutex",
    "network-traffic", "process", "software", "url", "user-account",
    "windows-registry-key", "x509-certificate",
})

# Common relationships (§3.7) usable between ANY two objects.
_UNIVERSAL_ANY: frozenset[str] = frozenset({"related-to"})
# Common relationships valid only when source and target share the same type.
_UNIVERSAL_SAME_TYPE: frozenset[str] = frozenset({"duplicate-of", "derived-from"})

# Forward relationship summaries, keyed by source type → verb → {target types}.
_SUGGESTED: dict[str, dict[str, frozenset[str]]] = {
    "attack-pattern": {
        "delivers": frozenset({"malware"}),
        "targets": frozenset({"identity", "location", "vulnerability"}),
        "uses": frozenset({"malware", "tool"}),
    },
    "campaign": {
        "attributed-to": frozenset({"intrusion-set", "threat-actor"}),
        "compromises": frozenset({"infrastructure"}),
        "originates-from": frozenset({"location"}),
        "targets": frozenset({"identity", "location", "vulnerability"}),
        "uses": frozenset({"attack-pattern", "infrastructure", "malware", "tool"}),
    },
    "course-of-action": {
        "investigates": frozenset({"indicator"}),
        "mitigates": frozenset({"attack-pattern", "indicator", "malware", "tool", "vulnerability"}),
        "remediates": frozenset({"malware", "vulnerability"}),
    },
    "domain-name": {
        "resolves-to": frozenset({"domain-name", "ipv4-addr", "ipv6-addr"}),
    },
    "identity": {
        "located-at": frozenset({"location"}),
    },
    "indicator": {
        "based-on": frozenset({"observed-data"}),
        "indicates": frozenset({"attack-pattern", "campaign", "infrastructure",
                                "intrusion-set", "malware", "threat-actor", "tool"}),
    },
    "infrastructure": {
        "communicates-with": frozenset({"domain-name", "infrastructure", "ipv4-addr", "ipv6-addr", "url"}),
        "consists-of": frozenset({"*SCO*", "infrastructure", "observed-data"}),
        "controls": frozenset({"infrastructure", "malware"}),
        "delivers": frozenset({"malware"}),
        "has": frozenset({"vulnerability"}),
        "hosts": frozenset({"malware", "tool"}),
        "located-at": frozenset({"location"}),
        "uses": frozenset({"infrastructure"}),
    },
    "intrusion-set": {
        "attributed-to": frozenset({"threat-actor"}),
        "compromises": frozenset({"infrastructure"}),
        "hosts": frozenset({"infrastructure"}),
        "originates-from": frozenset({"location"}),
        "owns": frozenset({"infrastructure"}),
        "targets": frozenset({"identity", "location", "vulnerability"}),
        "uses": frozenset({"attack-pattern", "infrastructure", "malware", "tool"}),
    },
    "ipv4-addr": {
        "belongs-to": frozenset({"autonomous-system"}),
        "resolves-to": frozenset({"mac-addr"}),
    },
    "ipv6-addr": {
        "belongs-to": frozenset({"autonomous-system"}),
        "resolves-to": frozenset({"mac-addr"}),
    },
    "malware": {
        "authored-by": frozenset({"intrusion-set", "threat-actor"}),
        "beacons-to": frozenset({"infrastructure"}),
        "communicates-with": frozenset({"domain-name", "ipv4-addr", "ipv6-addr", "url"}),
        "controls": frozenset({"malware"}),
        "downloads": frozenset({"file", "malware", "tool"}),
        "drops": frozenset({"file", "malware", "tool"}),
        "exfiltrates-to": frozenset({"infrastructure"}),
        "exploits": frozenset({"vulnerability"}),
        "originates-from": frozenset({"location"}),
        "targets": frozenset({"identity", "infrastructure", "location", "vulnerability"}),
        "uses": frozenset({"attack-pattern", "infrastructure", "malware", "tool"}),
        "variant-of": frozenset({"malware"}),
    },
    "malware-analysis": {
        "characterizes": frozenset({"malware"}),
        "analysis-of": frozenset({"malware"}),
        "static-analysis-of": frozenset({"malware"}),
        "dynamic-analysis-of": frozenset({"malware"}),
    },
    "threat-actor": {
        "attributed-to": frozenset({"identity"}),
        "compromises": frozenset({"infrastructure"}),
        "hosts": frozenset({"infrastructure"}),
        "impersonates": frozenset({"identity"}),
        "located-at": frozenset({"location"}),
        "owns": frozenset({"infrastructure"}),
        "targets": frozenset({"identity", "location", "vulnerability"}),
        "uses": frozenset({"attack-pattern", "infrastructure", "malware", "tool"}),
    },
    "tool": {
        "delivers": frozenset({"malware"}),
        "drops": frozenset({"malware"}),
        "has": frozenset({"vulnerability"}),
        "targets": frozenset({"identity", "infrastructure", "location", "vulnerability"}),
        "uses": frozenset({"infrastructure"}),
    },
}


# Pairs this project emits on purpose although the spec does not list them
# (ADR-0061).  Kept apart from _SUGGESTED so that table stays a verbatim
# transcription: ``indicator --based-on--> <SCO>`` links an Indicator straight
# to the observable it was built from, instead of through an ObservedData whose
# first/last_observed times would be the build time, not an observation.  The
# default stix2validator run accepts it; only the strict best-practice check
# ({202}) reports it.
_PROJECT_EXTENSIONS: dict[str, dict[str, frozenset[str]]] = {
    "indicator": {"based-on": frozenset({"*SCO*"})},
}


def rel_is_allowed(src_type: str, verb: str, tgt_type: str) -> bool:
    """`rel_is_suggested`, plus the project's documented extensions (ADR-0061).

    The STIX mapper uses this to decide whether to keep a verb or downgrade it
    to ``related-to``; `rel_is_suggested` stays the pure spec check.
    """
    if rel_is_suggested(src_type, verb, tgt_type):
        return True
    targets = _PROJECT_EXTENSIONS.get(src_type, {}).get((verb or "").lower())
    if targets is None:
        return False
    return tgt_type in targets or ("*SCO*" in targets and tgt_type in SCO_TYPES)


def rel_is_listed(src_type: str, verb: str, tgt_type: str) -> bool:
    """True when `verb` is named for this exact pair: by the spec's per-object
    relationship tables, or by a project extension (ADR-0061).

    Stricter than `rel_is_allowed` on purpose.  The §3.7 common relationships
    (``related-to``, ``duplicate-of``, ``derived-from``) are valid between any
    two objects, so they say nothing about the pair; an unknown or empty type
    is not given the benefit of the doubt.  Stage 4 keeps an observable as the
    direct endpoint opposite an SDO only for such a verb, and routes every other
    claim through the observable's Indicator (ADR-0062).
    """
    if not src_type or not verb or not tgt_type:
        return False
    verb = verb.lower()
    for table in (_SUGGESTED, _PROJECT_EXTENSIONS):
        targets = table.get(src_type, {}).get(verb)
        if targets and (tgt_type in targets or ("*SCO*" in targets and tgt_type in SCO_TYPES)):
            return True
    return False


def rel_is_suggested(src_type: str, verb: str, tgt_type: str) -> bool:
    """
    Return True if (src_type) --verb--> (tgt_type) is a *suggested* STIX 2.1
    relationship (i.e. would not raise a {202} best-practice warning).

    Returns True when any type is unknown/empty — we only downgrade verbs we can
    positively prove are non-suggested, never edges we simply can't classify.
    """
    if not src_type or not verb or not tgt_type:
        return True
    verb = verb.lower()

    # §3.7 common relationships
    if verb in _UNIVERSAL_ANY:
        return True
    if verb in _UNIVERSAL_SAME_TYPE:
        return src_type == tgt_type

    targets = _SUGGESTED.get(src_type, {}).get(verb)
    if targets is None:
        return False
    if tgt_type in targets:
        return True
    if "*SCO*" in targets and tgt_type in SCO_TYPES:
        return True
    return False
