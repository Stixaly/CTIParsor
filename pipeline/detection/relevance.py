"""Rank detection rules by what a report actually contains (ADR-0014).

Coverage (ADR-0008) answers "does a rule exist for this technique?".  This
module answers a different question — *which rules should an analyst read
first?* — and answers it from the report's technical content: hashes, domains,
IPs, binaries, paths, registry keys, tool names, CVEs, plus the platform the
intrusion actually happened on.  The ATT&CK tag is kept as one term among
several, so behaviour-only reports still get proposals; it just no longer
*selects* on its own.

Deterministic and offline: no model, no network, no randomness — the same store
and the same accepted entities always produce the same ranking (ADR-0008's
constraint on the detection artifact).
"""
from __future__ import annotations

import math
import sqlite3
from collections.abc import Iterable
from dataclasses import dataclass, field

from pipeline.detection.observables import Observable, observables_from_entities, report_platform
from pipeline.detection.store import (
    atom_document_frequency,
    atom_hits,
    atom_index_built,
    canonical_rule_count,
    rule_details,
    techniques_for_rules,
)

# ── Tunables — every weight in the ranking lives here ────────────────────────

#: Which rule atom classes a report observable class may legitimately match.
#: An IP can show up in a rule's command line; a registry key only ever matches
#: a registry field.
MATCHABLE: dict[str, frozenset[str]] = {
    "hash":     frozenset({"hash"}),
    "ip":       frozenset({"ip", "url", "cmdline"}),
    "domain":   frozenset({"domain", "url", "cmdline"}),
    "url":      frozenset({"url", "cmdline"}),
    "file":     frozenset({"file", "image", "cmdline"}),
    "image":    frozenset({"image", "file", "cmdline"}),
    "registry": frozenset({"registry"}),
    "user":     frozenset({"user"}),
    "port":     frozenset({"port"}),
    "name":     frozenset({"image", "file", "service", "cmdline"}),
}

#: How much a match of this observable class is worth before IDF. A hash match
#: is near-proof; a port match is near-noise.
CLASS_WEIGHT: dict[str, float] = {
    "hash": 1.00, "url": 0.90, "domain": 0.85, "ip": 0.80,
    "registry": 0.75, "image": 0.70, "cve": 0.80, "file": 0.60,
    "name": 0.50, "user": 0.40, "port": 0.25,
}

#: A substring hit ("meshagent" inside "meshagent64.exe") is real but weaker
#: than an exact value match.
PARTIAL_FACTOR = 0.55

#: Technique contribution — deliberately below the weight of a single strong
#: observable match, since it is what over-selected before.
#:
#: This is the *ceiling*, not the value (ADR-0018): the term is scaled by the
#: technique's IDF and by how many techniques the rule carries. As a flat constant
#: it gave ~1,400 rules per report an identical score, so past the handful of
#: evidence-backed hits the list was ordered alphabetically.
TECH_EXACT = 0.30
TECH_PARENT = 0.18

#: Parent-technique matches keep their ADR-0014 discount as a *ratio* now that the
#: term is weighted: TECH_PARENT / TECH_EXACT.
TECH_PARENT_RATIO = TECH_PARENT / TECH_EXACT

#: Floor under the technique IDF. Unlike an atom match — where a hit on `cmd.exe`
#: genuinely carries no information — a technique tag match always means the rule
#: addresses something the report describes, so IDF should modulate it, never
#: annihilate it. Without the floor the term collapses to exactly 0 whenever a
#: technique is carried by every canonical rule, which is unreachable on a real
#: store (the commonest, T1059 at 358 of 6,349 rules, scores 0.33) but routine on
#: a small or freshly-seeded one, where it would flatten the ranking to zero.
TECH_IDF_FLOOR = 0.15

#: A rule tagged with many techniques is diffuse; one tagged with a single
#: technique is *about* that technique. Damping is 1/sqrt(n): gentle enough that a
#: 2-technique rule keeps 71% of its weight, firm enough to separate an 8-technique
#: rule (35%). Measured: IDF alone still left a 200-rule tie, IDF x breadth 107.
def technique_breadth(n_techniques: int) -> float:
    """Damp a rule's technique term by how many techniques it carries."""
    return 1.0 / math.sqrt(max(1, n_techniques))

#: A rule written for another OS than the report is demoted, never dropped: a
#: mixed intrusion can legitimately involve both.
PLATFORM_MISMATCH_FACTOR = 0.40

#: Shortest string that may be substring-matched. Rule atoms include bare
#: extension fragments (".exe", ".dll", "http"); below this length containment
#: is meaningless — every Windows binary "matches" ".exe".
MIN_PARTIAL_LEN = 8

#: A substring match must also cover a real share of the longer string. Without
#: it, "meshagent64-v2.exe" would match a rule looking for any ".exe" download.
MIN_PARTIAL_RATIO = 0.5

#: Only the strongest few matches feed the score. Noisy-OR saturates at 1.0
#: given enough mediocre evidence, which would let a report with many weak
#: observables push unrelated rules to a perfect score.
MAX_SCORING_MATCHES = 4

#: A tool/malware name matching more than this share of the candidate rules is
#: not discriminative ("python", "powershell") — dropped from title matching.
NAME_TITLE_MAX_SHARE = 0.20


@dataclass(frozen=True, slots=True)
class Match:
    """One piece of evidence for why a rule was proposed."""

    obs_class: str      # report side ("domain")
    atom_class: str     # rule side ("cmdline"), or "title" for a text match
    value: str          # the normalized value that matched
    display: str        # the report's original spelling, for the UI
    exact: bool         # False = substring match
    weight: float       # contribution to the score


@dataclass(slots=True)
class Proposal:
    """A ranked rule proposal with its evidence."""

    rule_id: str
    corpus: str
    title: str
    severity: str
    license: str
    source_ref: str
    platform: str
    score: float
    tier: str                                     # direct | behavioural | weak
    techniques: list[str] = field(default_factory=list)   # report techniques covered
    matches: list[Match] = field(default_factory=list)
    format: str = "sigma"                         # source rule language — Sigma / Suricata / YARA

    def as_dict(self) -> dict:
        return {
            "id": self.rule_id, "corpus": self.corpus, "title": self.title,
            "severity": self.severity, "license": self.license,
            "source_ref": self.source_ref, "platform": self.platform,
            "format": self.format,
            "score": round(self.score, 4), "tier": self.tier,
            "techniques": self.techniques,
            "matches": [
                {"obs_class": m.obs_class, "field": m.atom_class, "value": m.value,
                 "display": m.display, "exact": m.exact, "weight": round(m.weight, 4)}
                for m in self.matches
            ],
        }


# ── Scoring primitives ───────────────────────────────────────────────────────

def idf(df: int, total: int) -> float:
    """Inverse document frequency of an atom value, normalized to 0..1.

    This is what separates a meaningful match from a meaningless one without a
    hand-written stoplist: `cmd.exe` appears in thousands of rules and scores
    ~0, a campaign-specific binary appears in none and scores ~1.
    """
    if total <= 1:
        return 1.0
    return max(0.0, min(1.0, math.log(total / (1 + max(0, df))) / math.log(total)))


def combine(weights: Iterable[float]) -> float:
    """Noisy-OR of independent match weights — saturating, never above 1.

    Additive scoring would let ten weak matches outrank one hash match; this
    keeps a single strong piece of evidence decisive while still rewarding
    corroboration.
    """
    product = 1.0
    for w in weights:
        product *= (1.0 - max(0.0, min(1.0, w)))
    return 1.0 - product


def platform_factor(rule_platform: str, report_plat: str) -> float:
    """1.0 when the rule's OS is compatible with the report's, else a demotion."""
    if not rule_platform or report_plat in ("", "multi"):
        return 1.0
    return 1.0 if rule_platform == report_plat else PLATFORM_MISMATCH_FACTOR


def tier_of(has_evidence: bool, has_technique: bool, compatible: bool) -> str:
    """direct = matched report content; behavioural = technique only; weak = off-platform."""
    if has_evidence:
        return "direct"
    if has_technique and compatible:
        return "behavioural"
    return "weak"


def _parent(technique_id: str) -> str | None:
    """"T1059.001" → "T1059"; a parent technique has no parent."""
    return technique_id.split(".", 1)[0] if "." in technique_id else None


# ── Matching ─────────────────────────────────────────────────────────────────

def _exact_matches(
    conn: sqlite3.Connection, observables: list[Observable]
) -> dict[str, list[tuple[Observable, str, str]]]:
    """Rules holding a report observable verbatim.

    Returns rule_id → [(observable, atom_class, matched atom value)].
    """
    by_value: dict[str, list[Observable]] = {}
    for obs in observables:
        if obs.obs_class in MATCHABLE:
            by_value.setdefault(obs.value, []).append(obs)
    if not by_value:
        return {}

    hits: dict[str, list[tuple[Observable, str, str]]] = {}
    for rule_id, atom_class, value in atom_hits(conn, by_value):
        for obs in by_value.get(value, ()):
            if atom_class in MATCHABLE[obs.obs_class]:
                hits.setdefault(rule_id, []).append((obs, atom_class, value))
    return hits


def _substring_ok(needle: str, hay: str) -> bool:
    """Is a containment between two atom values meaningful, in either direction?

    Rule atoms include bare fragments (".exe", "http", "/opera.exe"), so plain
    containment links a campaign binary to any rule that downloads *some* .exe.
    Requiring both a real length and a real share of the longer string keeps the
    legitimate case ("meshagent" inside "meshagent64.exe") and drops the rest.
    """
    if needle == hay:
        return False
    short, long = (needle, hay) if len(needle) <= len(hay) else (hay, needle)
    if len(short) < MIN_PARTIAL_LEN or short not in long:
        return False
    return len(short) / len(long) >= MIN_PARTIAL_RATIO


def _partial_matches(
    conn: sqlite3.Connection,
    observables: list[Observable],
    candidates: set[str],
) -> dict[str, list[tuple[Observable, str, str]]]:
    """Substring hits, restricted to rules already in the candidate set.

    Scoped on purpose: a report's tool name ("meshagent") legitimately matches a
    rule's binary ("meshagent64.exe"), but running containment over the whole
    242k-row atom index on every request would cost seconds. Rules reachable
    *only* by substring are therefore not surfaced — exact matching already
    reaches untagged rules, which is the recall gap that mattered.
    """
    needles = [
        o for o in observables
        if o.obs_class in MATCHABLE and len(o.value) >= MIN_PARTIAL_LEN
    ]
    if not needles or not candidates:
        return {}

    ids = sorted(candidates)
    hits: dict[str, list[tuple[Observable, str, str]]] = {}
    for i in range(0, len(ids), 400):
        batch = ids[i:i + 400]
        placeholders = ",".join("?" * len(batch))
        for rule_id, atom_class, value in conn.execute(
            f"SELECT rule_id, atom_class, value FROM rule_atoms "
            f"WHERE rule_id IN ({placeholders})",
            batch,
        ).fetchall():
            for obs in needles:
                if atom_class in MATCHABLE[obs.obs_class] and _substring_ok(obs.value, value):
                    hits.setdefault(rule_id, []).append((obs, atom_class, value))
    return hits


def _text_matches(
    observables: list[Observable], details: dict[str, dict]
) -> dict[str, list[tuple[Observable, str, str]]]:
    """CVE ids and tool/malware names appearing in a rule's title or description.

    A rule *named* after the tool the report describes is a strong proposal even
    when no field value matches. Names hitting a large share of the candidates
    are dropped as non-discriminative — the same idea as IDF, computed against
    the candidate set because rule text is not in the atom index.
    """
    needles = [o for o in observables
               if o.obs_class == "cve" or (o.obs_class == "name" and len(o.value) >= 4)]
    if not needles or not details:
        return {}

    texts = {
        rid: f"{d.get('title') or ''} {d.get('description') or ''}".lower()
        for rid, d in details.items()
    }
    limit = max(1, int(len(texts) * NAME_TITLE_MAX_SHARE))

    hits: dict[str, list[tuple[Observable, str, str]]] = {}
    for obs in needles:
        matched = [rid for rid, text in texts.items() if obs.value in text]
        # A CVE id is specific by construction; only names need the guard.
        if obs.obs_class == "name" and len(matched) > limit:
            continue
        for rid in matched:
            hits.setdefault(rid, []).append((obs, "title", obs.value))
    return hits


# ── Entry point ──────────────────────────────────────────────────────────────

def rank_rules(
    conn: sqlite3.Connection,
    entity_rows: Iterable[dict],
    technique_ids: Iterable[str],
    *,
    limit: int = 200,
) -> dict:
    """Rank the store's rules against one report.

    Args:
        conn: open store connection.
        entity_rows: the report's entities (mappings with value + entity_type).
        technique_ids: the report's ATT&CK techniques.
        limit: how many proposals to return (the tail is counted, not returned).

    Returns a dict ready to serialize: the observable profile, the inferred
    platform, tier counts, and the ranked proposals with their evidence.
    """
    observables = observables_from_entities(entity_rows)
    plat = report_platform(observables)
    techniques = [t.upper() for t in technique_ids if t]

    # Rule technique tag → the report technique(s) it covers, with the ADR-0008
    # parent→sub roll-up (a rule on T1059 covers a report's T1059.004).
    covers: dict[str, set[str]] = {}
    is_parent_tag: dict[str, bool] = {}
    for t in techniques:
        covers.setdefault(t, set()).add(t)
        is_parent_tag[t] = False
        parent = _parent(t)
        if parent:
            covers.setdefault(parent, set()).add(t)
            is_parent_tag.setdefault(parent, True)

    tech_rules: dict[str, set[str]] = {}     # rule_id → report techniques covered
    tech_weight: dict[str, float] = {}       # rule_id → best technique weight
    if covers:
        from pipeline.detection.store import (
            canonical_rule_ids_for_techniques,
            technique_counts_for_rules,
            technique_document_frequency,
        )
        # IDF on the technique axis (ADR-0018), the same argument that makes atom
        # IDF work: "tagged T1059" is worth almost nothing when 358 rules carry
        # T1059, and a lot when the technique is carried by a handful.
        tech_df = technique_document_frequency(conn, covers.keys())
        tech_total = canonical_rule_count(conn) or 1
        weight_of_tag = {
            tag: TECH_EXACT
            * max(TECH_IDF_FLOOR, idf(tech_df.get(tag, 0), tech_total))
            * (TECH_PARENT_RATIO if is_parent_tag.get(tag) else 1.0)
            for tag in covers
        }

        for tag, rule_id in canonical_rule_ids_for_techniques(conn, covers):
            tag = tag.upper()
            tech_rules.setdefault(rule_id, set()).update(covers.get(tag, ()))
            w = weight_of_tag.get(tag, 0.0)
            if w > tech_weight.get(rule_id, 0.0):
                tech_weight[rule_id] = w

        # Breadth damping is per *rule*, so it applies once the best tag is known.
        breadth_of = technique_counts_for_rules(conn, tech_rules.keys())
        for rule_id, w in tech_weight.items():
            tech_weight[rule_id] = w * technique_breadth(breadth_of.get(rule_id, 1))

    exact = _exact_matches(conn, observables)
    candidates = set(tech_rules) | set(exact)

    details = rule_details(conn, candidates)
    partial = _partial_matches(conn, observables, candidates)
    textual = _text_matches(observables, details)

    # IDF is keyed on the *matched atom value*, not on the observable. For a
    # substring match the observable itself is in no rule (df 0 → idf 1.0), so
    # weighting it that way would give a ".exe" fragment hit a perfect score.
    matched_values = {
        value
        for source in (exact, partial)
        for rows in source.values()
        for _obs, _cls, value in rows
    }
    df = atom_document_frequency(conn, matched_values)

    total_rules = canonical_rule_count(conn) or 1
    # Only rules reached purely by an observable need their tags looked up —
    # technique-matched rules already know which report techniques they cover.
    rule_techs = techniques_for_rules(conn, candidates - set(tech_rules))

    proposals: list[Proposal] = []
    for rule_id in candidates:
        meta = details.get(rule_id)
        if meta is None:
            continue   # demoted by the dedup pass between the two queries

        # One entry per source *entity*: a single file path is emitted as `file`,
        # `image` and can also hit a `cmdline` atom, and must not be counted
        # three times. Keep its strongest match.
        best: dict[str, Match] = {}
        for source, is_exact in ((exact, True), (partial, False), (textual, True)):
            for obs, atom_class, value in source.get(rule_id, ()):
                base = CLASS_WEIGHT.get(obs.obs_class, 0.3)
                w = base * idf(df.get(value, 0), total_rules)
                if not is_exact:
                    w *= PARTIAL_FACTOR
                current = best.get(obs.display)
                if current is None or w > current.weight:
                    best[obs.display] = Match(obs.obs_class, atom_class, obs.value,
                                              obs.display, is_exact, w)

        matches = sorted(best.values(), key=lambda m: -m.weight)
        obs_component = combine(m.weight for m in matches[:MAX_SCORING_MATCHES])
        tech_component = tech_weight.get(rule_id, 0.0)
        factor = platform_factor(meta["platform"], plat)
        score = min(1.0, obs_component + tech_component) * factor

        proposals.append(Proposal(
            rule_id=rule_id,
            corpus=meta["corpus"],
            title=meta["title"],
            severity=meta["severity"] or "unknown",
            license=meta["license"] or "unknown",
            source_ref=meta["source_ref"] or "",
            platform=meta["platform"],
            format=meta.get("format") or "sigma",
            score=score,
            tier=tier_of(bool(matches), rule_id in tech_rules, factor == 1.0),
            techniques=sorted(tech_rules.get(rule_id, ())) or rule_techs.get(rule_id, []),
            matches=matches[:8],     # evidence is for reading, not exhaustiveness
        ))

    proposals.sort(key=lambda p: (-p.score, p.corpus, p.title))

    counts = {"direct": 0, "behavioural": 0, "weak": 0}
    for p in proposals:
        counts[p.tier] = counts.get(p.tier, 0) + 1

    return {
        "platform": plat,
        "atom_index_built": atom_index_built(conn),
        "observables": [
            {"class": o.obs_class, "value": o.value,
             "display": o.display, "entity_type": o.entity_type}
            for o in observables
        ],
        "observables_total": len(observables),
        "candidate_total": len(proposals),
        "counts": counts,
        "returned": min(limit, len(proposals)),
        "proposals": [p.as_dict() for p in proposals[:limit]],
    }


def job_observable_rows(conn: sqlite3.Connection, job_id: str) -> list[dict]:
    """A job's accepted (or still-pending) entities, as plain mappings.

    Mirrors `coverage.job_technique_ids`' accept filter so the proposal list and
    the coverage matrix always describe the same report.
    """
    rows = conn.execute(
        "SELECT value, entity_type FROM entities "
        "WHERE job_id=? AND (accepted IS NULL OR accepted=1)",
        (job_id,),
    ).fetchall()
    return [{"value": r[0], "entity_type": r[1]} for r in rows]


def propose_for_job(conn: sqlite3.Connection, job_id: str, *, limit: int = 200) -> dict:
    """Ranked, evidence-backed rule proposals for one report (ADR-0014)."""
    from pipeline.detection.coverage import job_technique_ids

    result = rank_rules(
        conn,
        job_observable_rows(conn, job_id),
        job_technique_ids(conn, job_id),
        limit=limit,
    )
    return {"job_id": job_id, **result}
