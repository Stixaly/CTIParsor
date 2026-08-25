"""
Detection coverage keyed on report artifacts, not ATT&CK techniques.

ADR-0025: The unit of coverage is the technical artifact (IoC, malware, tool)
present in the report, scored on the real evidence that a rule fires on it.

Measured on the live store (75,127 canonical rules): the technique-keyed path
selects 25,493 rules of which only 4 are backed by a technical element of the
report, and 58 of the 64 cells scored >= 2 have NO rule matching anything in
the report. This module replaces that score.

Deterministic and offline: no models, no network, no randomness.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Iterable
from dataclasses import dataclass

from pipeline.detection.coverage import job_technique_ids
from pipeline.detection.observables import Observable, observables_from_entities
from pipeline.detection.phases import phase_band
from pipeline.detection.relevance import MATCHABLE, job_observable_rows
from pipeline.detection.store import (
    atom_document_frequency,
    atom_hits,
    canonical_rule_count,
    rule_details,
)

#: Pyramid of Pain tier per artifact class. A hash match and a tool-name match
#: are not the same detection claim, and one averaged number hides the
#: difference: a hash is trivial for an adversary to change, a tool identity is
#: not. Coverage is therefore always reported per tier.
PYRAMID_TIER: dict[str, int] = {
    "hash": 1,
    "ip": 2, "domain": 2, "url": 2, "cve": 2,
    "file": 3, "image": 3, "registry": 3, "user": 3, "port": 3,
    "name": 4,
}

TIER_LABEL: dict[int, str] = {
    1: "trivial", 2: "easy", 3: "annoying", 4: "challenging",
}

#: Document frequency at or above which a value is corpus vocabulary rather than
#: an indicator, and leaves the coverage denominator.
#:
#: Measured on the live store (75 127 canonical rules), which is what sets the
#: boundary: powershell.exe 241, cmd.exe 190, rundll32.exe 143, wscript.exe 101,
#: svchost.exe 91, regsvr32.exe 91, mshta.exe 87, explorer.exe 72, curl 43,
#: net.exe 43 -- all vocabulary. Against: wget 27, python 17, mimikatz 7,
#: psexec 5, cobaltstrike 5, anydesk 4, /etc/hosts 3 -- all real identities that
#: must keep scoring. The threshold sits in the gap.
#:
#: Expressed as a share so it tracks corpus size, with an absolute floor so a
#: small or freshly seeded store does not exclude everything.
VOCABULARY_DF_MIN = 20
VOCABULARY_DF_SHARE = 0.0005

#: A tool or malware name appearing in more than this many rule titles is a
#: category label, not an identity. Measured against the live store: cobaltstrike
#: 202, trickbot 72, xmrig 31, meshagent 6 -- all real identities that must keep
#: their evidence. CVE ids are exempt: an id is specific by construction.
NAME_TITLE_MAX_RULES = 500

#: Evidence is for reading, not exhaustiveness -- the count is kept in full.
MAX_EVIDENCE_PER_ARTIFACT = 20

#: Artifact classes that can be matched against a rule's title and description.
#: `cve` has no atom class at all and is reachable ONLY this way, so this set is
#: what keeps a CVE inside the coverage denominator instead of being written off
#: as unmatchable.
TITLE_ELIGIBLE: frozenset[str] = frozenset({"cve", "name"})

#: Shortest name worth searching a title for. Below this, containment is noise.
MIN_TITLE_NEEDLE_LEN = 4


@dataclass(frozen=True, slots=True)
class ArtifactEvidence:
    """One rule that fires on this artifact, and how it matched."""
    rule_id: str
    corpus: str
    atom_class: str     # rule-side field that matched, or "title"
    exact: bool         # False = matched the rule title/description, not a field
    # The rule's persisted `native_key`, used to fold a rule forked across
    # corpora onto one owner. Carried by `title` evidence too, not only by exact
    # matches: a malware family corroborates on titles, and without the key every
    # such piece of evidence shared an empty one and collapsed to a single corpus.
    native_key: str = ""


@dataclass(slots=True)
class Artifact:
    """One technical element of a report, scored on the evidence that a rule
    would fire on it."""
    artifact_class: str
    classes: list[str]
    value: str
    display: str
    entity_type: str
    entity_types: list[str]
    tier: int
    tier_label: str
    score: int                  # 0-3
    corpora: list[str]          # distinct OWNING corpora with EXACT evidence -- drives the score
    # EVERY matching rule, never truncated. `as_dict` caps what it serializes,
    # but the object keeps the full list: the score, the corroborating corpora
    # and the phase band all read from it, and truncating here would quietly
    # shrink the set of rules the band believes matched.
    evidence: list[ArtifactEvidence]
    df: int                     # atom document frequency of `value`
    excluded: str | None        # None | "vocabulary" | "not_matchable"

    def as_dict(self) -> dict:
        """Serialize to a dict with the exact keys required by the API."""
        return {
            "class": self.artifact_class,
            "classes": self.classes,
            "value": self.value,
            "display": self.display,
            "entity_type": self.entity_type,
            "entity_types": self.entity_types,
            "tier": self.tier,
            "tier_label": self.tier_label,
            "score": self.score,
            "corpora": self.corpora,
            # Corpora across ALL evidence, weak included. Reported separately
            # because it must NOT feed the score: a rule merely named after a
            # malware family is not a rule holding this value in a detection
            # field. But leaving it out understated the dominant case on an
            # IoC-poor report -- `Elise` scores 1 with `corpora: []` while four
            # corpora carry twelve rules named after it, which reads as no
            # coverage at all.
            "evidence_corpora": sorted({ev.corpus for ev in self.evidence if ev.corpus}),
            "df": self.df,
            "excluded": self.excluded,
            "evidence_total": len(self.evidence),
            "evidence": [
                {
                    "rule_id": ev.rule_id,
                    "corpus": ev.corpus,
                    "field": ev.atom_class,
                    "exact": ev.exact,
                }
                for ev in self.evidence[:MAX_EVIDENCE_PER_ARTIFACT]
            ],
        }


def pyramid_tier(artifact_class: str) -> int:
    """Pyramid of Pain tier of an artifact class; 3 for anything unlisted."""
    return PYRAMID_TIER.get(artifact_class, 3)


def vocabulary_threshold(total_rules: int) -> int:
    """Document frequency at which a value stops being an indicator."""
    return max(VOCABULARY_DF_MIN, int(VOCABULARY_DF_SHARE * total_rules))


def _exact_evidence(
    conn: sqlite3.Connection,
    observables: Iterable[Observable],
) -> dict[tuple[str, str], list[tuple[str, str]]]:
    """
    Find exact evidence: rule atoms that match observable values.
    Returns dict keyed by (obs_class, value) -> list of (rule_id, atom_class).
    """
    # Collect all matchable values
    matchable_values: set[str] = set()
    obs_by_class_value: dict[tuple[str, str], Observable] = {}

    for obs in observables:
        if obs.obs_class in MATCHABLE:
            matchable_values.add(obs.value)
            key = (obs.obs_class, obs.value)
            if key not in obs_by_class_value:
                obs_by_class_value[key] = obs

    if not matchable_values:
        return {}

    # Single call to atom_hits
    hits = atom_hits(conn, matchable_values)

    # Build index for O(1) lookup: value -> list of obs_classes
    value_to_obs_classes: dict[str, list[str]] = {}
    for (obs_class, obs_value) in obs_by_class_value.keys():
        if obs_value not in value_to_obs_classes:
            value_to_obs_classes[obs_value] = []
        value_to_obs_classes[obs_value].append(obs_class)

    # Group hits by (obs_class, value)
    result: dict[tuple[str, str], list[tuple[str, str]]] = {}

    for rule_id, atom_class, value in hits:
        # Find which observable(s) this value belongs to
        if value in value_to_obs_classes:
            for obs_class in value_to_obs_classes[value]:
                # Check if atom_class is matchable for this obs_class
                if atom_class in MATCHABLE.get(obs_class, frozenset()):
                    key = (obs_class, value)
                    if key not in result:
                        result[key] = []
                    result[key].append((rule_id, atom_class))

    return result


def _title_evidence(
    conn: sqlite3.Connection,
    observables: Iterable[Observable],
) -> dict[tuple[str, str], list[ArtifactEvidence]]:
    """
    Find weak evidence: observable value appears in rule title/description.
    Only for 'cve' class and 'name' class with len(value) >= 4.
    Returns dict keyed by (obs_class, value) -> list of ArtifactEvidence.
    """
    # Collect eligible needles. A CVE id is specific whatever its length; a name
    # must clear MIN_TITLE_NEEDLE_LEN or containment matches everything.
    needles: list[tuple[str, str]] = []  # (obs_class, value)
    for obs in observables:
        if obs.obs_class not in TITLE_ELIGIBLE:
            continue
        if obs.obs_class == "cve" or len(obs.value) >= MIN_TITLE_NEEDLE_LEN:
            needles.append((obs.obs_class, obs.value))

    if not needles:
        return {}

    # Prepare search terms
    search_terms: list[tuple[str, str, str]] = []  # (obs_class, value, value_lower)
    for obs_class, value in needles:
        search_terms.append((obs_class, value, value.lower()))

    # Single pass over all canonical rules
    result: dict[tuple[str, str], list[ArtifactEvidence]] = {}
    name_match_counts: dict[str, int] = {}  # value -> count of rules matched

    cursor = conn.execute(
        "SELECT id, corpus, native_key, title, description FROM detection_rules WHERE is_canonical=1"
    )

    for rule_id, corpus, native_key, title, description in cursor:
        title_lower = (title or "").lower()
        desc_lower = (description or "").lower()

        for obs_class, value, value_lower in search_terms:
            # Title match takes precedence over description
            if value_lower in title_lower:
                key = (obs_class, value)
                if key not in result:
                    result[key] = []

                result[key].append(ArtifactEvidence(
                    rule_id=rule_id,
                    corpus=corpus,
                    atom_class="title",
                    exact=False,
                    native_key=native_key or rule_id,
                ))

                # Track name matches for discrimination guard
                if obs_class == "name":
                    name_match_counts[value] = name_match_counts.get(value, 0) + 1
            elif value_lower in desc_lower:
                key = (obs_class, value)
                if key not in result:
                    result[key] = []

                result[key].append(ArtifactEvidence(
                    rule_id=rule_id,
                    corpus=corpus,
                    atom_class="description",
                    exact=False,
                    native_key=native_key or rule_id,
                ))

                # Track name matches for discrimination guard
                if obs_class == "name":
                    name_match_counts[value] = name_match_counts.get(value, 0) + 1

    # Apply discrimination guard for names
    for value, count in name_match_counts.items():
        if count > NAME_TITLE_MAX_RULES:
            # Remove all evidence for this name
            key = ("name", value)
            if key in result:
                del result[key]

    return result


def _owner_corpora(
    evidence: Iterable[ArtifactEvidence],
    *,
    include_titles: bool = False,
) -> list[str]:
    """Distinct corpora backing this artifact, one per logical rule.

    Two rules sharing a `native_key` are the SAME rule forked across
    repositories: they count for one corpus, so a fork can never corroborate
    itself into a score of 3. This is ADR-0008's corroboration rule, kept
    verbatim.

    The key is the persisted `native_key` carried on the evidence, never a
    re-derivation from the rule id. Those agree in the live store only because
    the column happens to be populated from the id, and a test with explicit
    native_keys caught the two diverging.

    `include_titles` admits `title` evidence alongside exact matches, and is set
    only for a MALWARE identity. For a family, a rule named after it *is* the
    detection artifact — YARA rules and ET signatures are named that way — so
    excluding titles inverted the ranking: measured on a real report, the LOLBin
    `Ping` scored 2 while `BlackEnergy` scored 1 on 28 rules across 3 corpora.

    It stays off for `tool`: a tool's binary name is already reachable as an
    atom, and admitting titles there would corroborate LOLBins on generic rule
    names. `description` evidence never corroborates for anything — "similar to
    BlackEnergy" is not coverage.
    """
    native_key_to_corpus: dict[str, str] = {}

    for ev in evidence:
        if not ev.exact:
            if not (include_titles and ev.atom_class == "title"):
                continue
        if ev.native_key not in native_key_to_corpus:
            native_key_to_corpus[ev.native_key] = ev.corpus

    return sorted(set(native_key_to_corpus.values()))


def _score_from(corpora: list[str], has_weak: bool) -> int:
    """
    Score based on number of distinct owning corpora and weak evidence.
    3 if len(corpora) >= 2
    2 if len(corpora) == 1
    1 if len(corpora) == 0 and has_weak
    0 otherwise
    """
    if len(corpora) >= 2:
        return 3
    if len(corpora) == 1:
        return 2
    if len(corpora) == 0 and has_weak:
        return 1
    return 0


def score_artifacts(
    conn: sqlite3.Connection, observables: Iterable[Observable]
) -> list[Artifact]:
    """Score every report observable on the evidence that a rule fires on it."""
    # 1. Deduplicate observables on (obs_class, value), keeping the FIRST seen
    seen: set[tuple[str, str]] = set()
    unique_observables: list[Observable] = []
    for obs in observables:
        key = (obs.obs_class, obs.value)
        if key not in seen:
            seen.add(key)
            unique_observables.append(obs)

    if not unique_observables:
        return []

    # 2. Total rules and vocabulary threshold
    total = canonical_rule_count(conn)
    threshold = vocabulary_threshold(total)

    # 3. Document frequency for matchable values only
    matchable_values: set[str] = set()
    for obs in unique_observables:
        if obs.obs_class in MATCHABLE:
            matchable_values.add(obs.value)

    df_map: dict[str, int] = {}
    if matchable_values:
        df_map = atom_document_frequency(conn, matchable_values)

    # 4. Exact evidence (raw hits)
    exact_raw = _exact_evidence(conn, unique_observables)

    # Resolve corpus for exact evidence using rule_details
    exact_rule_ids: set[str] = set()
    for ev_list in exact_raw.values():
        for rule_id, _ in ev_list:
            exact_rule_ids.add(rule_id)

    details: dict[str, dict] = {}
    if exact_rule_ids:
        details = rule_details(conn, exact_rule_ids)

    # Build final exact evidence with resolved corpus
    exact_ev: dict[tuple[str, str], list[ArtifactEvidence]] = {}
    for key, ev_list in exact_raw.items():
        ev_list_final: list[ArtifactEvidence] = []
        for rule_id, atom_class in ev_list:
            if rule_id in details:
                meta = details[rule_id]
                ev_list_final.append(ArtifactEvidence(
                    rule_id=rule_id,
                    corpus=meta.get("corpus", ""),
                    atom_class=atom_class,
                    exact=True,
                    native_key=meta.get("native_key") or rule_id,
                ))
        if ev_list_final:
            exact_ev[key] = ev_list_final

    # 5. Weak evidence (title/description match)
    weak_ev = _title_evidence(conn, unique_observables)

    # 6. Group observables by value to fold duplicates (ADR-0014 lesson applied to coverage)
    # Measured: 16 values counted twice, 13 of 28 covered lines were halves of duplicates.
    value_groups: dict[str, list[Observable]] = {}
    for obs in unique_observables:
        value_groups.setdefault(obs.value, []).append(obs)

    artifacts: list[Artifact] = []
    for value, obs_list in value_groups.items():
        # Determine representative class: lowest tier, then alphabetical
        rep_class = min(
            obs_list,
            key=lambda o: (pyramid_tier(o.obs_class), o.obs_class)
        ).obs_class

        # Collect all evidence for all classes of this value
        all_exact: list[ArtifactEvidence] = []
        all_weak: list[ArtifactEvidence] = []
        seen_exact_keys: set[tuple[str, str, bool]] = set()
        seen_weak_keys: set[tuple[str, str, bool]] = set()

        for obs in obs_list:
            key = (obs.obs_class, value)
            exact_list = exact_ev.get(key, [])
            weak_list = weak_ev.get(key, [])

            for ev in exact_list:
                dedup_key = (ev.rule_id, ev.atom_class, ev.exact)
                if dedup_key not in seen_exact_keys:
                    seen_exact_keys.add(dedup_key)
                    all_exact.append(ev)

            for ev in weak_list:
                dedup_key = (ev.rule_id, ev.atom_class, ev.exact)
                if dedup_key not in seen_weak_keys:
                    seen_weak_keys.add(dedup_key)
                    all_weak.append(ev)

        # Combine evidence (exact first, then weak)
        all_evidence = all_exact + all_weak

        # Determine if there's any weak evidence
        has_weak = len(all_weak) > 0

        # Collect entity types for all observables in this group
        entity_types = sorted(set(o.entity_type for o in obs_list))

        # Measured: Ping (tool) scores 2, BlackEnergy (malware) scores 1.
        # BlackEnergy has 28 rules across 3 corpora named after it.
        # Title evidence should corroborate for malware identities.
        include_titles = "malware" in entity_types

        # Determine corpora from exact evidence and optionally title evidence
        corpora = _owner_corpora(all_evidence, include_titles=include_titles)

        # Score
        score = _score_from(corpora, has_weak)

        # Determine exclusion
        # "not_matchable" only if NO class is matchable or title eligible
        # "vocabulary" if df >= threshold and at least one class is matchable
        excluded: str | None = None
        any_matchable = any(o.obs_class in MATCHABLE for o in obs_list)
        any_title_eligible = any(o.obs_class in TITLE_ELIGIBLE for o in obs_list)

        if not any_matchable and not any_title_eligible:
            excluded = "not_matchable"
        elif any_matchable:
            df = df_map.get(value, 0)
            if df >= threshold:
                excluded = "vocabulary"

        # Tier from representative class
        tier = pyramid_tier(rep_class)
        tier_label = TIER_LABEL.get(tier, "annoying")

        # DF for this artifact
        df = df_map.get(value, 0) if any_matchable else 0

        # Display and entity_type from first observable seen
        first_obs = obs_list[0]

        # Sorted list of all classes
        classes = sorted(set(o.obs_class for o in obs_list))

        artifact = Artifact(
            artifact_class=rep_class,
            classes=classes,
            value=value,
            display=first_obs.display,
            entity_type=first_obs.entity_type,
            entity_types=entity_types,
            tier=tier,
            tier_label=tier_label,
            score=score,
            corpora=corpora,
            evidence=all_evidence,
            df=df,
            excluded=excluded,
        )
        artifacts.append(artifact)

    # 7. Sort: score descending, tier ascending, value ascending
    artifacts.sort(key=lambda a: (-a.score, a.tier, a.value))

    return artifacts


def _summarize(
    artifacts: list[Artifact],
    threshold: int,
    total_rules: int,
    job_id: str,
) -> dict:
    """Build the coverage summary dict from pre-scored artifacts.

    Extracted so that `coverage_with_phases` can reuse the same totals and
    tier breakdown without re-scoring the evidence graph.
    """
    non_excluded = [a for a in artifacts if a.excluded is None]
    excluded_count = len(artifacts) - len(non_excluded)

    covered = sum(1 for a in non_excluded if a.score >= 2)
    weak = sum(1 for a in non_excluded if a.score == 1)
    uncovered = sum(1 for a in non_excluded if a.score == 0)

    by_tier = []
    for tier in [1, 2, 3, 4]:
        tier_artifacts = [a for a in non_excluded if a.tier == tier]
        tier_covered = sum(1 for a in tier_artifacts if a.score >= 2)
        tier_weak = sum(1 for a in tier_artifacts if a.score == 1)
        tier_uncovered = sum(1 for a in tier_artifacts if a.score == 0)
        by_tier.append({
            "tier": tier,
            "label": TIER_LABEL.get(tier, "annoying"),
            "artifacts": len(tier_artifacts),
            "covered": tier_covered,
            "weak": tier_weak,
            "uncovered": tier_uncovered,
        })

    return {
        "job_id": job_id,
        "artifacts": [a.as_dict() for a in artifacts],
        "totals": {
            "artifacts": len(non_excluded),
            "covered": covered,
            "weak": weak,
            "uncovered": uncovered,
            "excluded": excluded_count,
        },
        "by_tier": by_tier,
        "vocabulary_threshold": threshold,
        "canonical_rules": total_rules,
    }


def coverage_for_job(conn: sqlite3.Connection, job_id: str) -> dict:
    """Evidence-keyed detection coverage for one report (ADR-0025)."""
    rows = job_observable_rows(conn, job_id)
    observables = observables_from_entities(rows)
    artifacts = score_artifacts(conn, observables)

    total_rules = canonical_rule_count(conn)
    vocab_threshold = vocabulary_threshold(total_rules)

    return _summarize(artifacts, vocab_threshold, total_rules, job_id)


def coverage_with_phases(conn: sqlite3.Connection, job_id: str) -> dict:
    """Evidence-keyed coverage plus the ATT&CK phase band (ADR-0025)."""
    rows = job_observable_rows(conn, job_id)
    observables = observables_from_entities(rows)
    artifacts = score_artifacts(conn, observables)

    total_rules = canonical_rule_count(conn)
    vocab_threshold = vocabulary_threshold(total_rules)

    base = _summarize(artifacts, vocab_threshold, total_rules, job_id)

    matched = set()
    for a in artifacts:
        if a.excluded is not None:
            continue
        if a.score >= 1:
            for ev in a.evidence:
                matched.add(ev.rule_id)

    techniques = job_technique_ids(conn, job_id)
    band = phase_band(conn, techniques, matched)

    base["phases"] = band
    base["matched_rules"] = len(matched)

    return base
