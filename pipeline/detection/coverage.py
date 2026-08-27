"""Coverage scoring (ADR-0006).

Maps a report's extracted ATT&CK techniques to a 0–3 coverage score against the
detection-rule store. Explicitly NOT lab validation — it reports detection
*readiness*: whether rules (and from how many independent corpora) exist.

Corroboration policy (handles both independent and forked corpuses):
each logical rule is identified by its corpus-independent `native_key` and
attributed to the first corpus it's seen in. A rule forked across repos shares a
native_key, so it collapses to one corpus and never inflates the score.
"""
from __future__ import annotations

import sqlite3
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field

#: The detection formats the store can hold. A closed set of three, kept in step
#: with `_EXPORT_EXTENSIONS` in api/routes/coverage.py — a format missing from
#: this tuple would silently vanish from every per-format breakdown. Verified
#: against the live store: exactly these three values occur, and a `native_key`
#: never spans two of them, so per-format attribution partitions cleanly.
DETECTION_FORMATS: tuple[str, ...] = ("sigma", "suricata", "yara")

#: Rule-side atom classes each report class additionally reaches under ADR-0030.
#: `strlit` holds every YARA string and every Suricata `content:` — 53,517 atoms
#: that no MATCHABLE value set referenced, which is why all 16,314 canonical YARA
#: rules were unreachable except by an exact hash. `pipe` holds Sigma named pipes.
WIDENED_EXTRA: dict[str, frozenset[str]] = {
    "hash":     frozenset({"strlit"}),
    "ip":       frozenset({"strlit"}),
    "domain":   frozenset({"strlit"}),
    "url":      frozenset({"strlit"}),
    "file":     frozenset({"strlit"}),
    "image":    frozenset({"strlit"}),
    "registry": frozenset({"strlit"}),
    "name":     frozenset({"strlit", "pipe"}),
}


@dataclass
class CoverageCell:
    technique_id: str
    score: int                              # 0–3
    corpora: list[str] = field(default_factory=list)   # distinct corpora contributing
    rule_count: int = 0                     # distinct logical rules
    # Populated only when `score_techniques` is given a `formats` map; one entry
    # per DETECTION_FORMATS name, zeroes included (ADR-0022).
    by_format: dict[str, dict] = field(default_factory=dict)


def score_techniques(
    technique_ids: Iterable[str],
    rule_refs: Iterable[tuple[str, str, str]],
    telemetry_techniques: set[str] | None = None,
    formats: Mapping[str, str] | None = None,
) -> list[CoverageCell]:
    """Score each technique.

    Args:
        technique_ids: techniques extracted from the report.
        rule_refs:     (technique_id, corpus, native_key) for matching rules.
        telemetry_techniques: techniques with ATT&CK data-source mapping but no
            rule (score 1 fallback — lights up once the ADR-0005 index enrichment
            lands; pass None to disable).
        formats: native_key → format name; None disables the per-format breakdown
            and leaves every cell's `by_format` empty. The score itself is always
            computed across all formats combined, because corroboration is a
            property of the technique, not of one tool's rule language (ADR-0022).
    """
    telemetry = {t.upper() for t in (telemetry_techniques or set())}

    # Attribute each logical rule (native_key) to its first-seen corpus.
    rule_refs_list = list(rule_refs)
    owner: dict[str, str] = {}
    for _tech, corpus, key in rule_refs_list:
        owner.setdefault(key, corpus)

    tech_corpora: dict[str, set[str]] = {}
    tech_keys: dict[str, set[str]] = {}
    for tech, _corpus, key in rule_refs_list:
        t = tech.upper()
        tech_corpora.setdefault(t, set()).add(owner[key])
        tech_keys.setdefault(t, set()).add(key)

    cells: list[CoverageCell] = []
    for t in dict.fromkeys(x.upper() for x in technique_ids):
        corpora = sorted(tech_corpora.get(t, set()))
        n = len(corpora)
        if n >= 2:
            s = 3
        elif n == 1:
            s = 2
        elif t in telemetry:
            s = 1
        else:
            s = 0

        by_format: dict[str, dict] = {}
        if formats is not None:
            keys = tech_keys.get(t, set())
            for fmt in DETECTION_FORMATS:
                fmt_keys = {k for k in keys if formats.get(k, "sigma") == fmt}
                by_format[fmt] = {
                    "rule_count": len(fmt_keys),
                    # The OWNING corpus via `owner`, never the corpus of each ref:
                    # a rule forked across two corpora must contribute its single
                    # owner here exactly as it does to the score, or the panel
                    # would claim more corroboration than the score does.
                    "corpora": sorted({owner[k] for k in fmt_keys if k in owner}),
                }

        cells.append(CoverageCell(t, s, corpora, len(tech_keys.get(t, set())), by_format))
    return cells


def _parent_technique(technique_id: str) -> str | None:
    """Return the parent technique of a sub-technique, or None.

    "T1059.001" → "T1059";  "T1059" → None.
    """
    return technique_id.split(".", 1)[0] if "." in technique_id else None


def job_technique_ids(conn: sqlite3.Connection, job_id: str) -> list[str]:
    """Distinct ATT&CK technique ids from a job's accepted (or pending) entities —
    the report's technique set, shared by coverage scoring and the rules listing."""
    rows = conn.execute(
        "SELECT DISTINCT mitre_id FROM entities "
        "WHERE job_id=? AND mitre_id IS NOT NULL AND mitre_id != '' "
        "AND entity_type IN ('technique','ttp','tactic','procedure') "
        "AND (accepted IS NULL OR accepted=1)",
        (job_id,),
    ).fetchall()
    return [r[0].upper() for r in rows if r[0]]


def compute_for_job(conn: sqlite3.Connection, job_id: str) -> dict:
    """Compute coverage for a job from its accepted technique entities."""
    from pipeline.detection.store import rule_refs_for_techniques

    technique_ids = job_technique_ids(conn, job_id)

    # Sub-technique → parent roll-up.  A detection rule tagged with the parent
    # technique (e.g. T1059) also provides coverage for its sub-techniques
    # (T1059.001) — detecting the generic behaviour catches the specific case.
    # We therefore (1) query rules for parents too, and (2) re-key each matching
    # rule to the report technique(s) it covers before scoring.  The reverse
    # (a sub-technique rule crediting the parent) is intentionally NOT done — a
    # rule for one sub-technique doesn't cover all siblings of the parent.
    query_ids = set(technique_ids)
    covers: dict[str, set[str]] = {}   # rule technique tag → report techniques covered
    for t in technique_ids:
        covers.setdefault(t, set()).add(t)            # exact match
        parent = _parent_technique(t)
        if parent:
            query_ids.add(parent)
            covers.setdefault(parent, set()).add(t)   # parent rule covers this sub-technique

    raw_refs = rule_refs_for_techniques(conn, query_ids)
    refs: list[tuple[str, str, str]] = []
    key_format: dict[str, str] = {}
    for tag, corpus, key, fmt in raw_refs:
        # First occurrence wins, mirroring how `owner` attributes a native_key.
        # A native_key never spans two formats in the live store, so first- and
        # last-wins agree there; first-wins is chosen so the two maps cannot
        # disagree if that ever stops holding.
        key_format.setdefault(key, fmt)
        for report_t in covers.get(tag.upper(), ()):
            refs.append((report_t, corpus, key))
    cells = score_techniques(technique_ids, refs, formats=key_format)

    by_score: dict[int, int] = {0: 0, 1: 0, 2: 0, 3: 0}
    for c in cells:
        by_score[c.score] = by_score.get(c.score, 0) + 1

    return {
        "job_id": job_id,
        "techniques_total": len(cells),
        "by_score": by_score,
        "validated": False,   # readiness, not lab validation (ADR-0005/0006)
        "cells": [
            {"technique_id": c.technique_id, "score": c.score,
             "corpora": c.corpora, "rule_count": c.rule_count,
             "by_format": c.by_format}
            for c in sorted(cells, key=lambda c: (-c.score, c.technique_id))
        ],
    }


def _widened_matchable() -> dict[str, frozenset[str]]:
    """MATCHABLE unioned with WIDENED_EXTRA, class by class (ADR-0030).

    Rebuilt per call rather than cached at module level: a mutable module-level
    dict would be shared between tests that tune the tables.
    """
    from pipeline.detection.relevance import MATCHABLE

    return {
        cls: atoms | WIDENED_EXTRA.get(cls, frozenset())
        for cls, atoms in MATCHABLE.items()
    }


def _admits(evidence: list[dict]) -> bool:
    """Does this evidence justify putting the rule in front of an analyst?

    A UBIQUITOUS value must not admit a rule. ADR-0030 ruled it contributes zero
    to corroboration, but leaving it able to admit was worse than letting it
    score: it put the rule in the export. Measured on the Cisco SD-WAN report —
    60 rules served, of which **50 matched nothing but `/bin/bash` (39),
    `/etc/passwd` (10) and `/etc/shadow` (3)**, while the proposals panel next to
    it reported 14 direct hits. A ubiquitous match is still carried in `matches`
    and displayed, but only as support on a rule that earned its place.

    Brand/title evidence (`kind == "title"`) admits by design: it is
    non-discriminating by construction and is ADR-0031's whole point.
    """
    return any(
        e.get("kind") == "title" or (e["discriminating"] and e.get("kind") == "atom")
        for e in evidence
    )


def _evidence_for_job(conn: sqlite3.Connection, job_id: str) -> dict[str, list[dict]]:
    """rule_id → one entry per DISTINCT report observable the rule holds verbatim.

    A rule appears here only if at least one hit survives the matchable filter —
    never merely because `atom_hits` touched it. That distinction is the gate: an
    empty-list entry would let a rule through `rid in evidence` with no evidence
    at all.
    """
    from pipeline.detection.brands import brand_evidence, brand_tokens, cve_evidence
    from pipeline.detection.control import is_ubiquitous
    from pipeline.detection.observables import observables_from_entities
    from pipeline.detection.relevance import job_observable_rows
    from pipeline.detection.store import atom_hits

    observables = observables_from_entities(job_observable_rows(conn, job_id))
    if not observables:
        return {}

    by_value: dict[str, list] = {}
    for obs in observables:
        by_value.setdefault(obs.value, []).append(obs)

    hits = atom_hits(conn, by_value.keys())

    widened = _widened_matchable()
    evidence: dict[str, list[dict]] = {}
    seen: dict[str, set[str]] = {}

    for rule_id, atom_class, value in hits:
        for obs in by_value.get(value, ()):
            if atom_class not in widened.get(obs.obs_class, frozenset()):
                continue
            # One entry per source ENTITY: a file path is emitted as both `file`
            # and `image` and must not corroborate twice.
            marks = seen.setdefault(rule_id, set())
            if obs.display in marks:
                continue
            marks.add(obs.display)
            evidence.setdefault(rule_id, []).append({
                "obs_class": obs.obs_class,
                "display": obs.display,
                "value": obs.value,
                "field": atom_class,
                "discriminating": not is_ubiquitous(obs.obs_class, obs.value),
                "kind": "atom",
            })

    # ADR-0031 — brand evidence. A rule whose TITLE names what the report is
    # about is admitted too, in its own weaker tier: on UNC6671 every one of the
    # campaign's 79 domains was freshly registered, so no rule held a single
    # value and the panel served 0 — while 31 Okta rules sat in the store and
    # "okta" appeared in 7 of those domains. These matches carry
    # `discriminating: False`, so they never lift `evidence_count`.
    brands = brand_tokens(conn, [o.value for o in observables if o.obs_class == "domain"])
    for rule_id, brand_matches in brand_evidence(conn, brands).items():
        evidence.setdefault(rule_id, []).extend(brand_matches)

    # CVE ids the same way. A CVE reaches no atom class at all — `MATCHABLE` has
    # no `cve` key — so a rule naming the vulnerability a report is *about* was
    # invisible to this panel. Measured: `cve-2021-44228` names 120 rules.
    for rule_id, cve_matches in cve_evidence(
        conn, [o.value for o in observables if o.obs_class == "cve"]
    ).items():
        evidence.setdefault(rule_id, []).extend(cve_matches)

    for evs in evidence.values():
        # Literal-value evidence first, then brand/title evidence, which is a
        # weaker claim: the rule is ABOUT this, it does not HOLD this.
        evs.sort(key=lambda e: (e.get("kind") != "atom", not e["discriminating"], e["display"]))
    return evidence


def rules_for_job(
    conn: sqlite3.Connection, job_id: str, *, evidence_only: bool = True
) -> dict:
    """Detection rules for this report, grouped by the technique they cover.

    ADR-0030: the panel serves ONLY rules backed by something the report actually
    contains. The tag join alone proposed 86,453 rules across seven reports of
    which 908 (1.05%) held any report value; on one report the ratio was 3 in
    12,280. `evidence_only=False` restores the unfiltered tag join, which the ZIP
    export and the detection-engineering backlog still want.

    Evidence also *adds* rules the tag join cannot reach: none of the 16,314
    canonical YARA rules carries an ATT&CK tag, so they arrive here only through
    `_evidence_for_job` and are grouped under `(untagged)`.

    Mirrors compute_for_job's parent→sub roll-up (a rule tagged with the parent
    technique also covers its sub-techniques). Rule bodies are never returned —
    metadata only (ADR-0006 license-aware drill-down).

    Rewritten as one flat sweep (ADR-0022): the per-technique form called
    `rules_for_technique` once per technique — 34 EXISTS joins and 34 `also_in`
    sweeps — and measured 26.3 s on a real report. One id query, one metadata
    batch and one `also_in` sweep replace them: 5.4 s for the same 10,372 rules.
    """
    from pipeline.detection.store import _also_in_map, canonical_rule_ids_for_techniques

    evidence = _evidence_for_job(conn, job_id)
    technique_ids = job_technique_ids(conn, job_id)

    # Same parent→sub roll-up as compute_for_job: a parent-tagged rule covers a
    # report's sub-technique.
    query_ids: set[str] = set()
    covers: dict[str, set[str]] = {}
    for t in technique_ids:
        query_ids.add(t)
        covers.setdefault(t, set()).add(t)
        parent = _parent_technique(t)
        if parent:
            query_ids.add(parent)
            covers.setdefault(parent, set()).add(t)

    rules_for_tech: dict[str, set[str]] = {}
    all_ids: set[str] = set()
    for tag, rid in canonical_rule_ids_for_techniques(conn, query_ids):
        for report_t in covers.get(tag.upper(), ()):
            rules_for_tech.setdefault(report_t, set()).add(rid)
            all_ids.add(rid)

    tag_total = len(all_ids)

    if evidence_only:
        admitted = {rid for rid, evs in evidence.items() if _admits(evs)}
        for t, ids in rules_for_tech.items():
            rules_for_tech[t] = {rid for rid in ids if rid in admitted}
        all_ids = admitted

    if not all_ids:
        return {"job_id": job_id, "techniques": [], "technique_total": 0,
                "rule_total": 0, "tag_total": tag_total, "evidence_total": 0,
                "evidence_only": evidence_only}

    # One metadata pass, 400 ids per statement (SQLite caps a statement at 999).
    meta: dict[str, dict] = {}
    ids_list = sorted(all_ids)
    for i in range(0, len(ids_list), 400):
        batch = ids_list[i:i + 400]
        placeholders = ",".join("?" * len(batch))
        for row in conn.execute(
            # Body size comes from the `rule_bytes` side table, never from
            # LENGTH(raw) nor a column on this table: both force SQLite past the
            # rule body's overflow pages — 8.2-8.8s versus 1.0s (ADR-0022).
            f"SELECT d.id, d.corpus, d.title, d.severity, d.license, d.source_ref, "
            f"d.format, d.dedup_key, COALESCE(b.bytes, 0) "
            f"FROM detection_rules d "
            f"LEFT JOIN rule_bytes b ON b.rule_id = d.id "
            f"WHERE d.id IN ({placeholders})",
            batch,
        ):
            meta[row[0]] = {
                "id": row[0], "corpus": row[1], "title": row[2], "severity": row[3],
                "license": row[4], "source_ref": row[5], "format": row[6] or "sigma",
                "bytes": row[8], "dedup_key": row[7],
            }

    # One also_in sweep for every dedup_key at once.
    also_in = _also_in_map(conn, (m["dedup_key"] for m in meta.values()))
    for m in meta.values():
        dk = m.pop("dedup_key")
        m["also_in"] = sorted(also_in.get(dk, set()) - {m["corpus"]}) if dk else []

    evidence_total = 0
    for rid, m in meta.items():
        evs = evidence.get(rid, [])
        m["matches"] = evs
        # Corroboration counts literal, discriminating values ONLY. A brand match
        # is admitted evidence but never corroboration (ADR-0031).
        m["evidence_count"] = sum(
            1 for e in evs if e["discriminating"] and e.get("kind") == "atom"
        )
        m["title_count"] = sum(1 for e in evs if e.get("kind") == "title")
        if evs:
            evidence_total += 1

    def _rank(r: dict) -> tuple:
        """Most-corroborated first: discriminating matches, then any match."""
        return (-r["evidence_count"], -len(r["matches"]), r["corpus"], r["title"] or "")

    groups: list[dict] = []
    for t in technique_ids:
        rules = [meta[rid] for rid in rules_for_tech.get(t, ()) if rid in meta]
        if not rules:
            continue
        rules.sort(key=_rank)
        groups.append({"technique_id": t, "rules": rules})

    groups.sort(key=lambda g: (-len(g["rules"]), g["technique_id"]))

    # Rules reached by evidence alone carry none of this report's techniques —
    # every YARA rule in the store is in this case. Computed against the rules
    # actually PLACED in a group, never against `all_ids`, which by then already
    # contains them.
    tagged_ids = {rid for ids in rules_for_tech.values() for rid in ids}
    untagged = [m for rid, m in meta.items() if rid not in tagged_ids]
    if untagged:
        untagged.sort(key=_rank)
        groups.append({"technique_id": "(untagged)", "rules": untagged})

    return {
        "job_id": job_id,
        "techniques": groups,
        "technique_total": len(groups),
        "rule_total": len(all_ids),
        "tag_total": tag_total,
        "evidence_total": evidence_total,
        "evidence_only": evidence_only,
    }


def rule_bodies_for_job(
    conn: sqlite3.Connection, job_id: str, body_ids: set[str] | None = None
) -> list[dict]:
    """Raw bodies of every canonical detection rule linkable to this report.

    Mirrors rules_for_job's technique selection (parent→sub roll-up) so the
    export contains exactly the rules the Detections panel shows, but includes
    each rule's `raw` body for local export (ADR-0006 — license carried alongside
    via the export manifest). Each entry also lists the report technique(s) it
    covers. Returns [] when no rules match.

    `body_ids` restricts which rules carry their raw body. The rule-id export
    packages a handful of rules but still counts the rest in the manifest's
    `excluded` block; loading all 10,372 bodies to do so read 219 MB and measured
    14.8 s (ADR-0022). Rules outside `body_ids` come back with `raw: ""`."""
    from pipeline.detection.store import (
        canonical_rule_bodies,
        canonical_rule_ids_for_techniques,
    )

    # Map each rule-technique tag to the report technique(s) it covers, applying
    # the same parent→sub roll-up as compute_for_job (a parent-tagged rule covers
    # a report's sub-technique).
    query_ids: set[str] = set()
    covers: dict[str, set[str]] = {}
    for t in job_technique_ids(conn, job_id):
        query_ids.add(t)
        covers.setdefault(t, set()).add(t)
        parent = _parent_technique(t)
        if parent:
            query_ids.add(parent)
            covers.setdefault(parent, set()).add(t)

    # One flat query for all (tag, rule_id) pairs, then re-key to report techniques.
    tech_for_rule: dict[str, set[str]] = {}
    for tag, rid in canonical_rule_ids_for_techniques(conn, query_ids):
        for report_t in covers.get(tag.upper(), ()):
            tech_for_rule.setdefault(rid, set()).add(report_t)

    # Evidence-reached rules too, or the export cannot package what the panel
    # serves. Measured before this was added: 582 of 1,069 served rules — 54% —
    # were silently dropped from the ZIP, every one of them a rule reached by
    # evidence alone (ADR-0030 `strlit`/YARA, ADR-0031 brand). They carry no
    # ATT&CK tag, so the tag join above cannot see them; `techniques` stays empty
    # for them, which is the truth and is what the manifest should say.
    for rid, evs in _evidence_for_job(conn, job_id).items():
        if _admits(evs):
            tech_for_rule.setdefault(rid, set())

    if not tech_for_rule:
        return []

    with_bodies = tech_for_rule.keys() if body_ids is None else tech_for_rule.keys() & body_ids
    bodies = canonical_rule_bodies(conn, with_bodies) if with_bodies else {}
    out = [
        {"id": rid, **meta, "techniques": sorted(tech_for_rule[rid])}
        for rid, meta in bodies.items()
    ]

    # The rest are still needed — the manifest reports what was excluded — but
    # only their metadata, never their bodies.
    rest = sorted(tech_for_rule.keys() - bodies.keys())
    for i in range(0, len(rest), 400):
        batch = rest[i:i + 400]
        placeholders = ",".join("?" * len(batch))
        for row in conn.execute(
            f"SELECT id, corpus, native_key, title, license, source_ref "
            f"FROM detection_rules WHERE id IN ({placeholders})",
            batch,
        ):
            out.append({
                "id": row[0], "corpus": row[1] or "", "native_key": row[2] or "",
                "title": row[3], "license": row[4], "source_ref": row[5],
                "raw": "", "techniques": sorted(tech_for_rule[row[0]]),
            })

    out.sort(key=lambda r: (r["corpus"] or "", r["title"] or r["native_key"] or ""))
    return out


def rule_facets_for_job(conn: sqlite3.Connection, job_id: str) -> dict:
    """Per-axis rule counts and byte sizes for the export filter UI (ADR-0020).

    Same technique selection as `rule_bodies_for_job`, but aggregated in SQL so the
    rule bodies never cross into Python. That distinction is the whole point: the
    body-loading path pulls **219 MB** for one real report and took 17.6 s, which is
    unusable for a panel that renders on open. `length(raw)` gives the same byte
    totals from the index without transferring the text.
    """
    from pipeline.detection.store import canonical_rule_ids_for_techniques

    query_ids: set[str] = set()
    for t in job_technique_ids(conn, job_id):
        query_ids.add(t)
        parent = _parent_technique(t)
        if parent:
            query_ids.add(parent)

    rule_ids = {rid for _tag, rid in canonical_rule_ids_for_techniques(conn, query_ids)}
    empty = {"total": 0, "bytes": 0,
             "format": [], "corpus": [], "license": [], "severity": []}
    if not rule_ids:
        return empty

    # ONE pass over the rules, all four axes aggregated in Python from the same
    # rows. Querying each axis separately looked tidier and measured 2.4x SLOWER
    # (43s vs 17.6s): every axis re-ran SUM(LENGTH(raw)), so SQLite read the same
    # 219 MB of rule text four times over. Reading LENGTH once per rule is what
    # matters here, not where the GROUP BY happens.
    axes = ("format", "corpus", "license", "severity")
    buckets: dict[str, dict[str, dict]] = {a: {} for a in axes}
    total = 0
    total_bytes = 0
    ids = sorted(rule_ids)
    for i in range(0, len(ids), 400):   # SQLite caps a statement at 999 params
        batch = ids[i:i + 400]
        placeholders = ",".join("?" * len(batch))
        for fmt, corpus, lic, sev, nbytes in conn.execute(
            f"SELECT format, corpus, license, severity, LENGTH(COALESCE(raw, '')) "
            f"FROM detection_rules WHERE id IN ({placeholders})",
            batch,
        ):
            total += 1
            total_bytes += nbytes or 0
            for axis, raw_value in zip(axes, (fmt, corpus, lic, sev)):
                value = (raw_value or "").strip().lower() or "unknown"
                b = buckets[axis].setdefault(
                    value, {"value": value, "rules": 0, "bytes": 0}
                )
                b["rules"] += 1
                b["bytes"] += nbytes or 0

    result: dict = {"total": total, "bytes": total_bytes}
    for axis in axes:
        result[axis] = sorted(
            buckets[axis].values(), key=lambda x: (-x["rules"], x["value"])
        )
    return result
