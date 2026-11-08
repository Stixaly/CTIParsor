"""Response models of the detection-coverage routes (api/routes/coverage.py).

Field types follow what the pipeline functions return (pipeline/detection/*.py).
Columns NOT NULL in the schema are declared `str`; the others `str | None`.
"""
from __future__ import annotations

from typing import Literal

from pydantic import Field

from api.response_models import Response

# ── GET /jobs/{job_id}/coverage ─────────────────────────────────────────────

class FormatCoverage(Response):
    """One detection format's share of a technique's coverage (ADR-0022)."""
    rule_count: int = Field(description="Distinct logical rules of this format for the technique")
    corpora: list[str] = Field(description="Owning corpora of those rules")


class TechniqueCoverage(Response):
    """Coverage of one technique the report holds (compute_for_job)."""
    technique_id: str
    score: int = Field(description="0 to 3: how many independent corpora hold a rule for the technique")
    corpora: list[str]
    rule_count: int
    by_format: dict[str, FormatCoverage] = Field(description="Keyed by sigma, suricata, yara")


class Coverage(Response):
    job_id: str
    techniques_total: int
    by_score: dict[int, int] = Field(description="Number of techniques at each score, 0 to 3")
    validated: bool = Field(description="Always false: readiness, not lab validation (ADR-0005/0006)")
    cells: list[TechniqueCoverage]


# ── GET /jobs/{job_id}/coverage/rules ───────────────────────────────────────

class RuleMatch(Response):
    """One observable of the report that a rule holds (kind `atom`), or a rule
    about it (kind `title`: a brand or a CVE named in the title)."""
    obs_class: str
    display: str
    value: str
    field: str = Field(description="The rule-side atom class, or `title`")
    discriminating: bool
    kind: Literal["atom", "title"]


class RuleEntry(Response):
    """Metadata of one canonical rule in the report's panel (no body)."""
    id: str
    corpus: str
    title: str
    severity: str | None
    license: str | None
    source_ref: str | None
    format: str
    bytes: int = Field(description="Length of the rule body in bytes")
    also_in: list[str] = Field(description="Other corpora that shipped a duplicate folded into this rule")
    matches: list[RuleMatch]
    evidence_count: int = Field(description="Distinct discriminating observables the rule holds")
    title_count: int = Field(description="Brand or CVE matches on the title")


class TechniqueRules(Response):
    technique_id: str = Field(description="A report technique, or `(untagged)`")
    rules: list[RuleEntry]


class RulesForJob(Response):
    job_id: str
    techniques: list[TechniqueRules]
    technique_total: int
    rule_total: int
    tag_total: int = Field(description="Rules the ATT&CK tag join reaches, before the evidence filter")
    evidence_total: int
    evidence_only: bool


# ── GET /jobs/{job_id}/detections/proposals ─────────────────────────────────

class ProposalMatch(Response):
    obs_class: str
    field: str = Field(description="The rule-side atom class")
    value: str
    display: str
    exact: bool = Field(description="False for a substring match")
    weight: float
    discriminating: bool


class Proposal(Response):
    id: str
    corpus: str
    title: str
    severity: str
    license: str
    source_ref: str
    platform: str
    format: str
    score: float
    tier: Literal["direct", "behavioural", "weak"]
    techniques: list[str]
    evidence_count: int
    support_count: int
    matches: list[ProposalMatch]


class Observable(Response):
    obs_class: str = Field(alias="class", description="Observable class, serialised as `class`")
    value: str
    display: str
    entity_type: str


class ProposalsForJob(Response):
    job_id: str
    platform: str = Field(description="The report's inferred operating system")
    atom_index_built: bool
    observables: list[Observable]
    observables_total: int
    candidate_total: int
    counts: dict[str, int] = Field(description="Proposals per tier: direct, behavioural, weak")
    corroborated_total: int = Field(description="Proposals with at least two discriminating matches")
    returned: int
    proposals: list[Proposal]


# ── GET /jobs/{job_id}/coverage/artifacts ───────────────────────────────────

class ArtifactEvidence(Response):
    rule_id: str
    corpus: str
    field: str
    exact: bool


class ArtifactItem(Response):
    artifact_class: str = Field(alias="class", description="Artifact class, serialised as `class`")
    classes: list[str]
    value: str
    display: str
    entity_type: str
    entity_types: list[str]
    tier: int = Field(description="Pyramid of Pain tier, 1 to 4")
    tier_label: str
    score: int = Field(description="0 to 3")
    corpora: list[str]
    evidence_corpora: list[str] = Field(description="Corpora across all evidence, weak included; not in the score")
    df: int
    excluded: str | None = Field(description="None, `vocabulary` or `not_matchable`")
    evidence_total: int
    evidence: list[ArtifactEvidence]


class ArtifactTotals(Response):
    artifacts: int
    covered: int
    weak: int
    uncovered: int
    excluded: int


class TierSummary(Response):
    tier: int
    label: str
    artifacts: int
    covered: int
    weak: int
    uncovered: int


class ReportColumn(Response):
    tactic: str
    label: str
    techniques: list[str]


class OffMatrixTechnique(Response):
    technique_id: str
    domain: str


class PhaseReport(Response):
    """Row 1 of the phase band: where the report places its techniques."""
    columns: list[ReportColumn]
    off_matrix: list[OffMatrixTechnique]
    on_matrix_total: int
    off_matrix_total: int


class CoveredColumn(Response):
    tactic: str
    label: str
    rules: int = Field(description="Matched rules placed in this tactic")
    techniques: list[str]


class PhaseCovered(Response):
    """Row 2 of the phase band: where the matched rules sit."""
    columns: list[CoveredColumn]
    rules_total: int
    rules_placed: int
    rules_untagged: int


class PhaseGap(Response):
    tactic: str
    label: str
    report_techniques: int
    covered_rules: int


class PhaseBand(Response):
    report: PhaseReport
    covered: PhaseCovered
    gap: list[PhaseGap]


class ArtifactCoverage(Response):
    job_id: str
    artifacts: list[ArtifactItem]
    totals: ArtifactTotals
    by_tier: list[TierSummary]
    vocabulary_threshold: int
    canonical_rules: int
    phases: PhaseBand
    matched_rules: int


# ── GET /jobs/{job_id}/coverage/{technique_id}/rules ────────────────────────

class TechniqueRule(Response):
    """Metadata of one canonical rule covering a technique (no body)."""
    id: str
    corpus: str
    title: str
    severity: str | None
    license: str | None
    source_ref: str | None
    format: str
    bytes: int
    also_in: list[str]


class RulesForTechnique(Response):
    technique_id: str = Field(description="Upper-cased")
    rules: list[TechniqueRule]


# ── GET /jobs/{job_id}/detections/export/facets ─────────────────────────────

class FacetValue(Response):
    value: str
    rules: int
    bytes: int = Field(description="Sum of the UTF-8 byte lengths of the rule bodies")


class RuleFacets(Response):
    total: int
    bytes: int
    format: list[FacetValue]
    corpus: list[FacetValue]
    license: list[FacetValue]
    severity: list[FacetValue]


# ── POST /rules/lookup ──────────────────────────────────────────────────────

class LookedUpRule(Response):
    id: str
    corpus: str
    title: str
    description: str
    severity: str
    license: str
    source_ref: str
    platform: str
    format: str
    bytes: int
    techniques: list[str]
    raw: str = Field(description="The rule body when `include_body` was true, else empty")


class RuleLookupResult(Response):
    rules: list[LookedUpRule]
    requested: int = Field(description="Distinct ids asked for")


# ── GET /detection-corpora ──────────────────────────────────────────────────

class CorpusCount(Response):
    corpus: str
    license: str | None
    rules: int = Field(description="Rules ingested for this corpus and licence")
    canonical: int = Field(description="Rules that survive deduplication")


class DetectionCorpora(Response):
    corpora: list[CorpusCount]
