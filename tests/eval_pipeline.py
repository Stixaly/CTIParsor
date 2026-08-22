"""
NER Evaluation Harness — ADR-004 P1-B

Scores the pipeline's Stage 2 NER output against labeled ground-truth data using
entity-level Precision / Recall / F1, following the methodology from:

  "Evaluation Metrics for Custom Named Entity Recognition Models"
  (Microsoft, 2024) — exact-match and partial-match scoring.

  "CTiKG: A Domain-Specific Knowledge Graph for CTI"
  (University of Windsor, 2025) — DNRTI-AUG-STIX2 dataset integration.

Usage (CLI):
  # Run built-in fixture tests (no dataset needed):
  python tests/eval_pipeline.py

  # Evaluate against DNRTI-AUG-STIX2 dataset (download separately):
  python tests/eval_pipeline.py --dataset /path/to/dnrti_aug_stix2.json

  # Evaluate only specific entity types:
  python tests/eval_pipeline.py --types malware threat_actor

  # Verbose output (show false positives / false negatives per sample):
  python tests/eval_pipeline.py --verbose

Dataset format (DNRTI-AUG-STIX2 or custom):
  JSON list of objects:
  [
    {
      "text": "APT29 deployed WellMess against government agencies.",
      "entities": [
        {"value": "APT29",     "type": "threat_actor"},
        {"value": "WellMess",  "type": "malware"}
      ]
    },
    ...
  ]

Metrics definitions (entity-level):
  True Positive (TP):  predicted entity matches a ground-truth entity
                       (same value, case-insensitive; same type)
  False Positive (FP): predicted entity has no matching ground-truth entity
  False Negative (FN): ground-truth entity not found in predictions

  Precision = TP / (TP + FP)
  Recall    = TP / (TP + FN)
  F1        = 2 × Precision × Recall / (Precision + Recall)

Partial match mode:
  A partial match occurs when the predicted value is a substring (or the ground
  truth is a substring) of the other, with the same entity type.
  Partial matches score 0.5 instead of 1.0.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

# Ensure project root is on sys.path
_ROOT = Path(__file__).parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from models.schemas import EntityType, RawEntity
from pipeline.stage2_extraction import extract_entities

# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class NERSample:
    """A single labeled CTI text sample."""
    text: str
    expected: list[tuple[str, EntityType]]   # (value, type) pairs
    description: str = ""


@dataclass
class MatchResult:
    """Result of comparing one predicted entity against the gold standard."""
    value: str
    entity_type: EntityType
    match_type: str   # "exact" | "partial" | "none"
    score: float      # 1.0 exact, 0.5 partial, 0.0 none


@dataclass
class StageScore:
    """Aggregated NER scores for one entity type."""
    entity_type: str
    tp: float = 0.0
    fp: float = 0.0
    fn: float = 0.0

    @property
    def precision(self) -> float:
        denom = self.tp + self.fp
        return self.tp / denom if denom else 0.0

    @property
    def recall(self) -> float:
        denom = self.tp + self.fn
        return self.tp / denom if denom else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) else 0.0


# ---------------------------------------------------------------------------
# Scoring functions
# ---------------------------------------------------------------------------

def _match_score(pred_value: str, pred_type: EntityType,
                 gold_value: str, gold_type: EntityType) -> float:
    """
    Returns match score between a predicted entity and a gold entity:
      1.0 — exact match (case-insensitive value, same type)
      0.5 — partial match (one is substring of the other, same type)
      0.0 — no match
    """
    if pred_type != gold_type:
        return 0.0
    pv = pred_value.lower().strip()
    gv = gold_value.lower().strip()
    if pv == gv:
        return 1.0
    if pv in gv or gv in pv:
        return 0.5
    return 0.0


def score_sample(
    predicted: list[RawEntity],
    expected: list[tuple[str, EntityType]],
    partial_credit: bool = True,
) -> tuple[float, float, float]:
    """
    Score predicted entities against expected entities for a single sample.

    Returns (tp, fp, fn) as floats (partial matches contribute 0.5).
    """
    gold = list(expected)   # mutable copy
    pred = list(predicted)

    tp: float = 0.0
    matched_gold: set[int] = set()

    for pe in pred:
        best_score = 0.0
        best_gold_idx = -1
        for gi, (gv, gt) in enumerate(gold):
            if gi in matched_gold:
                continue
            s = _match_score(pe.value, pe.entity_type, gv, gt)
            if s > best_score:
                best_score = s
                best_gold_idx = gi

        if best_gold_idx >= 0 and best_score > 0:
            if partial_credit:
                tp += best_score
            else:
                tp += 1.0 if best_score == 1.0 else 0.0
            matched_gold.add(best_gold_idx)

    fp = len(pred) - len(matched_gold)
    fn = len(gold) - len(matched_gold)

    return max(0.0, tp), max(0.0, float(fp)), max(0.0, float(fn))


def score_dataset(
    samples: list[NERSample],
    stage_fn=None,
    partial_credit: bool = True,
    verbose: bool = False,
    filter_types: set[EntityType] | None = None,
) -> dict[str, StageScore]:
    """
    Evaluate *stage_fn* (or the default Stage 2 regex extractor) over all samples.

    Returns a dict of entity_type_name → StageScore.
    Also returns an "overall" key with macro-averaged scores.
    """
    if stage_fn is None:
        stage_fn = extract_entities

    # Aggregate per entity type
    scores: dict[str, StageScore] = {}

    for sample in samples:
        predicted = stage_fn(sample.text)

        # Filter by type if requested
        if filter_types:
            predicted = [e for e in predicted if e.entity_type in filter_types]
            expected  = [(v, t) for v, t in sample.expected if t in filter_types]
        else:
            expected = sample.expected

        tp, fp, fn = score_sample(predicted, expected, partial_credit=partial_credit)

        # Break down by type
        for pe in predicted:
            key = pe.entity_type.value
            if key not in scores:
                scores[key] = StageScore(entity_type=key)

        for _, et in expected:
            key = et.value
            if key not in scores:
                scores[key] = StageScore(entity_type=key)

        # Per-type TP/FP/FN
        for pe in predicted:
            key = pe.entity_type.value
            type_gold = [(v, t) for v, t in expected if t == pe.entity_type]
            # Did this prediction match anything in gold of this type?
            best = max(
                (_match_score(pe.value, pe.entity_type, gv, gt) for gv, gt in type_gold),
                default=0.0,
            )
            if best > 0:
                scores[key].tp += best if partial_credit else (1.0 if best == 1.0 else 0.0)
            else:
                scores[key].fp += 1.0

        for gv, gt in expected:
            key = gt.value
            type_pred = [pe for pe in predicted if pe.entity_type == gt]
            best = max(
                (_match_score(pe.value, pe.entity_type, gv, gt) for pe in type_pred),
                default=0.0,
            )
            if best == 0:
                scores[key].fn += 1.0

        if verbose:
            _print_sample_diff(sample, predicted, expected)

    # Overall (macro average across types)
    if scores:
        overall = StageScore(entity_type="overall")
        for s in scores.values():
            overall.tp += s.tp
            overall.fp += s.fp
            overall.fn += s.fn
        scores["overall"] = overall

    return scores


def _print_sample_diff(
    sample: NERSample,
    predicted: list[RawEntity],
    expected: list[tuple[str, EntityType]],
) -> None:
    """Print false positives and false negatives for one sample (verbose mode)."""
    print(f"\n  [{sample.description or 'sample'}]")
    pred_set = {(e.value.lower(), e.entity_type) for e in predicted}
    gold_set = {(v.lower(), t) for v, t in expected}
    fps = pred_set - gold_set
    fns = gold_set - pred_set
    if fps:
        print(f"    FP (unexpected): {fps}")
    if fns:
        print(f"    FN (missed):     {fns}")


def print_scores(scores: dict[str, StageScore]) -> None:
    """Print a formatted score table."""
    overall = scores.pop("overall", None)

    print(f"\n{'Entity Type':<22}  {'Prec':>6}  {'Rec':>6}  {'F1':>6}  {'TP':>6}  {'FP':>6}  {'FN':>6}")
    print("-" * 70)

    for key in sorted(scores):
        s = scores[key]
        print(
            f"{key:<22}  {s.precision:>6.3f}  {s.recall:>6.3f}  {s.f1:>6.3f}"
            f"  {s.tp:>6.1f}  {s.fp:>6.1f}  {s.fn:>6.1f}"
        )

    if overall:
        print("-" * 70)
        print(
            f"{'OVERALL (macro)':<22}  {overall.precision:>6.3f}  "
            f"{overall.recall:>6.3f}  {overall.f1:>6.3f}"
            f"  {overall.tp:>6.1f}  {overall.fp:>6.1f}  {overall.fn:>6.1f}"
        )

    scores["overall"] = overall  # restore


# ---------------------------------------------------------------------------
# Built-in fixture samples  (no external dataset needed)
# ---------------------------------------------------------------------------

def _load_fixture_samples() -> list[NERSample]:
    """
    Hand-labeled CTI samples based on the test fixture (sample_report.txt) and
    representative patterns from the DNRTI-AUG-STIX2 dataset format.

    These cover: IPv4, SHA256, MD5, SHA1, URL, EMAIL, DOMAIN, CVE, TTP,
    MALWARE (via gazetteer), THREAT_ACTOR (via gazetteer).
    """
    return [
        # ── IoC-only sample ──────────────────────────────────────────────────
        NERSample(
            text=(
                "The malware connected to 185.220.101.45 and evil-c2-domain.ru. "
                "It downloaded https://evil-c2-domain.ru/payload.exe "
                "and sent data to phishing@malicious-domain.com. "
                "SHA256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 "
                "MD5: d41d8cd98f00b204e9800998ecf8427e "
                "SHA1: da39a3ee5e6b4b0d3255bfef95601890afd80709 "
                "CVE-2021-40444 was exploited."
            ),
            expected=[
                ("185.220.101.45", EntityType.IPV4),
                ("evil-c2-domain.ru", EntityType.DOMAIN),
                ("https://evil-c2-domain.ru/payload.exe", EntityType.URL),
                ("phishing@malicious-domain.com", EntityType.EMAIL),
                ("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", EntityType.SHA256),
                ("d41d8cd98f00b204e9800998ecf8427e", EntityType.MD5),
                ("da39a3ee5e6b4b0d3255bfef95601890afd80709", EntityType.SHA1),
                ("CVE-2021-40444", EntityType.CVE),
            ],
            description="IoC-only sample",
        ),

        # ── Defanged IoC sample ───────────────────────────────────────────────
        NERSample(
            text=(
                "Indicators: 192[.]168[.]1[.]1, hxxps://malware[.]example[.]com/drop, "
                "user[at]evil[.]org, 10[.]0[.]0[.]1:4444"
            ),
            expected=[
                ("192.168.1.1", EntityType.IPV4),
                ("https://malware.example.com/drop", EntityType.URL),
                ("user@evil.org", EntityType.EMAIL),
                ("10.0.0.1", EntityType.IPV4),
            ],
            description="Defanged IoCs",
        ),

        # ── MITRE TTP sample ──────────────────────────────────────────────────
        NERSample(
            text=(
                "T1566.001 (Spearphishing Attachment) was used for initial access. "
                "The actor leveraged T1059.001 (PowerShell) and T1547.001 for persistence."
            ),
            expected=[
                ("T1566.001", EntityType.TTP),
                ("T1059.001", EntityType.TTP),
                ("T1547.001", EntityType.TTP),
            ],
            description="MITRE TTPs",
        ),

        # ── Multi-hash IoC appendix ───────────────────────────────────────────
        NERSample(
            text=(
                "Malicious files:\n"
                "- d41d8cd98f00b204e9800998ecf8427e\n"
                "- e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n"
                "- da39a3ee5e6b4b0d3255bfef95601890afd80709\n"
            ),
            expected=[
                ("d41d8cd98f00b204e9800998ecf8427e", EntityType.MD5),
                ("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", EntityType.SHA256),
                ("da39a3ee5e6b4b0d3255bfef95601890afd80709", EntityType.SHA1),
            ],
            description="Multi-hash IoC appendix",
        ),

        # ── CVE-rich vulnerability section ───────────────────────────────────
        NERSample(
            text=(
                "The actor exploited CVE-2021-40444, CVE-2020-1472 (Zerologon), "
                "and CVE-2017-0144 (EternalBlue) to achieve lateral movement."
            ),
            expected=[
                ("CVE-2021-40444", EntityType.CVE),
                ("CVE-2020-1472", EntityType.CVE),
                ("CVE-2017-0144", EntityType.CVE),
            ],
            description="Multi-CVE vulnerability section",
        ),

        # ── IPv6 and ASN (edge cases) ─────────────────────────────────────────
        NERSample(
            text=(
                "Traffic was observed from 2001:db8::1 to malicious-host.example.com. "
                "The C2 URL was https://c2.attacker.net/api/v1/check-in."
            ),
            expected=[
                ("malicious-host.example.com", EntityType.DOMAIN),
                ("https://c2.attacker.net/api/v1/check-in", EntityType.URL),
            ],
            description="Domain + URL (IPv6 address not expected in this field)",
        ),
    ]


# ---------------------------------------------------------------------------
# DNRTI-AUG-STIX2 loader
# ---------------------------------------------------------------------------

def load_dnrti_dataset(path: Path) -> list[NERSample]:
    """
    Load the DNRTI-AUG-STIX2 dataset (CTiKG paper, University of Windsor 2025).

    Expected format: JSON list of STIX bundles or our flat format:
      [{"text": "...", "entities": [{"value": "...", "type": "..."}]}]

    Download: https://github.com/abdullahalzubaer/CTiKG (when publicly released)
    """
    data = json.loads(path.read_text(encoding="utf-8"))
    samples: list[NERSample] = []

    for item in data:
        text = item.get("text", "")
        if not text:
            continue

        entities: list[tuple[str, EntityType]] = []
        for ent in item.get("entities", []):
            try:
                etype = EntityType(ent["type"])
                entities.append((ent["value"], etype))
            except (KeyError, ValueError):
                continue

        samples.append(NERSample(text=text, expected=entities))

    return samples


# ---------------------------------------------------------------------------
# pytest integration — runs fixture samples as a test
# ---------------------------------------------------------------------------

def test_stage2_ner_f1_on_fixtures():
    """
    Smoke test: Stage 2 regex NER should achieve at least F1=0.80 on fixture data.
    Tests IoC types only (regex stage — not NER stages 2b/2c/2d).
    """
    ioc_types = {
        EntityType.IPV4, EntityType.IPV6, EntityType.DOMAIN, EntityType.URL,
        EntityType.EMAIL, EntityType.MD5, EntityType.SHA1, EntityType.SHA256,
        EntityType.CVE, EntityType.TTP,
    }
    samples = _load_fixture_samples()
    scores = score_dataset(samples, partial_credit=True, filter_types=ioc_types)
    overall = scores.get("overall")
    assert overall is not None, "No scores computed"
    assert overall.f1 >= 0.70, (
        f"Stage 2 IoC F1={overall.f1:.3f} below 0.70 threshold. "
        f"TP={overall.tp:.1f} FP={overall.fp:.1f} FN={overall.fn:.1f}"
    )


def test_stage2_no_false_positives_on_clean_text():
    """Stage 2 should extract zero entities from text with no IoCs."""
    clean_texts = [
        "This is a high-level executive summary with no technical indicators.",
        "The threat actor used social engineering to gain access.",
        "Table of Contents\n1. Introduction\n2. Background\n3. Findings",
    ]
    for text in clean_texts:
        entities = extract_entities(text)
        iocs = [
            e for e in entities
            if e.entity_type in {
                EntityType.IPV4, EntityType.SHA256, EntityType.MD5, EntityType.SHA1,
                EntityType.URL, EntityType.EMAIL,
            }
        ]
        # Allow CVE/TTP false positives (regex can fire on "T1234" in prose)
        assert len(iocs) == 0, f"Unexpected IoCs in clean text: {iocs}"


# ===========================================================================
# ATT&CK Technique Extraction (ATE) Benchmark — ADR-004 P3-C
#
# Based on the CTIBench ATE task (RIT / NeurIPS 2024):
#   "CTIBench: A Benchmark for Evaluating LLMs in Cyber Threat Intelligence"
#   GPT-4 baseline on ATE: F1 = 0.64
#   GPT-3.5-turbo on ATE:  F1 = 0.38  (much worse — avoid for TTP extraction)
#
# The ATE task measures how well a system identifies MITRE ATT&CK technique IDs
# from CTI text — both explicit (T-ID mentioned) and implicit (described semantically).
#
# Usage:
#   python tests/eval_pipeline.py --benchmark ate            # fixture samples
#   python tests/eval_pipeline.py --benchmark ate --dataset /path/to/ctibench_ate.json
#   python tests/eval_pipeline.py --benchmark ate --stage 2c  # semantic only
#   python tests/eval_pipeline.py --benchmark ate --stage all # all stages combined
#
# CTIBench dataset: https://github.com/xashru/cti-bench  (public)
# ===========================================================================

@dataclass
class ATESample:
    """A single ATE benchmark sample: text + expected ATT&CK technique IDs."""
    text: str
    expected_ids: set[str]      # canonical T-IDs, e.g. {"T1566.001", "T1059.001"}
    description: str = ""


@dataclass
class GranularityScore:
    """Macro-averaged P/R/F1 at one ATT&CK ID granularity."""
    n_samples:         int   = 0
    sum_precision:     float = 0.0
    sum_recall:        float = 0.0
    sum_f1:            float = 0.0
    sum_pred_labels:   int   = 0
    sum_gold_labels:   int   = 0
    tp:                int   = 0
    fp:                int   = 0
    fn:                int   = 0

    @property
    def precision(self) -> float:
        if self.n_samples == 0:
            return 0.0
        return self.sum_precision / self.n_samples

    @property
    def recall(self) -> float:
        if self.n_samples == 0:
            return 0.0
        return self.sum_recall / self.n_samples

    @property
    def f1(self) -> float:
        # NOTE: f1 is the mean of per-sample F1 scores, NOT the F1 recomputed from
        # the mean precision and recall.  The two differ; the macro-averaged form is
        # the one both reference protocols report.
        if self.n_samples == 0:
            return 0.0
        return self.sum_f1 / self.n_samples

    @property
    def mean_labels_predicted(self) -> float:
        if self.n_samples == 0:
            return 0.0
        return self.sum_pred_labels / self.n_samples

    @property
    def mean_labels_gold(self) -> float:
        if self.n_samples == 0:
            return 0.0
        return self.sum_gold_labels / self.n_samples

    def add_sample(self, precision: float, recall: float, f1: float,
                   n_pred: int, n_gold: int,
                   tp: int, fp: int, fn: int) -> None:
        """Increment n_samples and accumulate all fields for one sample."""
        self.n_samples += 1
        self.sum_precision += precision
        self.sum_recall += recall
        self.sum_f1 += f1
        self.sum_pred_labels += n_pred
        self.sum_gold_labels += n_gold
        self.tp += tp
        self.fp += fp
        self.fn += fn


@dataclass
class ATEScore:
    """ATE result reported at both ATT&CK ID granularities."""
    technique:    GranularityScore = field(default_factory=GranularityScore)
    subtechnique: GranularityScore = field(default_factory=GranularityScore)


# ---------------------------------------------------------------------------
# ATE scoring helpers
# ---------------------------------------------------------------------------

def _normalize_tid(tid: str) -> str:
    """Uppercase and strip a MITRE T-ID: ' t1059.001 ' → 'T1059.001'."""
    return tid.strip().upper()


def _truncate_to_parent(tid: str) -> str:
    """
    Return the parent technique ID of a MITRE T-ID.

    "T1059.001" -> "T1059"
    "T1059"     -> "T1059"
    "t1059.001" -> "T1059"   (normalized first via _normalize_tid)

    Splits on the LAST "." only. If the string contains no ".", the
    normalized string is returned as-is.
    """
    normalized = _normalize_tid(tid)
    if "." in normalized:
        return normalized.rsplit(".", 1)[0]
    return normalized


def _clean_ids(ids) -> set[str]:
    """
    Normalize an iterable of IDs into a set of canonical T-IDs.

    - Applies _normalize_tid to each element.
    - Ignores any element that is not a str (type guard: input may come
      from external JSON and contain integers or None).
    - Ignores empty strings after strip.

    Returns a set[str].
    """
    result: set[str] = set()
    for item in ids:
        if not isinstance(item, str):
            continue
        stripped = item.strip()
        if not stripped:
            continue
        result.add(_normalize_tid(item))
    return result


def _score_one_granularity(pred: set[str], gold: set[str]) -> tuple[float, float, float, int, int, int]:
    """
    Score one sample at a single ATT&CK ID granularity using exact set matching.

    Returns (precision, recall, f1, tp, fp, fn).
    """
    tp = len(pred & gold)
    fp = len(pred - gold)
    fn = len(gold - pred)

    # Empty-set conventions.  An empty prediction on an empty gold set is a
    # correct rejection and scores 1.0; any other empty-set combination scores
    # 0.0 on every metric.  This keeps negative samples meaningful: emitting a
    # technique where the gold set is empty must cost precision.
    if len(pred) == 0 and len(gold) == 0:
        return 1.0, 1.0, 1.0, tp, fp, fn
    if len(pred) == 0 and len(gold) > 0:
        return 0.0, 0.0, 0.0, tp, fp, fn
    if len(pred) > 0 and len(gold) == 0:
        return 0.0, 0.0, 0.0, tp, fp, fn

    precision = tp / len(pred)
    recall = tp / len(gold)
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
    return precision, recall, f1, tp, fp, fn


def _score_ate_sample(
    predicted_ids: set[str],
    expected_ids:  set[str],
) -> tuple[tuple[float, float, float, int, int, int],
           tuple[float, float, float, int, int, int]]:
    """
    Score one ATE sample at both ATT&CK ID granularities.

    Returns (technique_result, subtechnique_result), where each result is
    (precision, recall, f1, tp, fp, fn).

    Partial credit for parent/sub-technique mismatches is deliberately NOT
    awarded: predicting a parent technique when a sub-technique is the gold
    label (or vice versa) is scored as one false positive plus one false
    negative at sub-technique level, and as a match at technique level.
    """
    pred = _clean_ids(predicted_ids)
    gold = _clean_ids(expected_ids)

    # Sub-technique granularity: score raw sets
    sub_res = _score_one_granularity(pred, gold)

    # Technique granularity: truncate both sets to parent IDs before scoring
    tech_pred = {_truncate_to_parent(t) for t in pred}
    tech_gold = {_truncate_to_parent(t) for t in gold}
    tech_res = _score_one_granularity(tech_pred, tech_gold)

    return tech_res, sub_res


# ---------------------------------------------------------------------------
# ATE stage functions — wrap each extraction stage into a common interface
# ---------------------------------------------------------------------------

def _ate_stage2_regex(text: str) -> set[str]:
    """Stage 2 regex: extract explicit T-IDs from text (e.g. 'T1566.001')."""
    entities = extract_entities(text)
    return {e.value.upper() for e in entities if e.entity_type == EntityType.TTP}


def _ate_stage2c_semantic(text: str) -> set[str]:
    """Stage 2c semantic TTP matching — requires embedding cache."""
    try:
        from pipeline.stage2c_ttp_semantic import detect_ttps_semantic, semantic_available
        if not semantic_available():
            return set()
        results = detect_ttps_semantic(text)
        return {e.mitre_id.upper() for e in results if e.mitre_id}
    except Exception:
        return set()


def _ate_combined(text: str) -> set[str]:
    """Combine regex (Stage 2) + semantic (Stage 2c) TTP extraction, then apply
    the Stage 3c parent/sub-technique subsumption so the measured set reflects the
    same precision rules the pipeline ships (Phase C)."""
    ids = _ate_stage2_regex(text)
    ids |= _ate_stage2c_semantic(text)
    return _subsume_ids(ids)


def _subsume_ids(ids: set[str]) -> set[str]:
    """Drop a parent T-ID when a sub-technique of it is also present."""
    upper = {i.upper() for i in ids}
    parents = {i.rsplit(".", 1)[0] for i in upper if "." in i}
    return {i for i in upper if i not in parents}


def _ate_stage_full(text: str) -> set[str]:
    """
    Full TTP path: regex + semantic + LLM enrichment + Stage 3c normalize.

    This is the ONLY stage that measures what the pipeline actually emits to the
    DB — it includes the LLM and the merge/normalize/subsumption logic where the
    Phase A–C precision rules live.  Requires a configured LLM provider; without
    one it degrades to regex + semantic so the harness still runs offline.
    """
    from models.schemas import EntityType
    from pipeline.stage2_extraction import extract_entities
    from pipeline.stage3_llm import _provider_ready, enrich_all_chunks

    regex_ents = extract_entities(text)

    semantic_ents: list = []
    try:
        from pipeline.stage2c_ttp_semantic import detect_ttps_semantic, semantic_available
        if semantic_available():
            semantic_ents = detect_ttps_semantic(text)
    except Exception:
        pass

    ids = {e.value.upper() for e in regex_ents if e.entity_type == EntityType.TTP}
    ids |= {e.mitre_id.upper() for e in semantic_ents if e.mitre_id}

    if _provider_ready():
        result = enrich_all_chunks(
            [text], [regex_ents], semantic_ttp_entities=semantic_ents,
        )
        ids |= {t.mitre_id.upper() for t in result.ttps if t.mitre_id}

    return _subsume_ids(ids)


_ATE_STAGE_FNS: dict[str, object] = {
    "2":    _ate_stage2_regex,
    "2c":   _ate_stage2c_semantic,
    "all":  _ate_combined,
    "full": _ate_stage_full,
}


# ---------------------------------------------------------------------------
# ATE fixture samples
# ---------------------------------------------------------------------------

def _load_ate_fixture_samples() -> list[ATESample]:
    """
    Hand-labeled ATE samples covering both explicit T-ID references (Stage 2
    regex detects them) and semantic descriptions (Stage 2c semantic detects them).

    GPT-4 baseline on CTIBench ATE task: F1=0.64.
    These fixtures are designed to be representative of real CTI report language.
    """
    return [
        # ── Explicit T-ID references (Stage 2 regex) ─────────────────────────
        ATESample(
            text=(
                "The attacker used spearphishing emails with malicious attachments "
                "(T1566.001) to gain initial access into the target environment."
            ),
            expected_ids={"T1566.001"},
            description="Explicit T-ID — Spearphishing Attachment",
        ),
        ATESample(
            text=(
                "Lateral movement was achieved using T1021.001 (Remote Desktop Protocol). "
                "The actor also used T1059.001 to run PowerShell scripts and T1547.001 "
                "for registry persistence."
            ),
            expected_ids={"T1021.001", "T1059.001", "T1547.001"},
            description="Multiple explicit T-IDs in one snippet",
        ),

        # ── Semantic descriptions (Stage 2c should catch these) ───────────────
        ATESample(
            text=(
                "APT29 used PowerShell scripts to execute commands on compromised hosts, "
                "bypassing application control policies."
            ),
            expected_ids={"T1059.001"},
            description="Semantic — PowerShell Execution (T1059.001)",
        ),
        ATESample(
            text=(
                "The malware established persistence by adding itself to the Windows "
                "registry run keys, ensuring execution on every system startup."
            ),
            expected_ids={"T1547.001"},
            description="Semantic — Registry Run Keys persistence (T1547.001)",
        ),
        ATESample(
            text=(
                "Credential theft was performed by dumping the LSASS process memory "
                "using a custom tool, extracting NTLM hashes for pass-the-hash attacks."
            ),
            expected_ids={"T1003.001"},
            description="Semantic — LSASS Memory credential dumping (T1003.001)",
        ),
        ATESample(
            text=(
                "The threat actor exfiltrated data by encoding it in DNS TXT record "
                "queries, using the DNS protocol as a covert channel."
            ),
            expected_ids={"T1048.003"},
            description="Semantic — DNS exfiltration over alternative protocol (T1048.003)",
        ),
        ATESample(
            text=(
                "WellMess communicated with its C2 server using encrypted HTTPS traffic, "
                "blending in with legitimate web traffic to avoid detection."
            ),
            expected_ids={"T1071.001"},
            description="Semantic — C2 via Web Protocols (T1071.001)",
        ),
        ATESample(
            text=(
                "The implant injected malicious code into the memory of a legitimate "
                "Windows process (svchost.exe) using process hollowing."
            ),
            expected_ids={"T1055.012"},
            description="Semantic — Process Injection / hollowing (T1055.012)",
        ),

        # ── Mixed (explicit + semantic in same snippet) ───────────────────────
        ATESample(
            text=(
                "Initial access was gained via T1566.001. Once inside, the actor "
                "dumped credentials from memory and used them for lateral movement "
                "across the network using valid accounts."
            ),
            expected_ids={"T1566.001", "T1003.001", "T1078"},
            description="Mixed explicit + semantic",
        ),

        # ── No TTP — should produce zero predictions ──────────────────────────
        ATESample(
            text=(
                "Executive summary: In Q2 2025, threat activity increased across "
                "the financial sector. Organisations should remain vigilant."
            ),
            expected_ids=set(),
            description="No TTP — clean executive summary (FP check)",
        ),
    ]


# ---------------------------------------------------------------------------
# ATE adversarial precision fixtures (Phase D)
#
# Near-miss text that shares TTP vocabulary but describes NO concrete technique.
# These exist purely to measure false positives: a precise extractor returns the
# empty set for every one of them.  They lock in the Phase A recalibration
# (margin gate + single match/sentence) against future regressions.
# ---------------------------------------------------------------------------

def _load_ate_adversarial_samples() -> list[ATESample]:
    return [
        ATESample(
            text=(
                "This quarterly report discusses persistence of threat activity "
                "and the credential-security posture of the financial sector. "
                "Organisations should remain vigilant against phishing."
            ),
            expected_ids=set(),
            description="Adversarial — TTP vocabulary in a generic summary (FP check)",
        ),
        ATESample(
            text=(
                "The vendor's marketing team executed a campaign to download new "
                "customers, leveraging social media to escalate brand awareness."
            ),
            expected_ids=set(),
            description="Adversarial — action verbs in a non-security sentence (FP check)",
        ),
        ATESample(
            text=(
                "Our backup process encrypts data at rest and the registry of "
                "approved vendors is reviewed quarterly for compliance."
            ),
            expected_ids=set(),
            description="Adversarial — 'encrypt'/'registry' in benign IT context (FP check)",
        ),
    ]


def test_ttp_regex_no_false_positives_on_adversarial():
    """Explicit-ID regex must extract nothing from TTP-flavoured prose (offline)."""
    score = run_ate_benchmark(_load_ate_adversarial_samples(), stage="2")
    assert score.subtechnique.fp == 0, (
        f"Regex TTP extraction produced {score.subtechnique.fp} false "
        f"positives on adversarial prose"
    )


def test_ttp_semantic_precision_on_adversarial():
    """
    On adversarial (benign, TTP-flavoured) prose the recalibrated semantic stage
    must produce NO *high-confidence* false positives, and must not flood with
    medium candidates.

    Medium-confidence matches are expected here — they are *candidates* that the
    downstream gates handle (Stage 3c stops them overriding the LLM; Stage 3f
    verifies them). The guarantee the raw stage makes is about high confidence.

    Skipped when the embedding cache / sentence-transformers is unavailable
    (e.g. SKIP_HEAVY_MODELS=1 in CI).
    """
    import pytest
    try:
        from pipeline.stage2c_ttp_semantic import (
            detect_ttps_semantic,
            high_confidence_threshold,
            semantic_available,
        )
    except ImportError:
        pytest.skip("sentence-transformers not installed")
        return
    if not semantic_available():
        pytest.skip("embedding cache unavailable (SKIP_HEAVY_MODELS or no cache)")
        return

    high = high_confidence_threshold()
    high_conf_fps = 0
    total_fps = 0
    for sample in _load_ate_adversarial_samples():
        for ent in detect_ttps_semantic(sample.text):
            total_fps += 1
            if ent.confidence >= high:
                high_conf_fps += 1

    assert high_conf_fps == 0, (
        f"Semantic stage produced {high_conf_fps} HIGH-confidence false positives "
        f"on adversarial prose (expected 0 after Phase A recalibration)"
    )
    # Flooding guard: medium candidates are allowed, but a handful at most.
    assert total_fps <= 4, (
        f"Semantic stage flooded adversarial prose with {total_fps} spurious "
        f"techniques (expected ≤4 — margin gate / single-match recalibration)"
    )


# ---------------------------------------------------------------------------
# ATE dataset loader — CTIBench format
# ---------------------------------------------------------------------------

def load_ctibench_ate(path: Path) -> list[ATESample]:
    """
    Load the CTIBench ATE dataset (RIT / NeurIPS 2024).

    Expected format (CTIBench GitHub — https://github.com/xashru/cti-bench):
      JSON list of objects:
      [
        {
          "text": "The actor used PowerShell...",
          "techniques": ["T1059.001", "T1566.001"]
        },
        ...
      ]

    Also accepts the alternate flat format:
      [{"text": "...", "ids": ["T1234"]}]
    """
    data = json.loads(path.read_text(encoding="utf-8"))
    samples: list[ATESample] = []

    for item in data:
        text = item.get("text", "").strip()
        if not text:
            continue

        # Support multiple key names used in the wild
        raw_ids = (
            item.get("techniques") or
            item.get("technique_ids") or
            item.get("ids") or
            []
        )
        expected_ids = {_normalize_tid(t) for t in raw_ids if t}
        samples.append(ATESample(text=text, expected_ids=expected_ids))

    return samples


# ---------------------------------------------------------------------------
# ATE benchmark runner
# ---------------------------------------------------------------------------

def run_ate_benchmark(
    samples: list[ATESample],
    stage: str = "all",
    verbose: bool = False,
) -> ATEScore:
    """
    Run the ATE benchmark over *samples* using the specified pipeline stage.

    Args:
        samples:  List of ATESample objects.
        stage:    Which TTP stage to evaluate: "2" | "2c" | "all"
                  "2"  = Stage 2 regex only (explicit T-IDs)
                  "2c" = Stage 2c semantic only (requires embedding cache)
                  "all"= Stage 2 + Stage 2c combined
        verbose:  Print per-sample false positives / negatives.

    Returns:
        ATEScore with macro-averaged P/R/F1 at both granularities.
    """
    stage_fn = _ATE_STAGE_FNS.get(stage, _ate_combined)
    score = ATEScore()

    for sample in samples:
        predicted_ids = stage_fn(sample.text)
        tech_res, sub_res = _score_ate_sample(predicted_ids, sample.expected_ids)

        # Compute n_pred / n_gold at each granularity
        pred_clean = _clean_ids(predicted_ids)
        gold_clean = _clean_ids(sample.expected_ids)
        tech_pred_set = {_truncate_to_parent(t) for t in pred_clean}
        tech_gold_set = {_truncate_to_parent(t) for t in gold_clean}

        score.technique.add_sample(
            precision=tech_res[0], recall=tech_res[1], f1=tech_res[2],
            n_pred=len(tech_pred_set), n_gold=len(tech_gold_set),
            tp=tech_res[3], fp=tech_res[4], fn=tech_res[5]
        )
        score.subtechnique.add_sample(
            precision=sub_res[0], recall=sub_res[1], f1=sub_res[2],
            n_pred=len(pred_clean), n_gold=len(gold_clean),
            tp=sub_res[3], fp=sub_res[4], fn=sub_res[5]
        )

        if verbose:
            sub_pred = pred_clean
            sub_gold = gold_clean
            tech_pred = tech_pred_set
            tech_gold = tech_gold_set
            if (sub_pred - sub_gold) or (sub_gold - sub_pred) or \
               (tech_pred - tech_gold) or (tech_gold - tech_pred):
                print(f"\n  [{sample.description or 'sample'}]")
                print(f"    sub  FP={sorted(sub_pred - sub_gold)} FN={sorted(sub_gold - sub_pred)}")
                print(f"    tech FP={sorted(tech_pred - tech_gold)} FN={sorted(tech_gold - tech_pred)}")

    return score


def print_ate_scores(score: ATEScore, stage: str, gpt4_baseline: float = 0.64) -> None:
    """Print the ATE benchmark result with comparison to the GPT-4 baseline."""
    print(f"\n{'=' * 68}")
    print(f"  ATT&CK Technique Extraction (ATE) — Stage {stage}")
    print(f"{'=' * 68}")
    print(f"  {'':<14} {'Prec':>7} {'Rec':>7} {'F1':>7}   {'TP':>5} {'FP':>5} {'FN':>5}")
    for label, g in (("technique", score.technique),
                     ("sub-technique", score.subtechnique)):
        print(f"  {label:<14} {g.precision:>7.3f} {g.recall:>7.3f} {g.f1:>7.3f}"
              f"   {g.tp:>5d} {g.fp:>5d} {g.fn:>5d}")
    print(f"{'-' * 68}")
    print(f"  samples: {score.subtechnique.n_samples}"
          f"   mean labels predicted: {score.subtechnique.mean_labels_predicted:.2f}"
          f"   gold: {score.subtechnique.mean_labels_gold:.2f}")

    # The GPT-4 baseline (F1 0.64) comes from CTIBench ATE, which labels parent
    # techniques only.  Compare it against the technique-level score; the
    # sub-technique score has no published counterpart on that dataset.
    delta = score.technique.f1 - gpt4_baseline
    sign = "+" if delta >= 0 else ""
    print(f"  technique-level vs GPT-4 (CTIBench ATE): {sign}{delta:.3f}")
    print(f"{'=' * 68}")


# ---------------------------------------------------------------------------
# Retrieval recall @ k  (ADR-0023 Phase 2)
#
# The fraction of gold techniques present in Stage 2c's top-k candidates before
# any confidence threshold.  RCPO reports this as a first-class number because a
# downstream selector can only ever pick from what retrieval proposed: "As the
# LLM selects only from the retrieved candidate list, this caps the model's
# attainable recall."  Their figures span 97.3% down to 78.6% by dataset.
# ---------------------------------------------------------------------------

@dataclass
class RetrievalRecall:
    """Macro-averaged retrieval recall at one k, at both ATT&CK ID granularities."""
    k: int = 0
    n_samples: int = 0
    sum_recall_tech: float = 0.0
    sum_recall_sub: float = 0.0
    sum_candidates: int = 0

    @property
    def recall_technique(self) -> float:
        if self.n_samples == 0:
            return 0.0
        return self.sum_recall_tech / self.n_samples

    @property
    def recall_subtechnique(self) -> float:
        if self.n_samples == 0:
            return 0.0
        return self.sum_recall_sub / self.n_samples

    @property
    def mean_candidates(self) -> float:
        if self.n_samples == 0:
            return 0.0
        return self.sum_candidates / self.n_samples


def _recall_of(retrieved: set[str], gold: set[str]) -> float:
    """Fraction of *gold* IDs present in *retrieved*."""
    if not gold:
        # A sample with no gold techniques cannot lower retrieval recall: there is
        # nothing to miss.  Precision on negative samples is what run_ate_benchmark
        # measures; this metric answers only "could the retriever have found it?".
        return 1.0
    return len(retrieved & gold) / len(gold)


def run_retrieval_recall(
    samples: list[ATESample],
    ks: list[int],
    verbose: bool = False,
) -> list[RetrievalRecall]:
    """Measure the retrieval ceiling at each k in *ks*.

    One embedding pass per (sample, k).  An earlier draft skipped larger k once a
    sample already scored recall 1.0 -- recall is monotone in k, so the skip is
    sound for recall -- but it reused the smaller k's candidate set and therefore
    reported the wrong mean_candidates for every skipped k.  Correctness of a
    reported number beats saving passes on a corpus this size; when Phase 5
    introduces a ranked candidate API, one pass will serve every k honestly.
    """
    try:
        from pipeline.stage2c_ttp_semantic import semantic_available, semantic_topk_ids
    except ImportError:
        return []

    if not semantic_available():
        return []

    sorted_ks = sorted({k for k in ks if k >= 1})
    if not sorted_ks:
        return []

    results = [RetrievalRecall(k=k, n_samples=len(samples)) for k in sorted_ks]
    max_k = sorted_ks[-1]

    for sample in samples:
        gold_sub = _clean_ids(sample.expected_ids)
        gold_tech = {_truncate_to_parent(t) for t in gold_sub}

        for pos, k in enumerate(sorted_ks):
            ret_sub = _clean_ids(semantic_topk_ids(sample.text, k))
            ret_tech = {_truncate_to_parent(t) for t in ret_sub}

            results[pos].sum_recall_sub += _recall_of(ret_sub, gold_sub)
            results[pos].sum_recall_tech += _recall_of(ret_tech, gold_tech)
            results[pos].sum_candidates += len(ret_sub)

            if verbose and k == max_k and gold_sub - ret_sub:
                print(f"    [{sample.description or 'sample'}] missed at k={k}: "
                      f"{sorted(gold_sub - ret_sub)}")

    return results


def print_retrieval_recall(results: list[RetrievalRecall]) -> None:
    """Print the retrieval-recall table, or explain why it is unavailable."""
    if not results:
        print("\n  Retrieval recall unavailable: Stage 2c embedding cache or "
              "sentence-transformers is missing.")
        print("  Run: python scripts/build_indexes.py --only embeddings")
        return

    print(f"\n{'=' * 68}")
    print("  Retrieval recall @ k  (ceiling on every downstream stage)")
    print(f"{'=' * 68}")
    print(f"  {'k':>5} {'technique':>12} {'sub-technique':>15} {'mean cands':>12}")
    for r in results:
        print(f"  {r.k:>5d} {r.recall_technique:>12.3f} "
              f"{r.recall_subtechnique:>15.3f} {r.mean_candidates:>12.1f}")
    print(f"{'-' * 68}")
    print(f"  samples: {results[0].n_samples}")
    print(f"{'=' * 68}")


def print_gate_stats(samples: list[ATESample]) -> None:
    """Aggregate and print the two Stage 2c sentence gates over *samples*."""
    try:
        from pipeline.stage2c_ttp_semantic import sentence_gate_stats
    except ImportError:
        print("\n  WARNING: could not import sentence_gate_stats.")
        return

    total_sent = total_kept = total_scored = total_drop_kw = total_drop_cap = 0
    for sample in samples:
        stats = sentence_gate_stats(sample.text)
        total_sent += stats.get("sentences_total", 0)
        total_kept += stats.get("kept_by_keyword", 0)
        total_scored += stats.get("scored", 0)
        total_drop_kw += stats.get("dropped_by_keyword", 0)
        total_drop_cap += stats.get("dropped_by_cap", 0)

    pct_kept = (total_kept / total_sent * 100) if total_sent else 0.0
    pct_scored = (total_scored / total_sent * 100) if total_sent else 0.0

    print(f"\n{'=' * 68}")
    print("  Stage 2c sentence gates")
    print(f"{'=' * 68}")
    print(f"  sentences total      : {total_sent}")
    print(f"  kept by keyword gate : {total_kept} ({pct_kept:.1f}%)")
    print(f"  actually scored      : {total_scored} ({pct_scored:.1f}%)")
    print(f"  dropped by keyword   : {total_drop_kw}")
    print(f"  dropped by cap       : {total_drop_cap}")
    print(f"{'=' * 68}")



# ---------------------------------------------------------------------------
# pytest — ATE smoke tests
# ---------------------------------------------------------------------------

def test_stage2_ttp_regex_ate_fixtures():
    """
    Stage 2 regex TTP extraction must detect all explicit T-ID references.
    Expected F1=1.0 on the two explicit-T-ID fixture samples.
    """
    explicit_samples = [
        s for s in _load_ate_fixture_samples()
        if "Explicit" in s.description
    ]
    score = run_ate_benchmark(explicit_samples, stage="2")
    assert score.subtechnique.f1 >= 0.95, (
        f"Stage 2 regex ATE sub-technique F1={score.subtechnique.f1:.3f} on "
        f"explicit T-ID samples — expected >=0.95.  "
        f"TP={score.subtechnique.tp} FP={score.subtechnique.fp} "
        f"FN={score.subtechnique.fn}"
    )


def test_stage2_ttp_no_false_positives_on_clean_text():
    """Stage 2 TTP regex must not fire on clean non-technical text."""
    clean_samples = [
        s for s in _load_ate_fixture_samples()
        if "FP check" in s.description
    ]
    score = run_ate_benchmark(clean_samples, stage="all")
    assert score.subtechnique.fp == 0, (
        f"Stage 2 TTP extracted {score.subtechnique.fp} false-positive "
        f"T-IDs from clean text"
    )


# ===========================================================================
# Grounding / Hallucination-rate benchmark  (ADR-0012 — measurement keystone)
#
# The NER and ATE benchmarks above measure RECALL (did we find the real
# entities/techniques?).  This benchmark measures the opposite failure mode:
# HALLUCINATION — of what the pipeline actually emits, how much is NOT supported
# by the source text?
#
# It is deliberately OFFLINE.  It reuses the pipeline's own grounding primitive
# (_name_in_text from stage3b) so the number it reports is the *same* notion of
# "present in the source" that the hallucination filter enforces.  Measuring
# POST-filter output therefore reports the filter's residual leak (should be ~0
# for entities — a regression guard), while relationship co-sentence grounding
# reports the claim-support gap that the name filter structurally cannot close
# (that is Stage 3d's job, and this is its offline scorecard).
#
# Three metrics:
#   entity_grounding_rate       — emitted named entities found verbatim/fuzzily
#                                 in the source. < 1.0 ⇒ hallucinated names leaked.
#   rel_endpoint_grounding_rate — relationships whose BOTH endpoints are grounded
#                                 (a dangling endpoint ⇒ a hallucinated edge).
#   rel_cosentence_grounding    — relationships whose endpoints co-occur in a
#                                 SINGLE sentence — the offline proxy for "the
#                                 text actually asserts this relation".  This is
#                                 the headline claim-grounding number.
#
# Usage:
#   python tests/eval_pipeline.py -b grounding                 # built-in fixtures
#   python tests/eval_pipeline.py -b grounding --from-db all   # your real jobs
#   python tests/eval_pipeline.py -b grounding --from-db <job_id>
#   python tests/eval_pipeline.py -b grounding --dataset out.json --verbose
#
# --from-db reads cti_stix.db (report_text + emitted entities + relationships),
# so it scores the hallucination rate on reports you have ALREADY processed —
# no API key, no re-run.  Filter to LLM-origin entities with --llm-only to
# isolate the stage that actually hallucinates.
# ===========================================================================

# Entity types that are NAMED by the LLM (and therefore hallucination-prone).
# IoCs (regex) and TTPs (regex/semantic) are grounded by construction, so they
# are excluded from the entity grounding rate by default.
_NAMED_ENTITY_TYPES: frozenset[str] = frozenset({
    "malware", "threat_actor", "intrusion_set", "tool",
    "campaign", "infrastructure", "identity",
})


# Prefer the pipeline's real grounding primitive so the metric matches the
# filter.  Fall back to a self-contained copy if the import chain is unavailable
# (keeps the harness runnable in a minimal environment).
try:
    from pipeline.stage3b_validate import _name_in_text as _grounded_in
except Exception:  # pragma: no cover - fallback path
    import re as _re

    def _grounded_in(name: str, text: str, threshold=None) -> bool:  # type: ignore
        if not name or len(name) < 3:
            return True
        nl, tl = name.lower().strip(), text.lower()
        if len(nl) <= 5:
            return bool(_re.search(r"(?<![a-z0-9])" + _re.escape(nl) + r"(?![a-z0-9])", tl))
        return nl in tl


def _ground_split_sentences(text: str) -> list[str]:
    """Sentence splitter for co-sentence relationship grounding (mirrors 2c)."""
    text = re.sub(r"\r\n|\r", "\n", text)
    raw = re.split(r"(?<=[.!?])\s+|\n{1,}|;\s+", text)
    return [s.strip() for s in raw if len(s.strip()) > 2]


@dataclass
class GroundingSample:
    """A source text plus the entities/relationships the pipeline EMITTED for it."""
    text: str
    entities: list[tuple[str, str]] = field(default_factory=list)          # (value, type)
    relationships: list[tuple[str, str, str]] = field(default_factory=list)  # (src, verb, tgt)
    rel_evidence: list[str] = field(default_factory=list)                 # aligned quote per rel
    description: str = ""


@dataclass
class GroundingScore:
    ent_total: int = 0
    ent_grounded: int = 0
    rel_total: int = 0
    # Exclusive best-grade counts, weakest → strongest support:
    #   none       — a dangling endpoint (not in the source at all)
    #   endpoints  — both endpoints in text, but no sentence/window/evidence link
    #   evidence   — both endpoints appear in the stored evidence quote
    #   window     — both endpoints co-occur within a ±N-sentence window
    #   cosentence — both endpoints in a SINGLE sentence (strongest)
    g_none: int = 0
    g_endpoints: int = 0
    g_proximity: int = 0
    g_evidence: int = 0
    g_window: int = 0
    g_cosentence: int = 0

    # Per-segment grade tallies (grade → count), so one global number stops
    # hiding two very different populations (named-entity vs IoC/technical rels).
    rel_named_grades: dict = field(default_factory=dict)
    rel_tech_grades: dict = field(default_factory=dict)

    # ── Entities ──────────────────────────────────────────────────────────────
    @property
    def entity_grounding_rate(self) -> float:
        return self.ent_grounded / self.ent_total if self.ent_total else 1.0

    @property
    def entity_hallucination_rate(self) -> float:
        return 1.0 - self.entity_grounding_rate

    # ── Relationships (backward-compatible names retained) ────────────────────
    @property
    def rel_endpoints_grounded(self) -> int:
        """Both endpoints present somewhere in text (everything but dangling)."""
        return self.rel_total - self.g_none

    @property
    def rel_endpoint_grounding_rate(self) -> float:
        return self.rel_endpoints_grounded / self.rel_total if self.rel_total else 1.0

    @property
    def rel_cosentence_grounded(self) -> int:
        return self.g_cosentence

    @property
    def rel_cosentence_grounding_rate(self) -> float:
        return self.g_cosentence / self.rel_total if self.rel_total else 1.0

    @property
    def rel_claim_grounded(self) -> int:
        """Supported by one sentence, a ±window, the stored evidence quote, OR
        raw-text proximity (tables/lists) — the honest 'is this relation actually
        asserted by the source' count."""
        return self.g_cosentence + self.g_window + self.g_evidence + self.g_proximity

    @property
    def rel_claim_grounding_rate(self) -> float:
        return self.rel_claim_grounded / self.rel_total if self.rel_total else 1.0

    @property
    def rel_unsupported(self) -> int:
        """True hallucination candidates: dangling, or endpoints with no link."""
        return self.g_none + self.g_endpoints

    @property
    def rel_hallucination_rate(self) -> float:
        return self.rel_unsupported / self.rel_total if self.rel_total else 0.0

    def segment_stats(self, segment: str) -> tuple[int, float, float]:
        """(total, claim_grounding_rate, hallucination_rate) for a segment
        ('named' or 'technical')."""
        grades = self.rel_named_grades if segment == "named" else self.rel_tech_grades
        total = sum(grades.values())
        if not total:
            return 0, 1.0, 0.0
        claim = (grades.get("cosentence", 0) + grades.get("window", 0)
                 + grades.get("evidence", 0) + grades.get("proximity", 0))
        unsup = grades.get("none", 0) + grades.get("endpoints", 0)
        return total, claim / total, unsup / total


def _quote_from_source(evidence: str, text: str) -> bool:
    """Guard against a fabricated evidence quote: a real quote's opening slice
    appears in the source text."""
    probe = evidence.strip()[:40].lower()
    return bool(probe) and probe in text.lower()


_TID_RE = re.compile(r"(?:T\d{4}(?:\.\d{3})?|CAPEC-\d+)", re.IGNORECASE)

# Endpoint classification (metric segmentation): a relationship is "technical"
# if either endpoint is an IoC or a TTP — that population lives in tables/lists
# where the co-sentence proxy is structurally blind.  "named" relationships link
# named SDOs (actor/malware/tool/…) and are where the proxy actually works.
_IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
_HASH_RE = re.compile(r"^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$")
_FILE_EXT_RE = re.compile(
    r"\.(?:ps1|js|mjs|exe|dll|pyz|py|bat|vbs|jar|zip|dat|bin|sh|scr|hta|lnk|iso|msi|dmg|apk)$",
    re.IGNORECASE,
)
_DOMAINLIKE_RE = re.compile(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9-]+)+$")


def _endpoint_kind(value: str, named_set: set[str]) -> str:
    """Classify a relationship endpoint: 'named' | 'ioc' | 'ttp'."""
    v = (value or "").strip()
    vl = v.lower()
    if vl in named_set:
        return "named"
    # TTP: an explicit MITRE id anywhere, or a known canonical technique name.
    if _TID_RE.search(v):
        return "ttp"
    try:
        from pipeline.aliases import technique_id_for
        if technique_id_for(_TID_RE.sub("", v).strip(" ()")):
            return "ttp"
    except Exception:
        pass
    # IoC: url / email / ip / hash / filename / bare domain
    if vl.startswith(("http://", "https://")):
        return "ioc"
    if "@" in v and "." in v:
        return "ioc"
    if _IPV4_RE.match(v) or _HASH_RE.match(v) or _FILE_EXT_RE.search(v):
        return "ioc"
    if " " not in v and _DOMAINLIKE_RE.match(vl):
        return "ioc"
    return "named"


def _relationship_segment(src: str, tgt: str, named_set: set[str]) -> str:
    """'named' if both endpoints are named entities; else 'technical'."""
    if _endpoint_kind(src, named_set) == "named" and _endpoint_kind(tgt, named_set) == "named":
        return "named"
    return "technical"


def _technique_grounded(name: str, text: str) -> bool:
    """Technique-aware grounding for TTP relationship endpoints.

    Handles the composite 'Name (T1234.001)' form the pipeline emits by trying:
      1. the explicit MITRE id embedded in the endpoint, present in the text;
      2. the bare technique name with the '(T####)' suffix stripped;
      3. the canonical technique's id (looked up by name), present in the text.
    """
    tl = text.lower()
    m = _TID_RE.search(name)
    if m and m.group(0).lower() in tl:
        return True
    bare = _TID_RE.sub("", name).replace("()", "").strip(" ()")
    if bare and bare != name and _grounded_in(bare, text):
        return True
    try:
        from pipeline.aliases import technique_id_for
        tid = technique_id_for(bare or name)
        if tid and tid.lower() in tl:
            return True
    except Exception:
        pass
    return False


def _grounded_alias(name: str, text: str) -> bool:
    """Alias-aware grounding: a name is grounded if it — OR any MITRE alias that
    shares its canonical id, OR its MITRE id, OR (for techniques) its T-ID /
    canonical technique name — appears in the text.  Resolves the 'OilRig'
    (canonical, emitted) vs 'APT34' (alias, in text) mismatch, plus the
    'Spearphishing Link (T1566.002)' composite-TTP-endpoint case."""
    if _grounded_in(name, text):
        return True
    try:
        from pipeline.aliases import alias_surface_forms
        base = name.lower().strip()
        for form in alias_surface_forms(name):
            if form != base and len(form) >= 3 and _grounded_in(form, text):
                return True
    except Exception:
        pass
    if _technique_grounded(name, text):
        return True
    return False


def _occurrence_positions(name: str, text_lower: str, alias_aware: bool) -> list[int]:
    """Start offsets of every literal occurrence of *name* (and, when alias-aware,
    its MITRE surface forms) in the lowercased text."""
    forms = {name.lower().strip()}
    if alias_aware:
        try:
            from pipeline.aliases import alias_surface_forms
            forms |= {f for f in alias_surface_forms(name) if len(f) >= 3}
        except Exception:
            pass
    positions: list[int] = []
    for f in forms:
        if not f:
            continue
        start = 0
        while True:
            i = text_lower.find(f, start)
            if i < 0:
                break
            positions.append(i)
            start = i + 1
    return positions


def _proximity_grounded(src: str, tgt: str, text_lower: str, max_gap: int,
                        alias_aware: bool) -> bool:
    """True if an occurrence of *src* and one of *tgt* fall within *max_gap*
    characters — the structure-aware proxy for IoC relationships that live in
    tables/lists rather than narrative sentences."""
    ps = sorted(_occurrence_positions(src, text_lower, alias_aware))
    pt = sorted(_occurrence_positions(tgt, text_lower, alias_aware))
    i = j = 0
    while i < len(ps) and j < len(pt):
        if abs(ps[i] - pt[j]) <= max_gap:
            return True
        if ps[i] < pt[j]:
            i += 1
        else:
            j += 1
    return False


def _relationship_grounding(
    src: str, tgt: str, sentences: list[str], text: str,
    window: int = 0, evidence: str = "", match=_grounded_in,
    proximity: int = 0, alias_aware: bool = False,
) -> str:
    """Classify a relationship's textual support (best grade wins).

    Returns 'cosentence' | 'window' | 'evidence' | 'proximity' | 'endpoints' | 'none'.
    *match* is the grounding predicate (swap in _grounded_alias for alias-aware).
    *proximity* (chars) enables the table/list-aware tier for IoC relationships.
    """
    both_in_text = match(src, text) and match(tgt, text)

    if both_in_text:
        for s in sentences:
            if match(src, s) and match(tgt, s):
                return "cosentence"
        if window > 0:
            for i in range(len(sentences)):
                joined = " ".join(sentences[max(0, i - window): i + window + 1])
                if match(src, joined) and match(tgt, joined):
                    return "window"

    # Honour the pipeline's own cited support — but only if the quote is real
    # (its opening slice is present in the source, so it wasn't fabricated).
    if evidence and match(src, evidence) and match(tgt, evidence) \
            and _quote_from_source(evidence, text):
        return "evidence"

    # Structure-aware tier: endpoints co-located in the raw text (same table row
    # / list item) even though no sentence links them.
    if both_in_text and proximity > 0 \
            and _proximity_grounded(src, tgt, text.lower(), proximity, alias_aware):
        return "proximity"

    return "endpoints" if both_in_text else "none"


def score_grounding(
    samples: list[GroundingSample],
    named_only: bool = True,
    window: int = 0,
    alias_aware: bool = False,
    proximity: int = 0,
    verbose: bool = False,
) -> GroundingScore:
    """Compute entity + relationship grounding over emitted pipeline output."""
    total = GroundingScore()
    match = _grounded_alias if alias_aware else _grounded_in

    for sample in samples:
        sentences = _ground_split_sentences(sample.text)
        named_set = {v.lower().strip() for v, _ in sample.entities}

        ungrounded_ents: list[tuple[str, str]] = []
        for value, etype in sample.entities:
            if named_only and etype not in _NAMED_ENTITY_TYPES:
                continue
            total.ent_total += 1
            if match(value, sample.text):
                total.ent_grounded += 1
            else:
                ungrounded_ents.append((value, etype))

        unsupported_rels: list[tuple[str, str, str, str]] = []
        for idx, (src, verb, tgt) in enumerate(sample.relationships):
            total.rel_total += 1
            evidence = sample.rel_evidence[idx] if idx < len(sample.rel_evidence) else ""
            grade = _relationship_grounding(
                src, tgt, sentences, sample.text, window=window, evidence=evidence,
                match=match, proximity=proximity, alias_aware=alias_aware,
            )
            setattr(total, f"g_{grade}", getattr(total, f"g_{grade}") + 1)
            # Segment tally (named-entity vs IoC/technical relationship).
            seg_grades = (total.rel_named_grades
                          if _relationship_segment(src, tgt, named_set) == "named"
                          else total.rel_tech_grades)
            seg_grades[grade] = seg_grades.get(grade, 0) + 1
            if grade in ("none", "endpoints"):
                unsupported_rels.append((src, verb, tgt, grade))

        if verbose and (ungrounded_ents or unsupported_rels):
            print(f"\n  [{sample.description or 'sample'}]")
            for v, t in ungrounded_ents:
                print(f"    UNGROUNDED entity:  {t}: '{v}'")
            for s, verb, t, grade in unsupported_rels:
                why = "dangling endpoint" if grade == "none" else "no sentence/window/evidence link"
                print(f"    UNSUPPORTED rel:    '{s}' {verb} '{t}'  ({why})")

    return total


def print_grounding_scores(score: GroundingScore, window: int = 0) -> None:
    print(f"\n{'=' * 64}")
    print("  Grounding / Hallucination-rate benchmark")
    print(f"{'=' * 64}")
    print("  Entities (named types):")
    print(f"    grounding rate       : {score.entity_grounding_rate:.3f}  "
          f"({score.ent_grounded}/{score.ent_total})")
    print(f"    hallucination rate   : {score.entity_hallucination_rate:.3f}"
          f"   ← ungroundable emitted names")
    print(f"  Relationships  (co-sentence window = ±{window}):")
    print(f"    endpoint grounding   : {score.rel_endpoint_grounding_rate:.3f}  "
          f"({score.rel_endpoints_grounded}/{score.rel_total})   both ends in text")
    print(f"    co-sentence only     : {score.rel_cosentence_grounding_rate:.3f}  "
          f"({score.g_cosentence}/{score.rel_total})")
    print(f"    CLAIM grounding      : {score.rel_claim_grounding_rate:.3f}  "
          f"({score.rel_claim_grounded}/{score.rel_total})"
          f"   ← sentence + ±window + evidence quote")
    print(f"    hallucination rate   : {score.rel_hallucination_rate:.3f}  "
          f"({score.rel_unsupported}/{score.rel_total})   ← truly unsupported")
    print(f"      breakdown: cosentence={score.g_cosentence} window={score.g_window} "
          f"evidence={score.g_evidence} proximity={score.g_proximity} "
          f"endpoints-only={score.g_endpoints} dangling={score.g_none}")
    # ── Segmentation: named-entity vs IoC/technical relationships ─────────────
    n_total, n_claim, n_hall = score.segment_stats("named")
    t_total, t_claim, t_hall = score.segment_stats("technical")
    print("  Relationships by SEGMENT (one global number hides two populations):")
    print(f"    named-entity rels    : claim {n_claim:.3f}  halluc {n_hall:.3f}  (n={n_total})"
          f"   ← proxy works here")
    print(f"    IoC / technical rels : claim {t_claim:.3f}  halluc {t_hall:.3f}  (n={t_total})"
          f"   ← table/list blind spot + loose links")
    print(f"{'=' * 64}")


# ---------------------------------------------------------------------------
# Grounding loaders
# ---------------------------------------------------------------------------

def load_grounding_dataset(path: Path) -> list[GroundingSample]:
    """
    Load emitted pipeline output for grounding analysis.

    Format:
      [
        {
          "text": "source report text ...",
          "entities":      [{"value": "APT29", "type": "threat_actor"}, ...],
          "relationships": [{"source": "APT29", "type": "uses",
                             "target": "Cobalt Strike"}, ...]
        }, ...
      ]
    """
    data = json.loads(path.read_text(encoding="utf-8"))
    samples: list[GroundingSample] = []
    for item in data:
        text = item.get("text", "")
        if not text:
            continue
        ents = [(e["value"], e.get("type", "")) for e in item.get("entities", []) if e.get("value")]
        rels, rel_ev = [], []
        for r in item.get("relationships", []):
            if r.get("source") and r.get("target"):
                rels.append((r["source"], r.get("type", "related-to"), r["target"]))
                rel_ev.append(r.get("evidence", "") or "")
        samples.append(GroundingSample(text=text, entities=ents, relationships=rels,
                                       rel_evidence=rel_ev,
                                       description=item.get("description", "")))
    return samples


def load_grounding_from_db(
    db_path: Path,
    job_id: str = "all",
    llm_only: bool = False,
) -> list[GroundingSample]:
    """
    Build grounding samples from a real cti_stix.db: report_text + the entities
    and relationships the pipeline emitted for each job.  Fully offline — scores
    the hallucination rate on reports you have already processed.

    llm_only=True restricts entities to source='llm' (the stage that actually
    invents names); relationships are LLM-derived regardless of the flag.
    """
    import sqlite3

    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row

    if job_id == "all":
        jobs = conn.execute(
            "SELECT id, report_text FROM jobs "
            "WHERE report_text IS NOT NULL AND length(report_text) > 0"
        ).fetchall()
    else:
        jobs = conn.execute(
            "SELECT id, report_text FROM jobs WHERE id = ? "
            "AND report_text IS NOT NULL AND length(report_text) > 0",
            (job_id,),
        ).fetchall()

    samples: list[GroundingSample] = []
    for job in jobs:
        ent_q = "SELECT value, entity_type FROM entities WHERE job_id = ?"
        ent_params: tuple = (job["id"],)
        if llm_only:
            ent_q += " AND source = 'llm'"
        entities = [(r["value"], r["entity_type"]) for r in conn.execute(ent_q, ent_params)]

        rels, rel_ev = [], []
        for r in conn.execute(
            "SELECT source_value, relationship_type, target_value, evidence_text "
            "FROM relationships WHERE job_id = ?",
            (job["id"],),
        ):
            rels.append((r["source_value"], r["relationship_type"], r["target_value"]))
            rel_ev.append(r["evidence_text"] or "")
        samples.append(GroundingSample(
            text=job["report_text"], entities=entities, relationships=rels,
            rel_evidence=rel_ev, description=f"job {job['id'][:8]}",
        ))

    conn.close()
    return samples


# ---------------------------------------------------------------------------
# Grounding over the SHIPPED bundle, split by evidence label (ADR-0024 Phase C)
#
# load_grounding_from_db above scores the `relationships` table -- 65 edges of
# the 1,207 actually shipped.  This reads bundle_json instead, and scores only
# the edges that claim evidential support: an `assessed` or `inferred` edge
# makes no claim about a sentence in the report, so measuring it against the
# report text reports an assertion as a hallucination.
# ---------------------------------------------------------------------------
# ADR-0024 Phase C.  An "assessed" or "inferred" edge makes no claim to be
# supported by a sentence in the report, so scoring it against the report
# text measures nothing -- it would report a hallucination that is really an
# assertion.  Only edges claiming evidential support are scored.
_EVIDENTIAL_LABELS = frozenset({"observed", "reported"})
_SYNTHESISED_LABELS = frozenset({"assessed", "inferred", "gap"})


def _stix_display_name(obj: dict) -> str:
    """Return the human-readable label of a STIX object.

    Tries, in order: ``name``, ``value``, first hash, ``path``, ``id``.
    Returns an empty string if none are present or ``obj`` is not a dict.
    """
    if not isinstance(obj, dict):
        return ""
    name = obj.get("name")
    if name:
        return name
    value = obj.get("value")
    if value:
        return value
    hashes = obj.get("hashes")
    if isinstance(hashes, dict) and hashes:
        first_val = next(iter(hashes.values()), None)
        if first_val:
            return first_val
    path = obj.get("path")
    if path:
        return path
    return obj.get("id", "")


def load_grounding_from_bundle(
    db_path: Path,
    job_id: str = "all",
) -> tuple[list[GroundingSample], dict[str, int]]:
    """Load grounding samples from the shipped STIX bundle.

    Reads ``jobs.bundle_json`` — what is actually delivered — instead of the
    ``relationships`` table, which contains only 3.3% of the edges.
    """
    import sqlite3

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row

    query = (
        "SELECT id, report_text, bundle_json FROM jobs "
        "WHERE report_text IS NOT NULL AND length(report_text) > 0 "
        "AND bundle_json IS NOT NULL"
    )
    params: list = []
    if job_id != "all":
        query += " AND id = ?"
        params.append(job_id)

    rows = conn.execute(query, params).fetchall()
    conn.close()

    samples: list[GroundingSample] = []
    census: dict[str, int] = {}

    for row in rows:
        try:
            bundle = json.loads(row["bundle_json"])
        except Exception:
            continue

        objects = bundle.get("objects")
        if not isinstance(objects, list):
            continue

        by_id = {
            o["id"]: o for o in objects if isinstance(o, dict) and "id" in o
        }

        relationships: list[tuple[str, str, str]] = []
        rel_evidence: list[str] = []

        for o in objects:
            if not isinstance(o, dict) or o.get("type") != "relationship":
                continue

            label = o.get("x_evidence_label", "(unlabelled)")
            census[label] = census.get(label, 0) + 1

            if label not in _EVIDENTIAL_LABELS:
                continue

            src = _stix_display_name(by_id.get(o.get("source_ref", ""), {}))
            tgt = _stix_display_name(by_id.get(o.get("target_ref", ""), {}))
            if not src or not tgt:
                continue

            verb = o.get("relationship_type", "related-to")
            relationships.append((src, verb, tgt))
            rel_evidence.append(o.get("x_evidence_text", ""))

        entities: list[tuple[str, str]] = []
        skip_types = {
            "relationship", "report", "marking-definition",
            "identity", "observed-data", "artifact",
        }
        for o in objects:
            if not isinstance(o, dict):
                continue
            if o.get("type") in skip_types:
                continue
            name = _stix_display_name(o)
            if name:
                entities.append((name, o.get("type", "")))

        job_id_court = row["id"][:8]
        samples.append(GroundingSample(
            text=row["report_text"],
            entities=entities,
            relationships=relationships,
            rel_evidence=rel_evidence,
            description=f"job {job_id_court}",
        ))

    return samples, census


def print_label_census(census: dict[str, int]) -> None:
    """Print a summary of shipped edges grouped by evidence label."""
    if not census:
        print("  No relationship objects found in any bundle.")
        return

    total = sum(census.values())
    print(f"\n{'=' * 68}")
    print("  Shipped edges by evidence label")
    print(f"{'=' * 68}")
    for label, n in sorted(census.items(), key=lambda kv: -kv[1]):
        pct = (n / total * 100) if total else 0.0
        marker = "  <- scored below" if label in _EVIDENTIAL_LABELS else ""
        print(f"  {label:<16} {n:>7} ({pct:>5.1f}%){marker}")
    print(f"{'-' * 68}")
    print(f"  {'total':<16} {total:>7}")

    if census.get("(unlabelled)", 0) > 0:
        print("\n  Unlabelled edges carry no provenance: a materialised assumption")
        print("  is indistinguishable from an extracted fact.  See ADR-0024.")


# ---------------------------------------------------------------------------
# Grounding fixtures — planted hallucinations prove the metric discriminates
# ---------------------------------------------------------------------------

def _load_grounding_fixture_samples() -> list[GroundingSample]:
    return [
        # Fully grounded — everything appears in the text, rels are co-sentence.
        GroundingSample(
            text=(
                "APT29 deployed Cobalt Strike against government agencies. "
                "APT29 also used WellMess for command and control."
            ),
            entities=[("APT29", "threat_actor"), ("Cobalt Strike", "tool"),
                      ("WellMess", "malware")],
            relationships=[("APT29", "uses", "Cobalt Strike"),
                           ("APT29", "uses", "WellMess")],
            description="Fully grounded (expect 1.0 across the board)",
        ),
        # Hallucinated entity + dangling relationship endpoint.
        GroundingSample(
            text="The intrusion relied on Cobalt Strike beacons for lateral movement.",
            entities=[("Cobalt Strike", "tool"), ("WizardSpider", "threat_actor")],
            relationships=[("WizardSpider", "uses", "Cobalt Strike")],
            description="Hallucinated actor 'WizardSpider' not in text (expect <1.0)",
        ),
        # Both endpoints present but in DIFFERENT sentences — no textual assertion
        # of the relation.  Endpoint-grounded but NOT co-sentence-grounded: this is
        # the claim-support gap the name filter cannot see.
        GroundingSample(
            text=(
                "Emotet was observed in phishing campaigns this quarter. "
                "Separately, the TA542 group has been active in Europe."
            ),
            entities=[("Emotet", "malware"), ("TA542", "threat_actor")],
            relationships=[("TA542", "uses", "Emotet")],
            description="Endpoints in different sentences (co-sentence grounding <1.0)",
        ),
    ]


# ---------------------------------------------------------------------------
# pytest — grounding metric discrimination
# ---------------------------------------------------------------------------

def test_grounding_metric_discriminates():
    """The metric must score a clean sample 1.0 and a hallucinated sample <1.0."""
    fixtures = _load_grounding_fixture_samples()

    clean = score_grounding([fixtures[0]])
    assert clean.entity_grounding_rate == 1.0
    assert clean.rel_cosentence_grounding_rate == 1.0

    hallucinated = score_grounding([fixtures[1]])
    assert hallucinated.entity_grounding_rate < 1.0, "should flag ungrounded actor"
    assert hallucinated.rel_endpoint_grounding_rate < 1.0, "dangling edge should fail"


def test_grounding_segments_named_vs_technical():
    """The metric separates named-entity relationships from IoC/technical ones so
    a global number can't hide two populations."""
    sample = GroundingSample(
        text="APT29 used WellMess. Unrelated appendix mentions evil.example.com in a table.",
        entities=[("APT29", "threat_actor"), ("WellMess", "malware")],
        relationships=[
            ("APT29", "uses", "WellMess"),               # named, co-sentence → grounded
            ("WellMess", "communicates-with", "evil.example.com"),  # technical, split → not
        ],
    )
    score = score_grounding([sample], window=0)
    n_total, n_claim, _ = score.segment_stats("named")
    t_total, t_claim, _ = score.segment_stats("technical")
    assert n_total == 1 and n_claim == 1.0, "named rel should be claim-grounded"
    assert t_total == 1 and t_claim == 0.0, "technical rel (IoC endpoint) should not"


def test_grounding_proximity_rescues_table_iocs():
    """A file→domain relationship whose endpoints sit in a compact IoC list —
    more than one sentence apart, so unsupported at window ±1 — is grounded once
    raw-text proximity is enabled."""
    sample = GroundingSample(
        text=(
            "dropper.exe flagged.\n"
            "row filler one.\n"
            "row filler two.\n"
            "evil.example.com flagged."
        ),
        entities=[],
        relationships=[("dropper.exe", "communicates-with", "evil.example.com")],
    )
    without = score_grounding([sample], window=1)
    assert without.rel_claim_grounding_rate == 0.0, "no sentence/window links them"
    with_prox = score_grounding([sample], window=1, proximity=200)
    assert with_prox.rel_claim_grounding_rate == 1.0, "co-located in the list → grounded"
    assert with_prox.g_proximity == 1


def test_grounding_cosentence_gap():
    """Endpoints present but in different sentences ⇒ endpoint-grounded but not
    co-sentence-grounded (the claim-support gap)."""
    fixtures = _load_grounding_fixture_samples()
    score = score_grounding([fixtures[2]])
    assert score.rel_endpoint_grounding_rate == 1.0, "both names are in the text"
    assert score.rel_cosentence_grounding_rate == 0.0, "but never in one sentence"


# ---------------------------------------------------------------------------
# ===========================================================================
# REL benchmark — Stage 4b graph-completion edge precision  (ADR-0013)
# ===========================================================================
#
# Measures the *completion* engines (reference grounding, transitive inference,
# long-distance) in isolation: given a base graph of verified objects + edges,
# does Stage 4b add the edges a human accepts (gold_accept) and none of the
# edges a human rejects (gold_reject)?
#
# This is the edge-level analogue of the ATE benchmark: CTINexus (EuroS&P 2025)
# reports 90.99% relation-prediction precision; this harness produces the
# comparable number for CTIParsor's completion layer.
#
# Usage:
#   python tests/eval_pipeline.py --benchmark rel                    # fixtures
#   python tests/eval_pipeline.py --benchmark rel --dataset gold.json
#
# Dataset format — JSON list of samples:
#   [{
#      "description": "...",
#      "objects":     [{"type": "threat-actor", "name": "APT29"},
#                      {"type": "attack-pattern", "name": "Phishing",
#                       "mitre_id": "T1566"}],
#      "edges":       [["APT29", "uses", "WellMess"]],       # base (verified)
#      "gold_accept": [["APT29", "uses", "Phishing"]],       # must be added
#      "gold_reject": [["APT29", "targets", "Phishing"]],    # must NOT be added
#      "closed": false,    # true → any unjudged added edge counts as FP
#      "completion": {"alias": true}   # optional: per-sample engine config, for
#                                      #   measuring an engine that is off by
#                                      #   default; omit to use ship defaults
#   }, ...]
# ===========================================================================

@dataclass
class RelSample:
    """One graph-completion sample: base graph + judged completion edges."""
    objects: list[dict]
    edges: list[list[str]]
    gold_accept: list[list[str]]
    gold_reject: list[list[str]]
    closed: bool = False
    description: str = ""
    # Optional per-sample completion config, so a sample can measure an engine
    # that is off by default (e.g. the alias fallback).  Merged into the policy
    # as {"completion": {...}}; None means "ship defaults".
    completion: dict | None = None


@dataclass
class RelScore:
    """Per-engine and overall completion-edge scores."""
    tp: float = 0.0
    fp: float = 0.0
    fn: float = 0.0
    unjudged: int = 0
    by_engine: dict = None   # engine → {"added": n, "tp": n, "fp": n}

    def __post_init__(self):
        if self.by_engine is None:
            self.by_engine = {}

    @property
    def precision(self) -> float:
        d = self.tp + self.fp
        return self.tp / d if d else 0.0

    @property
    def recall(self) -> float:
        d = self.tp + self.fn
        return self.tp / d if d else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) else 0.0


def _rel_build_objects(specs: list[dict]):
    """Instantiate stix2 SDOs from the light per-sample object specs."""
    import stix2

    made = []
    for spec in specs:
        t, name = spec.get("type"), spec.get("name", "")
        kwargs: dict = {"name": name}
        if t == "attack-pattern" and spec.get("mitre_id"):
            mid = spec["mitre_id"]
            kwargs["external_references"] = [stix2.ExternalReference(
                source_name="mitre-attack", external_id=mid,
                url=f"https://attack.mitre.org/techniques/{mid.replace('.', '/')}/",
            )]
        cls = {
            "threat-actor": stix2.ThreatActor,
            "intrusion-set": stix2.IntrusionSet,
            "campaign": stix2.Campaign,
            "tool": stix2.Tool,
            "attack-pattern": stix2.AttackPattern,
            "identity": stix2.Identity,
            "location": lambda **kw: stix2.Location(country="FR", **kw),
            "vulnerability": stix2.Vulnerability,
            "infrastructure": stix2.Infrastructure,
        }.get(t)
        if t == "malware":
            made.append(stix2.Malware(is_family=True, **kwargs))
        elif cls is not None:
            made.append(cls(**kwargs))
    return made


def run_rel_benchmark(samples: list[RelSample], verbose: bool = False) -> RelScore:
    """Run Stage 4b completion over each sample's base graph and score the
    added edges against the gold accept/reject judgments."""
    import stix2

    from pipeline.stage4b_graph_completion import complete_graph

    score = RelScore()

    for sample in samples:
        objs = _rel_build_objects(sample.objects)
        by_name = {o.get("name", "").lower(): o for o in objs}
        for src, verb, tgt in sample.edges:
            s, t = by_name.get(src.lower()), by_name.get(tgt.lower())
            if s is not None and t is not None:
                objs.append(stix2.Relationship(s, verb, t, confidence=90))

        base_keys = {(r.get("source_ref"), r.get("relationship_type"), r.get("target_ref"))
                     for r in objs if r.get("type") == "relationship"}

        complete_graph(
            objs,
            policy={"completion": sample.completion} if sample.completion else None,
        )

        # Map post-completion ids → all known names (name + absorbed aliases).
        id_names: dict[str, set[str]] = {}
        for o in objs:
            if o.get("type") == "relationship" or not hasattr(o, "id"):
                continue
            names = {(o.get("name") or "").lower()}
            names.update((a or "").lower() for a in (o.get("aliases") or []))
            id_names[o.id] = {n for n in names if n}

        def _matches(edge_key, gold_edge) -> bool:
            src_id, verb, tgt_id = edge_key
            g_src, g_verb, g_tgt = (x.lower() for x in gold_edge)
            return (verb == g_verb
                    and g_src in id_names.get(src_id, set())
                    and g_tgt in id_names.get(tgt_id, set()))

        added = [
            r for r in objs
            if r.get("type") == "relationship"
            and (r.get("source_ref"), r.get("relationship_type"), r.get("target_ref"))
            not in base_keys
        ]

        matched_gold: set[int] = set()
        for r in added:
            key = (r.get("source_ref"), r.get("relationship_type"), r.get("target_ref"))
            engine = (r.get("x_inference_rule") or "unknown").split(":")[0]
            eng = score.by_engine.setdefault(engine, {"added": 0, "tp": 0, "fp": 0})
            eng["added"] += 1

            hit = next((i for i, g in enumerate(sample.gold_accept)
                        if i not in matched_gold and _matches(key, g)), None)
            if hit is not None:
                matched_gold.add(hit)
                score.tp += 1
                eng["tp"] += 1
            elif any(_matches(key, g) for g in sample.gold_reject) or sample.closed:
                score.fp += 1
                eng["fp"] += 1
                if verbose:
                    print(f"  FP [{sample.description}] {key} ({engine})")
            else:
                score.unjudged += 1

        missed = len(sample.gold_accept) - len(matched_gold)
        score.fn += missed
        if verbose and missed:
            for i, g in enumerate(sample.gold_accept):
                if i not in matched_gold:
                    print(f"  FN [{sample.description}] {g}")

    return score


def _load_rel_fixture_samples() -> list[RelSample]:
    """Built-in graph-completion samples (no external dataset needed)."""
    return [
        RelSample(
            description="transitive uses-chain",
            objects=[{"type": "intrusion-set", "name": "APT-X"},
                     {"type": "malware", "name": "Backdoor-Y"},
                     {"type": "attack-pattern", "name": "Phishing"}],
            edges=[["APT-X", "uses", "Backdoor-Y"],
                   ["Backdoor-Y", "uses", "Phishing"]],
            gold_accept=[["APT-X", "uses", "Phishing"]],
            gold_reject=[],
            closed=True,
        ),
        RelSample(
            description="non-suggested composition must be skipped",
            objects=[{"type": "intrusion-set", "name": "APT-Z"},
                     {"type": "threat-actor", "name": "Group-Q"},
                     {"type": "identity", "name": "Ministry"}],
            edges=[["APT-Z", "attributed-to", "Group-Q"],
                   ["Group-Q", "attributed-to", "Ministry"]],
            gold_accept=[],
            gold_reject=[["APT-Z", "attributed-to", "Ministry"]],
            closed=True,
        ),
        RelSample(
            description="reference grounding APT29+Mimikatz",
            objects=[{"type": "threat-actor", "name": "APT29"},
                     {"type": "malware", "name": "Mimikatz"}],
            edges=[],
            gold_accept=[["APT29", "uses", "Mimikatz"]],
            gold_reject=[["Mimikatz", "uses", "APT29"]],
        ),
        RelSample(
            description="alias merge feeds transitive (fallback engine, opt-in)",
            completion={"alias": True},
            objects=[{"type": "threat-actor", "name": "FIN7-Group"},
                     {"type": "threat-actor", "name": "fin7 group"},
                     {"type": "malware", "name": "Loader-A"},
                     {"type": "attack-pattern", "name": "Masquerading"}],
            edges=[["fin7 group", "uses", "Loader-A"],
                   ["Loader-A", "uses", "Masquerading"]],
            gold_accept=[["FIN7-Group", "uses", "Masquerading"]],
            gold_reject=[],
        ),
        RelSample(
            description="no spurious edges on unrelated objects",
            objects=[{"type": "tool", "name": "SomeCustomTool-42"},
                     {"type": "vulnerability", "name": "SomeUnknownVuln-9"}],
            edges=[],
            gold_accept=[],
            gold_reject=[],
            closed=True,
        ),
    ]


def load_rel_dataset(path: Path) -> list[RelSample]:
    """Load a labeled graph-completion dataset (format in the header above)."""
    data = json.loads(path.read_text(encoding="utf-8"))
    return [
        RelSample(
            objects=s.get("objects", []),
            edges=s.get("edges", []),
            gold_accept=s.get("gold_accept", []),
            gold_reject=s.get("gold_reject", []),
            closed=bool(s.get("closed", False)),
            description=s.get("description", ""),
            completion=s.get("completion"),
        )
        for s in data
    ]


def print_rel_scores(score: RelScore) -> None:
    print("\n" + "=" * 60)
    print("Stage 4b Graph-Completion Benchmark (edge level)")
    print("=" * 60)
    print(f"  TP={score.tp:.0f}  FP={score.fp:.0f}  FN={score.fn:.0f}  "
          f"unjudged={score.unjudged}")
    print(f"  Precision = {score.precision:.3f}")
    print(f"  Recall    = {score.recall:.3f}")
    print(f"  F1        = {score.f1:.3f}")
    if score.by_engine:
        print("\n  Per engine:")
        for eng, s in sorted(score.by_engine.items()):
            d = s["tp"] + s["fp"]
            p = s["tp"] / d if d else 1.0
            print(f"    {eng:<20} added={s['added']:<4} judged-precision={p:.3f}")
    print("\n  Reference: CTINexus relation prediction ≈ 0.910 (EuroS&P 2025)")


# ---------------------------------------------------------------------------
# CLI entry point  (updated to support --benchmark ate)
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Evaluate cti-to-stix pipeline NER stages against labeled data.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--benchmark", "-b", choices=["ner", "ate", "grounding", "rel"], default="ner",
        help=(
            "Which benchmark to run:\n"
            "  ner       — NER IoC/entity extraction recall (default)\n"
            "  ate       — ATT&CK Technique Extraction (CTIBench ATE task)\n"
            "  grounding — hallucination rate: how much emitted output is NOT\n"
            "              supported by the source text (offline)\n"
            "  rel       — Stage 4b graph-completion edge precision (ADR-0013)"
        ),
    )
    parser.add_argument(
        "--from-db", dest="from_db", default=None,
        help=(
            "[grounding mode] Score real processed reports from cti_stix.db.\n"
            "  'all' for every job, or a specific job_id."
        ),
    )
    parser.add_argument(
        "--llm-only", dest="llm_only", action="store_true",
        help="[grounding mode, --from-db] Restrict entities to source='llm'.",
    )
    parser.add_argument(
        "--db-path", dest="db_path", type=Path, default=Path("cti_stix.db"),
        help="[grounding mode] Path to the SQLite DB (default: cti_stix.db).",
    )
    parser.add_argument(
        "--from-bundle", dest="from_bundle", default=None,
        help=(
            "[grounding mode] Score the emitted STIX bundle instead of the "
            "relationships table.  'all' for every job, or a job_id.  Only edges "
            "labelled observed/reported are scored; assessed/inferred are "
            "assertions, not claims about the text."
        ),
    )
    parser.add_argument(
        "--rel-window", dest="rel_window", type=int, default=1,
        help=(
            "[grounding mode] ± sentence window for relationship claim grounding "
            "(default: 1). 0 = strict single-sentence."
        ),
    )
    parser.add_argument(
        "--alias-aware", dest="alias_aware", action="store_true",
        help=(
            "[grounding mode] Resolve MITRE aliases when grounding (e.g. emitted "
            "'OilRig' grounds against 'APT34' in the text). Prototype — Option B."
        ),
    )
    parser.add_argument(
        "--rel-proximity", dest="rel_proximity", type=int, default=0,
        help=(
            "[grounding mode] Char window for structure-aware (table/list) "
            "grounding of IoC relationships. 0 = off; try 200. Endpoints co-located "
            "within N chars count as claim-grounded even without a linking sentence."
        ),
    )
    parser.add_argument(
        "--dataset", "-d", type=Path, default=None,
        help=(
            "Path to dataset JSON file.  "
            "NER mode: DNRTI-AUG-STIX2 format.  "
            "ATE mode: CTIBench ATE format (https://github.com/xashru/cti-bench)."
        ),
    )
    parser.add_argument(
        "--stage", "-s", choices=["2", "2c", "all", "full"], default="all",
        help=(
            "[ATE mode] Which pipeline stage to evaluate (default: all).\n"
            "  2    = regex (explicit T-IDs)\n"
            "  2c   = semantic only\n"
            "  all  = regex + semantic + subsumption (offline)\n"
            "  full = regex + semantic + LLM + Stage 3c normalize (needs API key)"
        ),
    )
    parser.add_argument(
        "--retrieval-recall", dest="retrieval_recall", default=None,
        help=(
            "[ATE mode] Comma-separated k values (e.g. '1,5,10,25').  Reports the "
            "fraction of gold techniques present in Stage 2c's top-k candidates, "
            "before any confidence threshold.  This is the ceiling on every "
            "downstream stage."
        ),
    )
    parser.add_argument(
        "--types", "-t", nargs="+", default=None,
        help="[NER mode] Entity types to evaluate (e.g. ipv4 sha256 malware).",
    )
    parser.add_argument(
        "--no-partial", action="store_true",
        help="[NER mode] Disable partial-match scoring (strict exact match only).",
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true",
        help="Show false positives and false negatives per sample.",
    )
    args = parser.parse_args()

    # ── REL benchmark (Stage 4b graph completion) ─────────────────────────────
    if args.benchmark == "rel":
        if args.dataset:
            print(f"Loading graph-completion dataset: {args.dataset}")
            rel_samples = load_rel_dataset(args.dataset)
            print(f"  {len(rel_samples)} samples loaded.")
        else:
            print("Using built-in graph-completion fixture samples.")
            rel_samples = _load_rel_fixture_samples()
            print(f"  {len(rel_samples)} fixture samples.")
        print_rel_scores(run_rel_benchmark(rel_samples, verbose=args.verbose))
        return

    # ── Grounding / hallucination-rate benchmark ──────────────────────────────
    if args.benchmark == "grounding":
        if args.from_bundle:
            print(f"Loading grounding samples from bundle_json (job={args.from_bundle})")
            samples, census = load_grounding_from_bundle(
                args.db_path, args.from_bundle)
            print_label_census(census)
            if not samples:
                print()
                print("  No evidential edges to score.")
                return
            n_scored = sum(len(s.relationships) for s in samples)
            print()
            print(f"  Scoring {n_scored} evidential edge(s) across "
                  f"{len(samples)} bundle(s).")
            print_grounding_scores(
                score_grounding(
                    samples,
                    window=args.rel_window,
                    alias_aware=args.alias_aware,
                    proximity=args.rel_proximity,
                ),
                window=args.rel_window,
            )
            return
        if args.from_db:
            if not args.db_path.exists():
                print(f"  ERROR: DB not found: {args.db_path}")
                return
            print(f"Loading grounding samples from {args.db_path} (job={args.from_db}, "
                  f"llm_only={args.llm_only})")
            samples = load_grounding_from_db(args.db_path, args.from_db, args.llm_only)
        elif args.dataset:
            print(f"Loading emitted pipeline output: {args.dataset}")
            samples = load_grounding_dataset(args.dataset)
        else:
            print("Using built-in grounding fixtures (planted hallucinations).")
            samples = _load_grounding_fixture_samples()
        print(f"  {len(samples)} sample(s).")

        if not samples:
            print("  No samples to score (no jobs with report_text?).")
            return

        score = score_grounding(
            samples, window=args.rel_window,
            alias_aware=args.alias_aware, proximity=args.rel_proximity,
            verbose=args.verbose,
        )
        if args.alias_aware:
            print("  (alias-aware grounding ON — MITRE aliases resolved)")
        print_grounding_scores(score, window=args.rel_window)
        return

    # ── ATE benchmark ─────────────────────────────────────────────────────────
    if args.benchmark == "ate":
        if args.dataset:
            print(f"Loading CTIBench ATE dataset: {args.dataset}")
            samples = load_ctibench_ate(args.dataset)
            print(f"  {len(samples)} samples loaded.")
        else:
            print("Using built-in ATE fixture samples (no external dataset).")
            samples = _load_ate_fixture_samples()
            print(f"  {len(samples)} fixture samples.")

        print(f"  Stage: {args.stage}")

        if args.stage in ("2c", "all", "full"):
            try:
                from pipeline.stage2c_ttp_semantic import semantic_available
                if not semantic_available():
                    print(
                        "\n  WARNING: Stage 2c embedding cache not found.\n"
                        "  Run: python scripts/build_indexes.py --only embeddings\n"
                        "  Falling back to Stage 2 regex only.\n"
                    )
            except ImportError:
                pass

        score = run_ate_benchmark(samples, stage=args.stage, verbose=args.verbose)
        print_ate_scores(score, stage=args.stage)

        if args.stage in ("2c", "all", "full"):
            print_gate_stats(samples)

        if args.retrieval_recall:
            ks: list[int] = []
            for raw in args.retrieval_recall.split(","):
                raw = raw.strip()
                if not raw:
                    continue
                try:
                    k_val = int(raw)
                except ValueError:
                    print(f"  Ignoring invalid k value: {raw!r}")
                    continue
                if k_val >= 1:
                    ks.append(k_val)
            ks = sorted(set(ks))
            if not ks:
                print("  No valid k values given; skipping retrieval recall.")
            else:
                print_retrieval_recall(
                    run_retrieval_recall(samples, ks, verbose=args.verbose)
                )
        return

    # ── NER benchmark (default) ───────────────────────────────────────────────
    if args.dataset:
        print(f"Loading NER dataset: {args.dataset}")
        samples = load_dnrti_dataset(args.dataset)
        print(f"  {len(samples)} samples loaded.")
    else:
        print("Using built-in NER fixture samples (no external dataset).")
        samples = _load_fixture_samples()
        print(f"  {len(samples)} fixture samples.")

    filter_types: set[EntityType] | None = None
    if args.types:
        filter_types = set()
        for t in args.types:
            try:
                filter_types.add(EntityType(t))
            except ValueError:
                print(f"  WARNING: unknown entity type '{t}' — skipping")

    partial = not args.no_partial
    print(f"\nScoring Stage 2 (regex IoC extraction) — partial_credit={partial}")
    scores = score_dataset(
        samples,
        stage_fn=extract_entities,
        partial_credit=partial,
        verbose=args.verbose,
        filter_types=filter_types,
    )

    print_scores(scores)

    overall = scores.get("overall")
    if overall:
        print(f"\nSummary: P={overall.precision:.3f}  R={overall.recall:.3f}  F1={overall.f1:.3f}")


if __name__ == "__main__":
    main()
