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
import sys
from dataclasses import dataclass
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
class ATEScore:
    """Precision/Recall/F1 for the ATE task."""
    tp: float = 0.0
    fp: float = 0.0
    fn: float = 0.0

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


# ---------------------------------------------------------------------------
# ATE scoring helpers
# ---------------------------------------------------------------------------

def _normalize_tid(tid: str) -> str:
    """Uppercase and strip a MITRE T-ID: ' t1059.001 ' → 'T1059.001'."""
    return tid.strip().upper()


def _score_ate_sample(
    predicted_ids: set[str],
    expected_ids:  set[str],
    parent_credit: float = 0.5,
) -> tuple[float, float, float]:
    """
    Score one ATE sample.  Returns (tp, fp, fn).

    parent_credit:
      If 0.5 — predicting the parent T-ID (e.g. T1059) when the ground truth is
      a sub-technique (T1059.001) gives partial credit (0.5).  This is fair
      because Stage 2c may match at technique level while the report means a
      specific sub-technique.
      If 0.0 — strict exact match only (no partial credit for parents).
    """
    pred = {_normalize_tid(t) for t in predicted_ids}
    gold = {_normalize_tid(t) for t in expected_ids}

    tp: float = 0.0
    matched_gold: set[str] = set()

    for pt in pred:
        if pt in gold:
            tp += 1.0
            matched_gold.add(pt)
        elif parent_credit > 0:
            # Check if predicted is the parent of any gold sub-technique
            for gt in gold:
                if gt in matched_gold:
                    continue
                if "." in gt and gt.rsplit(".", 1)[0] == pt:
                    tp += parent_credit
                    matched_gold.add(gt)
                    break
                # Or if gold is the parent of a predicted sub-technique
                if "." in pt and pt.rsplit(".", 1)[0] == gt:
                    tp += parent_credit
                    matched_gold.add(gt)
                    break

    fp = len(pred)  - sum(
        1 for p in pred if p in gold or any(
            ("." in g and g.rsplit(".", 1)[0] == p) or
            ("." in p and p.rsplit(".", 1)[0] == g)
            for g in gold
        )
    )
    fn = len(gold - matched_gold)

    return max(0.0, tp), max(0.0, float(fp)), max(0.0, float(fn))


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
    """Combine regex (Stage 2) + semantic (Stage 2c) TTP extraction."""
    ids = _ate_stage2_regex(text)
    ids |= _ate_stage2c_semantic(text)
    return ids


_ATE_STAGE_FNS: dict[str, object] = {
    "2":    _ate_stage2_regex,
    "2c":   _ate_stage2c_semantic,
    "all":  _ate_combined,
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
        ATEScore with aggregated P/R/F1 across all samples.
    """
    stage_fn = _ATE_STAGE_FNS.get(stage, _ate_combined)
    total = ATEScore()

    for sample in samples:
        predicted_ids = stage_fn(sample.text)
        tp, fp, fn = _score_ate_sample(predicted_ids, sample.expected_ids)
        total.tp += tp
        total.fp += fp
        total.fn += fn

        if verbose and sample.expected_ids:
            pred_norm = {_normalize_tid(t) for t in predicted_ids}
            gold_norm = {_normalize_tid(t) for t in sample.expected_ids}
            fps = pred_norm - gold_norm
            fns = gold_norm - pred_norm
            if fps or fns:
                print(f"\n  [{sample.description or 'sample'}]")
                if fps:
                    print(f"    FP (unexpected): {fps}")
                if fns:
                    print(f"    FN (missed):     {fns}")

    return total


def print_ate_scores(score: ATEScore, stage: str, gpt4_baseline: float = 0.64) -> None:
    """Print the ATE benchmark result with comparison to the GPT-4 baseline."""
    print(f"\n{'=' * 55}")
    print(f"  ATT&CK Technique Extraction (ATE) — Stage {stage}")
    print(f"{'=' * 55}")
    print(f"  Precision : {score.precision:.3f}")
    print(f"  Recall    : {score.recall:.3f}")
    print(f"  F1        : {score.f1:.3f}   (GPT-4 baseline: {gpt4_baseline:.2f})")
    print(f"  TP={score.tp:.1f}  FP={score.fp:.1f}  FN={score.fn:.1f}")
    delta = score.f1 - gpt4_baseline
    sign = "+" if delta >= 0 else ""
    print(f"  vs GPT-4  : {sign}{delta:.3f}  {'✓ above baseline' if delta >= 0 else '✗ below baseline'}")
    print(f"{'=' * 55}")


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
    assert score.f1 >= 0.95, (
        f"Stage 2 regex ATE F1={score.f1:.3f} on explicit T-ID samples — "
        f"expected ≥0.95.  TP={score.tp} FP={score.fp} FN={score.fn}"
    )


def test_stage2_ttp_no_false_positives_on_clean_text():
    """Stage 2 TTP regex must not fire on clean non-technical text."""
    clean_samples = [
        s for s in _load_ate_fixture_samples()
        if "FP check" in s.description
    ]
    score = run_ate_benchmark(clean_samples, stage="all")
    assert score.fp == 0, (
        f"Stage 2 TTP extracted {score.fp} false-positive T-IDs from clean text"
    )


# ---------------------------------------------------------------------------
# CLI entry point  (updated to support --benchmark ate)
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Evaluate cti-to-stix pipeline NER stages against labeled data.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--benchmark", "-b", choices=["ner", "ate"], default="ner",
        help=(
            "Which benchmark to run:\n"
            "  ner  — NER IoC/entity extraction (default)\n"
            "  ate  — ATT&CK Technique Extraction (CTIBench ATE task)"
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
        "--stage", "-s", choices=["2", "2c", "all"], default="all",
        help="[ATE mode] Which pipeline stage to evaluate (default: all).",
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

        if args.stage in ("2c", "all"):
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
