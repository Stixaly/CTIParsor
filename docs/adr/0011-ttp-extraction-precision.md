# ADR-0011: TTP Extraction Precision

**Status:** Accepted
**Date:** 2026-06-21
**Deciders:** maintainer

## Context

TTPs reach the STIX bundle from three independent producers — Stage 2 regex
(explicit `T1234` IDs), Stage 2c semantic embedding match, and the Stage 3 LLM —
merged in Stage 3c (`normalize_ttps`). Unlike relationships, which pass two
precision gates (Stage 3d self-verification, Stage 3e cross-model consensus), TTPs
had **none**: Stage 3b explicitly excludes them and Stage 3c only checks that a
*name/ID is real*, not that the *text supports it*.

Five concrete false-positive sources were identified:

1. Stage 2c emitted the **top-2 techniques per candidate sentence** at a 0.48
   cosine floor — every keyword sentence forced up to two matches, the second
   usually a wrong nearest-neighbour.
2. The cosine thresholds (`0.62` / `0.48`) were **hardcoded for all-MiniLM-L6-v2**
   yet the model is configurable (ADR-0004 recommends SecureBERT-Plus), so swapping
   the model silently miscalibrated the gate.
3. In Stage 3c, semantic matches were **seeded first and won** the dedup — a
   *medium*-confidence semantic guess could override the context-aware LLM.
4. **No evidence grounding for TTPs** — an LLM-guessed technique whose name merely
   fuzzy-matched a real ATT&CK entry was accepted even if the document never
   described it.
5. A parent technique (`T1059`) and its sub-technique (`T1059.001`) both survived
   dedup, leaving a redundant, less-specific entry.

## Decision

Add four precision layers, each independently toggleable and offline-capable.

| Phase | Change | File(s) |
|---|---|---|
| **A** | Model-aware cosine thresholds (per-model table → manifest → env override); single match per sentence (`top_k=1`) with a `TTP_TOP2_MARGIN` gate for any 2nd match; Stage 3c stops *medium*-confidence semantic matches overriding the LLM (only ≥ high-threshold semantic wins). | `pipeline/stage2c_ttp_semantic.py`, `pipeline/stage3c_mitre.py`, `scripts/build_indexes.py` |
| **B** | Stage 3f — TTP self-verification (analogue of 3d): a second LLM pass must quote the sentence describing each technique's use; unsupported claims dropped. TTPs corroborated by a high-confidence semantic match are trusted and skipped. Opt-in via `ENABLE_TTP_VERIFICATION`. | `pipeline/stage3f_ttp_verify.py`, `pipeline/stage3_llm.py` |
| **C** | Parent/sub-technique subsumption (drop the parent when a sub-technique is present); technique→tactic lookup feeding the Stage 3f prompt so a technique whose described behaviour fits the wrong tactic can be rejected. | `pipeline/stage3c_mitre.py` |
| **D** | ATE benchmark extended with a `full` stage (regex + semantic + LLM + Stage 3c normalize — the only stage measuring what ships) and adversarial precision fixtures; new unit + precision tests. | `tests/eval_pipeline.py`, `tests/test_ttp_precision.py` |

## Consequences

- **Easier:** measurably higher TTP precision; the semantic gate now travels with
  the embedding cache (manifest `thresholds`) instead of drifting from the model;
  the same evidence-grounding discipline relationships already had now applies to
  techniques.
- **Harder / revisit:** Phase A trades a little semantic recall for precision
  (medium, uncorroborated matches no longer override the LLM and the 2nd-per-
  sentence match is gated). Phase B adds ~1.4× LLM calls when enabled. Per-model
  thresholds (SecureBERT-Plus row) are seeded by reasoning, not yet calibrated —
  run the Phase D `full` benchmark on CTIBench ATE to tune them.
- Every layer degrades gracefully: Phases A, C and the offline parts of D run with
  no model/LLM; Phase B and the `full` ATE stage no-op without a provider.

## Related

Extends ADR-0004 (extraction quality) and mirrors the verification/consensus
philosophy of ADR-0009 (STIX trust & provenance), applying it to techniques rather
than relationships.
