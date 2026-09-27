# ADR-0060 — Evaluation protocol: AnnoCTR, an in-house set, paired comparisons

**Status:** Accepted (harness implemented 2026-09-27; baseline in
[docs/eval/baseline-2026-09.md](../eval/baseline-2026-09.md); in-house set to annotate)
**Date:** 2026-09-27
**Relates to:** [evaluation/](../../evaluation/), [docs/eval/README.md](../eval/README.md),
[docs/eval/annotation-guide.md](../eval/annotation-guide.md), ADR-0023 (TTP
measurement), ADR-0059 (one pipeline), ADR-0058 (decision provenance)

## Context

ADR-0059 made the benchmark run the application's pipeline. What it could
still not say is whether a change helps: the only gold data were a handful of
fixture sentences and CTIBench's ATE task (single sentences, no document), no
comparison accounted for noise, and the Stage 3 LLM ran with the provider's
default sampling, so two runs of one report could differ.

A review of the plan (with a second model's critique) added constraints this
protocol adopts:

* AnnoCTR has 400 reports but only **120** carry the cybersecurity layer
  (70/16/34); the rest must never be read as "no techniques";
* its official split is temporal and puts every vendor in every split — kept;
* an annotation that is missing is not a fact that is absent: every document
  records which layers it was annotated for;
* gold labels from 2022 ATT&CK must be mapped to today's ids, on both sides;
* a quote located on the right passage is not a quote that supports the claim;
* compare configurations on the same documents (paired bootstrap), with the
  decision rule fixed before looking at test.

## Decision

1. **`evaluation/`** — a package separate from unit tests and production:
   `annoctr` (loader, layer registry, mention location), `attack` (ATT&CK
   mapping with `revoked-by` chains, against the pipeline's own index),
   `dedup` (copies and excerpts across splits and extra corpora), `metrics`
   (parent/exact TTP scores, explicit/implicit recall, per-document average,
   one-to-one entity matching strict and lenient, typed and directed
   relations, paired bootstrap), `evidence` (exists / on the passage / sample
   for human judgement), `inhouse` (file-based gold with layers and negative
   cases, agreement between annotators). CLI: `python -m evaluation`.
2. **AnnoCTR** is used with its official split; dev for tuning, test once per
   frozen configuration. Data stays in `data/` (CC-BY-SA 4.0, not committed).
3. **An in-house set** of 10–20 of our reports, annotated from the original
   file with a written guide, measures IoCs, relationships, ingestion losses
   and negative cases (negated behaviours, recommendations, generic examples).
   Pre-annotations from the pipeline are drafts, never scored.
4. **Decision rule** (docs/eval/README.md): paired-bootstrap interval of the
   parent-level F1 difference excludes 0, gain ≥ +0.02, precision loss ≤ 0.02,
   gain above the run-to-run spread, cost ≤ +25% per report.
5. **Two production changes the measurement needed:**
   * `LLM_TEMPERATURE` / `LLM_SEED` (unset by default = unchanged behaviour),
     recorded in the run manifest and the Stage 3 checkpoint fingerprint;
   * **Stage 3 counts what came back** — failed request, empty answer,
     unparseable answer, usable answer; 3d/3f likewise. Stage 3 is `failed`
     when no answer was usable (ADR-0059 §4b). The runner records such a
     report as failed and goes on; two in a row stop the run (a setup
     problem, like the 404 below). `score` reports these counts as
     `llm_health`.

## What the first measurements showed

* **The configured model did not exist on the server.** `.env` asked vLLM for
  `Qwen3.8-27B-NVFP4`; the server serves `Inferact/Qwen3.8-27B-NVFP4`. Every
  Stage 3 call returned 404, each was caught, and the pipeline produced bundles
  without any LLM content while reporting Stage 3 as run. The first baseline
  attempt scored that. Fixed in the harness (call accounting above); the
  `.env` value is the operator's to fix.
* **ATT&CK drift is real:** of 145 gold ids, T1562 and T1562.001 are revoked
  (→ T1685) and 5 are Mobile ids; nothing is out of the pipeline's reach.
* **AnnoCTR leaves most vendor ATT&CK tables unannotated:** 15 of the 23 ids
  written verbatim in dev reports are not in the gold. Scored against the gold
  plus those ids, the dev baseline goes from F1 0.339 to 0.412. Both rows are
  reported; the official gold stays primary.
* **Run-to-run noise exceeds the minimum useful gain.** Two identical dev runs
  with the provider's default sampling differ by +0.028 technique F1 (paired
  bootstrap P(not better) 0.044): a document bootstrap does not capture LLM
  sampling. Comparisons need repeated runs until the sampling is fixed;
  temperature-0 runs are measured next.
* **Stage 2c's candidate recall is low as configured:** on dev, one candidate
  per sentence (production) reaches 22.5% of gold techniques (14 candidates
  per report); k = 5 → 57.4% (47), k = 20 → 80.6% (121). Any retrieve-then-
  validate design (ADR-0023, Phase 4) starts from this ceiling.

## Consequences

* A full run of dev costs about an hour with the local Qwen server, test about
  two; an ablation matrix is a day of compute and is run on dev only.
* The in-house set needs a person's time; the guide asks for a second
  annotator on 3–5 reports and says how to report consistency without one.
* Active review time and double annotation are second-tier, recorded in
  docs/eval/README.md.
