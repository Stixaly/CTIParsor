# Baseline — AnnoCTR dev, 2026-09-27

The application's pipeline as it ships (ADR-0059), scored with the ADR-0060
protocol. **Dev split only** (16 reports, 129 document-level technique labels):
this is the reference later changes are compared against, not a headline
number — the test split is run once per frozen configuration.

Configuration: Stages 1–3 with every Stage 2 extractor available (gazetteer,
semantic TTPs, CyNER, GLiNER, alias lists), Stage 3d and 3f verification on,
consensus and document-level relations off; LLM `vLLM/Inferact/Qwen3.8-27B-NVFP4`
with the provider's own sampling (no `LLM_TEMPERATURE`), thinking off; prompt
fingerprint `53195bfc6d7b8870`. About 300 s per report.

Reproduce: `python -m evaluation run --split dev --name baseline-dev` then
`score` (docs/eval/README.md).

## Techniques

| | Precision | Recall | F1 |
|---|---|---|---|
| **Parent level, micro (primary)** | 0.279 | 0.434 | **0.339** |
| Parent level, per-document average | 0.246 | 0.384 | 0.282 |
| Exact id, micro | 0.123 | 0.202 | 0.153 |
| Gold + ids written in the report (sensitivity) | 0.353 | 0.493 | 0.412 |

* Recall of techniques annotated **explicitly**: 16/36 (0.44); **only
  implicitly**: 40/93 (0.43).
* The sensitivity row exists because AnnoCTR leaves most ids of a vendor's own
  ATT&CK table unannotated (15 of 23 on dev); see docs/eval/README.md.

### Where the technique errors come from

| Entry path | Predictions | Precision |
|---|---|---|
| Stage 2c semantic match | 111 (55%) | **0.16** |
| LLM only | 67 | 0.45 |
| Id written in the text (regex) | 23 | 0.35 — every one is an id the report writes out, so the 15 "errors" are the unannotated ATT&CK tables |

The semantic stage produces most predictions and most false positives, and its
candidate recall as configured (one candidate per sentence) is 22.5% of gold
techniques; 57% at k = 5, 81% at k = 20 (`evaluation retrieval`). Misses: 53
only-implicit, 20 explicit. Most frequent false positives: T1588, T1586,
T1219, T1564, T1659, T1105; most frequent misses: T1105, T1486, T1190, T1036,
T1685 (ex-T1562).

## Evidence

* 204 predicted techniques carry a quote; **98.5%** of the quotes are found in
  the text.
* Of the 58 correct techniques with a located quote, **55%** sit on a passage
  the annotators marked for that technique, **67%** within 200 characters.
* Whether the quote *supports* the technique: 50 quotes to judge in
  `data/eval/runs/baseline-dev/support-sample.csv` (not yet judged).

## Named entities (strict / lenient F1)

| Type | Precision | Recall | F1 strict | F1 lenient |
|---|---|---|---|---|
| malware | 0.20 | 0.85 | 0.33 | 0.36 |
| threat_actor | 0.14 | 0.94 | 0.24 | 0.24 |
| tool | 0.34 | 0.73 | 0.47 | 0.47 |
| location | 0.41 | 0.40 | 0.40 | 0.47 |
| identity (sectors) | 0.36 | 0.38 | 0.37 | 0.49 |

Precision by source (exact match): CyNER 0.09 for malware (99 predictions) and
0.09 for threat actors (94) — generic words ("cybercriminals", "scammers"),
countries, a victim ("Colonial Pipeline"); the spaCy fallback 0.08 for malware
("Cyprus", "XOR", "SHA256"); the gazetteer 0.55–0.68.

## Run-to-run spread

The same configuration run twice (`baseline-dev`, `baseline-dev-r2`), the
provider's default sampling (Qwen's generation config, temperature 0.7):

| | run 1 | run 2 | difference (paired bootstrap, 95% CI) |
|---|---|---|---|
| Technique F1 | 0.339 | 0.367 | +0.028 [−0.004, +0.063], P(not better) 0.044 |
| Precision | 0.279 | 0.300 | +0.022 [−0.004, +0.051] |
| Recall | 0.434 | 0.473 | +0.039 [−0.008, +0.086] |

Entities barely move (their stages before the LLM are deterministic; F1
within 0.01).

**Chance alone moves technique F1 by about 0.03 — more than the +0.02 minimum
gain of the decision rule — and the document bootstrap nearly calls it
significant**, because it resamples reports, not the LLM's sampling. Until the
sampling is fixed, a comparison needs repeated runs on each side, and a gain
below ~0.04 is not a result.

### With the sampling fixed (`LLM_TEMPERATURE=0 LLM_SEED=13`)

| | Precision | Recall | F1 |
|---|---|---|---|
| t0, run 1 | 0.277 | 0.434 | 0.338 |
| t0, run 2 | 0.277 | 0.434 | 0.338 |
| t0 − baseline run 1 | −0.001 [−0.030, +0.028] | 0.000 [−0.059, +0.054] | −0.001 [−0.040, +0.036] |

* **The two runs are identical, report for report** (difference 0.0000): with
  temperature 0 and a seed, this vLLM server returns the same answers, so one
  run per configuration is enough and the noise floor for comparisons is zero.
  Measured with `LLM_PARALLELISM=1`; concurrent batching could reintroduce
  small differences.
* **Quality does not move**: F1 0.338 against 0.339 (default sampling, run 1)
  and 0.367 (run 2) — within the old spread.
* Stage 3 health: 68/68 extraction calls usable; 3d 61 usable / 1 unparseable,
  3f 57 / 1; no provider failure. 321 s per report.

**Consequence for the protocol**: evaluation runs set `LLM_TEMPERATURE=0
LLM_SEED=13` from now on. The Stage 2c ablation above was made at the default
sampling; its effect (+0.12 to +0.15) is far above the old spread, so it
stands, but a re-run at temperature 0 would give its exact size.

**For production** (operator's choice, `.env`): temperature 0 gives the same
quality on dev and makes a report's extraction reproducible — the same file
gives the same entities and techniques, which the review and the audit trail
can rely on.

## First ablation: Stage 2c off

`python -m evaluation run --split dev --name abl-2c-dev --disable 2c`, same
sampling as the baseline, compared with both baseline runs:

| | Precision | Recall | F1 | vs run 1 (95% CI) | vs run 2 (95% CI) |
|---|---|---|---|---|---|
| Baseline run 1 | 0.279 | 0.434 | 0.339 | | |
| Baseline run 2 | 0.300 | 0.473 | 0.367 | | |
| **Stage 2c off** | **0.522** | **0.457** | **0.488** | +0.148 [+0.077, +0.222] | +0.120 [+0.054, +0.194] |

* Precision gains +0.22 to +0.24 (intervals well above 0); recall does not
  move (−0.016 to +0.023, intervals around 0): the LLM finds on its own what
  the semantic stage contributed, without its false positives.
* Per-document F1 0.422 (from 0.282); gold + written ids 0.576 (from 0.412);
  explicit recall 0.53, implicit-only 0.43.
* Entities unchanged (Stage 2c emits techniques only).
* 343 s per report against ~300 — within the 25% budget; the difference is
  mostly one report (944 s against 480 s), i.e. LLM latency, not work done.

Against the decision rule (docs/eval/README.md): the gain is 5 to 7 times the
+0.02 minimum and 4 to 5 times the measured run-to-run spread, the interval
excludes 0 against either baseline run, precision rises. **On dev, Stage 2c as
configured is a net loss.** Not yet done: the frozen configuration on test, and
the question of what 2c should become — Phase 4 turns it into a candidate
generator for the LLM to validate rather than a direct source of techniques.

## What this says about the next phase

These reports are clean text, so nothing here is lost to PDF, OCR or tables:
the errors are in **mapping behaviour to ATT&CK** and in **named-entity
precision**. That points to Phase 4 (retrieve-then-validate for techniques)
before Phase 5 (structured ingestion), which needs the in-house set to be
measured at all. Two cheaper candidates showed up on the way: the semantic
stage, whose removal alone lifts technique F1 by +0.12 to +0.15 (ablation
above), and CyNER / spaCy precision on named entities.

**Follow-up (2026-10-03):** the retrieval half of Phase 4 is measured in
ADR-0072 — parent recall per passage at k=5 from 0.33 (Stage 2c's cache and
retriever) to 0.77 (ATT&CK descriptions + procedure examples, BM25 ⊕ dense);
the selector (`TTP_MODE=select`) awaits its dev run.
