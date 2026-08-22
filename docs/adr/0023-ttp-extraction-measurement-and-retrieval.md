# ADR-0023: TTP extraction — fix the ruler, then retrieve-then-validate

**Status:** Proposed
**Date:** 2026-08-22
**Deciders:** maintainer

## Context

ADR-0011 added four precision layers to TTP extraction and closed with an explicit
debt: *"run the Phase D `full` benchmark on CTIBench ATE to tune them."* That run
never happened. Every threshold, margin and tier currently shipping was chosen by
reasoning, not measurement. Three findings — one from the code, two from the
literature — say the debt is larger than a tuning run.

### 1. The measuring instrument is wrong, in two separate ways

`_score_ate_sample` (`tests/eval_pipeline.py`) awards `parent_credit=0.5` when a
predicted parent matches a gold sub-technique or vice versa. The 0.5 is added to
`tp`, but the prediction is excluded from `fp` entirely, so half the prediction's
mass leaves the accounting. Measured:

| case | tp | fp | fn | prec | rec | leak |
|---|---|---|---|---|---|---|
| parent predicted, sub is gold | 0.5 | 0.0 | 0.0 | **1.00** | **1.00** | 0.5 |
| sub predicted, parent is gold | 0.5 | 0.0 | 0.0 | **1.00** | **1.00** | 0.5 |
| two subs predicted, one parent gold | 0.5 | 0.0 | 0.0 | **1.00** | **1.00** | 1.5 |
| exact match (control) | 1.0 | 0.0 | 0.0 | 1.00 | 1.00 | — |
| pure false positive (control) | 0.0 | 1.0 | 1.0 | 0.00 | 0.00 | — |

Predicting `T1059.001` **and** `T1059.002` against a gold `T1059` scores perfect
precision and perfect recall. Since ATT&CK sub-techniques are where most of the
label space lives, this inflates every number the harness can produce.

The deeper problem is the design, not the arithmetic. Both reference systems
reject partial credit outright and report **two granularities** instead:
technique-level (truncate every ID to its parent, then score) and sub-technique
level (exact match only — *"predicting a parent technique when a sub-technique is
the gold label, or vice versa, is not considered correct"*, RCPO §4.4). One number
with fractional credit hides which of the two regimes is failing.

The harness also micro-averages TP/FP/FN across the whole corpus. The SoK computes
F1 **per document and averages the document scores** (§3.3), and RCPO macro-averages
per sample (§4.4). Micro-averaging lets a handful of long, technique-dense reports
dominate the score.

### 2. A documented gate that cannot fire

ADR-0011 Phase A specifies *"single match per sentence (`top_k=1`) with a
`TTP_TOP2_MARGIN` gate for any 2nd match."* Those two clauses contradict each
other. With `top_k_per_sentence=1`, `np.argsort(...)[::-1][:1]` yields one index,
so the `if rank > 0` branch at `stage2c_ttp_semantic.py:418` is unreachable. Both
production callers — `api/worker.py:383` and `SemanticTTPStage.extract` — use the
default, and no test passes `k>1`. `TTP_TOP2_MARGIN` has never gated anything.
Multi-label recall was removed in Phase A and the compensating valve was never
connected.

### 3. Stage 2c's architecture is the weakest method in the field, and the gap is quantified

Büchel et al. evaluate exactly Stage 2c's design — cosine similarity between
sentence embeddings and ATT&CK technique text, no labels, threshold cut — under the
name *unlabeled classification*, and report it as unusable at full label scope:

| setting | model | TRAM2 F1 / Prec | AnnoCTR F1 / Prec |
|---|---|---|---|
| top-50 techniques | ATT&CK-BERT | 50.60 / 43.07 | 35.45 / 35.72 |
| **all techniques** | **ATT&CK-BERT** | **10.71 / 7.24** | **13.44 / 8.93** |
| all techniques | SBERT (MPNet) | 12.23 / 8.31 | 12.85 / 8.23 |

Stage 2c scans all 1,531 techniques. That is the bottom row: single-digit precision.
The SoK's verdict on the whole family is *"practically unusable due to their low
Precision."* Labeled classifiers on the same data reach 70.55% (RoBERTa-Large,
TRAM2) and 62.75% (CySecBERT, AnnoCTR) — the ~70% F1 ceiling the SoK reports no
approach has cleared, generative LLMs included.

Two further results from the same tables bear directly on the plan I had drafted:

- **CTI-pretrained encoders do not consistently beat generic ones.** The best
  TRAM2 score is a general model; SecureBERT (58.44 / 70.24) does not dominate
  BERT-base (50.24 / 66.55). For the *unlabeled* setting specifically, the winner
  is **ATT&CK-BERT**, not SecureBERT. Swapping in SecureBERT-Plus — ADR-0004's
  recommendation and the obvious next config flip — is not supported by evidence.
- **Ambiguity is a hard floor.** Two annotators agree on only 31% of ATT&CK
  concepts in AnnoCTR; `T1112` vs `T1547.001` and `T1140` vs `T1027` are routinely
  confused by humans. Targets above ~70% F1 are not meaningful on this task.

### What the two systems that do work actually do

| | Multi-Step (Kim et al., IEEE Access 2025) | TTP-R1 / RCPO (Zhang et al., AWS) |
|---|---|---|
| Retrieval corpus | ATT&CK **procedure examples** (v15.1) | ATT&CK technique corpus, BM25 + dense |
| Retriever | MiniLM-L12-v2 fine-tuned w/ Triplet loss | BM25 (Okapi k₁=1.6, b=0.75) + ATT&CK-BERT, fused `rank = min(rank_BM25, rank_dense)` |
| Candidate set | **k=5** (swept 2–8; 5 optimal) | **k=25** |
| Selector | LLM Validator ranks/filters candidates | Ministral-8B, LoRA SFT + GRPO |
| Result | F1 **82.28%** on CTI-ATE; **73.43%** with the Validator removed | best avg F1 on 4 benchmarks; +7.4 pp sub-technique F1 over Claude Sonnet 4.5 + RAG |

Both replace "embed and threshold" with **retrieve a candidate set, then have a
model select from it**. Neither treats the encoder as the thing to optimise.

Three details are worth lifting verbatim:

- **Retrieval recall is a first-class, reported number** because it caps everything
  downstream: 97.3% / 96.9% / 89.7% / 78.6% across RCPO's four benchmarks. Stage 2c
  has two uninstrumented recall caps — the `_has_ttp_keyword` allow-list of ~70
  strings, which decides *which sentences are embedded at all*, and
  `_MAX_CANDIDATES=200` strided sampling, which drops sentences on long reports.
  Measured on the two real reports in `cti_stix.db`
  (`scripts/probe_ttp_recall_caps.py`):

  | report | sentences | kept by keyword | scored | kept % |
  |---|---|---|---|---|
  | GREYVIBE (WithSecure) | 242 | 43 | 43 | 17.8 |
  | ShinyHunters (Mandiant/GTIG) | 235 | 34 | 34 | 14.5 |
  | **total** | **477** | **77** | **77** | **16.1** |

  **The keyword gate discards 83.9% of all sentences before a single embedding is
  computed.** No threshold, encoder or margin change can recover them. The
  `_MAX_CANDIDATES` cap, by contrast, discarded **zero** sentences on both reports —
  it only binds above roughly 1,200 sentences at this keyword-hit ratio, so it is a
  latent rather than an active cap: instrument it, but do not prioritise it.

  A third defect surfaced while reading the discarded sentences: on PDF-extracted
  text `_split_sentences` yielded line-wrap fragments rather than sentences ("AI
  across state-aligned operations -", "vulnerability (CVSS 9.8) in the Environment
  Management component"), because its regex treated every newline as a sentence
  boundary. **Phase 2 measurement inverted the obvious fix:** the ingested corpus
  carries **237 `\n\n` runs against 2 single `\n`** — every hard-wrapped PDF line
  arrives *doubled*, so a rule that protects "two or more newlines" as paragraph
  breaks protects exactly the newlines that need joining (477 segments before,
  475 after: no effect). Deciding on content alone, ignoring run length:

  | | before | after |
  |---|---|---|
  | segments | 477 | 195 |
  | median length | 68 chars | 155 chars |
  | **ending in `.!?`** | **128/477 (27%)** | **158/195 (81%)** |

  The share of segments that actually end like a sentence is the quality signal.
  With properly-formed sentences the keyword gate's cost also drops from 83.9% to
  **68.2%** — the earlier figure partly measured the splitter, not the gate.
- **Over-prediction is the LLM failure mode, and it is measurable by label count.**
  Claude Sonnet 4.5 holds recall above 67% but drops to 28% precision, emitting 4.2
  labels per sample against a gold mean of 1.7. Conversely token-level fine-tuning
  over-corrects: TechniqueRAG reaches 75.2% precision on the Expert set at 37.7%
  recall, emitting 1.01 labels per sample where gold averages 3.32. Mean predicted
  labels vs. gold is a one-line diagnostic that names which failure you have.
- **Procedure examples are the right retrieval corpus, and we already have them.**
  `scripts/build_indexes.py:180` embeds `obj["description"]` — the taxonomy prose
  ("Adversaries may attempt to…"). `data/enterprise-attack.json` also carries
  **18,215 `uses` relationships with prose descriptions** — real procedure sentences
  ("*Indrik Spider* used *Cobalt Strike* to carry out credential dumping…") written
  in the same register as report text. They are on disk, unused, and free.

### Datasets

The current harness targets CTIBench ATE. The SoK rejects datasets of that shape
for this task: CTI-to-MITRE and Kumarasinghe et al. *"lack sentences without
techniques, which is relevant for replicating a realistic evaluation scenario"* —
without negative sentences, precision is unmeasurable. It selects **TRAM2** (50
techniques, sentence + document labels, 19,011 sentences) and **AnnoCTR** (133
techniques). RCPO uses a four-set suite (TRAM, Procedures, Derived Procedures,
Expert) at `github.com/tumeteor/mitre-ttp-mapping`, of which **Expert** —
paragraph-level, five expert annotators, 3.32 labels/sample — is the closest
analogue to what CTIParsor actually ingests. CTI-ATE stays useful as the
comparison point against Multi-Step's 82.28%, but it labels **parent techniques
only**, which is precisely the regime the partial-credit bug corrupts.

## Options considered

### Option A — Fix the ruler, then tune the existing stage

| Dimension | Assessment |
|---|---|
| Complexity | Low |
| Cost | ~2 delegations, no new runtime deps |
| Ceiling | Capped at ~13% F1 by the SoK's all-techniques row |
| Risk | None; strictly improves what we can see |

**Pros:** every later decision becomes falsifiable; catches the inert margin gate
and the keyword/candidate recall caps.
**Cons:** cannot lift Stage 2c past the architectural ceiling. Tuning thresholds on
a method the field measured at 7–9% precision is polishing the wrong surface.
**Verdict:** necessary, insufficient. Mandatory prerequisite for everything else.

### Option B — Reproduce TTP-R1 (retrieval + SFT + GRPO) on the GB10

| Dimension | Assessment |
|---|---|
| Complexity | High |
| Cost | LoRA SFT + GRPO training infra; 16,780 labeled samples |
| Ceiling | Best published |
| Risk | High — needs labeled training data we do not have |

**Pros:** state of the art; 8B on one GPU matches the hardware exactly; 0.34 s/query.
**Cons:** the RL stage buys **3.4% relative** over its own SFT baseline — the
retrieval and SFT stages carry the result. Training requires a labeled corpus and a
training loop this project has never had.
**Verdict:** out of scope now. Revisit only if Option C lands and plateaus.

### Option C — Retrieve-then-validate, reusing Stage 3f

| Dimension | Assessment |
|---|---|
| Complexity | Medium |
| Cost | Reuses the Stage 3f verifier and the existing embedding cache |
| Ceiling | Multi-Step reports 82.28% with exactly this shape and no fine-tuning |
| Risk | Medium — moves Stage 2c from detector to candidate generator |

**Pros:** the two components already exist in the codebase and are currently wired
backwards. Stage 2c already computes a full similarity matrix and discards
everything below rank 1; Stage 3f already asks an LLM to justify a technique with a
quoted sentence. Turning 2c into a k-candidate generator and 3f into a selector is
a re-wiring, not a new subsystem. Multi-Step's ablation prices the validator at
**+8.85 F1** (73.43 → 82.28).
**Cons:** techniques stop being detectable offline — the semantic stage alone no
longer decides. Requires an explicit "no provider" degradation path.
**Verdict:** the target architecture.

## Decision

Adopt Option A as Phases 1–3, then Option C as Phases 4–6. Ship each phase behind
its own measurement; do not proceed on a phase whose predecessor did not move a
number.

| Phase | Change | File(s) |
|---|---|---|
| **1** | Replace fractional partial credit with **dual-granularity scoring**: `technique_level` (truncate all IDs to parent, exact match) and `subtechnique_level` (exact match only). Switch aggregation from corpus-micro to **per-document macro**. Add `mean_labels_predicted` / `mean_labels_gold` to every report. Regression tests must be verified by re-introducing each defect. | `tests/eval_pipeline.py` |
| **2** | Instrument the recall caps (`scripts/probe_ttp_recall_caps.py` measures 83.9% of sentences discarded by the keyword gate, 0% by the candidate cap) and report `sentences_total / kept_by_keyword / scored` plus `retrieval_recall@k` as first-class benchmark outputs. Add `TTP_KEYWORD_GATE=off` to price the gate against Phase 1's baseline. Fix `_split_sentences` fragmenting PDF-extracted text. | `pipeline/stage2c_ttp_semantic.py`, `tests/eval_pipeline.py` |
| **3** | Acquire and wire **TRAM2** + **AnnoCTR** (SoK splits) and the **Expert** set (RCPO); keep CTI-ATE for the Multi-Step comparison. Record a baseline table: per-dataset, both granularities, at technique-subset sizes 10/25/50/all. | `tests/eval_pipeline.py`, `scripts/` |
| **4** | Re-embed against **ATT&CK procedure examples** (18,215 `uses` descriptions already in `data/enterprise-attack.json`) alongside technique descriptions; a procedure hit resolves to its `target_ref` technique. Manifest-versioned so caches invalidate. | `scripts/build_indexes.py`, `pipeline/stage2c_ttp_semantic.py` |
| **5** | Add **BM25 lexical retrieval** fused with the dense scores by `rank = min(rank_bm25, rank_dense)`, and expose `detect_ttp_candidates(text, k)` returning the top-k set. Sweep k ∈ {5, 10, 25}. Encoder candidate is **ATT&CK-BERT**, not SecureBERT-Plus. | `pipeline/stage2c_ttp_semantic.py` |
| **6** | Re-wire Stage 3f from *post-hoc verifier* to **selector over the k-candidate set**, constraining output to the candidate IDs. Offline path unchanged: with no provider, fall back to today's threshold behaviour. | `pipeline/stage3f_ttp_verify.py`, `pipeline/stage3c_mitre.py` |

Phase 1 is a prerequisite for reading any other phase's result. Phases 4 and 5 are
independent of each other and can be measured separately.

### Phase 2 result — the retrieval ceiling is already high; rank-1 throws it away

With the splitter fixed and the gates instrumented, `--retrieval-recall 1,5,10,25`
on the ATE fixtures (all-MiniLM-L6-v2, ATT&CK-only corpus):

| k | technique recall | sub-technique recall |
|---|---|---|
| 1 | 0.533 | 0.533 |
| 5 | 0.700 | 0.667 |
| 10 | 0.833 | 0.700 |
| **25** | **0.967** | **0.867** |

Production runs at **k=1** and scores F1 0.550. The retriever finds **96.7%** of
gold techniques at k=25 — the pipeline discards roughly 43 points of attainable
technique recall by never looking past rank 1. This is the same shape RCPO
reports (97.3% / 96.9% at k=25) and it is the measured, local case for Phases 5-6:
the retrieval is not the weak part, the single-match gate on top of it is.

**Caveat, stated plainly: n=10, and they are hand-written fixtures.** A fixture
invented by hand can validate behaviour that reality never produces, so this curve
is a strong hypothesis, not a result. Phase 3 must re-measure it on TRAM2 and the
Expert set before any of Phases 4-6 is justified by it.

Phase 2 also left a known cost for Phase 3: `run_retrieval_recall` runs one
embedding pass per (sample, k). A monotonicity early-exit was written and then
removed, because skipping a larger k reuses the smaller k's candidate set and
reports the wrong `mean_candidates`. On TRAM2 (19,011 sentences) four k values
therefore cost four passes; Phase 5's ranked candidate API removes that honestly.

## Consequences

- **Easier:** every subsequent TTP decision becomes falsifiable against published
  baselines rather than reasoned. The recall caps become visible instead of silent.
  Retrieval and selection separate cleanly, so the encoder, k, and the selector can
  each be swapped without touching the others.
- **Harder:** Stage 2c stops being a standalone offline detector — full-quality TTP
  extraction gains a provider dependency (Phase 6 keeps an offline fallback, but it
  is the weaker path). The embedding cache grows by the procedure corpus. Benchmark
  numbers produced before Phase 1 are not comparable to anything after it and should
  be discarded, not migrated.
- **Expectations:** the SoK's ~70% F1 ceiling and AnnoCTR's 31% inter-annotator
  agreement mean this work should target *measured, comparable* numbers in the
  60–80% band on the multi-label sets — not "accuracy" in the abstract. A phase that
  moves nothing is a valid, reportable result.
- **Revisit:** ADR-0011's `TTP_TOP2_MARGIN` becomes live for the first time under
  Phase 5 (k>1). Its default was never calibrated against a working gate and must be
  swept, not inherited. If Phase 6 plateaus well below Multi-Step's 82.28%, Option B
  (SFT on the GB10) becomes the next question, with retrieval already in place.

## Related

Pays ADR-0011's unpaid measurement debt and corrects its Phase A specification (the
`top_k=1` + margin-gate contradiction). Supersedes ADR-0004 P1-A's SecureBERT-Plus
recommendation for the *unlabeled similarity* setting. Uses the evidence-quoting
discipline of ADR-0009 / ADR-0012 as the Phase 6 selector contract.

**Sources.** Büchel et al., *SoK: Automated TTP Extraction from CTI Reports — Are We
There Yet?* (Tables 4, 6, 7; §3.2, §3.3, §9) · Kim et al., *Multi-Step LLM Pipeline
for Enhancing TTP Extraction in CTI*, IEEE Access 13 (2025) (§V, Table 9) · Zhang
et al., *Retrieval-Constrained Policy Optimization for Attack Technique Extraction
from CTI*, AWS (§4.1–4.6).
