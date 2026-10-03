# Evaluation protocol

How CTIParsor's extraction is measured (ADR-0060). The code is in
`evaluation/`; results are written to `data/eval/` (git-ignored); the numbers
worth keeping are copied into `docs/eval/baseline-*.md`.

## Two gold sets, two questions

| | AnnoCTR (public) | In-house set |
|---|---|---|
| What it measures | reading a clean text: techniques (explicit and implicit), malware, groups, tools, locations, sectors | the application on the original file: IoCs, relationships, ingestion losses, negative cases |
| Size | 120 reports with the cyber layer: 70 train / 16 dev / 34 test | 10 to 20 reports to start (a pilot, not a verdict on small gains) |
| Not measured | IoCs, relationships, PDF/OCR/tables | — |
| Guide | the AnnoCTR guidelines (in its repository) | [annotation-guide.md](annotation-guide.md) |

AnnoCTR facts that shape the protocol (checked against the paper, §3.1, §5.1,
tables 3 and 10, and the repository):

* the official split is **temporal**, with every vendor in every split — kept
  as is; a vendor-held-out split would be another protocol, reported apart;
* the 280 general-layer-only reports are **not** reports without techniques
  and are never scored for TTPs;
* techniques are annotated almost only at the **parent** level (17 sub-technique
  ids among 1,067 document-level labels): the primary TTP score is at parent
  level, exact ids are reported alongside;
* mentions come with context, not offsets; all 3,337 technique mentions are
  located back in the text by `evaluation/annoctr.py`;
* **ids written in a vendor's own ATT&CK table are mostly not annotated**: on
  dev, 15 of the 23 technique ids that appear verbatim in the reports are
  absent from the gold, so predicting them counts as a false positive. `score`
  therefore adds a sensitivity row, "gold + ids written in the report". The
  primary score stays the official gold; read both.

## Setup

```bash
git clone --depth 1 https://github.com/boschresearch/anno-ctr-lrec-coling-2024 data/annoctr-repo
python scripts/download_attack.py          # current ATT&CK, for the id mapping
python -m evaluation prepare               # layer registry, ATT&CK mapping, near-duplicates
```

`prepare` writes, in `data/eval/`:

* `annoctr-registry.json` — per report: split, vendor, date, annotated layers,
  what can be scored;
* `attack-mapping.json` — every gold technique id against the current ATT&CK
  and the pipeline's index. Predictions go through the same mapping, so a gold
  T1562 and a predicted T1562 both become T1685 (revoked in 2026);
* `near-duplicates.json` — copies and excerpts across splits (and any
  `--corpus` folder, e.g. a Phase 4 retrieval corpus).

## What `run` scores

`run` disables Stages 1f, 4 and 5 and scores the pipeline's own lists —
`result.entities` for IoCs and the detectors' names, the LLM's
`malware_families` / `threat_actors` / `tools` / `ttps` — not a bundle. So the
October 2026 audit's CLI defect (detector names dropped at Stage 4, fixed by
`pipeline/named_entities.py`) never touched these numbers, and the entity
precision reported here is the union of the detectors before Stage 4 — which
is neither the CLI's bundle nor the worker's. `inhouse-run` is the exception:
Stage 4 stays on and relationships are scored as the bundle ships them.

## Running and scoring

```bash
# fixed sampling: two runs of the same configuration then give the same result
export LLM_TEMPERATURE=0 LLM_SEED=13

# the application's pipeline (Stages 1-3, LLM required) on the dev split
python -m evaluation run --split dev --name t0-dev
python -m evaluation score --name t0-dev

# a variant: a stage off, another model...
python -m evaluation run --split dev --name t0-no2c-dev --disable 2c
python -m evaluation compare --a t0-dev --b t0-no2c-dev              # paired bootstrap, TTPs
python -m evaluation compare --a t0-dev --b t0-no2c-dev --task malware

# candidate recall (the ceiling of any retrieval-based TTP step), no LLM —
# per passage, per document and per chunk (ADR-0072)
python scripts/build_indexes.py --only retrieval     # corpus of the select path
python -m evaluation retrieval --split dev --corpus short,both --method dense,rrf \
    --gate on,off --k 1,5,10,20,25 --chunk 5:25,10:25

# the select path (Stage 2c retrieves, Stage 3f selects with a quote)
TTP_MODE=select python -m evaluation run --split dev --name sel-dev

# 50 quotes for a person to judge (does the passage show the technique used?)
python -m evaluation support-sample --name baseline-dev
```

`retrieval` reports, per corpus × retriever × keyword gate: recall per
passage (the technique is in the top-k of a passage carrying one of its
annotated mentions), per window (that passage or a neighbour), per document,
at parent level and exact id; the distinct candidate ids per document; where
each miss was lost (gate, rank, elsewhere); with `--chunk k:cap`, the recall
of the capped candidate lists the selector actually gets. Procedure examples
MITRE wrote from an AnnoCTR report are left out (`--keep-cited` keeps them);
`run` does the same for the select path through
`TTP_RETRIEVAL_EXCLUDE_CITED`. Results: ADR-0072.

A run is resumable (one file per report) and stops at once if the LLM cannot
run — including when every call fails, e.g. a model name the server does not
serve (Stage 3 is then `failed`, not an empty success).

`score` reports, per run:

* **TTPs** — parent-level micro P/R/F1 (primary), per-document average,
  exact-id micro, recall of explicitly vs only-implicitly annotated techniques;
* **entities** — per type, strict (partial name = FP + FN) and lenient;
* **evidence** — three separate questions: the quote *exists* in the text; for
  a correct technique it lies *on* (or *near*, ≤ 200 characters) a passage the
  annotators marked; whether it *supports* the claim is only answered by the
  human-judged `support-sample`;
* which stages ran, were skipped or failed, and seconds per report.

## Ablations

One stage off at a time, on **dev only**, fixed sampling (about 1 h 30 per run with the local
Qwen server — see ADR-0060 for the budget):

```bash
for s in 2b 2c 2d 2e 2g 3d 3f; do   # 3e and 3doc are off unless enabled
  python -m evaluation run --split dev --name abl-$s-dev --disable $s
  python -m evaluation compare --a t0-dev --b abl-$s-dev
done
```

Contributions do not add up: two extractors can cover for each other. When
two ablations both look harmless, run them together before concluding either
stage is useless.

## Deciding (fixed before any comparison on test)

A change to the TTP path is adopted when, on **dev**:

1. the paired-bootstrap 95% interval of the parent-level F1 difference
   excludes 0, **and** the observed gain is at least **+0.02 F1**;
2. precision does not drop by more than **0.02** (a recall gain paid for in
   false positives is analyst time);
3. the gain is larger than the run-to-run spread of the baseline (two runs of
   the same configuration, see below). With the provider's default sampling
   that spread was **+0.028 F1** — larger than rule 1's +0.02. With
   `LLM_TEMPERATURE=0 LLM_SEED=13` two runs were identical (spread 0), so
   **evaluation runs use those settings** and one run per configuration is
   enough (docs/eval/baseline-2026-09.md);
4. seconds per report grow by at most **25%**, or the cost is accepted
   explicitly.

The winning configuration is then frozen and run **once** on test; the test
number is reported, never tuned against. These thresholds are proposals
(ADR-0060) — change them before a comparison, never after.

## Run-to-run spread

Stage 3 sends no temperature unless `LLM_TEMPERATURE` is set, so the provider's
own sampling applies (vLLM: the model's generation config) and two runs of one
report can differ — by 0.028 F1 on dev. **Run evaluations with
`LLM_TEMPERATURE=0 LLM_SEED=13`**: two such runs were identical. With another
provider or model, check it once — run the baseline twice (`--name
baseline-dev-r2`) and `compare` the two; the interval is the noise floor.

## Deferred (second tier)

* a second, independent annotator on 3 to 5 in-house reports (`agreement`);
* active review time in the review page (visible, focused time only, not
  tabs left open), next to the number of edits — a system that extracts
  little would otherwise look cheap to review.
