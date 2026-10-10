# ADR-0072: TTPs — retrieve candidates from ATT&CK procedures, ship only what a selector can quote

**Status:** Accepted — select mode is **the default** since its dev run of 2026-10-03 (see "Outcome" at the end, and docs/eval/baseline-2026-10.md)
**Date:** 2026-10-03
**Deciders:** maintainer
**Implements:** ADR-0023 Phases 4–6 (procedure corpus, BM25 + dense, selector)

## Context

An outside roadmap (2026-10-02) proposed six steps to bring technique
extraction closer to retrieve-then-select systems (TechniqueRAG, TTP-R1):
P0 a reproducible baseline and error review, P1 separate "candidate" from
"confirmed technique", P2 index ATT&CK procedure examples, P3 hybrid BM25 +
dense retrieval with rank fusion, P4 a strict selector that may abstain, P5
decide on comparable numbers. Most of it is ADR-0023's open Phases 4–6. Each
factual claim was checked against the tree and the data before acting.

**Confirmed.**

* Stage 2c is the main TTP false-positive source: 55% of predicted
  techniques at 0.16 precision, and switching it off lifts dev F1 from 0.339
  to 0.488 (docs/eval/baseline-2026-09.md).
* Stage 3f fails open: a failed or unparseable call keeps every claim, and a
  claim the answer omits defaults to verified (`stage3f_ttp_verify.py`).
* The current Enterprise bundle carries **17,136** `uses` relationships to an
  active technique with a description — the roadmap's count. ADR-0023's 18,215
  came from another bundle (this one has 18,457 `uses` in all).

**Not in the roadmap, found on the way.**

* Stage 2c reaches the output through three doors, not one: its matches are
  Stage 2 entities; Stage 3c seeds every high-confidence match *and adds every
  medium one the LLM did not cover*; and the Stage 3 prompt lists all of the
  document's semantic TTPs to every chunk as "already detected — DO NOT
  re-extract", so a wrong match also suppresses the LLM's own answer.
* The legacy embedding cache embeds each technique's name and the **first 300
  characters** of its description (`build_mitre_index` truncates, and
  `build_embeddings` reads the truncated index).
* **48 procedure examples cite AnnoCTR reports** (28 from test reports, 20
  from train, none from dev). A retrieval corpus that keeps them hands the
  retriever sentences MITRE wrote from the report being scored.
* The keyword allow-list drops the passage carrying **36% of the annotated
  technique mentions** on dev (64% kept; 99% with the gate off).
* T1105 has 520 procedure examples, the median technique 7, and 86 active
  techniques none: ranking examples instead of techniques would let the
  first crowd the list.

## Decision

### 1. A versioned procedure corpus (P2)

`python scripts/build_indexes.py --only retrieval` builds
`pipeline/data/attack_retrieval_corpus.json` and its embeddings (git-ignored,
~35 MB): one `description` entry per active technique (name + **full**
description) and one `procedure` entry per distinct `uses` example. Links
become their label, citations and tags are removed, duplicates (same
technique, same cleaned text) are one entry. Actor, software and campaign
names are replaced by placeholders by default (`--keep-names` keeps them).
Each procedure keeps the URLs it cites; the manifest records the bundles'
sha256, the model and the options. 697 descriptions + 16,653 procedures
(17,136 before the name-neutral dedup).

### 2. Hybrid retrieval over techniques, not examples (P3)

`pipeline/ttp_retrieval.py` ranks techniques for a passage with dense cosine,
Okapi BM25 (k1 1.6, b 0.75, written here: no new dependency), their
min-rank fusion (TTP-R1) or reciprocal rank fusion. Entries are grouped by
technique first — a technique scores its best example — so `k` counts
distinct ids. Passages are Stage 2c's sentences with their offsets kept
(`split_passages`, tested equal to `_split_candidate_sentences`), so an
annotated mention or a quote can be placed in one.

### 3. The contract: a candidate is not a technique (P1)

`TTP_MODE=select` changes what Stage 2c produces: a `TtpCandidate` list per
chunk (id, passage and offsets, sources, dense / BM25 / fused ranks, the
example that ranked it), stored on the run, never an entity, never in the
bundle, never in the Stage 3 prompt. Stage 3c therefore seeds nothing from
2c. Without an LLM, select mode falls back to the old detector and the 2c
stage report says "offline fallback … unvalidated semantic matches, less
reliable". `TTP_MODE=verify` (the default) is today's pipeline, unchanged.

### 4. A selector that validates in code (P4)

In select mode Stage 3f makes one call per chunk with the chunk text (whole)
and its candidates: the retrieved ones (capped) plus **the Stage 3 LLM's own
proposals, never cut** — the LLM finds techniques retrieval misses, and the
2c-off configuration's recall must not be lost. The prompt asks for the
candidates the text shows being *used*, several or none, each with an exact
quote and a reason, and lists near-negatives (a tool only named, an ATT&CK
table, a recommendation, a capability, a denial, outside knowledge of the
group); a retrieved procedure is labelled "other report, not evidence". The
code then keeps an answer only if it is JSON of the expected shape, the id is
a candidate, the quote is in the chunk (whitespace and case aside, ≥ 3
words), once per id. A failed or unparseable call ships nothing: every
candidate goes to `ttp_review`, the stage report says so, and 3f is `failed`
when no call answered. `--disable 3f` in select mode lets the LLM's techniques
through unchecked and drops the retrieved ones — the "no selector" ablation.

### What was not taken from the roadmap, and why

* **ATT&CK ids a vendor writes in its own table are not sent to the
  selector.** The roadmap lists "an ATT&CK table" as a negative. AnnoCTR
  leaves 15 of 23 such ids unannotated, so dropping them would raise its
  precision; but a vendor's mapping table is the vendor stating the technique
  was used, which an analyst wants. That is a product decision, left as it
  is (the regex path is unchanged in both modes); `score`'s "gold + ids
  written in the report" row keeps both readings visible.
* **One selector call per chunk, not per passage.** Per passage would cost
  ~60 calls per dev report against today's ~5 for 3f, far past the decision
  rule's +25% time budget. The chunk is sent whole, each candidate says which
  sentence retrieved it, and the list is capped.

## Results — retrieval on AnnoCTR dev (no LLM)

`python -m evaluation retrieval` (rewritten): 16 reports, 129
(document, technique) gold pairs, all 445 technique mentions located;
procedures citing an AnnoCTR report excluded (no effect on dev, as expected).
Parent level. *Passage* = the technique is in the top-k of a passage carrying
one of its annotated mentions; *doc* = in the union over the document (the
old unit); *ids/doc* = distinct candidate ids per document.

| Corpus | Retriever | Gate | passage k=5 | k=10 | k=25 | doc k=5 | ids/doc k=5 |
|---|---|---|---|---|---|---|---|
| short (today) | dense | on | 0.333 | 0.411 | 0.566 | 0.574 | 47 |
| description | minrank | on | 0.488 | 0.558 | 0.643 | 0.659 | 44 |
| procedure | dense | on | 0.543 | 0.651 | 0.736 | 0.775 | 38 |
| both | rrf | on | 0.667 | 0.736 | 0.845 | 0.830 | 36 |
| both | rrf | off | **0.767** | **0.845** | **0.946** | 0.907 | 71 |
| both, names neutral | rrf | off | 0.736 | 0.853 | 0.961 | 0.930 | 74 |

* `short`/dense/gate on reproduces the previous command exactly (doc recall
  0.225 / 0.574 / 0.806 at k = 1 / 5 / 20).
* **Procedures are the largest single gain** (passage recall at k=5 from 0.33
  to 0.54 with the same dense retriever); BM25 alone on procedures does better
  than dense (0.63 at k=5), and fusing the two adds more — RRF beats min-rank
  here (0.77 against 0.68 at k=5, gate off), the reverse of TTP-R1's choice,
  whose corpus was annotated CTI sentences rather than ATT&CK's own text.
* **The keyword gate costs 10 points of passage recall** at k=5 for the best
  retriever — but not once the list is capped per chunk (next table).
* The roadmap's target, ≥ 90% parent recall at a reasonable k, is met at the
  document level from k = 5 and per passage from k = 20 (0.930). Exact-id
  recall stays lower (passage 0.49 at k=5, 0.74 at k=25): gold is almost all
  parent ids, and an exact parent id competes with its sub-techniques.
* Neutral names change recall by at most ±0.03 (4 of 129 pairs), in both
  directions — no evidence either way; neutral is the default for the reason
  recall cannot measure (the selector never sees another report's actor).
* Error buckets at k=25 (both / rrf / gate off): 122 found in their passage,
  1 in a neighbour, 5 elsewhere in the report only, 1 passage gated. At k=1,
  39 of 129 are ranked first by no passage of the report although their
  passage is kept.

### What the selector gets: one capped list per chunk

The select path does not see passages: it sends one list per Stage 1 chunk
(`--chunk k:cap`, k candidates per passage merged by technique, at most `cap`
per chunk, best fused rank first). *Local* = the technique is in the list of a
chunk containing one of its annotated passages; *doc* = in some chunk's list.
Both corpora, names neutral, 16 dev reports, 6.3 chunks per report.

| Retrieval | k : cap | local | doc | candidates / chunk |
|---|---|---|---|---|
| short, dense, gate on (today's 2c) | 5 : 25 | 0.450 | 0.519 | 12 |
| both, rrf, gate on | 5 : 25 | 0.783 | 0.876 | 12 |
| both, rrf, gate off | 5 : 25 | 0.767 | 0.861 | 17 |
| both, rrf, gate on | **10 : 40** | **0.861** | **0.954** | **21** |
| both, rrf, gate off | 10 : 40 | 0.861 | 0.923 | 28 |
| both, rrf, gate on | 25 : 40 | 0.884 | 0.961 | 30 |
| both, rrf, gate on | 25 : no cap | 0.954 | 0.992 | 55 |
| both, minrank, gate on | 10 : 40 | 0.829 | 0.915 | 22 |

* **Under a cap the keyword gate helps**: it spends the cap on behaviour
  sentences. The select path keeps it (`TTP_RETRIEVAL_KEYWORD_GATE`, its own
  switch, default on).
* Defaults: both corpora, RRF, 10 per passage, 40 per chunk — 86% of the gold
  techniques reach the selector in their own chunk from retrieval alone, with
  21 candidates per chunk on average (prompts of 16k characters on average,
  25k at most, under the 32k limit; past it the lowest-ranked retrieved
  candidates are dropped, never the text or the LLM's proposals). No cap
  reaches 0.95 but at 55 candidates per chunk.
* **Chunks Stage 3 skips** (no IoC, no known name) never reach the LLM, in
  either mode: on dev 36 of 101 chunks would carry candidates, yet only 5 of
  129 gold techniques (3.9%) appear in skipped chunks alone (measured with
  CyNER and GLiNER off, which overstates skipping). A selection-only call
  for them is opt-in (`TTP_SELECT_SKIPPED_CHUNKS`): 36 calls for 5 pairs is
  outside the time budget by default.

## What remains — the LLM half (P0, P4, P5)

These need the LLM server and were not run here. With `LLM_TEMPERATURE=0
LLM_SEED=13`, on dev:

```bash
python scripts/build_indexes.py --only retrieval
python -m evaluation run --split dev --name t0-dev                       # baseline (verify)
python -m evaluation run --split dev --name t0-no2c-dev --disable 2c     # exact 2c-off size
TTP_MODE=select python -m evaluation run --split dev --name sel-dev
TTP_MODE=select python -m evaluation run --split dev --name sel-noret-dev --disable 2c
python -m evaluation compare --a t0-no2c-dev --b sel-dev
python -m evaluation support-sample --name sel-dev
```

`sel-noret-dev` prices the selector alone (LLM proposals, no retrieval);
`sel-dev` adds retrieval. Select mode becomes the default only if it beats
**the 2c-off run** — the best configuration measured so far — under the
protocol's rule (+0.02 F1, interval excluding 0, precision −0.02 at most,
time +25% at most), then once on test. Each run's record now carries the
candidates and `ttp_review`, so the error review can split a miss into
"never retrieved" and "retrieved, not selected".

## Consequences

* **Easier:** retrieval, corpus and selector can each be measured and
  swapped; the recall ceiling is a reported number per passage and per chunk;
  a technique in select mode always carries a quote that exists.
* **Harder:** a ~35 MB build step for the select path, and a dependency on
  the LLM for full-quality techniques (the offline fallback is the old,
  weaker detector, labelled as such). The evaluation's `run` sets
  `TTP_RETRIEVAL_EXCLUDE_CITED` so a test run never retrieves from MITRE
  examples written from AnnoCTR reports.
* **Not done:** a review UI for `ttp_review` (kept in the result and the
  evaluation record, not yet persisted or shown — done by ADR-0082: stored
  pending as a held `ttp` row, shown in Review); per-passage selection; a
  fine-tuned selector, which the roadmap rightly puts after the prompt-only
  selector plateaus.

## Outcome — the dev run (2026-10-03)

All four runs on `d580e8c`, same server, temperature 0, seed 13
([baseline-2026-10](../eval/baseline-2026-10.md)). Against the 2c-off run,
`sel-dev` lifts parent technique F1 from 0.465 to **0.607** (+0.142, paired
bootstrap 95% interval [+0.061, +0.236]), precision from 0.500 to 0.587 and
recall from 0.434 to 0.628, for +18% time per report: every condition of the
ADR-0060 rule holds, so **select mode becomes the default**. Against the
shipped default re-run on the same code (verify with 2c, 0.330), it is
+0.276 [+0.231, +0.329]. Retrieval puts
123 of the 129 gold techniques among a report's candidates (ceiling 0.954);
the selector now loses most (42 offered, not chosen). Every shipped quote is
found in the text, against 98.2% before.

The gain is retrieval's. Selecting among the LLM's own proposals alone
(`sel-noret-dev`, 0.443) is no better than verify without 2c (−0.021,
interval [−0.085, +0.023]) and loses recall (−0.070); retrieval adds +0.163
[+0.085, +0.267] on top of it. A deployment without the corpus would run
that weaker configuration, so **the corpus is committed** with the default
switch (`pipeline/data/attack_retrieval_*`, ~35 MB, the exact file the dev
run measured), like the other indexes, rather than built at image build or at
bootstrap: a clone and the published image carry it, offline included.
