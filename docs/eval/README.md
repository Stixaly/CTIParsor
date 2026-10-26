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
python scripts/download_attack.py --release 19.2   # the bundles of the default track, for the id mapping
python scripts/download_attack.py --release 20.0   # only to map against, or run on, the v20 track
python -m evaluation prepare               # layer registry, ATT&CK mapping, near-duplicates
```

`--release X.Y` downloads the three bundles (Enterprise, Mobile, ICS) of that
release of mitre-attack/attack-stix-data into `data/attack-stix/vX.Y/` and
checks each against the sha256 GitHub publishes. Without `--release` the
script fetches `enterprise-attack.json` from the master branch of mitre/cti,
which is the latest release (20.0 on 2026-10-18). The default track's mapping
refuses that file: it looks for the release's Enterprise bundle by sha256
(`data/enterprise-attack.json` at `f7eaf37f…`, or
`data/attack-stix/v19.2/enterprise-attack.json` at `dc1639…`), never by name,
and says what to download when neither is there (ADR-0087).

`prepare` writes, in `data/eval/`:

* `annoctr-registry.json` — per report: split, vendor, date, annotated layers,
  what can be scored;
* `attack-mapping.json` — every gold technique id against the default track's
  ATT&CK release (19.2) and the pipeline's index of that track. Predictions go
  through the same mapping, so a gold T1562 and a predicted T1562 both become
  T1685 (revoked in 2026). `prepare --attack-release 20.0` writes
  `attack-mapping-20.0.json` instead: one file per release;
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

# where the technique errors arise: never retrieved / retrieved, not selected /
# false positives from the candidates or from outside them -> runs/<name>/ttp-errors.json
python -m evaluation ttp-errors --name sel-dev

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

## ATT&CK releases (ADR-0087)

The gold is annotated with the ATT&CK of 2022. It is mapped through the
`revoked-by` chains of one release, and predictions go through the same
mapping. The release a run's pipeline read is in its manifest
(`run.json`, `manifest.attack.release`; `ATTACK_RELEASE` selects it,
[docs/configuration.md](../configuration.md#attck-release)). A run from before the
manifest recorded it has no `attack` block and is mapped on the default track.

```bash
# the gold mapped against another release (default: the run's own)
python -m evaluation prepare --attack-release 20.0              # attack-mapping-20.0.json
python -m evaluation score --name sel-dev --attack-release 20.0
python -m evaluation ttp-errors --name sel-dev --attack-release 20.0
ATTACK_RELEASE=20.0 python -m evaluation retrieval --split dev   # corpus and mapping of the v20 track

# a run on the v20 track, and the two compared
ATTACK_RELEASE=20.0 python -m evaluation run --split dev --name sel-dev-v20
python -m evaluation compare --a sel-dev --b sel-dev-v20 --attack-release 20.0

# what changed between two releases, then how much of two runs' difference that explains
python -m evaluation attack-diff --old 19.2 --new 20.0
python -m evaluation release-effect --a sel-dev --b sel-dev-v20 --attack-release 20.0
```

* `score` and `ttp-errors` map with the run's release unless `--attack-release`
  names another; then the result goes to `score-attack-<X.Y>.json` or
  `ttp-errors-attack-<X.Y>.json` beside the usual file, and the report carries
  an `attack_mapping` block (release, bundle hash).
* `retrieval` reads the corpus of the track `ATTACK_RELEASE` selects, and maps
  the gold with that release unless `--attack-release` names another.
* **`compare` needs the same mapping on both sides.** Without the option it uses
  the release of the two runs if they share one. If they differ, it stops and
  asks for `--attack-release`. With the option, the output file gets an
  `__attack-<X.Y>` suffix. `release-effect` follows the same rule.
* `run` and `inhouse-run` resume only on the release the run began with. An
  unknown `ATTACK_RELEASE` stops the command before any document, and another
  valid one is refused with a message (a run from before the manifest recorded a
  release is on the default track). `inhouse-score` maps with the run's release.
  `python -m evaluation` reads `.env` first, as `main.py` does.
* When a run's manifest lists `attack.modified_files` (a rebuilt file, or a file
  its track's manifest does not know), `score`, `ttp-errors`, `compare` and
  `release-effect` warn on stderr and put them under `attack_modified_files` in
  the report. The score is still computed.
* The mapping's Enterprise bundle is found by sha256, from `data/`
  (`data/attack-stix/vX.Y/` for a release other than the default's).
* `attack-diff --old --new` reads the three bundles of each release in
  `data/attack-stix/` and writes `data/eval/attack-diff-<old>-<new>.json`. Per
  domain: techniques that became active or stopped being (with the id that
  replaced a revoked one), renamed ones, changed descriptions or tactics,
  procedure examples (a non-revoked `uses` relationship with a description), and
  the same for software, groups and campaigns. 19.2 → 20.0: Enterprise 697 → 706
  active techniques, none revoked, deprecated or renamed, 31 descriptions
  changed.
* `release-effect` works at parent-technique level. `--old` and `--new` default
  to the releases the two runs ran on; an option has to be the release of the run
  it stands for, and two runs on the same release need both. It classes each
  parent on which the two runs differ, the first class that applies:

  | Class | The parent, between `--old` and `--new` |
  |---|---|
  | `new_technique` | was not active, is now |
  | `new_subtechnique` | is active in both; a sub-technique is new |
  | `status_changed` | was revoked or deprecated, or one of its sub-techniques was |
  | `content_changed` | has another name, description or tactics, or more procedure examples, or one of its sub-techniques does |
  | `unchanged` | none of the above |

  Per class it gives the number of ids and of differences, and the **hybrid**:
  run A with only that class's differences taken from run B. ΔTP, ΔFP and ΔFN
  are the hybrid's counts minus run A's, and the hybrid F1 is its micro F1.
  The overall ΔTP, ΔFP and ΔFN are run B minus run A. It also lists the
  documents where the entities the gazetteer found, or the candidate lists,
  differ between the two runs: on those, the difference is not the taxonomy's
  alone. Output: `data/eval/compare/<a>__vs__<b>__release-effect.json`.

Reading a 19.2 / 20.0 comparison on this gold:

* v20 revokes no Enterprise technique, so the gold maps the same under 19.2 and
  under 20.0.
* An id new in v20 cannot be in the gold. A T1698 prediction counts as a false
  positive. A T1685.007 prediction can be a true positive at parent level,
  because its parent T1685 is in the gold.
* The 39 name variants the 20.0 gazetteer has beyond the default track's (14
  of 19.2, 25 of 20.0) appear in none of the 16 dev reports (case-insensitive,
  word boundaries).
* The paired comparison of the two tracks on dev, and how its difference splits:
  [attack-v20-2026-10.md](attack-v20-2026-10.md).

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

Moving the default ATT&CK release (19.2 to 20.0) is a change like any other:
this rule, paired, on dev (ADR-0087). The test split is not consulted for it.

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

## Measurement notes

Measurement pages that the sections above do not link:

- [baseline-2026-09.md](baseline-2026-09.md) — the shipped pipeline on the AnnoCTR dev split (16 reports), the reference that later changes are compared with.
- [baseline-2026-10.md](baseline-2026-10.md) — the LLM selector (`TTP_MODE=select`, ADR-0072) against the best configuration measured so far, on dev; the test split is run once.
- [gazetteer-policy-2026-10.md](gazetteer-policy-2026-10.md) — Stage 2b with and without the gazetteer's ordinary-word policy, on AnnoCTR train and dev.
- [ner-precision-2026-10.md](ner-precision-2026-10.md) — the CyNER and spaCy precision filters (ADR-0088), designed on train and measured on dev; two adopted.
- [ner-malware-2026-10.md](ner-malware-2026-10.md) — one malware-precision lead, measured once on AnnoCTR test (2026-10-19): not adopted.
- [selection-cut-off-2026-10.md](selection-cut-off-2026-10.md) — Stage 3f selection answers cut off at `LLM_MAX_OUTPUT_TOKENS` on dev, and the fix that keeps their complete choices (technique F1 0.584 → 0.610).
- [selection-loop-2026-10.md](selection-loop-2026-10.md) — the Stage 3f selection loop (about one call in 65 on AnnoCTR dev) and three changes measured against it.
- [selection-once-2026-10.md](selection-once-2026-10.md) — a sentence added to the selection prompt, "write that object once, then stop", as a follow-up to selection-loop-2026-10.

## Deferred (second tier)

* a second, independent annotator on 3 to 5 in-house reports (`agreement`);
* active review time in the review page (visible, focused time only, not
  tabs left open), next to the number of edits — a system that extracts
  little would otherwise look cheap to review.
