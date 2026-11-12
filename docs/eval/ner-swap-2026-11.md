# NER seat, November 2026: CyNER, a candidate model, and no cyber NER

**Result.** On AnnoCTR dev and on the in-house set, the pipeline without any
cyber NER (Stage 2d and Stage 2e off) finds almost the same true malware and
threat actors as the shipped pipeline, with at least half the false ones. The
candidate model, put in CyNER's seat, removes some of CyNER's false names but
does no better than having no cyber NER on dev, for about twice CyNER's CPU.
The decision this page supports is ADR-0099.

## Question

1. Is Stage 2d (CyNER) worth what it costs?
2. Does a recent cyber NER model do better in its seat?
3. What happens with no cyber NER at all?

## Setup

**Offline (no LLM).** 2026-11-10, main `afd9ee6`. CPU only (CUDA hidden, 6
torch threads, 12 cores). AnnoCTR dev (16 reports) and the in-house set (8
reports, [inhouse-set.md](inhouse-set.md)). `--disable 2c,3`, with threshold
calibration and entity overrides off (`THRESHOLD_CALIBRATION_ENABLED=false`,
`ENTITY_OVERRIDES_ENABLED=false`).

**End to end.** 2026-11-11, from a detached worktree on `2045763` (between the
two commits, only the version number changes in `pipeline/`). vLLM serving
`Inferact/Qwen3.8-27B-NVFP4`, thinking off, `LLM_TEMPERATURE=0`, `LLM_SEED=13`,
`LLM_PARALLELISM=1`, `TTP_MODE` at its default (select), Stages 3d and 3f and
the document-level relation pass on, `VISION_PROVIDER=none`, ATT&CK 19.2. One
run at a time.

**The candidate.** `attack-vector/SecureModernBERT-NER` (ModernBERT-large,
token classification, 22 labels, MIT licence), safetensors weights only. It
takes CyNER's seat by replacing Stage 2d's loader and label table: MALWARE and
THREAT-ACTOR; in the "alone" variant also TOOL, CAMPAIGN, SECTOR to identity
and LOC to location, with GLiNER and spaCy's NER off. Same 1,600-character
chunks, same 0.70 threshold, same filters, same merge. Its rows keep
`source="cyner"` in the records.

**GLiNER** was silent in every configuration except those marked "repaired":
the defect was found during this measure (ADR-0098).

**Configurations.**

| Name | What runs |
|---|---|
| `base` | the pipeline as it is (CyNER) |
| `none` | CyNER and GLiNER off; spaCy, rules and gazetteer kept |
| `cand` | the candidate in CyNER's seat (malware, threat actor) |
| `cand_all` | the candidate with its other labels, GLiNER and spaCy's NER off |
| repaired | `base` or `cand` with GLiNER repaired (the same six labels, threshold 0.40) |

**Score.** Strict entities, unique names per document and per type, after
merge (the functions of `evaluation`). These scores are not comparable with the
mention-level F1 of a model card.

**The candidate's aggregation** was chosen on dev: `first` against `simple`
(the two aggregation strategies of the token-classification pipeline). Punctuation stuck to a name ("OYSTERFRESH,") was
stripped afterwards on the stored records for the offline "strip" rows, and
inside the pipeline, before the filters, for the end-to-end `cand` run.

## Offline results

Strict, true positives / false positives, all sources after merge.

**AnnoCTR dev (16 reports)**

| Type | `base` | `none` | `cand` (first) | `cand` (simple) | `cand` (first, punctuation stripped) |
|---|---|---|---|---|---|
| malware | 33 / 129 | 27 / 37 | 31 / 64 | 27 / 90 | 32 / 57 |
| threat actor | 14 / 27 | 6 / 6 | 11 / 17 | 6 / 20 | 12 / 13 |

**In-house set (8 reports)**

| Type | `base` | `none` | `cand` | `cand` (stripped) | `cand_all` | `cand_all` (stripped) |
|---|---|---|---|---|---|---|
| malware | 84 / 296 | 23 / 88 | 66 / 237 | 78 / 176 | 66 / 170 | 78 / 109 |
| threat actor | 14 / 46 | 4 / 11 | 14 / 44 | 15 / 38 | 14 / 44 | 15 / 38 |
| tool | 19 / 11 | 19 / 11 | 19 / 11 | 19 / 11 | 32 / 45 | 37 / 36 |
| campaign | 0 / 0 | 0 / 0 | 0 / 0 | 0 / 0 | 4 / 12 | 5 / 8 |

Stripping punctuation moves `base` almost not at all (dev malware 33 / 129
before and after; in-house malware 84 / 295, threat actors 15 / 45).

The seat alone, dev, rows whose source is `cyner`:

| Type | CyNER | Candidate (first) | Candidate (simple) |
|---|---|---|---|
| malware | 7 / 92 | 5 / 27 | 0 / 53 |
| threat actor | 9 / 21 | 6 / 10 | 0 / 14 |

On the in-house set, the seat alone gives CyNER malware 64 / 205 and threat
actors 11 / 38, the candidate 46 / 147 and 11 / 35.

**What the seat's errors are** (in-house set, malware, each false name read
against the gold names):

| | Exact | Partial, same type | Name of another gold type | No gold name |
|---|---|---|---|---|
| CyNER | 77 | 77 | 68 | 47 |
| Candidate, raw | 50 | 96 | 35 | 12 |

CyNER's 47 names with no gold name are mostly generic words ("RAT client",
"malware families", "spyware", "LLMs"). The candidate's partials are mostly
punctuation stuck to a name ("OYSTERFRESH,").

**spaCy PRODUCT proposing malware** (`base` run): 2 correct / 23 false on dev,
2 / 69 on the in-house set.

**GLiNER repaired** (six labels, threshold 0.40, added to `base`):

| Set | Result |
|---|---|
| dev | identity 37 / 30 (none before); location +7 / +4; malware +1 / +17; threat actor +3 / +51, precision 0.34 → 0.16 |
| in-house | campaign 8 / 58 (of 12 gold); threat actor +2 / +47 |

**Names handed to Stage 3's prompt** (malware, threat actor, tool, campaign;
gazetteer and seat sources), and how many are false / correct among malware
and threat actors:

| Set | `base` | `cand` (stripped) | `none` |
|---|---|---|---|
| dev | 194 (131 / 47) | 104 (44 / 44) | 65 (17 / 32) |
| in-house | 394 (268 / 96) | 261 (140 / 91) | 76 (21 / 25) |

**CPU cost of Stage 2d** (wall seconds in the stage, then process CPU seconds):

| Set | CyNER | Candidate | GLiNER repaired (2e) |
|---|---|---|---|
| dev | 304 s / 1,779 | 617 s / 3,675 | 934 s / 5,401 |
| in-house | 150 s / 885 | 319 s / 1,892 | 361 s / 2,134 |

Median per report, in-house: 4.6 s for CyNER, 13.3 s for the candidate. One
205 KB report is about 85 % of Stage 2d's time on dev.

**Peak memory of the process** (offline, GB):

| Set | `base` | `cand` | `cand_all` | `none` |
|---|---|---|---|---|
| dev | 5.6 | 5.9 | 2.9 | 0.7 |
| in-house | 5.4 | 6.5 | 3.4 | 1.4 |

## End to end: AnnoCTR dev

Runs `nerswap-e2e-base`, `nerswap-e2e-cand` and `nerswap-e2e-none`. Strict,
true positives / false positives.

| Type | `base` | `cand` | `none` |
|---|---|---|---|
| malware | 34 / 132 | 34 / 59 | 32 / 46 |
| threat actor | 15 / 31 | 14 / 17 | 14 / 12 |
| tool | 11 / 20 | 12 / 26 | 12 / 28 |
| location | 40 / 36 | 40 / 36 | 40 / 37 |
| identity | 29 / 57 | 29 / 51 | 29 / 51 |

Paired differences (bootstrap over the 16 documents, `evaluation compare`), F1
with the 95 % interval:

| Type | `cand` − `base` | `none` − `base` | `cand` − `none` |
|---|---|---|---|
| malware | +0.1834 [+0.1075, +0.2753] | +0.2153 [+0.1284, +0.3070] | −0.0319 [−0.0969, +0.0378] |
| threat actor | +0.1119 [−0.0025, +0.2582] | +0.1828 [+0.0089, +0.3333] | −0.0709 [−0.2286, +0.0763] |
| tool | −0.0254 [−0.1016, +0.1386] | −0.0419 [−0.1672, +0.1275] | +0.0165 [−0.0563, +0.1249] |
| location | +0.0000 [−0.0086, +0.0096] | −0.0027 [−0.0142, +0.0073] | not reported |
| identity | +0.0136 [+0.0014, +0.0353] | +0.0136 [+0.0022, +0.0357] | not reported |
| technique | +0.0179 [−0.0534, +0.0951] | −0.0010 [−0.0729, +0.0732] | +0.0190 [−0.0182, +0.0599] |

Malware recall: −0.0513 [−0.1163, +0.0645] for `none` − `base`. Technique
recall: −0.0310 [−0.0826, +0.0135] for `cand` − `base`.

Process wall time: `base` 8,038 s, `cand` 8,536 s, `none` 8,547 s. Peak memory:
5.8 GB, 6.1 GB, 1.5 GB.

## End to end: in-house set

Runs `nerswap-e2e-inh-base` and `nerswap-e2e-inh-none`, scored with
`inhouse-score --from run`, micro-averaged. True positives / false positives /
false negatives.

| Layer | `base` | `none` |
|---|---|---|
| malware | 98 / 319 / 6 | 96 / 135 / 8 |
| threat actor | 20 / 58 / 3 | 21 / 28 / 2 |
| tool | 63 / 32 / 56 | 84 / 30 / 35 |
| campaign | 1 / 7 / 11 | 1 / 7 / 11 |
| technique | 146 / 100 / 83 | 141 / 77 / 88 |
| IoC | 160 / 160 / 89 | 160 / 160 / 89 |
| relationship | 46 / 2,547 / 274 | 39 / 1,739 / 281 |

Relationships here are the triples in the run's records, not those of the
exported bundle: they do not compare with
[inhouse-bundle-2026-11.md](inhouse-bundle-2026-11.md).

Process wall time: 18,612 s against 16,526 s (the sum of the per-report
seconds is 18,430 s against 16,325 s). Peak memory 6.1 GB against 2.2 GB. No
interval was computed on this set.

## Reading

- On both sets the LLM finds back almost all the names CyNER brings offline.
  Malware true positives go from 34 to 32 on dev and from 98 to 96 on the
  in-house set.
- Without CyNER the false malware and threat actors are at least halved, at
  nearby recall: dev malware 132 → 46, threat actors 31 → 12; in-house malware
  319 → 135, threat actors 58 → 28.
- Tools rise on the in-house set (63 → 84 correct), and fall slightly in F1 on
  dev, within the interval.
- The candidate does no better than no cyber NER on dev (malware F1 −0.0319
  [−0.0969, +0.0378] against `none`), for about twice CyNER's CPU.
- **Not checked name by name.** CyNER's names reach the LLM mixed with the
  gazetteer's, under "Already detected named entities (from MITRE gazetteer —
  DO NOT re-extract these)". A tool that CyNER types as malware would then not
  be extracted again by the LLM, which could explain the tools gained without
  it. The runs do not show it.

## Found along the way

1. GLiNER answered nothing in every run: ADR-0098.
2. On the 205 KB dev report, the document-level relation pass is refused by the
   server in all three runs: 122,881 prompt tokens plus the 8,192 requested for
   the output is one more than the 131,072-token window (HTTP 400). Not
   fixed here.

## Limits

- Dev and the in-house set were used to tune (the aggregation, the punctuation
  strip), so they are not independent tests. AnnoCTR test is already spent.
- The in-house gold was annotated with AI assistance, by one maintainer, on 8
  reports.
- One LLM, vision off.
- The 0.70 threshold is CyNER's, not tuned for the candidate.
- The candidate was not run end to end on the in-house set.
- The bundle's relationships are not measured.
- No run on reports held out.
- The offline `none` and `cand` (simple) rows for dev, and the paired
  differences, come from the maintainer's session notes, not from the stored
  JSON files listed below.

## Reproducing

The raw outputs and the harness scripts (`ner_swap_run.py`,
`ner_swap_score.py`, `strip_copy.py`, `batch*.sh`) are in
`docs/reports/ner-swap-2026-11-10/`, which git does not track. The runs are
under `data/eval/runs/nerswap-*` and `data/eval/inhouse-runs/nerswap-*`, also
git-ignored.

`base` and `none` reproduce with the repository's commands:

```bash
export LLM_TEMPERATURE=0 LLM_SEED=13
CYNER_ENABLED=true  python -m evaluation run --split dev --name <base>
CYNER_ENABLED=false python -m evaluation run --split dev --name <none>
python -m evaluation compare --a <base> --b <none> --task malware
CYNER_ENABLED=true  python -m evaluation inhouse-run --name <base-inh>
CYNER_ENABLED=false python -m evaluation inhouse-run --name <none-inh>
```

In this measure, `inhouse-run` was launched by the harness's wrapper, without
Stage 5 and without a required stage. The candidate configurations need the
harness, which is kept out of the repository.
