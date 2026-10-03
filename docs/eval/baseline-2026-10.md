# Baseline — AnnoCTR dev, 2026-10-03: the ADR-0072 decision

The LLM half of ADR-0072: does the selector (`TTP_MODE=select`) beat the best
configuration measured so far, Stage 2c off, under the ADR-0060 rule? **Dev
split only** (16 reports, 129 document-level parent techniques). The test
split is run once, on the configuration this page selects.

## Setup

Every run below is the same code, `d580e8c`, and the same server: vLLM
`Inferact/Qwen3.8-27B-NVFP4`, `LLM_TEMPERATURE=0 LLM_SEED=13`, thinking off,
`LLM_PARALLELISM=1` (chunks one after another, so a run is reproducible),
extraction prompt fingerprint `114a2773001bf71e`. Retrieval corpus of
ADR-0072 built on the day (`attack_retrieval_corpus.json` `2c2eceb2e653bae8`,
embeddings `a9c2797c798e2e1f`); the evaluation excludes the 48 MITRE procedure
examples written from AnnoCTR reports (`TTP_RETRIEVAL_EXCLUDE_CITED`).

`runs/t0-dev` of the September baseline is **not** a reference here: it ran
on 2026-09-27 with prompt `53195bfc6d7b8870`, five Stage 3 commits earlier
(relationship dates, truncation recovery, whole-document relations, ADR-0072
itself). The shipped default is re-run on `d580e8c` as `t0-dev-d580e8c`.

| Run | Mode | Stage 2c | Command |
|---|---|---|---|
| `t0-dev-d580e8c` | verify | on (the shipped default) | `evaluation run --name t0-dev-d580e8c` |
| `t0-no2c-dev` | verify | off | `--disable 2c` |
| `sel-dev` | select | retrieves candidates | `TTP_MODE=select` |
| `sel-noret-dev` | select | off: the LLM's proposals only | `TTP_MODE=select --disable 2c` |

The commands are those of `d580e8c`, where verify was the default; since this
page select is, and a verify run needs `TTP_MODE=verify`.

## Techniques

| Run | Precision | Recall | **F1 parent (micro)** | F1 per document | Exact id F1 | s / report |
|---|---|---|---|---|---|---|
| `t0-dev-d580e8c` | _pending_ | | | | | |
| `t0-no2c-dev` | 0.500 | 0.434 | **0.465** | 0.402 | 0.191 | 334.5 |
| `sel-dev` | 0.587 | 0.628 | **0.607** | 0.529 | 0.232 | 396.2 |
| `sel-noret-dev` | 0.566 | 0.364 | **0.443** | 0.359 | 0.223 | 329.2 |

Recall of techniques annotated explicitly / only implicitly: `t0-no2c-dev`
19/36 (0.53) and 37/93 (0.40); `sel-dev` 28/36 (0.78) and 53/93 (0.57);
`sel-noret-dev` 16/36 (0.44) and 31/93 (0.33).

### The decision (ADR-0060 rule, against `t0-no2c-dev`)

`sel-dev` − `t0-no2c-dev`, paired bootstrap over the 16 reports (2 000
resamples):

| | Difference | 95% interval | P(not better) |
|---|---|---|---|
| **F1 parent** | **+0.142** | [+0.061, +0.236] | 0.0005 |
| Precision | +0.087 | [+0.025, +0.157] | 0.0015 |
| Recall | +0.194 | [+0.086, +0.307] | 0.0015 |

| Condition | Required | Measured | |
|---|---|---|---|
| Gain | ≥ +0.02 | +0.142 | ✓ |
| Interval excludes 0 | yes | [+0.061, +0.236] | ✓ |
| Precision loss | ≤ 0.02 | a gain of +0.087 | ✓ |
| Above the run-to-run spread | > 0 at temperature 0 | identical replicates (September) | ✓ |
| Cost per report | ≤ +25% | +18.4% (396.2 s against 334.5 s) | ✓ |

The extra time is the selection calls: Stage 3 goes from 306.0 to 365.2 s per
report, the local NER stage from 16.9 to 18.4 s (other jobs shared the CPU
during `sel-dev`, so the local share is if anything overstated).

**Decision: select mode becomes the default** (first row of the table in the
implementation report, A0).

### Retrieval is what wins, so the corpus has to ship

| Paired difference, F1 parent | | 95% interval | Recall | Precision |
|---|---|---|---|---|
| `sel-noret-dev` − `t0-no2c-dev` (the selector alone) | −0.021 | [−0.085, +0.023] | **−0.070** [−0.137, −0.028] | +0.066 [−0.004, +0.161] |
| `sel-dev` − `sel-noret-dev` (what retrieval adds) | **+0.163** | [+0.085, +0.267] | **+0.264** [+0.168, +0.369] | +0.021 [−0.049, +0.076] |

Selecting among the LLM's own proposals alone is no better than `verify`
without 2c: the strict contract (a checked quote, nothing shipped on a
failed call) trades recall for precision, and neither difference clears the
rule. All of the gain comes from the retrieved candidates. A deployment that
runs select mode **without the retrieval corpus** therefore runs the
`sel-noret` configuration, worse in recall than `verify` without 2c; the
default switch ships with the corpus or not at all.

## Where the errors are now (`evaluation ttp-errors`)

| | `t0-no2c-dev` | `sel-dev` | `sel-noret-dev` |
|---|---|---|---|
| Gold parents found | 56 | 81 | 47 |
| Missed, retrieved for the report but not selected | — | **42** | 1 (held in review) |
| Missed, never retrieved | — | 6 | 81 (nothing retrieved) |
| Missed (verify mode keeps no candidate list) | 73 | — | — |
| False positives among the retrieved candidates | — | 49 | — |
| False positives outside them (LLM proposals, ids written in the text) | 56 | 8 | 36 |
| Candidate ceiling (found + retrieved, over gold) | — | **0.954** | 0.372 |

- **Retrieval is no longer the bottleneck**: 123 of 129 gold techniques are
  among the report's candidates. The six never retrieved are T1048, T1083,
  T1134, T1189, T1482, T1629.
- **The selector is**: 42 gold techniques were offered and not chosen, most
  often T1105, T1190 (4 reports each), T1189 (3), T1001, T1055, T1056,
  T1112, T1140 (2). Six were held back in review rather than dropped: three
  refusals by the code (quote missing, too short or not verbatim) and three
  in the one selection answer that did not parse.
- False positives come from the candidates (49 of 57): T1105, T1547 (3
  reports), T1056, T1082, T1204, T1573, T1584 (2).

The candidate list in a run record is the union over the report's chunks, so
"retrieved, not selected" can also mean "retrieved for another chunk". The
records of these runs do not keep the quote of a refused selection; runs made
after 2026-10-03 do.

## Evidence

| | `t0-no2c-dev` | `sel-dev` | `sel-noret-dev` |
|---|---|---|---|
| Techniques with a quote | 113 | 141 | 68 |
| Quote found in the text | 98.2% | **100%** (the code checks it before shipping) | 100% |
| Correct techniques with a located quote | 60 | 90 | 46 |
| … on the passage annotated for that technique | 65% | 70% | 72% |
| … within 200 characters of it | 72% | 76% | 76% |

Whether a quote **supports** its technique is not measured by any of these:
the 50 quotes in `data/eval/runs/sel-dev/support-sample.csv` wait for a
person's judgement (`supports` ∈ yes / partial / no, and why).

## Named entities

Identical in all runs (strict F1: malware 0.32, threat actor 0.23, tool 0.47,
location 0.40, sectors 0.36): select mode changes how techniques are chosen
and nothing on the entity path.

## LLM health

`sel-dev`: 68/68 extraction calls usable; 3d 61/61; selection 64 usable and 1
unparseable; no provider failure. `t0-no2c-dev`: 68/68, 3d 61/61, 3f 58/58.
`sel-noret-dev`: 68/68, 3d 61/61, selection 57/57.

## Next

1. The prompt fixes of ADR-0074 (D7–D9) change every prompt fingerprint. The
   selected configuration is re-run once on dev with them, then **once on
   test**, its score reported as it comes.
2. The selector's 42 misses are the next target (prompt and per-passage
   selection), measured against this page.
3. Judge the 50 quotes of `support-sample.csv`.
