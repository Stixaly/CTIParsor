# Baseline — AnnoCTR, October 2026: the ADR-0072 decision, and test once

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
| `t0-dev-d580e8c` | 0.270 | 0.426 | **0.330** | 0.274 | 0.127 | 325.2 |
| `t0-no2c-dev` | 0.500 | 0.434 | **0.465** | 0.402 | 0.191 | 334.5 |
| `sel-dev` | 0.587 | 0.628 | **0.607** | 0.529 | 0.232 | 396.2 |
| `sel-noret-dev` | 0.566 | 0.364 | **0.443** | 0.359 | 0.223 | 329.2 |

Recall of techniques annotated explicitly / only implicitly: `t0-dev-d580e8c`
16/36 (0.44) and 39/93 (0.42); `t0-no2c-dev` 19/36 (0.53) and 37/93 (0.40);
`sel-dev` 28/36 (0.78) and 53/93 (0.57); `sel-noret-dev` 16/36 (0.44) and
31/93 (0.33).

### What Stage 2c costs as shipped, on one code base

| Paired difference, F1 parent | | 95% interval | Precision | Recall |
|---|---|---|---|---|
| `t0-no2c-dev` − `t0-dev-d580e8c` (2c off) | **+0.134** | [+0.068, +0.203] | +0.230 | +0.008 [−0.063, +0.082] |
| `sel-dev` − `t0-dev-d580e8c` (what users get, before → after) | **+0.276** | [+0.231, +0.329] | +0.317 | +0.202 |
| `t0-dev-d580e8c` − September's `t0-dev` (five Stage 3 commits) | −0.008 | [−0.036, +0.018] | −0.008 | −0.008 |

The September ablation's figure (+0.12 to +0.15 for 2c off) holds on today's
code: as shipped, 2c adds 93 false positives (149 against 56) and no correct
technique (55 against 56). The five Stage 3 commits between the two baselines
did not move technique F1. For a user, the default goes from 0.330 to 0.607.

`t0-dev-d580e8c` ran from 23:05 to 00:32; the checkout moved to `main` at
23:50 (PRs #94–96 merged). Python keeps the modules a process has imported,
and every Stage 1–3 module was imported on the first report, so the run is a
`d580e8c` run throughout.

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

| | `t0-dev-d580e8c` | `t0-no2c-dev` | `sel-dev` | `sel-noret-dev` |
|---|---|---|---|---|
| Techniques with a quote | 207 | 113 | 141 | 68 |
| Quote found in the text | 98.1% | 98.2% | **100%** (the code checks it before shipping) | 100% |
| Correct techniques with a located quote | 57 | 60 | 90 | 46 |
| … on the passage annotated for that technique | 63% | 65% | 70% | 72% |
| … within 200 characters of it | 70% | 72% | 76% | 76% |

Whether a quote **supports** its technique is not measured by any of these.

### Does the quote show the technique used? 50 quotes judged

`evaluation support-sample` drew 50 of `sel-dev`'s located quotes at random
(seed 7, correct and incorrect techniques mixed: 34 in the gold, 16 not). The
maintainer judged them on 2026-10-11, reading each published report, with a
note per quote (`data/eval/runs/sel-dev/support-sample.csv`; the blank sample
is kept beside it as `support-sample.blank.csv`).

| Quotes | yes | no | unsure | yes, 95% interval (Wilson) |
|---|---|---|---|---|
| All 50 | **35 (70%)** | 8 | 7 | 56–81% |
| Technique in the gold (34) | **29 (85%)** | 1 | 4 | 70–94% |
| Technique not in the gold (16) | **6 (38%)** | 7 | 3 | 18–61% |

- **The quotes of correct techniques mostly show the use**: 85%. The
  roadmap's target is 90% on what a strict export ships.
- **Six "false positives" are supported by the text**: T1505 (China Chopper
  and JspSpy web shells), T1071 (an HTTP C&C in the IoC table), T1204
  (enable macros), T1105 (Sliver downloaded), T1133 (Citrix, RDWeb, RDP
  access), T1074 (keystrokes staged in %AppData%). AnnoCTR does not annotate
  them, so the measured precision understates the selector's: if 38% of
  `sel-dev`'s 57 false positives held up, about 21 (11 to 35), precision
  would be about 0.74 rather than 0.587. An estimate from 16 quotes, not a
  score; the official number stays the gold's.
- **What the "no" quotes get wrong is the technique for the behaviour**,
  not the quote: buying access or botnets read as T1588 *Obtain
  Capabilities* (twice) and T1584 *Compromise Infrastructure*; initial access
  through RDP read as T1021 *Remote Services*; `schtasks /Disable` on
  Defender's tasks read as T1053 *Scheduled Task* (it impairs a defence);
  TeamViewer used for DLL side-loading read as T1219; a C2 that resolves by
  time of day read as T1029 *Scheduled Transfer*.
- **One is a domain error**: T1629 is the *Mobile* "Impair Defenses". The
  report's table says T1562, revoked in ATT&CK 2026 for T1685, and absent
  from the pipeline's index; resolving by name finds only the Mobile
  technique. 124 names in `mitre_index.json` belong to several ids
  (Enterprise, Mobile, ICS, CAPEC).
- **Three "yes" rest on the rest of the report**, not on the quoted passage
  and its context (rows 16 T1486, 33 T1133, 40 T1074). Read strictly, the
  passage supports its technique in 32 of 50 (64%, 50–76%).
- The notes name a sub-technique for 21 of the 35 "yes" (15 distinct: T1059.001, .003, .005,
  T1566.001, .002, T1204.002, T1027.002, T1550.002, T1053.005, T1574.001, T1505.003,
  T1071.001, T1567.002, T1070.004, T1074.001): a start for the exact-id score, at 0.23.

## Named entities

Identical in all runs (strict F1: malware 0.32, threat actor 0.23, tool 0.47,
location 0.40, sectors 0.36): select mode changes how techniques are chosen
and nothing on the entity path.

## LLM health

`sel-dev`: 68/68 extraction calls usable; 3d 61/61; selection 64 usable and 1
unparseable; no provider failure. `t0-no2c-dev`: 68/68, 3d 61/61, 3f 58/58.
`sel-noret-dev`: 68/68, 3d 61/61, selection 57/57. `t0-dev-d580e8c`: 68/68,
3d 62/62, 3f 59/59.

## Re-run on 2026-10-11: the configuration frozen for test

ADR-0074 (report text as delimited data, D7–D9) changed every prompt
fingerprint after this page's runs, and five weeks of commits followed. The
select configuration was run again on dev, at `dcd685e` (`main` on
2026-10-11), same server, model and settings (`LLM_TEMPERATURE=0
LLM_SEED=13 LLM_PARALLELISM=1`, thinking off), as `sel-dev-dcd685e`.

| Run | Precision | Recall | **F1 parent (micro)** | F1 per document | Exact id F1 | s / report |
|---|---|---|---|---|---|---|
| `sel-dev` (2026-10-03, `d580e8c`) | 0.587 | 0.628 | **0.607** | 0.529 | 0.232 | 396.2 |
| `sel-dev-dcd685e` (2026-10-11) | 0.571 | 0.651 | **0.609** | 0.513 | 0.229 | 370.9 |

| Paired difference (16 reports, 2 000 resamples) | | 95% interval |
|---|---|---|
| F1 parent | +0.002 | [−0.037, +0.034] |
| Precision | −0.016 | [−0.060, +0.014] |
| Recall | +0.023 | [−0.028, +0.071] |

Nothing moved beyond noise: the prompt changes cost nothing and gained
nothing on techniques. 84 gold parents found, 39 retrieved and not
selected, 6 never retrieved (candidate ceiling 0.954, unchanged); 56 false
positives from the candidates, 7 from outside them; one candidate held in
review (quote missing or not verbatim). The time per report is not
comparable: other work shared the CPU during this run.

Named entities are unchanged too (strict: malware P 0.20 R 0.87, threat
actor P 0.13 R 0.94, tool P 0.34 R 0.73). LLM health: 196 provider calls, no
failure; 68/68 extractions, 3d 61/61, selection 67/67.

**Quotes found in the text: 100% (153 of 153).** The first scoring said
98.0%: three quotes are verbatim in the text the pipeline read, which is
refanged (since PR #128 Stage 1 rejoins half-bracket defangs, so
`www.destroy2013.]com` reaches the model as `www.destroy2013.com`), and the
evaluator searched AnnoCTR's raw text. It now also searches the refanged
text and maps the span back to the source's offsets
(`stage2_extraction.refang_with_offsets`).

This configuration, `dcd685e`, is the one run once on test.

## Test, once: `sel-test-dcd685e`, 2026-10-11

The configuration above, frozen at `dcd685e`, on AnnoCTR's test split: 34
reports, 332 document-level gold parent techniques, never run before. Same
server, model and settings as `sel-dev-dcd685e`.

| Split | Precision | Recall | **F1 parent (micro)** | F1 per document | Exact id F1 |
|---|---|---|---|---|---|
| **test** (34 reports) | 0.679 | 0.702 | **0.690** | 0.565 | 0.415 |
| dev (16 reports, above) | 0.571 | 0.651 | 0.609 | 0.513 | 0.229 |

**0.690 is the number to report** for the select configuration on AnnoCTR
test. The two splits hold different reports (the split is temporal, every
vendor in each); test was chosen on nothing, so its higher score is the
splits' difference, not a fit.

- Recall of techniques annotated explicitly 0.851, only implicitly 0.535.
- Where the errors are: 233 gold parents found; 64 retrieved for the report
  and not selected; 35 never retrieved (candidate ceiling 0.895, against
  0.954 on dev); 108 false positives from the candidates, 2 from outside
  them; 3 candidates held in review (quote missing or not verbatim).
- Named entities, strict: malware P 0.197 R 0.889, threat actor P 0.119
  R 0.967, tool P 0.250 R 0.750. The same shape as dev: high recall, low
  precision.
- Evidence: 312 techniques with a quote, all found in the text (98.1% at
  first: the refang artefact above, and two quotes lost to a no-break space,
  a defect of `evidence_span.locate` the worker shared, fixed); 63% of the
  located correct ones on the annotated passage, 72% within 200 characters
  of it.
- LLM health: 357 provider calls, no failure; 122/122 extractions, 3d 116 of
  117 parsed, selection 118/118. 366.9 s per report.

**A server outage, and three reports run again.** The LLM server stopped
answering at 15:14. Report 7 and report 8 got no answer at all and were
recorded as failed; report 6 lost one of its extraction calls and its
selection call, and came out with no technique. The run stopped at report 9,
as it is built to, and was resumed when the server answered again. The three
reports were then run again at the same commit, from a worktree checked out
at `dcd685e` (the main checkout had moved on), their first records kept in
`data/eval/runs/sel-test-dcd685e/outage-2026-10-11/`. Running a report again
that never got its answers chooses nothing between results: sampling is
fixed (temperature 0, seed 13). The score as it came, on 32 reports with
report 6 degraded, is kept as `score-as-it-came.json`: P 0.689, R 0.707,
F1 0.698, exact id 0.425.

## Next

1. ~~Re-run the selected configuration on dev with the ADR-0074 prompts,
   then once on test~~ (above): F1 0.690 on test.
2. The selector's misses (39 on the re-run) are the next target (prompt and
   per-passage selection), measured against `sel-dev-dcd685e`.
3. ~~Judge the 50 quotes of `support-sample.csv`~~ (Evidence, above).
4. Resolve a revoked ATT&CK id to its replacement and prefer Enterprise
   names (the T1629 domain error), measured on dev.
5. ~~Locate quotes in the refanged text in `evaluation/evidence.py`~~ (done,
   with the no-break space fix in `evidence_span`).
