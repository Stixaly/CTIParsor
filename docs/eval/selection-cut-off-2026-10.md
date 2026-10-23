# Stage 3f selection answers cut off at the token limit — AnnoCTR dev, October 2026

In five of the eight select-mode dev runs, one Stage 3f selection answer did
not parse (`3f unparsed: 1`). Its chunk shipped nothing and its candidates
went to review. In the ATT&CK v20 comparison
([attack-v20-2026-10](attack-v20-2026-10.md)) that one answer moved from one
report to another and decided about half of the F1 difference.

The answers were not malformed. They were cut off at `LLM_MAX_OUTPUT_TOKENS`
(8,192) while the model deliberated in a loop inside a choice's `reason`. The
choices written before the loop were complete and valid. The fix keeps them,
each checked as before (ADR-0072, amendment of 2026-10-19). On dev it changes
one report: DarkSide gains five techniques, all five in the gold, and the 15
other reports are identical. Technique F1 0.584 → 0.610.

## What the model returned

Each failing report was re-run alone with every vLLM call logged (prompt,
answer, `finish_reason`, token counts), at the code and settings of the
reference run. Both reproductions gave the reference's technique ids,
candidate lists and review lists exactly.

| Report (run) | Chunk | Time | Tokens out | `finish_reason` | Complete choices before the loop | The loop |
|---|---|---|---|---|---|---|
| intel471 2021-05-10 DarkSide (19.2) | 1 of 2 | 322 s | 8,192 | `length` | 5: T1190, T1110, T1566, T1078, T1486 | in the 6th choice's `reason`: "So T1498 is the correct one. But T1499 is also a candidate. Let's check the candidates again..." |
| proofpoint 2021-10-19 TA505 (20.0) | 4 of 6 | 330 s | 8,192 | `length` | 6: T1204.002, T1105, T1071.001, T1027, T1219, T1036.008 | in the 7th choice's `reason`: "Let's add T1095. But T1071.001 is also a candidate..." |
| zscaler 2021-07-04 Kaseya (19.2) | 1 of 3 | 322 s | 8,192 | `length` | a complete answer of 8 choices, closed | the whole answer started over nine times, the last copy cut |

The other selection calls of these three reports took 2 to 31 seconds and 6
to 656 tokens. The cut answers' prompts were 6,078 to 6,341 tokens, and a
6,232-token prompt of TA505 got a complete answer: the prompt's length is
not the trigger. No prompt was cut, and no request timed out
(`LLM_TIMEOUT=400` in the run's `.env`).

`parse_selection` needs a closed JSON value. The DarkSide and TA505 answers
never close their `selected` list, so the whole answer was refused and every
candidate went to review, the valid choices included. The Stage 3 extraction
parser already salvages an answer cut off this way
(`stage3_llm._try_extract_complete_items`); the selector did not.

The Kaseya answer was read correctly, from its first object. It was found by
the first run of the fix, which read it as cut off and sent 35 candidates the
model had judged to review (below). Its copies swap one id: the first object
selects T1110 (not a candidate, refused) with a reason that describes T1105,
and every later copy selects T1105, which the gold holds. The fix keeps the
first object: it is the answer the model closed, and choosing a copy by its
score on dev would be tuning on dev.

At `main` (`086428e`) the DarkSide report no longer fails. ADR-0088 (PR #179)
removed twelve CyNER and spaCy entities from it, the extraction answer
changed, and so did the selection prompt. The loop depends on the exact
prompt; it is not gone.

### How often

| Select-mode dev run | Selection answers | Did not parse | Report |
|---|---|---|---|
| `sel-dev` | 65 | 1 | Proofpoint 2021-09-29 TA544 (40 held) |
| `sel-dev-dcd685e` | 67 | 0 | |
| `sel-noret-dev` | 57 | 0 | |
| `sel-dev-revoked-5d1bbe4` | 67 | 1 | DarkSide (41 held) |
| `ner-dev-base-1ef9638` | 67 | 1 | DarkSide |
| `ner-dev-cand-1ef9638p` | 62 | 0 | |
| `sel-dev-a19.2-5b98a49` | 67 | 1 | DarkSide (41 held) |
| `sel-dev-a20.0-5b98a49` | 67 | 1 | TA505 (36 held) |

About one selection answer in 65 to 70, and each costs a whole chunk. The
Kaseya kind is counted `ok` in these runs and is not in the table.

## The fix

`pipeline/stage3f_ttp_select.py`, `salvage_selection`:

- An answer whose `selected` list is still open at its end keeps its complete
  choices. The choice the cut runs through is not read.
- Each kept choice goes through the unchanged validation: an id among the
  candidates, a quote found verbatim in the chunk (≥ 3 words), once per id.
- Every candidate the answer did not decide goes to review with the reason
  "selection answer cut off before a choice for it". A complete answer that
  leaves a candidate out has judged it; a cut one may not have reached it.
- An answer cut before its first complete choice, and one that closes but
  does not parse, stay unparseable: every candidate goes to review.
- An answer whose object closes before the cut is read from that object,
  as before.
- The salvage runs before `parse_selection`, which tries every bracket,
  those inside a string too: a looping reason that writes "[]" would
  otherwise read as an empty selection.

The stage report counts these answers apart: 3f `truncated`,
`ttp_selection_truncated`, `3f_truncated` in the evaluation's LLM health.

Not changed: the loop itself, and its cost. A prompt that bounds `reason`, a
lower output ceiling for this call, or a repetition penalty would change every
selection answer and need their own comparison. A cut answer still takes
about 320 seconds.

## Setup

- **Reference**: `sel-dev-a19.2-5b98a49`, code `5b98a49`, ATT&CK 19.2 (the
  default track). It reproduces the historical `sel-dev-revoked-5d1bbe4` on
  16 of 16 reports ([attack-v20-2026-10](attack-v20-2026-10.md)).
- **Candidate**: `sel-dev-salvage-5b98a49p`, the same commit with this fix's
  diff of `pipeline/stage3f_ttp_select.py` and `pipeline/orchestrator.py`
  applied (a three-way apply: the changed lines are this branch's, the
  context is `5b98a49`'s). Run from a detached worktree, untouched during the
  run. The branch changed only docstrings and tests after it.
- Why not `main`: `main` has changed the DarkSide prompt since (ADR-0088), so
  a run at `main` + fix against this reference would mix the two changes.
  At `5b98a49`, a report without a cut answer must come out identical, which
  checks that only the fix moved.
- Same server and sampling as the reference: vLLM
  `Inferact/Qwen3.8-27B-NVFP4`, `LLM_TEMPERATURE=0 LLM_SEED=13
  LLM_PARALLELISM=1`, thinking off, `TTP_MODE=select`, the 48 AnnoCTR-cited
  procedure examples excluded from retrieval. The test split was not run or
  read.

## Result

| Run | Precision | Recall | **F1 parent (micro)** | F1 per document | Exact id F1 | Explicit recall | Implicit-only recall | s / report |
|---|---|---|---|---|---|---|---|---|
| `sel-dev-a19.2-5b98a49` | 0.565 | 0.605 | **0.584** | 0.478 | 0.211 | 0.639 (23/36) | 0.591 (55/93) | 424.5 |
| `sel-dev-salvage-5b98a49p` | 0.580 | 0.643 | **0.610** | 0.508 | 0.241 | 0.667 (24/36) | 0.634 (59/93) | 418.9 |

Totals: 78 → 83 correct, 60 → 60 false positives, 51 → 46 misses. Every
quote is found in the text (150 → 155 quotes). LLM health: 196 calls, 68/68
extractions, 3d 61/61; 3f 66 ok and 1 unparsed → 66 ok and 1 truncated.

| Paired difference (16 reports, 2,000 resamples) | | 95% interval | P(not better) |
|---|---|---|---|
| F1 parent | +0.026 | [+0.000, +0.098] | 0.36 |
| Precision | +0.015 | [+0.000, +0.056] | 0.36 |
| Recall | +0.039 | [+0.000, +0.136] | 0.36 |

**Per report.** 15 of 16 reports are identical to the reference: technique
ids, candidate lists, review lists, entities and relationships. The
sixteenth is DarkSide:

| DarkSide | Techniques | TP / FP / FN | Held for review |
|---|---|---|---|
| reference | T1059.001, T1133, T1567.002 | 2 / 1 / 7 | 41, "selection answer unparseable" |
| with the fix | + T1078, T1110, T1190, T1486, T1566 | 7 / 1 / 2 | 36, "selection answer cut off before a choice for it" |

The five salvaged techniques are all in the gold. The remaining misses are
T1189 and T1499; the false positive T1133 is the reference's.

## Verdict

ADR-0060's rule (docs/eval/README.md):

1. **The interval must exclude 0** and the gain reach +0.02: the gain is
   +0.026, but the interval's lower bound is +0.000, not above it. Not met as
   written. A change that moves one report of 16 cannot meet it: about a third
   of the resamples (P(not better) 0.36 ≈ (15/16)^16) leave that report out
   and show no difference at all. No resample shows a loss.
2. **Precision must not drop by more than 0.02**: met, +0.015.
3. **The gain must exceed the run-to-run spread**: met. The spread is 0 at
   this setting, and the 15 reports without a cut answer reproduce exactly.
4. **Cost must not grow by more than 25%**: met, −1% (the cut answer still
   takes its 320 seconds).

The rule is for choosing between configurations; this is a defect fix whose
effect is confined to the answers it repairs. On those, it ships five
correct techniques and no false positive, and the rest of dev does not move.
The decision is the maintainer's.

## The first run of the fix: the Kaseya answer

A first run (`sel-dev-cut-5b98a49p`, an earlier version of the fix) found a
second kind of cut answer. Its salvage looked for an open list anywhere in the
answer, so Kaseya's last, cut copy made the complete first answer look cut.
The eight techniques were the same, but the 35 candidates the model had
judged went to review. The fix now leaves an answer alone once its first
object closes (`test_a_complete_answer_repeated_until_the_cut_is_read_whole`),
and the final run reads Kaseya exactly as the reference does. The first run's
technique scores are the final run's: the difference was the review list.

## Limits

- **One report.** The gain is five techniques on one report; a bootstrap over
  16 documents cannot call it significant.
- **ATT&CK 20.0 not re-run.** On the 20.0 track the cut answer is TA505's.
  Offline, on the logged answer, the fix keeps its six complete choices.
  How many are correct, and what the v20 comparison becomes, needs a 20.0 run
  with the fix.
- **The loop remains.** It still costs about 320 seconds per occurrence, and
  a loop that starts in the first choice still loses the chunk.
- **The cut is inferred.** The selector sees the answer text, not the
  provider's `finish_reason`; an answer still open at its end is taken as cut.
  A closed answer with an unescaped `"` inside a quote can look open: its
  complete choices are then kept and checked, and the rest goes to review,
  where it went before. An answer whose `selected` is not its first key is
  not salvaged. Neither occurred on dev.

*Note, 2026-10-20.* The two limits "The loop remains" and "The cut is
inferred" describe the state of 2026-10-19 and are left as written. Since then
the selection call has its own output ceiling (4,096 tokens on vLLM with
thinking off, which cuts the three logged loops from about 325 to about 167
seconds) and the provider's finish reason is counted (`provider_at_ceiling`,
3f `at_ceiling`). The loop itself still happens. See
[selection-loop-2026-10](selection-loop-2026-10.md).
