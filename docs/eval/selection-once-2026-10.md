# Stage 3f selection prompt: "write the object once, then stop", October 2026

[selection-loop-2026-10](selection-loop-2026-10.md) measured a prompt, (b),
that asked Qwen3.8 to decide first, write the answer once and keep `reason` to
25 words. It removed every restarted answer on AnnoCTR dev (3 to 0) but cost
dev precision 0.027, and which wording did what was not separated. On AnnoCTR
train, most selection answers that reached the output ceiling had written a
complete answer first, then deliberated in prose, started again or repeated
junk tags. This measures the piece of (b) aimed at that, "then write the
answer once", in its own words and with a stop added:

- **(d)**: one sentence appended to the last paragraph of `_SELECT_SYSTEM`,
  after "Return ONLY the JSON object, no markdown.":
  "Write that object once, then stop: nothing goes after its closing brace."
  `reason` keeps no length limit, the model is not told to decide first, and
  `_SELECT_USER_TEMPLATE` is unchanged.

**Not adopted.** On AnnoCTR dev it broke rules 1 and 2 as fixed before the
run: technique F1 0.609 → 0.587 (−0.022), precision 0.571 → 0.515 (−0.057).
It did not do its job there either. Answers restarted after a complete answer
went from 3 to 4, and three answers reached the 4,096 ceiling, against none
with the shipped prompt. The train stress test was therefore not run. The
pipeline is unchanged.

## Fixed before the runs

Written on 2026-10-23 before the first call of this measurement (16:01 by the
run logs). The reading of an answer, last below, is the classifier the replay
scripts use, written before them.

- **Replays** (temperature 0, seed 13, thinking off, ceiling 4,096): the three
  logged dev loops (code `5b98a49`), the three dev answers of
  `sel-dev-ceiling-01aeea6p` that restarted, and the 35 train calls of the
  October 21 stress test that were cut at 2,048 or wrote something after their
  answer. Each under (d) and under a **control**: the same position, a neutral
  sentence instead ("Write each id as the candidate list writes it (T1234 or
  T1234.001)."). The control of selection-loop-2026-10 used the same
  sentence one sentence earlier, before "Return ONLY", and its DarkSide
  answer was cut; here it ends at 816 tokens. If (d) left as many replayed
  calls continued or cut as the control, the dev run would wait: the edit
  would be doing what any edit does.
- **Dev**, against a baseline at the same commit, both from pinned worktrees,
  every vLLM call logged, the server alone. Adopted only if all hold
  (ADR-0060's rule, docs/eval/README.md):
  1. rule 1, read for a change aimed at loops rather than accuracy: no gain is
     required, but the parent-level F1 must not fall by 0.02 or more (a loss
     as large as the smallest gain rule 1 calls real counts as real);
  2. rule 2 as written: precision drops by at most 0.02;
  3. rule 3: temperature 0, spread 0, one run per configuration;
  4. rule 4 as written: seconds per report grow by at most 25%;
  5. its purpose, on **train**: answers at the 4,096 ceiling, (d) no more than
     the shipped prompt; answers that continue after their complete answer,
     (d) at most half of the shipped prompt's. A dev failure on 1, 2 or 4 ends
     the measurement there.
- **Reading an answer**: as `parse_selection` reads it, the first
  `{"selected": [...]}` object or bare list of choices. It *continues* when
  anything but whitespace, or the closing fence of a fenced answer, follows:
  a restart (another `"selected"`), repeated tags (more than ten `</`), or
  other text, prose mostly. An answer cut before its list closes has *no
  closed answer*.

## Replays

Reproduction first: two ordinary logged dev calls (DarkSide, TA505) came back
byte for byte identical, and so did 14 train calls with the shipped prompt
(identical, or an exact extension of the answer the 2,048 ceiling had cut).

**Dev**, at 4,096:

| Call | Shipped prompt (logged) | (d) | Control |
|---|---|---|---|
| DarkSide, chunk 1 | loops in a `reason` until 8,192 | ends by itself, 1,325 tokens | ends by itself, 816 |
| TA505, chunk 4 | loops in a `reason` until 8,192 | ends by itself, 1,196 | ends by itself, 1,239 |
| Kaseya, chunk 1 | an answer, then nine restarts until 8,192 | an answer, a restart, ends at 1,586 | an answer, a restart, ends at 2,329 |
| The three dev restarts of `01aeea6p` | restart, end by themselves | clean (339–783 tokens) | clean (419–680) |

**Train**, the 35 calls (at 4,096; the shipped column replays at 4,096 the 12
answers cut at 2,048 and keeps the others, which had ended by themselves):

| | Shipped prompt | (d) | Control |
|---|---|---|---|
| Clean answers | 1 | 29 | 25 |
| Continued after the answer (restart / tags / other) | 32 (26 / 1 / 5) | 5 (4 / 0 / 1) | 7 (5 / 1 / 1) |
| No closed answer, cut | 1 | 1 | 3 |
| Closed but malformed | 1 | 0 | 0 |
| At the 4,096 ceiling | 6 | 4 | 5 |
| Seconds, all 35 | 3,027 | 1,650 | 1,824 |

Over the 41 replayed calls, (d) left 7 continued or cut and the control 11.
The two disagree on ten: the control alone on seven, (d) alone on three (a sign
test gives about 0.34, two-sided). By the gate, the dev run went ahead.

What the replays said, and did not:

- **Most of the effect is the edit, not its wording.** These calls were picked
  because the shipped prompt failed on them; any change to the prompt sends
  them down another path, and the neutral sentence stops most of them too.
  The replays cannot measure (d)'s effect on the calls that did not fail; the
  dev run can.
- **(d) also creates loops.** Two train answers that the shipped prompt ended
  by itself (proofpoint 2021-05-18 chunk 2, zscaler 2020-08-14 chunk 3) restart
  under (d) until the 4,096 ceiling. Dev showed the same, below.
- **A loop inside a `reason` is not its target**, and the logged dev loops of
  that kind (DarkSide, TA505) stop under the control as well.

## AnnoCTR dev

**Setup.** Baseline `sel-dev-base-7867cd3`: main at `7867cd3`, which carries
the ceiling of the previous amendment (PR #190). Candidate
`sel-dev-once-7867cd3p`: the same commit with the one-line prompt diff. Each
from its own detached worktree left untouched during the run, ATT&CK 19.2,
vLLM `Inferact/Qwen3.8-27B-NVFP4`, `LLM_TEMPERATURE=0 LLM_SEED=13
LLM_PARALLELISM=1`, thinking off, `TTP_MODE=select`, the 48 AnnoCTR-cited
procedure examples excluded. Every vLLM call of both runs is logged in the
run directory, and `/metrics`, sampled every 5 seconds, never showed a second
request. The test split was not run or read.

The baseline is identical to `sel-dev-ceiling-01aeea6p` on 16 of 16 reports
(technique ids, candidate and review lists, entities, relationships). The
server still reproduces a whole run, and rule 3's spread is 0.

During the candidate's 15th report the machine slept for eleven hours. The
server received one call in that time, the one in flight; the client resent it
on waking, to an idle server. The output does not change; that report's time
carries the client's 400-second timeout (`LLM_TIMEOUT`).

| Run | Precision | Recall | **F1 parent (micro)** | F1 per document | Exact id F1 | Explicit recall | Implicit-only recall | s / report |
|---|---|---|---|---|---|---|---|---|
| baseline | 0.571 | 0.651 | **0.609** | 0.517 | 0.243 | 0.722 (26/36) | 0.624 (58/93) | 364.1 |
| (d) | 0.515 | 0.682 | **0.587** | 0.506 | 0.214 | 0.750 (27/36) | 0.656 (61/93) | 428.4 (403.4 without the timeout) |

Totals: 84 / 63 / 45 correct, false positives and misses for the baseline;
88 / 83 / 41 for (d).

Paired against the baseline (16 reports, 2,000 resamples):

| Difference | | 95% interval | P(not better) |
|---|---|---|---|
| F1 parent | −0.022 | [−0.070, +0.030] | 0.80 |
| Precision | −0.057 | [−0.112, +0.012] | 0.95 |
| Recall | +0.031 | [−0.028, +0.081] | 0.17 |

Candidate lists, entities and relationships are identical on 16 of 16
reports, so only the selection answers moved; technique ids differ on 11. At
parent level (d) adds 28 false-positive techniques and drops 8, gains 7
correct ones and loses 3. The malicious-VPN report (zscaler 2021-05-21) gains
25 ids, among them four sub-techniques of T1055, and 12 parent-level false
positives; the Philippine-spoofing report gains 4 parent-level false
positives. These are the two reports that carried most of (b)'s false
positives too.

**The selection answers**, from the call logs (62 calls each). Prompt (b)'s
column comes from [selection-loop-2026-10](selection-loop-2026-10.md): it was
compared with a baseline whose outputs are identical to this one's on 16 of 16
reports, at the 2,048 ceiling of the time. The 95th percentile is the value
at rank 0.95 × (n − 1), rounded down, as in that document; with three answers
at 4,096 out of 62, (d)'s by linear interpolation is 3,437.

| | Baseline, shipped prompt | (d) | (b), for reference |
|---|---|---|---|
| Answers at the ceiling | 0 | 3 | 0 |
| Restarted after a complete answer | 3 | 4 (the baseline's 3 end cleanly; 4 others restart) | 0 |
| No closed answer (cut) | 0 | 2 | 0 |
| Completion tokens: median / 95th percentile / max | 384 / 920 / 1,550 | 421 / 2,458 / 4,096 | 266 / 777 / 2,030 |
| Choices written | 239 | 272 | 251 |
| A parent and its sub-technique in one answer | 9 | 21 | 21 |
| Words per `reason`: median / max | 23 / 135 | 23 / 43 | 13 / 21 |
| Selection time, all calls | 1,197 s | 1,876 s | 965 s |

The three answers at the ceiling:

- On the FK-undead rootkit report (lab52 2020-06-09), one deliberates inside
  a choice's `reason` ("I will select T1547.006. ... T1057 is Process
  Discovery. No") until the cut. Its complete choices are kept, and the 33
  candidates it never reached go to review.
- On the same report, another writes a complete answer of 6 choices, then
  starts again until the cut. It is read whole.
- On the Philippine-spoofing report, an answer written as a bare list
  deliberates inside a `reason` ("What about T1068? No. What about T1008? No.
  ...") until the cut. The salvage of ADR-0072's amendment of 2026-10-19 reads
  only a cut `{"selected": [...]}` object, not a cut bare list, so this
  answer's complete choices are lost: unparseable, 31 candidates to review.
  `parse_selection` accepts that shape from any prompt, though none of the
  shipped prompt's answers took it (62 on dev, 255 on train); nothing in this
  measurement changes the salvage.

## Verdict

ADR-0060's rule as fixed above:

1. **Broken.** F1 falls by 0.022, more than the 0.02 the reading allows.
2. **Broken.** Precision falls by 0.057, the limit is 0.02.
3. Met: the baseline reproduces the earlier run exactly.
4. Met: seconds per report grow by 17.7%, 10.8% without the timeout.
5. Not run: the dev failure on rules 1 and 2 ends the measurement.

(d) is not adopted and the shipped prompt stays.

What it separates in (b)'s wording, on this dev set and one run each:

- **"Write it once, then stop" alone does not stop restarts.**
  selection-loop-2026-10 credited (b)'s "write the answer once" with taking
  restarts from 3 to 0. Alone, the instruction left 4 restarts and three
  answers at the ceiling. What stopped them in (b) is then in its other
  parts, deciding first and a short `reason` that does not weigh the choice
  again, or in the combination.
- **The extra choices do not need a short `reason`.** (d) leaves `reason`
  alone and still writes more choices than (b) (272 against 251), with as many
  parent-and-sub-technique pairs (21, not all the same ones). An instruction
  about how to write the answer moved how much the model selects, and the two
  prompts lost precision on the same two reports.

## Limits

- **One dev run per prompt.** Temperature 0 makes a run reproducible, not
  representative of nearby prompts: the replays show how far a neutral
  sentence alone moves these answers.
- **The train effect on all calls is unmeasured.** The stress test was not
  run, by the rule above; on the 35 selected train calls (d) beat the control
  only modestly.
- **ATT&CK 20.0 was not run.**
- **The loop remains.** The ceiling caps its cost; a loop that starts before
  the first choice, or in an answer written as a bare list, still sends its
  chunk to review. A repetition penalty is still unmeasured.

## Found on the way: a cut bare list is not salvaged

`parse_selection` accepts a bare list of choices as well as a
`{"selected": [...]}` object, but `salvage_selection` looks for the
`"selected"` key. An answer written as a bare list and cut at the ceiling
therefore keeps none of its complete choices (the Philippine-spoofing answer
above, 31 candidates to review). One dev answer in 62 started with a bare list
in the (d) run; none in the baseline, nor among the shipped prompt's 255 train
answers.

## Found on the way: two train answers the October 21 analysis misread

The stress test of [selection-loop-2026-10](selection-loop-2026-10.md) found
the first complete object of an answer by trying every `{`. Where the
`selected` list never closed, that finds the first *choice*, so two of the 12
answers cut at 2,048 were counted among "a complete answer, then prose
deliberation". Read as `parse_selection` reads them, three of the 12 have no
closed answer, not one:

- **zscaler 2021-05-05, chunk 4**: a list still adding distinct choices at
  2,048 (16 kept). At 4,096 its object closes at **4,011 tokens** with 38
  choices (36 distinct ids, all kept), then it restarts and is cut. A genuine answer
  of 4,011 tokens is above the 3,167 that set the ceiling: by that document's
  rule (1.25 × the longest answer, 5,014) 4,096 is short, and this answer
  closes 85 tokens before it.
- **proofpoint 2021-07-28, chunk 3**: at 4,096 it writes 32 distinct choices,
  then loops inside the 33rd `reason` ("It has T1684.005? No." again and
  again). It keeps 28 validated choices at 4,096 against 11 at 2,048, so "the
  parser read the same choices it would have read at any higher ceiling" does
  not hold for it.

Of the 12, six still reach 4,096 with the shipped prompt and six end by
themselves, between 2,444 and 3,984 tokens. Both answers above were replayed
with the shipped prompt; the ceiling and its document belong to ADR-0072's
amendment of 2026-10-20 (PR #190, merged before this was found), which this
measurement does not change.
