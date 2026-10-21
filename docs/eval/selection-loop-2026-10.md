# Stage 3f selection loop: an output ceiling for the selection call, October 2026

About one Stage 3f selection call in 65 on AnnoCTR dev loops: Qwen3.8
deliberates inside a choice's `reason` ("So T1498 is the correct one. But
T1499 is also a candidate..."), or writes its whole answer again and again,
until `LLM_MAX_OUTPUT_TOKENS` (8,192) cuts it after about 320 seconds
([selection-cut-off-2026-10](selection-cut-off-2026-10.md)). Since ADR-0072's
amendment of 2026-10-19 the complete choices written before the loop are kept;
the loop and its cost remained.

Three changes were measured:

- **(a)** an output ceiling for the selection call alone,
  `TTP_SELECT_MAX_OUTPUT_TOKENS`;
- **(b)** a prompt that asks for the decision first, the answer once, and a
  `reason` of one sentence of at most 25 words that does not weigh the choice
  again;
- **(c)** the provider's finish reason in the stage report: an answer the
  provider stopped at the ceiling is counted (`provider_at_ceiling`, 3f
  `at_ceiling`), not inferred from an unclosed list.

**Adopted: (a) and (c)**, with a default of **4,096 tokens on vLLM with
thinking off** and the global ceiling everywhere else. On AnnoCTR dev they
change nothing (16 of 16 reports identical to the reference). On the three
logged loops the call takes about 167 seconds instead of 325, with the same
complete choices. The default was first 2,048; a stress test on AnnoCTR train
found a genuine answer of 3,167 tokens, which 2,048 cut before its first
choice. **Not adopted: (b).** It stopped the three logged loops, but on dev
its precision fell by 0.027 (rule 2 allows 0.02) and F1 by 0.012.

## The three logged loops, replayed

The calls logged on 2026-10-19 (code `5b98a49`) were sent again to the same
server (vLLM 0.27.1, `Inferact/Qwen3.8-27B-NVFP4`, temperature 0, seed 13,
thinking off), with only `max_tokens` or the prompt changed. Two ordinary
selection calls of the same reports (DarkSide, TA505) came back byte for byte
identical to the log: the server still reproduces.

| Call | Logged (8,192 tokens) | Ceiling 4,096 | Ceiling 2,048 | (b) prompt | Control prompt |
|---|---|---|---|---|---|
| DarkSide, chunk 1 | 322 s, cut in the 6th choice's `reason` | 165 s, cut | 86 s, cut | 45 s, ends by itself (1,048 tokens) | 90 s, cut |
| TA505, chunk 4 | 330 s, cut in the 7th choice's `reason` | 172 s, cut | 93 s, cut | 32 s, ends by itself (704 tokens) | 41 s, ends by itself (862 tokens) |
| Kaseya, chunk 1 | 322 s, a closed answer then nine restarts | 165 s, cut | 86 s, cut | 25 s, ends by itself (523 tokens) | 85 s, cut |

The two prompt columns were run at the 2,048 ceiling.

- **Ceiling**: at temperature 0 the ceiling does not change the tokens before
  it. Each cut answer is the exact prefix of the logged one. The complete
  choices end at token 490 (DarkSide) and 506 (TA505), and Kaseya's first
  object closes at token 834, so the salvage and the parser read exactly what
  they read before, at either ceiling.
- **(b)**: all three answers end by themselves, with reasons of 9 to 16 words.
- **Control**: the prompt with one neutral sentence added instead ("Write each
  id as the candidate list writes it"). It stops the TA505 loop but not the
  two others. A loop depends on the exact prompt, so a prompt edit can remove
  it by chance; (b) removed all three, which is more than chance alone.

## AnnoCTR dev

**Setup.** Reference: `sel-dev-a19.2-01aeea6`, the salvage fix (PR #187) at
`01aeea6`, ATT&CK 19.2. Candidates, at the same commit with this diff applied,
each from its own detached worktree left untouched during the run:
`sel-dev-ceiling-01aeea6p` (a + c) and `sel-dev-noloop-01aeea6p` (a + b + c),
both with the ceiling at 2,048, the default at the time. Same settings as the
reference: vLLM `Inferact/Qwen3.8-27B-NVFP4`,
`LLM_TEMPERATURE=0 LLM_SEED=13 LLM_PARALLELISM=1`, thinking off,
`TTP_MODE=select`, the 48 AnnoCTR-cited procedure examples excluded. Each run
had the server to itself; every vLLM call of the two candidate runs was
logged. The run manifests are identical apart from name and start time. The
test split was not run or read.

| Run | Precision | Recall | **F1 parent (micro)** | F1 per document | Exact id F1 | Explicit recall | Implicit-only recall | s / report |
|---|---|---|---|---|---|---|---|---|
| reference | 0.571 | 0.651 | **0.609** | 0.517 | 0.243 | 0.722 (26/36) | 0.624 (58/93) | 359.7 |
| (a) + (c) | 0.571 | 0.651 | **0.609** | 0.517 | 0.243 | 0.722 (26/36) | 0.624 (58/93) | 359.3 |
| (a) + (b) + (c) | 0.545 | 0.659 | **0.597** | 0.469 | 0.226 | 0.667 (24/36) | 0.656 (61/93) | 345.3 |

Totals: 84 / 63 / 45 correct, false positives and misses for the reference
and (a) + (c); 85 / 71 / 44 for (a) + (b) + (c).

**(a) + (c).** Identical to the reference on 16 of 16 reports: technique ids,
candidate lists, review lists, entities and relationships. None of the 62
selection answers reached the ceiling: the reference itself had no cut answer
(3f 62 ok, 0 truncated, 0 unparsed). Since ADR-0088 changed the DarkSide
prompt, the loop no longer occurs on dev at this commit, so dev cannot show
the time saved; the replays do. The longest dev answer took 1,550 tokens, so
the run at 4,096 would give the same tokens as the run at 2,048: the ceiling
does not change what comes before it.

**(a) + (b) + (c)**, paired against the reference (16 reports, 2,000 resamples):

| Difference | | 95% interval | P(not better) |
|---|---|---|---|
| F1 parent | −0.012 | [−0.044, +0.014] | 0.82 |
| Precision | −0.027 | [−0.069, +0.015] | 0.89 |
| Recall | +0.008 | [−0.035, +0.049] | 0.44 |

Candidate lists, entities and relationships are identical on 16 of 16
reports, so only the selection answers moved; technique ids differ on 13.
The largest change is the malicious-VPN report (zscaler 2021-05-21): one
answer chose 30 candidates, among them T1055 with four of its sub-techniques,
and that report gains 15 ids and loses 2.

**What the selection answers looked like**, from the call logs (62 calls each):

| | (a) + (c), the shipped prompt | (a) + (b) + (c) |
|---|---|---|
| Answers stopped at the ceiling | 0 | 0 |
| Completion tokens: median / 95th percentile / max | 384 / 920 / 1,550 | 266 / 777 / 2,030 |
| Answers restarted after a complete object | 3 (647, 1,014 and 1,550 tokens) | 0 |
| Choices written | 239 | 251 |
| A parent and its sub-technique in one answer | 9 | 21 |
| Words per `reason`: median / max | 23 / 135 | 13 / 21 |
| Answers not starting with `{` | 2 (a code fence) | 1 (a code fence) |
| Selection time, all calls | 1,197 s | 965 s |

With the shipped prompt, the three longest answers are restarts that ended
by themselves: the 1,550-token one is a complete 7-choice answer followed by
a second copy, and the 1,014-token one writes `</thinking>` after its first
object and starts again. The parser reads the first object of each. The
longest answer of (b) is not a restart: 30 choices in one object, 18 tokens
under the 2,048 ceiling it ran with.

## The ceiling's value: AnnoCTR train

Dev at this commit has no loop, and 62 answers say little about the longest
genuine one. The selection call alone was therefore run on AnnoCTR **train**
(never test): every chunk of the 70 train reports with retrieved candidates,
one call each, the shipped prompt, the production path (`select_chunk_ttps`)
at the 2,048 ceiling. The candidates are the retrieved ones only: without
the extraction pass, the chunks get no proposals of their own. 255 calls on 67
reports, 6,041 seconds; 85 answers were an empty list.

The rule for the ceiling was written before reading the results: the smallest
of 2,048, 3,072 and 4,096 that is at least 1.25 times the longest answer
that ends by itself, on dev and on train; an answer cut at the ceiling is read
by hand, and if it is still progressing rather than repeating, it counts as
longer than the ceiling.

| Train, at the 2,048 ceiling | |
|---|---|
| Answers stopped at the ceiling | 12 of 255 (4.7%) |
| … a complete answer, then prose deliberation until the cut | 7 |
| … a complete answer, then restarted | 3 |
| … a complete answer, then repeated `</invoke>` / `</parameter>` tags | 1 |
| … prose reasoning first, cut before any JSON | 1 |
| Answers restarted after a complete object, ended or not | 21 |
| Completion tokens: median / 95th percentile | 380 / 1,816 |
| Longest first object, closed before the cut | 1,936 tokens |

In 11 of the 12 cut answers the first object closed before the cut, at 1,936
tokens at most: the parser read the same choices it would have read at any
higher ceiling. The twelfth (zscaler 2021-04-14, Hydrojiin, chunk 7) starts
with `<previous_reasoning>` and analyses the excerpt in prose; at 2,048 it
was still reasoning, so the answer was unparseable and its 32 candidates
went to review. Sent again at 8,192,
it **ends by itself at 3,167 tokens** (137 s) with 6 choices. The answer
with the 1,936-token first object (proofpoint 2021-07-28, chunk 1) restarts,
and at 8,192 ends by itself at 2,921 tokens with the same 6 choices.

The longest answer that ends by itself is therefore 3,167 tokens:
1.25 × 3,167 = 3,959, so the ceiling is **4,096**. At 4,096 every train
answer gives what it gives at 8,192, and a loop stops after about 167
seconds. 2,048 would have halved that again, and cut the Hydrojiin answer
before its first choice.

## Verdict

ADR-0060's rule (docs/eval/README.md), fixed before the runs:

- **(b)**: rule 1 is not met (−0.012, the interval includes 0) and rule 2 is
  broken (precision −0.027, the limit is 0.02). Not adopted. Its "write the
  answer once" did remove the restarts (3 to 0). The model also chose more
  (251 choices against 239). At parent level, the level scored, (b) added 16
  false-positive techniques and dropped 8, over 9 reports; the malicious-VPN
  report (5) and the Philippine-spoofing one (4) carry most of them. The
  extra parent-and-sub-technique pairs (21 against 9) cost nothing there, as
  a sub-technique scores as its parent. Which part of the wording did what is
  not separated: a narrower prompt change would need its own dev comparison.
- **(a) + (c)**: they change no dev answer, so the rule's gain criterion does
  not apply; precision, the spread (0, the 16 reports reproduce exactly) and
  the cost (−0.1%) are unchanged. What they buy is on the loops: about 160
  seconds saved per loop, and a cut the stage report states.

## Limits

- **The loop still happens.** (a) caps its cost; it does not stop it. On
  train, at the shipped prompt, one selection call in 21 ended at the 2,048
  ceiling, more than on dev (the candidate lists there have no extraction
  proposals). A loop that starts before the first choice closes still loses
  its chunk.
- **The default is measured on one setup.** 4,096 applies on vLLM with
  thinking off. A model that reasons before it answers (Gemini 2.5, vLLM with
  `VLLM_ENABLE_THINKING=true`) spends an unmeasured share of its budget
  first, so every other provider keeps `LLM_MAX_OUTPUT_TOKENS` unless
  `TTP_SELECT_MAX_OUTPUT_TOKENS` is set.
- **A longer genuine answer is cut too.** Its complete choices are kept and
  checked, and the candidates it did not reach go to review. The Hydrojiin
  answer shows the model can reason in prose before answering even with
  thinking off; one such answer longer than 4,096 tokens would be cut.
- **The train test is the selection call alone**, with retrieved candidates
  only, at 2,048; its 4,096 conclusions follow from the prefix property and
  the two answers re-sent at 8,192, not from a run at 4,096.
- **ATT&CK 20.0 not run** with (a) + (c). The change does not depend on the
  release: it acts on answers longer than the ceiling.
</content>
