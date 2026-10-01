# ADR-0064: The whole-document relation steps read the whole document

**Status:** Accepted (the fixes). The document-level pass stays opt-in, as
measured below.
**Date:** 2026-10-01
**Deciders:** maintainer
**Amends:** ADR-0057 (document-level relation pass)
**Relates to:** ADR-004 P3-A (Stage 3d), ADR-0013 / ADR-0055 (Stage 4c
`long_distance`), ADR-0060 (evaluation protocol), ADR-0061 (mapping ledger)

## Context

Comparing CTIParsor with Stixify, a web front end for txt2stix, raised a
question: is it better to find relations in one dedicated call that reads the
whole report? txt2stix does that. It sends the whole text and the list of
extractions in one call. That call asks for relations only, with no quote. The
job is refused when the text exceeds `INPUT_TOKEN_LIMIT` (15 000 tokens
recommended). CTIParsor has three steps meant to see past a chunk. Each of them
read only the start of the report:

1. **The document pass (ADR-0057).** `enrich_document_relations` allowed
   300 000 characters. `_call_llm` then cut every user prompt to
   `LLM_MAX_PROMPT_LENGTH` (32 000). The report text comes first, then the
   entity list and answer format. Measured through the real code path, with
   only the network call intercepted:

   | Report | Reached the model | Entity list | Answer format |
   |---|---|---|---|
   | 30 000 chars | 31 976 | yes | yes |
   | 60 000 chars | 32 000 | **no** | **no** |
   | 110 000 chars | 32 000 | **no** | **no** |

   Nothing failed. The unit test mocks `_call_llm`. The ADR's own validation
   (14 → 88 relationships) used an agent in place of the LLM, so it never
   reached the cut.
2. **Stage 3d.** `verify_relationships` sent `text[:3_500]`:
   - On the document pass, every claim supported after character 3 500 was
     judged against text that did not contain it, and removed.
   - On reports over 30 000 / 60 000 characters, chunks are 4 000 / 5 000
     characters plus overlap. The verifier never saw their tail.
   - Stage 3f had the same cut.
   - 3d's "a single sentence" rule also rejects what the document pass exists
     to find.
3. **Stage 4c.** The long-distance inferer read the first 6 000 characters.

The document pass also read Stage 3d's switch from the environment only. It
ignored a run that asked for 3d.

## Decision

1. **`_call_llm(max_prompt_length=...)`.** The document pass and its
   verification pass `LLM_DOC_MAX_PROMPT_LENGTH`. Past a limit, the *report
   text* is cut, never the instructions after it (`llm_parse.fit_text`), and
   the cut is logged.
2. **Stages 3d and 3f get the whole text they are given.** Their caller's limit
   trims the text, never the claims.
   - **Batches.** 3d verifies in batches of `STIX_VERIFY_BATCH_SIZE` (40).
     Every answer carries a quote, so 100+ claims in one call would outgrow the
     output budget. A cut-off answer keeps every claim unverified.
   - **Document mode** (`document=True`, document pass only). One sentence
     supports a claim. So do two sentences when the second only says who the
     first one's subject is ("the group, tracked as APT29"). A chain through a
     third entity is not support: "A uses B" and "B contacts C" do not support
     "A contacts C".
3. **Stage 4c** sends the whole report up to 12 000 characters. For a longer
   report it sends the passages around each mention of either entity:
   - each passage is ±700 characters, snapped to sentence boundaries;
   - a mention can be the name, an alias or the ATT&CK id;
   - passages naming both entities come first;
   - it falls back to the start of the report when neither entity is found.

   There is one call per disconnected sub-graph, so sending the whole report
   each time would multiply the cost.
4. **The document pass follows the orchestrator's 3d switch.**

## Measurement (2026-09-30)

**Setup.**
- Corpus: the 7 reports of `ctiparsor_measure`, 16 000 to 37 000 characters.
- Model: `Inferact/Qwen3.8-27B-NVFP4` on vLLM, `LLM_SEED=42`, provider sampling.
- Stages: 2 with every extractor on, 3f off, 3e off.
- Limits raised for the experiment: `LLM_TIMEOUT=1800`,
  `LLM_MAX_OUTPUT_TOKENS=16384`.

**Variants.** One series of calls per report, from which every variant is
composed, so the variants do not differ by sampling:

| Variant | Entities from | Relations from |
|---|---|---|
| A | per-chunk calls | per-chunk calls (production today) |
| B | per-chunk calls | the document pass only |
| A+D | per-chunk calls | both (ADR-0057) |

B has txt2stix's *organisation*: entities first, then one relations-only call
over the whole report. It is **not** txt2stix. B uses CTIParsor's entities, its
prompt (verbatim quote, evidence label, dates) and Stage 3d. txt2stix has its
own extraction and a prompt with no quote. It refers to entities by id, runs no
verification and maps to STIX in its own way. None of that was run.

- 3d was applied separately to each output, so every variant is measured
  before and after it.
- The pre-fix verifier was replayed for comparison.

**Judgment.**
- A blind sample of 125 relations, stratified by which variants found them. It
  includes 35 relations that 3d removed.
- Criteria were fixed before reading the sample:
  - `correct`: the text states this relation, verb and direction;
  - `partial`: the entities are linked in the text, but the verb or direction
    is wrong, `related-to` stands where the text gives a precise relation, or
    an endpoint is generic;
  - `unsupported`: co-occurrence only, a chain, or a noise endpoint.
- The judge was Claude, not a person. Read the numbers as estimates, with the
  intervals below.

| After 3d | A (chunks) | B (document only) | A+D |
|---|---|---|---|
| Relationships | 195 | 309 | 434 |
| Precision, strict (estimated) | **0.81** | 0.51 | 0.58 |
| Correct relationships (estimated) | 157 | 157 | **253** |
| Recall against the pooled correct set | 0.60 | 0.60 | **0.97** |
| Precision, lenient (correct + partial) | 1.00 | 0.89 | 0.92 |
| Share of `related-to` | 9 % | 25 % | 21 % |
| Emitted by Stage 4 (finalize-style lists) | 117 | 277 | 322 |

**Per stratum (strict, 95 % Wilson interval).**

| Found by | Correct |
|---|---|
| Both | 22/25 [0.70, 0.96] |
| Chunks only | 23/30 [0.59, 0.88] |
| Document only | 14/35 [0.26, 0.56] |
| Removed by chunk 3d | 1/15 correct |
| Removed by document 3d | 2/20 correct |

- **What the document pass alone gets wrong.**
  - 8 of 35 are `related-to` where the text gives a precise relation.
  - Some endpoints are generic ("phishing campaigns").
  - Some endpoints are noise ("Machine" from "Machine DPAPI").
  - Some techniques are never stated.
  - 30 of 35 are labelled `observed`.
- **The two organisations find different relations.** They share 70 of
  195 + 309 triples, and 92 entity pairs.
- **Effect of the fixes.**
  - The old 3d on the document pass kept 71 of 336 relations; the new one keeps
    309. Document-mode 3d removes little (8 %, against 32 % in chunk mode), but
    what it removes is wrong.
  - On the 36 900-character report, chunk 3d keeps 48 relations instead of 43.
  - On the same report, the document pass returns 153 relations instead of 114
    under the old 32 000-character cut.
- **Cost.**
  - Document calls took 45–664 s. The longest answer was 50 532 characters, cut
    at 16 384 tokens.
  - With the shipped `LLM_MAX_OUTPUT_TOKENS=8192` and `LLM_TIMEOUT=400`, at
    ~15 tokens/s, that call times out, is retried, and returns nothing.
  - Totals over the 7 reports: chunk calls 3 875 s, document calls 1 660 s,
    document 3d 866 s.

## Consequences

- **The fixes ship.**
- **The document pass stays opt-in.**
  - It adds about 60 % correct relations.
  - Only 40 % of what it adds is strictly correct.
- **B, one dedicated relations call over the whole document, is not better
  than the chunked extraction.** This holds for that organisation run with
  CTIParsor's components. It says nothing about txt2stix as shipped, which was
  not run.
  - B finds as many correct relations as A (≈157 each), but mostly different
    ones.
  - B's precision is 0.51, against A's 0.81.
- **Before turning the document pass on by default:**
  - `related-to` only when the text says "linked" or "associated";
  - no generic endpoints;
  - an IoC-table row relates to the actor or malware its table belongs to;
  - a stricter `observed`;
  - an answer split for long reports;
  - `LLM_TIMEOUT` and `LLM_MAX_OUTPUT_TOKENS` sized for the server;
  - then measure again.
- **Limits of this measurement.**
  - 7 reports, one run, one judge that is not a person, no human gold for
    relations (the in-house set is empty).
  - 19 of the 35 sampled document-only relations come from one report
    (UNC6671, a long IoC table).
  - Recall is relative to what any variant found, not to the report.
- **Seen in passing, not addressed.** For every organisation, Stage 4 rewrites
  40–50 % of the relations it emits to `related-to`, because the verb is not
  suggested for the pair (A: 60 of 117, A+D: 133 of 322). The ledger
  (ADR-0061) records it.
