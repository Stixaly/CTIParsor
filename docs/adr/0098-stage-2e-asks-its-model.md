# ADR-0098: Stage 2e asks its model, and its report says whether it answered

**Status:** Accepted. Amended 2026-11-12: the default of
`GLINER_ENTITY_TYPES` is `identity,location` (§5).
**Date:** 2026-11-11
**Deciders:** maintainer
**Relates to:** ADR-0004 (P2-A, GLiNER as Stage 2e), ADR-0051 (one cutoff per
entity type), ADR-0059 (the stage report), ADR-0094 (the configuration
contract), the NER measurement of 2026-11-10 (main `afd9ee6`)

## Context

Stage 2e sent each batch of chunks to `model.predict_entities(batch_texts, …)`.
In gliner 0.2.29, the version of `requirements/requirements.lock.txt`, that
method takes one string: it wraps its argument in a list and calls
`inference`. Given a list of texts, it returns `[]` and raises nothing.

The stage read `[]` as "no entity in these chunks". So for every report it
recorded `ran`, 0 entities, about 0.003 s, with the model (about 3 GB) loaded.
The evaluation run `ner-dev-base-1ef9638` of October already shows it, and the
1.0 model journey recorded "2e ran (0 rows)" for both of its reports and passed
its "models ran" check.

Two things hid it:

- The stage accepted an empty answer for a batch as a valid shape.
- The tests' fake model answered a list with one list per text, which is what
  the stage assumed and not what gliner does.

The measurement of 2026-11-10 called the model through its batch API, with the
six labels and the 0.40 threshold, Stages 2c and 3 off. What GLiNER alone then
adds, strict matching:

| Set | Entity type | Correct | False | Precision |
|---|---|---|---|---|
| AnnoCTR dev, 16 reports | identity (sectors) | 37 | 30 | 0.55 |
| AnnoCTR dev | location | 7 | 4 | 0.64 |
| AnnoCTR dev | threat_actor | 3 | 51 | 0.06 |
| AnnoCTR dev | malware | 1 | 17 | 0.06 |
| In-house, 8 reports | campaign | 8 | 58 | 0.12 |
| In-house | threat_actor | 2 | 47 | 0.04 |
| In-house | malware | 7 | 55 | 0.11 |

Before the repair no Stage 2 source found a sector (77 in the dev gold) or a
campaign (12 in the in-house gold). With the six labels, the precision of
threat actors on dev goes from 0.34 to 0.16 (14 correct for 27 false, then 15
for 79). Stage 2e took 934 s for the 16 dev reports and 361 s for the 8
in-house ones; CyNER took 274 to 304 s and 150 s.

Not measured: infrastructure (neither gold has the type), any of this with
Stage 3 on, and the stage's time with fewer labels.

## Decision

### 1. A batch goes through the batch API

`_ask_batch` calls `model.inference(texts, labels, …)`, which returns one list
of predictions per text. A model without `inference` (gliner before that name;
the requirement is `gliner>=0.2.0`) is asked through `batch_predict_entities`.
`predict_entities` is kept for what it does: one chunk, in the fallback.

### 2. An answer is held to its shape

The answer for a batch is one list of prediction dicts for each chunk. Anything
else (an empty list, a flat list, a list one short, `None`) is an error, and
the batch is asked again one chunk at a time. An empty answer for a batch is
never "nothing found".

### 3. The stage report says `ran` only when the model answered

`run_gliner` returns the entities with what happened: the chunks, the chunks
answered, the batches asked again. The orchestrator records Stage 2e as:

- `failed` when the model did not load, or answered none of the chunks;
- `ran`, with a reason, when some chunks stayed unanswered or a batch answer
  was refused;
- `ran` otherwise.

The entry counts `chunks` and `chunks_unanswered` beside `entities`.
`extract_gliner_entities` keeps its signature.

### 4. `GLINER_ENTITY_TYPES` names what the model is asked for

A list of entity types, separated by commas, among `identity`, `location`,
`campaign`, `infrastructure`, `malware`, `threat_actor`. Each stands for one
GLiNER label. A name outside the six is left out with a warning. The run
configuration of a job records the variable.

Unset or empty, the stage is skipped with the reason
`disabled: GLINER_ENTITY_TYPES names no entity type`, and the model is not
loaded.

Empty is the default of this ADR because it is the only value that changes no
bundle: the stage produced nothing before, and produces nothing until a type is
named. The repair with the six labels would halve the precision of threat
actors. Which types to ask for is the maintainer's choice, between:

- **(a) `identity,location,campaign,infrastructure`.** Sectors and campaigns
  get their only Stage 2 source, at the precisions above (0.55 and 0.12);
  threat actors and malware stay with the gazetteer and CyNER. The model stays
  in the image and in each worker, and the stage costs about three times
  CyNER's time (measured with six labels).
- **(b) Remove the stage.** No GLiNER dependency, no model to download or
  load. Sectors, campaigns and infrastructure then have no Stage 2 source.

### 5. Amendment of 2026-11-12: the default is `identity,location`

The maintainer chose on 2026-11-12: GLiNER is used for identities (targeted
sectors) and locations (targeted countries). Unset, `GLINER_ENTITY_TYPES` is
`identity,location`. Set to an empty value, the stage is off as in §4. The
other four types stay available by naming them.

What is known when this is decided:

- GLiNER alone, without the LLM (table above): sectors 37 correct for 30
  false, countries 7 for 4, on AnnoCTR dev.
- The LLM alone, end to end on the same 16 reports with GLiNER silent
  (docs/eval/ner-swap-2026-11.md, run `nerswap-e2e-none`): 29 correct sectors
  for 51 false, out of 77 in the gold; with spaCy, 40 correct locations for
  37 false.
- The two together are not measured, nor the stage's time with two labels.

## Consequences

Of the amendment:

- Bundles change for the same report: sectors and countries from GLiNER are
  added. `BUNDLE_AFFECTING` has the entry, and the contract records the
  changed default.
- A run loads the GLiNER model again, and Stage 2e takes its time again
  (934 s for the 16 dev reports with six labels).
- A default run shows 2e as `ran`, so the "models ran" check of
  `scripts/check_model_journey.py` passes on it again.
- An `.env` that sets `GLINER_ENTITY_TYPES=` (the line of `.env.example`
  between ADR-0098 and this amendment) keeps the stage off.

Of the ADR as first written (the empty default of §4):

- No bundle changes with this ADR: no `BUNDLE_AFFECTING` entry. Setting a
  default other than empty will need one, and a `default` change in the
  contract.
- A run with the default configuration no longer loads the GLiNER model. The
  sizing figure of docs/operations.md (4.4 GB per report, mostly GLiNER) was
  measured with it loaded and is not measured again here.
  `docker/warm_models.py` still downloads the model when `GLINER_ENABLED` is
  true, so naming a type needs no new image, and
  `scripts/measure_cold_start.py` still loads it.
- The stage report of a default run shows 2e as `skipped`. `docker_smoke.sh
  --job` accepts a required stage that the configuration turned off. The
  "models ran" check of `scripts/check_model_journey.py` fails on 2e until a
  type is named: it passed before on a stage that had asked nothing.
- A GLiNER model that loads and answers nothing now fails the stage, and a run
  that requires 2e stops there.
- The tests' fake model behaves as gliner 0.2.29 does: `predict_entities`
  returns `[]` for a list.
