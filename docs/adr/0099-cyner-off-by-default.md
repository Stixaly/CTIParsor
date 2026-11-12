# ADR-0099: Stage 2d (CyNER) is off by default

**Status:** Accepted
**Date:** 2026-11-12
**Deciders:** maintainer
**Relates to:** ADR-0088 (CyNER filters), ADR-0089 (the malware lead),
ADR-0098 (Stage 2e asks its model), ADR-0059 (the stage report), ADR-0094 (the
configuration contract), [the measurement](../eval/ner-swap-2026-11.md)

## Context

CyNER is the cyber NER of Stage 2d. Its malware and threat-actor names reach
the LLM's prompt with the gazetteer's, and reach the bundle when the LLM does
not drop them. ADR-0088 and ADR-0089 tried to make them more precise by
filtering; the second was not adopted.

The measurement of 2026-11 ran the pipeline end to end with CyNER (`base`), with
a candidate model in its seat (`cand`, dev only) and without any cyber NER
(`none`), at `LLM_TEMPERATURE=0`, `LLM_SEED=13`, on a vLLM server
([the page](../eval/ner-swap-2026-11.md)). Strict, true / false positives:

| Set | Type | `base` | `none` |
|---|---|---|---|
| AnnoCTR dev, 16 reports | malware | 34 / 132 | 32 / 46 |
| | threat actor | 15 / 31 | 14 / 12 |
| | tool | 11 / 20 | 12 / 28 |
| In-house, 8 reports | malware | 98 / 319 | 96 / 135 |
| | threat actor | 20 / 58 | 21 / 28 |
| | tool | 63 / 32 | 84 / 30 |

On dev, `none` − `base` in F1: malware +0.2153 [+0.1284, +0.3070], threat
actors +0.1828 [+0.0089, +0.3333], tools −0.0419 [−0.1672, +0.1275]. Malware
recall: −0.0513 [−0.1163, +0.0645]. Techniques: −0.0010 [−0.0729, +0.0732].
The LLM finds back almost all the names CyNER brings offline.

## Decision

**Stage 2d is off by default. `CYNER_ENABLED=true` turns it back on, as it was.**
Stage 2e stays as ADR-0098 left it (off until `GLINER_ENTITY_TYPES` names a
type), and spaCy, the rules and the gazetteer are unchanged.

## Alternatives rejected

- **(a) Keep CyNER.** In the two sets it adds the false malware and threat
  actors above (dev 86 and 19 more, in-house 184 and 30 more), for two true
  malware (34 → 32 on dev, 98 → 96 in-house) that the pipeline loses without
  it. It costs about 4 GB of memory more per pipeline process.
- **(b) Replace it with SecureModernBERT-NER.** On dev it is not better than
  having no cyber NER: malware F1 −0.0319 [−0.0969, +0.0378] and threat actors
  −0.0709 [−0.2286, +0.0763] against `none`, with 59 false malware against 46.
  It costs about twice CyNER's CPU (dev 617 s against 304 s in the stage), and
  was not run end to end on the in-house set.
- **(c) Treat NER outputs as candidates the LLM confirms.** Not built. It is
  the open lead: the LLM already sees these names among the gazetteer's, and a
  confirmation would be a prompt change that needs its own measure.

## Consequences

- **Memory.** About 4 GB less per pipeline process in these runs: 5.8 → 1.5 GB
  on dev and 6.1 → 2.2 GB on the in-house set. GLiNER was not loaded either in
  `none`, so the saving is CyNER's and GLiNER's together.
- **The default bundle changes**: fewer malware and threat actors that only the
  NER proposed. A `BUNDLE_AFFECTING` entry and a minor version, under ADR-0085.
- Rows already stored with `source="cyner"` stay as they are.
- An installation with `CYNER_ENABLED=true` in its `.env` does not change.
- The stage report of a default run shows 2d as skipped.

## What would reverse it

A set held out from all tuning in which malware or threat-actor recall falls
without CyNER.

## Limits

Those of the page: dev and the in-house set were used to tune the candidate and
are not independent tests; the in-house gold is AI-assisted, from one
maintainer, on 8 reports; one LLM, vision off; no interval on the in-house set;
the bundle's relationships are not measured; the reason tools rise without
CyNER (its names being shown to the LLM as already detected) is not checked
name by name.
