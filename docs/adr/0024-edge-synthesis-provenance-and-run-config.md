# ADR-0024: Edge-synthesis provenance and run configuration

**Status:** Proposed
**Date:** 2026-08-22
**Deciders:** maintainer

## Context

ADR-0023 built a measurement layer for TTP extraction. Pointing the existing
harnesses at what the pipeline actually *ships* — rather than at what the
`relationships` table stores — surfaced a larger problem in a different stage.

### 1. The bundle is 30× the extraction, and 76% of it carries no provenance

On the GREYVIBE report (`cti_stix.db`, job `32b5475b`):

| | count |
|---|---|
| relationships in the `relationships` table (extracted) | 38 |
| relationship objects in `bundle_json` (shipped) | **1,140** |

By evidence label:

| `x_evidence_label` | count |
|---|---|
| **(absent)** | **914** |
| `inferred` (Stage 4b) | 204 |
| `reported` | 18 |
| `assessed` / `observed` | 4 |

872 of the unlabelled edges are `uses`, and their shape identifies the source
exactly:

```
malware        -> uses -> attack-pattern : 350   (7 malware  x 50 techniques)
attack-pattern -> uses -> tool           : 500   (10 tools   x 50 techniques)
```

Every malware family in the bundle — `LegionRelay`, `PhantomRelay`,
`PhantomRelayV1`, `PhantomRelayV2`, `PhantomRelayLite`, `FallSpy` — has an
out-degree of exactly 50, the number of attack-patterns present. That is an
all-pairs materialisation.

**This is not a defect in the loop.** It is the policy-pin feature at
`stage4_stix_mapping.py:769`, working as designed and as documented in its own
comment: *"This is an all-pairs (Cartesian) materialisation, so high-cardinality
pairs … can create many edges — set such pairs to 'Auto' in the policy if that's
not wanted."* In `enforce` mode a pinned rule materialises the analyst's link
model across every pair of the two types.

### 2. The real defect: a materialised assumption is indistinguishable from a fact

ADR-0009 established the evidence vocabulary `observed / reported / assessed /
inferred / gap`, carried into STIX as `x_evidence_label`, and made the
review-UI auto-accept gate evidence-graded. Two mechanisms in the pipeline
synthesise edges the extraction never proposed, and they behave oppositely:

| | Stage 4b (`complete_graph`) | policy-pin (`stage4_stix_mapping.py:769`) |
|---|---|---|
| labels every edge | **yes** — `x_evidence_label` at `stage4b:548` | **no** |
| names the rule that created it | **yes** — `x_inference_rule`, `x_inferred_from` | no |
| caps its output | **yes** — `max_new_edges: 200` | **no** |
| observed output on GREYVIBE | 204 edges | 872 edges |

So the weaker-provenance mechanism is both unlabelled and uncapped, and it
produced 4× more edges than the one that is careful. A consumer of the bundle
cannot distinguish "the report says this malware uses this technique" from "the
analyst pinned malware→uses→attack-pattern and every pair was materialised".

This also makes the hallucination metric unable to be honest: a policy edge is
not a hallucination, it is an assertion — but with no label, the harness has no
way to score it as one.

### 3. The run configuration is not recorded anywhere

The policy currently stored in `relationship_policy` is
`{"version": 1, "global": "enforce", "rules": []}` — **no pinned rules at all**.
The rules that produced those 872 edges no longer exist. `relationship_policy`
is a single mutable row; `jobs` has columns `id, original_filename, status,
report_text, bundle_json, llm_result_json, created_at, updated_at, tlp_level,
pap_level` and nothing else.

Therefore that bundle **cannot be reproduced or audited**. Neither can any
other: nothing records which stages ran, which embedding model, which
thresholds, or which policy was in force.

The same gap is visible in the entity table. Across both real reports, entity
`source` values are `llm=118`, `ioc=26`, `gazetteer=2`, and **zero** from
`semantic`, `cyner` or `gliner`. Either those four extraction stages were
disabled for those runs, or they contribute ~1% of entities — and there is no
way to tell which. Every A/B comparison ADR-0023 Phases 3-6 depends on is
unfalsifiable until this is fixed.

### 4. Measurement covers 3.3% of what ships

`-b grounding --from-db` scores the 38 rows in `relationships`. The `rel`
benchmark scores hand-written fixtures. Neither reads `bundle_json`. Run today
on both real reports, grounding reports:

```
Entities (named types):     grounding 0.947   hallucination 0.053
Relationships (window +-1): CLAIM     0.585   hallucination 0.415
  named-entity rels : claim 0.603  halluc 0.397  (n=63)
  IoC / technical   : claim 0.000  halluc 1.000  (n=2)
```

Those numbers describe 65 edges out of 1,207 shipped across the two bundles.

## Decision

Three phases. Phase A makes synthesised edges honest, Phase B makes runs
reproducible, Phase C points the metric at what ships.

| Phase | Change | File(s) |
|---|---|---|
| **A** | Policy-materialised edges carry `x_evidence_label="assessed"` and `x_policy_rule="<src> <verb> <tgt>"`, mirroring Stage 4b's `x_inference_rule`. Add a `max_pinned_edges` cap (default 200, same as 4b's `max_new_edges`) that logs a warning naming the rule when it truncates. | `pipeline/stage4_stix_mapping.py` |
| **B** | Additive `jobs.run_config_json` column, written by the worker at job start: relationship-policy snapshot, enabled stage list, embedding model id, resolved thresholds, the `TTP_*` / `ENABLE_*` env flags, and `git rev-parse HEAD`. | `api/worker.py`, migration |
| **A2** | Label the ordinary Stage 4 mapping edges (`based-on` -> `observed`; `indicates`, `targets` -> `reported`), which the audit showed are 48 of the 67 edges in the second bundle and are untouched by Phase A. | `pipeline/stage4_stix_mapping.py` |
| **C** | `-b grounding --from-bundle` reads `bundle_json` and reports **by evidence label**, scoring hallucination only over edges that claim evidential support. | `tests/eval_pipeline.py` |

### Why `assessed` rather than a sixth label

A pinned rule is the analyst's judgement about how objects relate, not the
document's evidence. Of the ADR-0009 vocabulary, `assessed` is that. Adding a
sixth term would fragment a taxonomy the review-UI auto-accept gate already
keys on, and `assessed` correctly fails that gate: only `observed`
auto-promotes, so materialised edges will queue for review rather than ship
silently — which is the behaviour we want and do not currently get.

### Why hallucination is scored only over evidential labels

An `assessed` or `inferred` edge makes no claim to be supported by a sentence in
the report, so scoring it against the report text measures nothing. Phase C
reports three separate populations — evidential (`observed`/`reported`),
synthesised (`assessed`/`inferred`), and unlabelled — and computes hallucination
only over the first. An unlabelled edge counts as a **defect in provenance**,
not as a hallucination, and its size is the regression signal.

**Correction, from running the audit (see below): Phase A does not empty that
population.** An earlier draft of this ADR claimed it would. It does not, because
the policy-pin block is not the only unlabelled edge source — the ordinary Stage 4
mapping helpers (`indicates`, `based-on`, `targets`) call `_add_relationship`
without a label too. Phase A2 covers those.

This also explains a known distortion. The harness reports 41.5% relationship
hallucination while manual review of the same output put the true rate near
12.5%; the gap is largely coreference and alias resolution, not invented facts.
Splitting by label is a precondition for that number becoming actionable —
the same lesson as ADR-0023 Phase 1, one stage further down.

### Audit baseline — measured, not assumed

`scripts/audit_edge_provenance.py` (read-only, stdlib only) over both stored
bundles:

| | GREYVIBE | ShinyHunters |
|---|---|---|
| edges | 1,140 | 67 |
| labelled | 226 (19.8%) | 19 (28.4%) |
| **unlabelled** | **914 (80.2%)** | **48 (71.6%)** |
| by label | `inferred=204, reported=18, assessed=3, observed=1` | `observed=11, reported=8` |
| run config | **ABSENT** | **ABSENT** |

**Total: 1,207 edges, 245 labelled (20.3%), 962 unlabelled.**

Three things this measurement changed:

1. **The two bundles have different unlabelled populations.** GREYVIBE's top
   pairs are `attack-pattern->tool=500`, `malware->attack-pattern=350`,
   `threat-actor->attack-pattern=100`, `indicator->attack-pattern=50` — every one
   a multiple of the 50 attack-patterns present, the signature of all-pairs
   materialisation. ShinyHunters has no such fan: its top pairs are
   `indicator->observed-data=24`, `threat-actor->identity=12`,
   `indicator->tool=10`. **Its 48 unlabelled edges are ordinary Stage 4 mapping
   output, not policy pins**, and Phase A does not touch them.

2. **Stage 4b hit its own cap.** 200 edges carry `x_inference_rule`, exactly
   `max_new_edges`. A further 4 carry `x_evidence_label="inferred"` without an
   `x_inference_rule` — a small inconsistency in 4b worth a follow-up.

3. **`policy-pin: 0` on both bundles**, because the old code stamped nothing.
   The attribution of GREYVIBE's 872-edge fan to the pin block therefore remains
   an inference from its arithmetic shape, not a proven provenance — which is
   precisely the condition Phase A ends and `run_config_json` makes impossible to
   fall back into.

### Phase A2 — label the ordinary mapping edges

The Stage 4 helpers that call `_add_relationship` without a label, and the grade
each should carry:

| call site | edge | label | why |
|---|---|---|---|
| `indicator --based-on--> observed-data` | structural | `observed` | a mechanical restatement of an IoC actually present in the text |
| `indicator --indicates--> malware` | from `llm_result.ioc_associations` | `reported` | the model's claim about what the document links |
| `threat-actor --targets--> location / identity` | from LLM targeting | `reported` | same |

Phase A2 is a small change — the `custom=` parameter Phase A added to
`_add_relationship` already carries it — but it must not be folded into Phase A
silently: it changes the label distribution of every bundle, and the audit above
is the baseline it will be measured against.

## Options considered

### Option 1 — Turn the policy-pin feature off by default

**Pros:** removes 872 edges immediately; smallest diff.
**Cons:** deletes a feature an analyst deliberately uses to express a link model,
to fix a labelling problem. The edges are not wrong, they are unattributed.
**Verdict:** rejected — treats the symptom.

### Option 2 — Label and cap (adopted)

**Pros:** keeps the feature; makes its output self-describing and bounded;
reuses the vocabulary, the cap value and the code shape Stage 4b already
established, so the two synthesisers stop behaving differently.
**Cons:** bundles gain edges that fail auto-accept and therefore need review —
a visible increase in analyst workload that was previously hidden by shipping
them unlabelled.
**Verdict:** adopted. The workload was always there; it was just invisible.

### Option 3 — Label, cap, and additionally cap by fan-out per source object

**Pros:** would stop one malware object acquiring 50 outgoing edges.
**Cons:** picks a fan-out limit with no data behind it, which is the mistake
ADR-0023 was written to stop repeating.
**Verdict:** deferred. Revisit once Phase C can measure whether high fan-out
correlates with analyst rejection.

## Consequences

- **Easier:** bundles become auditable — every edge says where it came from, and
  `run_config_json` says what produced the bundle. Phases 3-6 of ADR-0023 become
  falsifiable, because a baseline can finally be attributed to a configuration.
- **Harder:** more edges reach the review queue, because `assessed` correctly
  fails the auto-accept gate. Bundles produced before Phase B have no run config
  and stay unreproducible — they should be treated as un-attributable rather than
  back-filled with guesses.
- **Revisit:** Option 3's per-source fan-out cap, once there is evidence for a
  limit.

**Prediction that was wrong.** This ADR originally stated that the 41.5%
relationship hallucination figure "is expected to fall sharply once synthesised
edges are scored separately". Measured, it **rose**: 41.5% over the 65 rows of
the `relationships` table becomes **50.0% over the 38 evidential edges of the
bundle**. The two numbers were never comparable — different populations, which is
precisely why Phase C exists — so predicting a direction was the mistake, not the
result. What the split actually bought is diagnostic power, below.
- **Sequencing:** Phase B should land before ADR-0023 Phase 3. A TRAM2 baseline
  recorded without a run config cannot be compared against anything later.

## Results

### Phase A + A2 — rebuilt under the policy that caused the problem

`scripts/rebuild_bundle_provenance.py` replays a stored job in memory (read-only,
`mode=ro`) under an explicit policy. Rebuilding GREYVIBE with the two pinned
rules whose arithmetic signature the original bundle carries:

| | stored bundle | rebuilt with A + A2 |
|---|---|---|
| edges | 1,140 | **350** |
| **unlabelled** | **914 (80.2%)** | **0** |
| `assessed` | 3 | 203 (200 pinned + 3 extracted) |
| `inferred` | 204 | 100 |
| `reported` / `observed` | 18 / 1 | 45 / 2 |
| edges carrying `x_policy_rule` | 0 | 200 |
| cap | none | **respected** |

The cap warning fired naming the rule that hit it:

```
[Stage 4] policy-pin materialisation capped at 200 edges
(rule 'malware uses attack-pattern'); raise max_pinned_edges ...
```

Edge count fell 3.3x, entirely from the cap. Every shipped edge now carries
provenance.

### Phase C — what the split is actually worth

`-b grounding --from-bundle all` over both stored bundles:

```
  (unlabelled)         962 ( 79.7%)
  inferred             204 ( 16.9%)
  reported              26 (  2.2%)  <- scored
  observed              12 (  1.0%)  <- scored
  assessed               3 (  0.2%)
  total               1207
```

Scoring the 38 evidential edges:

| setting | claim grounding | hallucination |
|---|---|---|
| `--rel-window 1` (default) | 0.500 | **0.500** |
| `--rel-window 3 --alias-aware` | 0.789 | **0.211** |

**Endpoint grounding is 1.000 in both runs — 38 of 38, zero dangling.** No
evidential edge references an entity absent from the report. Every one of the
"hallucinations" is an `endpoints-only` grade: both entities present, never close
enough together to count as an assertion. Widening the window from +-1 to +-3 and
resolving aliases moves 12 of the 19 into `window`, leaving 8.

That is the diagnostic the split bought. The headline rate is dominated by a
proximity heuristic, not by invented facts, and it is now possible to say so with
a number instead of asserting it. The residual 8 edges are the population worth a
human read; the earlier 41.5% figure pointed at 27 and could not distinguish them.

## Related

Extends ADR-0009 (trust & provenance) to the one edge source it did not cover,
and applies ADR-0013's own discipline — label every synthesised edge, name the
rule, cap the output — to the mechanism that predates it. Unblocks ADR-0023
Phase 3 by making a measured baseline attributable to a configuration.
