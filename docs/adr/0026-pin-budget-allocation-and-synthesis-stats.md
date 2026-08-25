# ADR-0026: Per-rule budget allocation for policy pins, and a synthesis-stats channel

**Status:** Proposed
**Date:** 2026-08-23
**Deciders:** maintainer

## Context

ADR-0024 Phase A capped policy-pin materialisation at `max_pinned_edges`
(default 200) and made every materialised edge carry `x_evidence_label="assessed"`
and `x_policy_rule`. That worked: the audit below confirms both properties hold
on every bundle currently in `cti_stix.db`.

The cap also introduced a defect that ADR-0024 could not have seen, because at
the time it was written no stored bundle had ever been produced *with* a cap.

### 1. The cap is saturated on every bundle, and it truncates by list order

Measured over the four bundles in `cti_stix.db` (2,023 relationship objects):

| job | total edges | `x_policy_rule` edges |
|---|---|---|
| CERT Polska | 364 | **200** |
| APT44 / Sandworm | 832 | **200** |
| ShinyHunters | 470 | **200** |
| GREYVIBE | 357 | **200** |
| **total** | **2,023** | **800 (39.5%)** |

Exactly 200 in all four. The cap is not a safety valve that occasionally fires —
it is the mechanism that decides what ships, on every single run.

Which 200 survive is decided by the **rank of the rule in the policy's `rules`
array**, because the materialisation loop is first-come-first-served:

```python
for _rule in _rules:
    if _capped:
        break
```

On GREYVIBE, the policy's 10th rule is `malware uses attack-pattern`. With 13
malware objects and 39 attack-patterns it has 507 candidate pairs, and it
consumed the entire budget:

```
malware uses attack-pattern   : 200 emitted (of 507 candidates)
everything after it in the list: 0
```

The thirteen rules that follow — `exploits`, `communicates-with` (×3), `drops`,
`consists-of` (×2), `resolves-to`, `belongs-to`, `indicates`, `related-to` (×2),
`uses` — produced **zero edges**, silently. The only signal is a
`logger.warning` naming the one rule that hit the cap, which says nothing about
the rules that were starved by it.

The same effect, one rule later, on ShinyHunters: the budget is exhausted
part-way through the last rule, which emitted 10 of its 24 candidate pairs.

### 2. Cartesian arithmetic, confirmed exactly

The candidate counts are the plain product of the two type populations, which is
what makes a single rule able to eat the whole budget:

| bundle | rule | product | edges |
|---|---|---|---|
| ShinyHunters | `indicator related-to domain-name` | 24 × 4 | 96 |
| ShinyHunters | `domain-name resolves-to ipv4-addr` | 4 × 7 | 28 |
| CERT Polska | `campaign uses attack-pattern` | 1 × 112 | 112 |
| CERT Polska | `threat-actor uses tool` | 4 × 17 − 5 already extracted | 63 |
| GREYVIBE | `malware uses attack-pattern` | 13 × 39 = 507 | 200 (capped) |

### 3. There is no channel out of Stage 4 for any of this

`build_stix_bundle` returns a bare `stix2.Bundle`. Stage 4b's `complete_graph`
*does* return a `CompletionStats` — and the call site at
`stage4_stix_mapping.py:843` **discards it**. So neither synthesiser can report
what it did. An operator looking at the Policy UI sees 25 pinned rules and has
no way to learn that 13 of them contributed nothing.

This is the same class of gap ADR-0024 closed for *individual edges* ("the
bundle must say where each edge came from"), left open one level up: the bundle
does not say what the synthesis **pass** did.

### 4. This is the evidence ADR-0024 asked for

ADR-0024 considered a per-source fan-out cap and deferred it:

> **Verdict:** deferred. Revisit once Phase C can measure whether high fan-out
> correlates with analyst rejection.

The objection was that the limit would be "picked with no data behind it". The
measurement above is not about picking a *limit* — the limit already exists and
is already 200. It is about how that fixed budget is **divided**, and the data
says the current division is "whoever is listed first takes everything".

## Decision

Two changes, both inside Stage 4.

| # | Change | File |
|---|---|---|
| **1** | Replace first-come-first-served truncation with **max-min fair share** allocation of `max_pinned_edges` across the pinned rules. Escape hatch `pin_budget_mode: "sequential"` restores the old behaviour. | `pipeline/stage4_stix_mapping.py` |
| **2** | Emit `x_synthesis_stats` on the Report SDO — per-rule pin accounting plus the `CompletionStats` that was being discarded — and surface it through the worker's existing `emit_progress` channel. | `pipeline/stage4_stix_mapping.py`, `api/worker.py` |
| **3** | `GET /api/relationship-policy/last-run` serves the newest bundle's accounting to the Policy page, which shows a per-rule `emitted / candidates` badge and the budget controls. | `api/routes/policy.py`, `frontend/src/components/PolicySynthesis.tsx`, `frontend/src/pages/Policy.tsx` |

### Why the endpoint parses exactly one bundle

`bundle_json` runs 475 KB–1.3 MB. Scanning back until a bundle carries the
property would make latency depend on how many pre-ADR-0026 bundles are stored,
and would answer a different question than the one asked: "last run" means the
last run, not "the last run that happens to have this data". A newest bundle
without the property returns `available: false`, and the UI says *"last run
predates this feature"* — which is the honest answer and is why the job id and
filename are still returned in that case.

Measured warm on the real database: **101 ms median**, of which **0.7 ms is the
JSON parse**. The remainder is reading the blob off the filesystem, so the
design choice costs almost nothing and the parse is not the thing to optimise.

### Why an unmeasured rule shows nothing rather than zero

A rule absent from the last run's `rules` array was not measured; a rule with
`emitted: 0` was measured and produced nothing. Rendering both as "0" would
erase the distinction the whole ADR exists to expose, so `RuleRunBadge` returns
`null` for the former.

### Max-min fair share, and why ascending order

Rules are served in order of **ascending** candidate count, each taking at most
an equal share of what remains:

```
demands = [8, 24, 507, 96]   budget = 200

  8   : share = 200 // 4 = 50  -> grant 8    remaining 192
  24  : share = 192 // 3 = 64  -> grant 24   remaining 168
  96  : share = 168 // 2 = 84  -> grant 84   remaining  84
  507 : share =  84 // 1 = 84  -> grant 84   remaining   0

grants = [8, 24, 84, 84]
```

Ascending order is the whole point: a small rule is always served **in full**,
and its unspent share flows to the larger rules. Two rules that both exceed
their share are truncated to the *same* number, not in list order. A leftover
pass hands out the units lost to integer division, so a budget smaller than the
rule count still serves someone rather than everyone getting zero.

The allocation is a pure function of `(demands, budget)`, so the same policy
over the same job yields the same bundle — a property `_make_deterministic_id`
already guarantees for objects and which must not be lost for edges.

### Counting candidates without duplicating the emit logic

Allocating requires knowing each rule's demand *before* emitting, and the demand
is not `len(src) × len(tgt)`: a pair is dropped when the two objects are the
same, when the verb is downgraded by `rel_is_suggested` into a key that already
exists, or when extraction already produced that exact edge.

Rather than reimplement that test in a counting pass — which would drift from
`_add_relationship` the first time either changed — the decision procedure is
extracted into one pure function, `_pin_edge_key(src, verb, tgt)`, returning the
exact dedup key the emit path would use, or `None`. Pass 1 calls it, keeps the
surviving `(src, verb, tgt)` triples, and pass 3 emits a prefix of that same
list. Counting and emitting cannot disagree because they are the same list.

### Why the stats ride on the Report SDO

Three candidate channels:

| channel | verdict |
|---|---|
| return `(bundle, stats)` from `build_stix_bundle` | rejected — breaks five call sites (worker, `main.py`, two scripts, tests) for an accessory value |
| **`x_synthesis_stats` custom property on the Report SDO** | **adopted** — travels with the bundle, survives export, needs no signature change; `allow_custom=True` is already in use for `x_evidence_label` |
| `emit_progress` callback only | rejected as the sole channel — worker-only, and the information dies with the job |

The adopted option extends ADR-0024's own thesis one level up: the bundle should
be self-describing about its own synthesis, not only about each edge. The worker
reads the property back off the Report for `emit_progress`, so the live UI
channel is a consumer of the durable record rather than a parallel path.

Capturing `CompletionStats` into the same property is free once the channel
exists, and it closes the "4 edges labelled `inferred` with no
`x_inference_rule`" inconsistency ADR-0024 noted but did not act on.

## Options considered

### Option 1 — Raise `max_pinned_edges`

**Pros:** one number, no code.
**Cons:** does not fix the ordering bias, it only moves the cliff. With 507
candidates on one rule and 26 rules in the policy, any budget that serves the
tail generously also restores the cartesian blow-up the cap was added to stop.
**Verdict:** rejected — treats the symptom, and re-opens the ADR-0024 problem.

### Option 2 — Per-source fan-out cap (ADR-0024's deferred Option 3)

**Pros:** directly limits "one malware object acquiring 39 outgoing edges".
**Cons:** still needs a fan-out number with nothing behind it, and it does not
address starvation: a rule with many *sources* still exhausts a global budget.
**Verdict:** still deferred. Orthogonal to this ADR and can be layered later.

### Option 3 — Fair-share allocation (adopted)

**Pros:** no new magic number — it redistributes a budget that already exists;
deterministic; strictly better than the status quo for every rule that was
being starved, and never worse for the rules that were winning by rank alone.
**Cons:** the biggest rules emit fewer edges than before (84 instead of 200 in
the worked example), so a policy that *intends* a high-cardinality pin will look
under-served — which is exactly what the new stats make visible, and what the
`sequential` escape hatch exists for.
**Verdict:** adopted.

### Option 4 — Drop the budget and gate pins on textual evidence instead

**Pros:** attacks the cartesian at its root rather than rationing it.
**Cons:** a much larger change, with a real risk of deleting correct edges for
object types whose names never appear verbatim in the report (attack-patterns
come from ATT&CK mapping, not from the text). It needs a before/after
measurement per rule to be safe — and that measurement is precisely what the
stats channel in this ADR provides.
**Verdict:** deferred to a follow-up ADR, sequenced *after* this one, because
this one is its instrument.

## Consequences

- **Easier:** every pinned rule gets a defensible share of the budget; the Policy
  UI can show what each rule actually produced; the effect of any future change
  to pin materialisation becomes measurable per rule rather than as one total.
- **Harder:** high-cardinality rules emit fewer edges than they did, and an
  operator who wants the old behaviour must set `pin_budget_mode: "sequential"`
  explicitly. Bundles produced before this change carry no `x_synthesis_stats`,
  so every consumer of the property must treat it as optional.
- **Known limitation, accepted:** the candidate set is claimed across rules in
  policy order, so a key claimed by a rule that is later truncated is not
  offered to a subsequent rule. Reaching that needs two rules on the same
  (source-type, target-type) pair whose verbs both downgrade to `related-to`.
  The alternative — claiming at emit time — spends budget on calls that dedup
  into no-ops. The same mechanism correctly neutralises a rule duplicated in the
  policy: the stored policy contains `intrusion-set attributed-to threat-actor`
  twice, and the second copy reports zero candidates rather than doubling the
  demand.
- **Revisit:** the value `200` itself. It was inherited from Stage 4b's
  `max_new_edges` by symmetry, not measured. Once the stats accumulate across
  jobs, the answerable question becomes "how many synthesised edges does an
  analyst actually review per report?", and the budget can be set from that
  rather than from a sibling module's default.

## Results

`scripts/measure_pin_allocation.py` replays each stored job read-only under the
stored policy, once in each mode, and reads the per-rule table back off the
rebuilt Report's `x_synthesis_stats` — so the numbers below also prove the
property survives Report construction, `_stamp_objects` and Bundle assembly.

### Starvation was worse than the stored bundles showed

| job | candidate pairs | rules served, `sequential` | rules served, `fair-share` | rescued |
|---|---|---|---|---|
| CERT Polska | 1,673 | 6 | 17 | **+11** |
| APT44 / Sandworm | 16,226 | 3 | 15 | **+12** |
| ShinyHunters | 214 | 7 | 7 | +0 |
| GREYVIBE | 313 | 4 | 7 | **+3** |
| **total** | **18,426** | **20** | **46** | **+26** |

On APT44 the first rule alone has 7,838 candidates; under `sequential` it and
two others took the entire budget and **twelve rules emitted nothing**. The
audit in the Context section, taken from stored bundles, showed 13 starved rules
on one report — replaying under the current policy shows the pattern holds on
three of four.

GREYVIBE is the clean demonstration of the intent: every small rule is satisfied
in full (7/7, 6/6, 4/4, 1/1) and the single 273-candidate rule absorbs all the
truncation, instead of the four smallest getting nothing.

ShinyHunters is the honest null result: no rule was rescued, because
`sequential` already reached every rule. Fair-share still changed the split —
`indicator indicates campaign` goes from 10/24 to 24/24, paid for by
`indicator related-to domain-name` dropping from 96/96 to 82/96 — which is a
preference for completing a rule over half-serving it, not a measured
improvement.

### What the measurement also says, and it is not flattering

With 15–17 pinned rules and a budget of 200, fair share gives each rule **about
14 edges**. On APT44 that means emitting 14 of 7,838 candidate
malware×technique pairs. Those 14 are deterministic, but they are not
*meaningful*: nothing distinguishes them from the 7,824 that were dropped.

The total candidate pool across the four jobs is **18,426 for a budget of 200 —
92×**. So this ADR fixes a real, order-dependent defect (a rule's output
depended on its rank), and in doing so it makes plain that **rationing is the
wrong lever when the pool is two orders of magnitude larger than the budget**.
Spreading the arbitrariness evenly is better than concentrating it, but it is
still arbitrariness.

That is the argument for gating pins on textual co-occurrence (Option 4 above),
and it is now an argument backed by a number rather than by taste. This ADR is
the instrument that produced it.

### A defect the UI work uncovered, older than this ADR

Wiring the two new policy fields into the Policy page exposed why the stored
policy has no `completion` block even though `complete_graph` reads one:
`PUT /api/relationship-policy` is a **full replacement**, and all four save
paths in the page sent only `{version, global, rules}`. Every edit an analyst
made silently discarded the Stage 4b configuration of ADR-0013 — and would have
discarded `max_pinned_edges` and `pin_budget_mode` the same way. Saves now
spread the last server response so unknown top-level keys survive.

`max_pinned_edges` also had no validation anywhere: any type was accepted and
coerced silently inside Stage 4. It is now rejected at the API boundary.

### Verification that the regression test bites

Per the project's step 8bis, the defect was reintroduced (making `_fair_share`
allocate first-come-first-served) and the test re-run:

```
malware uses attack-pattern         candidates=507  emitted=200
domain-name resolves-to ipv4-addr   candidates=28   emitted=0
=> test WOULD FAIL
```

`test_materialise_no_rule_is_starved_by_list_order` locks the behaviour.

Six of the sixteen generated test fixtures were initially missing
`"mode": "pin"` on their rule dicts. Four failed outright; **two passed for the
wrong reason** — `test_materialise_respects_global_auto` and
`test_materialise_skips_non_spec_verb` both assert "nothing was emitted", which
was true because the rule was skipped for the missing `mode`, not for the reason
each test names. Fixed before counting the suite as green.

## Related

Extends ADR-0024, whose Phase A cap this ADR re-divides without removing, and
supplies the per-rule instrument its deferred Option 3 was waiting on. Uses the
evidence vocabulary of ADR-0009 unchanged — a fair-share edge is still
`assessed`. The stats channel mirrors ADR-0013's `CompletionStats`, and finally
delivers it to a consumer.
