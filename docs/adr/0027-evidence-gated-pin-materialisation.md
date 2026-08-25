# ADR-0027: Evidence-gated pin materialisation, restricted to anchorable types

**Status:** Proposed
**Date:** 2026-08-23
**Deciders:** maintainer

## Context

ADR-0026 replaced rank-order truncation of the policy-pin budget with max-min
fair share, and its own Results section said plainly what that did not fix:

> The total candidate pool across the four jobs is **18,426 for a budget of 200
> — 92×**. […] Spreading the arbitrariness evenly is better than concentrating
> it, but it is still arbitrariness.

The obvious next lever is to stop materialising pairs the report never discusses
together: emit `malware --communicates-with--> domain-name` only when that
malware and that domain co-occur in the text. ADR-0026 listed this as its
Option 4 and deferred it to "a follow-up ADR, sequenced after this one, because
this one is its instrument".

### The measurement that had to come first

The approach only works if an object's identity actually appears in the report.
Before writing any gate, every object in the four stored bundles was tested
against its own `report_text` (case-insensitive, over `name`, `value`,
`aliases`, and file hashes):

| STIX type | appears verbatim | rate |
|---|---|---|
| `domain-name` | 39/39 | **100%** |
| `ipv4-addr` | 20/20 | **100%** |
| `url` | 10/10 | **100%** |
| `tool` | 47/48 | **97.9%** |
| `malware` | 81/83 | **97.6%** |
| `threat-actor` | 15/16 | **93.8%** |
| `file` | 61/67 | **91.0%** |
| `vulnerability` | 4/5 | 80.0% |
| `location` | 9/13 | 69.2% |
| `campaign` | 1/3 | 33.3% |
| **`attack-pattern`** | **74/304** | **24.3%** |
| **`indicator`** | **0/136** | **0%** |
| **`course-of-action`** | **0/344** | **0%** |

Two of those rows invalidate assumptions written into ADR-0026's own sketch of
this feature.

**`indicator` at 0% is a fixable mistake, not a finding.** An Indicator's `name`
is `"Indicator: evil.com"` or `"Malicious IoC: evil.com"` — it *contains* the
IoC but the full string never appears in prose. Anchoring on the values parsed
out of its `pattern` instead:

| indicator anchor | rate |
|---|---|
| `name` | 0/136 (0%) |
| **`pattern` values** | **131/136 (96.3%)** |

**`attack-pattern` at 24.3% is a real finding, and no alternate anchor rescues
it:**

| attack-pattern anchor | rate |
|---|---|
| MITRE name | 74/304 (24.3%) |
| `external_id` (`T1071.001`) | 51/304 (16.8%) |
| parent id (`T1071`) | 63/304 (20.7%) |

An attack-pattern is produced by the ATT&CK mapping stages, not by a verbatim
mention. `course-of-action` is the same mechanism and scores 0/344. A textual
co-occurrence gate cannot judge these objects; applying one would delete the
majority of legitimately-mapped technique edges.

### How much volume that exempts

Candidate pairs whose target is an `attack-pattern`, across the four jobs:

| job | attack-pattern pairs | all pairs |
|---|---|---|
| CERT Polska | 416 | 1,673 |
| APT44 / Sandworm | 7,955 | 16,226 |
| ShinyHunters | 35 | 214 |
| GREYVIBE | 273 | 313 |
| **total** | **8,679** | **18,426** |

**47% of the candidate pool is out of the gate's reach.** This ADR therefore
does not claim to solve the cartesian problem; it solves it for the 53% where
evidence exists to solve it with.

### The alternative that was considered and rejected

The pipeline already produces `malware --uses--> attack-pattern` edges by
Stage 4b transitive inference, carrying `x_inference_rule`. On GREYVIBE the
bundle holds both mechanisms for the same pair:

```
('malware','uses','attack-pattern','assessed','PIN')   200
('malware','uses','attack-pattern','inferred','INF')    49
```

Dropping the two attack-pattern pin rules from the policy would remove 8,679
candidate pairs at zero code cost. It was rejected on analyst grounds: Stage 4b
infers 49 of those edges where the pin rule materialises 200, so removing the
rule removes the analyst's view of *which techniques this malware uses* and
*which techniques this campaign uses overall* — a primary question the tool
exists to answer. Coverage of that question is worth more than the tidiness of
the graph.

## Decision

A co-occurrence gate between the rule loop and `_add_relationship`, applied
**only to pairs whose endpoints are both textually anchorable**.

### 1. Anchor terms are extracted per type, not read off one field

`_evidence_terms(obj) -> list[str]`:

| object | terms |
|---|---|
| SCO with `value` | the value |
| `file` | `name` plus every hash value |
| SDO with `name` | `name` plus `aliases` |
| **`indicator`** | **the literals parsed out of `pattern`** — measured 96.3% against 0% for the name |
| `attack-pattern`, `course-of-action` | `[]` — unanchorable by construction |

### 2. Two fail-open guards, both measured

Doctrine, already applied by `rel_is_suggested`: *only remove what can be
positively proven wrong.* The gate therefore passes — emits the edge — whenever
it cannot judge:

- **Type guard.** `_UNANCHORABLE_TYPES = {"attack-pattern", "course-of-action"}`
  is an explicit frozenset carrying the measured rates in its comment. A pair
  touching either type is never gated. This is not an escape hatch: a
  technique's presence in the bundle is already the output of a scored
  extraction stage (ADR-0011, ADR-0023). Judging it a second time with a
  proximity heuristic would be the wrong instrument, not a stricter one.
- **Empty-terms guard.** Any object yielding no terms, and any bundle built
  without `report_text` (the CLI path passes it optionally), passes the gate.

### 3. One precomputed index, never a per-pair text scan

Sentences are split once; an inverted index `{obj.id → set[sentence_index]}` is
built once, in O(objects × sentences). Each pair is then an intersection of
small integer sets. A naive `value in report_text` per pair would be
O(pairs × |text|) — 7,838 pairs against 107 KB on APT44 — the "per-item query
instead of one sweep" defect family the project's own guidance calls out.

### 4. Window = 3 sentences, alias-aware — reused, not invented

ADR-0024 Phase C measured, on these same bundles, that moving the grounding
harness from `--rel-window 1` to `--rel-window 3 --alias-aware` reclassified 12
of 19 edges from `endpoints-only` to `window` and took the hallucination rate
from 0.500 to 0.211. It is the only proximity threshold in this project backed
by a measurement. ADR-0024 rejected its own fan-out cap precisely for "picking a
limit with no data behind it"; this ADR does not repeat that by inventing a
second number.

### 5. Policy control, in its own block

```json
"pin_evidence": { "mode": "cooccurrence" | "cartesian", "window": 3 }
```

Kept out of `completion`, which governs Stage 4b; this governs Stage 4. Mixing
them would make the policy unreadable.

### 6. Provenance: no sixth evidence label

The edge stays `x_evidence_label: "assessed"` — the verb remains the analyst's
judgement, and co-occurrence does not promote it to observed fact. ADR-0024
argued explicitly against a sixth vocabulary term ("would fragment a taxonomy
the review-UI auto-accept gate already keys on"). An anchoring property is added
instead:

```
x_pin_evidence: "cosentence" | "window:N" | "unanchorable" | "no-report-text"
```

so `-b grounding --from-bundle` can separate the populations later without the
auto-accept gate changing behaviour.

## Options considered

### Option 1 — Gate every pair uniformly

**Pros:** one rule, no type table.
**Cons:** deletes ~76% of attack-pattern edges and 100% of course-of-action
edges on measured data, for objects whose absence from the prose says nothing
about whether the edge is right.
**Verdict:** rejected by measurement.

### Option 2 — Drop the attack-pattern pin rules instead

**Pros:** removes 8,679 candidate pairs for zero code.
**Cons:** costs the analyst the malware→technique and campaign→technique
coverage that Stage 4b only partly reproduces (49 edges against 200).
**Verdict:** rejected — see Context.

### Option 3 — Gate anchorable pairs, fail open elsewhere (adopted)

**Pros:** every removed edge is one the report demonstrably never links;
reversible via `mode: "cartesian"`; reuses a measured threshold.
**Cons:** covers 53% of the candidate pool, not all of it; adds an index and a
type table to maintain.
**Verdict:** adopted, with the 47% stated rather than glossed.

## Consequences

- **Easier:** a materialised edge between two anchorable objects becomes
  defensible — the report links them within three sentences. Review load falls
  for exactly the rules an analyst would question first.
- **Harder:** two failure modes now need watching rather than one. An object
  named differently in prose than in the bundle (alias resolution, ADR-0021)
  loses its anchor, and the gate's answer depends on sentence splitting.
- **Unchanged:** the attack-pattern cartesian. It is still bounded only by the
  ADR-0026 budget. Whether that is acceptable is an analyst question, and the
  answer recorded here is that the coverage is worth the volume.
- **Revisit:** `campaign` scored 1/3 and `location` 9/13 — samples too small to
  classify. If either proves unanchorable at scale it joins the frozenset, with
  the number that justified it.

## Results

Each stored job replayed read-only under its real policy, once per mode.

### The gate removes 44% of the candidate pool

| job | cartesian | cooccurrence | blocked |
|---|---|---|---|
| CERT Polska | 1,673 | 605 | 1,068 |
| APT44 / Sandworm | 16,226 | 9,303 | 6,923 |
| ShinyHunters | 214 | 88 | 126 |
| GREYVIBE | 313 | 282 | 31 |
| **total** | **18,426** | **10,278** | **8,148 (44.2%)** |

The per-type split is exactly what the type table predicts. Rules whose target
is an attack-pattern keep **100%** of their pairs on every job — the fail-open
guard doing its job, visibly:

```
    cart   kept  blockd   %kept  rule
    7838   7838       0  100.0%  malware uses attack-pattern
    2925    401    2524   13.7%  indicator indicates malware
    1935    291    1644   15.0%  malware communicates-with domain-name
    1276    201    1075   15.8%  indicator related-to domain-name
     799    108     691   13.5%  malware drops file
```

Anchorable pairs fall to 10–20% kept. That is the cartesian being cut where
there is evidence to cut it with.

### The number that says whether it worked

`x_pin_evidence` over the pin edges each mode actually **emits**:

| mode | emitted | anchoring |
|---|---|---|
| `cartesian` | 800 | `unchecked` **100%** |
| `cooccurrence` | 688 | `unanchorable` 463 (67.3%) · `window` 119 (17.3%) · `cosentence` 106 (15.4%) |

**225 of 688 shipped pin edges (32.7%) now carry a textual anchor**, and the
other 463 are explicitly marked un-judgeable rather than silently unqualified.
No edge is `unchecked` any more.

The emitted total falls 800 → 688 for a reason worth recording: **ShinyHunters
stops saturating the cap.** Its 88 gated candidates fit inside the budget of
200, so for that report the ADR-0026 cap is no longer the mechanism deciding
what ships — which was ADR-0026's stated goal and the first time it is met on
real data.

### Latency: the precomputed index costs nothing

Full `build_stix_bundle`, cartesian → cooccurrence:

| job | cartesian | cooccurrence |
|---|---|---|
| CERT Polska | 399 ms | 310 ms |
| APT44 | 457 ms | 472 ms |
| ShinyHunters | 226 ms | 151 ms |
| GREYVIBE | 133 ms | 139 ms |

Within noise. Building one inverted index over the whole bundle is cheaper than
the pair enumeration it filters, which is why decision (3) mattered: a per-pair
`in report_text` on APT44 would have been 7,838 scans of 107 KB for one rule.

### Four rules fall to zero, and that is a finding, not a bug

| job | rule | cartesian → kept |
|---|---|---|
| CERT Polska | `malware communicates-with ipv4-addr` | 39 → 0 |
| APT44 | `url related-to file` | 36 → 0 |
| GREYVIBE | `malware communicates-with domain-name` | 7 → 0 |
| GREYVIBE | `indicator indicates malware` | 6 → 0 |

Each says the same thing: the report names both object populations but never
within three sentences of each other. Before this ADR those 88 edges shipped as
assertions. `PinRuleStat.blocked` keeps them countable instead of invisible —
which is why the gate's verdict is recorded as a separate field from
`truncated`. "The budget ran out" and "the document does not support this" are
different statements and an analyst reads them differently.

### Verification that the tests bite

Each guard was removed in turn and the suite re-run (the project's step 8bis):

| defect reintroduced | test that failed |
|---|---|
| `gating = False` — gate disabled outright | `test_cooccurrence_blocks_unlinked_pairs`, `test_blocked_is_reported_separately_from_truncated` |
| unanchorable exemption removed from `_evidence_terms` | `test_terms_for_attack_pattern_is_empty`, `test_terms_for_course_of_action_is_empty` |
| type guard removed from `_pair_is_grounded` | `test_unanchorable_type_fails_open` |

Worth recording: removing *either* unanchorable guard alone does **not** break
`test_attack_pattern_rule_is_not_gated`, because the two guards are independent
and either one is sufficient. That is deliberate defence in depth, and each
guard is locked by its own test rather than by the end-to-end one.

### Default

`pin_evidence.mode` defaults to **`cooccurrence`**, set from the measurement
above rather than before it: every blocked pair is one the report demonstrably
never links, the anchoring rate on shipped edges goes from 0% to 32.7%, and the
cost is nil. `"cartesian"` restores the previous behaviour exactly.

## Related

Sequenced after ADR-0026, which built the per-rule instrument this ADR is
measured with, and takes up its deferred Option 4. Reuses the window measured in
ADR-0024 Phase C and its argument against a sixth evidence label. Exempts the
object types whose evidence comes from ADR-0011 / ADR-0023 extraction scoring
rather than from the prose.
