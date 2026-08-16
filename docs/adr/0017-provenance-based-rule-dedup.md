# ADR-0017 — Provenance-based rule deduplication

**Status:** Proposed
**Date:** 2026-08-16
**Fixes:** [0010](0010-default-sigma-corpora-and-dedup.md) (cross-corpus dedup)
**Affects:** [0008](0008-detection-coverage-matrix.md) (coverage counts), [0014](0014-observable-driven-detection-proposals.md) (IDF denominator)

## Context

ADR-0010 elects one canonical rule per cluster of logical duplicates, clustering
on `dedup_key` — a sha256 of the normalised `logsource` + `detection` block. The
registry says of hayabusa: *"embeds a converted SigmaHQ copy — dedup folds it
under sigmahq"*.

It does not. Measured on the current store:

| Fact | Value |
|---|---|
| Rules in store | 11,396 |
| Rules folded as duplicates | **11** (0.1%) |
| hayabusa rules | 4,759 |
| `dedup_key`s shared between sigmahq and hayabusa | **1** |
| `dedup_key`s unique to hayabusa | **4,758** |

So ~42% of the canonical store is a near-copy of another 35% of it, counted twice.

### Why the hash differs

hayabusa converts SigmaHQ rules for its own backend, and the conversion changes
exactly the bytes `dedup_key` hashes. The same rule, three ways:

```yaml
# sigmahq
detection:
  selection_meshagent: [{CommandLine|contains: --meshServiceName}, {OriginalFileName|contains: meshagent}]
  filter_main_legitimate: {Image|endswith: \meshagent.exe}
  condition: selection_meshagent and not 1 of filter_main_*

# hayabusa/sigma/sysmon — adds a telemetry-binding selection, wraps the condition
detection:
  process_creation: {Channel: Microsoft-Windows-Sysmon/Operational, EventID: 1}
  selection_meshagent: [...]                     # identical
  filter_main_legitimate: {Image|endswith: \meshagent.exe}
  condition: process_creation and (selection_meshagent and not 1 of filter_main_*)

# hayabusa/sigma/builtin — different channel, and Image renamed to NewProcessName
detection:
  process_creation: {Channel: Security, EventID: 4688}
  filter_main_legitimate: {NewProcessName|endswith: \meshagent.exe}
  condition: process_creation and (selection_meshagent and not 1 of filter_main_*)
```

The detection *semantics* are identical; the telemetry binding is plumbing, and
`NewProcessName` is what Security 4688 calls `Image`.

### The cost, in the product

Four of the top twelve proposals on a real report are exact-title duplicates:

```
0.590 hayabusa   Remote Access Tool - Renamed MeshAgent Execution - Windows
0.590 hayabusa   Remote Access Tool - Renamed MeshAgent Execution - Windows   ← dup
0.300 hayabusa   7Zip Compressing Dump Files
0.300 hayabusa   7Zip Compressing Dump Files                                  ← dup
```

It also corrupts ADR-0014's IDF, whose denominator is `canonical_rule_count()`:
11,385 today against a true distinct-logic count far lower. ADR-0015 would carry
that error into a 7.5× larger store.

## Options considered

**A — Normalise the converted detection logic.** Strip selections consisting only
of `Channel`/`EventID`, un-wrap the injected condition prefix, and canonicalise
field aliases (`NewProcessName` ≡ `Image`, …). Verdict: **rejected.** It is a
guess at another project's conversion rules, needs a hand-maintained alias table,
and silently stops working when hayabusa changes its generator. It also risks
folding genuinely distinct rules whose only difference *is* the field.

**B — Fold on upstream-declared provenance.** Sigma has a `related:` block
carrying the ids a rule derives from. Verdict: **chosen** — it is authoritative
rather than inferred, and the coverage is near-total:

| hayabusa rules | 4,759 |
|---|---|
| with a `related:` id present in sigmahq | **4,758 (99.98%)** |
| with no `related:` block | 1 |

**C — Drop hayabusa from the registry.** Verdict: **rejected.** Its
telemetry-specific variants are useful on drill-down; the problem is
double-counting, not the content.

## Decision

### 1. Cluster on declared provenance as well as on `dedup_key`

The adapter extracts `related:` entries into a new `rule_related` table. The dedup
pass then treats a provenance edge as a cluster merge, via union-find so chains
chains (A derived from B, B derived from C) collapse to one cluster.

### 2. Only `derived` and `renamed` fold

Sigma defines five `related.type` values; they are not interchangeable, and the
direction matters. Observed in hayabusa: `derived` 5,189, `similar` 1,151,
`obsolete` 263, `merged` 2.

| type | meaning | fold? |
|---|---|---|
| `derived` | this rule was derived from the referent | **yes** |
| `renamed` | the referent is this rule's former id | **yes** |
| `similar` | same idea, *different* logic or logsource | **no** — folding would lose a real variant |
| `obsolete` | this rule obsoletes the referent — reversed direction | **no** |
| `merged` | assembled from several rules; ambiguous | **no** |

`similar` is the one that must not fold: SigmaHQ's own Windows and MacOS MeshAgent
rules declare each other `similar`, and they are genuinely different detections.

### 3. Election is unchanged

Corpus priority still elects the survivor (lower wins), so sigmahq (10) beats
hayabusa (95) and the original outranks the conversion. Folded rules stay in the
store — ADR-0010's losslessness is unchanged, and drill-down still reaches them.

### 4. The canonical rule inherits its cluster's ATT&CK techniques

*Added after validation — the first implementation lost coverage, exactly as the
"Harder" section below predicted it might.*

Folding two rules asserts they are the same logical detection, so their technique
tags describe the same detection and belong on the survivor. Without this, tags
carried only by a folded member vanish.

Measured: two techniques were lost, and the cause was not what one would guess.
SigmaHQ's "Double Extension" family derives several rules from one parent, and the
**derivatives carry `T1036.007` while the parent does not** — so folding a child
into its parent dropped a technique the cluster still detects. `T1623` was lost
the same way through a `tsale` rule.

With the union propagated, coverage does not merely hold — it rises from 885 to
**887** techniques, because a tag that previously sat only on a non-canonical rule
now counts. 57 technique rows are propagated on the real store.

The pass is idempotent (`INSERT OR IGNORE`) and bulk: an earlier per-cluster form
issued two queries per cluster, ~12,000 round-trips, and dominated the rebuild.

### 5. A provenance edge to a missing rule is ignored

If the referent is not in the store — sigmahq disabled, or an id from a corpus we
do not ingest — the rule stays canonical. Dedup must never depend on which
corpora happen to be enabled for its *correctness*, only for its *yield*.

## Consequences

**Easier**

- The top-N stops wasting slots on the same rule twice.
- IDF is computed against a denominator that means something, before ADR-0015
  scales the store.
- Adding a converted corpus (e.g. another backend's SigmaHQ port) now costs
  nothing in double-counting, provided it keeps `related:`.

**Harder**

- **Coverage may drop, and that has to be measured, not assumed.** Coverage reads
  canonical-only; if a folded hayabusa rule carried an ATT&CK tag its sigmahq
  parent lacks, that technique loses a rule. §Validation checks this explicitly
  and the decision is revisited if the loss is real.
- Dedup now depends on metadata a corpus may not supply. Corpora without
  `related:` are unaffected — they keep the `dedup_key` behaviour — so this
  degrades to today's result rather than breaking.
- Two rules can be folded that an operator wants separately (the Sysmon and
  Security variants). They remain in the store and reachable; only the canonical
  count changes.

## Validation

Run against a copy of the real store, with `rule_related` populated from the
stored raw YAML so no corpus re-clone was needed. **All four pass.**

| Criterion | Result |
|---|---|
| 1. Fold yield | canonical **11,385 → 6,349** (5,036 folded, 44%); hayabusa **4,758 → 5** |
| 2. No coverage loss | techniques with ≥1 canonical rule **885 → 887**; **0 lost** |
| 3. Top-20 duplicate-free | duplicate-title slots **0** on both reports (was 4 in the top 12) |
| 4. `similar` never folds | locked by unit test; SigmaHQ's MeshAgent Windows/MacOS both stay canonical |

Criterion 2 failed on the first implementation (2 techniques lost) and is what
produced §4 above. It is kept as a blocker precisely because it caught a real
defect that the fold-yield number alone would have hidden.

Side effect worth naming: with the duplicates gone, the top of the list is now
visibly dominated by `mthcht` auto-generated keyword rules tied at 0.300. That is
not a regression — it is the ~2,000-way technique-tie plateau becoming legible
now that it is no longer masked, and it is the subject of the next ADR.
