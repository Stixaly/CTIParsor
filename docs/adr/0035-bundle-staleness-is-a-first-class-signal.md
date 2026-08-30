# ADR-0035: A stored bundle carries the pipeline that built it, and must say so

**Status:** Accepted
**Date:** 2026-08-30
**Deciders:** maintainer

## Context

### A fixed bug still ships, because the bundle is not rebuilt

`scripts/audit_bundle_invariants.py` fails one invariant over the stored
bundles:

```
FAIL  error  check_relationship_no_self_loop   6/5160   2 jobs
```

The six edges are relationships whose `source_ref` equals their `target_ref`:

| job | edge |
|---|---|
| `cdf72dd1` | `ipv4-addr related-to` itself, ×4 |
| `73621bb5` | `Sandworm Team related-to Sandworm Team` |
| `73621bb5` | `EXARAMEL drops EXARAMEL` |

All six carry `x_evidence_label="reported"` and no `x_inference_rule` or
`x_policy_rule`, so they came from the Stage 3 → Stage 4 mapping path, not from
completion or policy materialisation.

**That path is already fixed.** The guard landed on 2026-08-28 in `eaee534`, and
`tests/test_stix_self_edges.py` covers the exact EXARAMEL shape
(`test_identical_endpoints_produce_no_edge`). The bundles were written on
2026-08-23. The code is correct; the artefacts are not.

### The data to detect this is already recorded, and nothing reads it

ADR-0024 added `jobs.run_config_json`, and it stamps every run with the commit
that produced it. Over the 13 stored jobs:

```
82c259d19  x5      11 pipeline commits between the oldest
8735489cf  x4      stamped revision and HEAD
a2b830296  x2
f48e2be6e  x1
0df9701fa  x1
```

`git merge-base --is-ancestor 8735489 eaee534` confirms every stored bundle
predates the self-edge fix. The provenance is exact, complete, and unused: no
route, no script and no view compares a bundle's `git_rev` to anything.

### Rebuilding is already free

`api/worker.re_run_final_stages(job_id)` re-runs **Stages 4 and 5 only**, from
the accepted entities already in the database. It makes no LLM call. The
expensive work — Stage 3 enrichment — is preserved in `jobs.llm_result_json`
and is never repeated for a mapping change. The `POST /api/jobs/{id}/finalize`
route already exposes it.

So both halves of the mechanism exist. What is missing is the wire between
them: something that notices a bundle is old and says so.

### Why "just re-finalize everything" is not the answer

Rebuilding on read would be wrong in both directions. It hides that the bundle
changed under an analyst who may have exported or cited the old one, and it
re-runs Stages 4–5 for jobs whose stamped revision touched nothing that could
alter their output. A bundle is a delivered artefact; it must not silently
mutate.

## Options

**1. Compare each bundle's `git_rev` to `HEAD`.**
Trivial to implement and immediately noisy: every frontend commit, every
docs commit, every test-only commit marks all bundles stale. The signal is
true and useless — it never returns to green, so it gets ignored, which is
worse than not having it.

**2. Hash the pipeline modules and compare digests.**
More precise than `HEAD`, still wrong: a comment or a rename changes the
digest without changing a single emitted object. It also cannot express
"this commit fixed a defect that mattered", which is the only question an
analyst actually has.

**3. Keep a hand-maintained list of bundle-affecting revisions.**
A short table in the repository naming the commits after which a bundle's
*content* can differ, with one line saying what changed. A bundle is stale
when its `git_rev` is an ancestor of any entry. Costs a line of discipline
per such fix; in exchange the signal is exact and actionable, and it stays
green when nothing relevant shipped.

**4. Version the mapping explicitly (`BUNDLE_SCHEMA_VERSION`).**
Equivalent in power to 3, but decouples the marker from git history and so
loses the "which commit, and why" that makes a staleness report readable.
It also invites bumping the number for changes that do not affect output,
recreating option 1's noise by hand.

## Decision

**Option 3.** A stale bundle is one whose recorded `git_rev` is an ancestor of a
revision listed as bundle-affecting.

The list lives in the repository next to the audit that reads it, and each entry
carries the commit, the date, and one sentence on what changed in the emitted
objects. Its first entry is the self-edge fix:

| revision | date | effect on emitted objects |
|---|---|---|
| `eaee534` | 2026-08-28 | Stage 4 no longer emits a relationship whose endpoints resolve to the same object |

Staleness is **reported, never repaired automatically**. The report names the
job, its stamped revision, and which listed entries it predates. Repair is the
existing `finalize` call, invoked deliberately.

`scripts/audit_bundle_invariants.py` is the natural host: it already walks every
stored bundle, already reads per-job state, and is already the thing whose FAIL
prompted this ADR. It gains a staleness section that is informational — a stale
bundle is not an invariant violation, it is an artefact awaiting a rebuild.

## Consequences

**A fixed mapping bug stops being invisible.** The six self-edges are the
proof-of-need: the suite was green, the code was right, and the delivered
artefacts were wrong, with nothing in the system able to say so.

**One line of discipline per output-affecting fix.** The list is only as good as
the habit of appending to it. A fix that changes emitted objects and is not
listed leaves bundles quietly stale — the same failure mode as before, narrowed
to a smaller and more visible surface. `CONTRIBUTING.md` gains the rule next to
the existing DB-migration one.

**The staleness report will be non-empty for a while.** All 13 stored bundles
predate the first entry. That is the correct reading of reality, not a defect of
the check, and it clears as jobs are re-finalized.

**Re-finalizing is not free of consequence, only of cost.** Stages 4–5 rebuild
from *currently accepted* entities. A job whose review state changed since the
original run will produce a different bundle for that reason too, not only
because of the fix. The report says a rebuild is available; it does not promise
the result differs only by the listed defect.

## What this does not fix

- **Entities and relationships are not versioned.** Only the bundle carries a
  `git_rev`. A Stage 2 or Stage 3 change alters what is stored in `entities`,
  and re-finalizing does not re-extract — recovering from that needs a full
  re-run, with its LLM cost. This ADR deliberately covers only the mapping tail.
- **The 313 legacy `entities` rows without `evidence_end`** (ADR-0028, reported
  by `audit_store_invariants`) are the same class of problem in another table,
  and are not addressed here.
- **Nothing detects a defect that was never diagnosed.** The list records fixes
  the maintainer knew to record. It shortens the distance between finding a bug
  and knowing which artefacts carry it; it does not find bugs.
