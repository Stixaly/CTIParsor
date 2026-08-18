# ADR-0022 — Per-format coverage breakdown, and the drill-down query rewrite

**Status:** Proposed
**Date:** 2026-08-17
**Extends:** [0008](0008-detection-coverage-matrix.md) (coverage semantics), [0006](0006-multi-corpus-detection-ingestion.md) (licence-aware drill-down)
**Caused by:** [0015](0015-multi-format-detection-matching.md) — the store is no longer Sigma-only
**Enables:** the granular multi-format rule selection reworked on `/coverage/:jobId`

## Context

The Detection Coverage page must make Sigma, Suricata and YARA visibly distinct
through coverage, drill-in and export, and let an analyst select rules at every
level — rule → technique → tactic → corpus → format. The product owner's
statement of the problem: *"there is no distinction between Suricata, Sigma, YARA
export"*, and *"no granular selection for every detection rule for each MITRE
tactic"*.

Two things block that, and only one of them was known.

### 1. Coverage carries no format (known)

`CoverageCell` is `{technique_id, score, corpora, rule_count}` and
`rules_for_technique` projects no `format` column, even though
`detection_rules.format` has existed since ADR-0015 and is already joined on in
the export path. Every format lane, tick and per-format count in the new design
keys off that field, so none of them can be built.

The store today, measured:

| Format | Rules | Canonical | Corpora |
|---|---|---|---|
| suricata | 52,481 | 52,464 | 2 |
| yara | 22,303 | 16,314 | 5 |
| sigma | 11,396 | 6,349 | 7 |

### 2. The endpoint the design is built on takes hours (not known)

The rework selects over `GET /api/jobs/{id}/coverage/rules`. On job `23f25a39`
(ShinyHunters / PeopleSoft — 34 techniques, 9,777 canonical rules, 9,244
distinct) that endpoint does not complete. A 600-second measurement finished
**3 of 34 techniques**. Extrapolated cost: **~2.4 hours**.

Two separate instances of one planner pathology, both in `rules_for_technique`:

| Query | Measured now | Rewritten | Factor |
|---|---|---|---|
| Outer rules query, per technique | **4.11 s** — *even for a technique with 0 rules* | 0.001 s | ~4,000× |
| `also_in` sub-query, per rule | **871–1,227 ms** | 0.4 ms (`INDEXED BY`) · 0.14 ms (batched) | ~2,000× |

The cause is the same in both: `is_canonical` has two distinct values, so
`idx_detection_canon` selects roughly half of 86,180 rows, and SQLite enters
through it rather than through `idx_rule_tech_tech(technique_id)` or
`idx_detection_dedup(dedup_key)`.

`EXPLAIN QUERY PLAN` before and after the outer rewrite:

```
before:  SEARCH d  USING INDEX idx_detection_canon (is_canonical=?)
after:   SEARCH rt USING INDEX idx_rule_tech_tech  (technique_id=?)
```

**This exact pathology is already documented in this module.**
`canonical_rule_ids_for_techniques` carries the note: *"as a JOIN, the planner
enters through `idx_detection_canon` and scans every rule (~1s); as an EXISTS it
drives off the technique index (~10ms)"*. `rules_for_technique` never received
the same treatment, and the per-rule `also_in` sub-query added a second copy of
it — the "one query per element instead of one sweep" family that ADR-0017 and
`rule_facets_for_job` both had to correct before.

### Two assumptions the design rests on, verified rather than assumed

- **A `native_key` never spans two formats** — 0 cases in 86,180 rows. Per-format
  corpus attribution therefore partitions cleanly, and per-format counts sum to
  the cell's total.
- **`native_key` ↔ canonical rule id is 1:1** — 9,244 = 9,244 across the job's
  techniques. Without this the matrix cell (which counts logical rules) and the
  drill-in list (which lists rule ids) would disagree, and the UI would show two
  different truths for the same cell.

## Options considered

**A — Expose `format`, leave the queries alone.** Verdict: **rejected.** Shipping
a field onto an endpoint that takes 2.4 hours delivers nothing usable.

**B — Add a second, format-aware endpoint beside the existing one.** Verdict:
**rejected.** Two code paths over the same rows drift; the coverage score and the
drill-in would eventually disagree about what covers a technique, which is the
precise failure ADR-0006 introduced `rules_for_job` to avoid.

**C — Precompute and persist a per-format coverage table.** Verdict: **rejected.**
ADR-0006 chose live computation so coverage always reflects current review
decisions with no per-job staleness. Persisting reintroduces exactly that
staleness to work around a query bug.

**D — Fix both queries in place and add `by_format` to the existing cell.**
Verdict: **accepted.** The data is already there; the cost was a planner choice,
not a modelling problem.

## Decision

1. `rule_refs_for_techniques` returns 4-tuples `(technique_id, corpus,
   native_key, format)`. NULL/empty reads back as `"sigma"`, matching the
   pre-multi-format default already used by the export path.

2. `score_techniques` keeps its 3-tuple `rule_refs` contract and gains an
   **optional** `formats` map (`native_key → format`). With it absent, behaviour
   is byte-identical to today. This keeps the ADR-0006 scoring policy — and its
   five pure tests — untouched, and keeps the first-seen-corpus attribution in
   **one** place: `by_format.corpora` reuses the same `owner` map the score uses,
   so the per-format panel can never claim more corroboration than the score.

3. `CoverageCell.by_format` is `{format: {rule_count, corpora}}` with an entry for
   **every** name in `DETECTION_FORMATS`, including zeroes. The UI renders a
   missing format as a visible absence, so the key must be present, not omitted.

4. **The score stays computed across all formats combined.** Corroboration is a
   property of the technique, not of one tool's rule language. A UI rework is not
   licence to change what a coverage score means.

5. `rules_for_technique` is rewritten: `EXISTS` in place of the `is_canonical`
   JOIN predicate, and one batched `also_in` sweep (`INDEXED BY
   idx_detection_dedup`, 400-key batches — the cap SQLite imposes at 999 bound
   parameters, and the batch size `rule_facets_for_job` already uses) in place of
   the per-rule sub-query. It also projects `format`.

## Outcome (measured after the change)

Same job, same machine, via `scripts/audit_coverage_formats.py`:

| Call | Before | After |
|---|---|---|
| `rules_for_technique("T1190")` — 6,404 rules | did not finish in 10 min | **1.990 s** |
| `rules_for_technique("T1082")` — 192 rules | 235.66 s | **0.123 s** |
| `rules_for_technique("T1011")` — 0 rules | 4.11 s | **0.000 s** |
| `compute_for_job` — 34 techniques | — | **1.64 s** |

All four per-cell invariants hold across all 34 cells, including
`Σ by_format[f].rule_count == rule_count` — confirming on real data that
`native_key` partitions cleanly by format. The batched `also_in` sweep was
compared key-by-key against the original per-rule query on live rules with folded
duplicates: **0 mismatches**, so the rewrite changed cost, not semantics.

### A finding this exposes

**YARA contributes 0 rules to every technique in the report** — the whole
`yara` column is `0/0` across all 34 cells, and the report-wide totals are
Sigma 2,993 · Suricata 8,380 · YARA 0. This is not a regression from this ADR: it
is the structural gap ADR-0020 already recorded — YARA rules carry no ATT&CK
technique tags, so a technique-keyed join can never reach them.

The consequence for the coverage rework is concrete: the YARA lane will render as
a permanent, honest absence — an empty card, empty ticks, and "0 of 34 techniques
have a YARA rule" — until YARA rules gain technique tags or the page reaches them
by a non-technique path. A three-lane design whose third lane is always empty is
worth knowing about before the lane is built, not after.

## Step 2 — granular export, and a second measurement that changed the design

The axis filters (`format`/`corpus`/`licence`/`severity`, ANDed) cannot express
"these 47 rules", so the rule-id selection needed its own entry point:
`POST /api/jobs/{id}/detections/export` with `{"rule_ids": [...]}`. Both routes
share one `_zip_export` builder, so archive layout, manifest and README cannot
drift; ids are intersected with the report's linkable set, so the endpoint can
never become a store dump keyed by arbitrary ids.

Building it surfaced three more instances of the same "per element instead of one
sweep" family, all measured on the same report:

| Call | Before | After | What it was doing |
|---|---|---|---|
| `GET /coverage/rules` | 26.34 s | **5.44 s** | `rules_for_technique` once per technique — 34 EXISTS joins + 34 `also_in` sweeps |
| `POST .../export` (45 ids) | 14.83 s | **4.08 s** | loaded all 10,372 rule bodies (219 MB) to package 45 |
| `_load_rules` enrichment | 4.83 s | ~0.3 s | scanned all 86,180 store rows to enrich ~10k |

### Where the body size must live

The selection UI shows live archive sizes, so each rule carries a `bytes` field.
Three placements were measured, reading one integer for 10,372 rules:

| Placement | Cost |
|---|---|
| `LENGTH(COALESCE(raw,''))` computed per query | 8.78 s |
| `raw_bytes` column added to `detection_rules` | **8.19 s** |
| `rule_bytes(rule_id, bytes)` side table | **~0.1 s** |

The middle row is the surprise, and the reason this is written down. Storing the
number instead of computing it changed nothing, because `ALTER TABLE` appends the
column *after* `raw`: SQLite still has to walk the record past a multi-kilobyte
body and its overflow pages to reach the last field. Reading `id` alone from the
same rows costs 0.07 s. **The fix was not "store it" but "store it away from the
body"** — a side table, matching how `rule_atoms`, `rule_techniques` and
`rule_related` already sit beside `detection_rules`.

Written on ingest by `replace_corpus_rules`; an existing store is filled by
`scripts/backfill_rule_bytes.py` (86,180 rows in 23 s, 386.6 MB accounted for) —
no corpus re-clone, the same approach ADR-0014 took for `rule_atoms`.

## Consequences

**Easier.** The coverage page can build format lanes, per-format ticks and
per-format counts from one endpoint that already agrees with the score. The
drill-down becomes usable at all: 9,777 rules is a payload question now, not a
two-hour question.

**Harder / newly constrained.**

- `INDEXED BY` is a *hard* directive: if `idx_detection_dedup` is ever dropped,
  the query raises instead of silently degrading by ~2,000×. That is the intended
  trade — this bug was invisible for exactly as long as it was silent.
- `DETECTION_FORMATS` is a closed set of three. A fourth format added to the store
  without updating it would vanish from every breakdown while still counting
  toward `rule_count`. The per-cell sum invariant (`Σ by_format[f].rule_count ==
  rule_count`) is asserted in the tests so that divergence fails loudly.
- `rule_refs_for_techniques`' 4-tuple is a breaking signature change. All callers
  are in-repo (`compute_for_job` and two test unpack sites) and move with it.
- The two verified assumptions above are now load-bearing. Both are locked by
  tests rather than left as comments.

- A store built before this ADR has no `rule_bytes` rows until the backfill runs;
  until then the UI shows `0 B` rather than wrong numbers. Databases that ran the
  intermediate migration also carry an unused `raw_bytes` column on
  `detection_rules` — harmless, and not worth a full-table rewrite to drop.
- Any future column added to `detection_rules` lands after `raw` and inherits the
  8.2 s read cost. New per-rule scalars belong in a side table.

## Frontend (steps 3-6)

Selection is an **exclusion set** — `selected(rule) === !excluded.has(rule.id)` —
so "everything that matches the report" stays the default and matches the
existing export semantics. It lives in `useRuleSelection`, persisted per job under
`coverage.selection.{jobId}`, and every scope (rule, technique, tactic, corpus,
format, all) toggles through one `toggleScope(ids)`. One `TriCheckbox` renders
every level, so a partial selection looks the same everywhere.

Because a rule can cover several techniques, it is flattened to **one** selection
entry keyed by id — otherwise a rule under two techniques would be counted twice
in every roll-up and exported twice.

The `Download ZIP` button takes the GET route when nothing is excluded (the
browser streams it) and the POST route otherwise, since ~10k ids cannot ride on a
URL. Drill-in columns cap an expanded list at 480px with `content-visibility`
per row — T1190's 6,172 Suricata rules would otherwise lay out 6,172 DOM rows in
a one-third-width column.

### The page has to scroll itself

`body` and `#root` are `height: 100vh; overflow: hidden` so the Review page can
own its internal scroll panes. A full-screen route therefore gets **no page
scrollbar at any window size** — the coverage page is ~1,680px tall and was
simply clipped at the fold, with the export panel unreachable even on a 1920×1080
display. It now carries its own `flex: 1; min-height: 0; overflow-y: auto`
container (`.cov-page`), the same pattern Policy and Dashboard already use. The
global rules are deliberately left alone: relaxing them would change every page.

Responsive behaviour lives in `index.css` rather than inline styles, because
inline styles cannot express media queries and would silently win over them —
so the grid and flex declarations that must respond were moved out of the
components entirely. Breakpoints follow the ones already in the file: the archive
preview drops under the selection table at 1180px (the handoff's figure), the
format board and drill-in columns go 3 → 2 at 1000px and 2 → 1 at 720px. The
matrix keeps its own horizontal scroll at every width, and the page never
overflows horizontally.

**Verified on the real report:** clicking the Sigma card moves the board to
`0 of 1992`, flips every matrix cell and tactic header to partial, drops the
drill-in to `3 of 123 rules selected · 3 KB`, and changes the export summary from
`1290 all-rights-reserved — local use only` to `All selected rules are
redistributable` — the restricted rules are all Sigma.
