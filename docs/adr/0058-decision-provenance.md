# ADR-0058 — Record who decided: decision provenance, server-side auto-accept, control sample

**Status:** Accepted (implemented 2026-09-27)
**Date:** 2026-09-27
**Relates to:** [pipeline/decisions.py](../../pipeline/decisions.py),
[pipeline/calibration.py](../../pipeline/calibration.py) (ADR-0051),
[pipeline/promotion.py](../../pipeline/promotion.py) (ADR-0052),
[api/routes/entities.py](../../api/routes/entities.py),
[api/routes/relationships.py](../../api/routes/relationships.py),
[frontend/src/pages/Review.tsx](../../frontend/src/pages/Review.tsx)

## Context

`entities.accepted` (1 / 0 / NULL) was the only record of a review decision,
and three different events wrote it through the same `PATCH`:

1. an analyst deciding one card;
2. an analyst deciding many rows in one click (a type, a group, a selection,
   "accept all pending");
3. **the review page itself.** On first load, `Review.tsx` set
   `accepted = true` for every pending entity at or above 90 % confidence and
   persisted each one with `updateEntity(..., {accepted: true})`. Merely
   opening a report was enough.

Two features learn from those rows as if every one were an analyst's verdict:

* **Threshold calibration (ADR-0051)** reads every decided CyNER/GLiNER row.
  Its `above_auto_accept` guard only stopped it from *proposing* a cutoff at
  or above 0.90; below that, both the support check (`min_block_samples`) and
  the precision it reports counted the auto-accepted rows above 0.90, which
  were accepted by construction.
* **Promotion to the gazetteer (ADR-0052)** counts accepts per name. The LLM's
  malware / threat-actor / tool lists are stored at confidence 0.9 exactly, so
  the page auto-accepted every one of them, and each counted toward promoting
  the LLM's own guesses into the dictionary.

Once written, the rows could not be separated after the fact: nothing on the
row, or anywhere else, said which of the three events produced it. Every day
the page was used added more of them.

## Decision

**1. Every write of `accepted` records its origin.** New columns on
`entities` and `relationships`: `decision_origin`, `decided_at`,
`policy_version` (and `control_sample` on `entities`). The values:

| origin | written by |
|---|---|
| `human` | one decision on one card (PATCH, the default) |
| `human_bulk` | one click over many rows: `/bulk`, `/accept-pending`, group / selection actions, "Undo all" |
| `auto_policy` | the worker's auto-accept, with `policy_version` = level and control rate |
| `default` | relationships the pipeline stores already accepted |
| `propagated` | the lexicon rescan copying an analyst's accept to other mentions |
| `legacy` | decided before this ADR; cannot be attributed |

A client may send only `human` or `human_bulk`; anything else is a 400, so no
client can label its own write as policy. Rows decided before the migration
become `legacy` (the migration runs at every start and is a no-op afterwards).

**2. A journal.** `review_decisions` gets one row per change of `accepted`:
previous value, new value, origin, actor (NULL until there is an identity,
ADR-0036), policy version, time. It is only ever inserted into.
`decisions.record()` writes the rows and the journal in **one** statement
(`WITH old … FOR UPDATE, upd AS (UPDATE … RETURNING …) INSERT … SELECT`), so
they cannot disagree.

**3. Auto-accept moves to the worker.** Right after the entities are saved,
`apply_auto_accept()` accepts pending, never-decided entities at or above
`AUTO_ACCEPT_LEVEL` (0.90) as `auto_policy`. The review page no longer writes
anything when it opens; it reads `decision_origin` to show the banner and an
`auto` chip. A row an analyst reset to pending keeps `decision_origin = human`
and is never re-accepted.

The page's relationship auto-accept pass is removed rather than ported: the
worker stores every relationship already accepted (`default`), so the pass
never had a pending relationship to act on.

**4. A control sample.** A deterministic share of the would-be auto-accepts
(`REVIEW_CONTROL_SAMPLE_RATE`, default 0.10, a hash of the row id) is left
pending with `control_sample = 1`; the page flags it `confirm`. An analyst's
verdict on those rows is the only unbiased label above 0.90, and
`GET /api/thresholds` reports `auto_accept_audit`: per (source, entity_type),
the share of control rows analysts confirmed one at a time — the measured
precision of auto-accept.

**5. Readers ask for analyst decisions.**

* Calibration reads `decision_origin = 'human'` only by default.
  `POST /api/thresholds/recalibrate` accepts `include_bulk` and
  `include_legacy`, and reports `excluded_by_origin` so a thin sample says
  what it set aside.
* Promotion counts an accept only when `decision_origin` is `human` or
  `human_bulk` (plus hand-created `manual` rows, as before). A `legacy`
  **reject** still counts toward the deny list: the page never rejected
  anything, so every stored reject was an analyst's.

## Consequences

* Historical accepts are `legacy` and leave calibration and promotion by
  default. On a store with many reviewed reports, calibration may drop back to
  `insufficient_samples` until new human decisions accumulate; `include_legacy`
  restores the old behaviour on request.
* Reports processed before this change and never opened keep their
  high-confidence entities pending (the page no longer accepts them). Pending
  rows are included in the bundle exactly as accepted ones are, so no bundle
  changes; only the review counts do.
* The control sample adds about one pending card in ten among high-confidence
  entities. `REVIEW_CONTROL_SAMPLE_RATE=0` disables it; the value is recorded in
  each run config.
* `actor` stays NULL: the application has no identity (docs/deployment.md
  §2). The column is where ADR-0036's identity will land.
