# ADR-0051 — NER confidence cutoffs calibrated from analyst decisions, per source and entity type

**Status:** Accepted (implemented 2026-09-18)
**Date:** 2026-09-18
**Relates to:** [pipeline/calibration.py](../../pipeline/calibration.py),
[pipeline/thresholds.py](../../pipeline/thresholds.py),
[pipeline/stage2d_cyner.py](../../pipeline/stage2d_cyner.py),
[pipeline/stage2e_gliner.py](../../pipeline/stage2e_gliner.py),
[api/routes/thresholds.py](../../api/routes/thresholds.py),
[scripts/calibrate_thresholds.py](../../scripts/calibrate_thresholds.py)

## Context

The question that opened this work: with some fifty analysts reviewing
reports, can what they accept and reject feed back into the NER stages
without a model that "blocks for thirty minutes between reports"?
Fine-tuning CyNER or GLiNER on corrections is possible, but it is a batch
job on a separate machine with a regression gate in front of deployment, and
it needs exact character spans the CyNER/GLiNER rows do not carry (they store
`value` and a ~50-character `context`; `evidence_start`/`evidence_end` are
only resolved for Stage 3 TTPs, ADR-0028). That is its own ADR. The lever
that works today, on data the store already holds, is the **discard cutoff**.

Today each stage applies one constant to every label it emits:

- Stage 2e, GLiNER: `GLINER_THRESHOLD` (0.40) across six labels — malware
  family, threat actor group, targeted sector, targeted country, attack
  campaign, attack infrastructure.
- Stage 2d, CyNER: `_MEDIUM_THRESH` (0.70) across `Malware` and
  `Threat_group`.

The labels do not behave alike: `_merge_gliner_into` already treats
`MALWARE`/`THREAT_ACTOR` as lower-precision than the gazetteer and CyNER for
the same names, while `IDENTITY`/`LOCATION`/`CAMPAIGN`/`INFRASTRUCTURE` have
no other source at all. ADR-0050 found that for CyNER's *generic-language*
noise "there is no threshold that separates them" — that is a content
problem and got a content filter. The cutoff still decides how much of a
label's low-score tail every analyst must click through, and nothing
measures where that tail should end.

The measurement already exists. Every CyNER/GLiNER entity is stored with the
model's raw score (`entities.confidence`, rounded to 4 decimals) and, once
reviewed, `entities.accepted` = 1/0. Per `(source, entity_type)` that is a
labelled sample of P(correct | score) — 640 such decisions on one label are
enough to see where the accept rate crosses 90 %.

Three properties of that sample shape what can honestly be done with it:

1. **Selection.** Only scores above the cutoff in force were ever shown, so
   nothing is known below it. A cutoff can be *raised* on evidence; it can
   only be *lowered* as far as the lowest score analysts have actually seen.
2. **Auto-accept.** `Review.tsx` accepts every entity at ≥ 90 % on load and
   persists it (`AUTO_ACCEPT_THRESHOLD = 90`); rejecting one is an *undo*.
   Above 0.90 an `accepted = 1` is mostly the model's verdict echoed back.
   ADR-0050 saw analysts undo several — the signal exists — but the band is
   biased in the model's favour.
3. **Over-confidence.** Neural taggers' scores are not probabilities; the
   calibration literature (Platt scaling, isotonic regression, temperature
   scaling) exists because a 0.85 is routinely right far less than 85 % of
   the time. Picking a cutoff straight off raw scores inherits that.

## Decision

**A cutoff per `(source, entity_type)`, proposed from the analysts' own
decisions through an isotonic fit, stored with its provenance, applied only
when an operator says so.**

1. **`model_thresholds` table** (both engines, ADR-0045 twin DDL), primary
   key `(source, entity_type)`: `threshold`, and the provenance of how it was
   chosen — `sample_size`, `target_precision`, `precision_at`,
   `recall_retained`, `origin` (`calibrated` | `manual`), `updated_at`. No
   row means the stage default applies, exactly as before this ADR.

2. **`pipeline/thresholds.py`** reads the table once per process and answers
   `get_threshold(source, entity_type, default)`. The pipeline runs in a
   `spawn`ed subprocess per job (api/worker.py), so every job sees the table
   as it stood when it started and no cross-process invalidation exists to
   get wrong. It fails soft in every direction — no store, no table, a driver
   error, or `THRESHOLD_CALIBRATION_ENABLED=false` all mean "the default" —
   and it checks the store exists before connecting, so a `main.py` run never
   creates an empty `cti_stix.db` by asking for a number.

3. **The stages hold each prediction to its type's cutoff.** CyNER replaces
   the single `score < _MEDIUM_THRESH` test. GLiNER's `predict_entities()`
   takes one threshold for every label (verified against urchade/GLiNER's
   API: there is no per-label threshold), so the model is asked at the
   *lowest* cutoff in force and each prediction is then filtered by its own
   type's — the per-type cutoff is a post-filter, which loses nothing
   because the score is on every prediction anyway.

4. **`pipeline/calibration.py`** fits, per pair, the pool-adjacent-violators
   isotonic regression over `(score, accepted)` — the closest non-decreasing
   step function to the observed accept rate, ~30 lines, no dependency — and
   proposes the lower edge of the first step whose calibrated rate reaches
   the target precision (default 0.90). Because every step edge is an
   observed score, the proposal never goes below what analysts have seen
   (property 1). Three guards are reported as a status, never silently
   resolved:
   - `insufficient_samples` (< 200 decisions by default) — the fit would be
     noise; the rarer GLiNER labels get here first.
   - `target_unreachable` — no band reaches the target; raising the cutoff
     would not fix the label, it needs a content filter or a better label
     wording.
   - `above_auto_accept` — the only clean band starts at or above 0.90
     (property 2). The data-supported number is still reported as
     `unclamped` for a human to set by hand; it is never applied.

   Alongside the proposal the report carries what the cutoff in force
   delivers today (`precision_at_current`, `recall_at_current`) and what the
   proposed one would (`precision_at_proposed`, `recall_at_proposed` — the
   share of everything analysts accepted that would still be shown), and the
   fitted curve so a UI can draw it.

5. **Surfaces.** `python -m scripts.calibrate_thresholds` prints the report
   and writes only with `--apply`; `GET /api/thresholds` shows defaults and
   stored rows, `POST /api/thresholds/recalibrate` returns the same report
   and writes only with `"apply": true`, `PUT`/`DELETE
   /api/thresholds/{source}/{entity_type}` hand-set or clear one row. The run
   configuration snapshot (ADR-0024) gains `ner_thresholds` — the defaults
   and every override in force — so a bundle built under a calibrated cutoff
   stays explainable after the next recalibration moves it.

6. **Nothing applies itself.** A write that changes what fifty analysts see
   next is an operator's visible action (a cron calling `--apply` is that
   operator's choice, and the report says what it did). The report is the
   product; the write is the decision.

## Options considered

- **Fine-tune the models on corrections** — deferred, not rejected. It is
  the only path to *generalisation* (new phrasings), but it needs exact
  spans the rows do not carry, a training job off the request path, a fixed
  evaluation set and a regression gate. This ADR is the layer that works
  today and stays useful under it: a new checkpoint changes the score
  distribution, and the answer is to recalibrate.
- **Pick the cutoff from cumulative precision on raw scores** — rejected in
  favour of the isotonic fit. It is the same data, but the fit gives a
  monotone P(correct | score) that a UI can show and that does not jump
  between neighbouring scores on a handful of decisions; the cost is thirty
  lines.
- **Platt scaling for the small-sample labels** — deferred. A two-parameter
  sigmoid is more data-efficient than a step function, but the
  `min_samples` guard is the honest answer until a label has decisions, and
  the guard is one number.
- **Per-label threshold inside GLiNER** — unavailable; the post-filter is
  equivalent.
- **Recalibrate automatically inside the worker after every job** — rejected
  (decision 6). Also pointless: one report adds a few dozen decisions to a
  fit that needs hundreds.
- **Remove the review UI's auto-accept so every accept is explicit** — out
  of scope here; it would lift the `above_auto_accept` ceiling and is worth
  its own decision, because it also changes fifty analysts' workload.

## Consequences

- **Zero latency added.** The cutoff is a dictionary lookup in the stage; the
  fit runs when an operator asks, on the API or a shell, in milliseconds for
  the row counts a store holds.
- **No change until someone applies one.** A fresh install behaves exactly
  as before this ADR; the table is empty.
- **A cutoff cannot be lowered below the current default from data** —
  there is none (property 1). Exploring below it would mean showing
  sub-threshold candidates to analysts, deliberately, on a sample; not
  built, flagged as the follow-up if a label looks over-cut.
- **A stored row outlives the evidence for it** until the next `--apply`
  overwrites it; a label that turns `target_unreachable` keeps its old row,
  and the report says so. A `manual` row is overwritten by the next apply
  that has a proposal for that pair.
- **What becomes harder:** two labels from two stages that used to share one
  number can now differ, and the number lives in the store, not in `.env`.
  `GET /api/thresholds` and `ner_thresholds` in every bundle's run config are
  the two places to read it.
- **Follow-ups this ADR sets up:** a Settings-page panel over
  `/api/thresholds` showing the fitted curve; a denylist/gazetteer overlay
  promoted from repeated rejections and manual entities (the same
  data, the other lever — ADR-0050's hand-kept lists, automated); a fixed
  evaluation set built from high-agreement decisions to test GLiNER label
  wordings against.

## Validation record (2026-09-18)

| Check | Result |
|---|---|
| Targeted unit tests | 36 new, all passing: `tests/test_calibration.py` (18 — fit, selection rule, the three guards, the observed-score floor, store round-trip on the temp database), `tests/test_thresholds_runtime.py` (5 — fail-soft read with no store / no table, no store created as a side effect, cache until `reload()`, kill switch), `tests/test_stage2e_gliner.py` (6 — per-type post-filter, the lowest cutoff sent to the model, a stored row reaching the stage end to end), `tests/test_stage2d_cyner.py` (+1 — per-type override), `tests/test_thresholds_api.py` (6 — dry run vs apply, hand-set, clear, validation). `test_build_run_config_shape` extended for `ner_thresholds` |
| Full suite, SQLite | `SKIP_HEAVY_MODELS=1 pytest tests/ -k "not llm"`: 1260 passed, 15 skipped, 0 failed |
| Full suite, PostgreSQL | throwaway PostgreSQL 16 on this host (`CTIPARSOR_TEST_DATABASE_URL`, UTF-8 cluster): 1267 passed, 7 skipped, 0 failed. One pre-existing test deselected, `test_api_routes.py::test_progress_stream_is_resumable`, which hangs on PostgreSQL on this host with this change stashed as well (passes on SQLite) — not touched by this ADR. Found on the way, not a bug: a cluster initialised with locale `C` (`SQL_ASCII`) makes psycopg return every TEXT column as `bytes`, which fails 83 tests across the suite — the compose stack's `postgres:17-alpine` is UTF-8 and unaffected |
| ruff | every touched file clean (`--select E,F,W,I`) |
| mypy | `pipeline/calibration.py`, `pipeline/thresholds.py`, `api/routes/thresholds.py`, `scripts/calibrate_thresholds.py` clean (`--ignore-missing-imports`: the optional `transformers`/`gliner` packages are not installed in this checkout) |
| CLI, end to end | on a scratch store: empty → "nothing to calibrate"; seeded with 640 `gliner/malware` decisions (50 % accepted below 0.60, 95 % above) and 120 `cyner/threat_actor` at 50 % throughout → `gliner/malware` proposed 0.600 (P 0.950, 96.6 % of accepted entities kept, against P 0.922 at the 0.40 in force), `cyner/threat_actor` `target_unreachable`; `--apply` wrote one row; the next run reports `unchanged` at 0.600 |
| Real data | none in this checkout — the fit was exercised on constructed samples whose answer is known by construction (a 50 % band under a 95 % band proposes the boundary; a clean band only at ≥ 0.90 is refused and reported as `unclamped`) |
