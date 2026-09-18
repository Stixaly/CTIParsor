# ADR-0052 — Deny and promote lists grown from analyst decisions

**Status:** Accepted (implemented 2026-09-18)
**Date:** 2026-09-18
**Relates to:** [pipeline/overrides.py](../../pipeline/overrides.py),
[pipeline/promotion.py](../../pipeline/promotion.py),
[pipeline/stage2b_gazetteer.py](../../pipeline/stage2b_gazetteer.py),
[pipeline/stage2d_cyner.py](../../pipeline/stage2d_cyner.py),
[pipeline/stage2e_gliner.py](../../pipeline/stage2e_gliner.py),
[api/routes/overrides.py](../../api/routes/overrides.py),
[scripts/promote_overrides.py](../../scripts/promote_overrides.py);
builds on [ADR-0050](0050-cyner-generic-language-filter.md) and
[ADR-0051](0051-calibrated-ner-thresholds.md)

## Context

ADR-0051 turned the analysts' accept/reject decisions into a *cutoff* per
source and entity type. A cutoff moves where a label's tail ends; it cannot
remove one specific value the model keeps proposing with high confidence,
and it cannot teach the pipeline a name it has never seen. ADR-0050 showed
both gaps on a real report: `"Russia"` tagged as a threat actor at 0.79 and
`"MicroSCADA"` as malware at 0.92 — no cutoff separates them from real names
— and `ARGUEPATCH`, `AXETERROR`, `BRUSHPASS`, real Mandiant codenames that
CyNER found but no gazetteer knows, so every later report depends on the
model finding them again.

ADR-0050's answer was three hand-kept lists in `pipeline/stage2d_cyner.py`
(`_ORG_BLOCKLIST`, `_KNOWN_NON_MALWARE`, `_KNOWN_NON_ACTORS`), each entry
added after someone read a report's noise. That is the right mechanism with
the wrong feed: the review UI already records the same judgement, one click
at a time, in `entities.accepted`. In the job ADR-0050 examined, `"Russian
state"`, `"campaign"` and `"backed threat groups"` had each been flipped to
rejected by hand before anyone opened the source file.

Two properties of that record decide what can be automated:

1. **A single review is not a rule.** One analyst can mis-click, one report
   can be odd, and `POST /entities/bulk` accepts or rejects a whole type in
   one call. A value has to be judged the same way across *reports* before
   it says anything about the pipeline rather than about one afternoon.
2. **The lists change what fifty analysts see next.** A wrong deny row is a
   false negative in every report from then on — the costly direction in
   CTI. A wrong promote row is a false positive at gazetteer confidence
   (0.92), which the review UI auto-accepts.

## Decision

**An `entity_overrides` table of `deny` / `promote` rows, grown from the
decisions as *candidates* and applied only once a person activates them.**

1. **Table** (both engines, ADR-0045 twin DDL), unique on
   `(term, entity_type, action)`: `term` is the exact value, case-folded and
   trimmed; `status` is `candidate` | `active` | `ignored`; the counts the
   rule was met with (`accepted_count`, `rejected_count`, `job_count`), the
   most common surface form as `display`, `origin` (`auto` | `manual`), a
   free `note`, timestamps.

2. **Two actions, each one line at the point it acts**
   (`pipeline/overrides.py`, read once per worker subprocess like ADR-0051,
   fail-soft, `ENTITY_OVERRIDES_ENABLED=false` as the kill switch):
   - `deny` — `drop_denied()` at the output of Stage 2b (gazetteer), 2d
     (CyNER) and 2e (GLiNER), and `is_denied()` on the LLM's name lists in
     `_save_entities`, the one source that reaches the store without passing
     through a stage. The match is the exact whole value, per type — never a
     substring, so denying `"Microsoft"` as a threat actor leaves `"Microsoft
     Threat Intelligence"` alone and `"Microsoft"` as an identity untouched.
     Same semantics as `_ORG_BLOCKLIST`.
   - `promote` — an entry in the gazetteer's own shape (`name`, `canonical`,
     `entity_type`, `mitre_id: None`, `domain: "override"`) merged into
     `stage2b_gazetteer._load()` and re-sorted longest-first, so the term is
     found by the same Aho-Corasick automaton, with the same word-boundary
     rule, at canonical confidence (0.92), before any model runs. Restricted
     to the three types the gazetteer emits.

3. **Two rules, each one number the operator can move**
   (`pipeline/promotion.py`):
   - **deny**: rejected ≥ 3 times, in ≥ 2 distinct reports, and in ≥ 80 % of
     its reviews. The report count answers property 1; the share keeps a
     contested name (accepted as often as rejected) out.
   - **promote**: a gazetteer type, accepted ≥ 3 times — a hand-created
     `manual` entity counts as an accept, the analyst typed it — in ≥ 2
     reports, in ≥ 80 % of its reviews, **not** already a gazetteer surface
     form, ≥ 4 characters (the gazetteer's own floor), and not made entirely
     of ADR-0050's generic vocabulary (`_is_generic_fragment` is reused as
     is): "accept all pending" is one click, and this is what keeps `"the
     malware"` out of a dictionary.
   - IoC types are never rules (an address rejected in one report says
     nothing about the next); TTPs are keyed by ATT&CK id, not surface form.

4. **Candidates, never activation** (property 2). The promotion job writes
   rows with `status = 'candidate'` and refreshes the counts of rows that
   already exist *without touching their status*: an `active` row stays
   active, an `ignored` one stays ignored, so a candidate a person turned
   down is not re-proposed every night. Activation is `PATCH
   /api/overrides/{id}` — or `--activate-all` on the CLI, for an operator
   who decides the cron is the person. A hand-written rule (`POST
   /api/overrides`) is active at once: it *is* the person's decision.

5. **Surfaces**: `python -m scripts.promote_overrides` (report; `--apply`
   stores candidates; `--apply --activate-all`; `--json`), `GET
   /api/overrides?status=&action=`, `POST /api/overrides/promote`, `POST` /
   `PATCH` / `DELETE /api/overrides`, and `entity_overrides` counts in every
   bundle's run config (ADR-0024). Both CLIs (this one and ADR-0051's) now
   send `api.logging_config`'s console log to stderr, so `--json` is a
   document on stdout.

## Options considered

- **Keep extending the hand-kept lists in `stage2d_cyner.py`** — that is the
  status quo, and it is what this replaces: the same judgement, already
  recorded by the review UI, no longer needs a maintainer to read a report
  and edit source.
- **Apply promotions immediately (no candidate step)** — considered, since
  a promote row is "additive". Rejected: a promoted term matches at 0.92
  and is auto-accepted by the review UI; a wrong one is not additive, it is
  a false positive in every report until noticed. Same gate for both.
- **Fuzzy or substring deny** — rejected. `"Russia"` must not sink `"XAKNET
  Cyber Army of Russia Reborn"` (the exact regression ADR-0050 hit with a
  blanket veto). Exact whole-value match is what `_ORG_BLOCKLIST` does and
  what the counts are computed on.
- **Filter once, centrally, in the worker** — rejected in favour of one
  line at each stage's output: the stages are what callers other than the
  worker (the registry, tests, a future CLI) use, and the LLM lists are the
  only source without a stage, filtered where they are built.
- **Write promoted terms into `gazetteer.json`** — rejected: the file is a
  build artefact of `scripts/build_indexes.py` and `pipeline/aliases.py`
  reads it for MITRE-id resolution, where an entry without a `mitre_id` has
  no meaning. The overlay lives in the store and is merged at load.

## Consequences

- **Zero latency added.** A deny check is a set lookup; a promoted term is
  one more automaton node.
- **Nothing changes on a fresh install**; the table is empty and the stages
  behave exactly as before.
- **What becomes harder:** the effective deny list is now the union of the
  hand-kept sets in `stage2d_cyner.py` and the active rows — two places to
  look. `GET /api/overrides?status=active` is the second one; folding the
  hand-kept sets into seed rows is a follow-up, not done here so ADR-0050's
  tests keep locking those specific strings.
- **A promoted term outlives its evidence** until a person ignores or
  deletes it; the counts on the row are refreshed by every promotion run,
  so a term the analysts start rejecting shows it there first.
- **Follow-ups this sets up:** a Settings-page panel over `/api/overrides`
  (candidates with their counts, one click to activate or ignore); seeding
  the table from ADR-0050's lists; the fine-tuning loop, for which the
  `entities` table still lacks the exact spans (ADR-0051, Context).

## Validation record (2026-09-18)

| Check | Result |
|---|---|
| Targeted unit tests | 35 new, all passing: `tests/test_promotion.py` (13 — both rules, their thresholds as parameters, per-type and named-type scoping, manual rows as accepts, generic/short/contested/known exclusions, store upsert that never changes a status, manual rules, activation, gazetteer surface forms), `tests/test_overrides_runtime.py` (7 — fail-soft with no store / no table, no store created, only active rows act, exact whole-value match per type, entry shape, kill switch, reload forgets the gazetteer), `tests/test_stage2b_gazetteer.py` (4 × 2 paths — base index still matches, promoted term matched at 0.92 whole-word only, longest base name still wins over a promoted prefix, denied canonical dropped), `tests/test_stage2d_cyner.py` / `tests/test_stage2e_gliner.py` (+1 each — a deny row in the store drops the value end to end), `tests/test_overrides_api.py` (5 — dry run vs apply, candidate inert until activated, filters, hand-written rule, validation). `test_build_run_config_shape` extended for `entity_overrides`; a conftest autouse fixture forgets both store-backed caches after every test |
| Full suite, SQLite | `SKIP_HEAVY_MODELS=1 pytest tests/ -k "not llm"`: 1295 passed, 15 skipped, 0 failed |
| Full suite, PostgreSQL | throwaway PostgreSQL 16 on this host (UTF-8 cluster, `CTIPARSOR_TEST_DATABASE_URL`): 1302 passed, 7 skipped, 0 failed; the same pre-existing SSE test ADR-0051 deselected (`test_progress_stream_is_resumable`, hangs on PostgreSQL on this host at the base commit too) |
| ruff | `pipeline/ api/ scripts/ tests/` clean (`--select E,F,W,I`) |
| mypy | the new modules and both CLIs clean (`--ignore-missing-imports`) |
| CLI, end to end | on a scratch store seeded with three reports: `microsoft`/threat_actor rejected in all three → `deny` candidate; `ARGUEPATCH`/malware accepted in all three and unknown to the gazetteer → `promote` candidate; `Snake`/malware accepted twice, rejected once → neither; `--apply` wrote 2 candidates, `--apply --activate-all` activated 2, `--json` parses |
| Real data | none in this checkout; the rule thresholds are the ones ADR-0050's real job would have met (`"Russian state"`, `"campaign"`, `"backed threat groups"` were each rejected by hand there) |
