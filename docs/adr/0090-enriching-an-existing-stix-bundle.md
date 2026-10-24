# ADR-0090: Enriching an existing STIX 2.1 bundle

**Status:** Proposed (2026-10-24). Design decisions D1–D5 taken by the
maintainer on 2026-10-24; nothing implemented.
**Date:** 2026-10-24
**Deciders:** maintainer
**Relates to:** ADR-0058 (decision provenance), ADR-0059 (one pipeline for every
entry point), ADR-0061 (bundle view and mapping ledger), ADR-0066 (STIX ids are
OpenCTI's), ADR-0067 and ADR-0070 (quoted rules ship only if OpenCTI parses
them), ADR-0084 (a bundle Stage 5 refuses is not served), ADR-0086 (a bundle
names its build), ADR-0052 (deny and promote lists)

## Context

An analyst often holds the report **and** a STIX 2.1 bundle that already
describes it in part: an export from OpenCTI or MISP, or an earlier CTIParsor
bundle. Today every report starts from scratch. The analyst re-reviews what the
bundle already says, and importing CTIParsor's result into OpenCTI creates
duplicates of objects OpenCTI holds.

The feature takes the report (file, URL or pasted text) plus that bundle, the
*baseline*, and produces one bundle: the baseline intact, plus what CTIParsor
adds, attached to the baseline's ids. The review shows, for each entity and
relation, whether the baseline already had it, whether it is new, or whether it
exists only in the baseline.

The obvious design is to seed Stage 4's internal name tables with the baseline.
It was read against the code on `main` @ `2481e0e` and fails; see "Alternatives
rejected". Two external drafts proposed it, and some of their other claims
(baseline objects kept "as they are" although `_stamp_objects` restamps them,
isolation by `decision_origin` alone, a regex for patterns) did not hold either;
each is answered below.

## Decision

Eight invariants hold throughout. Each has a test.

| # | Invariant |
|---|---|
| I1 | Full mode does not change: without a baseline the bundle and its ledger are identical up to build-time timestamps, the names of the ids stix2 draws at random (relationships, the Report, and an attack-pattern built from a legacy technique row; ADR-0066 §3) and the order of objects, none of which is meaningful in a STIX bundle. |
| I2 | A baseline object ships intact or not at all. `id`, `created`, `modified`, `created_by_ref`, `object_marking_refs`, `x_*` properties and extensions are untouched; no partial pruning. **One exception: the chosen Report** (decision 6). |
| I3 | Nothing disappears silently: every baseline object absent from the bundle has a reason in the `MappingLedger` (ADR-0061), shown in the interface. |
| I4 | The baseline wins collisions: its object stays and CTIParsor's references are rewritten to it. |
| I5 | What CTIParsor adds carries its own provenance (CTIParsor `created_by_ref`, the job's markings). The re-issued Report keeps its original author. |
| I6 | One matching function serves review (Stage 3r) and Stage 4, so badges and bundle cannot diverge. |
| I7 | The baseline teaches no learning mechanism: no calibration, auto-accept, deny/promote lists (ADR-0052) or extraction metric. |
| I8 | No baseline content enters an LLM prompt in v1. |

**1. Two modes, chosen at creation.** *Full processing* (no STIX) or *Enrich an
existing STIX 2.1*. File, URL and pasted text accept both. The mode is
`jobs.pipeline_mode` (`'full'` or `'enrich'`). One pipeline (ADR-0059): the
`enrich` mode adds one stage and one merge, and runs the same `run_document()`
and the same `build_bundle()` at finalize.

**2. The baseline is stored once and indexed once, at intake.** A new table
`job_baselines` (one row per job; migration `v0013`, ADR-0077) holds the bundle
as received (`bundle_json`, never rewritten), its `sha256`, a normalised
`index_json` (`BaselineIndex`) and `intake_json` (summary and excluded objects
with their reasons). No file and no column on `jobs`: `SELECT * FROM jobs` in
`api/routes/jobs.py:118` and `api/worker.py:881` would drag up to 20 MB into
every read. The quick finalize, which runs 4 s after each review edit, reads
`index_json` and does not redo patterns, validation or rule checks.

- **Format and limits.** STIX 2.1 only (2.0, or objects without `spec_version`,
  are refused with 400); at most 20 MB and 10,000 objects (to adjust after
  measurement); the `RecursionError` of `json.loads` on deep JSON becomes a 400.
- **Validation per object; an invalid object is excluded, not repaired**
  (D3). Reasons: `baseline_invalid`; `baseline_rule_refused` for a YARA, Sigma,
  Suricata or Snort Indicator that `check_pattern()` refuses (OpenCTI refuses
  these and drops every edge to them, ADR-0067/0070); `baseline_id_collision`
  for an id CTIParsor itself emits (author identity, TLP definitions) with other
  content; `baseline_out_of_scope`. Without this an invalid object makes the
  bundle `invalid`, the finalize answers 409 and the job never completes
  (ADR-0084). Each exclusion is visible in three places: one `WARNING` log line
  per object, written once at job creation (never by the preview); the modal's
  preview; the review's *Baseline: excluded* panel.
- **Scope.** No Report in the baseline: the whole bundle, and CTIParsor emits
  its own Report. One Report: chosen, scope is its `object_refs` and their
  reference closure. Several (D4): `POST /api/baselines/inspect` lists them and
  the analyst picks one in the modal; ingestion routes take `baseline_report_id`
  and answer 400 if it is missing or not a Report of the bundle.
- **Markings** (D2). The job's TLP (and PAP) must be at least as restrictive as
  the most restrictive imported object; the modal preselects the minimum, a
  lower level is refused with 400.
- **Entries, not objects.** An IoC held as a SCO plus an Indicator
  `[x:value = '…']` linked by `based-on` is one entry holding both ids.
  Patterns are read with `stix2patterns.v21` (`Pattern(p).inspect().comparisons`,
  about 0.25 ms per pattern, 1,000 parses in 0.25 s, measured; the default
  `stix2patterns.pattern` module uses the 2.0 grammar). Only `=` comparisons give
  keys; a pattern that does not parse, or uses only `MATCHES`, `LIKE` or `>`, is
  copied without matching. Unknown or unmodelled types (`note`, `sighting`,
  `observed-data`, `grouping`, `x-*`, rule Indicators, …) are `passthrough`:
  copied as they are if they pass the reference closure.
- **Matching keys**, computed with CTIParsor's own normalisation functions
  (imported, not copied): `id`, `obs` (type, value), `hash` (algorithm, value),
  `mitre`, `cve`, `loc` (ISO-2), `named` (family, name or alias). A file name
  (`file_name`) is a weak key: it sets a displayed status and never merges ids.
  Two names match only within a family: actor = {`threat-actor`,
  `intrusion-set`}, software = {`malware`, `tool`}, every other type its own.
  Without families, an OpenCTI `intrusion-set` APT29 and CTIParsor's
  `threat-actor` APT29 never meet. A cross-type match is noted `type_conflict`
  in the ledger; if a key hits several baseline entries and none has the exact
  type, nothing merges (`baseline_ambiguous`).

**3. Stage 3r reconciles; four stored statuses, three displayed states.** A pure
function (no network, no database) runs between `run.enrich()` and
`hooks.extraction_ready()`, `skipped` without a baseline. It marks extracted
entities and relations `matched` or `new`, looks the unmatched baseline entries
up in the refanged text, and imports them as rows. Stored in
`enrichment_status` (`NULL` in full mode) with `baseline_stix_id` on `entities`
and `relationships`:

| Stored | Provenance | In the text? | Displayed | At finalize |
|---|---|---|---|---|
| `new` | extraction | yes | + New | built by Stage 4 |
| `matched` | extraction | yes | Already in the STIX | built, then merged onto the baseline object |
| `baseline_in_text` | imported (3r) | found by search | Already in the STIX | built, then merged |
| `baseline_only` | imported | no | STIX only | never rebuilt: the baseline object is copied as it is |

Four values, not three, because the finalize must know which rows to rebuild
and which to copy; the drafts' three values mixed provenance with presence.
Imported relation rows (`baseline_in_text`, `baseline_only`) are never rebuilt,
so a policy pin cannot change a baseline verb. Rows are saved with
`accepted = 1`; imported rows have `source = 'baseline_stix'`, confidence 1.0
and `decision_origin = 'baseline_stix'`, which is outside `HUMAN_ORIGINS`, and
so are `matched` extracted rows (D5), including those the 3d/3f verification
held: the baseline settles what the verifier could not. Stage 3r changes no
prompt, no chunking, no `known_values`, no `ner_allow_list`: the Stage 3
fingerprint and checkpoint resumes stay valid.

**4. Stage 4 builds, then merges.** The CTIParsor bundle is built as today and
Stage 4b runs on CTIParsor's objects alone. `merge_baseline` then runs after 4b
and before the Report:

1. excluded ids = rejected (decision 7) plus excluded at intake;
2. reference closure over every `*_ref` / `*_refs`, nested ones included: an
   object pointing to an excluded or rejected object is removed whole, until
   nothing moves (reasons `baseline_rejected`, `baseline_refs_closure`);
3. each CTIParsor object (not SRO, not Report) gets its keys and, on a strong
   key or a same-family name key, `remap[ctiparsor_id] = baseline_id`;
4. CTIParsor objects remapped are dropped and the remaining CTIParsor
   references rewritten, with the semantics of 4b's `_rewrite_refs`. A SRO that
   became a self-loop, one that duplicates a kept baseline SRO (noted `merged`
   with `merged_with`), or one whose verb is no longer valid for the new
   endpoint types (`baseline_type_mismatch`) is removed;
5. kept baseline objects are added as they are;
6. ledger (ADR-0061): `objects[baseline_id] = {"origin": "baseline", "status":
   …}`; a merged entity gets `outcome = "merged"`, `reason = "baseline_match"`;
   a relation whose endpoint was rewritten updates `source_ref` / `target_ref`
   and **never** goes in `changes`, which the Graph page paints as a rewrite.

`_stamp_objects` takes `skip_ids`: baseline objects keep their own markings and
author (it stamps the job TLP and sets a default `created_by_ref` on every
object, `stage4_stix_mapping.py:294-319`). `build_bundle()` gets one `baseline`
parameter that the run and the finalize share. The Stage 4 lot adds a
`BUNDLE_AFFECTING` entry with scope `mapping`.

**5. Baseline objects are immutable and written back verbatim.** A stix2
parse then serialize round trip changes a foreign object: on `main` @ `2481e0e`,
`created: "2023-01-01T00:00:00Z"` becomes `"2023-01-01T00:00:00.000Z"`, and an
Indicator without `pattern_version` gets `"2.1"`. In memory Stage 4 keeps the
parsed objects (4b, Stage 5 and `verify_ioc_coverage` need them); at the three
serialisation points (`api/worker.py:586`, `api/worker.py:1120`,
`pipeline/stage5_validation.py:189`) a `serialize_bundle(bundle,
baseline_objects)` replaces each baseline object with the dict as received. Without
a baseline it returns `bundle.serialize(pretty=True)` unchanged (I1). STIX 2.1
reserves new versions of an object to its creator, so adding an alias or a
property to a baseline object is out of scope; what CTIParsor learns becomes
new objects and relations.

**6. The chosen Report is re-issued by an OpenCTI-style upsert (D1).** When the
baseline has a chosen Report R, CTIParsor emits no Report of its own and
re-issues R under its id. It is the one baseline object that changes. Everything
of R is kept (`id`, `created`, `created_by_ref`, `name`, `published`,
`description`, `labels`, `object_marking_refs`, `x_opencti_*` and
**`confidence`**); `modified` is the build time, or `R.modified` + 1 ms if R is
newer (a new version must be strictly later); `object_refs` are R's references
to kept objects in their order, then the objects CTIParsor adds and the document
states (new objects, new SROs, the source document artifact);
`external_references` gain CTIParsor's `original_document` (file name, SHA-256);
`x_ctiparsor_enrichment` records `baseline_sha256`, `baseline_bundle_id`, build
time, counts per status and the synthesis statistics the CTIParsor Report
carries today. References R holds to excluded objects are pruned. The ledger
records `objects[R.id] = {"origin": "baseline_report_upsert", "added_refs": n,
"removed_refs": […]}`. If the baseline has no Report, CTIParsor emits its own
with the same `x_ctiparsor_enrichment`; `baseline_only` objects stay in the
bundle, noted `outside_report` in the ledger.

OpenCTI's rules, read in its source (`opencti-master`, 2026-10-01): on upsert a
multi-valued reference list such as `object_refs` receives an ADD of the
missing references and never a removal outside full synchronisation, and only
when the applied confidence, the minimum of the import's confidence and the
importing user's maximum, is at least the stored object's confidence
(`src/utils/upsert-utils.js`, `generateRefsInputsForUpsert`;
`src/utils/confidence-level.ts`, `controlUpsertInputWithUserConfidence`);
`created` aligns to the oldest; `created_by_ref` is replaced only for a strictly
higher confidence. Hence R's `confidence` is never lowered, `created_by_ref` is
never changed, and `docs/stix-output.md` must say that the importing user's
ceiling has to be at least R's confidence, or OpenCTI drops the additions
**without an error**.

**7. Rejection.** A baseline object leaves the bundle when **all** the rows
linked to its id by `baseline_stix_id` are rejected (`accepted = 0`): several
rows (gazetteer, CyNER, LLM) can point to one object, and rejecting one must not
remove what the others keep. Rejecting an IoC entry removes the whole entry (SCO,
Indicators, `based-on`); what referenced it follows by the closure. In v1 an
imported row is accepted or rejected, never edited (editing a value is editing
the baseline object, I2); to change a value the analyst rejects it and adds one
by hand. Stage 4 does not trust `baseline_stix_id` to merge: it recomputes
the matches with the same function (I6), so a manually added row joins the
baseline without that column being filled.

**8. What the baseline must not feed.**
- Promotion (`pipeline/promotion.py:93` reads human decisions of any source):
  exclude `source = 'baseline_stix'`. Otherwise an analyst who rejects a
  baseline object as off-topic proposes a deny rule for all future extractions.
- The grounding harness (`tests/eval_pipeline.py:1867` reads every job's
  bundle): filter on `pipeline_mode = 'full'`, or every `baseline_only` object
  counts as a hallucination.
- `apply_auto_accept` (`pipeline/decisions.py`) only touches
  `decision_origin IS NULL`, and calibration reads only `HUMAN_ORIGINS`:
  nothing to do. `matched` rows, pre-accepted, give calibration fewer human
  labels; the loss is small and accepted.
- Prompts and `known_values`: `known_values` becomes `ner_allow_list`
  (`orchestrator.py:788-793`), the names the hallucination filter does not
  check; baseline names would escape it, and the chunks sent to the LLM and the
  Stage 3 fingerprint would change (I8).

**9. A feature flag, off until acceptance.** `STIX_ENRICHMENT_ENABLED=false`
(lot 2): with it off, `/inspect` and every `baseline_*` field answer 400, and the
modal hides the mode. Lot 7 sets the default to `true` once A1–A6 pass and this
ADR is Accepted. The mode is therefore invisible while the lots land one PR at a
time.

## Decisions taken on 2026-10-24

| # | Question | Decision |
|---|---|---|
| D1 | What becomes of the baseline's Report? | OpenCTI-style upsert: same id, `object_refs` extended, `modified` = build time, `confidence` kept (decision 6). The single exception to I2. |
| D2 | A job TLP lower than the baseline's? | Refuse (400). |
| D3 | Invalid baseline objects? | Exclude, with one explicit `WARNING` log per object and the same list in the preview and the review. |
| D4 | Several Reports in the baseline? | The analyst chooses in the modal (`baseline_report_id`). |
| D5 | Extracted rows that are `matched`: pre-accepted? | Yes, origin `baseline_stix`. |
| D6 | Baseline in the LLM context? | Not asked: phase 2, after measurement, outside this decision. |

Also decided: the OpenCTI import is checked in a throwaway OpenCTI in Docker,
started on demand (lot 7); the work is done in this repository, one PR per lot.

## Consequences

- **OpenCTI never removes a reference on upsert.** An object the analyst rejects
  disappears from our bundle but **not** from a Report OpenCTI already holds.
  Removing it there would take an explicit call to OpenCTI's API, out of scope.
  The *Baseline: excluded* panel and `docs/stix-output.md` say so.
- **Stage 4b does not infer through baseline-only objects.** It sees CTIParsor's
  objects alone, so it infers no transitive edge through a `baseline_only`
  object. Protecting 4b from the baseline costs less than teaching it never to
  touch a baseline object (it picks the canonical of an alias merge by degree
  then name length, `stage4b_graph_completion.py:338`, and would absorb a
  baseline object). To reassess after v1.
- **A `baseline_only` entity is never rebuilt.** The text does not mention it
  and CTIParsor must not invent plumbing (Indicator, `based-on`) the baseline
  does not state.
- **Quiet failure on confidence.** If the importing OpenCTI user's ceiling is
  lower than R's confidence, additions are ignored with no error. A4 checks it.
- **Matching imperfect.** A missed match leaves a duplicate in the bundle (an
  object CTIParsor builds beside the baseline's). A3 measures the duplicate rate.
- **Cost on the full mode:** none intended (I1); every lot compares Stage 4's
  output, in the canonical form of I1, against reference bundles frozen before
  any change (`tests/test_stage4_reference.py`).
- **OpenCTI discards an outdated update** (`isOutdatedUpdate`,
  `upsert-utils.js`): the re-issued Report's `modified` must be strictly newer
  than the stored one, hence "`R.modified` + 1 ms" when the clock is behind.
- **Documents to update** per lot: `docs/database-schema.md`, `docs/api.md`,
  `docs/configuration.md`, `docs/pipeline.md`, `docs/stix-output.md`,
  `docs/web-ui.md`, `TESTING.md`, `CHANGELOG.md`. Nginx and `upload.py` both cap
  a request at 50 MB (`docker/nginx/default.conf:25`): report and baseline travel
  in one multipart, so either nginx goes to 70 MB or 50 MB is kept in total and
  documented (to settle in lot 2).
- **Phase 2 stays open:** names only, capped (30) and cleaned, never in
  `ner_allow_list`, in the Stage 3 fingerprint, measured on dev against a neutral
  control as ADR-0072 did, adopted only if relation precision does not fall.

## Alternatives rejected

- **Seeding Stage 4's internal tables** (`name_to_stix`, `_named_seen_ids`,
  `value_to_sco`, `sco_id_to_indicator`, `seen_rel_keys`). `_register_named`
  overwrites `name_to_stix[name.lower()]` unconditionally
  (`stage4_stix_mapping.py:677`), and a deterministic id depends on the type
  (`named_object_id(stix_type, canon)`): an OpenCTI `intrusion-set` APT29 and
  CTIParsor's `threat-actor` APT29 give two objects and the baseline's stays an
  orphan. It also means priming about ten tables of a function over a thousand
  lines long (`build_stix_bundle`, lines 488 to 1536).
- **Enriching baseline objects** (adding properties, aliases, references) and
  bumping `modified`: a new version of an object another creator made, which
  STIX 2.1 forbids. Kept only for the chosen Report, because OpenCTI's practice
  is to upsert it; when the specification and OpenCTI diverge the project follows
  OpenCTI.
- **A separate CTIParsor Report** next to the baseline's (option A of D1): not
  chosen by the maintainer.
- **Parsing patterns with regexes and `_pattern_strings()`.** It returns the
  literals without their object path (`stage4_stix_mapping.py:2205`) and handles
  `OR`, `AND`, multiple observations and `network-traffic` badly.
- **The baseline in the LLM context and in `known_values` in v1** (see decision 8
  and phase 2).
- **A file plus a `jobs.baseline_bundle_json` column:** two sources of truth and
  a heavy `SELECT *`. **`jobs.enrichment_stats_json`:** it goes stale at each
  review click; a `COUNT … GROUP BY enrichment_status` is cheap.
- **Rejecting on `accepted = 0 AND baseline_stix_id IS NOT NULL`:** a partial
  rejection would remove an object other rows still keep.
- **Merging on file name:** `svchost.exe` identifies no sample.
- **Client-side validation of the STIX:** two parsers would disagree on what is
  recognised, copied or excluded; the server alone decides, and the preview shows
  the same figures as the job.

## Acceptance criteria

A1–A6 must pass before the status becomes Accepted. The figures are recorded
here by lot 7.

| # | Criterion | How |
|---|---|---|
| A1 | Full mode unchanged (I1) | The reference scenarios of `tests/test_stage4_reference.py`, frozen on `main` before lot 1, still match in canonical form (build-time stamps, random ids and order aside; everything else, TLP marking ids included, compared). |
| A2 | Round trip | A job's CTIParsor bundle given as baseline to the same document: 0 `new`, identical ids, no baseline object lost, Stage 5 `validated`, `scripts/audit_bundle_invariants.py` with no finding. |
| A3 | Recovery after ablation | On the 7 real reports of the measurement database (`ctiparsor_measure`, never the main one), with their CTIParsor bundles as baselines, plus the OpenCTI- and MISP-shaped fixtures (CTIParsor's own bundles do not exercise the actor family or indicator-only entries): remove 30 % of the objects (fixed seed), enrich, and measure (a) the share of removed objects found back as `new` and (b) the duplicate rate: `new` objects that designate an object left in the baseline. Proposed targets, to confirm before the runs: 0 duplicates on the round trip (A2), at most 1 % on the ablation. Result: `TODO(chiffre)`. |
| A4 | OpenCTI import | In a throwaway OpenCTI (Docker, pinned version): import the baseline, then the enriched bundle. Nothing refused, no baseline object duplicated, **one** Report holding the original references and the additions. Counter-test: with a user whose confidence ceiling is below the Report's, the additions are not made. Version and result: `TODO(chiffre)`. |
| A5 | Rejection | Rejecting a baseline object removes it and everything referencing it; each removal is in the ledger and displayed. |
| A6 | Real baselines | An OpenCTI export (`intrusion-set`), a MISP export (Indicators with no SCO), a bundle with compound patterns and YARA/Sigma rules. |

## Implementation

Eight lots, one PR each; each leaves full mode intact, and the Stage 4 lot is
the riskiest (it touches Stage 4's output). They merge one at a time, because
each touches `CHANGELOG.md`, this index and, for lot 4, `BUNDLE_AFFECTING`.

| Lot | Content | Done when |
|---|---|---|
| 0 | This ADR (Proposed), baseline fixtures in `tests/fixtures/baselines/` (valid ones pass `stix2-validator`, invalid ones fail for the intended reason), reference full-mode bundles generated on current `main` | ADR read, fixtures committed |
| 1 | `pipeline/baseline_stix.py`: intake, scope, index, keys, patterns, reference closure; fuzzing target (pure, no I/O) | unit tests green, A2 at module level |
| 2 | Migration `v0013_…` (`pipeline_mode`, `job_baselines`, `enrichment_status` and `baseline_stix_id` on both tables, all nullable or defaulted so a previous-revision worker keeps inserting), flag, `/api/baselines/inspect`, the three ingestion routes (`/api/upload`, `/api/ingest/url`, `/api/ingest/text`), deletion of the baseline row with the job, 409 on editing imported rows | a baseline is stored, the job runs in full mode, flag off gives 400 |
| 3 | Stage 3r, `_save_entities`, API fields, promotion and grounding exclusions | correct rows and statuses in the database |
| 4 | Stage 4 merge, finalize, ledger, marking, Report upsert, faithful serialisation, `BUNDLE_AFFECTING` | A1, A2, A5 green |
| 5 | Modal (mode, preview, exclusions, Report choice, minimum TLP) and review (ribbon, filters, badges, toast) | full path in the browser |
| 6 | Graph (legend, *Additions*, *Baseline: excluded* panels), dashboard badge, simultaneous drop of a PDF and a JSON bundle | legend and panels right on the fixtures |
| 7 | Measures A3, A4, A6, acceptance, flag default `true`, this ADR Accepted with the figures | figures in this ADR |

Lot 7 starts the OpenCTI Docker on demand only (about 8 GB of RAM under WSL).
