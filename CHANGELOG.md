# Changelog

All notable changes to CTIParsor are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/). Versions follow
[Semantic Versioning](https://semver.org/) from 0.1.0;
`scripts/release.py prepare` turns `[Unreleased]` into the release's section
([docs/releasing.md](docs/releasing.md)). Within a section, entries group by
theme.

## [Unreleased]

### Added

#### Enriching an existing STIX 2.1 bundle, lot 7: measured, checked in OpenCTI, and on by default (ADR-0090 accepted), 2026-10-25

An analyst can give CTIParsor a report and a STIX 2.1 bundle that already
describes it (an OpenCTI or MISP export, or an earlier CTIParsor bundle), and get
one bundle: the analyst's objects as received, plus what the report adds, attached
to their ids. The review shows what the bundle already holds and what is new.
**ADR-0090 is Accepted, and the feature is on by default**;
`STIX_ENRICHMENT_ENABLED=false` turns it off.

- **Measurements** (ADR-0090 A2 and A3; `scripts/baseline_ablation.py` and
  `scripts/baseline_round_trip.py`, read only, 7 real reports). Round trip: 0
  duplicate rows, 596 rows matched, 21 `new` (19 locations the bundle never held,
  2 ambiguous ledger keys). Object level: 6 of 7 enriched bundles pass Stage 5;
  the 7th has a `url` that Stage 4 builds invalid, a defect that predates the
  feature (its stored bundle already had it). 11 objects duplicate a baseline
  object by name: the CTIParsor author identity in each job, and two
  attack-patterns in two jobs. Ablation: 30 % of the 601 candidate entries removed
  (179), 175 recovered as `new` (97.8 %), 196 `new` rows, 0 duplicates (0.0 %,
  target at most 1 %). External control, the OpenCTI- and MISP-shaped fixtures
  over 5 seeds: 5 of 5 recovered each, 0 duplicates (one removed entry per seed:
  a small sample).
- **OpenCTI** (A4; `scripts/opencti_import_check.py`, `docker/opencti-test/`):
  OpenCTI 7.260930.0, 12 of 12 expectations hold. Nothing refused; one Report under
  the baseline's id, holding its references and the additions; no baseline object
  duplicated; a user whose maximum confidence is below the Report's adds nothing,
  with no error; a rejected object stays referenced by the Report.
- **Rejection and real-shaped baselines** (A5, A6): rejection checked end to end
  (`tests/test_baseline_e2e.py`) and in the browser. The repository's OpenCTI-shaped
  and MISP-shaped fixtures, and its YARA, Sigma and Suricata rules, go through
  Stage 5 and OpenCTI (MISP-shaped: audit 16/16, OpenCTI import 10/10). The
  fixtures stand for real exports; no live export was used.
- **Matcher fixes** (`pipeline/baseline_stix.py`): a file row with no hash
  matches through its name when one baseline entry carries that name, and that
  entry holds a file object (Stage 3r); a name-only Indicator joins the observable
  its `based-on` names when exactly one such observable is named; a name-only
  file merges onto the one baseline file of its name (Stage 4); a name-only
  `[file:name = …]` Indicator becomes the kept Indicator of that file's entry.
  Stage 4 also merges a course of action and a detection-rule Indicator with a
  kept baseline object of the same content (two such objects: no merge). Before
  the first three the same runs gave 35 duplicates on the ablation and 45 on the
  round trip, all `file`; the course-of-action and rule duplicates were found by
  the round trip (119 and 6) and are merged now.
- **File names, decision reversed**: a file known by its name alone merges into
  the baseline's file when exactly one baseline file carries that name. With two
  carriers nothing merges and the row stays `new`; a name carried only by a
  name-only Indicator, with no file object, matches nothing. The A4 run had held a second
  `svchost_update.dll` beside the baseline's, and the review badge and the bundle
  disagreed. A file with a hash of its own is never merged on its name.
- **Audit**: `scripts/audit_bundle_invariants.py` no longer flags an Indicator whose
  `pattern_type` is a detection-rule type (yara, sigma, suricata, snort, pcre) as
  a malformed STIX pattern. Such rules ship since ADR-0067 and ADR-0070.
- **Flag**: `STIX_ENRICHMENT_ENABLED` defaults to `true` (`.env.example`,
  `docs/configuration.md`).
- **Scripts and stack**: `scripts/baseline_ablation.py` and
  `scripts/baseline_round_trip.py` (both read only, no LLM);
  `scripts/opencti_import_check.py` (runs with pycti in its own venv, never a
  project requirement, and creates a role, a group, a user and an unlimited token
  it never revokes: a throwaway instance only); `docker/opencti-test/compose.yaml`
  and its `.env.example` (every secret is required, RabbitMQ pinned to
  `4.3.7-management`). How to run them again: `TESTING.md`, "Measuring baseline
  reconciliation and the OpenCTI import".
- **Tests**: `tests/test_baseline_ablation.py` (25), `tests/test_baseline_round_trip.py`
  (8) and `tests/test_audit_bundle_patterns.py` (2) are new; `test_baseline_stix.py`
  (452), `test_baseline_reconcile.py` (31) and `test_baseline_merge.py` (30)
  gain cases.
- **Docs**: ADR-0090 (Accepted, the figures, the file-name decision, the OpenCTI
  findings), `docs/stix-output.md` (OpenCTI capabilities, the A4 result, the
  file-name rule), `docs/api.md`, `docs/web-ui.md`, `docs/configuration.md`,
  `TESTING.md`, the ADR index.

#### Enriching an existing STIX 2.1 bundle, lot 6: the graph, the panel, the badge and the drop (ADR-0090), 2026-10-25

On an `enrich` job the Graph page shows what the analyst's bundle supplied and
what CTIParsor added to it. **A full job's graph is as before**, and the feature
stays behind `STIX_ENRICHMENT_ENABLED`, off by default. Still to do: lot 7
(measures, OpenCTI test, activation). Frontend only.

- **Bundle view**: objects from the analyst's bundle get a thin outer ring, and
  the legend counts them: "From your STIX bundle" and "Added by CTIParsor". The
  bundle's relationships are a link kind, "From your STIX bundle".
- **Against your bundle** (enrich jobs, bundle view) opens
  `components/graph/BaselinePanel.tsx`: Added by CTIParsor; Matched to your
  objects (CTIParsor's object, and yours, which ships in its place); Left out of
  your bundle (rejected objects, and objects whose reference left, named; the
  report when it is not re-issued; the intake exclusions, with "and N more"; a
  note that OpenCTI's upsert never removes a reference); Your report, re-issued
  (references added and removed).
- **Imported rows** join their bundle object by its STIX id, so a freshly built
  enrich bundle no longer reads "out of date" and draws no hollow ghosts for
  them. A row rejected after the build is listed as stale.
- **Relationships from the bundle** cannot be deleted on the Graph page: the
  button is disabled with the reason, and a refused delete shows "Not deleted:"
  with the server's reason.
- **Dashboard**: an "Enrich" badge on enrich jobs.
- **Drop**: a report and a STIX bundle dropped together, on the dashboard or in
  the New report modal, open the modal in enrich mode with both. A bundle alone
  keeps the pasted text. The modal names each `.json` it does not use (not a
  STIX bundle, or a second bundle); with the flag off, or the status unreadable,
  it says the bundle was not used. Bundles are recognised from their first
  64 KB and last 4 KB, in UTF-8 or UTF-16 with a byte-order mark.
- **Review**: "Change type" is disabled on imported rows in the hover chip, as on
  the margin card.
- **Types**: `LedgerRemoval.kind` takes `'baseline'`; `LedgerObjectInfo` gains
  `added_refs` and `removed_refs`; `EdgeKind` gains `'baseline'`.
- **Tests**: `components/graph/BaselinePanel.test.tsx` (7), `components/dropFiles.test.ts`
  (12), `pages/Graph.test.tsx` (6) and `components/review/InlineHoverChip.test.tsx`
  (3) are new; `NewReportModal.test.tsx` (31 in the file), `buildBundleGraph.test.ts`
  (22), `provenance.test.ts` (10) and `pages/Dashboard.test.tsx` (7) gain cases.
  The frontend has 27 Vitest files and 285 tests on 2026-10-25.
- **Docs**: `docs/web-ui.md` (enrich mode: graph, panel, badge, drop), `TESTING.md`.

#### Enriching an existing STIX 2.1 bundle, lot 5: the New report modal and the Review screen (ADR-0090), 2026-10-25

The analyst can start an `enrich` job from the New report modal and see on the
Review page what the bundle already holds. **A full job looks as before.** The
mode choice shows only when the server has `STIX_ENRICHMENT_ENABLED` on
(`GET /api/baselines/status`), which stays off by default. Still to do: lot 6
(graph legend and panels, dashboard badge, PDF and JSON dropped together,
delete on imported graph rows) and lot 7 (measures, OpenCTI test, activation).

- **New report modal**: "Full extraction" or "Enrich an existing STIX 2.1
  bundle". In enrich mode a `.json` bundle is dropped or browsed, and
  `POST /api/baselines/inspect` previews it: the objects kept by type, the
  objects outside the report's scope, the dangling references, the excluded
  objects with their reason, the warnings, and a note that the STIX schemas run
  when the job starts. Nothing is stored. A bundle over the size the status
  reports is refused before it is read. A bundle with several reports asks which
  one to enrich (ADR-0090 D4) and is previewed again for that report. Submit
  waits until the bundle is read for its scope.
- **Markings** (D2): the bundle's minimum TLP and PAP are preselected and the
  weaker levels are disabled. Switching back to full mode drops the bundle, and
  a level the bundle set (not one the analyst picked) returns to unset.
- **Job request**: the bundle goes with it, as `baseline_stix` on upload and
  `baseline_bundle` on pasted text or a URL, with `baseline_report_id`.
- **Review screen, enrich job**: the ribbon counts against the bundle (in STIX =
  matched + found in text, STIX only, + New). A filter "Any source · + New · In
  STIX · STIX only" sits in the margin notes and in the relationships rail. A row
  an analyst adds by hand counts as + New. In the margin it combines with the page's
  type filter; in the rail, with the tabs. Cards carry "+ new", "in STIX" or
  "STIX only" badges. Focusing a STIX-only card says it comes from the bundle
  and is not in the report text. A matched relationship whose two ends are
  STIX-only says its ends were matched through the bundle's names, in the
  badge's tooltip. A banner shows when no row is new.
- **Imported rows** can be accepted or rejected. Their type (entities) and verb
  and dates (relationships) are disabled, because the server answers 409 to an
  edit.
- **Types and client**: `PipelineMode`, `EnrichmentStatus`, `EnrichmentView`,
  `BaselineIntake`, `BaselineStatus` and `JobEnrichment` in
  `frontend/src/types/index.ts`; `inspectBaseline`, `fetchBaselineStatus` and
  `fetchBaselineIntake` in `frontend/src/api/client.ts`.
- **Tests**: `NewReportModal.test.tsx` (18), `review/Marginalia.test.tsx` (9) and
  `review/PipelineRibbon.test.tsx` (4) are new; `api/client.test.ts` (18),
  `review/RelationshipRail.test.tsx` (22) and `pages/Review.test.tsx` (16) gain
  ADR-0090 cases. The frontend has 23 Vitest files and 224 tests on 2026-10-25
  (`npm test`).
- **Docs**: `docs/web-ui.md` (enrich mode in the New report modal and on the
  Review page), `TESTING.md` (the frontend counts).

#### Enriching an existing STIX 2.1 bundle, lot 4: the merge into the baseline and the re-issued Report (ADR-0090), 2026-10-25

An `enrich` job now ships the analyst's bundle merged with CTIParsor's. Stage 4
merges the two after Stage 4b. When the baseline has a chosen Report, it is
re-issued under its own id and CTIParsor builds no Report of its own. **A `full`
job is built as before**, and the feature stays behind `STIX_ENRICHMENT_ENABLED`,
default off. The known limit of lot 3 is resolved: a finalize no longer rebuilds
a `baseline_only` entity or an imported relationship as CTIParsor's own object.

- **`merge_baseline`** (`pipeline/baseline_stix.py`) folds Stage 4's objects into
  the baseline. A CTIParsor object that a kept baseline entry matches is replaced
  by the baseline object, and every reference to it is rewritten. A CTIParsor
  object with the same id as a baseline object is that object. A CTIParsor
  relationship that becomes a self-loop, or a duplicate of a baseline
  relationship, is dropped. Baseline objects are never modified: they are written
  back as received (`serialize_bundle`, the parsed JSON, not a stix2 round trip),
  and they keep their own markings and author.
- **Rejection closure**: a baseline object leaves the bundle when all its rows are
  rejected (a pending row keeps it), and so does everything that references it.
  Each one is recorded in the mapping ledger as `removed`, kind `baseline`.
- **`reissue_report`** (ADR-0090 D1, an OpenCTI-style upsert). The chosen Report
  keeps its `id`, `confidence`, `created`, `created_by_ref` and markings. Its
  `object_refs` keep the references to kept objects and gain what CTIParsor adds
  and the document states: its new objects and relationships, and the baseline
  relationships the Report does not list that CTIParsor built too. An ATT&CK or
  composed edge is not stated and is not added. `modified` is the build time, or the Report's
  `modified` + 1 ms when the clock is behind. `external_references` gain
  CTIParsor's `original_document` once. `x_ctiparsor_enrichment` records the
  baseline's `baseline_sha256`, its bundle id, the build time and the counts.
- **Stage 5** validates only what CTIParsor built or re-issued
  (`validation_json`). The baseline objects were validated once at intake
  (lot 2), so a 10 000-object baseline is not checked again at every finalize.
  Lot 1 measured the intake with the JSON schemas at about 47 s for 10 000 objects.
- **Finalize** (`re_run_final_stages`) does not rebuild the baseline's share:
  `baseline_only` entity rows and imported relationship rows (`baseline_in_text`
  and `baseline_only`) are not Stage 4 inputs. A `baseline_in_text` entity row is
  still read, and the merge replaces it by the object it matches.
- **Scope**: every relationship between two in-scope objects is in scope, even
  one the Report does not list. A CTIParsor bundle given back as its own baseline
  therefore round-trips with the same ids.
- **Build record**: `jobs.bundle_build_json` names the baseline's SHA-256
  (`baseline_sha256`) for an `enrich` job, on a run and on a finalize.
- **`apply_baseline_merge`** (`pipeline/bundle_ledger.py`) records the matches
  (`baseline_match`), the dropped relationships and the baseline objects left
  out. It never writes `changes`, which the Graph page reads as a rewrite.
- **Not yet checked on a running OpenCTI**: the upsert and the confidence rule in
  `docs/stix-output.md` rest on the reading of OpenCTI's source in ADR-0090. The
  throwaway-instance import is lot 7.
- **Edge cases**: an id the baseline gives twice ships in the version the intake
  indexed (the latest `modified`), not the last one in the file. A lone surrogate a
  baseline carries as a JSON escape is written back as that escape, so the bundle
  stays UTF-8. A chosen Report whose references all leave is not re-issued (STIX
  wants one reference): a WARNING and the ledger (`baseline_report_empty`) say so;
  with nothing the document states, the bundle has no Report. A kept object the
  re-issued Report lists is not marked `outside_report`.
- **Tests**: `tests/test_baseline_merge.py` (24), `tests/test_stage4_baseline.py`
  (6), `tests/test_baseline_finalize.py` (20), `tests/test_run_baseline.py` (7),
  `tests/test_baseline_e2e.py` (16: the real merge end to end, a round trip, the
  verbatim objects, the upsert and a finalize with a rejection). The five files
  hold 73 tests, collected on 2026-10-25. `tests/test_baseline_stix.py` gains one
  test for the scope and is 448 on the same day.
- **Docs**: `docs/stix-output.md` (Enriched bundle: what ships, the upsert, the
  confidence rule, the rejection), `docs/pipeline.md` (the merge after 4b, Stage 5,
  the finalize).

#### Enriching an existing STIX 2.1 bundle, lot 3: Stage 3r, the baseline reconciliation (ADR-0090), 2026-10-25

An `enrich` job (lot 2) now runs Stage 3r. After the extraction, the run's
entities and relationships are matched against the analyst's bundle, and the
worker stores each row's status. **A `full` job runs as before**, and the
feature stays behind `STIX_ENRICHMENT_ENABLED`, default off. Stage 4 does not
read the baseline yet (lot 4).

- **`reconcile`** (`pipeline/baseline_stix.py`) is pure and runs in four
  passes: the extracted entities (the rows the run writes, the LLM's names and
  TTPs, held TTPs included) by match key; the baseline entries no extraction
  found, searched in the report text as whole words (`baseline_in_text` when
  found, `baseline_only` when not); the extracted relationships, held ones
  included, whose two ends and verb are a baseline relation (`matched`); and the
  baseline relations no extraction found, imported. It returns a
  `Reconciliation`, whose counts go into the stage's outcome.
- **Stage 3r** (`pipeline/orchestrator.py`) follows `3doc` in `STAGES`. In full
  mode it is skipped with the reason `no baseline`. An error fails the run: there
  is no fall back to full mode, and no entity or relationship is written. The
  `baseline_reconciled` hook receives the result before `extraction_ready`.
- **Stored rows** (`api/worker.py`): every entity and relationship row carries
  `enrichment_status` (`new`, `matched`, `baseline_in_text`, `baseline_only`) and
  `baseline_stix_id`. A matched row is accepted at once, with `decision_origin`
  `baseline_stix` and a `decided_at` (ADR-0090 D5). The rows the baseline adds
  are stored accepted, with origin `baseline_stix`; an entity's `source` is
  `baseline_stix`. A full job stores these columns NULL, as before.
- **Learning and grounding**: `load_decisions` (`pipeline/promotion.py`) never
  reads a `baseline_stix` row: an imported one by its source, a matched one by
  its origin, which is not a human origin. The grounding harness
  (`tests/eval_pipeline.py`) reads full jobs only.
- **`load_index`** (`api/baseline_store.py`) returns the validated index of an
  `enrich` job, and `None` for a full job or a job with no baseline row.
- **Known limit, for lot 4**: a Finalize rebuilds the bundle from the rows that
  ship (`re_run_final_stages` reads `accepted` or pending rows), so an accepted
  imported row is read by the rebuild and can reach the rebuilt bundle. The run's
  own Stage 4 does not see it, and no test covers the rebuild with such a row.
- **API**: the `enrichment` counts of an `enrich` job (`GET /api/jobs/{id}`) now
  hold the rows' statuses, which lot 2 left empty.
- **Docs**: `docs/pipeline.md` (Stage 3r and its place in the order),
  `docs/database-schema.md` (the `baseline_stix` origin and source values).
- **Tests**: `tests/test_baseline_reconcile.py` (28), `tests/test_orchestrator_baseline.py`
  (5), `tests/test_baseline_persistence.py` (11) and `tests/test_baseline_exclusions.py`
  (3): 47 collected on 2026-10-25. `tests/test_orchestrator.py` now expects 3r
  in the stage order.

#### Enriching an existing STIX 2.1 bundle, lot 2: storage, the flag and the API (ADR-0090), 2026-10-24

The third of ADR-0090's eight lots lets a job carry a baseline: the three
ingestion routes accept the bundle, check it with lot 1's module, and the job
stores it. **Jobs still run in full mode**: nothing reads the baseline to
extract or ship anything yet (lot 3 wires the pipeline), so no bundle changes.
The one effect on a job is the worker's schema check below, which fails an
`enrich` job whose chosen Report fails the JSON schemas.
The whole feature is behind `STIX_ENRICHMENT_ENABLED`, default off.

- **Migration v0013** (`api/migrations/v0013_stix_baseline.py`): `jobs.pipeline_mode`
  (`full` by default, `enrich` for a job with a baseline); the table
  `job_baselines` (one row per job, deleted with it: `sha256`, `size_bytes`,
  `report_id`, the bundle as received in `bundle_json`, its `index_json`, its
  `intake_json`, `validated`); `enrichment_status` and `baseline_stix_id` on
  `entities` and `relationships`, NULL in full mode. Every addition is nullable
  or defaulted and nothing is backfilled, so a worker of the previous revision
  keeps inserting.
- **`STIX_ENRICHMENT_ENABLED`** (`.env.example`), default `false`, read at each
  request. While it is off, a request that carries a baseline and
  `POST /api/baselines/inspect` answer **400** `STIX enrichment is not enabled on
  this server`; a request without a baseline is unchanged.
- **`GET /api/baselines/status`** returns `enabled`, `max_bytes` and
  `max_objects`. **`POST /api/baselines/inspect`** (multipart `file`, optional
  `report_id`, 10 requests a minute) returns the intake of lot 1 for a bundle
  without creating a job: counts by type, the objects left out and why, the
  reports, `needs_report_choice`, the minimum TLP and PAP. It stores and logs
  nothing and does not run the JSON schemas.
- **The three ingestion routes** take the baseline: `baseline_stix` (a file) and
  `baseline_report_id` on `/api/upload`; `baseline_bundle` (the TEXT of the
  file, since the `sha256` is of the bytes received) and `baseline_report_id`
  on `/api/ingest/text` and `/api/ingest/url`. Order of the checks: the flag
  and a `baseline_report_id` without a baseline (**400**, before a byte of the
  bundle is read), then the cheap checks on the report (pasted text: its
  length; upload: its size, streamed to disk; URL: its validation), then the
  baseline (size, **413** over 20 MB; UTF-8; the intake), **before the
  Playwright capture** for a URL, which can take up to its capture deadline. A
  refused baseline leaves no row, and an upload's report file is removed. An
  empty or blank `baseline_bundle` or `baseline_report_id` is no baseline. The
  job row and its `job_baselines` row are written in one transaction, before
  the worker can start; `job_baselines.job_id` is a foreign key to `jobs` with
  `ON DELETE CASCADE`. The `async` ingest routes run `start_job` off the event
  loop.
- **At most two baselines are read at once** per server process, whichever
  route they come by (a read is CPU and memory, and the four routes have
  independent rate limits): a request waits up to 30 s for a slot, then
  answers **503** `Busy reading another STIX bundle, retry in a moment.`
  Declared in the OpenAPI schema with the 400 and 413, as are the 404 of the
  baseline routes and the 409 of the entity and relationship routes.
- **A job that never runs keeps nothing.** When the queue is full and the job
  is marked failed (503), its `job_baselines` row is deleted with it. An
  upload that fails for any reason before the job is handed over removes the
  report file it wrote. A baseline is read on its own four threads, not in
  asyncio's default executor, which creates the jobs.
- **Choice of the Report (D4)**: with several Reports and no
  `baseline_report_id` the request is a 400 that lists them; an id the bundle
  does not hold is a 400; a bundle with no Report is taken whole.
- **TLP and PAP minimum (D2)**: a `tlp_level` or `pap_level` lower than the
  most restrictive marking the baseline carries is a 400, checked before
  anything is stored or captured. With no `tlp_level` the job gets the more
  restrictive of that minimum and the server's `STIX_TLP` default (AMBER when
  unset), never less than a job without a baseline; with no `pap_level`, the
  baseline's minimum (PAP has no default).
- **WARNING logs (D3)**: one line per object the baseline leaves out
  (`[baseline] job <id>: dropped invalid STIX object <id> (<type>): <reason> —
  <detail>`), written once the job is stored, for the first 200; then one line,
  `… and K more excluded object(s), listed in the job's intake`. The worker's
  step caps its lines the same way. `/inspect` logs none.
- **The JSON schemas run in the worker**, not in the request
  (`api/baseline_store.py`, `validate_in_worker`, called at the start of
  `_run_pipeline`). The request runs the stix2 checks only. Lot 1 measured
  intake at 1.9 s for 10 000 objects without the schemas and about 47 s with
  them (49.0 s with 1 invalid object); a request cannot wait that long. The
  worker re-runs the intake with the schemas, stores the index and the report,
  sets `validated` to 1 and logs one WARNING per object the schemas exclude
  that the request had not. A job already `validated` (a requeue, a lease
  reclaimed, a crash-resume) is not validated again.
- **A `BaselineError` at the worker fails the job** with its message (the chosen
  Report itself fails the schemas, or an `enrich` job holds no baseline); it
  does not fall back to full mode. It is logged as a WARNING with the message,
  without a traceback: the analyst's bundle is at fault, not the code. A `full`
  job is not touched.
- **`GET /api/jobs` and `GET /api/jobs/{id}`** carry `pipeline_mode`; an
  `enrich` job's `GET` adds `enrichment`: the intake, `validated`, and the
  number of entities and relationships by `enrichment_status` (empty until
  lot 3). The entity and relationship rows carry `enrichment_status` and
  `baseline_stix_id`. The bundle is never in these responses, and `excluded`
  lists the first 200 objects left out with `excluded_total` (a bundle can
  exclude thousands); **`GET /api/jobs/{id}/baseline/intake`** returns the
  whole stored intake, 404 for a job with none.
- **`GET /api/jobs/{id}/baseline`** downloads the bundle as received
  (`<job_id>_baseline.json`); 404 for a job with none. Deleting a job, and the
  retention sweep, delete its baseline.
- **Imported rows are decided, not edited.** A row whose `enrichment_status` is
  `baseline_in_text` or `baseline_only` answers **409** to a `PATCH` that
  changes an entity's `entity_type`, `value` or `mitre_id`, or a relationship's
  endpoints, verb or dates (a date counts as soon as it is sent), and to a
  `DELETE` (reject it instead: a deleted row could no longer say whether the
  object leaves the bundle). Accepting and rejecting, one by one or in bulk,
  work as before. `decisions.BASELINE_STIX` (`baseline_stix`) is a new decision
  origin that only the server writes: a client sending it gets a 400.
- **nginx** (`docker/nginx/default.conf`): `client_max_body_size` goes from 50m
  to **72m**, that is 50 MB of report plus a 20 MB baseline in one multipart,
  and a little for the form (72m is because of this feature). `/api/upload`
  accepts a `Content-Length` up to those 70 MB only while the mode is on; the
  report keeps its own 50 MB limit, checked on the bytes read.
- **Hostile text.** The bundle's strings come from outside. A baseline sent as
  text that is not valid UTF-8 (a lone surrogate) or a file that is not UTF-8
  is a 400, not a 500. A lone surrogate in what the intake returns or stores is
  replaced by U+FFFD (a JSON response could not encode it); a NUL stays, stored
  as the escape `\u0000`. In a log line, every character that does not print (a
  line break, a control character) is replaced by U+FFFD, so a bundle cannot
  forge a log line.
- **Docs**: `docs/api.md`, `docs/configuration.md`, `docs/database-schema.md`,
  `docs/architecture.md`.
- **Tests**: `tests/test_baseline_api.py` (66 collected on 2026-10-24) and
  `tests/test_baseline_worker.py` (8), a v0013 test in
  `tests/test_migrations.py`, `pipeline_mode` in `tests/test_jobs_routes.py`.
  `tests/test_api_schema.py` now covers 60 operations in the schema, 56
  exercised (56 and 52 before).

#### Enriching an existing STIX 2.1 bundle, lot 1: the module that reads the baseline (ADR-0090), 2026-10-24

The second of ADR-0090's eight lots adds the module that reads the bundle the
analyst already has (the baseline) and computes the keys the next lots match
on. It is not wired into the pipeline, the API or the UI yet (lots 2 to 5), and
the feature will stay behind `STIX_ENRICHMENT_ENABLED` (lot 2): this lot changes
no output.

- **`pipeline/baseline_stix.py`**, a pure module: no store, no network.
  `intake(raw, *, report_id=None, preview=False, validate=True)` returns
  `(BaselineIndex | None, Intake, parsed bundle)` and raises only
  `BaselineError`, whose message is meant for the analyst. In order:
  - **Limits**: 20 MB, 10 000 objects, 500 000 JSON objects however nested
    (a guard on memory, checked while the JSON is read).
  - **STIX 2.1 only**: a 2.0 bundle or an object without
    `"spec_version": "2.1"` (an observable may omit it) is refused. A
    malformed id is excluded, and so is every version of an id but the one
    modified last.
  - **Scope** (ADR-0090 D4): the chosen Report and what it references,
    transitively. With several Reports and none chosen, `preview=True` answers
    `needs_report_choice` and `preview=False` raises.
  - **Checks**: each object is parsed by stix2, then the bundle goes through
    the JSON schemas **once**; the validator's `<id>: ` prefix attributes each
    error to its object, and each object so named is validated alone to
    confirm it. The validator also reports, under its own id, a dict nested in
    another object, so an object could otherwise get an innocent one excluded
    in its place. When an error is not reproduced by the object it names, or
    names no object, the rest of the bundle is validated again and searched by
    halves, within a budget of three times the bytes searched. A STIX pattern
    of more than 64 KB, 64 nested brackets or 256 `AND`/`OR`/`FOLLOWEDBY`
    reaches no parser (stix2patterns is recursive: on CI, a 4 000-term `OR`
    killed the test process): its Indicator is excluded. A quoted
    detection rule is checked (`check_pattern` for Sigma, Suricata and Snort;
    the compile status for YARA) and one that is refused is excluded.
    An object that takes the id of CTIParsor's own author identity or of one of
    its markings, for something else, is excluded.
  - **Closure**: whatever references an excluded object is excluded in turn,
    whole and never pruned, except the chosen Report.
  - **TLP and PAP**: the minimum over every marking form, that is TLP 1.0 ids,
    CTIParsor's ids (the TLP 2.0 AMBER+STRICT among them), OpenCTI's markings
    that carry a name and no `definition`, granular markings, and a `tlp_2_0`
    extension property. A marking that looks like a level and states none
    earns a warning.
  - **Index**: one entry per observable together with its Indicators and the
    `based-on` between them, one per named SDO, the relations, and the rest
    copied (`passthrough_ids`). It serialises to JSON and refuses another
    `INDEX_VERSION`.
- **Match keys.** `keys_for_row` (a job-store row), `keys_for_object` (a STIX
  object) and `pattern_keys` (the `=` comparisons of a STIX 2.1 pattern, read by
  stix2patterns) reduce all three to one key space by one normalisation, so a
  baseline object and an extracted row meet. A threat-actor and an
  intrusion-set share a family, and so do a malware and a tool; two names meet
  only inside a family. `resolve` and `BaselineIndex.lookup` return the
  candidate, `None`, or `AMBIGUOUS` when several fit and none has the exact
  STIX type; a weak key (a file name) never merges.
- **Measured** on a synthetic bundle of 10 000 objects and 4.4 MB (WSL, on
  `/mnt/c`): intake takes 1.9 s without the schema validation and about 47 s
  with it. The whole bundle is validated once whatever the number of invalid
  objects, plus one small validation per object named: 1 and 10 invalid
  objects took 49.0 and 48.9 s.
- **`validate_bundle(..., quiet=False)`** (`pipeline/stage5_validation.py`):
  `quiet=True` returns the same verdict without printing or logging. The
  default is unchanged, so Stage 5 behaves as before.
- **Fuzz target `baseline_intake`** (`fuzz/fuzz_baseline_intake.py`): intake as
  `/inspect` reads it (preview) and as job creation reads it, the preview
  without the schema validation, and `pattern_keys`. It checks that nothing but
  `BaselineError` escapes, that every exclusion has four string fields, and
  that an index survives `to_json` / `from_json`. Its 14 seeds are in
  `fuzz/corpus/baseline_intake/`. The `Fuzzing` workflow runs it with
  `-max_len=65536`, the other targets keeping 16384: the largest seed is
  16.6 KB, and cut short it would no longer be JSON.
- **Tests**: `tests/test_baseline_stix.py` (447 collected on 2026-10-24),
  including the `quiet` verdict.

#### Enriching an existing STIX 2.1 bundle: ADR-0090 proposed, reference bundles and baseline fixtures, 2026-10-24

ADR-0090 proposes a second mode at report creation: the analyst gives the
report **and** a STIX 2.1 bundle that already describes part of it, and
CTIParsor shows what the bundle has, what is new and what only the bundle
says. It then ships the bundle unchanged plus its additions, the chosen Report
re-issued the way OpenCTI upserts it. Decisions D1–D5 are taken; nothing of the
feature is implemented yet (eight lots, one PR each).

This first lot adds only tests:

- **Stage 4 reference bundles** (`tests/test_stage4_reference.py`). Five
  synthetic scenarios (`tests/fixtures/stage4_reference/`): an APT report
  (with its source file, publication date and CVE data), a policy pin, rules
  quoted in the text, a long-distance edge, a minimal one. They are built
  through `build_bundle` and compared to a frozen canonical form of the bundle
  and its ledger. The canonical form ignores build-time timestamps, the names of the
  ids stix2 draws at random (relationships, the Report, an attack-pattern
  built from a legacy technique row) and object order, none of which means
  anything in a bundle; every other change to the full-mode output fails a
  test. `UPDATE_STAGE4_REFERENCE=1` regenerates the
  references, for a deliberate change that also comes with a
  `BUNDLE_AFFECTING` entry. The canonical form is the same under two
  `PYTHONHASHSEED` values.
- **Baseline fixtures** (`tests/fixtures/baselines/`), checked by
  `tests/test_baseline_fixtures.py`: an OpenCTI 2.1 export shaped after
  OpenCTI's converters (property extensions, a TLP marking with `name` and no
  `definition`), a MISP-style export with indicators only, detection rules (one
  Sigma rule `check_pattern` refuses), invalid objects, a STIX 2.0 bundle, two
  Reports, a Report with a confidence, references to objects outside the bundle.

#### The malware lead, measured once on AnnoCTR test and not adopted (ADR-0089), 2026-10-19

ADR-0088 left malware precision unchanged: three leads each stayed under the
+5-point gate alone. They were registered as one lead (CyNER's malware written
as ordinary language dropped; "Ryuk ransomware" and "hacking group TA505"
reduced to the name; spaCy's PRODUCT label no longer proposing malware),
frozen at `ccb9edf`, and measured once on the AnnoCTR test split against
criteria fixed before the runs (`docs/eval/ner-malware-2026-10.md`).

- **Malware precision doubled**: 0.194 → 0.389, +19.5 points [+14.5, +24.9],
  with three gold entities gained and none lost.
- **Locations lost** 4.2 points of precision and 4.5 of recall. In one report,
  the LLM, given other CyNER names, listed countries where it had listed the
  nationality adjectives AnnoCTR annotates. The lead is therefore not adopted,
  and the pipeline is unchanged.
- **ADR-0088's first test figures** come from the baseline run: threat-actor
  precision 0.259, location 0.505.

New: `scripts/measure_ner_precision.py`, the harness:

- `run`: records what spaCy and CyNER returned, with the commit, settings and
  models, and refuses a run that would measure nothing;
- `status`: lists the documents to run again after a server failure;
- `replay`: re-runs Stage 2 on recorded model outputs;
- `compare` and `gates`: the paired comparison and the registered decision
  rule.

The decision rule is tested in `tests/test_measure_ner_precision.py`.
#### An ATT&CK release is a track a run selects, and a v20.0 track ships (ADR-0087), 2026-10-18

ATT&CK v20.0 came out on 2026-10-13. No shipped file said which release it came
from (the retrieval corpus's manifest read `attack_version: null`), and
`scripts/download_attack.py` without an option now fetches 20.0 from the
mitre/cti master, which would have changed the evaluation's gold mapping while
the pipeline's index stayed on 19.2. The audit of 2026-10-17 asked for a v20
track that does not replace the experimental snapshots.

- **The shipped files are 19.2, except two.** Each was rebuilt from the
  official v19.2 assets and compared. `mitre_index.json`, `attack_revoked.json`,
  the retrieval corpus (17,350 entries) and both embedding sets match
  (`attack_retrieval_embeddings.npy` and `mitre_embeddings_meta.json` byte for
  byte, `mitre_embeddings.npy` to within 2e-7). `gazetteer.json` lacks the 14
  name variants 19.2 added, and
  `attack_relationships.json` lacks 237 pairs of 19.2 and keeps 1 it no longer
  has. The 615 CAPEC entries come from a bundle whose version was not recorded.
  `pipeline/data/attack_manifest.json` records all of it.
- **`ATTACK_RELEASE` selects the track**, per process. Unset (or `19.2`,
  `v19.2`, `default`) is the files of `pipeline/data/`; `20.0` reads
  `pipeline/data/attack/20.0/`. An unknown value raises `UnknownAttackRelease`:
  `run_document` checks it before Stage 1, `build_stix_bundle` before Stage 4
  (a finalize reaches it without `run_document`) and `build_manifest`. There is no
  fallback (ADR-0073's rule for TLP). A `v` is a prefix only before a digit, and
  digits are ASCII.
- **One release per process.** The first `attack_data.current()` that resolves
  fixes the release: `.env` is loaded when `stage3_llm` or `api.db` is imported,
  and a process could otherwise read the default track for Stages 2b and 2c and
  `ATTACK_RELEASE`'s after that. A later call that resolves another version
  raises `UnknownAttackRelease`. The API, the worker and the evaluation's `run`
  commands resolve it when they start, so a typo stops them there.
- **The run manifest records the release.** A new `attack` block (release,
  `requested`, directory, the manifest's and the source bundles' hashes, the
  documented `exceptions`, `built_with`, and `modified_files`: files whose hash no
  longer matches the track's manifest, or that it does not know). `data` hashes
  the files actually loaded.
  `ATTACK_RELEASE` is in the captured environment, and `stage3_settings`
  carries it: the Stage 3 checkpoints that exist are invalidated once.
- **The v20.0 track** is 39.9 MB in nine files: 706 Enterprise, 125 Mobile, 104
  ICS and 615 CAPEC entries in `mitre_index.json`, a retrieval corpus of 17,845
  entries, 20,849 curated pairs, 1,866 gazetteer name variants (1,827 on the
  default track). It differs from the default track by ATT&CK only, but for the default
  track's gazetteer and curated relationships, which predate 19.2: the CAPEC
  entries are carried over, the revoked table and the corpus are Enterprise-only,
  the embedding model is the same. The default does not change; moving it
  asks for ADR-0060's paired comparison on dev.
- **Tools.** `scripts/download_attack.py --release X.Y` downloads the release's
  three bundles from mitre-attack/attack-stix-data and checks each against the
  sha256 GitHub publishes (it refuses an asset without a digest, an unexpected
  URL, a size that differs from the published one and a published digest that
  differs from the track's manifest). Without `--release` it still fetches the mitre/cti master,
  and now says that this may not be the default track's release. `scripts/build_attack_release.py --release X.Y` builds
  a track from those bundles into a neighbouring directory and renames it
  (`--force` to replace one); another `TTP_EMBEDDING_MODEL` than MiniLM gives the
  track an embeddings manifest. `scripts/build_indexes.py` takes `--out-dir` and
  `--capec-index`.
- **Evaluation.** The gold is mapped against one release: a run's own by
  default, `--attack-release` on `prepare`, `score`, `ttp-errors`, `compare`,
  `release-effect` and `retrieval` to name another. `attack-mapping.json` is the
  default track's mapping, `attack-mapping-<X.Y>.json` another's. `compare`
  refuses two runs of different releases unless the option names the mapping.
  A run (`run`, `inhouse-run`) resumes only on the release it began with, and an
  unknown `ATTACK_RELEASE` stops it before any document; `inhouse-score` follows
  the run's release. A run whose manifest lists `modified_files` is scored with
  a warning on stderr and `attack_modified_files` in the report.
  `Catalogue.for_release` finds the release's Enterprise bundle by sha256, never
  by file name. `python -m evaluation attack-diff --old 19.2 --new 20.0` writes
  what changed between two releases (Enterprise 697 → 706 active techniques, none
  revoked, deprecated or renamed; ICS deprecates T0807 and T0853). `release-effect --a --b` (`--old` and
  `--new` default to the releases the runs ran on)
  classes each parent technique on which two runs differ (`new_technique`,
  `new_subtechnique`, `status_changed`, `content_changed`, `unchanged`), with
  ΔTP, ΔFP, ΔFN and a hybrid F1 per class.
- The interface keeps reading `frontend/public/mitre_index.json`, whatever the
  track. (Since 2026-10-19 it reads the selected track's index from the API:
  see "The interface reads the index of the selected ATT&CK track" under
  Changed.)
- **Measured on AnnoCTR dev, at one commit** (docs/eval/attack-v20-2026-10.md).
  - **The reference reproduces exactly.** The 19.2 run, `sel-dev-a19.2-5b98a49`,
    gives the same techniques and the same candidates as the historical
    `sel-dev-revoked-5d1bbe4` on all 16 reports: nothing between the two commits
    moved the TTP outputs on dev.
  - **Retrieval alone is unchanged.** The selector's candidate ceiling stays at
    0.884 and 0.954 on both tracks.
  - **20.0 against 19.2**: F1 0.584 → 0.609, +0.025 [−0.019, +0.076], not
    significant. Precision +0.026, recall +0.023.
  - **The taxonomy effect on ids is nil.** The gold maps the same under both
    releases, and no technique new in v20 reaches a candidate list.
  - **Every difference goes through the new descriptions and procedure
    examples.** About half of the F1 gain (0.011 of 0.025) goes with the one
    selection answer per run that did not parse, which moved from DarkSide (2 → 8 correct) to TA505.
    Without those two reports: +0.014 [−0.026, +0.042], and precision
    +0.041 [−0.015, +0.078].
  - **The default stays 19.2.** ADR-0060's rule is not met.
  - **Re-run on 2026-10-21 at `01aeea6`**, which has the Stage 3f cut-off
    salvage (ADR-0072): no selection answer is cut off, refused or salvaged on
    either track. 20.0 against 19.2: F1 0.609 → 0.612, +0.003
    [−0.028, +0.028], precision −0.001. The earlier gain does not survive, and
    the default stays 19.2 (addendum to docs/eval/attack-v20-2026-10.md).

#### The store audit checks the build's revision; a script measures the revision trigger (ADR-0086), 2026-10-18

`scripts/audit_store_invariants.py` gains `job.bundle_revision` (severity
`error`): no job has a `bundle_review_revision` above its `review_revision`. The
revision only grows and a build stores the one it read, so a bundle ahead of its
job means a revision written by hand, or restored without its rows; every later
finalize of that job would be refused until enough writes overtook it.
`tests/test_audit_store_invariants.py` holds it (3 tests).

`scripts/measure_review_revision_trigger.py` times the same writes under no
trigger, v12's row trigger and a statement trigger with transition tables, in a
throwaway schema. On 5,000 entity rows (PostgreSQL 17.11, median of 5 rounds)
the statement trigger is slower than the row trigger on the run's `executemany`
write: 1.03 s against 0.78 s, and 0.21 s with no trigger. It is faster only
where one statement writes many rows: an `UPDATE` of every row took 0.030 s
against 0.421 s. The row trigger stays and there is no new migration; ADR-0086
has an amendment with the whole table.

### Documentation

#### Seven small gaps the documentation audit left, 2026-10-29

- **`make ci`** does not run `reuse lint` nor the migration check from the base
  commit: `TESTING.md` and the `Makefile`'s comment no longer say it runs
  everything the pull-request CI runs, as `CONTRIBUTING.md` already does.
- **ADR-0023**'s header said Phases 3–6 were open; its status review of
  2026-10-03 records Phases 4–6 as implemented by ADR-0072, as the index said.
- **`docs/releasing.md`** no longer speaks of 0.1.0 as not yet released.
- **`docs/docker.md`**: schema migrations run at the first start of the API or
  of a worker, not of the API only.
- **`docs/development.md`**'s project tree gains the modules and data files it
  lacked: `api/migrate.py`, `api/db_identity.py`, `api/baseline_store.py`,
  `api/routes/baselines.py`, `pipeline/gazetteer_policy.py`,
  `pipeline/gazetteer_context.py`, `pipeline/named_entities.py`,
  `pipeline/benign.py`, `gazetteer_context_rules.json`, `warninglists.json`
  and `attack_revoked.json`.
- **`docs/eval/README.md`** gives `hard-docs` and points to the in-house set's
  commands (`preannotate`, `inhouse-run`, `inhouse-score`, `agreement`).
- **`docs/api.md`**: entity and relationship rows carry `held_reason`
  (ADR-0082); a held row is skipped by the bulk and accept-pending routes, and
  an accepting `PATCH` labelled `human_bulk` gets a 409.

#### The diagrams show both workflows, full extraction and enrich mode (ADR-0090), 2026-10-29

The Mermaid diagrams drew only the full extraction: none showed the STIX 2.1
bundle an analyst can give, Stage 3r or the merge.

- **`docs/pipeline.md`** opens its *Stages* section with a flowchart of the two
  workflows: the baseline intake (the preview, `job_baselines`, the worker's
  second intake with the JSON schemas), the stages both share, Stage 3r for an
  enrich job only, then CTIParsor's own Report or the merge into the baseline
  with the chosen Report re-issued, and Stage 5.
- **`README.md`**: the component map gains Baseline Reconciliation
  (`baseline_stix.py`) and the Baseline Store (`baseline_store.py`), joined by
  edges labelled *enrich*; the stage table gains the row for **3r**, which it
  lacked.
- **`docs/architecture.md`**: *The life of a report* marks with `opt` blocks
  what an enrich job adds (the preview, the `job_baselines` row written in the
  `jobs` row's transaction, the second intake, Stage 3r's rows), and the `jobs`
  row is shown inserted as `uploaded`, then queued, as the code does.

All five Mermaid blocks of these files render with mermaid 11.4.1.

#### The reference pages catch up with two weeks of changes, 2026-10-26

Nine read-only audits compared the reference pages with the code merged since
2026-10-11 (#166 to #215), and each finding was checked against the code before
it was written. The CHANGELOG and the ADRs had kept up; the pages they point to
had not always. What the pages now say:

- **Configuration** (`docs/configuration.md`, `.env.example`). Every variable
  added in the period was documented. Seven older ones were not, although the
  page says it lists every setting: `CTIPARSOR_CAPTURE_UNSANDBOXED`,
  `CTIPARSOR_CAPTURE_PROXY`, `CTIPARSOR_UPLOADS_DIR`, `CTIPARSOR_OUTPUT_DIR`,
  `CTIPARSOR_STATE_DIR`, `ENV` and `CTI_GIT_REV`. `CTI_DEV_IMAGE` joins
  `.env.example`, and `LLM_MODEL` joins the variables that have no effect.
- **API and schema** (`docs/api.md`, `docs/database-schema.md`). Every route was
  documented. Added: the rows' `enrichment_status` and `baseline_stix_id`; the
  503 of the two ingest routes when the queue is full, and what it removes; the
  400s of `PUT /api/relationship-policy`; the `queued` and `partial_graph`
  progress events; the JSON 404 of an unknown `/api/` path. In the schema:
  `job_baselines` in the table list, the `baseline_sha256` and `error` forms of
  `bundle_build_json`, how imported rows are written, and which writer the
  `bundle_review_revision` guard applies to.
- **Pipeline** (`docs/pipeline.md`). Stage 2b's ordinary-word policy; one type
  per name and resolution by the verb (ADR-0091, ADR-0092); a new section on
  rejected and held relationships (ADR-0013, amendment of 2026-10-26); Stage 3f's
  cut and ceiling counts; invalid LLM items and the cancelled chunks of an
  aborted Stage 3; the CIRCL stop; every stage that reads the ATT&CK track.
- **STIX output** (`docs/stix-output.md`). A section on the mapping ledger's new
  reasons (`not_a_uri`, `outranked_type`, `ambiguous_name`, the IoC-association
  reasons, `refused`), what the baseline intake leaves out, the enrich-mode
  ledger entries, and the YARA `include` rule. Corrected: the markings, the
  author and `x_synthesis_stats` are on what CTIParsor builds, not on baseline
  objects; a CTIParsor Report is built when the chosen Report is rejected;
  attack-pattern ids are computed except for hand-annotated techniques; a quoted
  rule ships unchecked when its checker is not installed.
- **Interface** (`docs/web-ui.md`). The Coverage page's ATT&CK release and its
  Other column; the New report modal's submit labels and bundle card; the
  Review page's `STIX` chip, hints and ribbon lines.
- **Operations** (`docs/upgrading.md`, `docs/deployment.md`, `docs/docker.md`,
  `SECURITY.md`, `README.md`). Upgrading from v0.1.0: schema versions 12 and 13,
  enrichment on by default, the shipped 20.0 track. The proxy's 72 MB body
  limit; reference bundles and request budgets as a threat surface; the
  baseline fuzzer. Corrected: the nginx config is `docker/nginx/default.conf`;
  only a job whose lease expired is requeued at start; the dev frontend runs on
  node 26.
- **Contributors** (`CONTRIBUTING.md`, `docs/development.md`, `TESTING.md`,
  `docs/eval/README.md`). Four of the five fuzzers are required checks; what
  `make ci` leaves to CI; the gazetteer policy is rebuilt after any edit to its
  document; the new scripts in the tree; an index of the measurement notes.
- **Registers** (`docs/adr/README.md`, ADR headers). The statuses of ADR-0040
  and ADR-0075 agree with their files; the index gives the latest amendments of
  ADR-0049 and ADR-0082; ADR-0058, 0065, 0069, 0072, 0088 and 0091 gain their
  `Amended by` line, ADR-0086's `Amends` gains ADR-0084, and ADR-0021 and
  ADR-0061 no longer call ADR-0091 proposed.

`docs/releasing.md` said, as the entry of 2026-10-24 below does, that the
release's four files pass `sha256sum -c SHA256SUMS`; `SHA256SUMS` lists the
archive and the SBOM. Comments in `scripts/check_migration_from.py` and
`.github/workflows/ci.yml` no longer say there are no release tags.

Left as found: `docs/gazetteer-ordinary-words.md` still says "not implemented",
because its SHA-256 is the policy version every run records; and
`PIPELINE_DISABLED_STAGES=3r` is accepted and then ignored, which is code.

#### The pages that said no release existed describe v0.1.0 (ADR-0085), 2026-10-24

`SECURITY.md`, `docs/docker.md`, `docs/releasing.md`,
`docs/openssf-best-practices.md` and ADR-0085 still said, as of 2026-10-17,
that no release had been published. They now give what was read back on
2026-10-23 and 2026-10-24, read-only, through the API, `gh attestation verify`,
the registry and Scorecard:

- **The Release.** "CTIParsor 0.1.0", published on 2026-10-17 and marked Latest,
  from the annotated tag `v0.1.0` on 4bdfa8f. Its four files pass
  `sha256sum -c SHA256SUMS`, and the pinned verify commands of its notes pass.
  `0.1.0`, `0.1` and `sha-4bdfa8f…` name one image digest.
- **The OpenSSF criteria** `version_unique`, `version_semver`, `version_tags`
  and `release_notes` are Met, with the Release, the tag and the notes as
  evidence. The answers are not entered on bestpractices.dev yet (new action
  item 6 of ADR-0085).
- **Release immutability is on**, but it was turned on after v0.1.0 was
  published: v0.1.0 is not immutable. ADR-0085's action item 3 is done, item 4
  too.
- **No tag ruleset exists.** The only ruleset targets the branch, so item 2
  stays open.
- **Scorecard's Signed-Releases check scores 10**, from the
  `ctiparsor-0.1.0.intoto.jsonl` asset.

`SECURITY.md`'s *Supported versions* no longer says `main` is the only supported
version.

#### A Stage 3f prompt that asks for the answer once, measured on AnnoCTR dev and not adopted (ADR-0072), 2026-10-24

One sentence was added to the selection prompt and measured: "Write that
object once, then stop: nothing goes after its closing brace." It restates the
"write the answer once" of the prompt rejected on 2026-10-20, without that
prompt's decide-first step or 25-word `reason`. On AnnoCTR dev at `7867cd3`, against a baseline
at the same commit that reproduces the earlier reference on 16 of 16 reports:

- **Rules 1 and 2 of ADR-0060 broken.** Technique F1 fell from 0.609 to
  0.587 (−0.022) and precision from 0.571 to 0.515 (−0.057).
- **It did not do its job either.** Answers restarted after a complete
  answer went from 3 to 4, and 3 answers reached the 4,096 ceiling, against
  none with the shipped prompt.
- **The prompt is unchanged.** The train stress test was not run, as fixed
  before the runs.

The model also chose more (272 choices against 239, 21 parent-and-sub-technique
pairs against 9), as with the earlier prompt, though `reason` was left alone.

Two findings concern code already merged; neither is changed here:

- A selection answer written as a bare list and cut at the ceiling keeps none
  of its complete choices: the salvage reads only `{"selected": [...]}`.
- A genuine train answer closes at 4,011 tokens, above the 3,167 that set the
  4,096 default.

Detail: `docs/eval/selection-once-2026-10.md`.

#### CONTRIBUTING.md points to the versioned migrations, 2026-10-18

Two passages still described a schema change as an addition to
`_JOB_STORE_DDL_POSTGRES` or `_RULE_STORE_DDL_POSTGRES`. They now point to a new
`api/migrations/vNNNN_<name>.py` (ADR-0077) and to
`docs/development.md#database-migrations`, and say the two constants are only
the history kept for the SQLite import scripts.

### Changed

#### The interface reads the index of the selected ATT&CK track (ADR-0087, amended), 2026-10-19

The Coverage page took technique names and tactics from
`frontend/public/mitre_index.json`, whatever `ATTACK_RELEASE` said. That file was
not one of a track's. It came with the initial commit and no script writes it.
It had the default track's 1,533 techniques, but 39 tactics instead of 41: the
two missing are mobile, `TA0038` Network Effects and `TA0039` Remote Service
Effects. It also spelled the domains `enterprise`, `mobile` and `ics`, had no
technique `shortname`, and cut descriptions at 161 characters.

- **`GET /api/attack/index`** serves the `mitre_index.json` of the track the API
  runs, unmodified, with the release in `X-Attack-Release`. The ETag is the
  file's sha256 and `Cache-Control` is `no-cache`, so a reload gets a 304 while
  the file is unchanged. After a restart on another track, the browser gets the
  new index, never the cached one. A track without the file answers 404, not
  with the default track's file.
- **The Coverage page and `useMitreSearch` read it** through one query
  (`useAttackIndex`). The page shows the release (`ATT&CK 20.0`) next to the
  report's name. On 20.0 the search finds `T1698` Indirect Prompt Injection.
  `useMitreSearch` still has no caller: nothing has imported it since the initial
  commit.
- **The static file is removed**, along with its entries in `REUSE.toml` and
  `THIRD_PARTY_NOTICES.md`. The index weighs about 750 KB instead of 440 KB
  (749,660 bytes on 19.2, 758,174 on 20.0). A browser downloads it once per
  index; later loads get a 304.
- **The column check covers every track.**
  `test_every_enterprise_tactic_in_the_index_has_a_column` reads the index of
  each track `attack_data.available()` lists, not only the one the process
  selects. The page's columns moved to `frontend/src/components/coverage/tactics.ts`,
  and `tactics.test.ts` holds them to the same rule. Both tracks have the same
  fifteen enterprise tactics, so no column changes.
- **ADR-0087's Consequences said the API's ATT&CK search follows the track.** No
  route calls `mitre_db.search`. The amendment corrects that sentence, and
  `docs/configuration.md` no longer repeats it.

#### A CyNER threat actor and a spaCy place must look like a name (ADR-0088), 2026-10-18

The audit of 2026-10-17 named entity precision as the main quality defect of the
shipped bundle. On AnnoCTR dev, CyNER gave 87 of the 97 threat-actor false
positives ("cybercriminals", "underground forums", "Chinese threat actors",
"Iran"), and spaCy's `GPE` label gave most of the location ones ("C&C", "XSS",
"GitHub"). It also returned "the United States" with its article, which Stage
4's ISO country table does not know. Two filters in the new
`pipeline/ner_precision.py` now run in Stages 2d and 2:

- **CyNER `Threat_group` only.** A fragment is dropped when it has no capital
  letter and no digit in a report written with capitals, when it is a country
  ("United States", "Hong Kong"), or when every word of 3 or more letters is a
  category word, a software name, a nationality or a country. The words are
  ADR-0050's 141 plus 178 read in the AnnoCTR train false positives, Stage 2's
  93 software names (with six added), 21 nationality words and the countries of
  Stage 4's table. Words that form real names (agent, crew, circles, miner) stay
  out; "Agent", "Crew" and "Miner" alone are dropped. The capital-letter test is
  skipped for a text with fewer than 0.5% capital letters. Malware is untouched.
- **spaCy `GPE` → location.** The value is put on one line, a leading "the" and
  a trailing apostrophe are dropped ("the United States" is now "United
  States"), and it is kept only if it can be a place name: a country or a known
  abbreviation, or letters (accented ones too), spaces, periods, hyphens and
  apostrophes, with a capital first letter, not an acronym of five capitals or
  fewer (XSS, SCADA), not camel case (GitHub, DocuSign; McLean is kept), not
  made only of category or software words (Payload, Linux). Two-letter values
  stay dropped, "the US" included.

Both filters run before the case-insensitive dedup, so a capitalised spelling
outlives a lowercase one. They are on by default. `NER_PRECISION_FILTERS=false`
restores the previous output exactly: replayed on recorded model outputs, Stage
2 gives the same entities on 70 of 70 train and 16 of 16 dev documents. Stages 2
and 2d record "precision filters on (ADR-0088)" in the stage report, and
`NER_PRECISION_FILTERS` joins the captured environment of the run config (it
appears only when set). The CLI's stage table (`main.py`) now prints a stage's
note and its counts together; it printed the note instead of the counts.

Measured on AnnoCTR dev, strict, in a real run with the LLM against a baseline of
the same commit (10,000-resample paired bootstrap; criteria fixed before any dev
figure; test split not read). Threat actors: precision 0.134 → 0.326 (+19.2
points, 95% interval [+11.4, +30.9]), recall 0.938 unchanged, 15 TP / 97 FP →
15 / 31, F1 0.234 → 0.484. Locations: precision 0.406 → 0.526 (+12.0 [+5.1,
+18.9]), recall 0.402 → 0.412 (one gold entity gained, none lost), 39 / 57 →
40 / 36, F1 0.404 → 0.462. Malware and identity are unchanged; tool precision
+1.1. On train (no LLM): threat actors 0.132 → 0.320 with none of 63 true
positives lost, locations 0.440 → 0.602 with 1 of 143 lost ("The United States",
annotated with a capital "The").

Not adopted, each under the +5-point gate on its own and losing nothing on dev:
the same rule for CyNER's malware (+2.6 points), reducing "Ryuk ransomware" or
"hacking group TA505" to the name and splitting on brackets (+1.2 actors, +3.0
malware), and dropping spaCy's PRODUCT → malware (+3.5). With all four leads in
place malware precision rose by 13.2 points offline, but that was read after the
measurement: it would have to be registered as one lead and measured on data this
study has not read. Malware precision stays 0.205. Known losses: an actor
written only in lowercase in a report written with capitals, "Iranian Cyber
Army", "Pakistan Cyber Army"; vendor names that look like towns remain places.

The bundle gets fewer Threat Actor objects named after ordinary language, and
Locations such as "United States" that Stage 4 now finds in its ISO table. A
follow-up commit lists this change in `BUNDLE_AFFECTING` with the `extraction`
scope (ADR-0086). Measurement:
[docs/eval/ner-precision-2026-10.md](docs/eval/ner-precision-2026-10.md).
ADR-0050 gets a dated amendment.

#### A freshness entry names its scope: a finalize clears a Stage 4/5 fix, only a new run clears an earlier one (ADR-0086), 2026-10-17

Each `BUNDLE_AFFECTING` entry (`pipeline/bundle_revisions.py`) gains a fourth
field. `mapping`: the fix changes Stages 4 and 5 only, and is judged on the
revision that built the stored bundle, so a finalize at a revision that has it
clears it. `extraction`: the fix changes Stages 1 to 3, maybe 4 too, and is
judged on the run's revision and the build's; a finalize rereads the rows a run
wrote and cannot add what the run never extracted, so only a new run clears it.
`eaee534` (the self-edge guard) is `mapping`; `3a25f45` (ADR-0063's dates) is
`extraction`.

`stale_entries(rev, repo_root, *, build_rev=None)` and `audit_staleness` take
and return the build's revision (`build_rev`); `unknown` is true only when
neither revision is known. `scripts/audit_bundle_invariants.py` prints the
run's and the build's revisions when they differ, and the remedy for each scope: `POST /api/jobs/{id}/finalize`
for a `mapping` fix, a new run for an `extraction` fix. `CONTRIBUTING.md`
carries the rule for choosing the scope: when in doubt, `extraction`. ADR-0035
gets a dated amendment.

### Fixed

#### The capture proxy starts without warnings it could have turned into an outage, 2026-10-26

`docker/squid/squid.conf` listed `::ffff:0:0/96` in `blocked_dst`. Squid stores
every IPv4 address as an IPv4-mapped IPv6 one, so to Squid that range is
`0.0.0.0/0`. Listed last, it was dropped with six "'240.0.0.0/4' is a subnetwork
of '0.0.0.0/0'" warnings at each start. Moved to the top of the list, it drops
every IPv4 line instead and blocks every IPv4 site (measured on the pinned
image). The line is gone. A mapped destination is still refused through the
IPv4 lines: `[::ffff:127.0.0.1]` and `[::ffff:10.0.0.1]` answer 403. The config
also sets `pinger_enable off`: under `cap_drop: [ALL]` the ICMP pinger had no
raw socket and logged `FATAL: Unable to open any ICMP sockets` at every start.
What the proxy lets through is unchanged.

#### The capture proxy no longer reports `unhealthy` while it works, 2026-10-27

`capture-proxy`'s health check ran `echo > /dev/tcp/127.0.0.1/3128` as
`CMD-SHELL`, that is through `/bin/sh`, which is dash in the Squid image. Dash
has no `/dev/tcp`, so the check exited 2 ("Directory nonexistent") on every run
since the proxy was added (2026-09-19), and `docker ps` showed the proxy
`unhealthy` while it served requests. The check now runs the same line through
`bash`: healthy at the first check, and it still fails against a closed port.
Nothing waited on that status (`app` depends on the proxy with
`service_started`).

#### Stages 1 and 3r can no longer be "disabled" to no effect, 2026-10-26

`PIPELINE_DISABLED_STAGES`, the CLI's `--disable-stage` and `RunOptions(disabled=…)`
accepted every known stage id, but Stage 1 (ingestion) and Stage 3r (baseline
reconciliation) never read the switch: `PIPELINE_DISABLED_STAGES=3r` was taken
without an error and both stages still ran. The two ids are now refused with a
message that says why: Stage 1 makes the text every stage reads, and Stage 4
merges an enrich job's baseline through Stage 3r's matches (ADR-0090). A worker
or CLI whose setting names one fails the run, as an unknown id already did.
`--require-stage` still accepts both. Bundles are unchanged.

#### A name two lists share no longer puts a claim on the wrong object (ADR-0091), 2026-10-26

Stage 4 kept one object per lower-cased name, so a name in two of the LLM's
lists (or in a list and a technique) kept the last object written, and every
relationship that named it hung on that object. With `Carbanak` as threat actor
and malware, the `targets` edge left the malware and none left the actor. With
`Mimikatz` as malware and tool, "Mimikatz uses OS Credential Dumping" resolved
on the Tool, and `tool uses attack-pattern` shipped as `related-to`.

`_NameIndex` now keeps one object per name and STIX type. Each end of a row
resolves to the type its verb expects. When several pairs fit, or none, the row
is dropped with the ledger reason `ambiguous_name` and the ids of the candidates,
which the Graph page shows. The `targets` product, raw entities, raw techniques
(no longer "merged" into a tool of the same name), IoC associations and
embedded-rule titles read the type they mean. Measured on 7 real reports
(150 rows): 10 names carry two or three types and touch 75 rows; 55 rows change
(51 shipped rows now dropped, 3 dropped rows change reason, 1 row now ships with
its verb); relationship SROs 1,390 → 1,361; 118 `targets` edges move from a
malware to the actor of the same name; object counts unchanged. The cost is
recall on reports whose detectors type one name two ways. It lands with ADR-0092,
which chooses one type per name by source rank before Stage 4.

#### A name typed several ways keeps the type of its best-ranked source (ADR-0092), 2026-10-26

Stage 2 already kept, for a name two detectors typed differently, the type of
the better-ranked one (ADR-0055). The LLM's names, its campaign name and the
analyst's rows come later, so a name could still reach Stage 4 under several
types, and ADR-0091 dropped its rows as `ambiguous_name`. The same ranking,
extended, is now applied where the named lists are built, on a run, a finalize
and `scripts/baseline_round_trip.py`: the analyst (a row added in review, a row
accepted on its own, a name the baseline holds under that type, whatever found
it), then the IoC regexes and the gazetteer, then
the LLM, then CyNER and GLiNER, then spaCy and the alias list. A campaign ranks
last unless the analyst gave it: the LLM's `campaign_name` reused a malware's or
an actor's name in all three cases measured. Equal ranks all stay, and ADR-0091
resolves each row by its verb. Each type left out is recorded in the ledger as
`dropped / outranked_type`, which the Graph page explains. Measured on the 7
real reports: of the 54 rows ADR-0091 drops, 13 ship again on main's object
types, 3 go back to main's `benign_observable`, and 38 stay dropped (37 are
CyNER typing one name as both malware and threat actor). Four Campaign objects
named like a malware or an actor leave their bundles. This reverses in practice
the audit's "A campaign named like a malware" fix below (Stage 4 still builds
such a Campaign, but it rarely reaches Stage 4 now); unlike before the audit, the
drop is recorded, and the analyst's accept of the campaign row brings the
Campaign back. Stage 4 is not changed.

#### IoC associations no longer build a rejected or held relationship (ADR-0013, amended), 2026-10-26

Stage 3 links IoCs to malware families in its JSON (`ioc_associations`), and
Stage 4 builds each IoC's Indicator `indicates` that malware from the link. No
review row stands for a link, and finalize reads them unfiltered: a rejected
"185.220.101.5 indicates ZetaLoader" row, which lands on that IP's Indicator,
came back from its association, and a held one shipped before anyone decided
it.

Each association now skips the edge a refused row names, with the same rules as
the targets product and pinned rules (entry below). The rows that do not ship
are resolved through each observable's Indicator, and the associations build
those Indicators: so each association, once its Indicator is in place, resolves
the refused rows that name its IoC. The Indicator and its `based-on` still ship:
the analyst refused the link, not the IoC. The mapping ledger lists the skipped
edge under `refused` with origin `ioc_association`, the IoC and the malware. A
build with no rejection is unchanged. The `BUNDLE_AFFECTING` entry follows in a
separate commit (scope `mapping`).

#### The targets product and pinned rules no longer build a rejected or held relationship (ADR-0013, amended), 2026-10-26

Stage 4 builds an edge from every threat actor to every country and sector the
LLM lists as targeted, and a pinned policy rule builds one for every pair of
its two types. Neither has a review row, and neither looked at the rows an
analyst rejected: the product filtered rejected locations and sectors, not
rejected relationships, so a rejected "APT29 targets France" came back from the
LLM's lists, and a pinned rule could build a rejected row's edge too. A claim
held for review (ADR-0082) shipped the same way before anyone decided it.

Both now skip the triples graph completion skips (entry below): Stage 4
resolves the rows that do not ship once, before the product, and the product,
the pin pass and Stage 4b read the same set, with graph completion on or off.
A country or sector named only by the LLM's list is found too, and a triple an
accepted row also names is not refused (the job store can hold both). A refused
pinned pair takes no `max_pinned_edges` budget. The mapping ledger lists each one
under `refused` with the origin that would have built it (`targeted_location`,
`policy_pin`), and every `refused` entry now carries that `origin`, the graph
completion ones included. A build with no rejection is unchanged. IoC
associations (`indicator indicates malware` from the LLM's JSON) are covered by
the entry above. The `BUNDLE_AFFECTING` entry follows in a separate commit
(scope `mapping`).

#### Graph completion no longer adds back a rejected or held relationship (ADR-0013, amended), 2026-10-26

Finalize gave Stage 4 only the relationships that ship, and Stage 4b skipped a
triple only when it was already in the bundle. A relationship the analyst had
rejected came back: two accepted edges "A uses B" and "B uses C" composed
"A uses C" (`transitive:uses+uses`), and ATT&CK reference grounding re-added a
rejected edge MITRE also states. A claim held for review (ADR-0082) shipped the
same way before anyone decided it. Both engines are on by default.

The maintainer decided that a rejection says the relationship is false for this
report, and that a held claim waits for its analyst. Finalize now also reads the
rows that do not ship (`decisions.WITHHELD`), Stage 4 resolves them as it
resolves the rows that ship, and no engine adds their triples back: not the
transitive step, not reference grounding, not long distance (which may not
turn a rejected `related-to` around either). A pipeline run
refuses Stage 3d's held claims the same way. The mapping ledger lists each
refused edge under `refused`, with the rule it would have carried and the
reason (`rejected_by_analyst`, `held_for_review`); a build with no rejection
keeps its ledger unchanged. Other edges Stage 4 builds with no review row (the
targeted-location product, pinned edges) are covered by the entry above. The
`BUNDLE_AFFECTING` entry follows in a separate commit (scope `mapping`).

#### A code audit's fixes: a web-capture range, a DOCX zip bomb, doubled rows after a requeue, lost detection rules, 2026-10-26

A code audit read the repository by zone (worker and API, Stage 1 to 4, the
ADR-0090 enrichment, the detection parsers, the frontend). Each finding was
read again in the code before it was fixed, and each fix has a test. The audit's
other findings are not fixed here.

**Security**

- **Web capture, carrier-grade NAT**: `_ip_is_public` (`pipeline/web_capture.py`)
  took 100.64.0.0/10 (RFC 6598) for a public range. `ipaddress` counts it as
  neither private nor global, and Alibaba Cloud's metadata endpoint,
  100.100.100.200, sits in it. The compose deployment's Squid filter already
  refused the range (`docker/squid/squid.conf`), so a deployment without that
  proxy was the exposed one. The range is refused now, and
  `http://100.64.0.1/` and `http://100.100.100.200/` are in the test.
- **DOCX zip bomb**: `_read_docx` and the creation-date reader opened any
  `.docx` and inflated it whole. Both now add up the members' declared
  uncompressed sizes first, and refuse the file with a `ValueError` above
  512 MiB (`_MAX_DOCX_UNCOMPRESSED_BYTES`).

**Worker and API**

- **A requeued job doubled its rows**: a job put back in the queue after
  Stage 3 (lease expired, worker drained) runs again from Stage 1, and
  `_save_entities` inserted its entities and relationships a second time under
  new ids. It now deletes the job's rows and inserts the new ones in one
  transaction. The write used to run in autocommit, behind a `commit()` that
  did nothing, so a failure could leave it half done.
- **`PATCH /api/jobs/{id}` took `processing` and `uploaded`**: a job set to
  `processing` with an old heartbeat was requeued, and ran the whole pipeline
  over a report under review. Only `for_review`, `reviewing`, `completed` and
  `failed` are accepted now; any other value is a 400. The client only sends
  `reviewing`.
- **The worker's owner**: `_run_pipeline` read the job's owner from the
  database instead of using the one captured when the subprocess was spawned.
  It is passed as an argument.
- **A job timeout in Stage 3 cancels the chunks still queued**: the timeout was
  raised inside a `with ThreadPoolExecutor` block, whose exit waited for every
  queued chunk to run. The queued chunks are cancelled now; the calls already
  running still finish (at most `llm_parallelism`).
- **The crash message** told the operator to reduce `WORKER_MAX_MEMORY_MB`,
  which nothing reads. It says to lower `WORKER_MAX_CONCURRENT` or raise the
  container's memory limit.
- **A full queue left the file behind**: the 503 left the uploaded file on
  disk. `start_job` removes it; for a URL capture, the PDF archive and its
  metadata go too. The job row stays, `failed`, as before.
- **Pasted text**: `POST /api/ingest/text` answered 500 and left an empty file
  for a text with a lone surrogate, and failed the job at Stage 1 for a NUL
  character. Both are a 400 before anything is written.
- **Unknown ids**: `POST /api/jobs/{id}/entities/accept-pending` on an unknown
  job and `DELETE /api/settings/corpora/{name}` on an unknown corpus answered
  200. Both are a 404.
- **Relationship policy**: a list or an object as a rule's `src`, `tgt` or
  `verb` raised a `TypeError` (500) in `value not in frozenset`. It is a 400
  that names the rule.
- **Malformed `Origin`**: `Origin: http://[` made `urlsplit` raise inside the
  cross-site guard, a 500. It is a 403.
- **Unknown `/api` path**: the SPA fallback answered `index.html` with a 200 for
  `/api/unknown`. A path under `api/` stays a JSON 404.
- **A baseline saved with a byte-order mark**: the stored text keeps the BOM
  (its sha256 matches the file), and `json.loads` refused it when the enrich job
  loaded the baseline, so the job failed. The BOM is dropped when the text is
  read; the stored text and its hash are unchanged.

**Stage 1 and 2**

- **OCR**: one page that Tesseract failed on dropped the whole scan, though
  `_ocr_page` already caught such a failure. A failing page is logged and the
  others are kept.
- **Figures**: an answer with a null `content` raised an `AttributeError`. It
  is an empty answer now, and one cut at `max_tokens` is reported as such
  (`finish_reason=length`); the figure reads as `unread` with that error.
- **Figure edges** were not refanged with the figure's text (Stage 2 caught
  them later). `map_verbatim` applies the refang to each edge's source,
  destination and label.
- **CVE enrichment (Stage 2f)**: a CIRCL timeout, connection error, 5xx or
  unreadable reply was saved in `cve_cache` as an absence, so the CVE was never
  asked again. Only a definite answer is saved (CIRCL's 404, or a reply that
  is not a JSON object). On an outage the report's lookups stop, a warning
  counts the CVEs left, and the next run asks again.
- **Registry keys**: `...\Run. It then...` was read as one key. The key ends at
  a full stop and a blank in its last segment; a vendor name before a backslash
  (`Acme Corp. Ltd\Run`) is kept.
- **Unix paths**: `/tmp/x.sh.` and `/usr/bin/updater,` kept the punctuation
  that follows them. A path that starts with `/` loses trailing `.,:;!?`.
- **TTP candidates (Stage 2c)**: with between 201 and 399 candidate sentences
  the cap's stride was 1, so the first 200 were kept and the end of the
  document was never seen. The cap takes `TTP_MAX_CANDIDATES` (200) sentences
  evenly spaced across the list.
- **GLiNER chunks (Stage 2e)**: a long unbroken token pulled each cut back to
  an early space, one character further on every time (about 70 chunks of a
  few characters on the test text). A cut is not walked back into the first
  quarter of the chunk (400 characters at the default `GLINER_CHUNK_CHARS` of
  1,600), as for CyNER.

**Stage 3**

- **A malformed value lost the whole chunk**: one TTP with `evidence_label`
  `"Observed"` or a null `description` failed validation of the answer, and
  every entity and relationship of the chunk went with it. A TTP's label is
  lower-cased and anything outside observed, reported, assessed, inferred and
  gap becomes `reported`, as for relationships. When validation still fails, the
  list items it points at (or a top-level field of the wrong type, which takes
  its default) are dropped and the answer is validated again, in at most five
  passes; a warning counts what was dropped.
- **Prose before the answer**: a `{}` written in the prose before the real
  object made the result empty. An empty object is skipped.
- **Verification answers (Stage 3d and 3f)**: a `[]` or `[1]` in the prose
  before the real array made the whole call unparseable, so every claim went to
  review. `parse_numbered_claims` goes on to the next array when one holds no
  numbered claim.
- **Dates**: a UTC offset of 24 hours or more (`+25:00`) raised a `ValueError`
  that stopped Stage 3, and a count of days or weeks past the calendar
  (`1000000 days ago`) an `OverflowError`. Both are `unresolved`, with the
  reasons `invalid_date` and `implausible_year`. A span of months or years past
  the calendar (`last 2000 years`) is `unresolved` as well. An analyst entry
  with such an offset is refused, and page metadata with one is no publication
  candidate.
- **Stage 3f proposals**: an ATT&CK-shaped id the index does not hold (`T9999`)
  became a candidate. It must be in the loaded index.
- **Stage 3f, a second copy of an id**: a copy with no valid quote put the id in
  review, and a later copy with a valid one was ignored. The valid copy replaces
  the review entry.

**Stage 4 and the ADR-0090 enrichment**

- **Stage 4c quotes**: any non-empty `quote` was accepted, one the model wrote
  itself included. It must be found in the report text (`stated_in`), the bar
  Stage 3d applies. `related` must be the JSON `true`: the string `"false"`
  passed.
- **A campaign named like a malware**: a `campaign_name` equal to a malware or
  an actor name built no Campaign, and the ledger recorded a merge into the
  malware (`same_value`). The Campaign is built and found by its own id, and a
  raw Campaign entity of that name is still the one Campaign.
- **Indicators of IoC associations** were built on the LLM's spelling of the
  value: the pattern differed from its observable, and the Indicator's id from
  the one `verify_ioc_coverage` computes. They use the value of the extracted
  entity.
- **Dropped associations left no trace**: an association abandoned because its
  observable or its malware is not in the bundle, or because no pattern could
  be built, has a ledger entry now: `dropped`, with the reason
  `ioc_not_in_bundle`, `malware_not_in_bundle` or `no_pattern`, which the
  Graph page explains.
- **IoC coverage**: `verify_ioc_coverage` counted a URL left out on purpose
  (`not_a_uri`, the entry below) as a missing observable, and a run logged
  "IoC coverage gaps". The URL is listed under a new `skipped` key, and counts
  neither in the total nor in the gaps.
- **Confidence**: `int(confidence * 100)` truncated, so 0.57 shipped as 56. It
  is rounded: 57.
- **A blank `mitre_id`**: `"  "` gave `x_mitre_id` `""`, and two different
  techniques shared one attack-pattern id. The id is built on the stripped value
  (on the name when it is blank), and a blank id gets no external reference.
- **A baseline object with a CTIParsor object's id**: the ledger kept Stage 4's
  origin for it, so the baseline panel listed it under "Added by CTIParsor" and
  the entity rows stayed `emitted`. The ledger records the origin `baseline`,
  keeping the object's annotations, and the rows that produced the object are
  `merged` with the reason `baseline_match`.
- **An invalid copy of a valid id**: the intake put the id in `excluded_ids`
  though a valid copy was kept. It does so only when no valid copy holds the id,
  and `newest_versions` skips a copy the intake refuses instead of choosing it
  for its later `modified`.

**Detection**

- **YARA regex literals**: a `//` or `/*` inside a regex (`= /…\/…/`) was read
  as a comment, which lost six rules in `corpora/`, among them
  `SUSP_JDNIExploit_Indicators_Dec21` and `RCS_Scout`. A regex opened by `/`
  after `=` is copied as it is, and a comment beside it is still blanked.
- **YARA tags on the next line**: `rule X :` with its tags on the lines that
  follow (allowed by YARA; `MALW_TrickBot.yar`) did not match the rule header,
  and the rule was ignored. Tags may wrap.
- **`private global rule`** was read as not private, the repeated prefix group
  keeping only its last word. The prefix is read whole.
- **`split_rules` was quadratic** on a text with many headers that never close
  (a report's text in Stage 4): each header searched for its closing brace to
  the end of the text, on a copy of it. The search stops at the next header.
- **Coverage facets**: `rule_facets_for_job` left out the rules reached by
  evidence, which `rule_bodies_for_job` (the export) includes, so the facets
  counted fewer rules than the packages. Both add them.
- **Suricata hex segments**: `|2e|` in a `content` became a space (`/gate.php`
  read `/gate php`) and DNS rules lost their domain. A segment of letters, digits,
  `.`, `-` and `_` is decoded; any other stays one space, as before, so
  `seed.nkn.org|3a|` keeps its domain. A leading `../` that decoding produces
  still yields the path's last segment.
- **Suricata ports**: `isdigit()` accepts `²`, `int()` then raised, and one such
  rule stopped the corpus. It is `isdecimal()`, and a rule that fails to convert
  is logged and skipped.
- **Sigma**: a `logsource` that is not a mapping, or a YAML date in a detection
  (not JSON-serialisable), raised and stopped the corpus. The first reads as
  empty, the dedup key serialises with `default=str`, and a document that fails
  is logged and skipped.
- **Sigma dedup keys** folded the case of every value, so `Foo.*bar` and
  `foo.*bar` under `|re` or `|cased` were one rule. They keep their case; `|re|i`
  still folds it.
- **A corpus with no `path`** ran `git -C . pull` and walked the working
  directory. `rebuild_store`, `iter_rules`, `sync_corpus` and
  `scripts/sync_corpora.py` skip it.

**Frontend**

- **Review shortcuts** ignored Ctrl, Cmd and Alt: Ctrl+C opened the Coverage
  page and Ctrl+F finalized the report. A key pressed with one of them held is
  left alone.
- **Leaving Review** dropped a pending auto-finalize, so the last edits were
  missing from the bundle. A pending rebuild now runs when the page unmounts, as
  `useDebouncedFinalize` does. The timer is cleared once it has fired or a
  manual finalize has run, so leaving after those rebuilds nothing.
- **A hash value that is not hexadecimal**: `buildRanges` built a `RegExp` from
  it, and a character such as `(` threw a `SyntaxError` that took the page
  down. Each character is escaped.
- **Group accept (✓ N)** sent the held rows (ADR-0082), which the server refuses
  with a 409, and left the local state wrong. It skips them. The count and the
  tooltip count the rows it accepts, and the button is hidden at zero.

**Checks**: the full suite 4121 passed, 0 failed, 9 skipped; ruff clean; mypy,
141 files; the parser tests on Python 3.12 with re2, 230 passed; the frontend
289 passed, then two Marginalia tests were added (11 of 11 in that file pass).
**Docs**: `docs/api.md`, `docs/web-ui.md`, `docs/database-schema.md`,
`docs/configuration.md` and `docs/pipeline.md` follow the changed statuses,
keys, cache rule and Stage 4c quote bar.

**To do after this change**: rebuild the detection index
(`scripts/build_detection_index.py`) so that the corrected Suricata atoms and
Sigma dedup keys enter it. The `BUNDLE_AFFECTING` entry follows in a separate
commit (scope `extraction`).

#### A URL that is not a valid URI no longer makes the bundle invalid, 2026-10-25

Stage 4 built a `url` observable, and its Indicator, from any URL in the
report, but the STIX schema requires `url.value` to be a URI (RFC 3986). One
redacted URL such as `https://[REDACTED]/socktz_v8.exe` made Stage 5 reject the
whole bundle, and finalize raised `BundleInvalidError`, in full mode as in
enrich mode. It was the one Stage 5 failure of the ADR-0090 lot 7 round trip
on the measurement reports.

Stage 4 now checks the value with the same `uri` format check Stage 5 runs. A
value that fails it gets no `url`, no Indicator and no relationship, and the
mapping ledger records it as dropped with the reason `not_a_uri`, which the
Graph page explains. The value is not repaired: a redaction has no URL to
recover, and a rewritten one would be another IoC. Stage 2 keeps extracting
it, so the Review screen still shows the mention. Defanged URLs are unchanged:
Stage 1 refangs `hxxp://` and `[.]` before the URL regex runs, so they ship.
The round trip now validates 7 of 7 bundles.

#### An upload error shows the server's message, 2026-10-25

`uploadFile` (`frontend/src/api/client.ts`) threw `Upload failed: <statusText>`,
which hid the server's detail. It now throws the status and the server's body,
which `errorDetail` reads, so the New report modal shows the server's message.

#### filelock and setuptools move past four new advisories, 2026-10-24

The dependency audit failed on 2026-10-24 on four advisories published since
its last pass:

- **filelock**: three (CVE-2026-112940, -112913, -112907), fixed in 4.2.1.
  filelock comes in through huggingface-hub and torch in the image lock, and
  through cachecontrol in the audit lock. It is now at 4.2.4 in both.
- **setuptools**: one (GHSA-xmj3-9gf7-h52w), fixed in 84.1.0. setuptools
  comes in through spacy, thinc and torch in the image lock. It is now at
  84.2.1.

The locks were rewritten by `scripts/lock.sh` with `--upgrade-package
filelock --upgrade-package setuptools`, so no other pin moved; the torch, CI
and uv locks are unchanged. pip-audit finds nothing in the four locks.

#### pillow moves past eight new advisories, 2026-10-23

The dependency audit has failed every run since 2026-10-21, on both open PRs
and on any new run of main: eight advisories against pillow 12.3.0
(CVE-2026-112395, -112397, -112400, -112404, -112895, -112896, -112897,
-112899), all fixed in 13.0.0. pillow comes in through pdfplumber, pdf2image
and pytesseract, in the image and CI locks. It is now at 13.0.0. The locks were
rewritten by `scripts/lock.sh` with `--upgrade-package pillow`, so no other
pin moved; the torch lock is unchanged. pip-audit finds nothing in the four
locks.

#### The Coverage page files only enterprise techniques under a tactic (ADR-0025), 2026-10-20

The page put a technique in a tactic column on its tactic shortnames alone, so
T1660 Phishing (`mobile-attack`, `initial-access`) sat in the enterprise
Initial Access column. The backend's phase band puts mobile, ICS and CAPEC
techniques off-matrix (`ENTERPRISE_DOMAIN` in `pipeline/detection/phases.py`).
The page now reads each technique's `domain` from `GET /api/attack/index` and
files a technique that is not `enterprise-attack` under Other, through
`techniqueColumns` in `components/coverage/tactics.ts`. Enterprise techniques
keep their columns: `tactics.test.ts` checks every technique of every committed
track.

#### A looping Stage 3f selection call stops at 4,096 tokens and the stage report says so (ADR-0072), 2026-10-20

About one Stage 3f selection call in 65 loops until `LLM_MAX_OUTPUT_TOKENS`
(8,192) cuts it, after about 320 seconds. The selection call now has its own
output-token ceiling, `TTP_SELECT_MAX_OUTPUT_TOKENS`, never above
`LLM_MAX_OUTPUT_TOKENS`. Unset, it is 4,096 on vLLM with thinking off
(`VLLM_ENABLE_THINKING` false), the setup it was measured on; every other
provider keeps `LLM_MAX_OUTPUT_TOKENS`, because a model that reasons before it
answers (Gemini 2.5, vLLM with thinking) spends an unmeasured share of its
budget first. The ceiling follows the provider of the call (Stage 3e's second
provider too), is part of the Stage 3 checkpoint fingerprint (a select-mode
checkpoint saved before this change does not resume), and is among the
variables the API records with a job.

The provider's finish reason (`length`, or Anthropic's `max_tokens`) is now
recorded for every call, also when the answer has no content. The Stage 3
counts gain `provider_at_ceiling`; Stage 3f gains `at_ceiling`, the selection
answers the provider stopped at the ceiling, cut inside a list or not (a
closed answer repeated until the cut, as on Kaseya, counts), with a note in
its reason, also when 3f fails; the evaluation's LLM health gains
`provider_at_ceiling` and `3f_at_ceiling`. The salvage still infers the cut
from the open list, so it works on the text alone; the counter states the
provider's word beside it.

With only `max_tokens` changed, the three logged loops took 322, 330 and 322
seconds and now take 165, 172 and 165, with the same complete choices (at
temperature 0 each answer is the exact prefix of the logged one). On AnnoCTR
dev at `01aeea6` (`sel-dev-ceiling-01aeea6p`, run at 2,048, against
`sel-dev-a19.2-01aeea6`), 16 of 16 reports are identical, technique F1 is
0.609 in both and time per report goes from 359.7 to 359.3 seconds (−0.1%).
No dev answer reaches the ceiling (the longest took 1,550 tokens): since
ADR-0088 changed the DarkSide prompt the loop no longer occurs there at this
commit, so the replays show the time saved and dev does not. The ceiling was
first 2,048. The selection call alone on AnnoCTR train (255 calls) stopped 12
answers there, 11 after a complete first object; the twelfth reasoned in prose
before any JSON and, sent again at 8,192, ended by itself at 3,167 tokens with
6 choices. 4,096 is 1.25 times that answer, rounded up, a rule fixed before
the train results were read.

A prompt asking for the decision first, the answer once, and a `reason` of at
most 25 words was measured and is not in this change. It stopped the three
loops and answers restarted after a complete object went from 3 to 0, but
dev precision fell from 0.571 to 0.545 (−0.027; ADR-0060 allows 0.02) and
technique F1 from 0.609 to 0.597. The loop itself still happens, and one that
starts in the first choice still loses its chunk. Detail:
`docs/eval/selection-loop-2026-10.md`; `tests/test_stage3_calls.py` and
`tests/test_ttp_select.py` hold the cases. ADR-0072 gets a dated amendment.

#### certifi and uv move past two new advisories, 2026-10-20

The dependency audit failed every run once two advisories were published:
certifi 2026.7.22 (GHSA-6q48-6c7w-9gw2, fixed in 2026.10.19), in the image,
CI and audit locks, and uv 0.12.23 (GHSA-hq85-5cpj-mr62, fixed in 0.13.4), the
uv `make lock` runs. Both are now at the fixed release. The locks were
rewritten by `scripts/lock.sh` with `--upgrade-package certifi --upgrade-package uv`,
so no other pin moved. pip-audit finds nothing in the four locks.

#### A Stage 3f selection answer cut off at the token limit keeps its checked choices (ADR-0072), 2026-10-19

The selection answer that "did not parse" in five of the eight select-mode
dev runs (DarkSide, TA505, TA544; one per run) was cut off, not malformed.
Reproduced with every vLLM call logged, the DarkSide and TA505 answers stop
at `finish_reason` "length" after 8,192 tokens (`LLM_MAX_OUTPUT_TOKENS`) and
about 325 seconds. The model wrote five and six complete choices, then
deliberated inside the next one's `reason` ("So T1498 is the correct one. But
T1499 is also a candidate...") until the ceiling. The list never closed, so
the whole chunk shipped nothing and its 36 to 41 candidates went to review.

`stage3f_ttp_select.salvage_selection` keeps the complete choices of an
answer cut inside its `selected` list. Each is validated as before (an id
among the candidates, a quote found verbatim, once per id), and every
candidate the answer did not reach goes to review ("selection answer cut off
before a choice for it"). An answer cut before its first choice, or one that
closes but does not parse, is still unparseable. An answer that closes and is
then repeated until the cut (the Kaseya report) is read from its first
object, as before. The salvage runs before `parse_selection`, which would read
a "[]" written inside a looping reason as an empty selection. The stage
report counts these answers as 3f `truncated`, apart from `unparsed`.

On AnnoCTR dev at `5b98a49` (`sel-dev-salvage-5b98a49p` against
`sel-dev-a19.2-5b98a49`), 15 of 16 reports are identical; DarkSide gains five
techniques, all in the gold (TP 2 → 7, FP 1 → 1). Technique F1 0.584 →
0.610, +0.026 [+0.000, +0.098]; precision 0.565 → 0.580, recall 0.605 →
0.643, time per report −1%. The loop itself is not addressed and still costs
its 320 seconds. Detail: `docs/eval/selection-cut-off-2026-10.md`;
`tests/test_ttp_select.py` holds the cases.

#### A no-break space is a space in production too (ADR-0049), 2026-10-18

google-re2 (CI, the container image) reads `\s` as ASCII whitespace only; the
stdlib `re` that `compile_pattern` falls back to without it (a dev venv) reads
it as `str.isspace()`. PDF extraction and HTML pages put no-break (U+00A0),
thin (U+2009) and narrow no-break (U+202F) spaces between words, so wherever a
pattern relied on `\s` the container extracted less than a local run:

- Stage 2: `AS\xa015169` gave no ASN; `evil\xa0[.]\xa0com` was refanged to
  `evil\xa0.\xa0com` and lost its domain; a Windows path ran across a no-break
  space (`C:\Program\xa0Files\…`). Stage 2g found no alias list whose marker
  sits next to one (`Static Tundra (aka\xa0Berserk Bear)`).
- Stage 2c and the retrieval passages joined a `1.\xa0` list item to the line
  before as a hard wrap and kept `Table\xa03` captions as candidates; passage
  and ATT&CK text kept the no-break spaces their blank collapse removes.
- Stage 3f did not find an evidence quote in a report that writes
  `spear\xa0phishing`, and sent the technique to review.
- Stage 4: an `import\xa0"pe"` outside a quoted YARA rule was not added to it,
  so the rule did not compile and was left out (ADR-0067); a rule with a
  no-break space before its brace was not found, so the ledger did not say why
  it was missing. A quoted Sigma rule followed by one that opens with
  `title\xa0:` shipped with the next rule inside its pattern. A port after
  `port\xa0` in a network-traffic value was lost.
- ADR-0050's generic-vocabulary test kept `malware\xa0family` as one token, so
  ADR-0052's promote gate let it through.

The 21 patterns write `regex_safety.PY_WHITESPACE` in their classes, or the code
splits with `str.split()`; without re2 they match what they matched. The 51
other module-level patterns that use `\s` are left, each with its reason (dates
are `fold()`ed first, lookbehinds always run on `re`, HTML and CommonMark blanks
are ASCII). Stage 2g's alias cleanup also strips every `str.isspace()` now,
under both engines: `Berserk Bear\xa0and\xa0Dragonfly` gave `Berserk Bear\xa0`
and lost `Dragonfly`. `tests/test_unicode_whitespace.py` runs 42 cases that pass
with re2 and without it (under RE2 all of them failed before the fix), and fails
on a new module-level `\s` pattern that is not listed.

#### Only a build that publishes writes the export file (ADR-0086), 2026-10-18

`re_run_final_stages` called `validate_and_export`, which writes
`output/{report}_{job_id}_bundle.json` (`..._bundle_invalid.json` when the
schemas refuse the bundle), before the conditional `UPDATE`. A refused build
therefore overwrote the file of the newer build that had published, and a
finalize that ended after `_delete_job` wrote again a file the deletion had just
removed. Two tests reproduced it and failed on the previous code:
`test_a_refused_build_writes_no_export_file` and the extended
`test_a_job_deleted_while_it_is_built_is_not_an_error`.

- Stage 5 is split: `validate_bundle(bundle_json)` returns the verdict and
  writes nothing; `export_path(output_path, result)` names the file (an
  `_invalid` suffix on an `invalid` verdict); `export_bundle(bundle_json,
  output_path, result)` writes it. `validate_and_export` composes them, so the
  CLI and the run are unchanged.
- A finalize validates, then in one transaction runs the conditional `UPDATE`
  and, only if it published, writes the file before the commit. The `UPDATE`
  holds the job's row until then: concurrent publications write the file in the
  order they publish, and a refused build or a job deleted meanwhile writes none.
  A write that fails (`OSError`) rolls the publication back and the finalize
  fails, as a failed export did before. The file is written in place, so a
  write that fails part-way leaves it truncated, as before.
- If the commit fails after the write, the file holds a build that was not
  stored; it is never served.
- Not changed: the run's own Stage 5 (the subprocess) still writes its file
  before `_finalize_job`'s write, which depends on the lease, so a run whose
  lease was taken over has written its file.

Tests: `test_an_export_that_cannot_be_written_publishes_nothing` and
`test_a_published_invalid_build_writes_only_the_invalid_file` in
`tests/test_bundle_builds.py` (30 to 33 tests); `TestValidateBundle` and
`TestExport` in `tests/test_stage5.py` (19 to 23). ADR-0086 gets a dated
amendment, which also corrects its decision 4 and its consequences.

#### `\d`, `\w` and `\b` read the same with RE2 or without (ADR-0049), 2026-10-18

google-re2 reads `\d`, `\w` and `\b` as ASCII; the stdlib `re` that
`compile_pattern` falls back to without it reads them as Unicode. 73
module-level patterns that RE2 compiles used them, so a letter or a digit of
another script split production from local runs:

- In production, a letter glued to a match had cut it out of a word:
  `joão@evil.com` gave the address `o@evil.com`, another mailbox, and
  `josé.perez@evil.com` gave `perez@evil.com`; `ÚLTIMOS DÍAS 2024` gave the ASN
  `AS2024`; `…\relatório.comunicação` gave the Windows path
  `…\relatório.comunica`; `téléport 443` in a network-traffic value gave port
  443. A match glued to a letter of a script with case (Latin, Greek,
  Cyrillic…) or to a digit is dropped now (`regex_safety.glued_to_a_word`), and
  the address's domain is still extracted. Chinese, Japanese, Korean and Thai
  write no spaces between words, so an IoC glued to them is kept, as RE2 kept
  it: `该IP属于AS4134网络` gives `AS4134`.
- In production, Stage 2g gave `Müller Group (aka Berserk Bear)` the anchor
  `Group`, lost the alias `Ghøst Blizzard`, and split `Cléand Bear` at `and`.
  Its patterns now read the text with every non-ASCII word character masked to
  `z`, a letter none of its words holds, and cut the names from the text itself.
- In production, a YARA rule named with a non-ASCII letter (`rule café`) was not
  found. It is now, and Stage 4 leaves it out with `rule_does_not_compile` in
  the ledger (ADR-0067). A spaCy span of other digits (`١.٢.٣`) was not taken
  for a version number and could be kept as a name; both version filters read
  every script's digits now (`regex_safety.PY_DIGIT`).
- Without re2, IoCs and dates took every script's digits: `T١٠٥٩` and `T１０５９`
  shipped as ATT&CK ids, `CVE-٢٠٢١-٤٤٢٢٨` as a CVE, `８.８.８.８` as an IPv4
  address, `AS١٥١٦٩` as an ASN, and `٢٠٢٤-٠٣-١٢` was a date. An IoC glued to
  Chinese text (`使用T1059技术`, `该IP属于AS4134网络`) was not found. 56 patterns
  now say `[0-9]` or `[A-Za-z0-9_]`, and the 11 that say `\b` pass `re.ASCII`,
  which `compile_pattern` now maps to RE2's own reading.
- The corpus settings refuse every transport helper git reads (`a-b::`,
  `a.b::`, `x+y::`), not only `\w+::`.

On AnnoCTR's 400 texts (44 hold a letter or a digit outside ASCII), Stage 2's
entities, the alias lists, the header dates and the YARA rule names are the
same before and after, under both engines. `tests/test_unicode_word_digit.py`
runs 68 cases that pass with re2 and without it; before the fix 47 failed under
`re` and 20 under RE2, and only helper tests, positive controls and three alias
cases (which guard the mask's letter) passed under both. It also fails on a
new module-level pattern that says `\w`, `\d` or `\b` without being reviewed.

#### A finalize records the build it made, and a rebuild clears a Stage 4/5 staleness (ADR-0086), 2026-10-17

A finalize (`POST /api/jobs/{id}/finalize`, quick or full) rebuilds Stages 4 and
5 with the current policy, data and code, but `jobs.run_config_json` kept
describing the initial run (audit of 2026-10-17, lot L1). The staleness check
(ADR-0035) judged the bundle on the run's `git_rev`, so a rebuild never cleared
a Stage 4 staleness, although `scripts/audit_bundle_invariants.py` told people
to rebuild. Entity overrides were recorded only as counts.

Migration v12 adds `jobs.bundle_build_json`, written in the same `UPDATE` as the
bundle, its ledger and its verdict:

- A finalize records its `kind` (`finalize` for the button, `quick` for the
  auto-finalize), `built_at`, `git_rev`, the policy it passed to `build_bundle`
  (read once), `env` and `manifest`. `env` is the `_CAPTURED_ENV` allow-list,
  never a scan of the environment, so no key can appear. It records no
  overrides: Stages 4 and 5 never read them. A record that cannot be built
  never fails the finalize: it is stored as `kind`, `built_at` and the `error`,
  without `git_rev`, and freshness falls back to the run's revision.
- A run writes its own record (`run`), copied from its run config. Stage 4 ran
  in the run's subprocess with the code and data that run config captured.
- `api/storage.py::save_bundle` clears the record, as it clears the ledger and
  the verdict.
- `entity_overrides` in the run config gains `fingerprint`: 16 hex characters of
  the SHA-256 of the canonical JSON of the active deny and promote rows,
  independent of their order. It says whether the same rows applied, not which.
- `NULL` means the bundle was built before v12, and `run_config_json` describes
  it. There is no backfill.

ADR-0059 and ADR-0035 get dated amendments.

#### A slower finalize no longer overwrites a newer one (ADR-0086), 2026-10-17

`re_run_final_stages` read the job's rows under `_lock`, released it for the
mapping, then wrote the bundle unconditionally (audit of 2026-10-17, lot L1).
The review page schedules a quick finalize 4 s after each edit and the Finalize
button starts another, so a slow finalize A and a fast B, started after one more
decision, could publish in the reverse order of their reads. A test reproduced it
first: `test_a_slow_finalize_does_not_publish_over_a_newer_one` failed on the old
code, the stored bundle being A's, without the entity the analyst had just
added. `_lock` is per process, so holding it longer would not have covered
several API processes or the workers.

Migration v12 adds `jobs.review_revision`, `jobs.bundle_review_revision` and
the trigger that links them:

- `review_revision` counts the writes to a job's `entities` and `relationships`
  rows. A row-level `AFTER INSERT OR UPDATE OR DELETE` trigger
  (`bump_review_revision()`) bumps it in the transaction of each write, whichever
  route, worker step or script writes; a row moved to another job bumps both.
  Every job starts at 0.
- A finalize reads the job row, the shipped entities, the relationships and the
  rejected entities in one `REPEATABLE READ READ ONLY` transaction
  (`api.db.transaction(conn, snapshot=True)`), so the rows match the revision read
  with them. The rejected rows used to be read in a second, separate block.
- One conditional `UPDATE` publishes the bundle, ledger, Stage 5 verdict, build
  record, revision and status together, `WHERE bundle_review_revision IS NULL OR
  bundle_review_revision <= R`. A build never replaces a bundle built from newer
  rows; an equal or newer one publishes (equal: the same rows, the last writer
  wins). The run's own write sets `bundle_review_revision` to the job's current
  revision, so a finalize that read the rows before the run's write is refused.
- A refused build publishes nothing and returns the stored bundle. A full
  finalize then completes the job with that bundle unless its verdict is
  `invalid`; if it is, the call raises `BundleInvalidError` with the stored
  errors (409, as in ADR-0084). The refused build's own verdict acts on nothing.
  The HTTP contract of `/finalize` is unchanged.

Limits. Every entity or relationship write now also updates its job row, about
0.1 ms per row: 5,000 entity `INSERT`s took 0.66 s with the trigger and 0.16 s
without, on a throwaway schema. Policy, data and code changes are not decisions
and do not bump the revision: two builds from the same rows under different
policies both publish, and the last to finish wins until the next finalize.
During a rolling restart, a finalize by an old-image process leaves
`bundle_build_json` describing the previous build. The export file in `output/`
was written by every build, including a refused one; since 2026-10-18 only a
build that publishes writes it ("Only a build that publishes writes the export
file", above).

### Security

#### Every other request body is held to 1 MB as it arrives, 2026-10-26

Outside the upload routes (next entry), a request body was read whole with
nothing to bound it: `PUT /api/relationship-policy` through `request.json()`,
and every POST, PUT or PATCH with a pydantic body (entities, relationships,
overrides, thresholds, settings, jobs) through FastAPI. Without the nginx
`proxy` profile in front, one chunked body of several GB on any of them used up
the API's memory. Every request without a budget of its own is now held to
1 MB the same way: a 413 on the `Content-Length`, or as soon as a body sent
without one passes it. The largest body the UI sends there is the relationship
policy with a rule for each of the 1,369 pairs of STIX types, 177 KB. The
detection export (`POST /api/jobs/{id}/detections/export`) sends rule ids, which
grow with the rule store: the tag join, the rules reached by evidence alone and
the promotions, at most every rule. On the 15 corpora on disk that is 0.94 MB
for the 38,059 ATT&CK-tagged rules and 2.1 MB for all 87,407. It gets 8 MB of
its own
([docs/api.md](docs/api.md#how-large-a-request-may-be)).

The budgets are now looked up the way the router matches a path. The table
compared paths exactly, while a Starlette route's pattern ends in `$`, which
also matches before a trailing newline. So `POST /api/upload%0A` reached the
upload route without a budget, and its whole form was spooled before the
route's own 413. It now gets the upload's budget, and a path that matches no
budget gets the 1 MB rather than nothing. The path in the `[body-limit]` log
line and in the 413 is quoted, as in uvicorn's access log.

#### An upload is held to its size limit while it arrives, chunked or not, 2026-10-26

`POST /api/upload` checked its size in the handler, and FastAPI runs the
handler only once it has read the whole multipart form and spooled its files
to disk. The `Content-Length` check therefore came after the body was on disk,
and a body sent without `Content-Length` (chunked) was bounded by nothing:
without the nginx `proxy` profile in front, the API wrote whatever it was sent
to its temporary directory. (uvicorn refuses a `Content-Length` that is not a
number itself; one that reached the handler made it fail with a 500.)

A middleware (`api/body_limit.py`, pure ASGI, so the SSE stream passes as it
is) now holds each route that takes a report or a STIX bundle to a budget. A
`Content-Length` over it gets a 413 before a byte is read; a body without one
gets a 413 as soon as it passes the budget, and the application never receives
the rest, and the refusal is logged (`[body-limit]`). A `Content-Length` that
is not a number is a 400. The budgets
([docs/api.md](docs/api.md#how-large-a-request-may-be)): `/api/upload` 70 MB,
the 50 MB report and the 20 MB bundle (50 MB with `STIX_ENRICHMENT_ENABLED=false`);
`/api/ingest/text` 51.5 MB (11.5 MB); `/api/ingest/url` 40 MB (64 KB);
`/api/baselines/inspect` 20 MB; each with 64 KB for the form. Within them the
routes keep their own limits. nginx's 72m lets the largest through, and a test
keeps it so. Checked against uvicorn, httptools and h11, with curl: a 113 MB
upload declared in `Content-Length` gets its 413 with nothing sent (curl waits
on `Expect: 100-continue`), a 2 GB chunked stream is cut after 77 MB in half a
second, nothing reaches `uploads/`, and the connection then serves the next
request.

#### A YARA rule's `include` no longer makes the server read a file, 2026-10-24

Before a quoted YARA rule ships as an Indicator, `compile_status`
(`pipeline/detection/yara_check.py`) compiles it, as OpenCTI does (ADR-0067).
It compiled with `include` directives enabled. A report could therefore quote
`include "/etc/passwd"`, and libyara would read that file on the server. The
compiler's message went into the mapping ledger, where the Graph page shows
it: "/etc/passwd(2): unterminated regular expression" for an existing file,
"can't open include file" for a missing one. Any path could be probed that
way, and for a readable file the message told the line and the kind of the
first lexer error in it.

The rule now compiles with `includes=False`. A rule with an `include` is
refused with the same message whether the file exists or not, and the file is
never opened. Such a rule is not self-contained, so nothing a reader could use
is lost.

## [0.1.0] - 2026-10-17

CTIParsor 0.1.0 is the first release. It reads a threat-intelligence report
(PDF, DOCX, HTML, TXT, Markdown, pasted text or a URL) and produces a validated
STIX 2.1 bundle ready for OpenCTI, MISP or a SIEM. Regex and NER extract the
indicators and names; an optional LLM stage adds actors, malware, relationships
and ATT&CK techniques, each backed by a verbatim quote from the report. Bundles
carry TLP markings that are never guessed and OpenCTI's standard ids, and a
bundle that fails validation is not served. Analysts review and edit the result
in a web UI, which also matches the report against local Sigma, Suricata and
YARA rules. It runs as a Docker Compose stack (API, workers, PostgreSQL), with a
hosted or local LLM, and installs air-gapped. Known limits: there is no
authentication, so everyone who reaches the port shares one workspace
(docs/deployment.md); on AnnoCTR's test split, technique F1 is 0.690 and named
entities have high recall but low precision (docs/eval/baseline-2026-10.md), so
a bundle is a draft for an analyst; and before 1.0 a minor version may change
the API, the bundle output or the configuration.

### Added

#### Releases: a tag vX.Y.Z publishes the image main built, with its provenance, 2026-10-17

ADR-0085. A release is a tag `vX.Y.Z` on a commit of `main` whose CI passed.
`.github/workflows/release.yml` rebuilds nothing: it gives the image main's CI
already built and attested for that commit the name `X.Y.Z` (and `X.Y`), from its
digest, and checks the digest is unchanged. It signs an SLSA provenance of the
source archive and of the image's SBOM, then publishes the GitHub Release
(draft, files, public) with the CHANGELOG section as its notes. A section longer
than 100 000 characters is replaced by its opening paragraph and the list of
its entry titles; that is the case for 0.1.0. `scripts/release.py` prepares the release pull request (`prepare`),
checks the tag against the version files and the CHANGELOG (`check`) and writes
the notes. `scripts/release_files.sh` finds the image and verifies its
attestations against `ci.yml` on `main` before anything is written. The verify
commands in the notes, SECURITY.md and `docs/releasing.md` pin the signer
workflow and the source ref: with `-R` alone, an attestation signed by any
workflow of the repository would pass. A pull request that changes this
machinery, and a weekly run, get a dry run with a read-only token, and publish
nothing. The workflow's checks catch mistakes, not a person who can push a tag;
a tag ruleset on `v*` does, and `docs/releasing.md` gives the clicks. No release
has been cut yet.

The version has one source, `pipeline.__version__`, `0.0.0` until the first
release. FastAPI's `version` and `frontend/package.json` said `1.0.0`, which
nothing backed; both now follow it (`0.0.0`), and `tests/test_release.py` fails
if the files disagree or the first `##` heading of this file is not
`## [Unreleased]`. `ci.yml` loses the two `type=semver` lines of
`publish-image`, which never applied (that workflow never runs on a tag).
SECURITY.md gains a "Supported versions" section, and
`docs/openssf-best-practices.md` says the four criteria that wait for a release
(`version_unique`, `version_semver`, `version_tags`, `release_notes`) are met
once v0.1.0 is published, not before.

#### The ordinary-word policy recognises naming constructions, 2026-10-12

Step 2 of `docs/gazetteer-ordinary-words.md`. A CONTEXT form ("page",
"route", "joker") or a form naming two ATT&CK objects ("snake", "play") is
resolved when its sentence names the object: an attached ATT&CK ID
("Machete (S0409)"), an explicit alias of another name of the same object,
itself identified ("Elise malware, also known as Page"), a typed apposition
with the nouns the form's rule allows ("Cuba ransomware"; none resolves
"Play ransomware", which does not say actor or software), or a command line
or executable for `ping`, `route` and `expand`. An occurrence inside a URL
or a file name ("landing_page.png") or inside a conflicting sense the rule
names ("Google Play", "Joker's Stash") is excluded, and a sentence that
names the other object of an ambiguous form excludes this one. A list item,
table row or heading is its own unit. The rules per form are in
`pipeline/data/gazetteer_context_rules.json`, versioned beside the
document's decisions; every example of the document's acceptance table
passes, on both matcher paths.

Measured on AnnoCTR train + dev: the whole policy now loses one valid
mention instead of two (`ping.exe` is back; "using ping and curl" names no
construction), and passes the precision and recall gates (+17.6 points of
precision on the affected documents, recall −0.5, CI low −1.7). It still
fails the per-type gate — that one `ping` is 6 points of 16 gold tool
triples — so it stays in shadow mode. On the 366 texts outside the test
split, the constructions resolve 9 occurrences, each one the object it is
mapped to (`docs/eval/gazetteer-policy-2026-10.md`).

#### The gazetteer's ordinary-word policy, in shadow mode, 2026-10-11

Step 1 of `docs/gazetteer-ordinary-words.md` (audit B 8.3.2). Stage 2b now
judges every occurrence of a reviewed form before it claims a span, on both
matcher paths: a CASE form in lowercase is `excluded` ("a barium meal"), a
CONTEXT form is `unresolved` until its naming construction is recognised
(step 2), and so is any of the 23 forms that name two ATT&CK objects ("Snake":
Turla and Uroburos; "Machete": the group and the malware), so that no
identity is chosen by the order of the index. An analyst's promotion is not
judged. `GAZETTEER_POLICY=shadow`, the default, changes no output: the stage
report counts what the policy would withhold (`policy_case_mismatch`,
`policy_missing_context`, `policy_ambiguous_identity`) with the policy
version. `apply` withholds it, for measurement. The decisions are built from
the document (`scripts/build_gazetteer_policy.py`; a test fails when they
drift).

Measured on AnnoCTR train + dev (86 documents, Stage 2b alone, distinct
document/type/ATT&CK-ID triples, `scripts/measure_gazetteer_policy.py`,
`docs/eval/gazetteer-policy-2026-10.md`): the whole policy raises precision
from 0.543 to 0.677 (+13.4 points, 95 % CI [10.1, 17.5]) for 1.0 point of
recall (CI [-2.5, 0]): two `ping` tools written in prose. CASE and the
ambiguous forms alone lose nothing (+2.5 points of precision, recall
unchanged) but stay under the document's +5-point gate. No subset passes
every gate, and AnnoCTR cannot supply adjudicated negatives, so the policy
stays in shadow mode.

### Documentation

#### The gazetteer's ordinary-word forms, reviewed one by one, 2026-10-11

`docs/gazetteer-ordinary-words.md` is the maintainer's review of the
gazetteer forms that are also ordinary words (audit B 8.3.2): "page" is a
MITRE alias of the malware Elise and occurs 699 times in lowercase in
AnnoCTR, "play" names both an actor and a ransomware, "route" and "ping"
are commands as well as words. Each of 151 forms gets a decision: RETAIN
(1), CASE, an initial capital required (105), or CONTEXT, an explicit naming
construction required (45), with corpus counts, excerpts and source checks
(Joker is a real alias of Bread; Microsoft wrote its element names in title
case too). It also specifies the outcomes a matcher must record (resolved,
unresolved, excluded), that nothing changes in production before a shadow
run and acceptance gates on labelled data, and that an unvalidated entity
must be held, not merely scored lower, since a pending row ships. Proposed
decisions; nothing is implemented by this entry. The document quotes AnnoCTR
(CC BY-SA 4.0) and is shared under that licence.

### Changed

#### The report lexicon re-scan on Finalize is removed, 2026-10-17

`_lexicon_rescan` in `api/worker.py`, run by a full Finalize, could never
insert a row (audit of 2026-10-17, Q03): it skipped every value already
accepted, which is every value it scanned. The only exception, a stored value
with surrounding whitespace, would have been a duplicate. It is removed, and the docs
that announced it (`docs/pipeline.md`, `docs/api.md`, `docs/architecture.md`) no
longer do.
`re_run_final_stages(job_id, skip_rescan=...)` becomes
`re_run_final_stages(job_id, quick=...)`: `quick` now only decides whether the
rebuild completes the job (the manual Finalize does, the debounced
auto-finalize does not). Rows already stored with `source = report_lexicon`
and `decision_origin = propagated` stay readable; nothing writes them now.
ADR-0058 gets a dated amendment; ADR-0058 and ADR-0062 keep their historical
mentions of the rescan.

#### The run manifest records the settings, data and packages that shape a bundle, 2026-10-17

The run config (ADR-0059, `api/run_config.py`) did not record several things a
run reads (audit of 2026-10-17, Q04). It now captures, in addition:

- **Settings** (`_CAPTURED_ENV`): `STIX_TLP`, `STIX_AUTHOR_NAME`,
  `GAZETTEER_POLICY`, `BENIGN_IOC_FILTER`, `GLINER_ENABLED`,
  `GLINER_CHUNK_CHARS`, `CYNER_CHUNK_CHARS`, `LLM_MAX_PROMPT_LENGTH`,
  `LLM_DOC_MAX_PROMPT_LENGTH`, `LLM_MAX_RESPONSE_LENGTH`,
  `LLM_MAX_OUTPUT_TOKENS`, `LLM_TIMEOUT`, `STIX_VERIFY_MIN_RELS`,
  `STIX_VERIFY_BATCH_SIZE`, `TTP_VERIFY_MIN`, `VISION_PROVIDER`,
  `VISION_MODEL`, `VISION_ASSUME_CAPABLE`, `VISION_TIMEOUT_S`, and each
  provider's model name (`ANTHROPIC_MODEL`, `GEMINI_MODEL`, `MISTRAL_MODEL`,
  `OLLAMA_MODEL`, `LMSTUDIO_MODEL`, `VLLM_MODEL`). Names only, never a key or
  a base URL.
- **Data files** (`_DATA_FILES`, hashed): `warninglists.json`,
  `attack_revoked.json`, `gazetteer_policy.json`,
  `gazetteer_context_rules.json`, `mitre_embeddings_manifest.json`. A test now
  fails when a file in `pipeline/data/` is not fingerprinted.
- **Packages** (`_PACKAGES`): `yara-python`, `pysigma`, `parsuricata`,
  `lark-parser`, `lark`, `stix2-validator`, `spacy`, `rapidfuzz`.

Not done, left to a later lot: a manifest per finalize or rebuild (a rebuild
reads the current policy and data without recording a new configuration), and
analyst overrides recorded by content instead of by count. ADR-0059 gets a
dated amendment.

#### An IoC's Indicator is valid from the report's date, 2026-10-11

`valid_from` was the time the bundle was built, with no `valid_until`: an IoC
a 2021 report names was valid "from today" and for ever (audit B 8.1.10).
It is now the report's publication date when the document gives one
(ADR-0063's publication-grade anchor, the one `x_source_published` carries),
at midnight UTC, and the build time otherwise; the ledger records which
(`valid_from_basis`). No `valid_until` is set: OpenCTI computes it from its
decay rule for the indicator's type and creates an Indicator whose lifetime
is already over **revoked**, so the IoCs of an old report now arrive revoked
in OpenCTI, as the maintainer chose. A detection rule quoted in a report
keeps the build time: it still detects its family years later.

### Fixed

#### A bundle Stage 5 refuses is no longer served, nor does it complete a job (ADR-0084), 2026-10-17

Stage 5's verdict (`validated`, `unverified`, `invalid`) stopped at the stage
(audit of 2026-10-17, Q01, reproduced on `88bd1d7`). The initial run stored the
bundle without reading it, `re_run_final_stages` ignored it, a full finalize
marked the job `completed` even for an invalid bundle, and
`GET /api/jobs/{id}/bundle` served whatever was stored. Only the file on disk
got an `_invalid` suffix.

Migration v0011 adds `jobs.bundle_validation` and
`jobs.bundle_validation_errors` (a JSON list: the first 20 errors, 500
characters each), written in the same `UPDATE` as the bundle and its ledger.
`NULL`, for a bundle built before v11 or when Stage 5 did not run, means
unknown: served as before, with no backfill.

- An invalid bundle never completes a job. A full finalize leaves the status
  alone, and a job that was `completed` goes back to `for_review`. The initial
  run still stores the job `for_review`: nothing is published at that stage.
- `GET /api/jobs/{id}/bundle` answers 409
  `{"detail": {"validation": "invalid", "errors": [...]}}` for an invalid
  bundle; otherwise the bundle, with the header
  `X-Bundle-Validation: validated | unverified | unknown`.
- `POST /api/jobs/{id}/finalize` answers 409 with the same detail when the
  rebuilt bundle is invalid, and its success response gains `"validation"`.
- `PATCH /api/jobs/{id}` refuses `status="completed"` with 409 while the stored
  bundle is invalid. The ledger route is unchanged.
- The frontend shows a refused bundle as refused, with the first errors,
  instead of "not built yet": in the graph view, on Finalize and on download.
- The CLI already returned failure on an invalid bundle; unchanged.

409 and not 422, which FastAPI keeps for request validation. Finalizing the
same job twice at once is not made safe by this change.

#### The NER cutoff no longer depends on the order of the rows, 2026-10-17

`isotonic_blocks` (ADR-0051) fitted one observation at a time, so a refusal and
an acceptance at the same score could stay in separate blocks, and the
proposed cutoff depended on the order the rows came back from SQL (audit of
2026-10-17, Q02). 100 rejections then 100 acceptances at 0.60 proposed 0.60
with status `ok` and an empirical precision of 0.50 for a 0.90 target; the
reverse order proposed nothing. Observations with the same score are now pooled
into one weighted point before the pool-adjacent-violators fit (de Leeuw's
"secondary" treatment of ties, as scikit-learn does). Ties are common: Stages
2d and 2e store `round(score, 4)`. The policy of `propose()` is unchanged:
statuses, sample guards and the auto-accept ceiling. A stored
`model_thresholds` row keeps its value until the next `--apply`. ADR-0051 gets
a dated amendment.

#### A bundle built at the fix is not stale for it, 2026-10-17

`stale_entries` (ADR-0035) used `git merge-base --is-ancestor`, which is true
for a commit and itself, so a bundle built at a fix's own commit was reported
stale for that fix (audit of 2026-10-17, Q05, reproduced on the real
repository). A new `resolve_commit` (`git rev-parse`) excludes the equal case,
short and long ids alike; when either id cannot be resolved, the ancestor
verdict stands. Known limit, unchanged: `BUNDLE_AFFECTING` has two entries, the
last from 2026-09-29, so "not stale" does not mean that every output change
since is present. ADR-0035 gets a dated amendment.

#### A revoked ATT&CK id is its replacement; a shared name is the Enterprise technique, 2026-10-11

The MITRE index leaves revoked techniques out, so an id a report still
writes was resolved by its name: T1562 *Impair Defenses*, revoked for T1685
in ATT&CK 2026, became the Mobile T1629, the only technique left with that
name, in a report about a Windows intrusion (found in the 50 quotes judged
on 2026-10-11). `scripts/build_indexes.py --only revoked` now writes
`pipeline/data/attack_revoked.json` (149 revoked ids and the active one each
`revoked-by` chain ends on, and the revoked names no active technique
bears), and Stage 3c maps a revoked id or name to its replacement. A name
several domains share ("Phishing": T1566, Mobile T1660, CAPEC-98) resolves
to the Enterprise technique instead of the last one indexed. An explicit id
still decides.

Measured on AnnoCTR dev (`sel-dev-revoked-5d1bbe4` against
`sel-dev-dcd685e`): F1 0.584 against 0.609, −0.024 [−0.089, +0.024], not
significant. The fix changed what it targets (the T1629 false positive gone,
a correct T1685 found); the rest is run-to-run variance: on one report the
selection answer did not parse this time, holding its 41 candidates and
losing 7 correct techniques. Without that report, the same 76 correct
techniques and 44 misses in both runs.

### Fixed

#### A value the report names without accusing it gets no Indicator, 2026-10-11

Every IPv4, domain and URL Stage 2 extracted became an Indicator typed
`malicious-activity`: the victim's `10.0.0.5`, the `www.google.com` malware
checks its connectivity with, the vendor blog a report links to (audit
B 8.1.7). An Indicator is a detection, and a consumer of the bundle would
alert on them. `pipeline/benign.py` now names why a value is not one, and
Stage 4 ships it as an observable without an Indicator, the reason in the
ledger (`no_indicator: benign`):

- a non-routable address (private, loopback, link-local, documentation,
  shared, reserved, multicast), by Python's `ipaddress`;
- the four big public DNS resolvers (Google, Cloudflare, Quad9, OpenDNS);
- a security vendor's, researcher's or sandbox's site, the host of a
  reference link (MISP warninglists security-provider-blogpost,
  automated-malware-analysis), except platforms anyone publishes on (GitHub,
  raw.githubusercontent.com, Medium, Twitter, Dropbox, S3…): a payload there
  keeps its Indicator;
- one of the 10,000 most popular domains (MISP warninglist tranco10k), that
  exact domain only: `evil.duckdns.org` is not popular because `duckdns.org`
  is, and a URL on a popular domain keeps its Indicator.

The three lists (CC0 1.0) are vendored by `scripts/build_warninglists.py`
into `pipeline/data/warninglists.json` (174 KB, commit `af01b1d`). MISP's
public-dns-v4 is not: its 62,780 open resolvers may include a compromised C2.
On AnnoCTR's 400 texts, about 1,220 of 8,300 network IoCs would lose their
Indicator: 1,021 reference links, 166 popular domains, 12 reference sites,
19 non-routable addresses. A claim Stage 4 routes through such a value's
Indicator is dropped with the reason `benign_observable`; the IoC coverage
check counts them apart (`benign`) instead of as missing. The Graph page
says why an observable has no Indicator. `BENIGN_IOC_FILTER=false` turns it
off.
#### A quote next to a no-break space is found; the evaluator reads the refanged text, 2026-10-11

- **`evidence_span.locate` missed quotes across a no-break space** that sits
  next to another blank, as HTML pages leave them: `_CHAR_MAP` turned
  U+00A0 into a space one character at a time, so "instead of\xa0 plain"
  became "instead of  plain" and the quote "instead of plain" matched
  nothing. The worker locates each technique's quote with it and grades a
  technique whose quote it cannot find one step down, as if the quote were
  not in the report. On the AnnoCTR test run, 2 of 312 quotes; 0 now. Every
  space `_CHAR_MAP` reads as one now joins the run of blanks around it.
- **The evaluator searched AnnoCTR's raw text for quotes the pipeline took
  from the refanged one** (`www.destroy2013.com` for `www.destroy2013.]com`),
  and reported 98% of quotes found where all were. It now also searches the
  refanged text, through `stage2_extraction.refang_with_offsets`, which maps
  each refanged character back to the source, so the annotated-passage
  measure keeps working. Quotes found: 153/153 on dev, 312/312 on test.

### Documentation

#### AnnoCTR test, once: technique F1 0.690; 50 quotes judged, 2026-10-11

`docs/eval/baseline-2026-10.md` gains three results:

- **Test, run once** on the select configuration frozen at `dcd685e`: 34
  reports, F1 0.690 (P 0.679, R 0.702), exact id 0.415. The LLM server went
  down during the run; three reports that got no answer or lost calls were
  run again at the same commit, and the score as it came (32 reports, F1
  0.698) is kept beside the complete one.
- **The dev re-run** with the ADR-0074 prompts: F1 0.609 against 0.607,
  +0.002 [−0.037, +0.034]. The configuration did not move.
- **50 quotes judged** by the maintainer: 70% show the technique used, 85%
  for techniques in the gold; 6 of 16 "false positives" are supported by
  the text, so AnnoCTR's gold understates precision. The judging found a
  domain error: a revoked id (T1562) resolved by name to the Mobile
  technique T1629.

### Documentation

#### A file named without a hash keeps its path in `name` (ADR-0083), 2026-10-11

The October audit (B 8.1.12) asked to split `C:\Users\Public\it's.exe`
into a File named `it's.exe` and a Directory, as STIX 2.1 describes. OpenCTI,
the target, identifies a hashless file by its name alone and drops the
directory from its pattern-to-observable conversion: the split would merge
the `svchost.exe` an attacker dropped in `C:\Users\Public` with the
legitimate one in System32. CTIParsor keeps the path in `name`, as it already
did, and ADR-0083 records it as a choice. Checked against OpenCTI's
`identifier.js`: the id shipped for a hashless file equals OpenCTI's
standard id. `tests/test_file_identity.py` holds it. A strict STIX export
profile, when there is one, would split.

### Fixed

#### An actor is no longer renamed after a malware, nor software after an actor, 2026-10-11

A name the gazetteer knows for one MITRE object resolved to it whatever type
was asked (ADR-0021 only used the type to break ties). When the LLM listed
a ransomware brand as a threat actor, "LockBit Black" became a threat-actor
named "LockBit 3.0", the malware S1202; OpenCTI derives the id from the type
and the name, so it created that threat-actor beside the malware (audit
B 8.1.8). A name now resolves only within its family: actors
(threat-actor, intrusion-set) or software (malware and tool, which MITRE
files together and the extractors mix up, so "Mimikatz" asked for as malware
still resolves). Across families the name stays as written, and the ledger
records the emitted object with `reason: "type_conflict"` and what MITRE
calls it (`mitre_ids`, `mitre_types`); the Graph page's panel shows it beside
the review row. "snake" (Turla and Uroburos) is not a conflict: the type
picks one. The other half of the finding, more aliases (MISP galaxies,
Malpedia, ETDA) with their source, is not done here: it needs a choice of
sources and their licences.

#### The CLI brings its database to this code's schema, as the API does, 2026-10-11

`main.py` never ran the migrations (ADR-0077); only the API, the workers and
`bootstrap` did (audit 8.1.11). On a database with no tables yet, a CLI run
said the store was unreachable for the relationship policy (`UndefinedTable`)
and Stage 2f failed on `relation "cve_cache" does not exist`; nothing was
created. The CLI now migrates the database before its first report:
reproduced on an empty schema of the test server, it now creates the 18
tables, reads the policy ("aucune enregistrée") and runs Stage 2f. A
database this code cannot migrate (newer than the code, an edited migration,
a cluster that lost its data) stops the CLI as it stops the API. With no
`DATABASE_URL`, or no server behind it, the CLI says so once, before the
report, and runs without policy, analyst lists or CVE cache, as before.
`tests/test_cli_store.py`.

### Security

#### Stage 2 on RE2: five more patterns, the rest pinned and timed (ADR-0049), 2026-10-11

RE2 refuses lookaround, and `compile_pattern` then falls back to `re`,
without RE2's linear-time guarantee. The October audit (B 8.2.5) found that
was the case for Stage 2's key patterns. Five now run on RE2, the IPv4
addresses, the hash blocks of IoC tables, the half-bracket defang
(`evil.]com`) and the SHA-1 and MD5 column labels, with the guards their
lookarounds held now checked in code. Each rewrite is exact: on AnnoCTR's
400 texts, entities, file paths, hashes and refanged text are the same,
with google-re2 and without it. The only change is on three synthetic
inputs with Arabic-Indic digits, where `re`'s Unicode `\d` used to extract
an "address" such as `1.2.3.4١`.

The domain, bare-filename and Unix-path patterns, and three sentence
splitters (Stages 2c and 4, the retrieval passages), stay on `re`: a filter
after one RE2 pass would miss some of their matches. `compile_pattern` now
records each pattern RE2 refuses, and `tests/test_re2_fallbacks.py` fails on
one it does not list; it runs each listed pattern under `re` on 14
adversarial inputs of 50,000 characters, within 1 s.

The first IPv4 rewrite restarted its search after each refused match, and
Stage 2 took 2.7 s instead of 0.5 s on the performance test's 5,000-IP
appendix: google-re2 encodes the whole text at every call. Every rewrite is
one pass.

#### Scorecard's eight python-multipart findings: floors read as versions, 2026-10-11

After the requirement files moved to `requirements/` (PR #138), Scorecard's
Vulnerabilities check dropped from 10 to 2: eight advisories on
python-multipart (PYSEC-2026-1851, -1852, -3036 to -3041: upload-parsing
denial of service, parameter smuggling, a file write in a non-default
configuration). The image and CI were never exposed: their locks pin
python-multipart 0.0.32, past every fix (0.0.31 the last). OSV-Scanner had
read `python-multipart>=0.0.9` in `requirements/requirements.txt` as
version 0.0.9.

- The floors are raised to the last fix: python-multipart `>=0.0.31`, and
  two Scorecard did not report but would on the same reading,
  sentence-transformers `>=5.6.0` (2 advisories) and transformers
  `>=5.10.0` (50 advisories on 4.35–5.9). The five locks do not change.
- `scripts/check_requirement_floors.py` asks OSV about every floor in the
  four lists and exits 1 when one is a vulnerable version: 3 of 46 before,
  0 after. It is step 7 of the quarterly routine (docs/dependencies.md).

### Changed

#### The Python requirement files: four lists instead of six, in `requirements/`, 2026-10-10

Eleven `requirements*` files sat at the root, and `requirements-ci.txt` was
a hand-kept copy of about twenty names from `requirements.txt`: a new
dependency had to be added twice, or its tests skipped in CI. spaCy was
declared in two files.

- `requirements.txt` is the light runtime, the pipeline without its ML
  models and the API; `requirements-full.txt` starts with it and adds what
  only the image needs. `requirements-api.txt`, `-optional.txt` and
  `-ci.txt` are gone: the CI lock resolves `requirements.txt` +
  `requirements-dev.txt` under the image lock.
- Every requirement file, and the `osv-scanner.toml` covering them, is in
  `requirements/`, with a README saying which file is for what.
- **Nothing installed changes.** The five locks, regenerated, have the same
  pins, markers and sha256 as before (158 / 1 / 127 / 28 / 1 packages),
  and are byte-identical after the move.
- The names keep "requirements": OSV-Scanner reads a `.txt` only when its
  name contains it, and only the `osv-scanner.toml` next to a file, so
  Scorecard's scan keeps seeing them. ADR-0080 is amended.

To add a Python dependency: `requirements/requirements.txt` when the fast
tests need it, `requirements/requirements-full.txt` when only the image does,
then `make lock` (CONTRIBUTING.md).

### Security

#### The UI on Tailwind CSS 4: the last accepted npm vulnerability goes, 2026-10-10

Tailwind CSS 3 brought braces (GHSA-vfj7-8cjw-p6xm, no fixed release),
accepted in SECURITY.md as a build-time dependency, and postcss-selector-parser
6.x, forced to 7.1.6 by an npm override. The UI now builds with Tailwind
CSS 4.3.3 through `@tailwindcss/vite`: PostCSS, autoprefixer, braces and
postcss-selector-parser leave the lock (61 packages out, 12 in), the
override and the OSV-Scanner exception go, and `npm audit` reports nothing,
dev dependencies included.

The UI looks the same, checked element by element. The UI uses Tailwind for
its reset (preflight) and one utility (`animate-spin`); the rest is its own
CSS. With the CSS that `main` builds (v3) and v4's swapped in the same page,
every element's computed style (colours, borders, fonts, cursor, spacing,
sizes) was compared on the dashboard, the new-report dialog, Policy,
Settings, Review, Graph and Coverage, on a real report, in the light and dark
themes: about 8,000 elements per theme, no difference. Four of v4's reset
changes are set back to v3's values in `index.css`: a border with no colour
of its own is gray-200 again (not the text colour), placeholders gray-400,
an `<option>` keeps the browser's padding, and a disabled control the
default cursor.

`tailwind.config.js` and `postcss.config.js` are gone: the fonts are in
`index.css`'s `@theme`, and the sources Tailwind scans are named there, so
it does not read `public/` (the vendored graph viewer). Tailwind 4 needs
Chrome or Edge 111, Safari 16.4 or Firefox 128, or later (docs/web-ui.md).

### Added

#### The API tested against its own OpenAPI schema (Schemathesis), 2026-10-10

`tests/test_api_schema.py` sends every API operation requests generated
from the schema FastAPI publishes: valid ones, and ones that break a
declared constraint. Each response must not be a server error and must
match its declared schema. Generation is derandomized, so the test is as
deterministic as the rest of the fast tests (ADR-0071); it runs in about
30 s, against a disposable database holding one reviewed job. URL
capture, corpus sync and rebuild, and the progress stream are left out:
they reach the network, the corpus clones, or never end. TESTING.md
describes it.

Its first run found one defect: `GET /api/jobs/{job_id}/relationships/valid-types`
was published without its `job_id` parameter, an OpenAPI schema that
generated clients reject. The route now declares it; it answers as before.

`schemathesis` 4.30.1 joins `requirements-dev.txt`; the CI lock gains it
and 11 dependencies, every other pin unchanged.

### Security

#### The TLS proxy: forward secrecy, and no more MD5 password entries, 2026-10-10

Found while answering the OpenSSF Best Practices criteria, and checked
against the compose proxy image (`nginx-unprivileged:1.31-alpine`, pinned)
with `curl` and `openssl s_client`:

- **TLS 1.2 accepted suites without forward secrecy.** With no
  `ssl_ciphers`, nginx's default also took RSA key exchange
  (`AES256-GCM-SHA384`) and CBC with SHA-1 (`AES128-SHA`). The proxy now
  offers ECDHE with AEAD ciphers only, Mozilla's "intermediate" list
  without DHE. Both suites above are refused; ECDHE and TLS 1.3 still
  connect.
- **The docs wrote proxy passwords as APR1**, an MD5-based scheme
  (`openssl passwd -apr1`). They now give bcrypt, cost 12
  (`htpasswd -nBC 12`), or SHA-512-crypt (`openssl passwd -6`) where
  `htpasswd` is missing. The image reads both (`$2b$`/`$2y$` and `$6$`
  entries: 200 with the password, 401 without). An existing `$apr1$`
  entry keeps working until it is replaced.

### Documentation

#### OpenSSF Best Practices: the answers, and what they asked for, 2026-10-10

`docs/openssf-best-practices.md` answers the 67 "passing" criteria with
their evidence, ready to enter on bestpractices.dev. Four MUST criteria wait
for the first versioned release. Three gaps were closed in the repository:

- the README says where bugs and feature requests go (*Feedback and
  contributing*);
- CONTRIBUTING.md says how a change gets in: issue, branch, pull request,
  the required checks, review, with tests in the same change;
- SECURITY.md says what happens to a private report: a first answer within
  14 days, then a fix, the advisory and a CHANGELOG line.

#### ADR-0078's repository settings, as applied, 2026-10-10

The maintainer applied the settings ADR-0078 left to them (items 8–11);
the ADR's last amendment records them as read back through the API. `main`
now takes changes only through a pull request whose 13 required checks
pass, with a CodeQL gate on the alerts a pull request adds (medium severity
or higher). Private vulnerability reporting, secret scanning with push
protection, and required SHA-pinned actions are on. Three choices differ
from the ADR's Decision, each with its reason: Dependabot security updates
stay on, Grype does not gate the merge, and branches need not be up to
date. SECURITY.md describes the protected branch.

#### Every file names its copyright and licence (REUSE), 2026-10-10

The repository carries files from other projects, and nothing listed them
in one place. It now follows the [REUSE](https://reuse.software)
specification 3.3, and `reuse lint` runs in CI's fast tests:

- `REUSE.toml` gives each file its copyright and licence: Apache-2.0 for
  CTIParsor's own files, an override for each set of copied files.
- `LICENSES/` holds every licence text in use, MITRE's ATT&CK and CAPEC
  licences included (split from `mitre/cti`'s `LICENSE.txt`).
- `THIRD_PARTY_NOTICES.md` lists the copied files with their source,
  copyright, licence and whether they were modified. Each file listed as
  unmodified was compared byte for byte with its source.

What the inventory found:
- **The 27 STIX icons are EclecticIQ's, under CC BY-SA 4.0**, not "official
  OASIS" icons as `docs/development.md` said. So are the 52 graph icons
  that OASIS's viewer ships (by Bret Jordan). CC BY-SA asks for
  attribution, and the image ships the UI: `.dockerignore`, which kept every
  `*.md` out of the image, now lets `THIRD_PARTY_NOTICES.md` in.
- **MITRE's licences ask every copy to reproduce MITRE's copyright
  designation**, for the ATT&CK and CAPEC data in `pipeline/data/` and
  `frontend/public/mitre_index.json`. The notices reproduce it.

`reuse` 6.2.0 joins `requirements-dev.txt`; the CI lock gains it and four
dependencies, every other pin unchanged.

### Fixed

#### ruff's bugbear rules (B), and the GLiNER batch they caught, 2026-10-10

`ruff check` now runs flake8-bugbear on the whole repository, tests and
scripts included. Of its 57 findings, 52 were fixed and none carries a
`noqa`; the other 5 were FastAPI declarations (last paragraph).

- **Stage 2e could drop the last chunks of a batch.** GLiNER's batch answer
  was zipped against its chunks. An answer with fewer lists than chunks,
  such as the flat list a one-chunk call returns, then stood for the first
  chunk, and the other chunks' entities were lost without a log line. Such
  an answer now takes the existing path that asks the model one chunk at a
  time (`test_a_batch_answer_short_of_its_chunks_is_retried_per_chunk`).
- **Every `zip()` over parallel lists says `strict=True`** (B905): Stage 3's
  chunks and their entities, Stage 4's dates and their ledger decisions,
  database rows, the retrieval corpus, the AnnoCTR BIO tags. A length
  mismatch now raises instead of truncating. Two test assertions,
  `all(... zip(bbox, expected))`, passed on an empty bbox; they no longer do.
- **`raise` inside `except` names its cause** (B904): `from exc`, as
  `api/routes/ingest.py` already did, and `from None` where the rejection
  is not caused by the exception being handled.
- Duplicate entries in `DOMAIN_STOPWORDS` (B033), loop variables nothing
  read (B007), and a closure over loop variables in `promotion.py` (B023,
  harmless there, now a `functools.partial`).

FastAPI's `Depends`, `File`, `Form` and `Query` defaults are declared
immutable calls (`pyproject.toml`): they declare parameters (B008).

#### Stage 2 network indicators: IPv6, sentence-final IPv4, half-bracket defangs, 2026-10-10

Three recall defects in `pipeline/stage2_extraction.py`, each there since the
first commit or close to it. Measured on AnnoCTR's 400 texts, old against
new: +22 IPv4, 13 truncated lab52 domains now whole (`1.duckdns` →
`1.duckdns.org`), 11 defanged URLs now refanged, no URL or email lost.

- **No IPv6 address was ever extracted.** The code called
  `iocextract.extract_ipv6s(text, refang=True)`; the function takes no
  `refang`, so it raised `TypeError` on every report, and the
  `extract_urls` / `extract_emails` calls after it in the same `try` never
  ran either. The IPv6 call is fixed and its candidates are validated:
  iocextract's pattern is loose (in AnnoCTR: 101 candidates, all clock
  times, MAC addresses or a byte fingerprint). The URL and email calls are
  removed, not revived: turned on, they added 244 URLs (mostly copies of
  regex hits with Markdown escapes or a trailing slash) and 39 "emails"
  such as `i7-6700hqcpu@2.60ghz`, each of which hid its host from the
  domain list — `avsvmcloud.com`, SUNBURST's C2, among them.
- **An IPv4 address that ends a sentence was dropped.** The trailing guard
  meant to refuse a fifth octet (`192.168.1.1.5`) refused any following
  `.`. It now refuses `.` followed by a digit only; 5 C2 addresses in
  AnnoCTR. The same change lets through two version strings that end a
  sentence (`1.6.0.27.`), the kind of match the pattern already made
  mid-sentence.
- **One-bracket defangs were not refanged.** `www.destroy2013.]com`,
  `107.150.112.]250`, `evil[.com` — 9 AnnoCTR texts, all lab52 — gave no
  indicator or a truncated one. `refang` now restores a dot written with
  one bracket between two alphanumerics, so `[.NET]` stays as it is.

### Security

#### ruff's bandit rules (S) on shipped code, 2026-10-10

ADR-0075's "Not done" item. Every finding in shipped code was fixed or now
says why on a `noqa: Sxxx — reason` line. Four were worth fixing:

- **The worker's liveness file is never followed through a symlink.**
  `touch_alive` opens it with `O_NOFOLLOW`: on a host install `/tmp` is
  shared, and another user's link at that name made the worker create its
  target.
- **`git merge-base` receives only commit ids.** A stored bundle revision
  shaped like an option (`--output=…`) used to reach git.
- **The vision providers' URLs must be http(s).** A `file:` base URL in the
  settings could read local files.
- **Two `assert`s in the orchestrator became explicit errors**: `python -O`
  drops asserts.

Not enforced:
- S608 (SQL built from a string) is left to CodeQL's `py/sql-injection`.
  All 31 sites interpolated `?` lists or identifiers fixed in the code.
- Tests, scripts and fuzz targets are exempt.
- `BLE001` stays off. Of its 126 sites, 18 return a fallback without
  logging: those are the ones to review (ADR-0075).

### Security

#### The UI's build tools: source-map-js and postcss-selector-parser, 2026-10-10

Dependabot raised two alerts, and Scorecard's scanner found the same two in
`frontend/package-lock.json`. Both are in the UI's build tools only (`"dev":
true`): neither is in the built UI nor in the image.

| Package | Advisory | Fix |
|---|---|---|
| source-map-js 1.2.1 | GHSA-68fv-2mgg-jv7q, high: event-loop DoS through section offsets | 1.2.2, within the existing ranges (lock only) |
| postcss-selector-parser 6.1.4 | GHSA-rj75-hqrm-r3gf, moderate: quadratic selector parsing | an npm override to `^7.1.6` (`frontend/package.json`) |

Tailwind CSS 3 asks for postcss-selector-parser 6.x, and its last 3.x
release still does. The override is checked:

- `npm run build` gives a `dist/` byte-identical to the build without it;
- `npm run check` passes (lint, typecheck, 141 tests).

`docs/dependencies.md` says why the override exists and when it goes: with
Tailwind CSS 4, which also removes braces, the one accepted npm advisory.
`npm audit` now reports only braces, and the Scorecard-equivalent scan
reports nothing.

### Documentation

#### The containers: their code, their ports, their traffic, 2026-10-10

The README's "How it works" gains a **Containers** view: a diagram of the
containers, their networks and ports, a table of what each one runs, and a
link to the details. `docs/architecture.md` §2 gains three views, each checked against
`compose.yaml`, the `Dockerfile` and the code:

- **What each container runs and the code in it.** One application image
  holds all of the project's code. `app`, `worker` and `bootstrap` start
  it with different commands. The other services are upstream images,
  configured by files from `docker/`. It also says why only one image is
  published: the API and the workers must run the same version, because
  both migrate the schema and share the job rows (ADR-0044, ADR-0077).
- **Who talks to whom:** network, protocol and port for each flow.
- **What leaves the host:** destination, from which container, when, and
  the setting that turns it off.

Corrected on the way:

- PostgreSQL 18, not 17, and the `pg-data-18` volume.
- The diagram now shows bootstrap's downloads, the LLM on the host, and
  the calls `app` makes when it finalizes a report.

It also records a defect found while tracing the traffic. The image has no
STIX schemas, so every Stage 5 run downloads them from GitHub, fails to
install them on the read-only filesystem, and leaves the bundle
`unverified`.

#### The fuzzers are required checks; what the docs left out, 2026-10-10

- **The four fuzz jobs are required checks on `main`.** This is recorded in
  ADR-0078's amendment, ADR-0081 and `fuzz.yml`. A fuzzer failure is fixed
  before the merge, and its input joins `fuzz/corpus/<target>/`, where the
  fast tests replay it.
- **TESTING.md.**
  - It did not mention fuzzing (ADR-0081). It now has a section on it, and
    `test_fuzz_targets.py` in the coverage map.
  - Its CI list named four jobs and said the image waits for three. It now
    lists all seven jobs and the three other workflows. The image waits for
    four: the dependency audit too.
- **CONTRIBUTING.md.** For a test skipped on a missing import, it said to
  install the dependency in the CI job. Since ADR-0080 it goes in
  `requirements-ci.txt`, then `make lock`. A `pip install` in a workflow
  would bypass the hashes.
- **`/api/health`** is in `docs/api.md`: 200 when the job store answers, 503
  when it does not.
- **Two variables documented nowhere.** Both are now in `.env.example` and
  `docs/configuration.md`:
  - `DB_MIGRATION_LOCK_TIMEOUT_S`: how long a starting process waits for
    another one's migration, 600 s by default;
  - `WORKER_ALIVE_FILE`.
- **Fixed: `WORKER_ALIVE_FILE` and the worker's healthcheck.** The compose
  healthcheck read a fixed path, so setting the variable made the worker
  unhealthy. It now reads the same variable as the worker.
- **`docs/dependencies.md`** lists react-pdf (pdf.js, the Source tab's PDF
  viewer), atheris and httpx.

#### What Scorecard still scores low, and the quarterly routine's locks, 2026-10-10

- **ADR-0078, amendment.** The Scorecard workflow and ADR-0078 named
  Fuzzing among the checks a one-maintainer project scores low by
  construction. Fuzzing scores 10 since ADR-0081. Only Code-Review and
  Contributors are low by construction. The amendment lists every check
  below 10, why, and what raises it.
- **Signed-Releases.** It is not scored while there is no GitHub Release.
  A Release without a provenance file or a signature among its assets
  would score 0. The amendment says so, and which files count.
- **Settings checked through the API.** Private vulnerability reporting is
  off, so SECURITY.md's reporting link does not work for an outside
  reporter. The `main` ruleset exists but is disabled.
- **The quarterly routine (`docs/dependencies.md`).**
  - It reviewed and committed only the image's lock. `make update-deps`
    rewrites all five, and CI's lock follows the image's versions. It now
    commits every lock, and so does the hint `make update-deps` prints.
  - New step: review the accepted vulnerabilities, and move their
    `osv-scanner.toml` review dates.

### Security

#### Scorecard: the accepted vulnerabilities and the last unhashed pip install, 2026-10-04

OpenSSF Scorecard still found two vulnerabilities and one pip install without
hashes.

- **Two vulnerabilities SECURITY.md already settles.** Scorecard scans the
  manifests with OSV-Scanner, which reads neither SECURITY.md nor
  `.grype.yaml`. It reported:
  - braces 3.0.3 in `frontend/package-lock.json`, accepted: build-time only;
  - diskcache, although no lock lists it any more. OSV-Scanner resolves
    `requirements-ci.txt`, a list of ranges, through pySigma's declared
    dependencies.

  Each is now listed, with its reason, in the `osv-scanner.toml` next to its
  manifest (the root, and `frontend/`), until 2027-01-04. After that date
  Scorecard reports it again, for a new review. pip-audit, npm audit and
  Dependabot do not read these files.
- **uv, installed by hash (ADR-0080, item 7).** `make lock` installed uv
  with a bare `pip install uv`, the one pip install left without a hash. It
  now installs uv from its own hashed lock, `requirements-uv.lock.txt`
  (uv 0.12.23). `make lock` regenerates that lock, and the dependency-audit
  job audits it with the other locks.

#### The image scan skips the CVEs SECURITY.md accepts, per version, 2026-10-04

Three CPython 3.14.8 CVEs have no fix in a 3.14 release and cannot be
reached from CTIParsor: poplib, the `TemporaryDirectory` race, and the
`tarfile` link fallback. SECURITY.md already accepted them.

Until now they could only be dismissed by hand, alert by alert. They are now
listed in `.grype.yaml`, which the image scan reads, each with its reason
and tied to python 3.14.8 exactly. The scan stops reporting them, and the
three alerts close at the next scan of `main`. When the image moves to
another Python, the rules stop matching and Grype reports them again.

#### diskcache is no longer shipped, 2026-10-04

diskcache 5.6.3 has an unfixed unsafe-pickle CVE (PYSEC-2026-2447).
Dependabot raised it twice, once per lock. Until now it was accepted in
SECURITY.md. It is now **removed** from the image and from CI:

- **Why it can go.** pySigma declares it, but only its ATT&CK and D3FEND
  data cache imports it, which CTIParsor never loads.
- **How.** The locks omit it, and every install of them is `--no-deps`.
- **Guard.** A test checks that the Sigma gate passes a rule with ATT&CK
  tags without loading it.

pip-audit no longer needs an `--ignore-vuln`.

### Fixed

#### The test run's warnings on Python 3.14, 2026-10-04

- **16 `ResourceWarning: unclosed database`.** Since Python 3.13, an sqlite3
  connection that is garbage-collected while open reports it.
  `tracemalloc` traced them to two test helpers that never closed their
  stand-in databases: 10 from `tests/test_technique_idf.py::_db`, 6 from
  `tests/test_db_transaction.py::_conn`. Both now close what they opened
  after every test, failed or not. The warnings showed up in unrelated
  tests, wherever the garbage collector ran.
- **slowapi's `asyncio.iscoroutinefunction` deprecation.** slowapi is the
  API's rate limiter; this call is removed in Python 3.16, and the latest
  release, 0.1.10, still makes it. The tests filter that one warning, scoped
  to slowapi's module. ADR-0079 records that the image cannot move to 3.16
  until slowapi is fixed or replaced.

### Security

#### Fuzzing the code that reads attacker input (ADR-0081), 2026-10-04

Four Atheris fuzzers (`fuzz/`) target the code that reads what the report's
author controls:

- report text (refang, extraction);
- dates;
- the gates quoted rules pass before OpenCTI (Sigma, Suricata, Snort, YARA
  through libyara, STIX literals);
- the enclosure that keeps report text from closing its block in an LLM
  prompt.

Each target checks its own invariant. A crash, an input slower than 10 s or
a memory blow-up also fails the run.

They run 60 s each on every pull request and 10 minutes weekly (the
`Fuzzing` workflow), and the failing input is uploaded. A seed test keeps
them alive in the ordinary suite. A first two-minute run per target tried
1.1 million inputs on the parsers and 23.5 million on the enclosure, and
found nothing.

#### Every pip install checks hashes (ADR-0080), 2026-10-04

The image, CI and the audit now install with `pip install --require-hashes`,
from four locks `make lock` writes:

- the image's own, from PyPI;
- torch's CPU build, from the PyTorch index;
- CI's fast-test set, at the image's versions;
- pip-audit.

**The first hashed build caught the image taking markupsafe 3.0.3 from the
PyTorch index**, whose copy is not PyPI's file. The two indexes are no longer
mixed at install time. torch is installed alone from its index first; then
everything else comes from PyPI only, with the hashes PyPI publishes (the
resolver had recorded the PyTorch copies' hashes for markupsafe, jinja2 and
colorama).

Other changes:

- CI's three installs become one.
- The audit also covers CI's tools and the scanner itself.
- The image no longer upgrades pip without a hash: Python 3.14.8's bundled
  pip, 26.2.1, is current.

#### What OpenSSF Scorecard found, 2026-10-04

The first Scorecard run scored 6.9/10. This entry covers its two checks that
code can fix.

- **Vulnerabilities: 5.** Three were not in the shipped versions:
  - The lock already installs pytest 9.1.1, python-dotenv 1.2.3 and
    sentencepiece 0.2.2. But `requirements.txt` still allowed the
    vulnerable releases (`>=8.0.0`, `>=1.0.0`, `>=0.1.99`), and Scorecard
    reads the ranges. The minimums are now the fixed releases (9.0.3, 1.2.2,
    0.2.1); the lock does not change.
  - The other two have no fix. diskcache was already accepted. braces is a
    build-time-only dependency of the UI, now accepted in SECURITY.md.
- **CPython 3.14.8: 3 CVEs reported by Grype, all unreachable and accepted.**
  - Two are fixed only in 3.15.
  - The third, the `tarfile` link fallback, is fixed in 3.12.15 but not yet
    in a 3.14 release. The corpus sync never extracts a link.
- **Download-then-run: 3.** These were false positives: smoke-test and
  offline-check scripts piped `curl` of the local API's JSON into
  `python3 -c`. They now fetch first, then parse.

#### Python 3.14 (ADR-0079), 2026-10-04

The image, CI and the lock move from Python 3.12.15 to 3.14.8.

- **CVEs.** 3.14.8 clears five of the seven Python vulnerabilities Grype
  found; the other two are fixed only in 3.15 and not reachable from
  CTIParsor.
- **Dependencies.** onnxruntime goes from 1.20.1 to 1.30.0: the old version
  could not install on 3.14. Nothing else in the lock changes version.
- **yara-python.** It has no 3.14 wheel, so the image compiles it, with
  OpenSSL. Without OpenSSL the build drops the `hash` module and PE
  signatures without an error, and the YARA gate would then refuse rules
  OpenCTI accepts. A test now checks those modules are present.
- **Smoke test.** `scripts/docker_smoke.sh` runs in its own compose project
  (`ctiparsor-smoke`). On the default project, `ctiparsor`, its `--clean`
  deleted a local install's database and state volumes.

#### The image scan's first findings, 2026-10-04

Grype's first run (ADR-0078) reported 14 vulnerabilities with a fix in the
image:

- **pip (6, the image's highest at high).** They were in the base image's
  own pip, under `/usr/local`, which the application never uses: it runs
  from `/opt/venv`, whose pip the builder upgrades. That pip is now
  uninstalled from the runtime image.
- **libpcre2 (1, high).** The runtime stage now runs `apt-get upgrade`
  before installing its packages. A digest-pinned base image otherwise
  receives Debian's security updates only when Dependabot next bumps it.
- **Python 3.12.15 (7).** These are fixed in Python 3.13 and later only:
  base64 decoding, imaplib, poplib, `tempfile.TemporaryDirectory`,
  `http.cookies`, `pkgutil` (the last one disputed). None of these is
  reachable from CTIParsor; the only use is `TemporaryDirectory` in a
  measurement script. They stay open until the image moves to a newer
  Python.

Dependabot's one alert, diskcache, has no fix and is accepted in
SECURITY.md.

#### Pinned workflows, an image scan, and what the settings must add (ADR-0078), 2026-10-04

- **Pinning.** Every GitHub Action is pinned to a full commit SHA, with its
  version as a comment so Dependabot keeps both current. Anchore had stopped
  moving its major tags in March: `anchore/sbom-action@v0` was running a
  release six months old.
- **Tokens.** Workflow tokens are read-only unless a job asks for more, and
  no checkout leaves its token in `.git/config`.
- **New checks:**
  - CodeQL also analyses the workflows (`actions`);
  - Grype scans the image's operating-system packages, which no other check
    saw, and sends the CVEs that have a fix to Code scanning;
  - dependency review fails a PR that adds a dependency with a high-severity
    vulnerability;
  - CI runs every Monday, so vulnerabilities published since the last push
    are found without one.
- **Scorecard.** OpenSSF Scorecard rates the repository weekly; the badge is
  in the README.
- **Reporting.** SECURITY.md links the private advisory form.
- **Settings, applied by the maintainer:**
  - Dependabot alerts (security updates stay off for the uv lock);
  - private vulnerability reporting;
  - a `main` ruleset: pull requests only, required checks, no force-push,
    CodeQL high-severity gate;
  - after this merge, required SHA pinning.

#### CodeQL's first findings triaged, 2026-10-04

The 25 alerts CodeQL raised when it was switched on (ADR-0075):

- **Job ids in file names and logs (11).** `DELETE /api/jobs/{id}` and
  finalize built file paths and log lines from the id in the URL. Both now
  use the id the database holds, a uuid the server generated. A request that
  names no job never reached the files, but a `%0A` in the URL could forge a
  log line.
- **Corpus sync errors (1).** The Settings page received the raw exception
  text: server paths and OS messages. It now says what failed ("download
  failed", "not a tar archive", "git is not installed"…). The text goes to the
  server log, on one line.
- **`stix-viz` page (1).** It fetched and drew whatever URL `?bundle_url=`
  named. It now only takes this app's `/api/jobs/<id>/bundle`, with the id
  URI-encoded so it cannot step out of its path segment (`../`).
- **Tests (9).** CodeQL no longer scans `tests/`: it is not shipped, and its
  `"evil.com" in urls` asserts and `(a+)+$` are the attacker input the tests
  are for.
- **Polynomial regexes (3): ten slow regexes, rewritten.** CodeQL pinned
  them on three call sites that use other, linear regexes: it cannot tell
  which regex `compile_pattern` returns. The ten regexes it named are linear
  under re2, which the image and CI install. Under stdlib `re` (a source
  install or a dev venv without google-re2), they were quadratic, and the
  YARA rule header was cubic: 110 s on one line of 8,000 tabs. The affected
  inputs:
  - the refang pass over report text (`\s{1,16}` before a spaced `[.]`);
  - quarter and half dates;
  - YARA rule headers, meta and string lines;
  - the edge-stripping of advisory tokens and the literals of an indicator
    pattern (now short loops).

  Results are unchanged on 30,000+ random inputs per regex, every rewritten
  pattern still compiles with re2, and `tests/test_linear_regexes.py` holds
  each one under one second on CodeQL's input with stdlib `re`.
  `requirements-api.txt` still said `pip install re2`, the abandoned package
  that does not build on Python 3.12+; it now points to google-re2.


#### A verifiable supply chain (ADR-0075), 2026-10-03

The Dockerfile's base images are pinned by digest, like compose's. A blocking
`dependency-audit` CI job runs `pip-audit` on `requirements.lock.txt` (the
versions the image installs; `make audit` used to scan the ranges and never
failed) and `npm audit` on the UI's production packages; the image is
published only after it passes. One known vulnerability is accepted, with
its reason, in SECURITY.md: diskcache 5.6.3 (PYSEC-2026-2447), which
CTIParsor never loads. CodeQL scans the Python and the TypeScript. Each
image pushed to GHCR gets a CycloneDX SBOM and two signed attestations
(build provenance, SBOM): `gh attestation verify oci://ghcr.io/stixaly/ctiparsor@<digest>
-R Stixaly/CTIParsor`. Dependabot proposes updates for actions, images and
npm; Python stays on `make update-deps`.


#### Report text reaches the model as delimited data, nothing is redacted (ADR-0074), 2026-10-03

A report containing `<|im_end|>` or `<|im_start|>system` produced the real
chat-template tokens on the vLLM server (checked on Qwen3.8; `<think>` and
`<tool_call>` too): the sanitiser never touched them. Meanwhile it deleted
intelligence — `[REDACTED]` from "ignore" to "prior" in a description of
environmental keying, `<iframe src=…>` with its URL — and let any synonym or
other language through (B 8.2.3). Every prompt that embeds report text now
encloses it between `<<<REPORT n>>>` / `<<<END REPORT n>>>` markers named by
the system prompt (spotlighting; `n` is a hash of the text, so prompts stay
reproducible). The sanitiser removes invisible characters, defuses chat
markup with a space, and deletes nothing else; both are counted in the stage
report. **Every prompt fingerprint changes.**

#### The API answers only to its own hosts and refuses cross-site writes, 2026-10-03

Reproduced by the October 2026 audit (B 8.2.1): any `Host` header was
accepted (DNS rebinding reads and edits every report as same-origin, even
over an SSH tunnel) and a multipart `POST /api/upload` from a foreign origin
created a job (CSRF: no preflight on a simple request). `api/main.py` now runs
Starlette's `TrustedHostMiddleware` on `API_ALLOWED_HOSTS` (default
`localhost,127.0.0.1,[::1]`; **list the public name or address you reach the
app on**, see docs/deployment.md) and answers 403 to a mutating request the
browser marks `Sec-Fetch-Site: cross-site` or stamps with a foreign `Origin`.
curl, scripts and the nginx `proxy` profile are unaffected.
`tests/test_api_hosts.py`.

#### Corpus git remotes: https on a public host only, 2026-10-03

`POST /api/settings/corpora` accepted `file://`, `ssh://`, `git://` and
internal addresses as a `git` remote and `git clone`d them on the server
(B 8.2.2). The remote now goes through the same `validate_url` policy as a
tarball, and git itself is locked to https (`protocol.allow=never`,
`protocol.https.allow=always`, `GIT_ALLOW_PROTOCOL=https`, no redirects, no
terminal prompt) for the API and the CLI sync alike. A private corpus over
SSH is cloned by hand and registered with its `path`.

#### A TLP marking is never guessed (ADR-0073), 2026-10-03

`TLP:AMBER`, `AMBER+STRICT` or any unknown value fell back to TLP:CLEAR, and
`STIX_TLP=TLP:AMBER` with no level on the job shipped an unmarked bundle
(B 8.1.3). One function now normalises the level (`TLP:` prefix, WHITE →
CLEAR) and raises on anything else; the API, the worker and the CLI refuse to
start on a bad `STIX_TLP`; the default is **AMBER** (set `STIX_TLP=clear` to
keep the old one). AMBER+STRICT is a fifth level, shipped the way OpenCTI
exports it, with OpenCTI's own id.

### Fixed

- **Stage 2 was quadratic in the size of the report** (B 8.1.1):
  `iocextract.extract_ipv4s`, 99 % of Stage 2's time and ~4 min for a
  5,000-address appendix, was redundant with `_IPV4_PATTERN` and is gone;
  `tests/test_stage2_performance.py` holds 200 KB with 5,000 IPs under 2 s.
- **Stage 3b accepted the neighbouring identifier** (B 8.1.4): UNC4763 for
  UNC4736, APT2 for APT28, BlackBasta for BlackCat. Names with a digit, under
  8 characters or single-token are matched exactly on word boundaries; fuzzy
  matching stays for multi-word names OCR split. `tests/test_stage3b_confusables.py`.
- **CLI bundles had no actors, malware or tools** (B 8.1.2): Stage 4 reads
  the LLM's lists, the worker rebuilt them from the job store, the CLI did
  not. `pipeline/named_entities.py` adds the detectors' names on both paths.
- **Stage 4 dropped Indicators and CourseOfActions silently** (B 8.1.9): each
  failure is now a `dropped / build_failed` ledger entry with the error.
- **No exception is swallowed without a trace in the code that ships**: the
  20 remaining `except Exception: pass` of `pipeline/` and `api/` log, record
  or catch a narrower error. The ones that lost data said nothing at all: a
  finalize whose stored LLM result no longer parses rebuilt a bundle with no
  techniques, campaign or targets; stored entity rows and relationship dates
  that no longer validate were dropped; a corrupt stored policy showed the
  factory default as if it were saved; a markitdown failure fell back to plain
  text with no word about the lost tables; the run manifest wrote `None` for
  the prompt fingerprint without saying why. ruff now enforces S110/S112
  (`pass`/`continue` in a broad handler) outside `scripts/` and `tests/`; the
  four handlers left say why on their line.
- **Compose images are pinned by digest**; `capture-proxy` was
  `ubuntu/squid:latest` (B 8.2.6) and is `6.6-24.04_edge` (24.04 LTS; `latest`
  pointed at 25.04, end of life).
- **Documentation figures taken from papers say so** (B 8.9.1): aCTIon's
  27% → 8%, CyNER's model-card F1, SecureBERT-Plus's +8–12% (ADR-0023 found no
  gain; no longer recommended), the ~40% estimate; `check_doc_claims.py` fails
  on a figure stated without its source. `docs/deployment.md` no longer
  describes a CORS setting that was removed.
- **The extraction prompt offered a verb STIX does not have** (B 8.1.6): the
  user template said `originated-from`, which Stage 4 shipped as
  `related-to`. The template says `originates-from`, model output is
  normalised (`originated-from`, `attributed_to`, `communicates with`), and a
  test holds every prompt's verb list to `STIX_RELATIONSHIP_TYPES`.
- **The extraction prompt described its inputs with stale figures and
  reliability claims** (B 8.3.4): "1,792 known malware families … with high
  precision", "XLM-RoBERTa" (CyNER is DeBERTa-v3), techniques found "with
  high cosine-similarity confidence" (measured precision 0.16). It now says
  what each pass proposed, nothing about how good it is.

### Changed

#### The database knows its version; every start brings it up to date (ADR-0077), 2026-10-04

`init_db()` used to replay an idempotent DDL list at each API start: no
record of what a database had, no way to rename, split, retype or rewrite
data, backfills forever, no defence against an older image on a newer
schema, and a worker that relied on the API starting first. The schema is
now a history, `api/migrations/v0001`–`v0009`, rebuilt from git one version
per schema-changing commit since the first PostgreSQL job store (ADR-0045),
each with its statements, an optional data step and its own verification.
**The API, every worker and `bootstrap` bring the database to the code's
version at start**, under an advisory lock (whoever starts first migrates,
the others wait), one transaction per version, verified before it is
recorded in `schema_migrations`. A database created before the history is
recognised version by version, without a change; a database newer than the
code, or an applied migration edited since, stops the start with what to do.
`python -m api.migrate status | up | check`. How to add a version:
docs/development.md, "Database migrations".

#### Frontend toolchain: Vite 8, plugin-react 6, vitest 5, jsdom 30, TypeScript 6.0, 2026-10-04

The Dependabot PRs for the frontend, applied together because they depend on
each other: `@vitejs/plugin-react` 6 requires Vite 8 (the Rolldown-based
bundler), vitest 5 runs on it, and jsdom 30 is its test DOM. `@types/node`
moves to 24 (vitest 5 wants 22 or later), plus the minor and patch group
(react-query, react-router, testing-library, autoprefixer, postcss).
TypeScript goes to **6.0.3, not 7**: typescript-eslint, even its canary,
accepts TypeScript < 6.1, so 7 would drop the lint. TypeScript 6 checks
side-effect imports and no longer loads every `@types` package by default:
`src/vite-env.d.ts` references Vite's client types (CSS imports), and the one
test that reads files references Node's. `npm run check` (lint, typecheck,
141 tests), the production build and `npm audit --omit=dev` pass; the UI was
checked in the browser (dashboard, review, graph, PDF viewer).

#### Relationship dates keep what the source said (ADR-0063), 2026-09-29

A relationship date was the model's own ISO conversion, padded to a 1st of
the month by `pipeline/dates.py`. Nothing checked it, and Stage 3d could
overwrite the only quote that carried it. On 7 real reports (150
relationships), 26 % of relationships were dated. 43 % of the dated bounds
fell on a 1st: "April and June 2026" shipped as `2026-04-01 → 2026-06-01`.
Only 57 % had their year in the relationship's own quote.

- **The model names and places a date; the code reads and judges it.** Each
  relationship carries `times`. Each date there has:
  - the expression copied verbatim;
  - its role (`start`, `end`, `within`, `throughout`, `observed`);
  - the value the code reads from the quote, unpadded (`2021` stays a year);
  - its precision;
  - a status the pipeline computes (`verified`, `ambiguous`, `unresolved`,
    `conflict`) and never takes from the model.
- **The check is strict about quotes and dates.** A quote must be in the
  chunk, on word boundaries (`2021` inside `CVE-2021-44228` is not a date).
  `03/04/2023` stays ambiguous unless its own passage fixes the day/month
  order.
- **Relative dates are resolved by the code, only against a publication
  date.** Sources: the URL capture's page metadata, an HTML file's
  `<meta>`, a "Published …" header line. A PDF's print timestamp never
  resolves "last month". The model no longer sees a reference date.
- **Export is `faithful` by default.** `start_time`/`stop_time` are set only
  from a verified instant. The policy's `temporal_export.mode: "day"` also
  projects a verified day onto the whole day, labelled as such. Every date
  ships in `x_temporal_assertions`. The ledger says per row why each date
  was exported or not (`times`, beside `changes`). The Report gains
  `x_source_published`, and `published` stays the build time.
- **Duplicates keep every date.** "in 2021" and "in 2024" stay two dates;
  the same quote read through two overlapping chunks stays one.
- **Storage and the analyst.** Dates are stored in `relationships.times_json`.
  Rows from before this change become legacy dates of unknown precision,
  never re-interpreted. The review rail takes a date at any precision
  ("2023", "March 2023") and sends only the bound that changed.
- **Measured.** `python -m evaluation.annoctr_time` scores the normaliser on
  AnnoCTR's TimeML layer: on test, 87.9 % of expressions read, and 99.2 %
  right when read.
- **Visible change for consumers.** Month- and year-precision dates no longer
  appear in `start_time`/`stop_time`; they are in `x_temporal_assertions`.

### Fixed

#### STIX ids are OpenCTI's standard ids (ADR-0066), 2026-10-01

**The problem.** Domain objects, indicators and markings were UUIDv5 under the
namespace STIX 2.1 reserves for observables, which the spec forbids (MUST NOT).
The key they were hashed from (`cti:<type>:<name>`) was one only CTIParsor
computed.

**The change.**
- Ids are now computed exactly as OpenCTI computes its standard ids
  (`pipeline/stix_ids.py`, mirroring pycti's `generate_id`). Each type hashes a
  few normalised properties: a technique's ATT&CK id, a sector's name and class,
  an indicator's pattern, a PAP marking's definition.
- Run against OpenCTI's own code, the ids match 15 out of 15.
- A bundle now lands on the objects OpenCTI already holds: the ATT&CK
  technique, the built-in PAP marking, the sector, the country.
- Relationships and the Report keep random UUIDv4 ids.
- Incidents keep a name-only id, because pycti also hashes the build time.

**What does not change.** The validator's `{103}` (UUIDv5 is not UUIDv4) and
`{302}` (no hash on the ATT&CK URL) warnings remain, by choice: OpenCTI's own
exports show both, and MITRE's ATT&CK data has no hash on any of its 37,478
URLs.

**Visible change.** Every SDO, indicator and marking id changes once, at the
next finalize.

#### Review shows what nobody decided; an IoC indicates a technique (ADR-0065), 2026-10-01

**An IoC → technique link never reached the bundle.**
- The relationship form offered all 35 verbs for the pair.
- Stage 4 dropped every observable ↔ attack-pattern edge before routing the
  observable through its Indicator. An accepted `link.ps1 indicates Group
  Policy Modification` was dropped.
- Now `indicates` ships as `indicator indicates attack-pattern`, the form STIX
  2.1 lists. A row written the other way round is turned around, and the ledger
  says so. Other verbs are still dropped.
- The form offers only `indicates` for that pair and says why.
- The form's search also matches ATT&CK ids ("T1484") and shows up to 50
  results instead of 8.

**No relationship was ever offered for review.**
- The pipeline stores every relationship accepted, as `default` (ADR-0058). The
  rail's "pending" tab counted only undecided rows, so it read 0 on every
  report, while every relationship shipped.
- "To review" now counts what no analyst has decided. A `default` chip marks a
  row kept by default, and ✓ confirms it instead of resetting it.
- Rows that share a target are grouped. ✓ all / ✗ all decide a group in one
  call: `POST /api/jobs/{id}/relationships/bulk`, journaled as `human_bulk`.
- What ships does not change.

#### The whole-document relation steps read the whole document (ADR-0064), 2026-10-01

Three steps meant to see past a chunk read only the start of the report. Nothing
failed, so it did not show.

- **The document-level pass (ADR-0057)** allowed 300 000 characters, but
  `_call_llm` cut every prompt to `LLM_MAX_PROMPT_LENGTH` (32 000). The entity
  list and the answer format come after the report text. Past ~30 000
  characters, the model got part of a report and nothing to answer.
  - `_call_llm` now takes a per-call limit.
  - Past a limit, the report text is cut, never the instructions after it.
- **Stage 3d** sent the first 3 500 characters.
  - On the document pass, every claim supported further down was removed: on 7
    real reports, it kept 71 of 336 document-level relations; now 309.
  - On reports over 30 000 characters, the tail of each chunk was never checked.
  - Stage 3f had the same cut.
  - Both now get the whole text they are given.
  - 3d verifies in batches of `STIX_VERIFY_BATCH_SIZE` (40).
  - On the whole report, 3d accepts a second sentence only when it says who the
    first one's subject is. A chain through a third entity does not count.
- **Stage 4c** read the first 6 000 characters. It now sends the passages that
  name either entity (name, alias or ATT&CK id), or the whole report up to
  12 000 characters.
- **The document pass now follows the run's 3d switch**, not only the
  environment.

**Measured on the 7 reports, relations after 3d:**

| | Chunks only (default) | Document pass only | Both |
|---|---|---|---|
| Relations | 195 | 309 | 434 |
| Strict precision | 0.81 | 0.51 | 0.58 |
| Estimated correct relations | ≈157 | ≈157 | ≈253 |

The document pass stays off by default. Before turning it on, see ADR-0064. At
~15 tokens/s, its answer on a 37 000-character report takes 11 minutes, past
the shipped `LLM_TIMEOUT`.

#### An observable keeps the relationships STIX 2.1 defines for it (ADR-0062), 2026-09-28

ADR-0041 routed every observable opposite an SDO through its Indicator
before checking the verb. `malware communicates-with domain-name`, `malware
drops file`, `infrastructure consists-of ipv4-addr`, all relationships the
spec defines on the observable itself, therefore shipped as `related-to` an
Indicator. The mapping ledger showed it on the seeded Industroyer2 report.

- The routing now applies only when the verb is not *listed* for the direct
  pair (`stix_rel_spec.rel_is_listed`). `related-to` is valid between any two
  objects, so it still goes through the Indicator, as ADR-0041 intended.
- The verb judged is the one the direct edge would carry: the row's, or the
  policy's pin for that pair of types. A pinned `malware>domain-name` rule
  reaches extracted rows again; since ADR-0041 its lookup ran on the rerouted
  `malware>indicator` pair.
- The pin engine applies the same rule with the rule's own verb. A rule
  labelled `malware communicates-with domain-name` now emits exactly that
  edge, and no longer needs the domain to have an Indicator.
- Measured on 7 real reports re-extracted into a throwaway database: 3 of 150
  extracted rows no longer lose their verb. Under the Policy page's template,
  304 of 1,245 pinned edges (24 %) had shipped as `related-to` an Indicator,
  and none do now. Rows whose verb is listed for no form of the pair (12,
  e.g. `malware targets ipv4-addr`) still go through the Indicator.

#### Further graphic defects found by a page sweep (N1–N10), 2026-09-28

Found by loading every page at 1024–1440 px, light and dark, with long file
names, hashes and URLs; the app targets 15″–38″ desktop screens.

- **Dashboard**: a long report name was cut mid-line with no ellipsis on its
  Kanban card; it now wraps within two lines ending in "…" (full name on
  hover). In a narrow column the TLP badge and the delete button wrap
  instead of being pushed out of the card.
- **Review**: the document title (the file name) wraps instead of running
  past the column. The pipeline ribbon's file name is one line with an
  ellipsis (it spilled under the stages), and the six stage cards shrink to
  labels, then numbers, as the width requires — below ~1900 px the last ones
  sat behind an unseen horizontal scroll. The breadcrumb keeps the report
  name (≥ 120 px) and shortens "Dashboard" and the status first.
- **Contrast**: the text greys meet 4.5:1 on every background of every
  theme (`--ink-4` carried labels at ~2:1, `--ink-3` sat at 4.3:1), as do
  `--warn` (3.2:1 on Ember) and the teal and rose accents (3.8:1 and 4.4:1
  on Ember). Text on
  accent fills uses `--on-fill` in the Policy segmented controls, the graph
  layout switcher and the coverage checkboxes (white fell to 2.6:1 on the
  dark theme). The Policy "Override" badge and the Detections score pills
  follow the theme (the badge was 1.6:1 on dark).
- **Animations**: the processing dialog's live dot pulses and Review's "not
  found" hint fades in — both named keyframes that did not exist.
- **Coverage**: the tactic columns wrap onto rows instead of a single row
  whose right-hand columns were reachable only through a scrollbar far below.

#### Graphic defects from the interface audit (G01–G27), 2026-09-28

- **Policy**: the "Auto" / "Full auto" colour (`--frost`) was never defined,
  so its buttons, badges and legend lost their fill (white text on nothing);
  it is now a steel blue in every theme. Below 1100 px the editor and the
  preview stack instead of squeezing the editor to 230 px, and the JSON
  dialog fits a low window and scrolls.
- **Graph**: arrow heads end on the target's rim instead of under it;
  parallel and reciprocal links bow apart instead of sharing one line; a
  single node (or one row of nodes) is framed at once and by Fit (it sat in
  the top-left corner). Hiding the last type in the legend hides it — it
  used to show everything again. A rejected link no longer pulls, sizes or
  highlights its nodes. Zooming or panning cancels the automatic fits that
  snapped the view back; accepting a link no longer reshuffles the layout;
  positions of removed entities no longer skew Fit. The canvas re-frames when
  resized, and below 960 px the detail / link panel floats over it.
- **PDF source**: opens fitted to the width, with a "Fit to width" button;
  a page wider than the column (zoomed, landscape) scrolls sideways instead
  of being cut on both edges. Highlights are placed from pdf.js's text layer
  (real glyph widths) instead of an even split per character, which drifted
  by ~20 px in proportional fonts. Picking an entity scrolls to it when it is
  off screen, and the page indicator no longer names the page below the one
  on screen.
- **Source (PDF, TXT/MD)**: accepted entities are underlined solid (✓ in
  TXT/MD), pending ones dashed — they looked the same. Rejected entities stay
  unhighlighted, and selecting one no longer says it is "not found verbatim".
- **Review**: long hashes, URLs and encoded strings wrap in the Text and
  Preview views instead of running under the margin. The Relationships rail
  is capped to the window on every resize (a rail sized on a tall window
  covered a smaller one) and restores its height when the window grows. The
  "Change type" menu is placed from its measured height and scrolls, and the
  "Add as entity" popover never outgrows the window.
- **Settings and Coverage**: corpus actions wrap inside their column; long
  corpus names and licences break instead of squeezing Source to 0 px; the
  technique band wraps into rows instead of leaving its card past ~100
  techniques; the export table's header scrolls with its rows so a classic
  scrollbar no longer shifts the columns; rule metadata wraps.
- **Processing dialog**: Close stays in the header whatever the width, and
  below 760 px the live graph goes under the stage list.
- **Focus**: the Graph and Policy search / filter fields show a focus ring.

#### Review and Dashboard interface, 2026-09-28

- **Narrow windows**: below 1180 px the entity margin, and below 900 px the
  type filters, used to disappear with no way back — an active filter stayed
  applied with its only control off screen. They now open as drawers
  ("Filters", "Entities"), and an active filter is always shown above the
  document ("Showing 2 of 9 · Malware · Clear filter").
- **A server that does not answer is not an empty list**: the Dashboard said
  "Nothing here" with zero counters, and Review showed a report with no
  entities. Both now say the load failed, with Retry; a failed refresh keeps
  the last list and says when it dates from.
- **Opening a report**: when moving it to Reviewing failed, the button did
  nothing. The failure is shown, with Retry and "Open anyway".
- **Status**: the breadcrumb said "For review" whatever the report's status,
  and the background auto-finalize (4 s after each review edit) marked the
  report completed; only "Complete Review" does now.
- **Theme**: the toggle's label names the theme and accent applied (it knew
  only "Dark · amber" and "Warm · oxblood"), and dark → light returns to the
  last light theme instead of Warm.
- **Dark theme contrast**: text on green/red/accent fills is dark there
  (8.6:1 and 6.4:1, was 2.2:1 and 2.9:1 in white).
- **Windows that ran off screen**: the "New relationship" card fits the
  window's width and height (scrolling when needed); the hover actions stay
  inside the window and "Change type" opens toward the larger space with a
  scroll; the shortcut help scrolls; the "New report" dialog scrolls its body
  and keeps its actions on screen.

### Added

#### Where a run's technique errors arise: `evaluation ttp-errors`, 2026-10-03

Splits every gold parent technique of a run into found, retrieved but not
selected, and never retrieved, and every false positive by whether it came
from the candidate list (ADR-0072 step 4: "never retrieved" is a retrieval
problem, "retrieved, not selected" a selector problem). Writes
`runs/<name>/ttp-errors.json` with the most frequent techniques per category;
counts match `score` exactly. Run records now keep the quote of a selection
the code refused, so a refusal can be told apart as missing, too short or not
verbatim.

#### TTPs: retrieve from ATT&CK procedures, select with a quote (ADR-0072), 2026-10-03

Stage 2c emitted a technique for any sentence whose best cosine match cleared
a threshold; on AnnoCTR dev that was 55 % of the predicted techniques at 0.16
precision, and turning it off lifted F1 from 0.339 to 0.488. Its matches also
reached the output through Stage 3c's seeding and told the Stage 3 LLM not to
re-extract them.

- **A procedure corpus.** `python scripts/build_indexes.py --only retrieval`
  builds a versioned, git-ignored corpus: 697 full technique descriptions
  (the old cache embedded the first 300 characters) and 16,653 distinct
  ATT&CK `uses` examples. Links, citations and tags are removed. Actor,
  software and campaign names are neutralised by default (`--keep-names`
  keeps them). Each example keeps the URLs it cites.
- **Hybrid retrieval.** `pipeline/ttp_retrieval.py` ranks techniques (not
  examples) per passage with dense cosine, BM25, min-rank fusion or RRF.
- **`python -m evaluation retrieval`, rewritten.** It measures recall per
  passage, per document and per chunk, at parent level and exact id, with
  the candidate count and an error bucket per miss. On dev, parent recall per
  passage at k=5 goes from 0.33 (today's cache, dense, keyword gate) to 0.77
  (both corpora, RRF). It is 0.95 at k=25. Per capped chunk list (the
  selector's input), 0.45 → 0.86. The 48 MITRE examples that cite AnnoCTR
  reports (28 from test) are excluded, and `evaluation run` does the same.
- **`TTP_MODE=select` (off by default).** Stage 2c only retrieves
  `TtpCandidate`s: never an entity, never in the bundle or the prompt. Stage
  3f makes one call per chunk with the chunk, its retrieved candidates and
  the LLM's own proposals. The code keeps a choice only if its id is a
  candidate and its quote is in the chunk. A failed or unparseable call ships
  nothing: its candidates go to `ttp_review`, and the stage report says so.
  Without an LLM, the old detector runs, labelled "offline fallback, less
  reliable". `TTP_MODE=verify` is today's pipeline, unchanged.
- To decide: the dev runs listed in ADR-0072, compared with the 2c-off run.

#### The graph shows the bundle that ships (ADR-0061), 2026-09-28

The Graph page drew the review rows, never the bundle: on the stored bundles
80–100 % of the edges had no row behind them, and rows were rewritten or
dropped with no trace.

- **Mapping ledger.** Stage 4 records what it did with each entity and
  relationship row — the object or edge it became, what it was merged into,
  each rewrite (verb downgraded to `related-to`, verb set by a pinned rule,
  observable replaced by its Indicator), or why it was dropped (unresolved
  endpoint, alias self-loop, observable ↔ technique, no ISO country, named
  entity the LLM did not list) — plus why every generated object and edge
  exists and what the Stage 4b alias merge removed. Stored beside the bundle
  in `jobs.bundle_ledger_json` (same write), served at
  `GET /api/jobs/{id}/bundle/ledger`. The bundle is unchanged by it.
- **Bundle view** (the Graph page default, remembered per viewer): the
  bundle's objects and links, each link coloured by origin with a toggleable
  legend; rewritten rows in amber; dropped rows and entities drawn as hollow
  dashed ghosts with their reason; a **Differences** panel; clickable edges
  with their provenance (rule, premises, quoted evidence, the rows behind
  them). The review view marks each row with its fate in the bundle.
- **Graph-page edits rebuild the bundle** (4 s debounce, as on the Review
  page); Download runs a pending rebuild first. Before, the Graph page's
  Download served a bundle that ignored its own edits.
- **Changed — `indicator --based-on--> <observable>` directly**: the
  ObservedData wrapper is gone — it stated a sighting at the build time that
  nobody made. Documented as the one project extension to the STIX suggested
  pairs (`stix_rel_spec.rel_is_allowed`); the default validator run passes,
  strict mode reports `{202}`.

#### Fixes from a review of phases 0–2, 2026-09-27

- **Stage 3 checkpoint**: the fingerprint now covers every setting and input
  that changes Stage 3's output; turning 3d/3f verification on, or changing
  the consensus model, no longer resumes results from the other setting.
- **Unusable LLM answers**: an empty answer or one that never parses no longer
  counts as a successful Stage 3 — each extraction call is classed (ok,
  failed request, empty, unparseable), as are the 3d/3f verifications, and a
  Stage 3 with no usable answer is `failed`.
- **Control sample**: a reset to pending is no longer counted as a decided
  (rejected) row in the auto-accept precision.
- **Decision journal**: deleting a report keeps its `review_decisions` rows
  (the cascade contradicted "never deleted").
- **CLI and worker**: the CLI applies the saved relationship policy like the
  worker (`--policy`); the equivalence test compares whole bundles, edges by
  their endpoints, under a non-default policy.
- **Ablations**: 3d, 3f, 4b and 4c are stage ids that can be turned off.
- **Lock file**: documented that it pins versions, not hashes, and why.

#### Evaluation protocol (ADR-0060), 2026-09-27

`python -m evaluation` scores the application's pipeline on document-level
gold data. **AnnoCTR** (120 vendor reports with ATT&CK techniques, explicit and
implicit; official temporal split 70/16/34; data kept in `data/`, CC-BY-SA)
with a per-report registry of the annotated layers, an ATT&CK id mapping that
follows `revoked-by` on gold AND predictions (T1562 → T1685), and a
near-duplicate check across splits. An **in-house set** format and annotation
guide (docs/eval/annotation-guide.md) for our own reports, scored from the
original file: IoCs, relationships, negative cases (negated behaviours,
recommendations, generic examples), agreement between two annotators.
Metrics: parent-level TTP P/R/F1 (primary), per-document averages, recall of
explicit vs implicit techniques, strict and lenient entities, evidence split
into "quote exists", "quote on the annotated passage" and a human-judged
sample for "quote supports the claim"; **paired bootstrap** between two runs on
the same documents; Stage 2c candidate recall at several k. Decision rule fixed
before any test comparison (docs/eval/README.md).

Two changes in the pipeline came out of the first runs:

- **Stage 3 counts provider calls and failures.** The first baseline found
  every Stage 3 call answered 404 — the `.env` model name lacked the
  `Inferact/` prefix the vLLM server serves — while Stage 3 reported success
  and bundles came out without any LLM content. Stage 3 is now `failed` when
  all its calls fail (and reports partial failures), so the benchmark stops and
  the job's stage report says so.
- **`LLM_TEMPERATURE` / `LLM_SEED`** (unset = unchanged: the provider's own
  sampling). Recorded in the run manifest and the checkpoint fingerprint.

#### Measurement, ingestion and CI fixes, 2026-09-27

- **NER score.** A partial match ("Cobalt" for gold "Cobalt Strike") added 0.5
  to TP and nothing to FP or FN, so it scored P = R = F1 = 1.0; predictions were
  matched greedily in input order, and the per-type table let two predictions
  both match one gold entity. The score is now strict by default (a partial
  pair is a FP and a FN) over a one-to-one matching, with a separate lenient
  line and a `partial` column. `scripts/verify_ner_scorer.py` replays the old
  scorer to prove every new test would have failed against it.
- **DOCX tables** are read, in reading order, one row per line — a hash in a
  cell used to never reach Stage 2. Merged cells are read once, nested tables
  flattened into their cell.
- **OCR is decided page by page.** A page is a scan when it has almost no text
  and an image covers half of it; a mixed PDF keeps its text pages and OCRs the
  scans in place (before: the first three pages decided for the whole file, so
  a scan after text pages was lost). `OCR_LANG` (default `eng`) sets the
  Tesseract languages.
- **`requirements.lock.txt` is what gets installed.** `make lock` resolves the
  three requirements files for Python 3.12 with CPU-only torch (uv, every
  platform); the Dockerfile installs from it and CI installs under
  `-c requirements.lock.txt`, so CI tests the image's versions. It used to be a
  `pip freeze` record the build never read, and was not committed.
  `requirements-dev.txt` pins ruff, mypy and pytest-cov.
- **CI.** New `frontend-tests` job (`tsc --noEmit`, vitest); the GHCR image is
  published only after `fast-tests`, `frontend-tests` and the container smoke
  test pass (it used to depend on the smoke test alone); mypy is blocking — the
  tree has no errors left.

#### One pipeline for the worker, the CLI and the benchmark (ADR-0059), 2026-09-27

`pipeline/orchestrator.py` runs Stages 1 to 5 for every entry point. The CLI
used to skip the gazetteer, the semantic TTP stage, CyNER, GLiNER, the alias
lists and type-conflict resolution; the ATE `--stage full` benchmark sent the
whole text as one chunk and, without an LLM provider, quietly scored regex +
semantic. Each run now reports every stage as ran, skipped or failed, with the
reason; the CLI prints it and the worker stores it in the job's run config
(`stage_report`), next to a new `manifest` (LLM model, prompt hash, NER models,
data-file hashes, package versions). `--stage full` stops when the LLM cannot
run unless `--allow-degraded`. The CLI gains `--disable-stage`,
`--require-stage` and `--no-llm`; `PIPELINE_DISABLED_STAGES` does the same for
the API. The Stage 3 checkpoint used to resume any run with the same number of
chunks; it now needs the same text, model and prompts. A CVE-cache failure
(no database, as with the CLI) no longer fails the run.
`api/worker.py`: 1,777 → 1,077 lines.

#### Decision provenance: who accepted what (ADR-0058), 2026-09-27

Every write of `accepted` now records its origin — `human`, `human_bulk`,
`auto_policy`, `default`, `propagated` or `legacy` — and appends a line to a
new insert-only `review_decisions` journal. Opening the review page used to
write `accepted = true` for every entity at or above 90 % through the same
PATCH an analyst's click used; the worker applies auto-accept now, and the page
writes nothing on load. Calibration (ADR-0051) reads only one-at-a-time
analyst decisions by default, and promotion (ADR-0052) counts only analyst
accepts: the LLM's name lists, stored at 0.9, had all been auto-accepted and
were counting toward promoting the LLM's own guesses into the gazetteer.
Decisions made before this change become `legacy` and are left out of both
unless asked (`include_legacy`). A control sample
(`REVIEW_CONTROL_SAMPLE_RATE`, default 10 %) of the would-be auto-accepts
stays pending, flagged `confirm`; `GET /api/thresholds` reports the share
analysts confirm (`auto_accept_audit`).

#### vLLM: a thinking switch and a `vllm` vision provider, 2026-09-27

`VLLM_ENABLE_THINKING` (default `false`) sends
`chat_template_kwargs.enable_thinking` with every vLLM request, Stage 3 and
Stage 1f alike. Qwen3-family models think unless told not to. Measured on
Qwen3.8-27B served by vLLM 0.27, the Stage 3 extraction prompt spent the whole
8192-token output budget reasoning and returned no JSON after 431 s, so the
chunk came back empty. With thinking off, the same chunk went through
extraction, Stage 3d and Stage 3f in 106 s. The value is recorded in each
bundle's run config.

`VISION_PROVIDER=vllm` reads figures on the Stage 3 server (`VLLM_BASE_URL`),
with `VLLM_MODEL` as the default model. vLLM publishes no capability flag, so
the probe first checks the name against `/v1/models` (the served id carries
its organisation prefix, and a bare name 404s), then sends one 64 px image. A
text-only model refuses it, and Stage 1f is disabled with the server's reason.

#### Full-Docker installation: `setup.sh` becomes environment prep only (ADR-0054), 2026-09-19

Docker is now the only supported way to install, develop and run CTIParsor —
the developer loop and the air-gapped install included, not just deployment.
`setup.sh` drops from 1298 lines to ~250: it checks Docker/Compose are
present and the daemon is reachable, writes `.env` and generates
`CTI_DB_PASSWORD`/`.secrets/db_password`, then prints the next commands — it
no longer builds, downloads or starts anything itself. Everything that used
to happen on the host (system packages, the Python venv, Node, NLP models,
MITRE data, the detection corpora, the frontend build) is now either baked
into the image or done by `docker compose --profile bootstrap run --rm
bootstrap`.

Two new `profiles: [dev]` compose services replace the venv-based dev
workflow: `dev` bind-mounts the repo live over `/app` (the same image as
`app`/`worker`, `read_only: false`) so `docker compose run --rm dev pytest`
or `... cli input/report.pdf` need no rebuild on edit — `tests/` is
`.dockerignore`d from the built image specifically so this bind mount is
what supplies it; `frontend-dev` bind-mounts `frontend/` into a plain
`node:24-bookworm-slim` container for Vite HMR at `http://localhost:5173`.
Re-examined ADR-0037's WSL `/mnt/` bind-mount warning against this new
bind mount and found it doesn't recur: that measurement was SQLite random
access (gone since ADR-0053) and Torch/HF `.so` reads from `/opt/venv`,
which stays baked inside the image and is never bind-mounted.

The air-gapped install (ADR-0040) is redesigned around Docker:
`scripts/package_offline_docker.sh` builds the image, `docker save`s every
image the stack needs, runs `bootstrap` locally, and exports the NLP-model/
corpus cache (a volume tar) and the job/rule store (`pg_dump -Fc`, not a raw
`pg-data` tar — binary PostgreSQL data directories aren't reliably portable
even same-version) into one checksummed bundle.
`scripts/check_offline_bundle_docker.sh` verifies a bundle restores and the
stack actually works, reusing the existing `scripts/docker_smoke.sh` for
that check after confirming it never itself invokes `bootstrap`.
`setup.sh --offline=DIR` loads the images and restores both volumes, leaving
`docker compose up -d` as the only remaining step. The three old venv-based
offline scripts (`package_offline.sh`, `check_offline_bundle.sh`,
`offline_lib.sh`) are removed, not kept dormant.

`README.md`, `CONTRIBUTING.md`, `TESTING.md`, `docs/docker.md`,
`docs/deployment.md` and `docs/upgrading.md` updated throughout; the
`Makefile` drops every venv-relative target in favor of `docker compose run
--rm dev` for anything that touches Python/Node.

#### PostgreSQL only: the detection-rule corpus moves off SQLite, and SQLite is removed entirely (ADR-0053), 2026-09-19

ADR-0045 moved the per-report tables to PostgreSQL and deliberately left the
detection-rule corpus (87k+ rules) on SQLite, reasoning that FTS5's
`rule_text` index and the `INDEXED BY idx_detection_dedup` planner hint in
`pipeline/detection/store.py` "do not port." Revisited: every `MATCH` call
site (`pipeline/detection/brands.py`) is a quoted-phrase lookup — brand
tokens, CVE ids — never free-text ranking, so `to_tsvector('simple', ...)` +
`phraseto_tsquery` gives the same word-boundary, non-substring semantics
FTS5 was chosen for (ADR-0031's founding case: a substring match on `reat`
used to fire inside `threat`/`great`). The `INDEXED BY` hint defeated a
SQLite-specific no-`ANALYZE` planner quirk that PostgreSQL's cost-based
planner does not share, so it is dropped, not translated.

`DATABASE_URL` is now mandatory everywhere — the API, the worker, and the
test suite all refuse to start without a reachable PostgreSQL server, with a
clear message rather than a silent SQLite fallback (`main.py`'s batch CLI is
unaffected — it touches neither store). `rule_text` becomes a plain table
with a `GENERATED ALWAYS AS` `tsvector` column instead of an FTS5 virtual
one; six upserts across `pipeline/detection/store.py` and `dedup.py`
rewritten to `ON CONFLICT`, the same treatment ADR-0045 already gave the job
store; a new `scripts/migrate_rules_to_postgres.py` sibling to
`migrate_jobs_to_postgres.py`; roughly twenty peripheral audit/measurement
scripts that bypassed `api.db` and opened `cti_stix.db` directly converted,
catching a few already-latent bugs along the way (a hardcoded `instr()` call
with no PostgreSQL equivalent, `rowid`-based ordering that doesn't exist on
PostgreSQL, a `.cursor()` call that skipped placeholder translation).

Validated: 1377 tests green against a live PostgreSQL server, 0 failed,
including new coverage for the two cases most at risk in the FTS5→tsvector
swap — the `reat`-inside-`threat`/`great` regression and a hyphenated CVE id
— both previously untested because a bare fixture table with no real
`rule_text` made the existing brand/CVE tests pass vacuously. CI's
`postgres-tests` job, now byte-for-byte redundant with `fast-tests` once
every job requires PostgreSQL regardless, is retired.

#### Deny and promote lists grown from analyst decisions (ADR-0052), 2026-09-18

ADR-0050 fixed CyNER's generic-language noise with three hand-kept lists in
`pipeline/stage2d_cyner.py`, each entry added after someone read a real
report's noise. The review UI records the same judgement one click at a
time, in `entities.accepted` — on the very job ADR-0050 examined,
`"Russian state"`, `"campaign"` and `"backed threat groups"` had each been
flipped to rejected by hand. And the other direction had no mechanism at
all: `ARGUEPATCH`, `AXETERROR`, `BRUSHPASS` — real codenames CyNER found and
no gazetteer knows — depend on the model finding them again in every later
report.

`python -m scripts.promote_overrides` (and `POST /api/overrides/promote`)
reads the decisions and proposes, per exact `(value, entity_type)`: a
`deny` row when the value was rejected at least 3 times, in at least 2
reports, in at least 80 % of its reviews; a `promote` row when a
malware/threat-actor/tool name was accepted (or created by hand) at least 3
times, in at least 2 reports, in 80 % of its reviews, is unknown to the
gazetteer, at least 4 characters and not made of ADR-0050's generic
vocabulary. The report is the product: `--apply` stores **candidates** and
never changes the status of a row that exists, so a cron can run it while
a person still decides — `PATCH /api/overrides/{id}` (or `--activate-all`)
activates, `POST /api/overrides` writes a rule by hand, active at once.

An active `deny` row drops the exact value from the output of the
gazetteer, CyNER, GLiNER and the LLM's name lists (never a substring:
`"Russia"` does not sink `"XAKNET Cyber Army of Russia Reborn"`); an
active `promote` row is merged into the Stage 2b gazetteer and matched by
the same Aho-Corasick automaton at canonical confidence before any model
runs. `entity_overrides` exists on both engines; rows are read once per
worker subprocess (`pipeline/overrides.py`), `ENTITY_OVERRIDES_ENABLED=false`
ignores them all, and every bundle's run config records how many acted.
Both CLIs now log to stderr so `--json` is a clean document on stdout.

#### NER confidence cutoffs calibrated from analyst decisions, per source and entity type (ADR-0051), 2026-09-18

The discard cutoff Stage 2d (CyNER, 0.70) and Stage 2e (GLiNER,
`GLINER_THRESHOLD` = 0.40) apply was one constant per stage across every
label the stage emits, chosen once and never measured. The store already
holds the measurement: every CyNER/GLiNER entity is saved with the model's
raw score and, once reviewed, the analyst's accept/reject — a labelled
sample of P(correct | score) per `(source, entity_type)`.

`python -m scripts.calibrate_thresholds` (and `POST
/api/thresholds/recalibrate`) fits an isotonic regression to that sample per
pair and proposes the lowest score at which the *calibrated* accept rate
reaches a target precision (0.90 by default), reported next to what the
cutoff in force delivers today and the share of accepted entities the
proposal would still show. Nothing is written without `--apply` /
`"apply": true`; a written row (`model_thresholds`, both engines) overrides
the stage default for that one pair and is read once per worker subprocess
(`pipeline/thresholds.py`), a dictionary lookup in the stage —
`THRESHOLD_CALIBRATION_ENABLED=false` ignores every row. `GET`/`PUT`/`DELETE
/api/thresholds` read, hand-set and clear rows; every bundle's run config
(ADR-0024) now records the cutoffs it was built under.

Three things the data cannot honestly say are reported as a status instead
of applied: too few decisions (< 200), no score band reaching the target
(a content problem, not a cutoff problem — cf. ADR-0050), and a clean band
that only starts at the review UI's own auto-accept tier (≥ 0.90), where
"accepted" is mostly the model's verdict echoed back. A proposal also never
goes below a score analysts have actually seen. GLiNER's library has a
single threshold for all labels (checked), so the model is asked at the
lowest cutoff in force and each prediction is held to its own type's.

### Fixed

#### A malformed number in `.env` no longer stops the process; the CLI reads `.env` first, 2026-09-27

28 numeric settings were read with a bare `int(os.getenv(...))` or
`float(...)`, most of them at import time, so a typo such as
`WORKER_MAX_CONCURRENT=abc` or `LLM_TIMEOUT=2 minutes` raised a ValueError that
stopped the API, the worker or the CLI. They now go through `env_int` /
`env_float` in `pipeline/env_flags.py`, beside `env_bool`. Unset or blank gives
the default silently; a value that does not parse gives the default and a
warning naming the variable.

`python main.py` loaded `.env` only through the `load_dotenv()` inside
`stage3_llm`. That ran after `api.logging_config` had read `LOG_LEVEL`,
`LOG_FORMAT`, `LOG_FILE`, `MAX_LOG_SIZE` and `LOG_BACKUP_COUNT`, so the CLI
ignored those five when they were set in `.env`. It now loads the `.env` beside
it before any project import; a real environment variable still wins.

#### CyNER's Malware/Threat_group labels tagged generic language as named entities (ADR-0050), 2026-09-18

A user-reported real report (`apt44-unearthing-sandworm.pdf`) came back with
far more `malware`/`threat_actor` entities than made sense to review.
Pulling the job's actual extracted entities confirmed it: CyNER's labels
fire on any span *discussing* malware or threat-actor activity, not only on
spans that *name* one, and `extract_cyner_entities` accepted almost
everything above a 0.70 confidence score. The result included pure category
language at high confidence (`"malware"` 0.98, `"ransomware family"` 0.96,
`"cyber espionage"` 0.86), a comma-separated list of six real malware names
glued into one entity, spans crossing a sentence boundary or mixing script
(OCR/translation artifacts), truncated possessive fragments, and countries
mistagged as threat actors. The job's own review history already showed
several of these — `"Russian state"`, `"campaign"`, `"backed threat
groups"` — manually flipped from auto-accepted to rejected.

Added list splitting (a joined span is evaluated part by part), a
~150-word enumerated stoplist of malware/actor category vocabulary (a
fragment survives if even one token isn't generic), and two small
denylists for specific software/country false positives, folded into the
same "any real content?" check so one denylisted word can't veto an
otherwise distinct name — an earlier version of the fix used a separate
blanket veto and wrongly dropped the real hacktivist-front name "XAKNET
Cyber Army of Russia Reborn" for containing "Russia".

Measured by replaying the job's actual captured CyNER output through the
fix: 255 → 162 raw `malware`/`threat_actor` entities (−36.5%; malware
−26.4%, threat_actor −67.7%), every removed entity manually verified as
generic language, a list-join artifact, or script/OCR garbage. 17/17
targeted tests pass, including 8 built from the real noisy strings; full
suite 1227 passed / 15 skipped. Details, the enumerated stoplist rationale,
and a known accepted loss (a spelled-out tool name that reads as pure
generic language) are in
[ADR-0050](docs/adr/0050-cyner-generic-language-filter.md).

### Added

- **The image publishes to GHCR; a queue-status endpoint reports backlog and
  worker liveness (ADR-0047, ADR-0048).** Two operational blind spots named
  while documenting the container/PostgreSQL/worker work, closed the same
  session they were found. Every push to `main` now builds, smoke-tests, and
  — only if that passes — publishes `ghcr.io/stixaly/ctiparsor` tagged
  `sha-<full sha>` and `latest`; `packages: write` is scoped to that one job,
  never to the build/smoke job that also compiles PR code. A host that only
  wants to run the stack sets `CTI_IMAGE` in `.env` and does
  `docker compose pull && docker compose up -d`, no local build — verified
  against the real `compose.yaml`, not assumed: a pre-existing local tag
  made `up` skip the build step entirely (6.4 s to running containers).
  Separately, `GET /api/queue/status` answers job counts by status, the
  oldest queued report's age against `API_QUEUE_MAX_DEPTH`, and one row per
  active worker with its heartbeat age and whether it has crossed
  `WORKER_LEASE_TIMEOUT_S` (`stale: true`) — the lease ADR-0046 introduced,
  made visible instead of only inferable from logs. No new dependency
  either way: no registry account beyond the repo's own GitHub, no
  Prometheus client — both were weighed and rejected as disproportionate to
  what was actually missing. `tests/test_queue_status_api.py` (8 tests, both
  engines) and validated against the live compose stack: a worker row
  appeared 1.1 s after a real upload and the endpoint returned to empty the
  moment the report reached `for_review`.

### Documentation

- **`.env.example` reorganised for a configuration pass**, 2026-09-27. It now
  opens with how to use the file: the conventions (active vs commented lines,
  the boolean vocabulary), the minimum settings needed to run, and a table of
  contents. The body is fourteen numbered sections in pipeline order, with one
  variable per line. No value changes: the same 38 keys are active, with the
  same values. Five variables the code reads were missing and are now
  documented: `TTP_ADVISORY_GATE`, `CYNER_BATCH_SIZE`, `CYNER_CHUNK_CHARS`,
  `CTI_GIT_REV` and `ENV`. The six `CTI_*_MEMORY` limits get their own line;
  each shared a line with its CPU counterpart, so uncommenting it produced one
  broken value.

  Three corrections. The compose worker defaults to
  `WORKER_MAX_CONCURRENT=1`, not 10. The CVE cache lives in the database, not
  `cti_stix.db`. `CHUNK_MAX_CHARS`, `CHUNK_OVERLAP` and `LLM_MAX_RETRIES` are
  now marked as having no effect: they feed a config object that nothing
  reads.
- **`docs/architecture.md`** maps the deployment model that ADR-0044, 0045
  and 0046 built: the two shapes (host install, container stack), every
  piece and what it owns, the life of a report from upload to bundle as a
  sequence diagram, the configuration surface, the security controls and
  their stated limits, the sizing table, the decisions with their rejected
  alternatives, and what comes next. **`docs/upgrading.md`** is the runbook
  for an existing install — host or the first compose stack — with the
  required steps, the optional ones, and a rollback for each. The README lists
  the `docs/` pages; the container guide's diagram now shows the worker and
  the database.

### Added

- **The pipeline runs in its own container; the `jobs` table is the queue
  (ADR-0046).** `CTIPARSOR_ROLE` decides who runs reports: `all` (default)
  is the single-process host install, unchanged in behaviour; `api` makes the
  API a stateless front that only queues; `worker` is `python -m api.queue_loop`
  — the same image with `command: worker` in compose, scalable with
  `docker compose up -d --scale worker=2`. The claim that already existed
  (`UPDATE … WHERE id=? AND status='queued'` with a rowcount check) was
  atomic on both engines; what several workers needed was a **lease**: two
  columns on `jobs` (`worker_id`, `heartbeat_at`), a heartbeat every
  `WORKER_HEARTBEAT_S` (30 s) on the rows a worker runs, and a requeue of
  `processing` rows whose stamp is older than `WORKER_LEASE_TIMEOUT_S`
  (180 s) — the old `requeue_orphans()` reset *every* `processing` row and
  would have stolen jobs a second worker was running. The subprocess per
  report (ADR-0002) and its crash-to-`failed` watcher are untouched; the
  in-memory slot counter is gone, the loop counts the subprocesses it
  started. A stopping worker drains for `WORKER_DRAIN_S` then requeues what
  is left, which Stage 3 checkpoints make cheap. Liveness is a file on tmpfs
  touched every poll, so the worker container has a healthcheck without a
  port. `run_pipeline_async()` keeps its three answers; in role `all` it
  kicks the loop synchronously so a free slot still answers `"processing"`.
  Every compose service now declares CPU and memory limits and reservations
  from measured figures (app 2 CPU / 3 GB, worker 4 CPU / 6 GB per report,
  postgres 1 / 512 MB, proxy 0.5 / 128 MB, bootstrap 2 / 4 GB, ollama
  8 / 12 GB), each overridable in `.env`. No broker: ADR-0002's and ADR-0036's
  reasons still hold. Tests: `tests/test_job_queue.py` rewritten (14 tests,
  both engines) — atomic claim under 8 threads, lease semantics, heartbeat
  scoping, slot accounting with a fake spawn, the three answers under each
  role, `--once`. The smoke test now asserts that the worker container is
  healthy, that the API runs as `api`, and that the sample report was
  processed by the worker and not by the API.

- **The job store can run on PostgreSQL; the rule corpus stays in SQLite
  (ADR-0045).** `DATABASE_URL=postgresql://…` moves the eight per-report
  tables — `jobs`, `entities`, `relationships`, `progress_events`,
  `relationship_policy`, `report_figures`, `figure_reads`, `cve_cache` — to
  PostgreSQL; unset, nothing changes and every host install keeps its single
  `cti_stix.db`. ADR-0037 had accepted exactly this split and deferred it to
  the arrival of authentication; the maintainer brought it forward. What made
  it a days-long change rather than a rewrite, measured before starting: of
  213 SQL call sites only seven statements on the per-job tables were
  SQLite-only (`INSERT OR REPLACE` / `OR IGNORE`, now the standard
  `ON CONFLICT` form both engines accept), every row is read by column name,
  and that SQL contains no `%` or `LIKE` — so a 165-line adapter
  (`api/db_backend.py`: `?`→`%s` outside string literals, a `sqlite3.Row`-like
  tuple as psycopg's row factory, a wrapper whose `with` block does **not**
  close the per-thread connection the way psycopg's own does) replaces the
  ORM ADR-0036 rejected. The FTS5 `rule_text` table and `store.py`'s planner
  hints cannot move, so `api/db.py` now has two getters: `get_conn()` is the
  job store, `get_rule_conn()` always the SQLite corpus; without
  `DATABASE_URL` they are the same connection. The coverage code is the one
  place both stores meet (`job_technique_ids`, `job_observable_rows` and
  their eight callers) and takes a `jobs_conn` keyword the routes pass.
  PostgreSQL DDL uses `IDENTITY` and `DOUBLE PRECISION` (its `REAL` is a
  4-byte float that would round every confidence score).
  `scripts/migrate_jobs_to_postgres.py` copies an existing store in one
  transaction — ids preserved, `progress_events` sequence realigned so SSE
  resume points survive, `--dry-run` rolls back, a guard refuses a non-empty
  target without `--append`. The compose stack gains a `postgres:17-alpine`
  service on the internal network only: non-root (`user: 70:70`), every
  capability dropped, read-only root, `scram-sha-256` for local and host
  connections, `pg_isready` healthcheck the app waits for, its own `pg-data`
  volume; `CTI_DB_PASSWORD` in `.env` is required and travels as `PGPASSWORD`,
  never inside a URL; the `backend` network it shares with the app is
  `internal: true`, so the database has no route out of the host even if
  compromised (Ollama, which must pull models, moved to its own `llm`
  network for that reason). Tests: `tests/test_db_backend.py` (adapter, no server),
  `tests/test_db_postgres.py` (skipped unless `CTIPARSOR_TEST_DATABASE_URL`
  is set; CI runs it against a service container), and the whole existing
  suite runs unchanged on SQLite and, through the same `temp_db` fixture
  creating a disposable schema per test, on PostgreSQL. `psycopg[binary]` is a
  new dependency in `requirements-api.txt`. Measured on 2026-09-16: 1198
  tests green on SQLite, 1206 on PostgreSQL 17 (76 tests had encoded the
  single-store assumption and were rewritten to ask for both connections);
  inside the compose stack the pre-existing SQLite job store was migrated
  (47 rows, one transaction) and a report went through the API to a
  53-object bundle with the job store on PostgreSQL.

- **Container install: one hardened image and a compose file (ADR-0044).**
  `docker compose up -d` is now the third install path beside `setup.sh` and
  the air-gap bundle. The request arrived as "one container for PostgreSQL,
  one for the app", then "app / worker / Chromium / database"; checked
  against the code, none of those seams exist — the store is a SQLite file
  opened in-process (ADR-0037 defers PostgreSQL until authentication), the
  worker is a subprocess spawned from inside the API with no broker
  (ADR-0002), and Chromium is launched in-process by Playwright. So: a
  three-stage `Dockerfile` (Node builds the UI, a builder makes the venv with
  CPU-only torch — the PyPI wheel drags 2.2 GB of CUDA libraries the image
  would never use — and a slim runtime), two named volumes (`cti-state` for
  the database, uploads, outputs and backups; `cti-cache` for the 2.6 GB of
  models and the corpora, rebuildable), and `compose.yaml` with three optional
  profiles: `bootstrap` (one-shot model warm-up + corpus sync + rule store),
  `ollama` (a local LLM with no published port) and `proxy`
  (`nginx-unprivileged` with TLS + htpasswd, the container form of
  docs/deployment.md option C). Measured: 4.48 GB image, 3 min 24 s cold
  build, healthy 7 s after start, bootstrap 13 min (3 models, 14 corpora,
  87,480 rules), and a real report through the API to a 63-object bundle in
  5 min 42 s with the LLM stage on an external Ollama. Hardening, each verified by
  `scripts/docker_smoke.sh`: non-root uid 1001, read-only root filesystem with
  tmpfs scratch, every capability dropped, `no-new-privileges`, a pids limit,
  the API published on 127.0.0.1 only, secrets passed by `env_file` and
  excluded from every layer by `.dockerignore`. The Chromium sandbox stays
  **on**: `docker/seccomp-chromium.json` is Docker's default profile plus user
  namespaces — and plus `chroot`, because with all capabilities dropped
  Playwright's stock profile still gated that syscall on `CAP_SYS_CHROOT` and
  the zygote died with `Check failed: sys_chroot("/proc/self/fdinfo/")`; the
  kernel enforces the capability inside the zygote's own namespace, so
  allowing the syscall grants nothing to the container. Two smaller findings
  from the build: `python-magic` needs `libmagic1`, which `python:*-slim`
  does not ship (the upload MIME check was silently falling back to
  `filetype`), and the optional `re2>=0.2.20` pin cannot build on Python 3.12
  (`PyUnicode_AS_UNICODE`), so no current install actually has the ReDoS
  guard it advertises — the image reports this as a warning, a follow-up
  covers the `google-re2` shim. Code changes are three env overrides so the
  store can live on a volume and a bundle still records its revision without
  a `.git` directory: `CTIPARSOR_DB_PATH`, `CTIPARSOR_DB_BACKUP_DIR`
  (`api/db.py`, which now creates the parent directory) and
  `CTIPARSOR_GIT_REV` (`api/run_config.py`, git wins when present);
  `scripts/check_stages.py` resolves its paths from the repository root.
  New: `docs/docker.md`, `make docker-build|up|bootstrap|smoke|logs|down`, a
  CI job that builds the image and runs the smoke test,
  `tests/test_container_env.py`.

- **The API warns at startup if Chromium isn't installed, instead of failing
  on the first URL capture.** `pipeline/web_capture.py` already had a precise
  diagnostic for this (`_launch_hint`, "Chromium is not installed for the
  account running this API…") but it only fired reactively, the first time
  an analyst tried the URL-ingestion tab — a service that had been running
  for hours could still be missing the browser and nobody would know until
  a request failed. `check_chromium_installed()` resolves Playwright's
  expected executable path (via `sync_playwright().chromium.executable_path`)
  and checks the filesystem, without launching a browser or touching the
  network; `api/main.py`'s startup `lifespan` hook runs it once off-thread
  (`asyncio.to_thread` — Playwright's sync API refuses to run on a thread
  already driving an asyncio loop, which the hook's coroutine is) and logs a
  warning if it's missing. A second, unrelated bug surfaced while building
  this: `sync_playwright()`'s own connection teardown logs a spurious
  `asyncio` "Task was destroyed but it is pending!" on every call, at a
  GC-determined moment a `try/finally` cannot bracket — worked around by
  raising the `asyncio` logger's level for the remainder of the process,
  since this check runs exactly once, at boot, before any request is served.

- **Proposed Detections highlights the report evidence inside the rule body.**
  Opening a rule's detail previously showed its raw text with no connection
  to *why* it was proposed — the evidence chip lived only in the row above.
  The rule-body drawer now reuses `buildRanges` (the same whole-token,
  defanged-IOC-aware, hash-line-wrap-tolerant matcher already driving the
  report text viewer) to find and `<mark>` every matched value directly in
  the rule text, colour-coded to match its observable type and titled with
  the rule field it matched. Verified in-browser against a real report: the
  drawer for `WEBSHELL_PHP_Dynamic_Big` correctly highlights `"backdoor"`
  inside its `strings:` section.

- **`setup.sh` installs Node.js instead of printing instructions.** A fresh
  WSL2 run stopped at "Node.js not found — web UI build unavailable", left the
  operator to paste a NodeSource one-liner, and the web UI never got built.
  Step `[1b/6]` now asks *Install Node.js 24 from NodeSource now?* (default
  yes, like every other step) and installs it through apt, dnf or yum;
  `--no-node` skips it. Node 24 is the current Active LTS — Node 20, which the
  old hint named, reached end-of-life on 2026-04-30. The NodeSource script is
  downloaded to a file before it runs, because `curl | bash` with a failed
  curl feeds bash an empty script that exits 0, and every step is checked
  explicitly because `set -e` is off inside an `if`. Verified with a stub
  harness (fake `sudo`, `curl`, `apt-get`) across seven scenarios: fresh
  install, curl failure, apt failure, `--no-node`, answering no, Node already
  present, and Node too old then upgraded.

- **All three detection formats are enabled by default, and ET Open is
  fetched.** `detection_corpora.yaml` shipped the five YARA and two Suricata
  corpora of ADR-0015 as `enabled: false` ("until the adapter lands") long
  after the adapters had landed, so a fresh clone built a Sigma-only store and
  the only way to the other two formats was the Settings page, one corpus at
  a time. Flipping the flag was not enough: ET Open is published only as a
  tarball, and the `tarball:` registry source ADR-0015 §5 promised was never
  implemented — `sync_corpora.py` skipped it as "managed manually" and the
  Settings *Redownload* button answered 400.

  `pipeline/detection/sync.py` gains `fetch_tarball`: download, verify
  against the `.md5` sidecar ET publishes (a mismatch keeps the previous
  copy), extract only regular files and directories that resolve inside the
  target (no links, absolute names or `..`), swap a staging directory into
  `path`, and record URL, sha256, md5, size and fetch time in
  `<path>/.sync.json` — the "URL and content hash" the ADR asked for in place
  of a git revision. The CLI and the Settings button share it. Eleven tests
  cover it; two were mutation-checked (dropping the member filter, then the
  checksum comparison, each fails its test).

  Measured on 2026-09-09: the tarball came down as 5,604,389 bytes / 62
  files, md5-verified, carrying 52,196 active rules (the ADR counted 51,799
  on an earlier drop). Ingesting the seven corpora into a scratch store
  (`scripts/measure_corpus_ingest.py`, new) took 25 s: YARA 23,065 rules
  (16,473 canonical, 12,724 hash atoms, zero ATT&CK tags), Suricata 52,878
  rules (27,643 tagged onto 45 techniques, 24,586 IP atoms). On top of the
  11,464 Sigma rules that is ~87,400 rules, 7.6× the old default — within 2%
  of the 85,677 ADR-0015 projected. `setup.sh`'s corpora step says so; the
  README, `docs/detection-coverage.md` and ADR-0019 no longer describe the
  tarball fetch as future work.

- **Offline (air-gapped) installation bundle** (ADR-0040). `setup.sh` fetches
  from twelve network sources — apt, NodeSource, PyPI, HuggingFace, GitHub
  (MITRE, spaCy, Ollama), fourteen git remotes plus rules.emergingthreats.net,
  Playwright's CDN and npm — and a SOC network that reaches none of them had
  no install path. `scripts/package_offline.sh`, run on a connected twin of
  the target (same release, same Python major.minor), fills `offline/` with
  the wheelhouse, the full apt closure (Node.js included), the HuggingFace
  models, Chromium, the MITRE bundles, the corpora, the built UI and an
  Ollama runtime with the `.env` model pulled, writes `bundle.env` +
  `SHA256SUMS`, and packs it with the source tree. `setup.sh
  --offline=<dir>` verifies the checksums and the Python/distro match before
  touching the host, installs the `.deb`s with `dpkg`, then runs its ordinary
  steps with `PIP_NO_INDEX`/`PIP_FIND_LINKS` and `HF_HUB_OFFLINE` exported and
  the bundle's files pre-staged, so each step's own "already present" branch
  fires instead of the network (`scripts/offline_lib.sh`; twelve small hooks
  in `setup.sh`). `scripts/check_offline_bundle.sh` replays an install from
  the tarball in a scratch `HOME` with every proxy pointed at a closed port
  and `sudo`/`dpkg` stubbed, then checks the venv, the model loads, the
  indexes, the rule store, Chromium and Ollama. Size was explicitly not the
  constraint: CUDA wheels and the LLM stay in.

  Measured on 2026-09-09 (Ubuntu 26.04, Python 3.14): first build 30 min 51 s,
  a 13.9 GB tarball — Ollama + `mistral` 5.5 GB, wheels 3.1 GB (torch and 15
  `nvidia_*` wheels are 2.7 GB of it), models 2.6 GB, Chromium 655 MB, corpora
  663 MB, 457 `.deb` 388 MB, `node_modules` 242 MB, MITRE 65 MB; 1,314
  checksummed files. The replayed install took 713 s and passed 17 of 18
  checks; the two failures were real and are fixed: GLiNER fetches its
  encoder's tokenizer (`microsoft/deberta-v3-large`) from the Hub at load
  time, so the packager now ships those files (2.4 MB) next to the model, and
  `.env`'s bare `TTP_EMBEDDING_MODEL=all-MiniLM-L6-v2` gets the
  `sentence-transformers/` prefix the runtime adds silently (the Hub answers
  401 without it). The rule store built offline holds the same 87,407 rules
  as the online path. Ollama served the staged `mistral` (7.2B Q4_K_M) from
  the extracted runtime and found the workstation's GPU on its own. The
  rebuilt bundle replayed at 18 of 18 checks in 706 s.

### Added

#### Detection rules embedded verbatim in a report become Indicator SDOs, 2026-09-14

CTI vendor reports routinely publish a literal YARA, Suricata/Snort, or Sigma
rule alongside their write-up — verified on a real Google Threat Intelligence
Group report, which embeds 4 complete YARA rules — and none of it survived
past ingestion as anything more than prose. STIX 2.1 already models this
(`Indicator.pattern_type` = `"yara"`/`"suricata"`/`"snort"`/`"sigma"`,
`pattern` holding the rule verbatim), so `build_stix_bundle` now extracts and
represents them: YARA via `yara_atoms.split_rules` and Suricata/Snort via
`suricata_atoms.rule_header`/`parse_options` (both existing, corpus-scale-
validated ADR-0015 parsers, reused unchanged), Sigma via a new grow-then-
shrink YAML boundary heuristic (fail-closed — a candidate that never parses
as valid `title`+`detection` YAML yields nothing). Each rule auto-links to an
already-extracted malware/tool whose name appears in its own title. Verified
end to end on the real report (`re_run_final_stages`, zero LLM cost): all 4
YARA rules became Indicators, correctly linked to their malware. One honest
finding along the way: 2 of the 4 also linked to `backdoor`/`tunneler` —
Stage 2d (CyNER) had mistagged those generic category words as malware names
for this job, a pre-existing defect in a different stage that this feature
surfaced rather than caused. See
[ADR-0042](docs/adr/0042-embedded-yara-rules-as-indicators.md).

### Fixed

#### Observables reached malware/threat-actor SDOs directly, bypassing their Indicator, 2026-09-14

Stage 4 already built the STIX 2.1 best-practice chain (`SCO ◄ ObservedData ◄
Indicator`) for every accepted IoC, but nothing stopped the raw SCO itself
from also becoming the direct endpoint of a `Relationship` to a threat SDO.
Two independent paths did this: the LLM relationships loop (only
observable↔attack-pattern was ever guarded) and the Relationship Policy's pin
engine — the larger source, per ADR-0024's own measurement of 872/1,140 edges
on one report. Re-running Stage 4+5 for a real stored job
(`re_run_final_stages`, zero LLM cost) turned 2 raw `file --related-to-->
malware` edges into 0, rerouted through 40 `indicator --indicates--> malware`
edges instead. A related gap is closed in the same change: `NETWORK_TRAFFIC`
entities got a placeholder `Software` SCO but silently never got an
Indicator, which would have made every network-traffic relationship simply
vanish under the new rule instead of being fixed by it.

Scoped deliberately to observable↔non-observable-SDO pairs only —
observable-to-observable edges (`file related-to ipv4-addr`, the majority of
what was actually measured) are left alone, since STIX 2.1's real answer for
those is per-SCO-type embedded ref properties, a separate piece of work. See
[ADR-0041](docs/adr/0041-observables-route-through-indicators.md).

#### Stage 2d fed whole documents to DeBERTa and the OOM killer took the worker, 2026-09-03

`extract_cyner_entities` called the HuggingFace token-classification pipeline
once with `text[:50_000]`. DeBERTa-v3 uses relative positions, so an input far
beyond its 512-token window does not raise — it runs, and attention memory
grows with the square of the token count. Measured: the worker reached
10.3 GB resident on a 27 KB report and 15.5 GB on a 77 KB report
(`CERT_Polska_Energy_Sector_Incident_Report_2025.pdf`, capped to 50 K chars),
both a few seconds after "CyNER model loaded", and `dmesg` records the
SIGKILL. The 50 K cap was the wrong knob: it bounds the input, not the square.

Stage 2d now chunks like Stage 2e already did — ~1 600 characters with a
200-character overlap (`CYNER_CHUNK_CHARS`, `CYNER_BATCH_SIZE`), one batched
call, and a dedup of the spans the overlap re-reports. Two regression tests
lock it: `test_long_text_is_chunked_before_inference` fails when the window is
forced back to a single call (verified by running it with
`CYNER_CHUNK_CHARS=100000000`), and the chunker is checked for coverage,
empty pieces and unbroken tokens.

### Architecture

#### ADR-0039 — per-stage observability, 2026-09-02

Filed `docs/adr/0039-per-stage-observability.md`. The pipeline has 18 stage
modules and 6 of them report anything to the API; the stages that change the
data most report least. Stage 3d deletes every relationship whose supporting
sentence the model cannot quote and Stage 4b adds up to 200 edges, and neither
emits a progress event — although both already compute the numbers (`removed
N/M`, `CompletionStats`) and discard them. Measured alongside: all 209
`logger.*` call sites render `[none]` as the request id, because the worker
subprocess never calls `set_request_id`; `LOG_FILE` defaults to empty so a
detached run keeps no record; `traceback.format_exc()` is computed and then
only `str(exc)` is stored; a job killed by a signal does not say which stage
it died in (establishing that four jobs died at the first Stage 3 LLM call took
seven manual greps of stdout); and the dashboard progress bar is
`(stage / 5) * 100`, which hardcodes the stage count, weights a millisecond
stage the same as a four-minute one, and evaluates to `NaN` for the figures
stage because its id is the string `"1f"`.

Decision: a typed `job_stages` table written through a single `stage_span`
context manager that sets the job id on the log context (fixing all 209 call
sites without editing them), times the stage, writes the row, emits the
progress event, and records the failing stage plus its full traceback. Plus
`STAGE_PLAN` as one weighted source of truth for the progress bar,
`GET /api/jobs/{id}/stages`, stage attribution for signal deaths, and
retention for the two event tables, which have none today.

Both ADRs were then confronted with external practice (OpenCTI rules engine
and issue #174, GRID and ANCHOR 2026, AZERG 2025, txt2stix, Prefect run
states, OpenTelemetry GenAI conventions, MLflow tracing) and each carries a
dated confrontation section. Two amendments came out of it: ADR-0038 makes the
`uses∘exploits → targets` composition opt-in, because it is the shape OpenCTI
shipped and retracted as a bug; ADR-0039 adds a `crashed` status distinct from
`failed` and names Stage 3 detail keys after the OTel GenAI attributes.

#### ADR-0038 — link density under policy, and an ADR status refresh, 2026-09-02

Filed `docs/adr/0038-link-density-under-policy.md`. It answers "how do we get
more links between objects without loosening the evidence gate" by enumerating
where every edge can come from and finding two accidents rather than
decisions (the before/after run itself is recorded as a procedure: on this
workstation the WSL distro terminates at the first Stage 3 LLM call, seven
attempts across API, CLI and both providers — the numbers are to be produced
on the Linux host): the factory relationship policy has **no rules** while the Policy
page displays 27 (nothing seeds the database, so on a fresh install Stage 4
materialises nothing from the model the page shows), and `gap`-labelled
relationships are requested from the LLM and then deleted by Stage 3d. The
decision moves the default rule set into the backend, keeps `gap` edges under
their label, makes Stage 4 endpoint resolution alias-aware, replaces the
shared "first 200 then stop" caps with per-node fan-out caps, and binds
long-distance completion to a local model when one is configured.

New instrument: `scripts/measure_graph_links.py` (stdlib, read-only) reports
per bundle the node/edge counts, isolated nodes, connected components, edges
by evidence label and by source tag, and the number of unlinked node pairs
that share a sentence — the pool a policy rule can reach.

**ADR status refresh.** Nineteen ADRs still said *Proposed* although their
code has been on `main` for weeks (0015–0022, 0024–0033); each now carries
`Accepted (implemented)` and a dated *Status review* section naming the
module or route that implements it. 0007 is accepted for slice 1 only, 0023
for Phases 1–2 only, 0037 is superseded in part by 0036, and 0002, 0004 and
0013 keep their status but gain a review note where the text no longer
matched the code (open pool items, the opt-in SecureBERT default, the Graph
page that never learned to draw inferred edges). The README index follows.

Also: README documents the empty factory default.


### Security

#### The ReDoS guard becomes real: `google-re2`, and actually called (ADR-0049), 2026-09-16

A routine Docker build warning — the optional `re2>=0.2.20` package failing to
compile its Cython wheel on Python 3.12 — led to a second, more serious
finding: `pipeline/stage2_extraction.py::_compile_pattern`, the function
`setup.sh` and this changelog's own earlier entries described as giving
Stage 2 "guaranteed linear time," **was never called**. All 19 module-level
compiled patterns went straight to `re.compile()`. A working `re2` install
would have protected nothing — the gap was two bugs, not one, and nobody has
had the guarantee since Python 3.12 became current, host installs included.

Fixed both. Switched to `google-re2` (prebuilt wheels for cp312+, no C++
toolchain, no `libre2-dev`/`libre2-9` — `ldd` confirmed it statically bundles
RE2, so those apt packages came out of the Dockerfile too) and wired every
pattern through `_compile_pattern`, which now maps the three `re` flags this
codebase uses (`IGNORECASE`, `MULTILINE`, `DOTALL`) onto RE2's inline
`(?ims)` prefix syntax — `google-re2`'s `compile()` rejects raw `re` flag
integers.

Checking which patterns actually ended up on RE2 (rather than assuming the
flag mapping covered everything) found 7 of the 19 sub-patterns —
`_HASH_BLOCK_PATTERN`, `_IPV4_PATTERN`, `_DOMAIN_PATTERN`,
`_BARE_FILENAME_PATTERN`, `_UNIX_PATH_PATTERN`, and the `sha1`/`md5` entries
of `_HASH_LABEL_PATTERNS` — use negative lookaround (`(?<!...)`, `(?!...)`),
which no non-backtracking engine can parse, RE2 included. These 7 stay on
stdlib `re` regardless of whether `google-re2` is installed. Stress-tested
each against adversarial input (5,000–8,000 repeated ambiguous units) under
plain stdlib backtracking: all completed in under 11 ms — none has the
nested-unbounded-quantifier shape that makes backtracking actually
exponential, so this is a checked, not assumed, residual gap.

Validated against the 9 real reports already ingested into `cti_stix.db`
(228,651 chars of `report_text`): `extract_entities()` returned the same 501
entities and `refang()` the same output whether `_RE2_AVAILABLE` was true or
patched false. `tests/test_re2_guard.py` (6 tests) locks the type of a
compiled pattern, the flag mapping, and the re2-vs-fallback identity. Full
suite: 1208 passed / 14 skipped on SQLite, 1216 passed / 6 skipped on
PostgreSQL — 0 failures on either engine. See
[ADR-0049](docs/adr/0049-redos-guard-actually-wired-in.md).

#### Seven npm advisories cleared by two major upgrades, 2026-09-02

`npm audit` on `frontend/` reported **7 vulnerabilities — 1 critical, 1 high,
5 moderate**. All seven came from two roots, and the dependency *tree* mattered
more than the version numbers did.

*The vite findings were not about our vite.* The top-level `vite` was already
`6.4.3`, outside the advisory's `<=6.4.2` range. Every vite and esbuild finding
— the high (path traversal in optimized-deps `.map` handling, `server.fs.deny`
bypass on Windows alternate paths, launch-editor NTLMv2 hash disclosure) and
the esbuild dev-server CORS moderate — came from the private `vite@5.4.21`
subtree that `vitest@2.1.9` carried under `node_modules/vitest/node_modules/`.
Reading the audit top-level would have suggested the wrong fix.

`vitest` 2.1.9 → **4.1.11** (critical: arbitrary file read and execution while
the Vitest UI server listens) collapses five of the seven findings at once. The
two-major jump is a no-op for this suite: the config uses only `environment`,
`globals`, `setupFiles` and `include`, none of them touched by the v3/v4
removals, and the tests use only `vi.fn`, `vi.spyOn`, `mockImplementation` and
`restoreAllMocks`. **69/69 tests still pass, no test file changed.** Vitest 4
now shares the top-level `vite@6.4.3` rather than vendoring its own, so
`vite-node` leaves the tree entirely and one `esbuild@0.25.12` remains.

`react-router-dom` 6.30.6 → **7.18.3** clears the remaining two (CVE-2025-68470
bypass: open redirect via backslash in `<Link>`/`useNavigate`; arbitrary
constructor injection in `deserializeErrors()`). **Neither was reachable here**,
and the entry says so rather than claiming a hole was closed: the app is a pure
`BrowserRouter` SPA with no SSR hydration, and every navigation target is a
literal-prefixed template (`/review/${jobId}`, `/graph/${jobId}`) or a bare
literal — the backslash bypass needs a value that *begins* with `\`. The
upgrade is worth taking on its own terms, not as an incident. The v7 API
surface this app uses — `BrowserRouter`, `Routes`, `Route`, `Navigate`,
`NavLink`, `Outlet`, `Link`, `useParams`, `useNavigate` — is unchanged, so
`tsc && vite build` passed first try with no source edits.

Cost: the main chunk grew 1,130.95 → 1,146.90 kB (gzip 336.68 → 342.24 kB).

Two traps worth recording. `npm install --save-dev vitest --save react-router-dom`
applies `--save-dev` to **both** packages: `react-router-dom` silently landed in
`devDependencies`, where a runtime dependency would have survived every local
check and broken a production install. Fixed with `--save-prod`. And the whole
drift was invisible because **CI has no frontend job** — `ci.yml` builds and
tests Python only, so `npm run build`, `npm test` and `npm audit` have never run
there.

`frontend/src/test/dependencyAudit.test.ts` locks the result: it walks *every*
`node_modules` directory to a depth of 12, not just the top level, and fails on
any copy of `esbuild`, `vite`, `vite-node`, `vitest`, `@vitest/mocker`,
`react-router` or `react-router-dom` at or below its known-vulnerable version.
It also asserts the watched packages are present at all, so an empty or moved
tree fails loudly instead of passing vacuously.

Verified by reintroducing the defect rather than by trusting the green run:
reinstalling `vitest@2.1.9` makes it fail with all seven copies named, five of
them nested two levels deep (`node_modules/vitest/node_modules/vite@5.4.21`,
`node_modules/vite-node/node_modules/esbuild@0.21.5`, …) — precisely what a
top-level check would have missed.

Reading `node:fs` from a test needs `@types/node`, which the project had never
had; without it `npm test` stayed green (Vitest transpiles without checking
types) while `npm run build` failed on three `TS2307`s. Added at `^20` to match
the Node 20 line `setup.sh` and CI target, rather than a major that would inject
globals for a runtime nobody runs. It is type-only: the emitted bundle is
byte-identical. Nothing else in `src/` broke, because every stored timer handle
already used the portable `ReturnType<typeof setTimeout>` rather than `number`.

### Fixed

- **Registry keys no longer fail STIX validation, and no longer carry half a
  sentence.** Three `[X]` errors on a delivered bundle, all
  `windows-registry-key`: `HKLM\SYSTEM C`, `HKLM\SECURITY C`, `HKLM\SAM C`.
  Two independent defects stacked on the `reg save` credential-dump triple
  (T1003.002).

  *Illegal hive.* The STIX 2.1 schema puts a `not` pattern on
  `^HKLM|HKCC|HKCR|HKCU|HKU` — the hive must be spelled out — and Stage 4
  handed the extracted value straight to `stix2.WindowsRegistryKey`. **Every**
  report mentioning `HKLM\…` failed validation, not just this one. Now expanded
  through `_expand_registry_hive` in both the SCO and the Indicator pattern, so
  the two agree. Deliberately *not* expanded in Stage 2: entity values have to
  stay findable in the displayed document text for click-to-locate, and
  `HKEY_LOCAL_MACHINE\…` appears nowhere in a report that wrote `HKLM\…`.

  *Swallowed text.* `_REG_KEY_PATTERN`'s segment class excludes `\`, `:`, `"`,
  `|`, `<>` and control characters but not the space, so the last segment runs
  to end-of-line. Measured on the real strings: `reg save HKLM\SYSTEM
  C:\windows\temp\sys.tmp` yielded `HKLM\SYSTEM C`, and
  `…\Winlogon was set.` yielded `…\Winlogon was set.` — the second case is the
  common one and was missed on the first pass. Banning the space was rejected:
  real keys contain them (`Windows NT`, `Windows Defender`). The regex is
  unchanged; two post-processing passes trim instead — prose (a fragment not
  starting upper-case or a digit) and a single-letter drive before a colon,
  which is what separates `C:` from `NT:`.

  Both defects are locked by re-introducing them: neutering the Stage 2 trims
  fails 5 tests, neutering the hive expansion fails 7.

### Added

- **A stored bundle now says which pipeline built it, and the audit says when
  that is stale** (ADR-0035). The self-edge fix shipped on 2026-08-28, yet six
  `source_ref == target_ref` relationships still ride in two delivered bundles,
  because a bundle is never rebuilt on its own. `jobs.run_config_json` already
  recorded the `git_rev` of every run and nothing read it;
  `pipeline/bundle_revisions.py` now compares it against a hand-kept list of
  output-affecting revisions, and `scripts/audit_bundle_invariants.py` reports
  the result. All 13 stored bundles are flagged, across 5 distinct revisions.

  Reported, never repaired automatically — a delivered artefact must not mutate
  under an analyst who cited it. The repair is the existing
  `POST /api/jobs/{id}/finalize`, which re-runs Stages 4–5 from the accepted
  entities at **zero LLM cost**. Comparing against `HEAD` was rejected: it marks
  every frontend commit as invalidating and so never returns to green.

- **`VISION_CONCURRENCY`** — how many figure reads Stage 1f keeps in flight.
  Ollama sits at 1 against 4 for the API backends. ADR-0033 §5 put it there
  because the single GPU is shared with other local workloads;
  measurement now supplies an independent second reason and the value stays:
  raising it to 4 did overlap the work (per-call times summing to 1392.7s inside
  737s of wall clock, **1.89x**) but inflated each call from ~43s to ~127s, so
  throughput per figure got *worse* — 40.9s against 36.3s. A figure read ships a
  600–2400 token image and generates hundreds of tokens back, so four in flight
  contend for memory bandwidth rather than filling an idle pipe. The override
  exists for hosted endpoints, where the arithmetic differs.

- **`scripts/measure_figure_iocs.py`** — read-only harness asking whether the
  vision model's `iocs` are grounded in its own `verbatim_text`.

- **Figures in CTI reports can be read, not just skipped** (ADR-0032, ADR-0033).
  A geometric triage keeps the 141 real figures out of 341 images across the
  corpus — **56.9% are icons and logos, discarded before any model is involved** —
  crops each one, and transcribes it into `report_text` between `⟦figure n⟧`
  sentinels so every downstream stage works unchanged. One FortiGate console
  screenshot in the CERT Polska report carries three techniques the text layer
  never states; one Ukrainian lure page carries a payload filename found nowhere
  else.

  Crops, never whole pages: a 1:15 web-capture sheet is 105 pixels wide after any
  long-edge normalisation, which is why the local model returned empty JSON after
  100 s and the Anthropic API returns a 400. On real figures a crop costs 977
  input tokens against 2 191 for its page, runs ~5× faster, and gets the
  `figure_kind` right where the page returns one blanket verdict for three
  figures.

- **Attack-chain diagrams become relationships in the graph and the bundle.**
  A figure classified `attack-chain` or `network-diagram` has its connectors
  rendered into `report_text` as `src -> dst` lines, inside the figure's own
  block. Stage 3 then extracts them with the evidence contract it already has,
  so they pass Stage 3d verification and Stage 4 mapping like any other
  relationship — nothing bypasses a hallucination gate.

  Measured on `silkparasite-tracking-a-china-nexus-apt-across-central-asia`,
  whose twelve figures include seven attack-chain diagrams: **35 arrows that were
  previously dropped** now yield **26 relationships, 24 of them with evidence
  inside a figure block** — seven complete DLL-sideloading chains
  (`mpclient.dll → DriveSilkRAT`, `tak_deco_lib.dll → CookiETagRAT`,
  `dsp_ippv2_x64.dll → BloodAlchemy`, …) that appear nowhere in the report's
  text, which on its own yields only 4 extra observables.

- **`VISION_PROVIDER` / `VISION_MODEL`** — a vision backend for `anthropic`,
  `mistral` or `ollama`, deliberately separate from `LLM_PROVIDER`. None of the
  Stage-3 Ollama models can see (`mistral`, `mistral-nemo`, `llama3.2` are all
  text-only), and a text model handed an image does not error — it invents. The
  model is probed for image support before a single figure is sent;
  `python -m pipeline.vlm` reports what the current environment resolves to and
  why, without starting the pipeline.

- **Proposals can be promoted into the coverage selection.** Each row in
  *Proposed detections* gains an **Add** checkbox; ticked rules join the coverage
  selection, the format-board counts and the export. They need it: measured on
  the ShinyHunters report, **199 of the 200 proposals are outside the coverage
  set**, so before this the panel could rank a rule an analyst had no way to act
  on. Promotions persist per job under `coverage.promoted.{jobId}` — a set of
  ADDITIONS, deliberately separate from `coverage.selection.{jobId}`, which holds
  exclusions.

- **A rule's body can be read before trusting its rank.** Clicking a proposal's
  title opens a side drawer with the rule text, its ATT&CK tags, its source link
  and its licence. Bodies are capped at 20,000 characters with the rest one click
  away — the mthcht corpus averages ~176 KB per rule and one measured **825,817
  characters**. The licence is shown prominently rather than in the metadata
  line: `none` means ALL RIGHTS RESERVED, usable locally and not redistributable.

- **`POST /api/rules/lookup`** — metadata for arbitrary canonical rule ids, and
  their bodies on demand (`include_body`, capped at 500 ids). Deliberately not
  job-scoped: the proposals panel shows rules outside the report's tag join by
  construction.

### Fixed

#### A report submitted while the workers are busy is no longer thrown away, 2026-09-01

When `WORKER_MAX_CONCURRENT` was reached, the job was marked `queued` and then
handed a `done` progress event. The frontend reads `done` as "this report is
finished", so the analyst saw a completed job that had never run, and nothing
ever picked it up: `queued` was written in four places and **read nowhere in
`api/`**. It was never a broken queue — it was a queue with no consumer.

The bug was written twice, and only one copy could fire. The check in
`_run_pipeline` runs inside the spawned subprocess, which holds its own fresh
copy of `_job_counter` starting at zero, so it always passed; that copy is
deleted. `run_pipeline_async` now emits a `queued` event, never `done`, and
returns `"started"` / `"queued"` / `"rejected"`.

The consumer is the watcher thread that already waits on each subprocess: after
it releases the slot it claims the next waiting job, atomically, with
`UPDATE jobs SET status='processing' WHERE id=? AND status='queued'` and a
`rowcount` check — two watchers finishing together cannot take the same job. A
job whose upload has vanished is failed rather than retried forever. On startup
`requeue_orphans()` returns anything left `processing` by a restart to the
queue, so a redeploy no longer strands work in a state nothing finishes.

`API_QUEUE_MAX_DEPTH` (default 50, 0 = unbounded) bounds the wait: beyond it the
upload is refused with HTTP 503 instead of being accepted and dropped. The
`status` field of `/api/upload` and `/api/ingest/*` still reads `processing` for
work that started; only the genuinely new case reports `queued`.

Deliberately not adopted: Celery, RQ and ARQ. The first two default to `fork`,
which deadlocks against Torch's OpenMP pool — the reason `spawn` was chosen here
in the first place — and ARQ is asyncio, which does nothing for work bounded by
CPU and 4.4 GB of resident weights. ADR-0002 reached the same conclusion in June
and its action items are still open; ADR-0036 records why.

`scripts/measure_cold_start.py` measures what a worker actually pays at startup
(imports, model loads, peak RSS) and suggests a pool size from the host's RAM.
It refuses to suggest one when any step fails, and exits non-zero: a partial run
leaves the peak RSS at the cost of the bare imports, and the formula then
recommends a pool several times too large — measured 16 on a 15 GB host where
the answer is 2.

#### The frontend builds from Linux again, 2026-08-30

`frontend/node_modules` had been installed from Windows, leaving
`@rollup/rollup-win32-*` plus `.bin` shims that `exec node.exe`, so
`npm run build` under WSL died with `exec: node.exe: not found`. The error reads
like a PATH problem and is not: the shim's fallback tests `[ -x node ]`, a
*file* test on a bare name that never consults PATH, so it falls through to
`node.exe` and fails.

Reinstalled with `npm ci` from WSL — Linux is the deployment target `setup.sh`
supports, and the two platforms cannot share one `node_modules`. `npm run build`
(tsc + vite, 33s) and `npm test` (9 files, 69 tests) are both green from WSL.

#### `iocs` is a cross-check, not an extraction path (ADR-0032 amendment)

§3 of ADR-0032 described the vision model as returning "observables", which
reads as though they were extracted; `render_block` never injected them.
Measured over two production runs — the first time Stage 1f ran through
`read_figures` at all — **63 of 64** listed IoCs were already in the
transcription, so injecting the list buys almost no recall.

The one that was not is a phishing URL the model transcribed twice and garbled
differently each time (`accounts.gooq e.com/A3/signin/?de=ntifier?...`), so
injecting it would have added a domain that does not exist to the bundle as an
Indicator, with no stage able to catch it. The same amendment corrects its
predecessor: `render_block` *does* call `render_edges`, so diagram arrows have
reached STIX since `a390bae`.

#### Documentation caught up with the code, 2026-08-30

Stage 1f was wired into `api/worker.py` and absent from the README, which
mentioned "figure", "vision" and "VLM" zero times. Also added: six undocumented
REST endpoints, three missing tables and five missing columns in the schema,
seven undocumented dependencies including the `requirements-optional.txt` that
carries Playwright for the URL capture the README already documented, and a test
count stale by a factor of 1.8 (571 → 1047 across 64 modules). `pytest.ini`
gained `testpaths = tests`, so a bare `pytest` no longer collects 14 tests
vendored under `corpora/sigmahq/`.


#### Duplicated logic folded into shared helpers, 2026-08-29

An AST clone scan over `pipeline/`, `api/` and `models/` (560 functions, 76
files) found four groups of exact clones and four near-duplicate pairs. Seven
were folded; the rest were left alone with a reason. Net **−258 / +70** lines
across 22 files, plus four small shared modules and a behaviour-lock test file.

- **One vocabulary for boolean environment flags** (`pipeline/env_flags.py`).
  Seven call sites each parsed their flag differently — `== "1"`,
  `in ("true","1","yes")`, `not in ("false","0","no")`, `!= "true"` — so
  `ENABLE_CONSENSUS=1` left consensus **off** while `ENABLE_STIX_VERIFICATION=1`
  turned verification **on**. Worse, `api/run_config.py` answered with a *third*
  vocabulary and wrote that answer into the bundle's provenance block, so a run
  could be recorded as `consensus: true` when stage 3e never ran — the exact
  failure ADR-0024 Phase B added the run config to prevent. Those three entries
  now call the stages' own predicates (`verify_enabled`, `consensus_enabled`),
  the way the other four already did.

  `scripts/check_flag_equivalence.py` compares the old and new semantics for all
  eight flags across 32 values and reports every divergence. Verdict: **no
  documented configuration changes behaviour**. Two undocumented spellings do —
  `CYNER_ENABLED=off` and `GLINER_ENABLED=off` used to leave the stage *enabled*
  and now disable it, which is what the operator asked for.

- **The worker no longer merges Stage-2d entities with its own copy of the merge.**
  `_merge_cyner_into` was byte-identical to `BaseExtractionStage.merge_into` —
  the helper `pipeline/base.py` exists to stop stages reimplementing — and it was
  the copy production ran, since the worker calls Stage 2d directly rather than
  through `StageRegistry.run_all`. The two tests locking `merge_into`'s
  intra-batch dedup fix covered only the unused one.

- **`_parse_verification_response`** was duplicated between `stage3d_verify` and
  `stage3f_ttp_verify`, identical bar one docstring line, and is now
  `pipeline/llm_parse.parse_numbered_claims`.

- **`_unescape_content` / `_unescape_literal`** shared a 25-line single-pass
  decoder differing only in their escape table; both now call
  `pipeline/detection/textutil.unescape`, keeping their names so
  `tests/test_escape_unescaping.py` still locks the behaviour.

- **The STIX dict-or-attribute accessor** existed four times across stage 4, 4b
  and 4c (`_field`, `_otype`, `_type`, `_name`); one `pipeline/stix_access.field`
  now backs all of them.

- **The `404 Job not found` guard** was repeated verbatim in ten handlers across
  four route modules, now `api/routes/_common.require_job`. It takes the caller's
  open connection rather than being a FastAPI dependency, which would have added
  a second SQLite connection per request.

- **`usePref`** was copy-pasted into `ThemeContext.tsx` and `Review.tsx`; it is
  now `frontend/src/hooks/usePref.ts`.

A second pass then covered `scripts/`, which the first scan had skipped:

- **`audit_store_invariants.py` held six copies of one invariant.**
  `check_atoms_orphan`, `check_techniques_orphan`, `check_related_orphan`,
  `check_rule_bytes_missing`, `check_entity_orphan_job` and
  `check_relationship_orphan_job` were the same 21-line query shape — count the
  rows of a child table whose foreign key resolves to nothing, sample three,
  wrap in a `Finding` — differing only in table and column names. They are now
  one `_check_orphan(conn, name)` driven by an `_ORPHAN_SPECS` table, 639 → 569
  lines. `rule_bytes.missing` runs the relation the other way round (rules with
  no bytes row) but is the same shape, so it moved into the table too. Table and
  column names are interpolated into the SQL — SQLite cannot bind an
  identifier — so each is checked against `^[A-Za-z_][A-Za-z0-9_]*$` first.

  Verified by diffing the script's full output against the pre-refactor run:
  identical, all 16 invariants, character for character.

- **The two `_split_sentences` now have different names.** `stage2c` unwraps
  PDF hard-wraps and drops segments of 20 characters or fewer; `stage4` splits
  on a regex and keeps everything non-empty. One name for two incompatible
  notions of "sentence", in the same pipeline, where the indices of one do not
  address the segments of the other. They are now
  `_split_candidate_sentences` and `_split_evidence_sentences`. Not a
  deduplication — the opposite: making two things that were never the same stop
  looking interchangeable.

A third pass covered `frontend/src`, which no clone detector had ever seen — the
Python one is an AST walker and stops at `.py`. An equivalent built on the
TypeScript compiler API found the frontend far cleaner than the backend: four
small exact-clone groups over 272 functions. Two were worth folding, into
`frontend/src/hooks/sets.ts`:

- **`persist` was duplicated between `usePromotedRules` and `useRuleSelection`**,
  identical bar the storage key, and each carried its own comment describing the
  same bug: persisting from a `useEffect` fires on the mount pass while the
  closure still holds the initial empty set, so it wrote `[]` over the value
  just loaded. Two copies of a fix whose justification had to be written twice.
  Both now call `saveStringSet` / `loadStringSet`.

  `useRuleSelection` also read its stored value with a bare
  `JSON.parse(raw) as string[]`, where the sibling validated the shape. The
  shared loader keeps the stricter guard, so a corrupt or hand-edited entry now
  yields an empty set instead of a `Set` of non-strings.

- **The "toggle an id in a `Set`" updater appeared three times in
  `Marginalia.tsx`** and once more inside `usePromotedRules.toggle`, always the
  same five lines. Now `toggleInSet`.

**A test that did not lock what its comment claimed.** Making `saveStringSet` a
no-op — removing persistence outright — left all three tests in
`useRuleSelection.test.ts` green. All three assert that something is *never*
written, so they pass trivially when nothing is written at all. A positive test
was added (`writes the exclusion to this job's key when one is toggled`) and
verified to fail against that mutant.

Frontend: 69 tests pass (up from 56), `tsc --noEmit` clean, −77/+35 lines.

Deliberately **not** merged: the three `_normalize` / `_add` atom extractors
(their per-class rules have diverged, and unifying them silently changes what the
atom index holds — it needs a measured before/after first); `store.py`'s two
chunked technique queries (the `EXISTS`-vs-`JOIN` split is documented and
measured); `_merge_gliner_into` (it has real high-precision-source logic on top);
and `_strip_quotes` / `_unquote` (one strips `'` and `"`, the other only `"`).

#### Bug hunt, 2026-08-28

A sweep over the detection, evidence, STIX and UI paths, driven by real-store
measurement rather than by reading alone. The 938-test suite was green before
and after every one of these — none of them was visible to it, so each fix
lands with a test that fails when the defect is put back (verified by putting
it back).

Checked against real data and found **clean**, which is worth recording so the
next sweep can start elsewhere: the regex extractors over 415,981 characters of
stored report text (0 contract violations across hashes, IPs, domains, URLs,
emails, MACs, ASNs, CVEs, paths, registry keys); the Suricata negation guard
(3,628 rules with a negated `content:`, 0 leaked atoms); the YARA extractor
(777 rules using `not`, none indexing a negated string — YARA negates
`filesize` and `pe.*`, not literals); dedup election (75,127 clusters, exactly
one canonical each); graph-completion provenance (2,586 premise refs, 0
dangling); `web_capture`'s SSRF validation (scheme, port, host blocklist and
every resolved address must be public — a trailing-dot `localhost.` is caught
by the IP check); STIX pattern escaping; and an adversarial-input sweep over
every pure function in the detection and evidence modules, which raised nothing.

- **The atom index held what rules EXCLUDE, indexed as what they look for**
  (ADR-0034). `extract_atoms` walked the whole `detection:` block, but a Sigma
  rule keeps its exclusions there too — only the `condition` says which is
  which. Measured over the full store: **14,037 atoms across 1,742 rules
  (15.3%)** existed solely because a negated selection was walked. They are the
  exclusion vocabulary of Windows detection engineering — `svchost.exe` (80
  rules), `explorer.exe` (75), `msmpeng.exe` (62, Windows Defender),
  `teams.exe` (43), `c:/windows/system32/` (112). A report mentioning
  `explorer.exe` was pulling in 75 rules whose only reason to name it is to not
  fire on it.

  The condition is parsed rather than the `filter*` naming convention trusted:
  measured, **10 rules use a `filter*` selection positively and 72 negate a
  selection not named `filter*`** (`legitimate_process_path`, `falsepositives`,
  `exclude_tlds`, `z_flag_unset`). Both failure modes are silent.
  **Requires a store rebuild to take effect** — the fix is in the extractor.

  Measured at the other end, the panel: **7 of 2,400 served proposals (0.3%)**
  rested only on excluded values — IDF already suppresses `svchost.exe` and
  friends, so what survived was the *specific* exclusion. Small, but inverted:
  *"Notepad++ Updater DNS Query to Uncommon Domains"* was served at score 0.470
  because the report mentioned `github.com`, which that rule excludes precisely
  because it is where the updater is supposed to go.

- **`locate()` reported full coverage for a quote containing a word absent from
  the report.** When the normalised quote had edge whitespace, `nq.split(' ')`
  produced empty words, so the two binary searches indexed more words than the
  coverage fraction was computed against. A quote whose last word was
  hallucinated came back `coverage = 1.000` instead of `0.875` — a hole in the
  guard that demotes an unlocatable quote from `reported` to `inferred`.

- **One character silently shifted every evidence offset after it.**
  `_normalise` assumed `str.lower()` is length-preserving. U+0130 (Turkish
  dotted I) lowercases to two characters, which made the normalised string
  longer than its index map, so every span resolved after it was off by one.
  Now handled the way ligatures already were.

- **`evidence_start` did not delimit anything.** `locate()` returns a start
  *and an end*; only the start was stored. Since `evidence_text` is the model's
  wording and normalisation folds curly quotes and whitespace runs, the two
  differ in length — measured, **68 of 313 stored quotes (21.7%)** could not be
  recovered by `report_text[start:start + len(evidence_text)]`. New
  `entities.evidence_end` column; existing rows are reported as legacy rather
  than as corrupt.

- **Figure ordinals followed thread-completion order, not reading order.**
  `read_figures` appends cache hits in candidate order and parallel reads in
  arrival order, then sorted on `page` alone. Python's sort being stable, two
  figures on one page kept that construction order — so a cached figure, or one
  whose read finished first, took ordinal 1 from the figure printed above it.
  Now sorted on `(page, top, x0)`, the key `find_figures` itself uses and the
  key `inject_append`'s docstring already claimed.

- **`with get_conn() as conn:` was never a transaction.** Connections open with
  `isolation_level=None`, so every statement inside such a block is already
  committed and sqlite3's rollback on exception has nothing to undo — verified
  with a DELETE + INSERT that survived an exception raised between them. New
  `api.db.transaction()`, applied where a partial write loses data:
  `figure_store.save_spans` (DELETE then INSERT) and `dedupe_store`, whose
  `UPDATE ... SET is_canonical=0` used to commit on its own — leaving a window
  in which **every rule in the store read as non-canonical**, which is what
  coverage and drill-down filter on.

- **Atoms could carry a leading space and so match nothing.** For `image` and
  `file`, the basename was taken after the path split but not re-stripped;
  49 values in the store, e.g. `" 2>nul"` and `" rev_shell.py"`. A report
  observable is stripped, so these could never match.

- **An object could be related to itself.** `_add_relationship` and the LLM
  edge loop both resolve their endpoints through `name_to_stix`, which merges
  aliases — so two surface forms of one actor collapse onto a single id and the
  edge survived. `seen_rel_keys` cannot catch it: each is one edge, not a
  repeat. Measured over the 12 stored bundles: **6 self-edges in 2 reports** —
  `Sandworm Team related-to Sandworm Team`, `EXARAMEL drops EXARAMEL`, and four
  IP addresses related to themselves. `_pin_edge_key` and
  `stage4b._rewrite_refs` already refused self-pairs; these two paths had
  drifted from the mirror they document.

- **Merging chunks silently dropped evidence quotes.** `_merge_results`
  deduplicated TTPs and relationships with plain last-write-wins, and
  `evidence_text` is optional — so a later chunk restating a technique *without*
  a quote erased the chunk that had one. The result depended on chunk order:
  reversing two chunks changed the output. It also let confidence 0.5 replace
  0.9, and a one-word quote (`"downloaded"`) replace a full clause. Duplicates
  are now resolved by evidence, then by confidence, keeping the incumbent on a
  tie so the merge is deterministic. This is the field ADR-0028 is entirely
  about.

- **Frontend: a job's rule selection could be written under another job's key.**
  `useRuleSelection` persisted through a `useEffect` on `[excluded, jobId]`.
  That effect also fires on the pass where `jobId` has already changed but
  `excluded` still holds the previous job's value, and on the mount pass where
  the closure holds the initial empty set — both reproduced in
  `useRuleSelection.test.ts`, which recorded job A's exclusions being written to
  job B's key and `[]` being written over a stored selection. Persistence moved
  into the mutators, which is the rule its twin `usePromotedRules` already
  documents and the last place in the frontend that had not adopted it.

- **Stage 1f never ran on a URL capture, and its figures sat one filename
  away.** ADR-0029 deliberately ingests `{job_id}.txt`, the rendered DOM, because
  the PDF text layer wraps a 64-character hash into column fragments and loses
  28% of the observables. But `worker.py` gated Stage 1f on the *ingested*
  file's suffix, so every capture was skipped — while `{job_id}.pdf`, the
  archive holding every diagram, sat beside it untouched. ADR-0029 and ADR-0032
  did not compose. `_figure_source_pdf()` now resolves the archive; the text
  still comes from the DOM and the figures now come from the PDF, which is what
  both ADRs wanted separately. Offsets are unaffected — `inject_append` appends
  figure blocks after the document text either way.

- **The geometric triage discarded most figures on a tall-sheet capture.**
  `MIN_AREA_RATIO` is measured against page area, and a capture is one sheet:
  the SilkParasite report is 960 × 14400 pt, **17× an A4**. Diagrams occupying
  37–51% of a normal page scored 1.3–1.9% and were dropped; the survivors
  cleared the 2% bar by only 12–37%, so a slightly longer article would have
  lost those too. Adds `MIN_FIGURE_AREA_PT2` (40,000 pt², ~200×200) as an **OR**
  with the ratio, never a replacement — on a normal page an image that large
  already exceeds 2%, so nothing previously kept can change.

  Measured across every PDF on disk, which is exactly what that property
  predicts: **all four normal PDFs unchanged** (10→10, 8→8, 75→75, 27→27),
  **13 tall captures 146 → 214 figures (+47%)**, several going from **0 to 5–7**
  — the triage had been finding nothing at all on them. SilkParasite itself goes
  5 → 12, with the 112×150 icon still correctly dropped. These are candidates
  offered to the model, not confirmed figures; the model still classifies a
  `logo` or `none` into an empty block, so the cost is calls, and the benefit is
  not silently discarding real diagrams.

- **`scripts/audit_bundle_invariants.py`** — 16 read-only invariants over every
  stored STIX bundle (id uniqueness and format, dangling `source_ref` /
  `target_ref` / `created_by_ref` / marking refs, report `object_refs`,
  indicator pattern well-formedness, timestamp parsing, confidence range,
  orphans, relationship vocabulary). 15 of the 16 were clean on first run; the
  self-edge check is what found the bug above.

- **`scripts/audit_store_invariants.py`** — a read-only harness checking 16
  invariants over the live store (orphans, dedup election, atom
  normalisation, figure spans, evidence spans, JSON columns). Two of its
  invariants were wrong when first written and are documented as such: grouping
  the dedup election on `dedup_key` reported 5,036 false failures, because
  provenance folding merges rules that do not share a key; and the
  "wildcard-free" atom contract is a Sigma rule — YARA and Suricata literals
  carry `*` and `?` as content (`select * from moz_logins`).

- **A ubiquitous value could admit a rule into the panel and the export.**
  ADR-0030 ruled such a value contributes zero to corroboration, but it was still
  allowed to *admit* — which is worse, because admission is what reaches the ZIP.
  Measured on the Cisco SD-WAN report: **60 rules served, 50 justified by nothing
  but `/bin/bash` (39), `/etc/passwd` (10) and `/etc/shadow` (3)**, while the
  proposals panel beside it reported 14. Across eleven reports the panel now
  serves **267 rules rather than 1,069**. A ubiquitous hit is still displayed as
  support on a rule that earned its place.

- **A file's basename escaped the ubiquity check.** Observables carry both the
  full path and its basename, so `/etc/shadow` was classified ubiquitous while
  bare `shadow` read as discriminating — it and `auth.log` were the only thing
  admitting all 10 rules the Cisco report served after the fix above.
  `UBIQUITOUS_SYSTEM_FILES` now covers standard OS files by name, and the
  `/var/log` paths joined the exact-path table.

- **CVE ids reached no evidence path.** `MATCHABLE` has no `cve` key, so a rule
  naming the vulnerability a report is *about* was invisible to the coverage
  panel. `cve_evidence` resolves them through the ADR-0031 FTS index, as title
  evidence that admits but never corroborates. `cve-2021-44228` names 120 rules;
  a 2026 zero-day names none, which is the honest answer rather than a failure.

- **Promoted rules never reached the ZIP.** Both download buttons took a
  shortcut: when nothing was *excluded* — the default state — they used the
  streaming `GET /detections/export`, which rebuilds the archive server-side from
  the report's own rules and knows nothing about promotions. So ticking **Add**
  updated the coverage counts and then the ZIP silently shipped without those
  rules. Both buttons now send the explicit id list as soon as anything has been
  promoted. The Review button's count also double-counted a promotion that was
  already covered — it read 6 for a 5-rule archive.

- **The export could not package half of what the coverage panel served.**
  `rule_bodies_for_job` still selected by ATT&CK tag alone, so every rule reached
  by evidence — all of YARA, plus ADR-0031 brand hits — appeared in the panel and
  was then silently dropped from the ZIP. Measured across six reports: **582 of
  1,069 served rules, 54%**, including 264 of CERT Polska's 508 and 124 of
  aeternum's 160. Evidence-reached rules now join the export selection with an
  empty `techniques` list, which is the truth about them.

### Added
- **Brand evidence, mined from the campaign's own domains** (ADR-0031).  A rule
  whose **title** names what the report targets is now admitted to the coverage
  panel, in a weaker tier that never corroborates and always sorts below
  literal-value evidence.

  This fixes a false-negative mode ADR-0030 introduced and did not measure: it
  validated the top of the *kept* list and never looked at what was *dropped*.
  On the UNC6671 vishing report all 79 campaign domains were freshly registered,
  so no public rule held a single one of its 98 values — verified against the
  whole 363,166-row atom index — and the panel served **0**.  Meanwhile the store
  held **32 Okta rules**, including `Okta FastPass Phishing Detection`, and
  "okta" appeared in 7 of those domains (`oktaenroll.com`, `keyokta.com`,
  `myoktasso.com`, …).

  Brands are found without a gazetteer: **a substring recurring across ≥3 of the
  report's domains is a campaign theme**, and recurrence is itself the noise
  filter — the one-off `sqfepjvmrd.xyz` yields nothing at any threshold.  Three
  guards, each forced by measurement: word boundaries (as substrings, `reat`
  matched **52,775** rules — it is inside "c*reat*ed" and "th*reat*"), a cap of
  50 rules per token (okta 31, polygon 22, ms365 8 — against port 160, create
  155, secure 124), and a stoplist of domain-construction vocabulary
  (`passkey` recurs 60 times on UNC6671 and names a concept, not a product).

  Result: UNC6671 **0 → 31 rules**, all Okta and Scattered Spider — the cluster
  the report is about.  aeternum 138 → 160 (`polygon`), distinct-clusters 3 → 11
  (`ms365`).  apt44 and CERT Polska gain nothing, which is the noise floor
  holding.  `≥2 corroborated` stayed at 26 across all reports: brand evidence
  corroborated nowhere.

- **An FTS5 index over rule title and description** (`rule_text`), built by
  `scripts/build_rule_text.py`.  Looking a token up by scanning `detection_rules`
  cost **4.1 s**, and the first implementation needed two sweeps — 12.8 s on one
  report, against a panel that answers in 2.9 s.  FTS5 answers in **0.4 ms**, and
  its tokenizer *is* the word-boundary semantics the match needs, so the regex
  went away rather than being reimplemented.  Builds in 26.9 s, costs 22 MB, and
  is optional: brand evidence is simply absent while the table is empty, exactly
  as proposals degrade while the atom index is unbuilt.  No corpus re-clone.

### Fixed
- **A hostname typed as a file is no longer treated as a file** (ADR-0031).
  ADR-0025 put this gate on the domain side so `agent.ashx` cannot become a
  domain; the mirror was missing.  On UNC6671 all 78 `file`/`image` observables
  were the campaign's domains and 77 duplicated a `domain` observable already
  present — **175 observables for 98 distinct values**.  Beyond the wrong count,
  `file` reaches `{file, image, cmdline, strlit}` and admits substring matching,
  which is how `file: gmail.com` came to match an lsassy rule.

  The value is **re-routed to `domain`, not dropped**, so it survives when the
  extractor typed it only as a file; a value carrying a path separator is always
  kept as a file.  UNC6671 175 → 97 observables, distinct-clusters 71 → 56, while
  genuine files are untouched (CERT Polska keeps all 40, aeternum all 26).

### Changed
- **The coverage panel now serves only rules backed by something the report
  actually contains** (ADR-0030).  Measured across the seven reports in the live
  store, the ATT&CK tag join proposed **86,453 rules of which 1,011 — 1.05% —
  hold any report value**; on one report the ratio was 3 in 12,280.  The panel is
  also 2.3× faster (41.6 s → 18.3 s in total), because it stops materialising
  rules it was going to show without justification.  `evidence_only=False`
  restores the unfiltered join for the ZIP export and the backlog view.

  **526 rules become visible that no view could previously reach** — over half
  the gated set.  Two atom classes were indexed and referenced by nothing:
  `strlit` (53,517 atoms — every YARA string and every Suricata `content:`) and
  `pipe` (14,468 Sigma named pipes).  Since **none of the 16,314 canonical YARA
  rules carries an ATT&CK tag**, an exact hash was YARA's only way into any view;
  the tag join could not reach it and the atom matcher would not.  Widening
  `MATCHABLE` takes YARA rules with evidence from 32 to 73 and Suricata from 71
  to 117.  On the Aeternum report the panel goes from 0 YARA rules to 16.

- **Corroboration is counted over discriminating values, and ranks the list**
  (ADR-0030).  Rules holding several distinct report values now sort first, and
  the noisy-OR over a hard cap of four matches is replaced by a saturating sum,
  so a third and a fourth genuine observable keep moving the score instead of
  hitting the ceiling.

  Document frequency could not decide what counts: on the live store it keeps
  `certutil` (df 15), `ping` (10), `tasklist` (7) and `netstat` (9) while
  stripping `api.telegram.org` (60) — it measures rarity in the *rule corpus*,
  which is not the question.  A static table (`pipeline/detection/control.py`,
  seeded from LOLBAS and the OS binary sets) classifies each value instead.
  Ubiquitous values are still shown as supporting evidence; they never score.
  Effect: rules with ≥2 corroborating values fell from 174 to 26, losing
  fourteen apt44 rules tied on `powershell.exe + schtasks.exe` and keeping
  `SMOKELOADER + TrickBot` and `rsocx + rsocx.exe`.

  On the Aeternum blockchain-C2 report the top of the list is now its GitHub C2
  path, its Telegram channel and the Smart Chain RPC endpoints the report is
  about.  Previously it was `gmail.com` matching ET "Google Talk" signatures,
  reached because an attacker's mail address had been reduced to its free-mail
  domain.

### Added
- **Two more ways to start a job: paste text, or give a URL** (ADR-0029).  Both
  land exactly where an upload lands — a file under `uploads/{job_id}`, a `jobs`
  row, `run_pipeline_async` — so nothing downstream of Stage 1 knows the
  difference, including the source viewer and `_delete_job_files`.

  `POST /api/ingest/text` picks between `.html`, `.md` and `.txt` from the paste
  itself, HTML first — a `<li>` also trips the Markdown list pattern, and
  misfiling markup as Markdown keeps the tags.

  **Pasted HTML is now stripped instead of ingested raw.**  It used to land as
  `.txt` and reach the extractor with its markup, so `<div class="post">` read as
  content.  On the live Unit 42 page, pasting its source: 258,095 characters
  handed to Stage 1 before, **35,971** now, and 41 bogus observables gone —
  `cdn.cookielaw.org`, `fonts.googleapis.com`, the site's own navigation.  Only
  one real observable is lost with them, a SHA-256 that exists solely inside a
  VirusTotal `href`; `get_text()` reads text, not attributes.  A paste that is
  markup and nothing else is refused rather than queued.

  `POST /api/ingest/url` renders the page with a headless Chromium.  A plain
  HTTP fetch was tried first and rejected on measurement: the Microsoft security
  blog answers **403** to any non-browser client, and on a DFIR Report post the
  usual `article`/`main` heuristic returns **506 characters of 50,800** — the
  page has no `<article>` element at all.

  The capture writes **two artefacts**, and they are not interchangeable: the
  `.pdf` is the archive the analyst reviews, the rendered DOM text is what the
  pipeline ingests.  Measured over 7 CTI reports, ingesting the PDF instead
  keeps **99.6% of the characters and 72.2% of the observables** — on the
  COLDRIVER report, 9 of 12 SHA-256 hashes are destroyed, because the IOC table
  renders in a narrow column and each 64-character hash wraps into 24-character
  fragments that the text layer interleaves with the neighbouring cells.
  Keeping the prose and losing the IOC table is the worst available trade.

  A capture whose DOM renders under 200 characters is **refused**, naming
  JavaScript as the likely cause.  cert.gov.ua is fully client-rendered and
  produced a valid 944-byte PDF containing a blank page — a zero-byte check does
  not catch that, and the pipeline would have run five stages on nothing.

  The capture assumes the page is hostile, because the URL comes from a report
  about an adversary:

  - JavaScript **off** unless the analyst opts in per capture — which also turns
    out to be what makes capture work at all: unit42.paloaltonetworks.com serves
    a **0-character** body to a JS-enabled headless browser (bot protection) and
    **25,909** characters with JS off, because the blanking script never runs;
  - every URL — the page and each subresource — checked for scheme, port,
    credentials, blocked host, and **every** resolved address being public.  One
    private answer among several rejects it, which is what stops DNS rebinding;
  - only `document`/`stylesheet`/`image`/`font` allowed through the context;
  - **the Chromium sandbox forced back on.**  Playwright's `launch()` defaults
    `chromium_sandbox` to `False` and appends `--no-sandbox` itself, so an
    argument list written specifically to avoid it still ran unsandboxed.

  Playwright is an **optional** dependency: absent, `/api/ingest/url` answers
  503 and the UI points at the Paste tab.  `make install-capture` installs it;
  `setup.sh` gained a `--no-capture` flag and ends its capture section with a
  real Chromium launch, because `playwright install chromium` succeeds without
  the system libraries and then dies at runtime with
  `error while loading shared libraries: libasound.so.2`.

- **One "New report" modal replaces the three-tab ingest panel.**  A single
  field works out whether it was handed prose, a URL, or a dropped file, so the
  tab click before the most common action is gone; the dashboard gets a page-wide
  drop target and denser kanban cards (the status pill was saying the same thing
  as the column it sat in, so it became a dot and a row disappeared).

  The design called for a ⌘N / Ctrl+N shortcut and it was built, then removed:
  both are reserved by the browser for "new window" and never reach the page, so
  `preventDefault()` cannot claim them. It worked on no platform, while the badge
  on the button promised that it did.

  **Behaviour change worth noting: TLP and PAP no longer default to `AMBER`.**
  They start unset and gate submission — the button reads "Set TLP & PAP to
  continue" until both are chosen, and they reset every time the modal opens.
  Every marking in `object_marking_refs` is now a decision rather than a default.

- **Captured pages print as one tall sheet instead of 25 A4 pages.**  On the
  INDUSTROYER.V2 report the archive went from 25 pages to 2, from 24 places
  where an image or paragraph is cut to 1, and from 6 pages with the site's
  sticky nav painted over the article text to none.  Page 9 of the old output
  read `Cloud BloSgleep Prior tCoo InEtCac-1t 0s4ales` — the nav bar interleaved
  with the prose, character by character.  `emulate_media("print")` was tried
  first and changed nothing at all: that site ships no print stylesheet.  The
  fix is to neutralise `position: fixed`/`sticky` before printing (12 elements
  on that page) and to size the sheet to the document, capped at 14,400pt — the
  largest page Acrobat will read.

- **Captured pages keep their code blocks and their figures.**  Two defects that
  only show on paper, both found on reports an analyst asked to capture:

  A container that scrolls on screen is a container that is *cut* in a PDF.  Two
  `<pre>` blocks 952px and 1071px wide inside a 739px column lost 22% and 31% of
  two command listings; expanding scrollers and wrapping `pre` before printing
  recovered **530 characters of code**.

  A JavaScript lazy-loader parks its URL in `data-src`, and with page scripts
  disabled nothing ever copies it into `src` — so the browser never fetches the
  image.  On a report using lozad.js, **31 of 98 images had no `src`**, and the
  archive held 11 distinct images, every one an icon.  Making that copy directly
  takes it to **32, of which 26 are figures**, and the file from 2.8 MB to
  9.5 MB.  No page script runs, and the images still pass the request filter.

- **A full-screen composer for pasted reports.**  The inline box in the
  dashboard panel is 180 px — about nine lines of a 50,000-character report —
  and on a 1280×620 window the "Ingest text" button sat **34 px below the fold**
  with the TLP/PAP selects 88 px below it, so the analyst could see neither what
  they had pasted nor how to submit it.  An **Expand** button opens a modal
  composer: the textarea fills the dialog (363 px on that same window), TLP/PAP
  and the submit button ride in its footer, Escape and a backdrop click close
  it, and the text is shared with the inline tab in both directions.

  The backdrop closes on `mousedown`, not `click`: with `click`, a text
  selection that starts inside the textarea and releases on the backdrop would
  dismiss the dialog and discard the paste.

  The URL tab's controls now wrap instead of overflowing on a narrow window.

- **The server must not run as root**, now that the Chromium sandbox is forced
  on: Chromium refuses to run as root while sandboxed, so `/api/ingest/url`
  answers 503 from a `sudo su` shell.  Documented in the README quick start and
  in `setup.sh`'s next steps.  A browser that cannot launch now raises
  `CaptureUnavailable` → **503** instead of escaping as a 500 ASGI traceback, and
  the message separates the three causes — running as root, a browser installed
  under a different account's HOME, or a missing system library — and always
  quotes the underlying Playwright error.  `make check` launches a real Chromium
  rather than importing the package, which is what reported a green tick while
  the endpoint was failing.

- `scripts/measure_web_capture.py` — measures what the PDF round-trip costs:
  character retention against the DOM, and how many IOCs survive it.

### Fixed
- **Stage 2c's evidence was being thrown away at the merge.** The semantic
  matcher *selects* a sentence from the report, so its evidence is verbatim by
  construction — measured **120/120 locatable**, against 109/280 for the LLM's
  written descriptions. But Stage 2c stored that sentence in `description`, and
  `normalize_ttps` then picked between the two by **length**:

  ```python
  if len(result_ttp.description) > len(existing.description):
      # the LLM's description replaces the semantic evidence sentence
  ```

  A quote and a summary compared by length in one field — the ADR-0028 defect
  one stage earlier. The two now live in separate fields and merge on separate
  rules: the description by length, the evidence by provenance.

  A second distinction the code did not make: the 0.62 cosine floor answers
  *"may this match create a technique?"* — it does **not** answer *"may it supply
  the sentence for a technique the LLM independently found?"* In that
  corroboration case two signals agree on the id and the LLM already vouched for
  it, so the semantic sentence is the better citation at any confidence.
  Restricting evidence to the high floor left the first fix inert (only 16 of
  120 matches clear 0.62): 38.9% → 39.3%. Lifting it for corroboration only:
  **38.9% → 43.9%** across the four reports, 43.6% → 50.4% on APT44 — **without
  re-running the LLM**. That is a floor, not a ceiling: it measures old stored
  TTPs that carry no `evidence_text` of their own.

  Agreement between the two extractors is large — 116 of 120 semantic techniques
  are also found by the LLM, which contributes 164 more — so the semantic stage
  is not a second opinion on *what* is present, it is a source of *evidence* for
  what the LLM already found.
- **Two response ceilings silently discarded whole LLM chunks.** Found on the
  first real call under the ADR-0028 contract, invisible to every unit test.
  `max_tokens` was hard-coded to 4096 at both provider call sites: the reply was
  cut mid-object at 14,812 characters and **TTPs, relationships and malware
  families were all lost**, not just the truncated tail. Raising it exposed the
  second guard — `_MAX_RESPONSE_LENGTH` at 16,000 characters, which *truncates
  the string*, so a complete and valid 23,324-character reply became invalid
  JSON. Now `_MAX_OUTPUT_TOKENS` (8192, `LLM_MAX_OUTPUT_TOKENS`) and 48,000
  characters, coupled in a comment: the character cap must stay above the token
  ceiling times ~4 or it silently undoes it.
- **344 orphan `course-of-action` objects.** Measured across the four stored
  bundles: 10.4% of every bundle — the third most numerous object type — and
  **not one carried a single relationship**. A STIX consumer received them as
  free-floating nodes. The default relationship model now declares the four
  `mitigates` pairs STIX 2.1 Appendix B allows, deliberately on **Auto**: a
  pinned rule is a Cartesian product and `course-of-action` is unanchorable
  (0/344 locatable), so the ADR-0027 gate cannot filter it — pinning would add
  12,768 candidate pairs on CERT Polska and 18,408 on APT44.

### Added
- **TTPs must quote, not describe** (ADR-0028) — what the pipeline read as
  evidence for a technique was a **`description`**, and the prompt asked for
  exactly that. `TTPExtracted` had no evidence field at all, while
  `RelationshipExtracted` twenty lines below already carried `evidence_text`
  ("verbatim quote from source text") and `evidence_label`, and the prompt's
  anti-fabrication rules applied only to relationships.

  Measured over every stored quote with the new locator — same model, same
  reports, same call: relationship quotes locate to a sentence **85.6%** of the
  time (215/277 exact, 22 partial), TTP descriptions **38.9%** (103/280 exact).
  **2.2× apart, from the contract alone.**

  Two hypotheses were tested and discarded first. PDF mangling: rejoining
  end-of-line hyphenation recovered **0** of the 166 failures, the alphanumeric
  skeleton 0.7%, fuzzy matching 3.9%. Invention: of those 166, **99.4% have at
  least half their distinctive tokens present in the report** and 24.7% have all
  of them — the model recomposes real facts, it does not fabricate them. One
  case in 166 falls below half.

  `TTPExtracted` now carries `evidence_text` + `evidence_label` under the same
  rules as relationships; `description` is kept and keeps its job. `entities`
  gains `evidence_text`, `evidence_label` and `evidence_start` (additive
  migration). A quote that cannot be located stores a NULL offset and demotes
  the grade one step — it never drops the technique.
- **`pipeline/evidence_span.py`** — locates a quote in the source text and
  returns a span in *original* coordinates, keeping an index map through
  normalisation of the substitutions PDF extraction introduces (curly quotes,
  en/em dashes, five space characters, five ligatures), with a longest-prefix
  and longest-suffix fallback worth 7.9 points over exact matching alone.
  Ligatures are handled apart from the character map because that map may only
  hold one-to-one substitutions — the offset invariant depends on it.
- **Evidence-gated pin materialisation** (ADR-0027) — a pinned rule now emits an
  edge only when the report links the two objects within three sentences. The
  gate applies **only to types whose identity actually appears in prose**,
  measured over the four stored bundles before any code was written: SCOs,
  `malware`, `tool` and `threat-actor` land at **91–100% verbatim**, while
  `attack-pattern` reaches only **24.3%** (16.8% by ATT&CK `external_id`) and
  `course-of-action` **0/344** — those come from ATT&CK mapping, not from the
  text, so pairs touching them are never gated. That exempts 47% of the
  candidate pool by design, and the ADR says so rather than glossing it.

  A second correction the measurement forced: an Indicator's `name`
  (`"Indicator: evil.com"`) never appears in prose — **0/136** — so its anchor is
  the literals parsed out of its `pattern`, which reach **131/136 (96.3%)**.

  Result over the four bundles: **18,426 → 10,278 candidate pairs, 8,148 blocked
  (44.2%)**, with build latency unchanged (399→310 ms, 457→472 ms) because one
  inverted sentence index is built per bundle instead of scanning the text per
  pair. On the edges actually shipped, `x_pin_evidence` goes from **100%
  `unchecked`** to **32.7% carrying a real textual anchor** (`cosentence` or
  `window:N`), the rest explicitly marked `unanchorable`. ShinyHunters stops
  saturating the ADR-0026 cap entirely — the first time on real data that the
  budget is no longer what decides which edges ship.

  `PinRuleStat.blocked` is reported **separately from `truncated`**: "the budget
  ran out" and "the report does not support this pair" are different verdicts.
  Controlled by `"pin_evidence": {"mode": "cooccurrence"|"cartesian", "window": 3}`;
  `"cartesian"` restores the previous behaviour exactly. The window of 3 is
  reused from ADR-0024 Phase C, the only proximity threshold in this project
  backed by a measurement.
- **Rejected, and recorded as such:** dropping the two `attack-pattern` pin rules
  would remove 8,679 candidate pairs for zero code, but Stage 4b only infers 49
  of the edges the pin rule materialises 200 of — so it would cost analysts the
  "which techniques does this malware use, which does this campaign use" view.
  Coverage of that question outweighs graph tidiness.
- **Per-rule budget for policy pins + `x_synthesis_stats`** (ADR-0026) — the
  `max_pinned_edges` cap ADR-0024 introduced turned out to truncate by the
  **rank of the rule in the policy array**. Measured over the four bundles in
  `cti_stix.db`: the cap was saturated **4 times out of 4** (exactly 200 pinned
  edges each, 800 of 2,023 relationships), and on GREYVIBE the 10th rule
  (`malware uses attack-pattern`, 13 × 39 = 507 candidate pairs) consumed the
  whole budget while the **13 rules after it emitted nothing, silently**.

  The budget is now split by **max-min fair share**: rules are served in
  ascending demand order, each taking at most an equal share of the remainder,
  so a small rule is always satisfied in full and its unspent share flows to the
  larger ones. Replaying all four jobs read-only, rules actually served go from
  **20 to 46** (+26). `pin_budget_mode: "sequential"` restores the old
  behaviour; `max_pinned_edges` and `pin_budget_mode` are now validated at the
  API boundary instead of being coerced silently in Stage 4.

  The Report SDO gains `x_synthesis_stats` — per-rule `candidates / emitted /
  truncated` for the pin pass, plus the `CompletionStats` Stage 4b had been
  **returning and having discarded** at the call site since ADR-0013. The worker
  reads it back off the Report for `emit_progress`, so the live channel consumes
  the same record that ships in the bundle.

  What the measurement also showed, and it is in the ADR: the candidate pool is
  **18,426 pairs for a budget of 200**. Fair share ends the starvation, but at
  ~14 edges per rule it distributes arbitrariness evenly rather than removing
  it — which is the evidence for gating pins on textual co-occurrence next.
- **`scripts/measure_pin_allocation.py`** — read-only harness that replays every
  stored job under both allocation modes and prints the per-rule table, read
  back off the rebuilt bundle's `x_synthesis_stats`.
- **Evidence gate in the Policy UI** — a panel above the rule list showing what
  the last run produced (edges emitted / candidate pairs / cut by budget /
  unevidenced, plus Stage 4b's completion counters), and a per-rule badge
  `emitted / candidates` with a fill bar that turns amber when the rule was
  truncated. A rule absent from the last run shows **nothing** rather than `0` —
  unmeasured and zero are not the same claim.

  The controls are the evidence gate (On/Off) and its window, offered as three
  named steps — Strict 1 / Normal 3 / Wide 10 — because a free number field
  invites typing 50 without realising that switches the gate off in practice.
  **`max_pinned_edges` is deliberately NOT exposed**: an analyst cannot know the
  right total before reading the report, and the number scales with report size
  rather than with anything they can judge. It stays in the policy as a safety
  ceiling. "How close must two things be in the text before I link them?" is
  answerable without knowing how big the report is; "how many edges in total?"
  is not.

  New `GET /api/relationship-policy/last-run` serves it from the newest bundle's
  `x_synthesis_stats`. It parses **exactly one** `bundle_json` by design: at
  ~475 KB–1.3 MB per bundle, scanning back until one carries the property would
  make latency depend on how many old bundles are stored. When the newest bundle
  predates ADR-0026 the answer is `available: false` — measured at **101 ms
  median** warm on the real database, of which **0.7 ms is the JSON parse**; the
  rest is reading the blob off the NTFS mount.

### Fixed
- **Saving the relationship policy wiped its `completion` block.** `PUT
  /api/relationship-policy` is a full replacement, and all four save paths in
  the Policy page sent only `{version, global, rules}` — so every edit silently
  dropped the Stage 4b configuration (ADR-0013) that `complete_graph` still
  reads. The stored policy had no `completion` key at all, despite the API
  documenting it. Saves now spread the last server response, so unknown
  top-level keys survive a round-trip.
- **`max_pinned_edges` was never validated.** It was accepted at any type and
  coerced silently inside Stage 4; it is now rejected at the API boundary
  alongside the new `pin_budget_mode`.

### Added
- **Evidence-keyed detection coverage** (ADR-0025) — coverage stops being indexed
  on ATT&CK techniques and becomes indexed on the report's own technical content.
  The measurement that forced it, over the two real reports in `cti_stix.db`
  (75,127 canonical rules): the technique key selects **25,493 rules of which 4
  match anything in the reports**, and **58 of the 64 cells scored ≥2 have no
  matching rule at all**. `T1071.003` scored 3 on 6,573 rules with zero evidence.

  New `GET /api/jobs/{id}/coverage/artifacts` returns one row per technical
  artifact — hash, IP, domain, URL, file, registry key, tool or malware identity —
  scored 3/2/1/0 on whether canonical rules actually hold that value and from how
  many independent corpora, tiered by **Pyramid of Pain** so a hash match and a
  tool-identity match are never averaged together. Every score above 0 names the
  rule and the field that matched. Measured result: **58 artifacts, 4 covered, 50
  uncovered** — sparse by construction, because a fresh campaign's indicators are
  not in public rule corpora, and the uncovered list is the point.

  ATT&CK is kept as an unscored **phase band** in kill-chain order, with two
  independent rows: what the report claims, and where the rules that actually
  matched an artifact sit. The second is sourced from the matching rule's own
  tags, never from the report's TTP extraction, so the gap between them is a real
  roadmap. On ShinyHunters the report spans 14 phases and detections reach 6.
- **`scripts/measure_ttp_vs_observable_coverage.py`** and
  **`scripts/validate_artifact_coverage.py`** — the before/after harness and the
  real-data validation behind ADR-0025.

### Fixed
- **Malware families scored below system utilities.** Validated against a CERT
  Polska energy-sector report (119 techniques, 22 hashes, 25 tools, 10 malware):
  `Ping` scored 2 and `netstat` 3, while `BlackEnergy` scored **1** despite 28
  dedicated YARA/Suricata rules named after it across three corpora. `tool`
  entities scored 2–3 in 12 of 18 cases; `malware` entities scored 0–1 in 8 of 10.

  Structural cause: a tool's binary name is an atom value inside a rule's
  detection block (exact match, 2–3), while a malware family name lives in the
  rule **title** — which was capped at 1. For a family, the rule named after it
  *is* the detection. Title evidence now corroborates, but only for `malware`
  entities, only on the title (a description mention stays weak), and carrying
  the rule's `native_key` so a forked rule still folds to one owner. Result:
  BlackEnergy 1→3, PrestigeRansomware 1→2, Impacket 2→3, while `Ping` stays 2.
- **One technical element was counted several times.** `nircmd.exe` counted twice
  (file + image) and `pastebin.com` three times (domain + file + image); 16 values
  duplicated on one report, and **13 of 28 "covered" rows were duplicate halves**.
  ADR-0014 had already drawn this lesson for ranking and it was never carried into
  coverage. Artifacts fold on the normalized value, with the score recomputed over
  the unioned evidence rather than taken as a max. 116→97 artifacts on CERT
  Polska, 38→29 on ShinyHunters.
- **`.com` was treated as an executable suffix on the file branch**, so
  `pastebin.com` and `curity.com` became `image` observables — DOS COM
  executables. Same carve-out as the domain guard: a `.com` value that is also a
  well-formed hostname is not an executable.
- **The ATT&CK phase columns were missing two tactics.** `mitre_index.json`
  renames `TA0005` to `stealth` (not `defense-evasion`) and adds `TA0112`
  `defense-impairment`, but the Coverage page hard-coded the classic fourteen —
  so **204 enterprise techniques were silently bucketed as "other"**. Both the
  page and `pipeline/detection/phases.py` now carry fifteen columns, locked by
  `test_every_enterprise_tactic_in_the_index_has_a_column`, which fails if a
  future ATT&CK version adds another.
- **The hostname gate ran on rules but not on reports.** `looks_like_domain`
  (ADR-0015) was applied when extracting atoms from Suricata/YARA rules and never
  when normalising a report, so `agent.ashx`, `exfil.tar.zst` and `psemhub.war`
  became `domain` observables — and a bogus domain is rare by construction, so its
  IDF is ~1.0 and it ranks first with maximum confidence. One real report drops
  from 41 to 38 observables with no genuine domain lost. `onion` joins `GTLDS`:
  on 1,399 domain-shaped Sigma atoms failing only the TLD test, Tor addresses were
  the sole real-domain category among filenames (`.exe` 382, `.zip` 163).
- **`store.rule_details` now returns `native_key`.** Corroboration folds a rule
  forked across corpora onto one owner; artifact scoring was re-deriving that key
  from the rule id, which matches the persisted column only by accident of how ids
  are built.
- **Grounding over the shipped bundle, split by evidence label** (ADR-0024
  Phase C) — `tests/eval_pipeline.py -b grounding --from-bundle all` reads
  `jobs.bundle_json` instead of the `relationships` table, which held only 65 of
  the 1,207 edges actually delivered. It prints a census of every edge by
  `x_evidence_label` and scores hallucination **only** over `observed`/`reported`:
  an `assessed` or `inferred` edge makes no claim about a sentence in the report,
  so measuring it against the text reports an assertion as a hallucination.
  What the split reveals: **endpoint grounding is 1.000 (38/38, zero dangling)** —
  every flagged edge has both entities present in the report, just never close
  enough together. Widening to `--rel-window 3 --alias-aware` takes hallucination
  from 0.500 to **0.211**, leaving 8 edges genuinely worth a human read.
- **`scripts/rebuild_bundle_provenance.py`** — replays a stored job in memory
  (strictly read-only, `mode=ro`) under an explicit relationship policy and counts
  the resulting edges by label. Rebuilding the GREYVIBE report under the two
  pinned rules its edge arithmetic implies: **1,140 edges with 914 unlabelled
  becomes 350 edges with 0 unlabelled**, the cap holds at 200, and the warning
  names the rule that hit it.
- **Run-configuration provenance** (ADR-0024 Phase B) — new `jobs.run_config_json`
  column, stamped by the worker immediately after the relationship policy is read,
  so the snapshot is the policy actually passed to `build_stix_bundle` rather than
  whatever the mutable `relationship_policy` row holds when someone later asks. It
  records the policy, the enabled stage list, the embedding model, the resolved
  TTP thresholds, `git rev-parse HEAD`, and an **allow-listed** set of `TTP_*` /
  `ENABLE_*` environment variables — never a scan of `os.environ`, which holds API
  keys. Without this a bundle cannot be explained: the 872 unlabelled edges in job
  `32b5475b` were produced by pinned rules the stored policy no longer contains.
- **`scripts/audit_edge_provenance.py`** — read-only, stdlib-only audit of what
  fraction of each stored bundle's edges carry provenance, broken down by
  `x_evidence_label` and by source-type -> target-type pair. Current baseline
  across both stored bundles: **1,207 edges, 245 labelled (20.3%), 962
  unlabelled**, and both report `run config: ABSENT`.
- **`custom=` on `_add_relationship`** — merges STIX custom properties and sets
  `allow_custom` only when properties are actually passed, so every existing edge
  stays byte-identical.
- **Retrieval recall @ k** (ADR-0023 Phase 2) — `tests/eval_pipeline.py -b ate
  --retrieval-recall 1,5,10,25` reports the fraction of gold techniques present in
  Stage 2c's top-k candidates *before* any confidence threshold, at both ATT&CK
  granularities. This is the ceiling on every downstream stage: a selector can
  only pick what retrieval proposed. On the ATE fixtures the retriever reaches
  **0.967 technique recall at k=25** while production runs at k=1 and scores F1
  0.550 — roughly 43 points of attainable recall discarded by never looking past
  rank 1. (n=10 hand-written fixtures; a hypothesis to re-measure on TRAM2 in
  Phase 3, not yet a result.)
- **Stage 2c sentence-gate instrumentation** — `sentence_gate_stats()` reports
  `sentences_total / kept_by_keyword / scored / dropped_by_keyword /
  dropped_by_cap` without loading a model, and the ATE benchmark prints the
  aggregate. Two measurement escape hatches: `TTP_KEYWORD_GATE=off` prices the
  keyword allow-list against a baseline, `TTP_UNWRAP_LINES=0` restores the old
  splitter. Both default to production behaviour and are read per call.
- **`semantic_topk_ids(text, k)`** — measurement-only top-k retrieval that
  deliberately ignores the confidence thresholds and the top-2 margin, so the
  ceiling can be measured independently of the gates applied under it.
- **`--gate-off` on `scripts/probe_ttp_recall_caps.py`** — runs the measurement
  twice and prints what the keyword gate costs in sentences of retrieval surface.
- **Dual-granularity ATE scoring** (ADR-0023 Phase 1) — the ATT&CK Technique
  Extraction benchmark now reports **technique-level** (all IDs truncated to their
  parent) and **sub-technique-level** (exact match only) scores side by side,
  macro-averaged per sample, following the protocols of Buchel et al. (SoK, 2025)
  and Zhang et al. (TTP-R1 / RCPO). Every run also prints
  `mean labels predicted` vs `gold` — the one-line diagnostic that separates
  over-prediction (frontier LLMs emit ~4.2 labels against a gold mean of 1.7) from
  the conservative under-prediction of token-level fine-tuned models.
- **`scripts/verify_ate_scorer.py`** — a mutation harness for the scorer. It
  re-implements the pre-ADR-0023 scorer verbatim and replays every case the
  regression tests assert on, requiring each defect case to diverge and each
  control case to agree; it separately replays a two-sample corpus to prove the
  micro-to-macro aggregation change is real (old micro F1 0.1667 vs new macro
  0.5000). A regression test that agrees with the old code is a test that locks
  nothing.
- **`scripts/probe_ttp_recall_caps.py`** — measures how many sentences Stage 2c
  discards before computing a single embedding. On the two real reports in
  `cti_stix.db`: the `_has_ttp_keyword` allow-list drops **400 of 477 sentences
  (83.9%)**, while `_MAX_CANDIDATES=200` drops **zero** — the keyword gate is the
  binding recall ceiling, the candidate cap is latent.
- **`make check-docs` — a documentation drift guard** (`scripts/check_doc_claims.py`)
  — recomputes every precise number the README asserts (gazetteer size, semantic
  corpus split, ATT&CK grounding pairs, all fuzzy thresholds, the ISO country
  table) from the actual JSON data files and module constants, and exits non-zero
  on any mismatch. Standard library only, read-only, degrades to SKIP when a data
  file is absent so it runs on a fresh clone. Every one of the 11 claims checked
  currently passes.
- **Granular multi-format detection selection on `/coverage/:jobId`** (ADR-0022) —
  the page now makes Sigma, Suricata and YARA distinct throughout, and lets an
  analyst select rules at every level (rule → technique → ATT&CK tactic → corpus
  → format) before exporting. A **format board** shows per-format selected counts,
  byte volume and a per-technique tick strip; matrix cells gained tri-state
  checkboxes and format ticks; a **drill-in strip** lists every rule of the
  focused technique in three always-present format columns (a format with no rule
  renders as a visible absence, not a missing lane); the **export panel** groups
  by tactic or by format/corpus, previews the actual ZIP contents, and warns on
  all-rights-reserved licences. Selection is modelled as an exclusion set, so
  "everything that matches the report" remains the default.
- **Rule-id export** — `POST /api/jobs/{id}/detections/export` with
  `{"rule_ids": [...]}` packages exactly the requested rules. The axis-filtered
  `GET` cannot express an arbitrary set, and ~10k ids cannot ride on a URL. Both
  routes share one ZIP builder, so layout, manifest and README cannot drift; ids
  are intersected with the report's linkable rules.
- **Detections tab reworked** (option 1b) — one ranked list with format as a
  column plus `All / Sigma / Suricata / YARA` filter chips carrying counts,
  instead of tier sections.
- **Per-format coverage breakdown** (ADR-0022) — `CoverageCell` now carries
  `by_format`, an entry per detection format (`sigma` / `suricata` / `yara`) with
  its own `rule_count` and `corpora`, and `CoverageRule` carries `format`. Every
  format key is always present, so a format with no rule renders as an explicit
  zero rather than a missing lane. The coverage *score* is unchanged and still
  computed across all formats combined — corroboration is a property of the
  technique, not of one tool's rule language. Per-format `corpora` reuses the
  same first-seen-corpus attribution as the score, so the panel can never claim
  more corroboration than the score does.

### Fixed
- **The six ordinary Stage 4 mapping edges shipped without provenance**
  (ADR-0024 Phase A2). Phase A labelled the policy-materialised edges, but the
  audit showed that was not the only unlabelled source: `indicates`, `based-on`
  and `targets` call `_add_relationship` too, and account for 48 of the 67 edges
  in the second stored bundle. `based-on` now carries `observed` — the Indicator
  restates an IoC regex actually found in the text — while `indicates` and
  `targets` carry `reported`, being model claims about the document. The grade is
  not bookkeeping: the review-UI auto-accept gate promotes only `observed`, so it
  decides what an analyst checks by hand.
- **Policy-materialised edges shipped with no provenance and no cap** (ADR-0024
  Phase A). Stage 4's pinned-rule materialisation is an intentional all-pairs
  feature — it expresses the analyst's link model — but unlike Stage 4b it stamped
  no `x_evidence_label` and had no ceiling, so on one real report it emitted **872
  of 1,140 edges** with nothing distinguishing a materialised assumption from an
  extracted fact. Pinned edges now carry `x_evidence_label="assessed"` and
  `x_policy_rule="<src> <verb> <tgt>"`, mirroring 4b's `x_inference_rule`, and
  obey a `max_pinned_edges` cap (default 200, matching 4b's `max_new_edges`) that
  logs a warning naming the rule when it truncates. `assessed` correctly fails the
  review-UI auto-accept gate, so these edges now queue for review — **the analyst
  workload this adds was always there, it was just invisible.**
- **`_split_sentences` fragmented PDF-extracted text** (ADR-0023 Phase 2). Its
  regex treated every newline as a sentence boundary, so each hard-wrapped PDF
  line became its own "sentence" — fragments like `"AI across state-aligned
  operations -"`. The obvious fix (protect runs of two-or-more newlines as
  paragraph breaks) does nothing, because the ingested corpus carries **237
  `\n\n` runs against 2 single `\n`**: every wrapped line arrives doubled, so
  that rule protects exactly the newlines that need joining. Deciding on content
  alone — join unless the previous segment ended in `.!?:;` or the next opens a
  list item — takes the corpus from 477 segments to 195, median length 68 to 155
  chars, and the share ending in sentence punctuation from **27% to 81%**.
  Measured consequence: the keyword gate's cost falls from 83.9% to 68.2%, so the
  earlier figure was partly measuring the splitter rather than the gate.
- **10 tests in `tests/eval_pipeline.py` had never run in CI.** The file holds the
  ADR-0011 Phase D adversarial precision tests plus the ATE benchmark tests, but
  its name does not match pytest's default `test_*.py` glob, so `pytest` collected
  it zero times — the suite went from 584 to 593 passing once `python_files` in
  `pytest.ini` named it explicitly. The file is also a documented CLI entry point
  (`python tests/eval_pipeline.py -b ate`), so it was named rather than renamed.
- **The ATE scorer was inflating both precision and recall** (ADR-0023 Phase 1).
  `_score_ate_sample` awarded 0.5 partial credit for a parent/sub-technique
  mismatch but excluded the prediction from the false-positive count, so half the
  prediction's mass left the accounting. Predicting `T1059.001` **and**
  `T1059.002` against a gold `T1059` scored precision 1.00 and recall 1.00.
  Partial credit is now removed entirely in favour of the two-granularity report,
  and `tp + fp == len(predictions)` is asserted as an invariant. Aggregation also
  moved from corpus-level micro-averaging — which let long, technique-dense
  reports dominate — to per-sample macro-averaging. **Any ATE number recorded
  before this change is not comparable to one recorded after it.**
- **Pipeline diagram corrected against the implementation** — the README's stage
  diagram drew Stage 3c (MITRE normalisation) between 3b and 3d, but
  `normalize_ttps()` runs once per document in `_merge_results()`, after every
  chunk is merged; the real per-chunk order is 3b → 3d → 3f → 3e. Stage 3e
  (cross-model consensus) was missing from the diagram entirely although it is
  configured in `.env.example` and listed in the file tree. Stage 2 no longer
  claims to extract mutexes (no pattern produces one — they are analyst-entered
  only, now footnoted in the STIX object table alongside user-account and
  network-traffic). Stage 2c's "margin gate" line implied two active filters when
  `top_k=1` is the operative one and `TTP_TOP2_MARGIN` guards a 2nd match that
  the default configuration never requests (ADR-0011 Phase A). Stage 4 now shows
  the real `Indicator → based-on → ObservedData → SCO` chain and the TLP/PAP +
  `created_by_ref` stamping that Stage 4b's note already referenced. Added a
  scope note: the diagram describes the API worker, not the thinner
  `python main.py` CLI.
- **File-tree drift in the README** — `pipeline/detection/` was missing eight
  modules (the whole Suricata/YARA multi-format layer from ADR-0015, plus
  `dedup.py`, `synth_sigma.py`, `tlds.py`, `sync.py`); `api/routes/` was missing
  `policy.py`; `models/` was missing `config.py`; and `tests/` listed 3 of 31
  modules with no indication it was a sample (571 tests, mapped in TESTING.md).
- **Stale counts** — `stage2b_gazetteer.py` still documented a 1,792-name
  gazetteer (actual: 1,827 variants / 1,114 unique) and a ~194 KB index (~275 KB).
  ADR-0002 was marked *Proposed* despite `WORKER_MAX_CONCURRENT` shipping;
  ADR-0012's status line did not use the same bold form as every other ADR.
- **Undocumented Ollama fallback** — the README and `.env.example` both set
  `OLLAMA_MODEL=mistral`, but leaving it unset falls back to `llama3.2`. Stated
  explicitly rather than leaving the two defaults to disagree silently.
- **`/api/jobs/{id}/coverage/rules` was unusable on real reports** (ADR-0022) —
  the endpoint the Detection Coverage page selects over did not complete: on a
  34-technique report (9,777 canonical rules) a 600 s measurement finished 3 of
  34 techniques, extrapolating to **~2.4 hours**. Two instances of one planner
  pathology in `rules_for_technique`, both already documented elsewhere in the
  same module: the `is_canonical` JOIN predicate made SQLite enter through
  `idx_detection_canon` (~43k of 86k rows) at **4.11 s per technique — even for a
  technique with zero rules** — and the per-rule `also_in` sub-query repeated the
  same scan at **871-1,227 ms per rule**. The first is now an `EXISTS`, the second
  one batched sweep pinned to `idx_detection_dedup`. Measured after: T1190's 6,404
  rules in **1.99 s**, T1082 235.66 s → **0.123 s**, a zero-rule technique
  4.11 s → **0.000 s**. Verified key-by-key against the original query on live
  rules with folded duplicates: 0 mismatches.
- **The Detection Coverage page could not be scrolled** (ADR-0022) — `body` and
  `#root` are `height:100vh; overflow:hidden` so the Review page can own its
  internal scroll panes, which means a full-screen route gets no page scrollbar
  at any window size. The coverage page is ~1,680px tall, so everything below the
  fold — including the whole export panel — was unreachable even on a 1920×1080
  display. It now scrolls itself (`flex:1; min-height:0; overflow-y:auto`), the
  same pattern Policy and Dashboard use, and the page is responsive: the archive
  preview stacks under the selection table at 1180px, and the format board and
  drill-in columns fold 3 → 2 → 1 at 1000px and 720px. Those declarations moved
  from inline styles into `index.css`, since inline styles silently override
  media queries.
- **Three more per-element query patterns in the same area** (ADR-0022) —
  `rules_for_job` called `rules_for_technique` once per technique (34 EXISTS
  joins + 34 `also_in` sweeps, **26.34 s → 5.44 s** as one flat sweep); the
  rule-id export loaded all 10,372 rule bodies (219 MB) to package 45
  (**14.83 s → 4.08 s** via a `body_ids` restriction); and `_load_rules` scanned
  all 86,180 store rows to enrich ~10k (**4.83 s → ~0.3 s** batched by id).
- **Rule body sizes moved to a `rule_bytes` side table** (ADR-0022) — the
  selection UI needs a per-rule byte count, and both obvious placements are slow:
  `LENGTH(raw)` per query costs 8.78 s for 10,372 rules, and a `raw_bytes` column
  on `detection_rules` costs **8.19 s** — no better, because `ALTER TABLE`
  appends it after `raw`, so SQLite still walks each record past a multi-kilobyte
  body. From its own table the same read is ~0.1 s. Written on ingest; existing
  stores are filled by `scripts/backfill_rule_bytes.py` (86,180 rows in 23 s).
- **Alias canonicalisation conflated groups with malware** (ADR-0021) — the
  gazetteer index was built with `name2id[name] = mid`, assuming a surface form
  identifies one MITRE object. It does not: **23 of the 1,814 surface forms carry
  two ids**, and for **18 of them the two objects have different canonical
  names**. `snake` resolved to the Turla *group* G0010 over the Uroburos
  *malware* S0022; `sofacy` and `sednit` to APT28 over CORESHELL/JHUHUGIT;
  `uac-0056` merged two distinct ATT&CK groups (G1031 and G1003).
  The rename was the visible half. The damaging half was in
  `stage4_stix_mapping._register_named`, which registered *every alias of the
  winning id* in `name_to_stix` — so a report describing the Snake malware
  registered `turla`, `secret blizzard`, `krypton`, `group 88` and
  `belugasturgeon` pointing at the **malware** node, and every later
  relationship naming "Turla" attached to the wrong object. Node counts looked
  correct throughout, which is why this was invisible.
  Lookups now take the STIX type the caller is about to create — which both
  production call sites already knew — and use the gazetteer's own `entity_type`
  to break ties. An unambiguous form still resolves whatever the type says, so
  the 1,791 unaffected forms behave exactly as before; a form the type cannot
  narrow resolves to nothing and passes through unchanged rather than being
  guessed. `stage4b_graph_completion` dropped its own last-write-wins copy of the
  index and now shares this one, so a malware node can no longer inherit a
  group's curated ATT&CK edges.
- **YARA and Suricata escape decoding corrupted Windows paths** — both parsers
  unescaped with a chain of `str.replace` that collapsed `\\` to `\` *first* and
  then re-read that backslash as the start of the next escape. The literal
  `"C:\\Windows\\notepad.exe"` decoded to `C:\Windows` + NEWLINE + `otepad.exe`.
  Measured over the real corpora: **349 atoms changed across 138 files**, and the
  mangled values failed the file-extension test and fell through to the
  unmatchable `strlit` class — **232 `file` and 7 `registry` atoms were missing
  from the index entirely**, while 41 truncated fragments sat in it matching
  nothing. `M:\\sc\\p\\testbuild.pdb` produced *no atoms at all*; it now yields
  two, including the PDB basename. Both parsers now decode in one left-to-right
  pass, and undefined escapes (`\x41`) are preserved verbatim as before.
- **A valid-looking relationship policy could fail every job** — `PUT
  /api/relationship-policy` checked that `rules` was a list but never checked its
  items, so `{"rules": ["oops"]}` was accepted and stored, then raised
  `AttributeError` in `build_stix_bundle` and `complete_graph` for every
  subsequent job until the policy was edited by hand. This also defeated Stage
  4b's own contract: it wraps all four completion engines in `try/except` because
  "completion must never break the bundle", but `_pol_index` ran *before* the
  first guard. The endpoint now validates each rule is an object, and both
  index builders skip non-dict entries.
- **The proposals endpoint counted 363k rows to answer a yes/no** —
  `atom_index_size` ran `SELECT COUNT(*) FROM rule_atoms` on every request purely
  to test `> 0`, costing **0.54 s** of each response. Replaced by
  `atom_index_built`, a `SELECT 1 … LIMIT 1` at 0.5 ms. Measured end-to-end on
  real reports: 4.30 s → 3.20 s and 13.95 s → 12.22 s, with identical results.

### Added
- **Filtered, multi-format rule export** (ADR-0020) — the export ZIPped every rule
  matching the report's techniques, and was written when the store held 11,396
  Sigma rules. At 86,183 rules across three formats it was broken three ways:
  a real report produced **10,372 rules / 224 MB** (another **18,196 / 268 MB**);
  **8,380 of those 10,372 were Suricata rules written with a `.yml` extension**,
  which no tool loads; and 1,290–1,642 rules carried licence `none`
  (all-rights-reserved) with no way to leave them out.
  Export now accepts `format`, `corpus`, `license` and `severity` — repeatable,
  combining with AND, applied to the technique-selected set so ADR-0008's coverage
  semantics are untouched. Files land as `rules/{format}/…` with the extension the
  format requires (`.yml` / `.rules` / `.yar`), and the archive drops `_sigma_`
  from its name. `MANIFEST.json` records both the filters requested and the
  per-axis counts **excluded**, so an export that omitted 1,642 rules is
  distinguishable from one where they never matched.
  A new `GET /jobs/{id}/detections/export/facets` reports each axis with rule
  counts and byte size, so the operator sees the volume and licence split *before*
  downloading — which is why no silent cap was added; truncating a detection
  package without saying so is worse than a large one.
  This makes ADR-0006's stance actionable: licence was always "carried, not
  enforced — the operator decides", but the operator had no mechanism to decide.
  Measured end-to-end: "Sigma only, redistributable licences, high severity"
  returns **324 rules / 0.30 MB**, with zero all-rights-reserved files.
  Known limitation, documented rather than hidden: facets take **12.4 s** because
  byte totals need `LENGTH(raw)` over 219 MB of overflow-page text. An earlier
  per-axis SQL version measured **43 s** — 2.4× worse, since each axis re-read the
  same bodies — and the fix (a `raw_bytes` column written at ingest) is scoped out.
  YARA still cannot be exported at all: selection is technique-based and YARA
  carries 0 techniques across all 16,314 canonical rules.

- **Suricata and YARA adapters — the formats now actually ingest** (completes
  ADR-0015 §1). ADR-0015 shipped the atom extractors, the store schema and the
  corpora registry, but never the `RuleCorpusAdapter` implementations, so
  `_ADAPTERS` held only Sigma and both formats reported `adapter unavailable`.
  `pipeline/detection/suricata.py` and `pipeline/detection/yara.py` close that.
  Measured on the real corpora: **86,183 rules ingested (75,127 canonical,
  363,166 atoms)** against 11,396 before — ET Open 51,799, Yara-Rules 12,258,
  signature-base 5,889, elastic-artifacts 2,877, rl-yara 1,240, tbg-hunting 682,
  inquest-yara 39. Severity is mapped from ET's own `signature_severity`
  distribution and `sid` is the native key (all 51,799 verified distinct).
  Four defects were found by reading the output rather than by tests:
  **(1)** the YARA rule regex required the opening brace on the `rule` line, but
  brace-on-next-line outnumbers it **7:1** (10,720 vs 1,492) — `peid.yar` alone
  holds 7,615 rules and yielded zero, and `inquest-yara` yielded zero entirely;
  **(2)** the Suricata `dedup_key` hashed only the option body, so the 854
  `ET TOR Known Tor Exit Node Traffic` rules — which differ *only* in their header
  address list — collapsed into one cluster, and ADR-0017 would have demoted 853
  of them, discarding thousands of exit-node addresses. The header is detection
  logic, and is now hashed with the options;
  **(3)** bracketed header address lists were skipped as "not a literal", which
  threw away precisely the C2 addresses the atom index exists to match — atoms
  rose 47,117 → 72,632 once unpacked;
  **(4)** `meta.id` was the YARA native key, but YARA has no uniqueness rule for
  it and signature-base reuses it across families (the eleven distinct
  `APT30_Sample_10..19` share one id, in 57 such groups) — they collided on
  `detection_rules.id` where `INSERT OR REPLACE` would have silently dropped them.
  YARA `private` rules are skipped: a private rule is a helper predicate that
  cannot fire alone, so counting it would overstate coverage.

- **Multi-format corpus management in Settings** (ADR-0019) — the panel was
  Sigma-only in three places at once: the API hardcoded
  `if body.adapter != "sigma"`, the heading read *"Detection Corpora (Sigma)"*,
  and the add form collected **name, git, license** and nothing else. That form
  could not express what the registry already supports, which blocked the corpora
  committed in ADR-0015: `subdir` (3 of the 5 YARA repos keep rules under
  `yara/`), `tarball` (ET Open is published only as a tarball, and is 70% of all
  Suricata rules), and `priority` (dedup authority).
  It also closes a trap of my own making: ADR-0015 committed seven corpora as
  `enabled: false`, and **there was no way to enable them** — `Remove` writes a
  *disable override*, with no route back short of hand-editing
  `detection_corpora.local.yaml`. `PATCH /api/settings/corpora/{name}` now
  toggles `enabled`, verified to round-trip through `load_corpora()` so the
  toggle actually changes what gets ingested.
  New `GET /api/settings/formats` reports each format with `available` derived
  from the adapter registry, so the UI never hardcodes a format list and lights
  up on its own when an adapter ships. **Configuring and ingesting are separate
  gates**: a repo may be configured for any of sigma/suricata/yara, while
  `available` reflects whether a parser is compiled in. Gating creation on the
  registry alone would have refused to create the very corpora the committed
  registry already holds. Corpora whose adapter is missing are badged
  `adapter unavailable` and the create response carries an explicit `warning`,
  so the operator learns at creation time rather than after a Rebuild returns
  zero rules.
  The table now groups by format with per-format repo and rule counts.
  Today that reads: **sigma available (8 repos, 11,396 rules), suricata and yara
  unavailable (2 and 5 repos, 0 rules)** — which is the truth, displayed.

### Changed
- **The detection-proposal ranking no longer collapses into one score** (ADR-0018).
  ADR-0014's technique term was a flat `TECH_EXACT = 0.30`, so a report's 34–48
  techniques tagged ~1,400 rules that all scored *identically*. **99.7% of
  proposals were tied**, and since `rank_rules` sorts by `(-score, corpus, title)`,
  everything past the handful of evidence-backed hits was ordered alphabetically —
  "7Zip Compressing Dump Files", "ADFS Database Named Pipe", "APT29".
  The term is now weighted by the technique's **IDF** — the same argument that
  already makes atom IDF work, applied to the axis it was never applied to. Being
  tagged `T1059` says little when 358 rules carry it; a technique carried by a
  handful says a lot. A `1/sqrt(n)` breadth damping then separates rules tagged
  with one technique from rules tagged with eight.

  | | Distinct scores | Largest tie |
  |---|---|---|
  | ShinyHunters | 6 → **284** | 1,469 → **107** |
  | GREYVIBE | 4 → **296** | 1,336 → **95** |

  The improvement is qualitative too: for a Linux PeopleSoft intrusion the list
  now surfaces `Chmod Targeting Sensitive Directories`, `Remove Immutable File
  Attribute` and `File or Folder Permissions Change` behind the MeshAgent hits.
  An earlier formula that ranked by rule *quality* (breadth × corpus authority)
  was simulated and rejected — it barely dented the tie and put `Screen Capture -
  macOS` and `Too Many Global Admins` at the top of a Linux report.
  Evidence-backed proposals still occupy the top of the list; latency is +1.7%.
  Absolute scores shift downward (technique-only hits now ~0.20–0.26 rather than
  0.300), so any saved threshold is stale.
  Requires the ADR-0017 dedup: a technique's document frequency is meaningless
  against a store that counts the same rule twice.

### Fixed
- **A redacted IoC placeholder could fail an entire ingestion job.** Stage 2 called
  `urlparse()` on report-derived text; since Python 3.11 `urlsplit` validates a
  bracketed netloc as an IPv6 literal via `ipaddress.ip_address()`, so any URL
  whose host is bracketed but not a valid address raises `ValueError`. A real
  Mandiant report contained `http://[actor-controlled-ip]/…` — a redaction
  placeholder — and the unguarded call killed the job at stage 2. The report was
  otherwise fully processable: after the fix it yields **83 entities and 35
  relationships**, where it previously produced nothing.
  Brackets are routine in this corpus (defanging, redaction), so the failure is
  recurring rather than exotic. Hostname extraction moves to `_url_host()`, which
  falls back to a lexical split and keeps a valid IPv6 literal intact — stripping
  brackets then splitting on `:` turned `[2001:db8::1]:8080` into `2001`.
  Found by ingesting a 15-report corpus of public vendor reporting; two reports
  were never going to surface it.
- **Cross-corpus dedup was folding 11 rules out of 11,396** (ADR-0017). ADR-0010
  clusters on `dedup_key`, a hash of the normalised detection logic, and the
  registry claimed hayabusa's converted SigmaHQ copies folded under sigmahq. They
  did not: hayabusa shared **exactly one** `dedup_key` with sigmahq, because its
  conversion injects a `Channel`/`EventID` selection, wraps the condition around
  it, and renames `Image` to `NewProcessName` for the Security-4688 variant. Same
  detection, different hash.
  Rules are now also clustered on **declared provenance** — the Sigma `related:`
  block — via union-find, so derivation chains collapse. 4,758 of hayabusa's
  4,759 rules declare a `related:` id present in sigmahq, so the signal is
  near-total where the hash was useless. Only `derived` and `renamed` fold:
  `similar` means same idea but *different* logic (SigmaHQ's own MeshAgent
  Windows and MacOS rules declare each other `similar`), and `obsolete` runs the
  other way.
  Canonical rules drop **11,385 → 6,349**, hayabusa **4,758 → 5**, and the top-20
  on both stored reports goes from four duplicate-title slots to zero.
  The canonical rule now also inherits the **union of its cluster's ATT&CK
  techniques** — added after validation showed the first version losing two
  techniques, because SigmaHQ's "Double Extension" derivatives carry `T1036.007`
  while the parent they derive from does not. With the union propagated, coverage
  rises 885 → 887 techniques instead of falling.
  This also corrects ADR-0014's IDF denominator, which had been computed against
  a store roughly 44% redundant — an error ADR-0015 would have carried into a
  7.5× larger store.
  The pre-existing dedup test passed throughout, because its fixture made the
  "converted" rule byte-identical to its source — a conversion that never occurs
  upstream. It now asserts the fixture's own limitation, and a second test models
  the real conversion and fails if provenance folding is removed.

### Added
- **Report-derived Sigma rule synthesis** (ADR-0016) — ADR-0014 ranks rules that
  already exist; on a real 41-observable intrusion it found **2** `direct`-tier
  proposals, meaning the campaign's hashes, binaries and C2 addresses were in no
  corpus rule at all. `pipeline/detection/synth_sigma.py` closes that gap: it
  turns a report's observables into draft Sigma, grouped **one rule per telemetry
  type** (`dns_query`, `proxy_url`, `network_connection`, `process_hash`,
  `process_image`, `file_event`, `registry_set`) rather than one rule per
  observable, so a 41-observable report yields 4 reviewable rules instead of 41.
  Deterministic throughout — UUIDv5 rule ids over `(job_id, kind)` and an explicit
  `date` — so re-running a report reproduces byte-identical rules.
  Observables are gated before they may key a rule: values already carried by a
  canonical corpus rule are skipped (ADR-0014 will propose that rule instead), and
  `domain` values must pass the ADR-0015 hostname test — which on a real report
  rejects `agent.ashx`, `exfil.tar.zst` and `psemhub.war`, three filenames that
  upstream extraction had labelled as domains.
  Three further defects were found only by reading the generated rules, not by
  the tests: the report's entire technique list was being stamped on every rule
  (a `file_event` rule tagged with 34 techniques, including an ICS one), so tags
  are now one well-founded tactic per kind and none where the tactic is not
  determinable; `/etc/hosts` was being rendered as the Windows pattern `\hosts`,
  so path separators are now derived from the value's shape rather than assumed;
  and `/usr/bin:/bin`, a `$PATH` fragment, was producing a file rule. Every rule
  carries `status: experimental`, the source report, and the observables behind
  it — nothing is written to the corpus store, which stays a record of *ingested*
  rules only.

- **Multi-format detection matching — atom extractors** (ADR-0015, in progress) —
  groundwork for ranking a report against Suricata and YARA corpora, not Sigma
  alone. The store has always been format-agnostic on paper (`format` column,
  `RuleCorpusAdapter` seam) and single-format in practice: **11 396 rules, 100 %
  `sigma`**. Landed so far:
  **(1)** `pipeline/detection/suricata_atoms.py` — parses Snort/Suricata syntax
  (sticky buffers *and* legacy content modifiers, which are disambiguated by
  position since the two vocabularies overlap), yielding `domain`/`url`/`ip`/
  `port`/`hash`/`strlit` atoms. Validated on ET Open 7.0.3: **51 799 active rules
  → 45 682 atoms at 12 700 rules/s**;
  **(2)** `pipeline/detection/yara_atoms.py` — brace-balanced rule splitter plus
  meta/strings parser. Metadata hashes are extracted first as the highest-value
  atoms a YARA rule carries (**8 932 distinct hashes** across the corpora), and
  hex/regex strings are deliberately *not* indexed — a report never carries a byte
  pattern as an observable. Validated on 10 668 rules from five corpora;
  **(3)** `pipeline/detection/tlds.py` — one shared "is this a hostname" test.
  An allowlist, not the generic shape used for IoC extraction: an atom index needs
  precision where extraction needs recall, and the generic shape admitted ActiveX
  ProgIDs (`aventail.epinstaller`) and `kernel32.dll` as domains. Because such
  values are rare they earn *high* IDF and score near 1.0 — the ADR-0014 failure
  mode of confident nonsense at the top of the list.
  Registry entries for seven new corpora (five YARA, two Suricata) are committed
  **disabled** pending the adapters, with every licence verified from the repo.
  `Neo23x0/signature-base` is DRL-1.1 — the same licence as SigmaHQ, not the
  CC BY-NC it is widely reported to be. `ptresearch/AttackDetection` is excluded:
  proprietary Positive Technologies EULA, sanctioned entity.

- **Observable-driven detection proposals** (ADR-0014) — the Review "Detections"
  tab ranked rules by ATT&CK tag alone, which on a real Linux/WebLogic intrusion
  proposed **2 688 rules**, its two largest buckets being 760 PowerShell rules and
  500 generic `T1059` rules. Nothing in the selection knew the report mentioned
  `meshagent64-azure-ops.exe`, `azurenetfiles.net`, `_fanout.sh` or `/etc/hosts`,
  or that the intrusion was not on Windows. Three parts:
  **(1)** each Sigma rule's `detection:` block is now reduced to normalized
  **atoms** — the literal values it looks for, keyed by field class (`image`,
  `cmdline`, `file`, `registry`, `hash`, `domain`, `ip`, `url`, `pipe`, `service`,
  `port`, `user`) — stored in a new `rule_atoms` table, alongside a `platform`
  column derived from `logsource` (`pipeline/detection/atoms.py`);
  **(2)** a report's entities are normalized into the same vocabulary, with URLs
  expanded to their host, executable paths to path *and* basename, and defanged
  IoCs refanged, plus an inferred report platform
  (`pipeline/detection/observables.py`);
  **(3)** rules are scored on IDF-weighted observable overlap + a technique term
  + a platform factor, and tiered `direct` / `behavioural` / `weak`
  (`pipeline/detection/relevance.py`). IDF is what makes it work without a
  stoplist: a match on `cmd.exe` scores ~0, a match on a campaign-specific binary
  scores ~1. Every proposal carries the evidence behind its rank — which
  observable matched which rule field — so the ranking is auditable.
  Scoring is deterministic and offline (no model, honouring ADR-0008's constraint
  on the detection artifact). New endpoint
  `GET /api/jobs/{id}/detections/proposals`; the unranked
  `GET /api/jobs/{id}/coverage/rules` is unchanged. Coverage's 0–3 readiness
  score (ADR-0008) is untouched — readiness and relevance are separate questions.
- **`scripts/build_rule_atoms.py`** — backfills the atom index from the stored
  rule bodies, so a store built before ADR-0014 gains observable ranking without
  re-cloning several gigabytes of Sigma corpora.
- **Untagged rules are reachable** — 1 049 of the 11 396 rules in the default
  corpora carry no `attack.tXXXX` tag and were invisible to a tag-keyed join.
  They now surface when one of their atoms matches a report observable.

### Changed
- **Unified ATT&CK entities under a single `ttp` type** — the extractors no longer
  emit separate `technique` / `tactic` / `procedure` types; all ATT&CK entities are
  now `ttp`, which maps to the STIX 2.1 `attack-pattern` SDO (the only spec object
  for this concept — "technique"/"tactic" are not STIX object types). The
  tactic/technique distinction is preserved losslessly in each entity's `mitre_id`
  (TA#### vs T####), which Stage 4 still uses for ATT&CK URL routing. The review's
  type picker now offers only "TTP" for ATT&CK. Legacy `technique`/`tactic`/
  `procedure` rows in existing databases still render and still map to
  attack-pattern (kept for backward compatibility). Bundle output is unchanged —
  it already emitted only `attack-pattern`.

### Fixed
- **Runaway TTP counts on reports with no explicit T-IDs** — a 12-page report
  produced 65 TTP rows in the review UI against 51 attack-patterns in its bundle.
  Four compounding defects, each fixed and pinned by tests
  (`tests/test_ttp_volume_controls.py`):
  **(1)** `_save_entities` persisted the Stage 2c row *and* the Stage 3c-normalized
  LLM row for the same technique, so the UI double-counted every technique both
  stages found — it now skips a raw TTP the normalized set already covers, making
  the UI count match the bundle; **(2)** the same path reintroduced a parent
  technique next to its sub-technique when the two came from different stages
  (`T1027` beside `T1027.004`) — parents of a present sub-technique are now
  subsumed across sources; **(3)** Stage 3f's "already corroborated, skip
  verification" exemption ignored confidence despite its docstring promising
  *high*-confidence — every medium semantic match (≥ 0.48, the nearest-but-wrong
  tier the Phase A margin gate suppresses) was waiving quote-verification for its
  LLM twin. On the sample report 13 of 16 corroborators sat below the 0.62
  cut-point, waving through techniques with zero textual support (`T0873`
  "Project File Infection" at 0.52, in a report containing no ICS content).
  Extracted as `stage3_llm.corroborated_ttp_ids()` and floored at the model's
  high threshold; **(4)** CAPEC is ~40% of the embedding corpus (615/1533) and
  shadowed the ATT&CK technique that belonged in the bundle — the semantic corpus
  is now ATT&CK-only by default (`TTP_SEMANTIC_DOMAINS`, set to `all` to restore
  CAPEC), which also makes the *correct* technique surface instead
  (`CAPEC-648 Collect Data from Screen Capture` → `T1113 Screen Capture`).
  `ENABLE_TTP_VERIFICATION` now defaults to `true` in `.env.example`.
- **Wrapped hashes now extracted** — MD5/SHA1/SHA256 values that a PDF wraps
  across 1, 2 or 3 lines inside a narrow IOC-table cell were silently dropped
  (the strict contiguous-hex regex couldn't span the newlines). Stage 2 now
  de-wraps hex blocks and accepts them when the joined length is exactly
  32/40/64, while a strict fallback keeps stacked full hashes intact and avoids
  inventing hashes from unrelated hex. Recovered 5 SHA-256 IOCs on the
  ShinyHunters/PeopleSoft report that previously extracted none.
- **Wrapped hashes now highlight & locate in the document** — because the stored
  hash is de-wrapped (contiguous) but the source still has it split across lines,
  the review couldn't find it verbatim ("not found in document text") and drew no
  highlight. `buildRanges` now matches hash values with whitespace tolerance, so
  the wrapped occurrence is highlighted and click-to-locate works across the Text,
  Source and PDF views.
- **Bare filenames now extracted** — path-less filenames with an executable /
  script / installer extension (`payload.exe`, `_fanout.sh`, `meshctrl.js`) are
  extracted as `file` entities. Previously only path-embedded filenames were
  captured; the extension allow-list keeps prose (`report.pdf`, `chart.png`) out.

### Added
- **STIX graph completion** (ADR-0013) — a Stage 4b/4c layer that enriches edges
  *after* the Stage 3d/3f precision gate instead of loosening it, so the base graph
  is untouched and every added edge is independently justified. Engines, all guarded
  by `rel_is_suggested` (a composed verb that is not a *suggested* STIX 2.1
  relationship for the type pair is **skipped, not downgraded**):
  **(1)** ATT&CK reference grounding — `build_indexes.py --only relationships` distils
  the ATT&CK bundles into `pipeline/data/attack_relationships.json` (20 015 curated
  G/S/T triples); curated edges are added when both endpoints resolve to ATT&CK IDs
  and labelled `reported`, not `inferred`; **(2)** transitive inference over a fixed
  composition table; **(3)** an alias-merge *fallback* (default **off** — ADR-0012's
  `pipeline/aliases.py` already canonicalises MITRE-known aliases at SDO-creation
  time, so this only covers names absent from the gazetteer, with opt-in
  `fuzzy_alias` / `semantic_alias` matchers); **(4)** Stage 4c long-distance
  prediction (opt-in) — connects disconnected sub-graphs via degree-centrality
  central/topic nodes, requiring the LLM to quote a supporting sentence (Stage 3d's
  evidence bar) stored as `x_evidence_text`. Inferred edges carry `x_inference_rule`
  + `x_inferred_from` (premise ids). New: `pipeline/stage4b_graph_completion.py`,
  `pipeline/stage4c_long_distance.py`, `tests/test_stage4b_completion.py`,
  `tests/test_stage4c_long_distance.py`.
- **Graph-completion benchmark** (`eval_pipeline.py --benchmark rel`) — edge-level
  per-engine precision/recall/F1 against gold accept/reject judgments, with built-in
  fixtures and a documented dataset format for human-annotated reports. Complements
  `-b grounding` (ADR-0012): grounding measures hallucination in *extracted* output,
  `rel` measures precision of *completion-added* edges.
- **Inline source view for all formats** — the Review page's *Source* tab now
  renders the original upload inline for every supported format, not just PDF:
  HTML/HTM in a fully-sandboxed iframe (scripts disabled), and TXT/MD as raw
  source text with the same entity highlights the Text view uses. DOCX keeps a
  download fallback (no browser-native rendering). New:
  `frontend/src/components/SourceViewer.tsx`, `frontend/src/components/sourceKind.ts`.
- **TTP extraction precision** (ADR-0011) — four layers raising MITRE technique
  precision: **(A)** model-aware Stage 2c cosine thresholds (per-model defaults →
  embedding manifest → `TTP_HIGH_THRESHOLD`/`TTP_MEDIUM_THRESHOLD` env), one match
  per sentence with a `TTP_TOP2_MARGIN` gate, and Stage 3c no longer letting a
  *medium*-confidence semantic match override the LLM; **(B)** Stage 3f TTP
  self-verification (`ENABLE_TTP_VERIFICATION`) — a second LLM pass must quote the
  sentence describing each technique's use, semantic-corroborated TTPs skipped;
  **(C)** parent/sub-technique subsumption + a technique→tactic lookup feeding the
  3f prompt; **(D)** ATE benchmark `--stage full` (regex + semantic + LLM + Stage 3c
  normalize) and adversarial precision fixtures. New: `pipeline/stage3f_ttp_verify.py`,
  `tests/test_ttp_precision.py`.
- **Default Sigma corpora + cross-corpus dedup** (ADR-0010) — the committed registry
  now ships 8 public Sigma repos (SigmaHQ, DFIR-Report, tsale, P4T12ICK,
  RussianPanda95, linkedin, mthcht, Yamato hayabusa) with verified licenses,
  per-corpus `priority`, and `subdir` scoping. A global `dedupe_store` pass folds
  rules that share normalized detection logic into one canonical (by priority),
  losslessly (provenance kept as `also_in`), so a copied rule never inflates the
  coverage score. Registry columns: `detection_rules.dedup_key`, `is_canonical`.
- **Detection coverage matrix** (ADR-0008) — per-report ATT&CK techniques scored
  0–3 for *detection readiness* (not lab validation), in a tactic-column matrix at
  `/coverage/:jobId`.
- **Multi-corpus Sigma ingestion** (ADR-0006) — pluggable `RuleCorpusAdapter`,
  `SigmaAdapter`, a two-tier registry (committed public `detection_corpora.yaml` +
  gitignored private `detection_corpora.local.yaml`), a SQLite rule store, and a
  fork-safe corroboration score. Scripts: `sync_corpora.py`, `build_detection_index.py`.
- **In-app Settings panel** (ADR-0007 Slice 1) — list/add/remove corpora and rebuild
  the rule index from the UI (`/settings`).
- **Evidence labels** (ADR-0009) — every relationship carries `observed` / `reported`
  / `assessed` / `inferred` / `gap`, persisted, exposed on the API, emitted as
  `x_evidence_label` in STIX, and gating the review auto-accept.
- **Cross-model consensus** (ADR-0009, opt-in `ENABLE_CONSENSUS`) — re-runs
  relationship-bearing chunks through a second provider; agreement boosts confidence,
  single-model claims are downgraded.
- **STIX provenance & sharing markings** (ADR-0009) — every object stamped with a
  TLP (and optional PAP) marking and an authoring `Identity` (`created_by_ref`).
  Config: `STIX_TLP`, `STIX_AUTHOR_NAME`; per-job `tlp_level` / `pap_level`.
- **Docs** — `SECURITY.md`, `TESTING.md`, `CONTRIBUTING.md`, an ADR index, and ADRs
  0002–0011.

### Changed
- **Stage 2d NER model → CyNER 2.0 (DeBERTa-v3)** — replaces the removed
  `aiforsec/cyner-xlm-roberta-base` with `PranavaKailash/CyNER-2.0-DeBERTa-v3-base`
  (public, F1 91.88%), re-enabled by default (`CYNER_ENABLED=true`). The new model
  exposes a dedicated `Threat_group` label distinct from `Organization`, so
  threat-actor detection no longer relies on the `_ORG_BLOCKLIST` heuristic (kept
  as a safety net). New dependency: `sentencepiece` (DeBERTa-v2 tokenizer). `setup.sh`
  gains a CyNER pre-download step and clears the stale `.cyner_model_unavailable`
  sentinel. New: `tests/test_stage2d_cyner.py` (mapping + parsing, no model download).
- The relationship policy gained an optional `completion` block
  (`transitive` / `reference` / `alias` / `long_distance` / `fuzzy_alias` /
  `semantic_alias` / `max_new_edges`) — the "let the tool decide" switch for graph
  completion. A `"pin"` rule still always wins, so inference never contradicts an
  explicit analyst choice.
- `build_stix_bundle()` gained `long_distance_infer=`; the API worker supplies it
  via `stage4c_long_distance.default_long_distance_inferer(policy)`, which returns
  `None` unless the policy enables long-distance *and* the LLM provider is ready —
  keeping STIX mapping network-free by default.
- New API routes: `/api/jobs/{id}/coverage`, `/api/detection-corpora`,
  `/api/settings/corpora*`.
- DB schema: `relationships.evidence_label`, `jobs.tlp_level` / `pap_level`,
  and `detection_rules` / `rule_techniques` tables (auto-migrated).
- New dependency: `PyYAML`.

### Security
- Documented the security model (`SECURITY.md`): prompt-injection handling, the
  localhost/CORS posture, secrets/data-at-rest, and the deliberate deferral of the
  LLM-keys settings panel until its security work lands.

---

Earlier history predates this changelog; see `git log` and `docs/adr/`.
