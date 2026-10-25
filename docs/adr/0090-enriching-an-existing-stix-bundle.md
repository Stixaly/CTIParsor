# ADR-0090: Enriching an existing STIX 2.1 bundle

**Status:** Accepted (2026-10-25). Proposed 2026-10-24; design decisions D1–D5
taken by the maintainer on 2026-10-24; acceptance criteria A1–A6 measured and
passed on 2026-10-25 (lot 7, see "Acceptance criteria" and "Lot 7"). The
feature is on by default; `STIX_ENRICHMENT_ENABLED=false` turns it off.
**Date:** 2026-10-24 (proposed), 2026-10-25 (accepted)
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
  (`file_name`) is a weak key: it sets a displayed status. Lot 7 changed its
  merging: a file known by its name alone merges into the one baseline file of
  that name (see "Lot 7"). Before lot 7 it never merged ids.
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

**9. A feature flag, on by default.** `STIX_ENRICHMENT_ENABLED=false` turns the
mode off: with it off, `/inspect` and every `baseline_*` field answer 400, and
the modal hides the mode. Lot 2 added the flag off; lot 7 set the default to
`true` once A1–A6 passed and this ADR was Accepted (2026-10-25). The mode was
invisible while the lots landed one PR at a time.

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

## Decisions taken on 2026-10-25

| # | Question | Decision |
|---|---|---|
| D7 | Targets of A2 and A3 | A2 (round trip): 0 duplicates. A3 (ablation): at most 1 % duplicates. Recovery is measured and reported, with no threshold. |
| D8 | A6 fixtures | The repository's OpenCTI-shaped and MISP-shaped fixtures and its rules stand for real exports. The ADR says so wherever it cites them. |
| D9 | File names | **Reverses** the design's B15 and the first text of decision 2 ("a file name is a weak key … never merges ids"). A file known by its name alone (no hash of its own) merges into the baseline's file when exactly one baseline file carries that name; with two carriers, nothing merges and the row stays `new`. A name carried only by an Indicator (a name-only `[file:name = …]` with no file object of its own) matches nothing, in Stage 3r and in Stage 4. See "Lot 7". |
| D10 | Activation | If A1–A6 pass, the flag is on by default and this ADR is Accepted in the lot 7 PR. |

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
  object CTIParsor builds beside the baseline's). A3 measures the duplicate rate:
  0 of 196 `new` rows on the ablation (0.0 %), 0 duplicate rows on the round trip
  (lot 7). At object level the round trip still holds 11 objects that duplicate a
  baseline object by name: the CTIParsor author identity in each of the 7 jobs,
  and two attack-patterns in two jobs (A2).
- **A name-only file can merge onto the wrong sample.** Since lot 7 a file known
  by its name alone merges into the one baseline file of that name, even when
  it is another sample (D9). No measurement covers this case.
- **The mode is on by default** (lot 7). A server that does not set
  `STIX_ENRICHMENT_ENABLED` accepts a baseline and offers the enrich mode;
  `STIX_ENRICHMENT_ENABLED=false` restores the 400 answers of lot 2.
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
- **Merging on file name:** `svchost.exe` identifies no sample. Still rejected
  for a file with a hash of its own; reversed in lot 7 for a file known by its
  name alone when exactly one baseline file carries that name (decision D9).
- **Client-side validation of the STIX:** two parsers would disagree on what is
  recognised, copied or excluded; the server alone decides, and the preview shows
  the same figures as the job.

## Acceptance criteria

A1–A6 must pass before the status becomes Accepted. The figures are recorded
here by lot 7.

| # | Criterion | How |
|---|---|---|
| A1 | Full mode unchanged (I1) | The reference scenarios of `tests/test_stage4_reference.py`, frozen on `main` before lot 1, still match in canonical form (build-time stamps, random ids and order aside; everything else, TLP marking ids included, compared). **Result (2026-10-25): pass.** `tests/test_stage4_reference.py` passes on this branch; full-mode output is identical in canonical form (ids and timestamps normalised) to the output before the feature. |
| A2 | Round trip | A job's CTIParsor bundle given as baseline to the same document: 0 `new`, identical ids, no baseline object lost, Stage 5 `validated`, `scripts/audit_bundle_invariants.py` with no finding. **Result (2026-10-25), 7 real reports:** the row-level target restated in D7 is met: 0 duplicate rows (596 rows matched, 0 mismatches). The criterion's "0 `new`" is not met: 21 rows are `new`, 19 locations the bundle never held and 2 ambiguous ledger keys, none of them a duplicate. Object level (`scripts/baseline_round_trip.py`, `output/baseline_round_trip.md`), the enriched bundle of each job over its own stored bundle: 6 of 7 pass Stage 5 (`validated`), where the criterion asks for all seven. The 7th (job 07d1fd30) is `invalid` with one error: CTIParsor rebuilds a `url` whose value is not a valid `uri` (a `.exe` download); the same url made that job's stored bundle invalid already, and the intake excluded it with its 4 relationships. A pre-existing Stage 4 defect outside this feature, full mode included, to be fixed separately. Baseline objects lost: 0, except those 4 excluded at intake; altered: only the re-issued Report, by design. Audit (`scripts/audit_bundle_invariants.py` logic, run in memory): 14 invariant checks, 0 failing, on all 7 bundles; `check_orphan_objects` reports no orphan. Objects that duplicate a baseline object by name (the row count does not see them): the CTIParsor author identity in all 7 jobs (these September bundles carry an older author id than today's stable one; OpenCTI merges identities by name and class), and two attack-patterns, "System Binary Proxy Execution" in 4a9b9810 and "Phishing" in 7a318c22, each held twice by its job's baseline, so the matcher cannot pick one. Before the lot 7 review fixes, 119 courses of action and 6 YARA Indicators were rebuilt under new ids; 0 remain. The script reads the measurement database without the worker's `held_reason` and `enrichment_status` columns (reported in its output). Identical ids and no baseline object lost: `tests/test_baseline_e2e.py` (round trip). |
| A3 | Recovery after ablation | On the 7 real reports of the measurement database (`ctiparsor_measure`, never the main one), with their CTIParsor bundles as baselines, plus the OpenCTI- and MISP-shaped fixtures (CTIParsor's own bundles do not exercise the actor family or indicator-only entries): remove 30 % of the objects (fixed seed), enrich, and measure (a) the share of removed objects found back as `new` and (b) the duplicate rate: `new` objects that designate an object left in the baseline. Targets, confirmed on 2026-10-25 (D7): 0 duplicates on the round trip (A2), at most 1 % on the ablation; the recovery is reported, with no threshold. **Result (2026-10-25): pass on the seven real reports.** Seed 20261025, `scripts/baseline_ablation.py`: 179 of 601 candidate entries removed; 175 came back as `new` (recovery 97.8 %). Four removed entries were reached by a row and not returned as `new`, each with its cause: "NextChat" and "SoftEther" (malware rows matched to a kept `tool` of the same name, the software family); "System Binary Proxy Execution" (the report's own bundle held two attack-patterns of that name, and the row matched the kept one); "BREEZE COMET" (an ambiguous ledger key: a campaign and a malware share the name). 196 `new` rows, 0 duplicates (0.0 %, target at most 1 %); 19 unmapped locations and 2 ambiguous ledger keys counted apart; 2 mismatches, malware rows matched to a kept `tool` of the same name (the software family, accepted by design). Per job: `output/baseline_ablation.json`. Before the two matcher fixes of lot 7 the same runs gave 45 duplicates on A2 and 35 on A3, all `file` rows. The external control, the OpenCTI- and MISP-shaped fixtures in the same mode (`--fixture`, seeds 20261025 to 20261029, 30 %): OpenCTI-shaped, 2 candidate entries, 1 removed per seed, 5 of 5 recovered, 0 duplicates; MISP-shaped, 2 candidate entries, 1 removed per seed, 5 of 5 recovered, 0 duplicates. These are small numbers (one removed entry per seed): they show the path works on both shapes, not a rate. |
| A4 | OpenCTI import | In a throwaway OpenCTI (Docker, pinned version): import the baseline, then the enriched bundle. Nothing refused, no baseline object duplicated, **one** Report holding the original references and the additions. Counter-test: with a user whose confidence ceiling is below the Report's, the additions are not made. **Result (2026-10-25): pass.** OpenCTI **7.260930.0** (pinned in `docker/opencti-test/compose.yaml`; pycti 7.260930.0 in a separate venv). **12 of 12 expectations hold** on a fresh instance, in the final run with the final code: the baseline imported, nothing refused; as a user with maximum confidence 50 (below the Report's 85) the enriched bundle imported with 0 errors and the Report kept its 9 original references, the additions not made; as admin, nothing refused, one Report (the baseline's id) holding 16 references, each baseline object present once, all 23 objects present; the rejected bundle imported as admin, nothing refused, and WellMess still referenced by the Report (OpenCTI never removes a reference on upsert). A first run, before the file-name decision of lot 7, failed one check: a second `svchost_update.dll` file. |
| A5 | Rejection | Rejecting a baseline object removes it and everything referencing it; each removal is in the ledger and displayed. **Result (2026-10-25): pass.** `tests/test_baseline_e2e.py` finalizes with a rejection: the object and what references it leave, ledgered. Browser check of lot 6: WellMess rejected, its two relationships leaving with it, named in the "Against your bundle" panel. |
| A6 | Real baselines | An OpenCTI export (`intrusion-set`), a MISP export (Indicators with no SCO), a bundle with compound patterns and YARA/Sigma rules. **Result (2026-10-25): pass**, on the repository fixtures, which stand for real exports (D8); detail below the table. |

**A6 detail (2026-10-25).** The fixtures are the repository's, which stand for
real exports (D8); no live OpenCTI or MISP export was used.

- *OpenCTI-shaped* (`tests/fixtures/baselines/opencti_report.json` and `.txt`):
  the A4 run above; Stage 5 validated.
- *MISP-shaped* (`misp_indicators_only.json`: Indicators only, compound patterns
  `… OR …` and `[…] AND […]`), with a short report written for it: MD5 and URL
  rows matched through the compound patterns, the domain found in the text, the
  unnamed C2 IP imported as STIX only, a new IP and Rclone added. Stage 5
  validated; `scripts/audit_bundle_invariants.py` 16/16 OK; OpenCTI import on a
  fresh instance 10/10.
- *Rules* (`rules.json`: YARA, two Sigma, Suricata; no Report): the broken Sigma
  rule is excluded at intake (`baseline_rule_refused`). OpenCTI refuses that
  same rule when the raw fixture is imported ("Indicator of type sigma is not
  correctly formatted", INCORRECT_INDICATOR_FORMAT), so the intake agrees with
  OpenCTI. CTIParsor's enriched bundle (its own Report, the three good rules
  kept verbatim) imports with 0 refused; Stage 5 validated. The audit's only
  remaining flag is `check_orphan_objects`, the known conflict with objects
  outside the Report (`tests/test_baseline_e2e.py`).

## Lot 7 (2026-10-25): the changes, the file-name decision, the OpenCTI findings

**Code (`pipeline/baseline_stix.py`).**

1. Stage 3r `reconcile`: a `file` row with no strong key is matched through its
   file name when exactly one baseline entry carries that name
   (`BaselineIndex.lookup_weak`). Before, it never matched, and the same file
   also came back as an imported `baseline_in_text` row. The one entry must hold
   a file object: a name carried only by a name-only Indicator matches nothing,
   in Stage 3r and in Stage 4 alike (I6).
2. Index build: a STIX-pattern Indicator with no strong key shared with an
   observable (a name-only `[file:name = '…']`) joins the entry of the observable
   its `based-on` names, of the same type, and only when exactly one observable
   of that type is named and that observable carries a key the pattern states.
   A `based-on` to another value does not move that value onto the entry; the
   Indicator then keeps an entry of its own. Before, every such Indicator made an
   entry of its own, so the file name had two carriers and nothing matched.
3. Stage 4 `merge_baseline`: a CTIParsor `file` whose only strong key is its id
   (name only) is remapped onto the one baseline file of that name, as Stage 3r
   shows it. A file with a hash of its own is never merged on its name.
4. Stage 4 `merge_baseline`: a CTIParsor name-only Indicator `[file:name = …]`
   becomes the kept baseline Indicator of that file's entry whose pattern states
   the same name and no hash. Never a hash Indicator.
5. Stage 4 `merge_baseline`, objects no index entry holds: a course of action
   (same name, case and spacing folded) and a detection-rule Indicator (same
   `pattern_type` and text, whitespace folded) become the one kept baseline object
   of the same content; two such baseline objects, no merge. The round trip found
   it: 119 courses of action and 6 YARA Indicators were rebuilt under new ids.

Items 1 and 2 are the matcher fixes: before them the same measurement runs gave
45 duplicates on the round trip and 35 on the ablation, all `file` rows. The
final pass refined items 1 and 2 (the entry must hold a file object; the
`based-on` join needs one named observable) and added items 4 and 5. The
figures of A2 and A3 are measured on this final state.

**The file-name decision (D9), which reverses the first design.** A file name
was a weak key: a status, never a merge. It is now merged into the baseline's
file when exactly one baseline file (one index entry holding a file object) carries
that name. Two carriers: no merge, and the row stays `new`. A name carried only
by a name-only Indicator, with no file object, matches nothing. Reason: in the
first A4 run, OpenCTI held a second `svchost_update.dll` (CTIParsor's, name only) beside the
baseline's (name, MD5 and SHA-256). The review's "in STIX" badge and the bundle
disagreed, which invariant I6 forbids. Cost: a name-only file that is another
sample than the baseline's one file of that name is merged onto it (see
Consequences).

**The OpenCTI findings (A4, 7.260930.0).**

- *Importer capabilities.* Besides knowledge create and update, a non-admin
  importer needs `SETTINGS_SETMARKINGS` (without it every object carrying a
  marking is refused: FORBIDDEN_ACCESS, then MISSING_REFERENCE_ERROR "User
  trying to create the data has missing markings"), `KNOWLEDGE_KNUPLOAD` (the
  source artifact) and `SETTINGS_SETKILLCHAINPHASES` (attack patterns with kill
  chain phases). Its maximum confidence must be at least the Report's, or the
  additions are dropped without an error (the counter-test above).
- *Aliased standard ids.* OpenCTI gives some objects its own `standard_id` (an
  intrusion set's, from its name) and keeps the bundle's id in
  `x_opencti_stix_ids`. References resolve through that alias.
- *Ids that change between builds.* CTIParsor's relationship and ATT&CK
  attack-pattern ids differ between two builds of the same job (random ids,
  ADR-0066). OpenCTI attached the new ids as aliases of the existing entities:
  no duplicate.

**Other lot 7 changes.**

- `scripts/audit_bundle_invariants.py`: an Indicator whose `pattern_type` is a
  detection-rule type (`yara`, `sigma`, `suricata`, `snort`, `pcre`) is no
  longer reported as a malformed STIX pattern or a bad `pattern_type`. Such
  rules ship since ADR-0067 and ADR-0070. Tests: `tests/test_audit_bundle_patterns.py` (2).
- `scripts/baseline_ablation.py` (A3, and its external control on the fixtures;
  read only, on the measurement database), `scripts/baseline_round_trip.py` (A2
  end to end, read only, offline) and `scripts/opencti_import_check.py` (A4, run
  with pycti in a separate venv, never a project requirement; it creates a role,
  a group, a user and an unlimited token it never revokes, so it runs on a
  throwaway instance only), with `docker/opencti-test/` (`compose.yaml`: every
  secret required, RabbitMQ pinned to `4.3.7-management`; `.env.example`). How to
  run them again: `TESTING.md`, "Measuring baseline reconciliation and the OpenCTI
  import". Tests: `tests/test_baseline_ablation.py` (25) and
  `tests/test_baseline_round_trip.py` (8).
- The flag `STIX_ENRICHMENT_ENABLED` defaults to `true` (`api/routes/_common.py`,
  `enrichment_enabled`); `false` turns the mode off.

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
| 7 | Measures A3, A4, A6, acceptance, flag default `true`, this ADR Accepted with the figures (done 2026-10-25) | figures in this ADR; see "Lot 7" |

Lot 7 starts the OpenCTI Docker on demand only (about 8 GB of RAM under WSL).
