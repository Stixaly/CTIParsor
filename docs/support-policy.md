# Support policy

What CTIParsor 1.0 promises, what it does not, and how each promise is checked.
The decision and the options rejected are in
[ADR-0094](adr/0094-what-1-0-promises.md), which is **Proposed**.

**1.0 is not released.** The latest release is 0.2.0 (2026-10-29). Until 1.0,
the rules of [releasing.md, Versioning](releasing.md#versioning) apply: a minor
release may change any surface below, and the CHANGELOG says what an operator
must do. Several promises below have no evidence yet. Each row that lacks it
says so, and names the item of ADR-0094's plan that will provide it. This page
was checked against the code at commit 1c11b87 on 2026-10-31.

- [Who 1.0 is for](#who-10-is-for)
- [What 1.0 promises](#what-10-promises)
- [What 1.0 does not promise](#what-10-does-not-promise)
- [Stable surfaces](#stable-surfaces)
- [Breaking changes and deprecation](#breaking-changes-and-deprecation)
- [Capability matrix](#capability-matrix)
- [Quality: what is measured and published](#quality-what-is-measured-and-published)
- [Release blockers](#release-blockers)
- [Maintenance of 1.x](#maintenance-of-1x)
- [How to report a problem](#how-to-report-a-problem)

## Who 1.0 is for

One analyst, on a self-hosted install on their own machine, who reviews the
extractions before they are exported. The journey 1.0 covers:

1. import a report (a file, pasted text or a captured URL), alone or with a
   STIX 2.1 bundle to enrich;
2. review the extracted entities and relationships, then finalize;
3. export the STIX 2.1 bundle, and import it into OpenCTI;
4. upgrade to the next release;
5. restore a backup.

One person maintains the project. No promise on this page assumes a team.

## What 1.0 promises

Three things, and only these.

1. **A stable contract.** The surfaces under [Stable surfaces](#stable-surfaces)
   change incompatibly only in a new major version.
2. **Data that survives.** An upgrade from the previous release, and a restore
   from a backup, keep the reports, the review decisions, the baselines and the
   bundles.
3. **Measured, published limits.** Each release publishes the extraction
   measured on the bundle it exports, with the denominators and the limits
   ([Quality](#quality-what-is-measured-and-published)).

## What 1.0 does not promise

- **A level of precision.** No precision threshold blocks a release. A report
  can yield wrong objects: the analyst's review is part of the product.
- **The same predictions.** Two releases, or two runs of one release, can
  extract different objects from one report. With the provider's default
  sampling, two runs of one configuration differed by 0.028 F1 on the AnnoCTR
  dev split ([eval/README.md](eval/README.md), *Run-to-run spread*).
- **Several users.** There is no authentication and no access control
  ([SECURITY.md](../SECURITY.md)).
- **An install other than Docker Compose**
  ([ADR-0054](adr/0054-full-docker-installation.md)).
- **Fixes on an older version line, or a support duration**
  ([Maintenance of 1.x](#maintenance-of-1x)).
- **An import into a consumer other than the OpenCTI version the
  [matrix](#capability-matrix) names.**
- **What the matrix marks experimental or not supported.**

## Stable surfaces

What a 1.0 user can build on. Anything not listed here can change in a minor
release.

### HTTP API

- **Every operation of the OpenAPI schema** the app publishes at
  `/openapi.json` (60 operations on 2026-10-31; interactive at `/docs`), as
  [api.md](api.md) documents it: path, method, parameters, request body,
  response fields and status codes.
- **Routes stay under `/api/`.** There is no `/api/v1`: stability does not
  depend on a URL prefix.
- **The points clients rely on most:**
  - `GET /api/jobs/{id}/bundle` answers 200 with the header
    `X-Bundle-Validation: validated | unverified | unknown`, or 409 with
    `{"detail": {"validation": "invalid", "errors": [...]}}` when Stage 5
    refused the bundle. `POST /api/jobs/{id}/finalize`, and `PATCH
    /api/jobs/{id}` to `completed`, answer the same 409
    ([ADR-0084](adr/0084-a-bundle-stage-5-refuses-is-not-served.md)).
  - 413 when a body exceeds its route's budget (the table in api.md); 503 when
    the queue is full; 400 for a baseline sent while
    `STIX_ENRICHMENT_ENABLED=false`.
  - `GET /api/health`: 200, or 503 when the database does not answer.
  - The job statuses `uploaded`, `queued`, `processing`, `for_review`,
    `reviewing`, `completed` and `failed`.
  - The layout of the detection export archive:
    `rules/{format}/{corpus}__{slug}.{ext}`, `MANIFEST.json`, `README.txt`.
- **Progress (SSE),** `GET /api/jobs/{id}/progress`: the event names
  `connected`, `queued`, `stage`, `partial_graph` and `done`. The events
  recorded for the job carry an `id`, and a client that reconnects with
  `Last-Event-ID` resumes after it. `done` carries `status`, and `error` when
  the job failed or the stream timed out.

Not covered:

- the fields inside the `data` of `stage` and `partial_graph` events: they feed
  the progress display and change with the stages;
- the text of error messages (`detail` strings), except the structure of the
  409 body above;
- the web interface: its pages, layout and wording. Its journey is covered by
  the [release blockers](#release-blockers), not its screens.

Evidence today: `contract/openapi.json` records each operation of the schema
by method and path, a path parameter by its position (its name is invisible to
a client): its parameters, request body and responses, field by field, with
their types, whether they are required and the values they allow, and on the
request side the limits, formats and patterns, and whether an object refuses
unknown fields (321 entries on 2026-10-31). FastAPI's own 422, its
validation-error body, is left out: the policy does not cover error details.
`tests/test_contract.py` compares it with the code on every pull request
([Breaking changes and deprecation](#breaking-changes-and-deprecation)).
Its limits: 47 of the 60 operations publish no schema for their success
response and 12 an object without fields, so the fields they return are not
recorded; only `POST /api/baselines/inspect` declares its own. The 409 body
above is not in the schema either: its responses declare no content. The job
statuses, the `X-Bundle-Validation` values, the SSE event names and the layout
of the export archive are strings in the code, not in the schema: route tests
check them and the 409 body (`tests/test_jobs_routes.py`,
`tests/test_api_routes.py`, `tests/test_detection_coverage.py`), the contract
does not.

### Command line

- **The container commands** of `docker/entrypoint.sh`: `serve` (the default),
  `worker`, `bootstrap` with `--no-models`, `--no-corpora` and `--strict`,
  `cli <arguments>` and `check`. For example
  `docker compose run --rm app cli /input/report.pdf` ([docker.md](docker.md),
  *Day-to-day operations*). `bootstrap --strict` exits 1 when a model or a
  corpus is missing.
- **The arguments of the pipeline CLI** (`main.py`, run through `cli`): a file
  or `--input-dir DIR`, `--output`, `--output-dir`, `--disable-stage ID`,
  `--require-stage ID`, `--policy db|none|FILE` and `--no-llm`. The stage ids
  are `1 1f 2 2b 2c 2d 2e 2g 3 3d 3f 3e 3doc 3r 2f 4 4b 4c 5`; `1` and `3r`
  cannot be disabled.
- **Its exit codes:**

  | Code | One file | `--input-dir` |
  |---|---|---|
  | 0 | the bundle was written and Stage 5 did not refuse it (`validated` or `unverified`) | every file gave 0, or the folder holds no supported file |
  | 1 | Stage 5 refused the bundle; the file was not found; a stage named by `--require-stage` did not run; the database cannot be migrated | the folder does not exist; a file gave 1; the database cannot be migrated |
  | 2 | usage error: a wrong argument, an unknown or mandatory stage id, a `STIX_TLP` value that is refused | the same |

- **`make db-upgrade`**, the PostgreSQL major upgrade of
  [upgrading.md](upgrading.md) §7.

Not covered:

- what the CLI prints: its messages are in French and change with the stages;
- `scripts/`: development, measurement and maintenance tools. A script that an
  operator page ([docker.md](docker.md), [upgrading.md](upgrading.md)) tells you
  to run is supported as that page describes it, not as an interface of its
  own;
- `python -m evaluation`, the evaluation harness of
  [ADR-0060](adr/0060-evaluation-protocol.md): a development tool;
- `python -m api.migrate`: a development tool, since every start applies the
  migrations;
- the other `make` targets, and the `dev` and `frontend-dev` services of
  `compose.yaml`;
- importing `pipeline/`, `api/` or `models/` from your own code. There is no
  Python package ([ADR-0085](adr/0085-releases-promote-the-image-main-built.md)).

Evidence today: `contract/cli.json` records the arguments of `main.py` as
`build_parser()` declares them (action, type, const, default, choices, whether
required, the group that makes a file and `--input-dir` exclusive), the stage
ids and which can be disabled, the commands and `bootstrap` options of
`docker/entrypoint.sh`, and `make db-upgrade` (36 entries on 2026-10-31).
`tests/test_cli_exit_codes.py` runs `main()` for each row of the exit-code
table, with the pipeline and the database replaced where a real run would
need them. Two changes read as breaking although they are not, and are
recorded with `make contract ACCEPT_BREAKING=1`: a new alias of an option
renames its entry (`--output` becoming `-o|--output`), and a command whose
`case` label also names an alias (`serve|api)`) is no longer read.

### Configuration

- **Every variable of [`.env.example`](../.env.example)** (141 on 2026-10-31),
  except those listed below: its name, its meaning and the values it accepts.
  An on/off flag reads `1`, `true`, `yes`, `on` and `0`, `false`, `no`, `off`
  ([configuration.md](configuration.md)).
- **A default is the value a fresh install runs with:** the value
  `.env.example` sets, which `setup.sh` copies to `.env`, or, for a line it
  leaves commented out, the value it shows.
- **A default may change in a minor release** when the previous behaviour stays
  available by setting the variable. The CHANGELOG names the change and the
  value that restores the old behaviour. `WORKER_MAX_CONCURRENT` going from 10
  to 1 in the code (pull request #229) is such a change.
- **A value that is refused stays refused:** a `STIX_TLP` outside the TLP
  levels stops the start
  ([ADR-0073](adr/0073-tlp-fail-closed-and-amber-strict-as-opencti-defines-it.md)),
  and an unknown `ATTACK_RELEASE` stops the run
  ([ADR-0087](adr/0087-an-attack-release-is-a-track-a-run-selects.md)).
- **The Compose layout:** the services `app`, `worker`, `postgres` and
  `capture-proxy`; the profiles `bootstrap`, `ollama` and `proxy`; the volumes
  `cti-state`, `cti-cache` and `pg-data-18`, and `ollama-models` for the
  `ollama` profile; the `CTI_*` variables of `.env.example`.

Not covered:

- `SKIP_HEAVY_MODELS` (tests only) and `TTP_RETRIEVAL_EXCLUDE_CITED` (the
  evaluation);
- the default values of calibrated settings: the thresholds and gates of
  configuration.md's *NLP stages* and *Expert tuning*. Their names stay; their
  values follow measurements;
- the default model of a stage or a provider (`ANTHROPIC_MODEL`,
  `CYNER_MODEL`, `GLINER_MODEL`, `TTP_EMBEDDING_MODEL` and the like). A new
  default is announced in the CHANGELOG.

Evidence today: `contract/config.json` records each variable of
`.env.example`, whether its line sets it, and the value it shows: 139
variables, the file's 141 but the two above. A commented variable is a line
`# NAME=value`, one space, no blank in the value, so the prose lines that look
like one (the conventions' `KEY=value`, a command line, a heading) are not
read; a test names these three and fails on any other line that looks like a
variable but is not read. It also records the Compose layout: the project name
(`ctiparsor`, which prefixes the name of every volume), each service with its
profiles, and the named volumes with their own `name:` when one is set, the
`dev` profile left out (7 services and 4 volumes on 2026-10-31). A changed
value is reported as a changed default, which the CHANGELOG names: a
calibrated threshold or a default model changes that way, without breaking
the contract. Its limit: only `.env.example` is read, not the code. A
variable the code stops reading, or a default in the code that no longer
matches the value `.env.example` shows, is not caught.

### Persistent data

- **What is kept:** the PostgreSQL database (volume `pg-data-18`: reports,
  review decisions, baselines, bundles, the detection-rule store) and the files
  of `cti-state` (uploads, exported bundles, `db-identity.json`). `cti-cache`
  (models, corpora) is rebuilt by `bootstrap`.
- **The promise:** the image of a release, started on the database and the
  `cti-state` volume of the previous release, migrates them at its first start
  and keeps their content. The schema is versioned in `api/migrations/`
  (14 versions on 2026-11-01). The API, every worker and `bootstrap` apply what
  is pending at start, under a PostgreSQL advisory lock, one transaction per
  version ([ADR-0077](adr/0077-versioned-database-migrations.md)).
- **No downgrade.** An older image refuses a database that a newer one
  migrated. To go back, restore the backup taken before the upgrade
  ([docker.md, Data and backups](docker.md#data-and-backups)).
- **A PostgreSQL major upgrade** needs `make db-upgrade` before the first
  start ([upgrading.md](upgrading.md) §7). The release that brings one says so
  in its notes.
- **The SQL schema is not an interface.** Reading or writing the tables
  directly is not covered. [database-schema.md](database-schema.md) describes
  them for maintenance.

Evidence today: on every push to main, every pull request and every weekly
run, CI migrates a database written by the last release (the highest tag
`vX.Y.Z`) and, on a pull request, one written by the base commit
(`scripts/check_migration_from.py`, ADR-0094 item 2). Each is built by that
release's own code and seeded with four reports and what an analyst grows
beside them: decisions and their journal, bundles with their verdict, ledger
and build record, a STIX baseline, overrides, thresholds, the relationship
policy, a detection rule, and the uploaded sources and exported bundles of
the state volume. Its bundles and ledgers are the release's own Stage 4
reference builds when its tree has them (`v0.1.0` has none: today's are
written). Every column of every table holds a value in at least one seeded
row. Every value and every column's type is compared before and after the
migration, then again once the API has started and read the seed back; each
identity column's sequence must stay above its highest value, and the state
volume's files must not change.

Evidence for a restore, on the same runs: such a seeded database and its
state directory are backed up with the `pg_dump`, `pg_restore` and `tar` flags
of [docker.md](docker.md#data-and-backups) and restored into an empty database
and directory. Every row, column type, sequence, schema object (tables,
columns, constraints, indexes, triggers, functions) and file must come back as
it was, with nothing more, and the API reads the seed back
(`scripts/check_backup_restore.py`, ADR-0094 item 3). The container-image job
runs the documented commands themselves on a Compose stack, and restores it
into a second, empty project (`scripts/docker_smoke.sh --backup-restore`).
Not compared: the ACLs of sequences and functions and the owners of sequences
(the tables' ACLs and owners and the functions' owners are), comments, types
and domains, table options, objects outside the app's schema, and file modes
and owners; the schema this code creates uses none of the first five.

### STIX output

Stable:

- **STIX 2.1**, checked by Stage 5. A bundle Stage 5 refuses is not served.
- **The mapping:** which extracted value becomes which STIX object, as the
  table of [stix-output.md](stix-output.md) states it.
- **The custom properties CTIParsor writes**, with their names, types and
  meaning (values as stix-output.md lists them):

  | Property | On |
  |---|---|
  | `x_evidence_label`, `x_evidence_text` | relationships |
  | `x_inference_rule`, `x_inferred_from` | relationships added by graph completion (Stages 4b, 4c) |
  | `x_policy_rule`, `x_pin_evidence` | relationships added by a relationship-policy rule |
  | `x_temporal_assertions` | dated relationships ([ADR-0063](adr/0063-relationship-dates-keep-what-the-source-said.md)) |
  | `x_source_published`, `x_synthesis_stats`, `x_opencti_files` | the Report CTIParsor builds |
  | `x_ctiparsor_enrichment` | a baseline Report re-issued by enrichment ([ADR-0090](adr/0090-enriching-an-existing-stix-bundle.md)) |
  | `x_cvss_v3_score`, `x_cvss_v3_vector` | vulnerabilities |

- **The identity rules** ([ADR-0066](adr/0066-stix-ids-are-opencti-standard-ids.md)):
  a domain object, an indicator or a marking gets OpenCTI's standard id (as
  pycti's `generate_id` computes it); an observable gets the id STIX 2.1
  derives from its ID-contributing properties; an incident is identified by its
  name alone; relationships and the Report get a random UUIDv4. Apart from
  relationships and the Report, the same object gets the same id from one
  release to the next.
- **Markings and authorship:** the job's TLP (default `STIX_TLP`, AMBER) and
  optional PAP on every object CTIParsor builds, and one authoring identity in
  `created_by_ref`. An enriched bundle keeps the baseline's objects as
  received, with their markings (ADR-0090).

Varies, and is not a breaking change:

- which objects and relationships a report yields, and their `confidence`;
- generated text: the Markdown `description`s
  ([ADR-0093](adr/0093-context-in-stix-descriptions.md)), the summaries a
  language model writes, the sentences quoted as evidence;
- the ids of relationships and of the Report, `created` and `modified`, the
  order of the objects;
- the names and descriptions of ATT&CK objects, as the selected ATT&CK release
  states them.

Evidence today: `contract/stix.json` is read from the five Stage 4 reference
bundles (`tests/fixtures/stage4_reference/expected/`, which
`tests/test_stage4_reference.py` keeps equal to the code): each custom
property found there with its JSON types, and the id of each object known by
a name, a value, a key, a pattern, hashes or a definition (not a
relationship), named by scenario, type and that property; a random id (the
Report's) is recorded as `random` (79 ids, 5 of them random, and 12
properties on 2026-10-31). A changed id is a breaking change: an identity rule
changed. An id that becomes random, or stops being random, is a changed id.
An object a scenario no longer yields is not a breaking change.
`x_ctiparsor_enrichment` is in none of these bundles (only an enriched bundle
carries it, and none is checked in): it is not checked yet.

## Breaking changes and deprecation

After 1.0, the version number says what changed:

| Version | For |
|---|---|
| Major | a breaking change to a stable surface |
| Minor | new behaviour, a deprecation, a changed default, a database migration |
| Patch | fixes only, without a database migration |

A database migration goes into a minor version, as before 1.0
([releasing.md](releasing.md#versioning)).

**A breaking change** needs a major version:

- removing or renaming a route, a response field, a CLI argument, an
  environment variable or a STIX custom property;
- changing the type or the meaning of any of them, or of a CLI exit code;
- making an optional request field or argument required;
- removing a value from a documented list: a job status, an
  `X-Bundle-Validation` value, an SSE event name;
- lowering a size limit that api.md documents;
- a migration that loses data;
- changing an identity rule of the STIX output.

**Not a breaking change:**

- a change in what the models predict. It shows in the release's measurement
  ([Quality](#quality-what-is-measured-and-published));
- a new response field, a new optional request field, a new route;
- a new variable whose default keeps the previous behaviour;
- a new STIX custom property;
- a new SSE event, a new stage id, a new reason in the mapping ledger
  (`GET /api/jobs/{id}/bundle/ledger`);
- a fix that makes a surface behave as its documentation says, listed under
  *Fixed* in the CHANGELOG.

A client ignores the fields and events it does not know.

**How a change is caught.** `scripts/contract.py` reads each stable surface
from the code and compares it with `contract/` (ADR-0094 item 1). It classes
each difference as `breaking` (a removal or a rename, a type a request no
longer accepts or a response may now return, a field made required, a value
removed from a list, a request limit, format or pattern that appears or
changes, a changed STIX id), `default` (a changed default) or
`compatible` (an addition, a relaxation, a deprecation flag).
`tests/test_contract.py` runs `python scripts/contract.py check` on every pull
request and fails on any difference, a compatible one included, so the
reference always equals the code. `make contract` records a change; it
refuses a breaking one unless `ACCEPT_BREAKING=1`, which needs a major version
and a CHANGELOG entry. Recording a change does not approve it: the version
number and the CHANGELOG do.

**A deprecation:**

1. is announced in the CHANGELOG under `### Deprecated` (Keep a Changelog, the
   format the CHANGELOG follows), and on the page that documents the surface,
   with what replaces it;
2. marks a deprecated route `deprecated` in the OpenAPI schema;
3. makes a deprecated variable that is still set print a warning in the start
   log of the API and of each worker, naming its replacement. No variable is
   deprecated on 2026-10-31 and no such check exists yet: the first
   deprecation adds it;
4. keeps the surface working until the next major version, and at least
   through one minor release after the one that announces it. The removal is
   listed under `### Removed` in that major version.

Stored data is never deprecated: a migration keeps it, or it is a
[release blocker](#release-blockers).

## Capability matrix

- **Supported:** covered by the promises above. A defect in it can block a
  release.
- **Experimental:** works, without commitment. It can change, or go, in a minor
  release.
- **Not supported:** not provided, or provided without any check.

"Not yet: item N" names the work item of ADR-0094 that will provide the missing
evidence.

| Capability | Status | Limits | Evidence |
|---|---|---|---|
| Install with Docker Compose | supported | the only supported install (ADR-0054); Docker Engine 24+, Compose v2.24+; CPU only; about 4.4 GB of RAM per report in flight ([docker.md](docker.md)) | CI builds the image and runs `scripts/docker_smoke.sh` (job `container-image`). A clean install from the published image: not yet, item 9 |
| Host install (venv, systemd) | not supported | [upgrading.md](upgrading.md) §3 keeps it only to move an old install | — |
| Upgrade from the previous release | supported | automatic at the first start; no downgrade; a PostgreSQL major needs `make db-upgrade` | CI migrates a database written by the last release tag, and on a pull request one written by the base commit: every value and column type of every table compared after the migration and after the API's first start, identity sequences checked, the seed read back through the API, the state volume's files unchanged (`scripts/check_migration_from.py`, ADR-0094 item 2) |
| Backup and restore | supported | the commands of [docker.md](docker.md#data-and-backups): `app` and `worker` stopped during the backup; a restore into an empty project, with the same `CTI_DB_USER` and `CTI_DB_NAME`, on the release that took the backup or a newer one; `cti-cache` and `.env` are not in it | CI runs the documented commands on a Compose stack and restores it into a second, empty project, every table and file compared (`scripts/docker_smoke.sh --backup-restore`, job `container-image`); and restores a seeded database and its state directory with the same flags, every row, sequence, schema object and file compared, the seed read back through the API (`scripts/check_backup_restore.py`, job `fast-tests`, ADR-0094 item 3) |
| Import a file: PDF, DOCX, HTML, TXT, Markdown | supported | 50 MB; a scanned page goes to OCR (experimental, below) | `tests/test_upload_route.py`, `tests/test_stage1.py`, `tests/test_stage1_pdf_paths.py`, `tests/test_pdf_table_cells.py` |
| Import pasted text | supported | 20 to 2,000,000 characters | `tests/test_ingest_routes.py` |
| Capture a URL | supported | headless Chromium, JavaScript off by default; public addresses only, through `capture-proxy`; absent from an image built with `CTI_INSTALL_CAPTURE=false` | `tests/test_web_capture.py` (URL policy); `docker_smoke.sh` checks that Chromium starts sandboxed. No live capture in CI |
| IoC extraction | supported | defanged values are refanged; a value the report names without accusing it (a non-routable address, one of the 10,000 most popular domains) ships without an Indicator ([stix-output.md](stix-output.md)) | `tests/test_stage2.py`; fuzzing of the parsers ([ADR-0081](adr/0081-fuzzing-the-attacker-facing-parsers.md), `tests/test_fuzz_targets.py`). Against a gold set: not yet, items 5 and 6 |
| Named entities (malware, threat actors, tools, campaigns, places, sectors) | supported | English models; low precision on AnnoCTR test ([Quality](#quality-what-is-measured-and-published)) | `tests/test_stage2b_gazetteer.py`, `tests/test_stage2d_cyner.py`, `tests/test_stage2e_gliner.py`; AnnoCTR measurements in [eval/](eval/README.md) |
| ATT&CK techniques | supported | ATT&CK 19.2 by default, 20.0 selectable (`ATTACK_RELEASE`); without an LLM, Stage 2c's detector replaces the selection ([configuration.md](configuration.md)) | `tests/test_ttp_select.py`, `tests/test_ttp_retrieval.py`; F1 0.690 on AnnoCTR test ([baseline-2026-10.md](eval/baseline-2026-10.md)) |
| Relationships | supported | needs an LLM (Stage 3) | `tests/test_stage3d_verify.py`, `tests/test_relationships_api.py`. Against a gold set: not yet, items 5 and 6 |
| Review and finalize | supported | no authentication; built for one analyst | `tests/test_jobs_routes.py`, `tests/test_entities_api.py`, `tests/test_relationships_api.py`, `tests/test_decisions.py`, `tests/test_held_for_review.py`, `tests/test_bundle_builds.py`. The browser journey (`scripts/check_browser_e2e.sh`, job `browser-e2e`, ADR-0094 item 4): in Chromium against the built interface, the API, its worker and PostgreSQL, offline, a report imported, its progress followed from the run's events, the page reloaded, rows accepted, rejected and retyped, the review completed and the bundle downloaded and checked; the same with the keyboard alone; an enrichment and its ledger, a failed report and its reason, a refused bundle (409); axe on each page (TESTING.md) |
| STIX 2.1 export | supported | a bundle Stage 5 refuses is not served (409); `unverified` when the JSON schemas are missing | `tests/test_stage5.py`, `tests/test_stage4_reference.py` (five reference scenarios), `tests/test_stix_ids.py` |
| Enrich an existing STIX 2.1 bundle ([ADR-0090](adr/0090-enriching-an-existing-stix-bundle.md)) | supported, on by default | STIX 2.1 only (2.0 is refused with 400); 20 MB; `STIX_ENRICHMENT_ENABLED=false` turns it off; OpenCTI- and MISP-shaped baselines checked on repository fixtures, not on live exports | `tests/test_baseline_*.py`; round trip and ablation on 7 real reports, 2026-10-25: 0 duplicate rows, 175 of 179 removed entries recovered ([TESTING.md](../TESTING.md)) |
| Detection rules quoted in a report (YARA, Sigma, Suricata, Snort) | supported | a rule ships only if the parser OpenCTI uses accepts it; without that parser it ships `unverified` | `tests/test_yara_check.py`, `tests/test_pattern_check.py` |
| Detection coverage from rule corpora (Sigma, Suricata, YARA): matrix, proposals, ZIP export | supported | corpora downloaded by `bootstrap` from third-party repositories, each under its own licence; no Snort corpus | `tests/test_detection_coverage.py`, `tests/test_sigma_adapter.py`, `tests/test_suricata_yara_adapters.py` |
| Import into OpenCTI | supported for OpenCTI 7.260930.0 | other versions not tested. OpenCTI drops the bundle's `x_` properties and the Report's `original_document` reference. An import at a higher confidence rewrites the object it reaches by its standard id: an analyst's malware of the same name gets CTIParsor's author, confidence and description, and loses its `first_seen`; an analyst's ATT&CK technique is renamed after its ID (PowerShell becomes `T1059.001`), because a technique found in the text with no Stage 3 entry (always offline) is exported named as written, under a random id, against the identity rules above: a known bug. OpenCTI merges an object into another that holds its name as an alias; the check fails on such a merge. One name can be held by two types (APT29 as the analyst's Intrusion-Set and CTIParsor's Threat Actor): reported as a WARN ([TESTING.md](../TESTING.md) lists what OpenCTI changes) | `scripts/check_opencti_candidate.sh` ([TESTING.md](../TESTING.md), ADR-0094 item 8), not in CI: the bundles a candidate image produces through its API, offline, each imported twice into a throwaway OpenCTI and read back. 83 of 83 expectations and 1 WARN on 2026-11-01, on main's image at 4df5cbd (`sha256:3301b5c43038a8ef3dcc8948ee8c6c84c2aa1ec5b5cb90fa17047b574ae0408f`). Run again on the image of each release from 1.0 ([releasing.md](releasing.md)) |
| Import into MISP | not supported | no connector and no import test. A MISP-shaped STIX 2.1 bundle is accepted as a baseline (row above) | — |
| LLM: vLLM serving `Inferact/Qwen3.8-27B-NVFP4` | supported | `VLLM_ENABLE_THINKING=false`; repeatable runs need `LLM_TEMPERATURE` and `LLM_SEED` set | every evaluation run recorded in [eval/](eval/README.md) that calls an LLM |
| LLM: `anthropic`, the default `LLM_PROVIDER` | supported | `ANTHROPIC_MODEL` defaults to `claude-sonnet-4-6`; the report's text goes to Anthropic's API, billed per call; no seed (`LLM_SEED` reaches vLLM, Ollama and LM Studio only), so two runs can differ | the request code, with a fake client: `tests/test_stage3_calls.py`, `tests/test_stage3_providers.py`. A recorded run: not yet, item 11 |
| LLM: `gemini`, `mistral`, `lmstudio`, `ollama`, or vLLM with another model | experimental | wired; no recorded run in the repository | the request code, with a fake client: `tests/test_stage3_calls.py`, `tests/test_stage3_providers.py`, `tests/test_local_llm_providers.py` |
| Figure reading (Stage 1f) | experimental | off by default (`VISION_PROVIDER=none`) | `tests/test_stage1f_figures.py`, `tests/test_vlm.py` |
| Air-gapped install ([ADR-0054](adr/0054-full-docker-installation.md)) | experimental | no commitment in 1.0 | CI checks only that the bundle's images come back from `docker save` and `docker load` (`scripts/check_offline_images.sh`) |
| Reports in French | experimental | English NER models (spaCy `en_core_web_lg`, else `en_core_web_sm`); no French report in either gold set | — |
| OCR of fully scanned PDFs | experimental | Tesseract, `OCR_LANG` default `eng`; no fully scanned report in the in-house set | `tests/test_stage1_pdf_paths.py` (routing); `tests/test_ingestion_structure.py` (one real OCR run, skipped without Tesseract and Poppler) |
| Several analysts, authentication, access control | not supported | no authentication; the `proxy` profile adds TLS and one password ([deployment.md](deployment.md)) | — |
| GPU | not supported | the image carries torch's CPU build | — |
| A Python package, `pipeline/` as a library | not supported | no sdist, wheel or PyPI package (ADR-0085) | — |

## Quality: what is measured and published

**From 1.0, each release publishes:**

- the extraction measured on the bundle the release exports, per layer (IoCs,
  entities, techniques, relationships) and per document;
- the denominators: the reports scored, the gold items per layer, and each
  report or layer not scored, with the reason;
- the configuration: commit, image digest, LLM provider and model, sampling
  (`LLM_TEMPERATURE`, `LLM_SEED`), ATT&CK release;
- the comparison with the previous release, on the same data and the same
  configuration. A regression is explained in the release notes.

No precision threshold blocks a release. The measurement is published as it
comes out.

**The data.** Two gold sets ([ADR-0060](adr/0060-evaluation-protocol.md),
[eval/README.md](eval/README.md)):

- AnnoCTR, public: 120 reports with the cyber layer (70 train, 16 dev,
  34 test), read as clean text. It annotates techniques and named entities.
  The test split is read once per decision.
- The in-house set: reports read from their original file. On 2026-10-31,
  9 reports are in `data/eval/inhouse/` (git-ignored), all `pre-annotation`,
  none with a layer declared ([inhouse-set.md](eval/inhouse-set.md)).

**What the in-house annotation will cover.** Every layer of `LAYERS` in
`evaluation/inhouse.py` (`iocs`, `entities`, `techniques`, `relations`), on
every report, each declared in the `layers` field of its `gold.json`. Negative
cases are annotated as [annotation-guide.md](eval/annotation-guide.md) §6 asks,
and scored wherever a report has them. The limits, published with every
figure: 9 reports, one annotator, a pilot. Nine reports do not detect a small
difference between two releases, so the results are given per document as
well as in aggregate.

**What is published today, and its limits.** Before 1.0 the figures are not
measured on the exported bundle. The AnnoCTR runner turns off Stages 1f, 4
and 5, and `inhouse-run` turns off Stage 5 (`evaluation/__main__.py`). The
figures below describe Stages 1 to 3 at the commit their page names, with vLLM
serving `Inferact/Qwen3.8-27B-NVFP4`:

| Measure, AnnoCTR test split | Value | Date | Page |
|---|---|---|---|
| Techniques, parent level: precision / recall / F1 | 0.679 / 0.702 / 0.690 (34 reports, 332 gold parents) | 2026-10-11 | [baseline-2026-10.md](eval/baseline-2026-10.md) |
| Malware: precision / recall | 0.194 / 0.873 | 2026-10-19 | [ner-malware-2026-10.md](eval/ner-malware-2026-10.md) (baseline run) |
| Threat actors: precision / recall | 0.259 / 0.967 | 2026-10-19 | same |
| Locations: precision / recall | 0.505 / 0.545 | 2026-10-19 | same |

IoCs and relationships have no gold measurement yet: AnnoCTR does not annotate
them, and the in-house set is not annotated.

One more limit, until the measurement of the exported bundle replaces the
current scorer: the in-house entity score counts only the entity types the
report's gold contains (`evaluation/inhouse.py`). A false positive of a type
the report does not hold is not counted.

## Release blockers

Any one of these, while open, blocks a release, 1.0 and every one after it:

1. **Data loss:** an upgrade, a restore or a normal operation loses a report,
   a baseline or a bundle.
2. **A lost review decision:** an analyst's accept or reject does not reach the
   stored rows or the next bundle.
3. **An invalid export presented as validated:** a bundle Stage 5 refused is
   served, or reported as `validated`.
4. **An unusable essential journey:** import, review or export cannot be
   completed.

Other defects are fixed in the order the maintainer chooses. They do not hold
a release.

**Before 1.0,** the candidate is frozen and used on 5 real reports outside the
evaluation corpora, up to the export and an import into OpenCTI. 1.0 is tagged
when no blocking incident is open and the work items of ADR-0094 are done.

## Maintenance of 1.x

- **Only the latest minor version gets fixes.** A fix lands on `main` and ships
  in the next release. An earlier 1.x is not patched.
- **No double maintenance.** No fix is backported to an older minor version,
  to 0.x, or, once 2.0 exists, to 1.x.
- **No support duration** is promised.
- **To get a fix, upgrade to the latest release.** The data promise is checked
  for the step from the previous release. An older install goes through the
  same migration history, but only that last step is checked.
- **Security:** [SECURITY.md](../SECURITY.md#supported-versions) supports the
  latest release only, and says how a vulnerability is handled.

## How to report a problem

- **A vulnerability:** privately, as
  [SECURITY.md](../SECURITY.md#reporting-a-vulnerability) describes. Never in
  a public issue.
- **Anything else:** a [GitHub issue](https://github.com/Stixaly/CTIParsor/issues).
  Give:
  - the version: the image tag or digest, or `info.version` in
    `/openapi.json`;
  - what you ran, what you expected and what happened;
  - the job's stage report, or the bundle, if the report itself can be shared;
  - whether it hits one of the [release blockers](#release-blockers).
