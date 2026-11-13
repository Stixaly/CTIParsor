# Support policy

What CTIParsor 1.0 promises, what it does not, and how each promise is checked.
The decision and the options rejected are in
[ADR-0094](adr/0094-what-1-0-promises.md), accepted on 2026-11-01.

**1.0 is not released.** The latest release is 0.7.0 (2026-11-10). Until 1.0,
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
- [Capabilities: implemented, qualified, limits](#capabilities-implemented-qualified-limits)
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

**This will change.** [ADR-0097](adr/0097-1-0-is-a-shared-service-for-one-team.md)
(accepted on 2026-11-08) makes 1.0 a shared service for one
team: one install shared by several users, behind authentication, with roles.
The authentication it asks for is in the code, opt-in. With `AUTH_MODE=off`, the
default, the text above is the current state: no authentication, one analyst, and
an API that refuses to start on a bind address beyond loopback
([deployment.md](deployment.md)). The 1.0 qualification of the shared service is
not complete ([1.0-readiness.md](releases/1.0-readiness.md)).

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
- **Several users.** With `AUTH_MODE=off` (the default) there is no authentication
  and no access control ([SECURITY.md](../SECURITY.md)). Authentication is opt-in
  (ADR-0097).
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
statuses and the `X-Bundle-Validation` values are recorded in the schema as
enumerations (the `status` of a job, and the header of `GET /api/jobs/{id}/bundle`),
so a value removed from either is a breaking change. The SSE event names and
the layout of the export archive are recorded in `contract/formats.json` (see
below). Route tests still check the 409 body (`tests/test_jobs_routes.py`,
`tests/test_api_routes.py`, `tests/test_detection_coverage.py`); the contract
does not record it.

`contract/formats.json` holds the strings a client reads, which are not in the
schema:

- **The SSE event names** (`sse event <name>`): `connected`, then the stored
  progress types `queued`, `stage`, `partial_graph` and `done`
  (`api/db.py`, `api/routes/progress.py`), with whether a job stores each one.
  The frontend's listeners must name only these (`tests/test_contract_formats.py`).
- **The detection export ZIP** (`api/routes/coverage.py`): the manifest and
  readme names, the `rules` directory, and the file extension of each format
  (`sigma`, `suricata`, `yara`) and of any other.

Renaming one of these is a breaking change, and so is any change to its
recorded value; a name added is compatible.

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
  | 0 | the bundle was written and Stage 5 did not refuse it (`validated` or `unverified`), or Stage 4 or 5 was disabled with `--disable-stage` | every file gave 0, or the folder holds no supported file |
  | 1 | Stage 5 refused the bundle; the file was not found; a stage named by `--require-stage` did not run; the database cannot be migrated | the folder does not exist; a file gave 1; the database cannot be migrated |
  | 2 | usage error: a wrong argument, an unknown or mandatory stage id, a `STIX_TLP` value that is refused | the same |

- **The bundle names of a batch** (`--input-dir`, `--output-dir`). Every
  file gets `{stem}_bundle.json` in the output folder. A file whose stem
  another file of the batch shares, ignoring case, keeps its extension in
  the name (`report_md`, `report_txt`). A name that another file of the batch
  already takes gets `_2`, `_3`, and so on. A name that does not collide does
  not change. The planned names are printed before the first file runs. A
  bundle that Stage 5 refuses is written as `{stem}_bundle_invalid.json`, and
  the summary prints the path each file wrote, or `aucun fichier écrit`.
  A bundle already in the output folder under a name this batch plans is
  replaced by the run; no other file of the folder is touched. A single file
  with `--output` keeps the path it is given.

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

Evidence today: `contract/stix.json` is read from the seven Stage 4 reference
bundles (`tests/fixtures/stage4_reference/expected/`, which
`tests/test_stage4_reference.py` keeps equal to the code): each custom
property found there with its JSON types, and the id of each object known by
a name, a value, a key, a pattern, hashes or a definition (not a
relationship), named by scenario, type and that property; a random id (the
Report's) is recorded as `random` (87 ids, 7 of them random, and 13
properties on 2026-11-12). The `offline` scenario holds techniques no Stage 3
entry lists, as the offline profile exports them. The `opencti_enriched`
scenario enriches the OpenCTI baseline of `tests/fixtures/baselines/`
(ADR-0090): its Report is re-issued with `x_ctiparsor_enrichment`, which is
recorded. The objects it keeps from the baseline are not recorded: a baseline
object is kept as received, so its id is the upstream's, not one CTIParsor
computes. A changed id is a breaking change: an identity rule
changed. An id that becomes random, or stops being random, is a changed id.
An object a scenario no longer yields is not a breaking change.

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
| Install with Docker Compose | supported | the only supported install (ADR-0054): a release's archive and its image pinned by digest ([README](../README.md#quick-start)), or a build from a release tag; Linux x86-64 or WSL2 (the image is `linux/amd64` only); Docker Engine 24+, Compose v2.24+; CPU only; about 4.4 GB of RAM per report in flight ([docker.md](docker.md)) | CI builds the image and runs `scripts/docker_smoke.sh` (job `container-image`). `scripts/check_clean_install.sh` ([TESTING.md](../TESTING.md#clean-install-from-the-published-image), ADR-0094 item 9), not in CI: 0.2.0 installed from its archive and its image by digest as the README writes it, with the models and corpora (`bootstrap` 387 s, without an `HF_TOKEN`), a report reviewed and exported (`validated`), a restart with a report in flight (requeued, then finished), the upgrade to main's image at 248382c (`sha256:d3ee078fcecca0b100e1fb89eccf2fbea4316a898dc90d65c2b2612af6a122c8`) as docs/upgrading.md writes it, and the backup restored into an empty project: every step passed on 2026-11-01, in 14 minutes with the images present, as root under WSL2. Run again on the image of each release from 1.0 ([releasing.md](releasing.md)) |
| Host install (venv, systemd) | not supported | [upgrading.md](upgrading.md) §3 keeps it only to move an old install | — |
| Upgrade from the previous release | supported | the steps of [upgrading.md](upgrading.md#from-one-release-to-the-next): a backup, the new release beside the old one, `pull`, `up -d`, `bootstrap`; the schema migrated at the first start; no downgrade (restore the backup); a PostgreSQL major needs `make db-upgrade` | CI migrates a database written by the last release tag, and on a pull request one written by the base commit: every value and column type of every table compared after the migration and after the API's first start, identity sequences checked, the seed read back through the API, the state volume's files unchanged (`scripts/check_migration_from.py`, ADR-0094 item 2). The documented steps: 0.2.0 upgraded to main's image at 248382c on 2026-11-01, schema 13 to 14, a report and its bundle's sha256 unchanged (`scripts/check_clean_install.sh`, item 9) |
| Backup and restore | supported | the commands of [docker.md](docker.md#data-and-backups): `app` and `worker` stopped during the backup; a restore into an empty project, with the same `CTI_DB_USER` and `CTI_DB_NAME`, on the release that took the backup or a newer one; `cti-cache` and `.env` are not in it | CI runs the documented commands on a Compose stack and restores it into a second, empty project, every table and file compared (`scripts/docker_smoke.sh --backup-restore`, job `container-image`); and restores a seeded database and its state directory with the same flags, every row, sequence, schema object and file compared, the seed read back through the API (`scripts/check_backup_restore.py`, job `fast-tests`, ADR-0094 item 3). The documented commands from an install of 0.2.0: its backup restored with 0.2.0 into an empty project after the upgrade, the report and its bundle's sha256 back, on 2026-11-01 (`scripts/check_clean_install.sh`, item 9) |
| Import a file: PDF, DOCX, HTML, TXT, Markdown | supported | 50 MB; a scanned page goes to OCR (experimental, below) | `tests/test_upload_route.py`, `tests/test_stage1.py`, `tests/test_stage1_pdf_paths.py`, `tests/test_pdf_table_cells.py` |
| Import pasted text | supported | 20 to 2,000,000 characters | `tests/test_ingest_routes.py` |
| Capture a URL | supported | headless Chromium, JavaScript off by default; public addresses only, through `capture-proxy`; absent from an image built with `CTI_INSTALL_CAPTURE=false` | `tests/test_web_capture.py` (URL policy); `docker_smoke.sh` checks that Chromium starts sandboxed. No live capture in CI |
| IoC extraction | supported | defanged values are refanged; a value the report names without accusing it (a non-routable address, one of the 10,000 most popular domains) ships without an Indicator ([stix-output.md](stix-output.md)) | `tests/test_stage2.py`; fuzzing of the parsers ([ADR-0081](adr/0081-fuzzing-the-attacker-facing-parsers.md), `tests/test_fuzz_targets.py`). Against a gold set: not yet, items 5 and 6 |
| Named entities (malware, threat actors, tools, campaigns, places, sectors) | supported | English models; low precision on AnnoCTR test ([Quality](#quality-what-is-measured-and-published)) | `tests/test_stage2b_gazetteer.py`, `tests/test_stage2d_cyner.py`, `tests/test_stage2e_gliner.py`; AnnoCTR measurements in [eval/](eval/README.md) |
| ATT&CK techniques | supported | ATT&CK 19.2 by default, 20.0 selectable (`ATTACK_RELEASE`); without an LLM, Stage 2c's detector replaces the selection ([configuration.md](configuration.md)) | `tests/test_ttp_select.py`, `tests/test_ttp_retrieval.py`; F1 0.690 on AnnoCTR test ([baseline-2026-10.md](eval/baseline-2026-10.md)) |
| Relationships | supported | needs an LLM (Stage 3) | `tests/test_stage3d_verify.py`, `tests/test_relationships_api.py`. Against a gold set: not yet, items 5 and 6 |
| Review and finalize | supported | with `AUTH_MODE=off` (the default), no authentication; with authentication on, the role of each operation (`api/auth/permissions.py`), and an analyst deletes only the reports they imported | `tests/test_jobs_routes.py`, `tests/test_entities_api.py`, `tests/test_relationships_api.py`, `tests/test_decisions.py`, `tests/test_held_for_review.py`, `tests/test_bundle_builds.py`. The browser journey (`scripts/check_browser_e2e.sh`, job `browser-e2e`, ADR-0094 item 4): in Chromium against the built interface, the API, its worker and PostgreSQL, offline, a report imported, its progress followed from the run's events, the page reloaded, rows accepted, rejected and retyped, the review completed and the bundle downloaded and checked; the same with the keyboard alone; an enrichment and its ledger, a failed report and its reason, a refused bundle (409); axe on each page (TESTING.md) |
| STIX 2.1 export | supported | a bundle Stage 5 refuses is not served (409); `unverified` when the JSON schemas are missing | `tests/test_stage5.py`, `tests/test_stage4_reference.py` (six reference scenarios), `tests/test_stix_ids.py` |
| Enrich an existing STIX 2.1 bundle ([ADR-0090](adr/0090-enriching-an-existing-stix-bundle.md)) | supported, on by default | STIX 2.1 only (2.0 is refused with 400); 20 MB; `STIX_ENRICHMENT_ENABLED=false` turns it off; OpenCTI- and MISP-shaped baselines checked on repository fixtures, not on live exports | `tests/test_baseline_*.py`; round trip and ablation on 7 real reports, 2026-10-25: 0 duplicate rows, 175 of 179 removed entries recovered ([TESTING.md](../TESTING.md)) |
| Detection rules quoted in a report (YARA, Sigma, Suricata, Snort) | supported | a rule ships only if the parser OpenCTI uses accepts it; without that parser it ships `unverified` | `tests/test_yara_check.py`, `tests/test_pattern_check.py` |
| Detection coverage from rule corpora (Sigma, Suricata, YARA): matrix, proposals, ZIP export | supported | corpora downloaded by `bootstrap` from third-party repositories, each under its own licence; no Snort corpus | `tests/test_detection_coverage.py`, `tests/test_sigma_adapter.py`, `tests/test_suricata_yara_adapters.py` |
| Import into OpenCTI | supported for OpenCTI 7.260930.0 | other versions not tested. OpenCTI drops the bundle's `x_` properties and the Report's `original_document` reference. An import at a higher confidence rewrites the object it reaches by its standard id: an analyst's malware of the same name gets CTIParsor's author, confidence and description, and loses its `first_seen`. OpenCTI merges an object into another that holds its name as an alias; the check fails on such a merge. One name can be held by two types (APT29 as the analyst's Intrusion-Set and CTIParsor's Threat Actor): reported as a WARN ([TESTING.md](../TESTING.md) lists what OpenCTI changes) | `scripts/check_opencti_candidate.sh` ([TESTING.md](../TESTING.md), ADR-0094 item 8), not in CI: the bundles a candidate image produces through its API, offline, each imported twice into a throwaway OpenCTI and read back. 83 of 83 expectations and 1 WARN on 2026-11-01, on main's image at 4df5cbd (`sha256:3301b5c43038a8ef3dcc8948ee8c6c84c2aa1ec5b5cb90fa17047b574ae0408f`). Run again on the image of each release from 1.0 ([releasing.md](releasing.md)) |
| Import into MISP | not supported in 1.0; a target after it (ADR-0094, decision 14) | no connector and no import test. A MISP-shaped STIX 2.1 bundle is accepted as a baseline (row above) | — |
| LLM: vLLM serving `Inferact/Qwen3.8-27B-NVFP4` | supported | `VLLM_ENABLE_THINKING=false`; repeatable runs need `LLM_TEMPERATURE` and `LLM_SEED` set | every evaluation run recorded in [eval/](eval/README.md) that calls an LLM |
| LLM: `anthropic`, the default `LLM_PROVIDER` | supported | `ANTHROPIC_MODEL` defaults to `claude-sonnet-5-5`; the report's text goes to Anthropic's API, billed per call; no seed (`LLM_SEED` reaches vLLM, Ollama and LM Studio only), so two runs can differ. With the shipped `STIX_TLP=amber`, Stage 3 refuses this provider for every report: it runs only on CLEAR or GREEN reports, and an unmarked report takes `STIX_TLP` ([configuration.md](configuration.md#egress-policy-tlp)) | the request code, with a fake client: `tests/test_stage3_calls.py`, `tests/test_stage3_providers.py`. A recorded run: not yet, item 11 |
| LLM: `gemini`, `mistral`, `lmstudio`, `ollama`, or vLLM with another model | experimental | wired; no recorded run in the repository | the request code, with a fake client: `tests/test_stage3_calls.py`, `tests/test_stage3_providers.py`, `tests/test_local_llm_providers.py` |
| Figure reading (Stage 1f) | supported, on by default | PDF only, at most 40 figures per report. By default the figures are read by the provider chosen for the text, if its model passes the image probe, and the stage is skipped otherwise; a figure never goes to another provider, and none leaves the host when Stage 3 is disabled (`--no-llm`). `VISION_PROVIDER=none` turns it off | `tests/test_stage1f_figures.py`, `tests/test_vlm.py` (each provider's path and the skip), `tests/test_orchestrator.py` (the reason in the stage report). The measurement with the default provider: not yet, item 11 |
| Air-gapped install ([ADR-0054](adr/0054-full-docker-installation.md)) | experimental | no commitment in 1.0 | CI checks only that the bundle's images come back from `docker save` and `docker load` (`scripts/check_offline_images.sh`) |
| Reports in French | experimental | English NER models (spaCy `en_core_web_lg`, else `en_core_web_sm`); no French report in either gold set | — |
| OCR of fully scanned PDFs | experimental | Tesseract, `OCR_LANG` default `eng`; no fully scanned report in the in-house set | `tests/test_stage1_pdf_paths.py` (routing); `tests/test_ingestion_structure.py` (one real OCR run, skipped without Tesseract and Poppler) |
| Several analysts, authentication, access control | not supported | opt-in: `AUTH_MODE=local`, `oidc` or `both` (ADR-0097), off by default; the `proxy` profile adds TLS and one password ([deployment.md](deployment.md)). The qualification of several users is pending ([1.0-readiness.md](releases/1.0-readiness.md)) | `tests/test_auth_permissions.py`, `tests/test_auth_routes.py` |
| GPU | not supported | the image carries torch's CPU build | — |
| A Python package, `pipeline/` as a library | not supported | no sdist, wheel or PyPI package (ADR-0085) | — |

## Capabilities: implemented, qualified, limits

This table separates three things for each capability: what the code does,
what evidence shows it works, and what is still open. It was checked on
2026-11-13 against the code at commit 97a0bfa, the base of the branch that adds
it.

- **Implemented:** the code does it, and the tests named in the row exercise
  it. **no** means the capability is not in the code.
- **Qualified:** a run on a stack, a measurement, or a CI job shows it under the
  configuration the row names. A run that turns the capability off does not
  qualify it: a run with `VISION_PROVIDER=none` says nothing about figures. A
  run is cited with its date. **no** means no such evidence exists yet.
  **partly** means some of the claim is shown and the rest is not.
- **Limits** and **Open issue** say what is not covered and which issue holds
  the missing work.

Implemented is not qualified. The [capability matrix](#capability-matrix) keeps
each promise with its status and its limits. Two of its rows say *supported*
for a capability this table marks *no* for qualified: the `anthropic` provider
and figure reading with the default provider. The matrix already names the
missing evidence there (*not yet, item 11*). Changing those two statuses is a
decision for the maintainer.

| Capability | Implemented | Qualified | Limits | Open issue |
|---|---|---|---|---|
| Local accounts, roles, sessions and API tokens (`AUTH_MODE=local`) | **yes**, opt-in: `api/auth/`; the role of each route is in `api/auth/permissions.py` (reader, analyst, admin) | **partly** (2026-11-13): CI tests (`tests/test_auth_routes.py`, `tests/test_auth_permissions.py`, `tests/test_auth_store.py`), and the browser journey `scripts/check_browser_e2e.sh --auth local`, 3 of 3 passed, on one database with a reader, an analyst and an admin account: a reader read-only, a decision seen by the reader after a refresh, an expired session, a revoked token. No run with several analysts working at once is recorded ([readiness](releases/1.0-readiness.md): the qualification of several users is pending) | Off by default (`AUTH_MODE=off`). Every user sees every report; isolation between teams is after 1.0 ([ADR-0097](adr/0097-1-0-is-a-shared-service-for-one-team.md)) | #707 |
| Sign-in with OIDC (`AUTH_MODE=oidc` or `both`) | **yes**: code flow with PKCE, the role taken from the groups claim (`api/auth/oidc.py`) | **partly** (2026-11-13): `tests/test_auth_oidc.py` (a fake provider on an httpx mock transport), and the browser journey `scripts/check_browser_e2e.sh --auth oidc`, 4 of 4 passed, against a test provider (navikt/mock-oauth2-server 2.1.10, `docker/oidc-test`) over http on localhost: sign-in, the role from the groups claim, a person with no mapped group refused, sign-out, an expired session. No production identity provider and no https issuer is recorded ([deployment.md](deployment.md#sign-in-with-an-identity-provider-oidc)) | The API refuses to start without the `OIDC_*` settings. No SAML ([ADR-0097](adr/0097-1-0-is-a-shared-service-for-one-team.md)) | #707 |
| Audit trail | **yes**: one record per state-changing request and per admin change, naming the user or none (`api/audit.py`, migration v0020) | **partly**: `tests/test_audit.py`, and the backup check of the audit table (`scripts/check_backup_restore.py`, CI). No recorded run reads the records of a session with several users | A record names no user when nobody signed in | #707 |
| TLP egress policy ([ADR-0097](adr/0097-1-0-is-a-shared-service-for-one-team.md)) | **yes**: `pipeline/egress.py`, checked before Stage 3 (with 3d, 3e, 3f, 3doc and 4c), before Stage 1f and before the consensus provider | **partly**: the [model journey of 2026-11-09](releases/1.0-model-journey.md#runs) ran with `STIX_TLP=amber` and a local vLLM, and its provider calls passed. No hosted provider has run on an AMBER report, which the policy refuses by design. `tests/test_egress.py` | AMBER, AMBER+STRICT and RED go to a local provider only. A host not in `LLM_LOCAL_HOSTS` is external, with no DNS lookup ([configuration.md](configuration.md#egress-policy-tlp)) | — |
| Metrics, alert rules and queue status (`GET /metrics`, `GET /api/queue/status`, `docs/monitoring/ctiparsor.rules.yml`) | **yes** (ADR-0097 item 18): `METRICS_TOKEN` for a scraper outside loopback; `tests/test_metrics_endpoint.py` | **partly**: the [failure recipe run of 2026-11-13](releases/1.0-failure-recipe.md#run-of-2026-11-13-on-3c4fd6c-ops-qualification-710) on 3c4fd6c: five of five cases passed, the disk case on a dedicated 4 GiB test filesystem (`CtiparsorDiskNearlyFull` held for 10 minutes and cleared). The 2026-11-09 run on 5aa3e32 had `CtiparsorDiskNearlyFull` not checked, on a host with free disk | Five alerts are not raised by the recipe's cases, which [the recipe lists](releases/1.0-failure-recipe.md#what-the-recipe-does-not-cover). The disk alert was checked on a test filesystem, not on a production state disk | #710 |
| Scheduled backups (`BACKUP_TARGET`, `BACKUP_TIME`, `BACKUP_KEEP`, ADR-0097 item 19) | **yes**: `tests/test_scheduled_backup.py`. The backup refuses to run without `BACKUP_TARGET` | **partly**: the restore drill of the failure recipe restored a 26 MB dump on 5aa3e32 (the restore line took 6.7 s; the case 16.0 s) ([run of 2026-11-09](releases/1.0-failure-recipe.md#run-of-2026-11-09-on-5aa3e32)). No run of the schedule is recorded | `BACKUP_TARGET` is a host directory. Copying it off the host is the operator's job ([docker.md](docker.md#data-and-backups)) | #710 |
| Bounds: job list, requeue loop, uploads on a full disk (ADR-0097 item 20) | **yes**: `api/routes/jobs.py`, `api/queue_loop.py`, `api/disk_space.py`; `tests/test_jobs_pagination.py`, `tests/test_job_attempts.py`, `tests/test_disk_space_507.py` | **partly**: the worker-killed case of the [failure recipe](releases/1.0-failure-recipe.md#run-of-2026-11-13-on-3c4fd6c-ops-qualification-710) (2026-11-13) shows a job claimed a second time after its worker died. The [load profile of 2026-11-13](releases/1.0-failure-recipe.md#load-profile): 10 reports, burst and 7 s interval, one worker, and a burst with two workers; all ended with no failure, queue wait p95 139 to 254 s | The load is ten reports, with no LLM (Stage 3 skipped). The upload limit is ten per minute per address, so no longer queue was built. No SLA is set | #710 |
| Response models (`api/response_models/`, ADR-0097 item 22) | **yes**: `tests/test_response_models_g1.py` to `g4`; `tests/test_contract.py` compares the schema with the code on every pull request | **yes**: CI. The [readiness record](releases/1.0-readiness.md) (gate `contract`) lists the response fields recorded: 11 of the 78 operations have none, as of 2026-11-09 | The schema does not record the fields of every operation | #656, #657 |
| Figure reading, Stage 1f, with the default provider (`VISION_PROVIDER=auto`) | **yes**: `pipeline/stage1f_figures.py`, `pipeline/vlm.py`. PDF only, at most 40 figures | **no**: no run has read a figure with the default provider ([readiness](releases/1.0-readiness.md), gate `figure_reading_default`). The runs of 2026-11-09 set `VISION_PROVIDER=none`, which does not qualify figures. Tests: `tests/test_stage1f_figures.py`, `tests/test_vlm.py` | With the shipped `STIX_TLP=amber`, the default `anthropic` provider is refused, so figures are skipped. A figure goes only to a local vision provider for an AMBER report | #709 |
| Vision providers named in `VISION_PROVIDER` (`anthropic`, `ollama`, `mistral`, `vllm`) | **yes**: `pipeline/vlm.py` | **no**: fake-client tests only (`tests/test_vlm.py`) | `mistral` needs `VISION_MODEL`, since no vision model name was verified ([.env.example](../.env.example)). A figure never goes to another provider | #709 |
| Default LLM provider, `anthropic` (`LLM_PROVIDER=anthropic`, `ANTHROPIC_MODEL=claude-sonnet-5-5`) | **yes**: `pipeline/stage3_llm.py`; `tests/test_stage3_calls.py` and `tests/test_stage3_providers.py` with a fake client | **no**: no recorded run ([readiness](releases/1.0-readiness.md), gate `default_provider_measured`). `scripts/measure_default_provider.py` has not been run on a candidate | With the shipped `STIX_TLP=amber`, Stage 3 refuses this provider for every report, since it is external. It runs only on CLEAR or GREEN reports, and an unmarked report takes `STIX_TLP`. No seed reaches it, so two runs can differ | #709 |
| vLLM serving `Inferact/Qwen3.8-27B-NVFP4` | **yes**: `pipeline/stage3_llm.py`, `pipeline/vlm.py` | **yes**: the [in-house measurement of 2026-11-09](eval/inhouse-bundle-2026-11.md) (`LLM_TEMPERATURE=0`, `LLM_SEED=13`, figures off) and the [model journey of 2026-11-09](releases/1.0-model-journey.md#runs) (a PDF and a URL, on 5aa3e32) | `VLLM_ENABLE_THINKING=false` in both runs. One server on the local network. Figures are not measured with this model | #709 |
| Other LLM providers: `gemini`, `mistral`, `lmstudio`, `ollama`, vLLM with another model | **yes**, wired: `pipeline/stage3_llm.py`, `pipeline/vlm.py` | **no**: no recorded run. Fake-client tests: `tests/test_local_llm_providers.py`, `tests/test_stage3_providers.py` | Experimental: can change or go in a minor release ([ROADMAP](../ROADMAP.md#after-10)) | — |
| Named entities: malware, threat actors, tools, campaigns, places, sectors (Stages 2b, 2d, 2e) | **yes**: `pipeline/stage2b_gazetteer.py`, `pipeline/stage2d_cyner.py`, `pipeline/stage2e_gliner.py` | **partly**: the in-house runs of 2026-11-09 were made before Stage 2e was repaired. Its stage records in the [model journey of the same day](releases/1.0-model-journey.md#runs) show 0 rows, and [ADR-0098](adr/0098-stage-2e-asks-its-model.md) repaired it on 2026-11-11. The in-house entity figures do not describe the repaired stage. AnnoCTR test, malware precision and recall 0.194 and 0.873 ([2026-10-19](eval/ner-malware-2026-10.md)) | English models only. Precision is low on AnnoCTR (threat actors 0.259, malware 0.194). CyNER is off by default ([ADR-0099](adr/0099-cyner-off-by-default.md)) | — |
| ATT&CK techniques (Stages 2c, 3f) | **yes**: `pipeline/stage2c_ttp_semantic.py`, `pipeline/stage3f_ttp_select.py` | **yes**: AnnoCTR test, parent level, F1 0.690 ([2026-10-11](eval/baseline-2026-10.md)); in-house, F1 0.617 ([2026-11-09](eval/inhouse-bundle-2026-11.md)) | Enterprise only: the in-house gold holds 21 Mobile techniques, so its recall is lower. A selection answer can be cut at the output-token ceiling (1 of 16 in the PDF run of 2026-11-09). ATT&CK 19.2 by default, 20.0 with `ATTACK_RELEASE` | — |
| IoC extraction | **yes**: `pipeline/stage2_extraction.py`; defanged values are refanged | **partly**: in-house IoCs, precision 0.492, recall 0.630, F1 0.553 (249 gold, 8 reports, [2026-11-09](eval/inhouse-bundle-2026-11.md)). AnnoCTR does not annotate IoCs | A value the report names without accusing it ships without an Indicator ([stix-output.md](stix-output.md)) | — |
| Relationships (Stages 3, 3d, 3doc, 4b) | **yes**: `pipeline/stage3_llm.py`, `pipeline/stage3d_verify.py`, `pipeline/stage4b_graph_completion.py` | **partly**: in-house relations, precision 0.063, recall 0.428, F1 0.110 (320 gold, [2026-11-09](eval/inhouse-bundle-2026-11.md)). Of the false positives, 66.3 % are co-mention `targets` links ([analysis](eval/relation-false-positives-2026-11.md)) | Needs an LLM (Stage 3). No precision threshold blocks a release | — |
| Import of PDF, DOCX, HTML, TXT, Markdown and pasted text | **yes**: Stage 1, `pipeline/stage1_ingestion.py`; 50 MB per file, 20 to 2,000,000 characters pasted | **partly**: the 8 in-house reports are read from their source files, and a PDF went through the whole pipeline on [2026-11-09](releases/1.0-model-journey.md#runs). CI tests: `tests/test_stage1.py`, `tests/test_upload_route.py`, `tests/test_ingest_routes.py`. The five real reports of the freeze are not run yet ([real use](releases/1.0-real-use.md)) | Scanned pages go to OCR (below) | #711 |
| Capture of a URL | **yes**: headless Chromium through `capture-proxy`, public addresses only; `tests/test_web_capture.py` | **partly**: a captured URL went through the [model journey of 2026-11-09](releases/1.0-model-journey.md#runs): the archive was served and one request blocked. No live capture runs in CI | JavaScript off by default. Absent from an image built with `CTI_INSTALL_CAPTURE=false` | — |
| OCR of scanned PDFs (experimental) | **yes**: Tesseract, in `pipeline/stage1_ingestion.py`; `OCR_LANG` defaults to `eng` | **no**: no fully scanned report in the in-house set. The OCR test runs only where Tesseract and Poppler are installed (`tests/test_ingestion_structure.py`) | Experimental ([ROADMAP](../ROADMAP.md#after-10)) | — |
| Reports in languages other than English (experimental) | **partly**: the text is read in any language, but the named-entity models are English (spaCy `en_core_web_lg`, else `en_core_web_sm`) | **no**: no French report in either gold set | Experimental | — |
| Review and finalize, web interface and API | **yes**: the review routes of `api/routes/` and the review page (`frontend/src/pages/Review.tsx`) | **partly**: the browser journey, in Chromium, offline and with `AUTH_MODE=off` (job `browser-e2e`, read on 2026-11-08, [readiness](releases/1.0-readiness.md), gate `browser`). It covers neither several users nor the reader role | A reader who opens a report for review sends a status change the server refuses with 403 (#707). The review page does not yet reconcile the server's decisions with its failed writes (#706) | #706, #707 |
| Command line (`main.py`, the `cli` command of the image) | **yes**: `main.py`, `docker/entrypoint.sh` | **yes**: CI, the [`contract/cli.json`](../contract/cli.json) snapshot and `tests/test_cli_exit_codes.py` on every pull request (job `fast-tests`) | Its messages are in French and are not a stable output. Two outputs of a batch can collide (#722) | #722 |
| Enrichment of an existing STIX 2.1 bundle (ADR-0090, `STIX_ENRICHMENT_ENABLED`) | **yes**: `pipeline/baseline_stix.py`, on by default | **yes**: 7 real reports on 2026-10-25: 179 of 601 candidate entries removed, 175 recovered, 0 duplicate rows on the ablation ([TESTING.md](../TESTING.md)) | STIX 2.1 only (2.0 is refused). OpenCTI- and MISP-shaped baselines are checked on repository fixtures, not on live exports | #708 |
| STIX 2.1 export and identity rules (Stage 5) | **yes**: `pipeline/stage5_validation.py` | **yes**: six reference bundles in CI (`tests/test_stage4_reference.py`, [`contract/stix.json`](../contract/stix.json)); the two bundles of the [model journey of 2026-11-09](releases/1.0-model-journey.md#runs) validated | `unverified` when the JSON schemas are missing. `x_ctiparsor_enrichment` is not in the contract yet | #657 |
| Import into OpenCTI 7.260930.0 | **yes**: `scripts/opencti_import_bundle.py`, `scripts/check_opencti_candidate.sh` | **partly**: 83 of 83 expectations and one WARN on 2026-11-01, on main's image at 4df5cbd ([readiness](releases/1.0-readiness.md), gate `opencti`). Not run on the 1.0 candidate. The re-import and the attributes are not checked yet | Other OpenCTI versions are not tested. OpenCTI drops the bundle's `x_` properties | #708 |
| Import into MISP | **no**: no connector | **no**: no import test | A target after 1.0 (ADR-0094, decision 14). A MISP-shaped STIX 2.1 bundle is accepted as an enrichment baseline | — |
| Install with Docker Compose | **yes**: `compose.yaml`, `setup.sh` | **partly**: a clean install from the 0.2.0 archive, upgraded, with a restore, on 2026-11-01 ([readiness](releases/1.0-readiness.md), gate `clean_install`). Not run on the 1.0 candidate | Linux x86-64 or WSL2, CPU only. The only supported install | #711 |
| Upgrade from the previous release | **yes**: versioned migrations in `api/migrations/` ([ADR-0077](adr/0077-versioned-database-migrations.md)) | **yes**: CI, `scripts/check_migration_from.py`, on every push; 0.2.0 upgraded to main's image on 2026-11-01 ([readiness](releases/1.0-readiness.md), gate `upgrade`) | No downgrade. A PostgreSQL major needs `make db-upgrade` | #711 |
| Backup and restore | **yes**: the commands of [docker.md](docker.md#data-and-backups); `scripts/check_backup_restore.py` | **yes**: CI restores a seeded database with the documented flags; 0.2.0's backup restored on 2026-11-01 ([readiness](releases/1.0-readiness.md), gate `restore`); the restore drill of 2026-11-09 on 5aa3e32 ([failure recipe](releases/1.0-failure-recipe.md#run-of-2026-11-09-on-5aa3e32)) | Not across PostgreSQL majors. `cti-cache` and `.env` are not in the backup. A backup taken while `app` or `worker` run is not covered | #711 |
| Air-gapped install (experimental; `scripts/package_offline_docker.sh`, `setup.sh --offline`) | **yes**: `scripts/package_offline_docker.sh`, `setup.sh --offline` | **partly**: CI checks that the bundle's images come back from `docker save` and `docker load` (`scripts/check_offline_images.sh`). No install on an air-gapped host is recorded | No commitment in 1.0 | — |
| Queue, worker status and safe defaults (`WORKER_MAX_CONCURRENT=1`, ADR-0094 item 7) | **yes**: the `worker_heartbeats` table and `GET /api/queue/status` ([#229](https://github.com/Stixaly/CTIParsor/pull/229), [#243](https://github.com/Stixaly/CTIParsor/pull/243)) | **yes**: CI, `tests/test_queue_status_api.py` and `tests/test_job_queue.py`; the worker-killed case of the [failure recipe](releases/1.0-failure-recipe.md#run-of-2026-11-13-on-3c4fd6c-ops-qualification-710) (2026-11-13); the two-worker burst of 2026-11-13 had two reports processing at once (peak processing 2) | A crashed worker is listed as it was until its lease expires (180 s). A worker older than the heartbeat table is listed only while it holds a report | #710 |
| Detection rules quoted in a report (YARA, Sigma, Suricata, Snort) | **yes**: `pipeline/detection/` | **partly**: CI tests (`tests/test_yara_check.py`, `tests/test_pattern_check.py`). No run on a candidate | A rule ships `unverified` when its parser is missing | — |
| Detection coverage from rule corpora (matrix, proposals, ZIP export) | **yes**: `pipeline/detection/`, `tests/test_detection_coverage.py` | **partly**: CI tests. The store of 85,639 rules in 12 corpora was built and sized on 2026-11-08 ([readiness](releases/1.0-readiness.md)) | No Snort corpus. The corpora come from third-party repositories, each under its own licence | — |
| GPU, host install, a Python package | **no** | **no** | Not supported in 1.0 ([support policy](#capability-matrix)) | — |

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
- The in-house set: reports read from their original file. On 2026-11-07,
  8 reports are in `data/eval/inhouse/` (git-ignored), all `status: gold`,
  each with the 4 layers declared: 249 IoCs, 258 entities, 282 techniques,
  320 relations, 36 negative cases, plus 15 `observables`
  ([inhouse-set.md](eval/inhouse-set.md)). On 2026-10-31 there were 9, all
  `pre-annotation`. The ninth, the negative case on example domains, was
  removed by the maintainer on 2026-11-07: no report now measures a text
  filled with examples that are not IoCs.

**How the in-house gold was made.** ChatGPT (GPT-6) annotated; Claude reread
each report against its source file and completed the missing layers; the
maintainer arbitrated 40 disputed points. The undisputed elements were not
reread one by one by a person. It is AI-assisted annotation arbitrated by one
maintainer, not a human-reviewed one. ATT&CK Mobile techniques are included
(21), while the pipeline produces Enterprise only: technique recall on this set
is lower for that reason.

**What the in-house annotation covers.** Every layer of `LAYERS` in
`evaluation/inhouse.py` (`iocs`, `entities`, `techniques`, `relations`), on
every report, each declared in the `layers` field of its `gold.json`. Negative
cases are annotated as [annotation-guide.md](eval/annotation-guide.md) §6 asks,
and scored wherever a report has them. The limits, published with every
figure: 8 reports, AI-assisted annotation arbitrated by one maintainer, a
pilot. Eight reports do not detect a small difference between two releases,
so the results are given per document as well as in aggregate.

**What is published today, and its limits.** The exported bundle is measured
on the in-house set since 2026-11-09
([inhouse-bundle-2026-11.md](eval/inhouse-bundle-2026-11.md)): 0.6.0 and the
1.0 candidate (`fe0b0f3`), vLLM serving `Inferact/Qwen3.8-27B-NVFP4`,
`LLM_TEMPERATURE=0 LLM_SEED=13`, Stages 3d, 3f and the document-level relations
on for both, figures off. The two releases export the same bundles, so every
figure is the same for both:

| Measure, in-house set, exported bundle (8 reports) | Precision / recall / F1 | Gold |
|---|---|---|
| IoCs | 0.492 / 0.630 / 0.553 | 249 |
| Entities: threat actors | 0.274 / 0.870 / 0.417 | 23 |
| Entities: malware | 0.231 / 0.923 / 0.370 | 104 |
| Entities: tools | 0.663 / 0.529 / 0.589 | 119 |
| Entities: campaigns | 0.000 / 0.000 / 0.000 | 12 |
| Techniques | 0.598 / 0.638 / 0.617 | 229 |
| Relations | 0.063 / 0.428 / 0.110 | 320 |

The page gives the counts, the 17 of 36 negative cases violated, and each
report. Not measured there: the default provider (`anthropic`, ADR-0094
item 11), figure reading, and the commits after `fe0b0f3`.

The AnnoCTR figures below describe Stages 1 to 3, not the bundle: the AnnoCTR
runner turns off Stages 1f, 4 and 5 (`evaluation/__main__.py`). They are at the
commit their page names, with the same vLLM server:

| Measure, AnnoCTR test split | Value | Date | Page |
|---|---|---|---|
| Techniques, parent level: precision / recall / F1 | 0.679 / 0.702 / 0.690 (34 reports, 332 gold parents) | 2026-10-11 | [baseline-2026-10.md](eval/baseline-2026-10.md) |
| Malware: precision / recall | 0.194 / 0.873 | 2026-10-19 | [ner-malware-2026-10.md](eval/ner-malware-2026-10.md) (baseline run) |
| Threat actors: precision / recall | 0.259 / 0.967 | 2026-10-19 | same |
| Locations: precision / recall | 0.505 / 0.545 | 2026-10-19 | same |

AnnoCTR does not annotate IoCs or relationships: their only measurement is the
in-house one above.

The in-house score of Stages 1 to 3 (`inhouse-score` without `--from bundle`)
counts only the entity types the report's gold contains
(`evaluation/inhouse.py`). The bundle score counts them all: a report with no
malware in its gold still has its exported malware counted as false positives.

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
