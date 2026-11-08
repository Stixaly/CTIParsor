# ADR-0094: What 1.0 promises: a stable contract, data that survives, published limits

**Status:** Accepted (2026-11-01)
**Date:** 2026-10-31
**Deciders:** maintainer
**Extends:** ADR-0085 (its decision 8 covers the versions before 1.0 only)
**Amended by:** the amendment of 2026-11-07 below (item 5 done, with limits)
**Relates to:** ADR-0054 (Docker is the only supported install), ADR-0060 (the
evaluation protocol), ADR-0066 (STIX ids), ADR-0077 (versioned migrations),
ADR-0084 (a bundle Stage 5 refuses is not served), ADR-0090 (enriching a STIX
bundle), ADR-0036 (multi-user, proposed)

The page this ADR writes is [docs/support-policy.md](../support-policy.md).

## Context

CTIParsor released 0.1.0 on 2026-10-17 and 0.2.0 on 2026-10-29 (ADR-0085). Its
versioning rule covers only the time before 1.0 (ADR-0085 decision 8,
`docs/releasing.md`, *Versioning*): the minor version goes up for new behaviour
or anything an operator must act on, the patch version for fixes. Nothing says
what a 1.0 would freeze. In Semantic Versioning, 1.0.0 is the version that
declares the public interface stable.

The 1.0 target is narrow: a self-hosted, local install for one analyst, who
reviews the extractions. That analyst imports a report, reviews the
extractions, exports STIX 2.1, upgrades the install and restores it. One person
maintains the project.

What CTIParsor exposes, read from the code on 2026-10-31 (commit 1c11b87):

- **HTTP API.** 14 routers under `/api/` and `GET /api/health`: 60 operations
  in the OpenAPI schema FastAPI publishes at `/openapi.json`. A Server-Sent
  Events stream with five event names (`connected`, `queued`, `stage`,
  `partial_graph`, `done`). A 409 and the header `X-Bundle-Validation` for a
  bundle Stage 5 refused (ADR-0084).
- **Command line.** The container commands of `docker/entrypoint.sh` (`serve`,
  `worker`, `bootstrap`, `cli`, `check`), and `main.py`: eight arguments and
  the exit codes 0, 1 and 2.
- **Configuration.** 141 variables in `.env.example`.
- **Data.** A PostgreSQL schema at version 14 (`api/migrations/`, ADR-0077), and
  the volume `cti-state`.
- **STIX output.** The mapping of `docs/stix-output.md`, 13 custom properties
  CTIParsor writes, the identity rules of ADR-0066, and the TLP and PAP
  markings.

What already checks part of it, and what does not:

- `tests/test_api_schema.py` (Schemathesis) checks each response against the
  schema of the moment. Nothing compares the schema, the CLI or the
  configuration with those of the previous release.
- On every pull request, CI migrated a database written by the base commit and
  read it back (`scripts/check_migration_from.py`). Its seed was one job, three
  entities and one relationship, and only row counts were compared. Starting
  from the last release tag was ADR-0085's open item 5. Item 2 below replaced
  that seed and that comparison on 2026-10-31.
- `docs/docker.md` gives backup and restore commands. No test runs them.
- The frontend has unit tests (Vitest). No test drives the interface in a
  browser through import, review and export. Item 4 below added that
  journey on 2026-10-31.
- `GET /api/queue/status` lists only the workers that hold a `processing` job
  (`api/routes/queue.py`). An idle worker is not in the list, so an empty list
  does not mean that no worker runs. Item 7 below listed every running worker,
  idle or busy, on 2026-11-01.
- The OpenCTI import recipe (TESTING.md, *OpenCTI import (A4)*) passed 12 of
  12 expectations on OpenCTI 7.260930.0 on 2026-10-25, before ADR-0093 changed
  the descriptions. It is not in CI. Item 8 below ran it on 2026-11-01 on
  bundles a candidate image produced: the Report's description and attached
  file compared, and no description of an object or relationship emptied.

Quality, as published today:

- The AnnoCTR runner turns off Stages 1f, 4 and 5, and `inhouse-run` turns off
  Stage 5 (`evaluation/__main__.py`). No figure is measured on the exported
  bundle.
- On AnnoCTR test, with vLLM serving `Inferact/Qwen3.8-27B-NVFP4`: technique F1
  0.690 at parent level (2026-10-11, `docs/eval/baseline-2026-10.md`); malware
  precision 0.194, threat-actor precision 0.259, location precision 0.505
  (2026-10-19, `docs/eval/ner-malware-2026-10.md`, baseline run).
- With the provider's default sampling, two runs of one configuration differed
  by 0.028 F1 on dev; with `LLM_TEMPERATURE=0 LLM_SEED=13`, by 0
  (`docs/eval/README.md`).
- The in-house set holds 9 reports in `data/eval/inhouse/` (git-ignored), all
  `pre-annotation`, none with a layer declared (read on 2026-10-31; see the
  amendment of 2026-11-07 below).
  `docs/eval/inhouse-set.md` records that it has no French report and no fully
  scanned one.

LLM providers: `LLM_PROVIDER` takes `anthropic` (the default), `gemini`,
`mistral`, `lmstudio`, `vllm` or `ollama`. Every evaluation run recorded in
`docs/eval/` that calls an LLM used vLLM with `Inferact/Qwen3.8-27B-NVFP4`. The others are tested
with a fake client only (`tests/test_stage3_calls.py`,
`tests/test_stage3_providers.py`, `tests/test_local_llm_providers.py`).

## Decision

Decisions 1 to 10, and 13, are the maintainer's. Decisions 11, 12 and 14 were
proposed by this ADR; on 2026-11-01 the maintainer accepted 11 and 12 as
written, and 14 with two changes: figure reading is on by default, and an
import into MISP is a target after 1.0.

**0. What 1.0 promises.** Three things, and only these:

1. **a stable contract:** the stable surfaces change incompatibly only in a new
   major version;
2. **data that survives** an upgrade from the previous release, and a restore:
   reports, review decisions, baselines and bundles;
3. **measured, published limits:** the extraction measured on the exported
   bundle, published with each release, with its denominators and limits.

1.0 certifies no level of precision. No promise assumes a team.

**1. Quality is published, not gated.** The extraction measurement is
published with each release, on the exported bundle, with denominators and
limits. No precision threshold blocks a release. A regression against the
previous release, on the same data, is explained in the release notes.

Why: the in-house set is 9 reports with one annotator, a pilot that cannot
detect a small difference. The AnnoCTR test split is read once per decision
(ADR-0060), so it cannot gate every release. The run-to-run spread at the
provider's default sampling (0.028 F1) exceeds ADR-0060's adoption step
(+0.02); with fixed sampling it was 0, on the one provider checked. A threshold
fixed today would be fixed on drafts: no in-house report is gold yet
(on 2026-11-07, 8 are; see the amendment below).

**2. Real use before 1.0.** The candidate is frozen, then used on 5 real
reports outside the evaluation corpora, through the export and an import into
OpenCTI. 1.0 is tagged with no blocking incident open.

Why: the tests and the measurements run on fixtures and gold sets. The
journey on reports nobody tuned against, through OpenCTI, is checked nowhere
else.

**3. Enriching an existing STIX bundle (ADR-0090) is supported.** Why: it is on
by default, so every user gets it without asking for it. Its evidence exists:
0 duplicate rows on the round trip of 7 real reports, 175 of 179 removed
entries recovered on the ablation, 12 of 12 expectations against OpenCTI
7.260930.0 (2026-10-25).

**4. The air-gapped install (ADR-0054), French reports and OCR of fully
scanned PDFs are experimental,** with no commitment in 1.0. They keep working.
Why: no gold report is in French or fully scanned (`docs/eval/inhouse-set.md`),
and the NER models are English (spaCy `en_core_web_lg`, else `en_core_web_sm`).
CI checks only that the air-gap bundle's images come back from `docker save`
and `docker load` (`scripts/check_offline_images.sh`); the full offline check
is run by hand.

**5. Maintenance of 1.x.** Fixes go to the latest minor version only. No double
maintenance. No support duration is promised. Why: one maintainer.
`SECURITY.md` already supports the latest release only.

**6. `WORKER_MAX_CONCURRENT` defaults to 1.** Done by pull request #229
(commit 8f42f69). Why: each report in flight holds about 4.4 GB
(`docs/docker.md`); the code's old default of 10 asked for about 44 GB outside
Compose.

**7. Four severities block a release:** data loss; a lost review decision; an
invalid export presented as validated; the essential journey (import, review,
export) unusable. Why: each breaks one of the three promises or the journey
1.0 is for. Any other defect is fixed in the order the maintainer chooses.

**8. No `/api/v1`.** Stability does not depend on a URL prefix; routes stay
under `/api/`. Why: see *Options rejected*.

**9. Docker Compose is the only supported install.** ADR-0054 already made
Docker the only supported way to install, develop and run CTIParsor; a host
install is a migration path (`docs/upgrading.md` §3).

**10. The in-house annotation covers every layer of `LAYERS`**
(`evaluation/inhouse.py`: `iocs`, `entities`, `techniques`, `relations`), on
every report, each declared in the `layers` field of its `gold.json`. The
published limits: 9 reports, one annotator, a pilot (on 2026-11-07: 8 reports,
AI-assisted annotation arbitrated by one maintainer, a pilot; see the
amendment). Why: a layer left out of
`layers` is not scored, so a layer annotated on some reports only gives a
second, smaller denominator per layer.

**11. The stable surfaces** are those listed in `docs/support-policy.md`:

- every operation of the OpenAPI schema, as `docs/api.md` documents it; the SSE
  event names, the event ids and `Last-Event-ID`, and the `status` of `done`;
- the container commands, `main.py`'s arguments and exit codes, and
  `make db-upgrade`;
- the variables of `.env.example`, by name, meaning and accepted values; the
  Compose services, profiles and volumes;
- the data, through migration: the SQL schema is not an interface;
- the STIX mapping, the custom properties, the identity rules, the markings.

Out of the commitment: `scripts/` (development, measurement and maintenance
tools), `python -m evaluation` and `python -m api.migrate` (development tools),
`make` targets other than `db-upgrade`, the `dev` profile, the CLI's printed
text, the `data` fields of `stage` and `partial_graph` events, the text of
error messages, the web interface's screens, `pipeline/` as a library,
`SKIP_HEAVY_MODELS`, `TTP_RETRIEVAL_EXCLUDE_CITED`, and the default values of
calibrated settings and of model names. A default is the value a fresh install
runs with: the value `.env.example` sets, or the value it shows on a line left
commented out.

**12. Breaking changes, version numbers and deprecation.**

- A major version for a breaking change: a route, field, CLI argument,
  variable or STIX custom property removed or renamed; a type or meaning
  changed (exit codes included); an optional field made required; a value
  removed from a documented list; a documented size limit lowered; a
  migration that loses data; a STIX identity rule changed.
- A minor version for new behaviour, a deprecation, a changed default (when
  the previous behaviour stays available by setting the variable), a database
  migration. A patch version for fixes, without a migration.
- Not breaking: what the models predict; a new field, optional request field,
  route, variable with a compatible default, STIX custom property, SSE event,
  stage id or ledger reason; a fix that makes a surface do what its
  documentation says.
- A deprecation is announced in the CHANGELOG (`### Deprecated`) and on the
  page of the surface, a route is marked `deprecated` in the OpenAPI schema,
  and a deprecated variable still set gets a warning in the start log. The
  surface keeps working until the next major version, and at least through
  one minor release after the announcement.

Why: these are the rules a single maintainer can keep. One minor release of
notice matches the release pace, and no rule needs a second person.

**13. A provider is supported only with a recorded run, and the default
provider gets one before 1.0.** `anthropic`, the default `LLM_PROVIDER`, is
supported: its run is recorded before 1.0 (item 11). vLLM serving
`Inferact/Qwen3.8-27B-NVFP4` is supported by the runs already recorded in
`docs/eval/`. `gemini`, `mistral`, `lmstudio`, `ollama`, and vLLM with another
model, are experimental. Why: a test with a fake client checks the request
code, not what a model returns. The default provider is the one a user gets
without choosing, and relationships need an LLM: an experimental default would
leave the default journey outside the promises. Anthropic takes no seed
(`LLM_SEED` reaches vLLM, Ollama and LM Studio only), so its run is made twice
at `LLM_TEMPERATURE=0` and publishes the spread between the two.

**14. The other statuses.** Capturing a URL, the detection rules quoted in a
report and the detection coverage from rule corpora are supported (each has
tests and runs in the default stack). Several users, a GPU and a Python
package are not supported. The maintainer changed two of the proposed statuses:

- **Figure reading (Stage 1f) is supported and on by default** (item 12). When
  `VISION_PROVIDER` is left at its default, the provider chosen for the text
  (`LLM_PROVIDER`) reads the figures of a PDF, with the model it would use if
  it were set by name, provided the model passes the image probe Stage 1f
  already runs. Without a provider able to see, the stage is skipped, as
  Stage 3 is without a provider. A figure never goes to another provider than
  the one chosen for the text: an install that moves the text to a local LLM
  keeps its figures local. `VISION_PROVIDER=none` turns it off, and a named
  provider still overrides it. Why: figures (screenshots, attack chains) hold
  evidence the text does not, and an option off by default is one most users
  never turn on. It costs at most 40 calls per PDF (`stage1f_figures.py`),
  with `claude-haiku-4-5` by default on `anthropic`.
- **An import into MISP is not supported in 1.0, and is a target after it.**
  There is no connector and no import test today; a MISP-shaped STIX 2.1
  bundle is accepted as a baseline to enrich (decision 3).

## Options rejected

- **A precision threshold that blocks a release.** The data cannot support it
  (decision 1): a 9-report pilot, a test split read once per decision, and, at
  the provider's default sampling, a run-to-run spread larger than the step
  ADR-0060 adopts on. A threshold set
  low enough to pass would say nothing; one set higher would block on noise.
  Publishing the figures with their denominators is what the data supports.
- **`/api/v1`.** Moving every route under a new prefix is itself the breaking
  change 1.0 must avoid: the interface, the scripts and every client of the 60
  operations would move. Keeping a second tree beside `/api/` doubles what one
  maintainer keeps working. The version number already versions the whole
  interface; the prefix adds nothing to it.
- **Two maintained lines, N and N−1, for twelve months.** Each fix would be
  written, tested and released twice, on two schema histories. One maintainer
  cannot keep that up, and `SECURITY.md` already supports the latest release
  only.
- **A PyPI package.** ADR-0085 already rejected an sdist, a wheel and PyPI,
  because Docker is the only supported install (ADR-0054). A package would be a
  second install to build and support, without the models, the corpora,
  Chromium and PostgreSQL the image carries.
- **Authentication and several users before 1.0.** The 1.0 target is one
  analyst on a local install. ADR-0036 (Proposed) treats authentication as a
  project of several weeks; doing it first would delay the three promises for
  a use 1.0 does not target. `SECURITY.md` says CTIParsor is not a multi-user
  service. A deployment that needs a gate keeps the `proxy` profile's TLS and
  password, or its own authenticating proxy (`docs/deployment.md`).

## Consequences

- **Easier.** A user knows what can change under them, and what a version
  number means. Once item 1 exists, a pull request that removes a field or a
  variable fails until someone decides it. Each release says how well it
  extracts, on the bundle it ships.
- **Harder.**
  - A removal waits for a major version, after at least one minor release of
    deprecation.
  - Each release costs a measurement run with the LLM on both gold sets.
  - The four blockers apply to every release after 1.0, patches included.
- **Until 1.0 is tagged,** the *Before 1.0* rules of `docs/releasing.md` still
  apply. `docs/support-policy.md` describes promises made in advance, and says
  which have no evidence yet.
- **A billed run before 1.0.** Decision 13 needs item 11: two runs with
  `anthropic` on AnnoCTR test and two on the in-house set, each one billed
  per call. The in-house runs waited for its gold (item 5, done on 2026-11-07
  with the limits of the amendment below).
- **Figures are read by default (decision 14, item 12).** A PDF with figures
  costs up to 40 more calls to the text's provider, billed on `anthropic`, and
  its bundle can hold what the figures show.
- **`docs/eval/inhouse-set.md` differs from decision 10.** Its *Layers* column
  gives some reports fewer layers, and its *Double* column plans a second
  annotator for three of them. Decision 10 replaces the first. A second
  annotator stays welcome, and is not a condition of 1.0. That page is updated
  when the annotation starts.
- **A default that differs between the code and `.env.example`.**
  `ENABLE_TTP_VERIFICATION` is `true` in `.env.example` and `false` in the
  code's fallback (`pipeline/stage3f_ttp_verify.py`). Under decision 11's
  definition, the default is `true`. A process started without `.env` runs
  with `false`.
  Update, 2026-11-08: both now say `true`; the code's fallback is `true` too,
  so a process started without `.env` runs with it on.
- **What this ADR does not change:** the code, the routes, the release
  workflow (ADR-0085), the evaluation protocol (ADR-0060).

## Action plan

Items 1 to 4, 7 to 9 and 12 are done; none of the others is started on
2026-11-01 (item 12 was added that day, with decision 14's change). Each
proves part of a promise; `docs/support-policy.md` names the item where a piece
of evidence is missing.

| # | Work | What it proves | State |
|---|---|---|---|
| 1 | Contract snapshot in CI: a reference OpenAPI schema, the CLI's arguments and exit codes, the variables of `.env.example`, STIX fixtures; a semantic diff that fails on a removal, a rename, a changed type, a field made required | the stable contract | done: `contract/`, `scripts/contract.py` (`make contract`), `tests/test_contract.py`, `tests/test_cli_exit_codes.py`. Not covered: the response fields of the 59 operations whose schema declares none; job statuses, `X-Bundle-Validation` values, SSE event names and the export archive layout (strings in the code); the 409 body (not in the schema; `tests/test_jobs_routes.py` checks it); a variable the code stops reading, or a code default that drifts from `.env.example`; `x_ctiparsor_enrichment` (no enriched reference bundle) |
| 2 | Migration from the last release: `scripts/check_migration_from.py` from `v0.2.0`, then from each release tag (ADR-0085 item 5), with a seed that holds files, decisions, a baseline, a bundle, its verdict and its ledger; content compared, not only row counts | data survives an upgrade | done: `scripts/check_migration_from.py` (several refs, `--last-release`), `scripts/migration_seed.py`, `scripts/migration_compare.py`, `scripts/migration_readback.py`; CI from the last release tag on every run and from the base commit on a pull request; `tests/test_migration_seed.py`, `tests/test_migration_compare.py`, `tests/test_migration_readback.py`, `tests/test_check_migration_from.py`. Run from `v0.2.0` and from `v0.1.0` (versions 12 and 13 applied): every value kept, the seed read back. Not covered: the tables no route reads (the decision journal, figures, the figure and CVE caches, the rules' side tables) are compared in the database only; `detection_corpora.local.yaml` in `cti-state` (its path is the checkout's); a database older than `v0.1.0` |
| 3 | Backup and restore: a consistent backup of the database and `cti-state`, a restore into an empty project, a check that reports, decisions, baselines and bundles come back | data survives a restore | done: `scripts/check_backup_restore.py` (fast-tests, every run): the item 2 seed backed up with the `pg_dump`, `pg_restore` and `tar` flags of `docs/docker.md`, restored into an empty database and directory, compared strictly (every row, column type, sequence state, schema object and file, nothing more) and read back through the API; `scripts/check_backup_restore_docker.sh`, run by `scripts/docker_smoke.sh --backup-restore` (container-image): the documented commands as written, a Compose stack restored into a second, empty project; `tests/test_check_backup_restore.py`, `tests/test_migration_compare.py`. Run on PostgreSQL 17 and 18: everything back; a lost or added row, a changed value, a dropped trigger or index, a changed default, a reset sequence, a changed file, and a review revision bumped by triggers firing during the load, each caught. Not covered: a restore onto a new cluster at the same address is run by the Compose check only (the Python check restores on the same server); a backup taken while `app` or `worker` run; a restore across PostgreSQL majors (`make db-upgrade`); `cti-cache` and `.env`, which the backup leaves out |
| 4 | Browser journey: Playwright against the built interface, the API, a worker and PostgreSQL: import, review, export; in CI | the journey is usable (blocker 4) | done: `scripts/check_browser_e2e.sh` (job `browser-e2e`, every run; `publish-image` waits for it), `frontend/playwright.config.ts`, `frontend/e2e/`, `scripts/browser_e2e_db.py`, `tests/test_browser_e2e_db.py`. In Chromium, offline (`PIPELINE_DISABLED_STAGES` turns off every model, LLM and network stage; the stage report is checked): import, progress from the run's events, a reload, accept, reject and retype, completion, download, the bundle checked (STIX 2.1, references inside it, decisions applied) and compared with `GET /bundle` (`validated`); the same by keyboard alone; enrichment with the graph's ledger, each match checked; a failed report and its reason; a refused bundle answered 409; axe (WCAG 2.1 A/AA, serious and critical) on each page, one element allowlisted; an iptables guard counts every packet the API and its worker send off loopback, 0 required (a DNS lookup through a resolver on loopback is not counted, a connection after it is). Not covered: the models, the LLM and the vision and CVE stages (their own track); a PDF or a URL import; the graph and coverage pages by keyboard; a screen reader; whether the report still runs at the reload (recorded, not asserted: the run ends under a second after its first event); the reason a failed report failed, on the page (the journey reads it from the progress events) |
| 5 | In-house gold: the 9 reports annotated on every layer of `LAYERS`, `status: gold` (decision 10) | the denominators of the measurement | done on 2026-11-07, with limits: 8 reports, all `status: gold`, 4 layers declared on each (see the amendment). On 2026-10-31 it was not started (9 `pre-annotation` drafts) |
| 6 | Measurement of the exported bundle: score the bundle Stages 4 and 5 produce, per layer and per document, with every report not scored named; published with each release; compared with the previous release on the same data | published limits | scorer built on 2026-11-08 (ADR-0096): `inhouse-run` writes the bundle, `inhouse-score --from bundle` scores it and names each report not scored, `inhouse-compare` compares two scores. Not run on the candidate, not compared with the previous release; the proof and the after-review bundle are not scored. On 2026-10-31 it was not started |
| 7 | Worker status: an idle worker visible in `GET /api/queue/status`, or the documentation says that an empty list is not an outage | operations | done: `worker_heartbeats` (schema version 14, `api/migrations/v0014_worker_heartbeats.py`): every queue loop writes its row at start and every `WORKER_HEARTBEAT_S`, busy or idle, deletes it on a clean stop, and deletes the rows silent for an hour; while that write fails, the worker stops touching its liveness file, so its container turns `unhealthy` (before, it stayed `healthy` with the job store down); `GET /api/queue/status` lists each worker `busy`, `idle` or `stale`, and `worker_summary` the live ones and their free slots; `docs/operations.md`; `tests/test_queue_status_api.py`, `tests/test_job_queue.py`, `tests/test_migrations.py`; `scripts/docker_smoke.sh` checks that the idle worker container is listed (job `container-image`). Not covered: a worker of a version before 14 is listed only while it holds a report; a worker that crashed is listed as it was until its lease expires (180 s) |
| 8 | OpenCTI import of the candidate: the A4 recipe on bundles the candidate produced, tied to its commit and image digest | the import the matrix supports | done: `scripts/check_opencti_candidate.sh`, `scripts/opencti_candidate_bundles.py`, `scripts/opencti_expectations.py`, `scripts/opencti_import_check.py` (`--full`), `tests/test_opencti_expectations.py`; a release step (`docs/releasing.md`, step 4), not in CI. On 2026-11-01, on main's image at 4df5cbd: 83 of 83 expectations and 1 WARN (one name held by two types). Not covered: OpenCTI versions other than 7.260930.0; bundles made with the models or an LLM (the candidate runs offline); a connector or a live feed (bundles are imported by pycti) |
| 9 | Clean install from the published image, on a blank machine, following only the public documentation: bootstrap, first report, review, export, restart, upgrade, restore | the install path | done: `scripts/check_clean_install.sh`, `scripts/clean_install_journey.py`, `tests/test_check_clean_install.py`; the commands it runs are the README's, docs/docker.md's and docs/upgrading.md's, read from them; a release step (`docs/releasing.md`, step 4), not in CI. Run on 2026-11-01, WSL2, from 0.2.0 to main's image at 248382c: every step passed, in 827 s with both images present (`bootstrap` 387 s, the models and corpora without an `HF_TOKEN` in 2 min 27 s); the run found and fixed the backup block's `umask 077` left in the shell, a bootstrap command that did not run, and wrong figures (bootstrap time, volume and model sizes). Not covered: a blank machine (a fresh directory, `HOME` and Docker login, but the host's Docker daemon and its image cache); a user in the `docker` group (the run is as root, where `tar` keeps the archive's modes: the backup block's umask, which made the next release unreadable, is tested without Docker); an arm64 host (no image); an LLM provider (the run sets none); the web UI (the API journey stands in for it; item 4 covers the interface); the CLI, the `proxy` and `ollama` profiles; the restore made live under the install's own project, which needs `docker volume rm` |
| 10 | Freeze and real use: the candidate frozen, 5 real reports outside the evaluation corpora, through export and OpenCTI import, incidents logged (decision 2) | the journey on unseen reports | not started |
| 11 | A recorded evaluation run with `anthropic` and the default `ANTHROPIC_MODEL`: twice at `LLM_TEMPERATURE=0`, on AnnoCTR test (read once for this decision, as ADR-0060 allows) and on the in-house set once it is gold (item 5), with figure reading on (item 12); the spread between the two runs published | `anthropic` supported (decision 13) | not started |
| 12 | Figure reading on by default (decision 14): a default `VISION_PROVIDER` that follows `LLM_PROVIDER` when its model passes the image probe, the stage skipped otherwise; tests of each provider's path and of the skip; `.env.example`, the contract snapshot and the docs | figure reading supported, in the default journey | done: `pipeline/vlm.py` (`VISION_PROVIDER` unset, empty or `auto` builds the backend of `LLM_PROVIDER` with the model and the probe a named provider would have; `gemini`, `lmstudio` and any other value are skipped; never another provider; `skip_reason()`; a probe that raised is asked again for the next document; no credentials in a reason; `python -m pipeline.vlm` reads `.env`), `pipeline/orchestrator.py` (the reason goes in the stage report; under `auto` a run with Stage 3 disabled reads no figure, so `--no-llm` still sends nothing; the 1f record names the provider and model), `api/run_config.py` (an unset `VISION_PROVIDER` is recorded as `auto`), `.env.example`, `contract/config.json` (`make contract`: one `default` difference, none breaking), the docs; `tests/test_vlm.py` (each provider's path, the skips, the logging level, the two defaults of `LLM_PROVIDER`), `tests/test_orchestrator.py` (the reason in the stage report; no backend asked, not even a probe, under `auto` with Stage 3 disabled by `--no-llm` or `PIPELINE_DISABLED_STAGES`; a named provider still asked), `tests/test_run_config.py`, `tests/conftest.py` (the suite pins `VISION_PROVIDER=none`). Not covered: no real figure has been read through `auto` yet, the first will be in item 11's in-house runs; the tests fake the probe and the server, no CI job reads a figure |

Done before this ADR, by pull request #229: `WORKER_MAX_CONCURRENT` defaults to
1 in the code (decision 6), and `python -m evaluation inhouse-score` names the
gold reports a run failed or lacks, and exits 1 when there are any or when no
report was scored.

## Amendment (2026-11-07): the in-house gold, done with limits

The context above is dated 2026-10-31 and stays true at that date. State on
2026-11-07, for item 5 and decision 10:

- `data/eval/inhouse/` (git-ignored) holds **8 reports**, all `status: gold`,
  each with the 4 layers of `LAYERS` declared (`iocs`, `entities`,
  `techniques`, `relations`). `evaluation.inhouse.load()` loads all 8. Totals:
  249 IoCs, 258 entities, 282 techniques, 320 relations, 36 `negatives`, plus
  15 `observables`.
- The ninth report, `domain-collision-caturegli-2025` (the negative case: an
  article full of example domains), was removed from the corpus by the
  maintainer on 2026-11-07, who judges it of no interest. No report now
  measures a text filled with examples that are not IoCs; the remaining
  negatives are inside the other reports. `greyvibe-withsecure-2026` and
  `greyvibe-withsecure-web` cover the same subject.
- **How it was annotated.** ChatGPT (GPT-6) annotated; Claude then reread each
  report against its source file (each element checked against the text and
  the figures, missing layers completed, quotes ChatGPT invented replaced);
  the maintainer then arbitrated 40 disputed points. The undisputed elements
  were not reread one by one by a person. This is AI-assisted annotation
  arbitrated by the maintainer, not the human-reviewed annotation this ADR
  planned.
- Rules the maintainer set, applied to the whole corpus: a system command the
  attacker uses is a `tool` entity; ATT&CK Mobile techniques are included (21
  in all, while the pipeline produces Enterprise only, so technique recall is
  lower, on purpose); a new `observables` list holds legitimate items cited as
  indicators and values without an IoC type (neither the loader nor the scorer
  uses it yet); malware versions are aliases of the family; one technique
  (T1656) is absent from the local ATT&CK index.
- The published limits (decision 10) become: 8 reports, AI-assisted annotation
  arbitrated by one maintainer, a pilot. Item 5 no longer blocks items 6 and
  11; item 6 (the scorer of the exported bundle) is not built.

Update, 2026-11-08: item 6's scorer is built (ADR-0096). It has not been run
on the candidate nor compared with the previous release.
