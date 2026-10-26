# Contributing

Thanks for working on CTIParsor. This guide gets you from clone to a green test run
and points at the seams where most changes go.

## How a change gets in

1. Open an issue first for anything larger than a fix, so the approach can be
   agreed before the work ([GitHub Issues](https://github.com/Stixaly/CTIParsor/issues)).
   A vulnerability goes to [SECURITY.md](SECURITY.md#reporting-a-vulnerability) instead.
2. Fork, branch off `main`, and keep one change per pull request: the code,
   **its tests**, and the docs it changes, together (see *Conventions*). New
   behaviour comes with a test that fails without it.
3. Open a pull request against `main`. `main` is protected (ADR-0078): it
   takes changes only through pull requests, and only once every required
   check passes — the fast tests (ruff, `reuse lint`, mypy, pytest with
   coverage floors), the dependency audit and review, the frontend checks,
   the container build and smoke test, CodeQL, and four of the five fuzzers
   (`Fuzz (baseline_intake)` runs but is not required yet). Run `make ci`
   before pushing: it runs ruff, mypy, pytest and the frontend checks.
4. The maintainer reviews it; review conversations are resolved before the
   merge.

Contributions are accepted under the project's licence, Apache-2.0
([LICENSE](LICENSE)).

## Environment

Docker is the only supported way to develop CTIParsor (ADR-0054) — nothing
needs to be on the host but Docker itself, on Windows included (via Docker
Desktop's WSL2 backend; you do not need to install anything *inside* WSL).

```bash
bash setup.sh                      # writes .env + secrets, checks Docker — builds/starts nothing
nano .env                          # add ANTHROPIC_API_KEY for the LLM stage (optional)
docker compose build               # or: make docker-build
```

The LLM stage is optional — without a key the pipeline still produces valid STIX, and
the test suite mocks the LLM, so **no key is needed to develop or test**.

## Run it

```bash
docker compose run --rm dev cli input/report.pdf   # CLI
docker compose up -d                                # Web UI → http://localhost:8000
```

## Tests, lint, types — the green-build checklist

CTIParsor no longer supports SQLite (ADR-0053) — every check below needs a
reachable PostgreSQL server, which the `dev` compose service already points
at (`CTIPARSOR_TEST_DATABASE_URL`, set in `compose.yaml`):

`make ci` runs the lint, type, test, coverage-floor and frontend steps of the
pull-request CI, with the same scope and the same floors. It does not run
`reuse lint`, the migration check against the base commit
(`scripts/check_migration_from.py`, pull requests only, which needs a
PostgreSQL server), or the other checks: dependency audit and review,
container image, CodeQL and fuzzing. Each step also has a target of its own:

```bash
make ci               # all of the below
make lint             # ruff check .            (scope and rules: pyproject.toml)
make typecheck        # mypy                    (scope and flags: pyproject.toml)
make coverage         # pytest --cov, then the coverage floors (total + per area)
make frontend-check   # npm run check: eslint, tsc, vitest
make test             # the whole suite, without coverage
```

They run in two containers: `dev` for Python (the Dockerfile's `dev` stage:
the app image plus ruff, mypy and pytest-cov, rebuilt with
`docker compose --profile dev build dev` after a dependency change) and
`frontend-dev` for Node. The same commands work by hand, e.g.
`docker compose run --rm dev pytest tests/test_x.py -k name` for a small loop,
or `docker compose run --rm frontend-dev sh -c "npm ci && npm run lint"`.
`dev` bind-mounts the repo live over `/app`, so edits on the host need no
image rebuild. The image build and smoke test, which CI also runs, are
`make docker-smoke` (see *Container changes* below).

- LLM calls are mocked via `conftest.mock_llm`; tests run offline.
- Every test writes uploads and bundles under its own `tmp_path`
  (`tests/conftest.py` points `api/paths.py` there), never into the checkout's
  `uploads/` or `output/`; a run that still adds a file there names it, and
  fails in CI.
- A test skipped because an import is missing (`pytest.importorskip`) fails
  in CI and in `make coverage` (`CTIPARSOR_REQUIRE_TEST_DEPS=1`): add the
  dependency to `requirements/requirements.txt` (or a test-only tool to
  `requirements/requirements-dev.txt`)
  and run `make lock`, rather than let its tests skip. CI installs nothing but
  the hashed locks (ADR-0080), so never add a `pip install <package>` to a
  workflow. An application dependency goes in `requirements/requirements.txt` when
  the fast tests need it, in `requirements/requirements-full.txt` when only
  the image does, as a
  range, then `make lock`.
  Commit every lock `make lock` rewrites ([`docs/dependencies.md`](docs/dependencies.md)).
- DB-touching tests use the isolated `temp_db` / `temp_db_client` fixtures — a
  disposable schema per test on the server above, never a developer's real
  database. Reuse them for any new worker/route test; the fixture fails with
  a clear message if `CTIPARSOR_TEST_DATABASE_URL` is unset, rather than
  silently falling back to anything.
- See [`TESTING.md`](TESTING.md) for the full strategy and the open coverage gaps.

### One store — `api.db.get_conn()` and `get_rule_conn()`

Since ADR-0045/ADR-0053, `api.db.get_conn()` is the **job store** and
`api.db.get_rule_conn()` is the **rule store** — both PostgreSQL, both the
same connection today, kept as two accessors in case the rule corpus ever
needs a database of its own. A function that reads `entities` (the job
store) from inside `pipeline/detection` (the rule store) still takes a
`jobs_conn` keyword for that reason; see `docs/architecture.md` for the full
picture. `CTIPARSOR_TEST_DATABASE_URL` unset is not a fallback mode any
more — it is a hard failure, by design, so a change cannot pass locally on a
path that no longer exists in production.

### Container changes

If your change touches `Dockerfile`, `compose.yaml`, `docker/`, or
`scripts/docker_smoke.sh`, verify it builds and passes the smoke test before
opening a PR:

```bash
make docker-smoke                          # build, start api+worker+postgres, verify
bash scripts/docker_smoke.sh --no-build --job   # also process a sample report end to end
```

(On Windows with Docker only inside WSL, run `wsl -u root -e bash -c "cd
/mnt/c/... && make docker-smoke"` — see `docs/docker.md`.)

## Where changes go (extension seams)

| To add… | Touch |
|---|---|
| an LLM provider | `pipeline/stage3_llm.py` (`_call_llm`, `_provider_ready`) + `.env.example` |
| an input format | `pipeline/stage1_ingestion.py` + `SUPPORTED_EXTENSIONS` in `main.py` |
| an IoC type | `models/schemas.py` (`EntityType`), `stage2_extraction.py`, `stage4_stix_mapping.py` |
| a detection-rule format | a new `RuleCorpusAdapter` in `pipeline/detection/` + register it in `registry.py` |
| an API route | `api/routes/`, then `app.include_router(...)` in `api/main.py` |
| a frontend page | `frontend/src/pages/` + a route in `App.tsx` (+ a nav link in `Layout.tsx`) |
| a job-store or rule-store table, column, index, trigger or backfill | a new migration `api/migrations/vNNNN_<name>.py` (ADR-0077), never an edit of an applied one; a test in `tests/test_migrations.py`; document it in [`docs/database-schema.md`](docs/database-schema.md) |
| queue / worker behaviour | `api/queue_loop.py` (the claim, lease, heartbeat) — `api/worker.py` only owns spawning the subprocess (ADR-0046) |
| a compose service or resource limit | `compose.yaml`, then `docs/docker.md`'s sizing table and `.env.example` |

## Conventions

- **ADRs** — significant decisions get an Architecture Decision Record in
  [`docs/adr/`](docs/adr/). Copy an existing one; append, don't rewrite. Update the
  [ADR index](docs/adr/README.md).
- **DB migrations** — the schema is versioned (ADR-0077). A change is a new
  module `api/migrations/vNNNN_<name>.py`, one version after the last, that
  defines `MIGRATION` (its statements, an optional `data` step, and the
  `is_applied` check). An applied migration is never edited: its checksum is
  recorded, and the API refuses to start when it changes. `init_db()` applies
  what a database lacks, under an advisory lock, at every start of the API, a
  worker or `bootstrap`. Add a column nullable first and make it required in a
  later version, since a worker of the previous revision may still run. The
  rules, with the test each version needs in `tests/test_migrations.py`, are in
  [`docs/development.md`](docs/development.md#database-migrations). Document
  the new table or column in
  [`docs/database-schema.md`](docs/database-schema.md).
  `_JOB_STORE_DDL_POSTGRES` and `_RULE_STORE_DDL_POSTGRES` in `api/db.py` are
  only the concatenated history, kept for the one-shot SQLite import scripts:
  do not append to them.
  - **Avoid a bulk-read column on `detection_rules`.** Put per-rule scalars
    in their own table keyed by `rule_id` instead, as `rule_atoms`,
    `rule_techniques`, `rule_related` and `rule_bytes` do (ADR-0022) — the
    original measurement (8.2s to read one integer for 10,372 rules via a
    column added after the multi-kilobyte `raw` body, vs ~0.1s from a side
    table) was against SQLite specifically; re-measure against PostgreSQL
    before assuming it still holds at the same magnitude, but the side-table
    pattern costs nothing extra either way.
- **Output-affecting fixes get listed.** If a change makes Stage 4/5 emit
  different objects for the same input, append its commit to the
  bundle-affecting list (`BUNDLE_AFFECTING` in `pipeline/bundle_revisions.py`)
  read by `scripts/audit_bundle_invariants.py` (ADR-0035).
  Stored bundles are not rebuilt automatically, so without that line a fixed
  defect keeps riding in every artefact built before it — which is exactly how
  six self-edges outlived their fix. Each entry is `(commit, date, summary,
  scope)` (ADR-0086). Pick the scope by asking where the fix acts:
  - `"mapping"`: only in Stages 4/5. A finalize at a revision that has the fix
    rebuilds the bundle with it, so the entry is judged on the revision that
    built the stored bundle and a finalize clears it.
  - `"extraction"`: in Stages 1–3, even if Stage 4 changed too. A finalize
    rereads the rows the run wrote and cannot add what the run never extracted,
    so the entry is judged on the run's revision as well and only a new run
    clears it.

  When in doubt, pick `"extraction"`: it never claims a rebuild fixed what a
  rebuild cannot.
- **Generated policy data** — `pipeline/data/gazetteer_policy.json` is built
  from `docs/gazetteer-ordinary-words.md`. After any change to that document,
  run `docker compose run --rm dev python scripts/build_gazetteer_policy.py`
  and commit the regenerated JSON with it: `tests/test_gazetteer_policy.py`
  fails while the two differ. The version is the first 12 hex digits of the
  SHA-256 of the whole document (CRLF read as LF), so any edit to its text,
  even a reformatting, changes the version that runs record
  (`gazetteer_policy.version()`).
- **Line length** is 120 (ruff). Keep imports sorted (`ruff --fix` handles `I001`).
- **Files copied from another project** (code, data, icons) keep their
  copyright and licence. Give them a table in [`REUSE.toml`](REUSE.toml),
  their licence text in `LICENSES/` (`reuse download <SPDX id>`), and a row in
  [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md). `reuse lint` checks it
  in CI's fast tests.
- **Commits** — branch off `main`; keep a change + its tests + doc update together.
- **Releases** are cut by the maintainer, following [`docs/releasing.md`](docs/releasing.md).
  A change adds its CHANGELOG entry under `## [Unreleased]` and leaves the
  version alone.

## Docs to keep current
When a feature lands, update: the reference page in [`docs/`](docs/) it touches
([`pipeline.md`](docs/pipeline.md), [`configuration.md`](docs/configuration.md),
[`web-ui.md`](docs/web-ui.md), [`stix-output.md`](docs/stix-output.md),
[`api.md`](docs/api.md), [`database-schema.md`](docs/database-schema.md), or the
project structure in [`development.md`](docs/development.md)),
[`README.md`](README.md) only if it changes the overview (a highlight, a stage,
a quick-start step), [`CHANGELOG.md`](CHANGELOG.md), the relevant ADR, and
[`TESTING.md`](TESTING.md) if coverage changed. Keep the README a landing page:
detail goes in `docs/`, the README links to it. If you add or replace a
screenshot, follow [`docs/screenshots/README.md`](docs/screenshots/README.md) and
update its index.
