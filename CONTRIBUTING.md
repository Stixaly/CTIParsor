# Contributing

Thanks for working on CTIParsor. This guide gets you from clone to a green test run
and points at the seams where most changes go.

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

`make ci` runs every check the pull-request CI runs, with the same scope and
the same floors; each step also has a target of its own:

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
  in CI and in `make coverage` (`CTIPARSOR_REQUIRE_TEST_DEPS=1`): install the
  dependency in the CI job rather than let its tests skip.
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
| a job-store or rule-store table or column | `_JOB_STORE_DDL_POSTGRES` or `_RULE_STORE_DDL_POSTGRES` in `api/db.py` (ADR-0045, ADR-0053 — one PostgreSQL-only DDL tuple per store, `IF NOT EXISTS`/`ADD COLUMN IF NOT EXISTS` so it doubles as the migration); document it in [`docs/database-schema.md`](docs/database-schema.md) |
| queue / worker behaviour | `api/queue_loop.py` (the claim, lease, heartbeat) — `api/worker.py` only owns spawning the subprocess (ADR-0046) |
| a compose service or resource limit | `compose.yaml`, then `docs/docker.md`'s sizing table and `.env.example` |

## Conventions

- **ADRs** — significant decisions get an Architecture Decision Record in
  [`docs/adr/`](docs/adr/). Copy an existing one; append, don't rewrite. Update the
  [ADR index](docs/adr/README.md).
- **DB migrations** — `CREATE TABLE IF NOT EXISTS` / `ADD COLUMN IF NOT
  EXISTS` statements appended to `_JOB_STORE_DDL_POSTGRES` or
  `_RULE_STORE_DDL_POSTGRES` in `api/db.py` (one statement per tuple entry,
  applied through `_apply_postgres_ddl()`, which tolerates the
  duplicate-object race of two processes both calling `init_db()` against a
  fresh database). Document the new table or column in
  [`docs/database-schema.md`](docs/database-schema.md).
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
  bundle-affecting list read by `scripts/audit_bundle_invariants.py` (ADR-0035).
  Stored bundles are not rebuilt automatically, so without that line a fixed
  defect keeps riding in every artefact built before it — which is exactly how
  six self-edges outlived their fix.
- **Line length** is 120 (ruff). Keep imports sorted (`ruff --fix` handles `I001`).
- **Commits** — branch off `main`; keep a change + its tests + doc update together.

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
