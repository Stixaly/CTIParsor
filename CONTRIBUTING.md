# Contributing

Thanks for working on CTIParsor. This guide gets you from clone to a green test run
and points at the seams where most changes go.

## Environment

CTIParsor is Linux-oriented (the setup script targets Ubuntu/Debian/WSL). On Windows,
develop inside **WSL**.

```bash
bash setup.sh                      # venv, Python deps, MITRE data, frontend build
source .venv/bin/activate
cp .env.example .env               # add ANTHROPIC_API_KEY for the LLM stage (optional)
```

The LLM stage is optional — without a key the pipeline still produces valid STIX, and
the test suite mocks the LLM, so **no key is needed to develop or test**.

## Run it

```bash
python main.py input/report.pdf            # CLI
python run_api.py                         # Web UI → http://localhost:8000
```

## Tests, lint, types — the green-build checklist

```bash
pytest tests/ -q -k "not llm"     # fast lane — deterministic, no API key (CI gate)
pytest tests/ -q                  # full suite (adds retry/transient tests)
ruff check pipeline/ api/ models/ tests/ scripts/ --select E,F,W,I
cd frontend && npx tsc --noEmit   # frontend type-check
```

- LLM calls are mocked via `conftest.mock_llm`; tests run offline.
- DB-touching tests use the isolated `temp_db` / `temp_db_client` fixtures — never
  the developer's `cti_stix.db`. Reuse them for any new worker/route test.
- See [`TESTING.md`](TESTING.md) for the full strategy and the open coverage gaps.

### Two stores — run DB and queue tests on both engines

Since ADR-0044/0045/0046, `api.db.get_conn()` is the **job store** (SQLite by
default, PostgreSQL when `DATABASE_URL` is set) and `api.db.get_rule_conn()`
is the **rule store** (always SQLite — it's an FTS5 index). Without
`DATABASE_URL` both return the same connection, which is exactly why a test
that only exercises SQLite can pass while being wrong on PostgreSQL: 76 tests
in this codebase did, because they wrote rule tables through the job-store
connection.

**If your change touches `api/db.py`, `api/db_backend.py`,
`api/queue_loop.py`, or any raw SQL, run the suite against PostgreSQL before
opening a PR:**

```bash
docker run -d --name ctiparsor-pg-dev -e POSTGRES_PASSWORD=devpass \
  -e POSTGRES_USER=ctiparsor -e POSTGRES_DB=ctiparsor \
  -p 127.0.0.1:5433:5432 postgres:17-alpine   # once

CTIPARSOR_TEST_DATABASE_URL=postgresql://ctiparsor:devpass@127.0.0.1:5433/ctiparsor \
  pytest tests/ -q
```

The `temp_db` fixture creates a disposable PostgreSQL schema per test when the
variable is set, and a temp SQLite file otherwise — same tests, both engines.
A function that reads `entities` (the job store) from inside `pipeline/detection`
(the rule store) takes a `jobs_conn` keyword; see `docs/architecture.md` for
the full picture. CI runs both automatically (`fast-tests` on SQLite,
`postgres-tests` against a service container).

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
| a job-store table or column | the DDL/migration pair in `api/db.py` — **both** `_JOB_STORE_MIGRATIONS_SQLITE` and `_JOB_STORE_DDL_POSTGRES` (ADR-0045); document it in the README's Database schema section |
| queue / worker behaviour | `api/queue_loop.py` (the claim, lease, heartbeat) — `api/worker.py` only owns spawning the subprocess (ADR-0046) |
| a compose service or resource limit | `compose.yaml`, then `docs/docker.md`'s sizing table and `.env.example` |

## Conventions

- **ADRs** — significant decisions get an Architecture Decision Record in
  [`docs/adr/`](docs/adr/). Copy an existing one; append, don't rewrite. Update the
  [ADR index](docs/adr/README.md).
- **DB migrations** — additive `ALTER TABLE` / `CREATE TABLE IF NOT EXISTS`
  appended to the `_migrations` list in `api/db.py` (wrapped in try/except; safe
  to re-run). Document the new table or column in the README's
  [Database schema](README.md#database-schema) section.
  - **Never add a bulk-read column to `detection_rules`.** `ALTER TABLE` appends
    after `raw`, which holds multi-kilobyte rule bodies, so SQLite must walk each
    record past the body (and its overflow pages) to reach the new field —
    measured 8.2s to read one integer for 10,372 rules, versus ~0.1s from a side
    table. Put per-rule scalars in their own table keyed by `rule_id`, as
    `rule_atoms`, `rule_techniques`, `rule_related` and `rule_bytes` do (ADR-0022).
- **Output-affecting fixes get listed.** If a change makes Stage 4/5 emit
  different objects for the same input, append its commit to the
  bundle-affecting list read by `scripts/audit_bundle_invariants.py` (ADR-0035).
  Stored bundles are not rebuilt automatically, so without that line a fixed
  defect keeps riding in every artefact built before it — which is exactly how
  six self-edges outlived their fix.
- **Line length** is 120 (ruff). Keep imports sorted (`ruff --fix` handles `I001`).
- **Commits** — branch off `main`; keep a change + its tests + doc update together.

## Docs to keep current
When a feature lands, update: [`README.md`](README.md) (user-facing — including
the **Database schema** and **Project structure** sections if either changed),
[`CHANGELOG.md`](CHANGELOG.md), the relevant ADR, and [`TESTING.md`](TESTING.md) if
coverage changed. Feature-specific walkthroughs live in [`docs/`](docs/); if you
add or replace a screenshot, follow
[`docs/screenshots/README.md`](docs/screenshots/README.md) and update its index.
