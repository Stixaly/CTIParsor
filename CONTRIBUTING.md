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

```bash
docker compose run --rm dev pytest tests/ -q -k "not llm"     # fast lane (CI gate)
docker compose run --rm dev pytest tests/ -q                  # full suite (adds retry/transient tests)
docker compose run --rm dev ruff check pipeline/ api/ models/ tests/ scripts/ --select E,F,W,I
docker compose run --rm dev sh -c "cd frontend && npx tsc --noEmit"   # frontend type-check
```

`docker compose run --rm dev` bind-mounts the repo live over `/app` — edits
on the host are picked up with no image rebuild. A single-test edit/run
loop pays `docker compose run`'s startup cost each time; run `pytest tests/path/to/test_x.py -k name`
the same way to keep it small.

- LLM calls are mocked via `conftest.mock_llm`; tests run offline.
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
| a job-store or rule-store table or column | `_JOB_STORE_DDL_POSTGRES` or `_RULE_STORE_DDL_POSTGRES` in `api/db.py` (ADR-0045, ADR-0053 — one PostgreSQL-only DDL tuple per store, `IF NOT EXISTS`/`ADD COLUMN IF NOT EXISTS` so it doubles as the migration); document it in the README's Database schema section |
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
  fresh database). Document the new table or column in the README's
  [Database schema](README.md#database-schema) section.
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
When a feature lands, update: [`README.md`](README.md) (user-facing — including
the **Database schema** and **Project structure** sections if either changed),
[`CHANGELOG.md`](CHANGELOG.md), the relevant ADR, and [`TESTING.md`](TESTING.md) if
coverage changed. Feature-specific walkthroughs live in [`docs/`](docs/); if you
add or replace a screenshot, follow
[`docs/screenshots/README.md`](docs/screenshots/README.md) and update its index.
