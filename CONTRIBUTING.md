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
uvicorn api.main:app --reload --app-dir .  # Web UI → http://localhost:8000
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

## Where changes go (extension seams)

| To add… | Touch |
|---|---|
| an LLM provider | `pipeline/stage3_llm.py` (`_call_llm`, `_provider_ready`) + `.env.example` |
| an input format | `pipeline/stage1_ingestion.py` + `SUPPORTED_EXTENSIONS` in `main.py` |
| an IoC type | `models/schemas.py` (`EntityType`), `stage2_extraction.py`, `stage4_stix_mapping.py` |
| a detection-rule format | a new `RuleCorpusAdapter` in `pipeline/detection/` + register it in `registry.py` |
| an API route | `api/routes/`, then `app.include_router(...)` in `api/main.py` |
| a frontend page | `frontend/src/pages/` + a route in `App.tsx` (+ a nav link in `Layout.tsx`) |

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
