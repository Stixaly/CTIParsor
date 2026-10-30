# Professionalization plan: from a research prototype to a production product

**Status:** Proposed. **Date:** 2026-11-04. **Author:** Vibe Code (Mistral AI), from a
read of `main` @ `1b90613`.
**Scope:** this document turns the gap analysis into an ordered, implementable plan.
It changes no code; each workstream below names the files it will touch, the ADR it
must land, and the acceptance tests that close it.

## 0. Where the project already stands (do not re-do)

`main` already has what most projects never reach: full CI (ruff, mypy, unit tests,
coverage floors, pip-audit, npm audit, dependency review — `.github/workflows/ci.yml`),
CodeQL + OpenSSF Scorecard, fuzz targets in CI, hash-locked installs (ADR-0080),
versioned Postgres migrations (`api/migrations/v0001…v0013`), SLSA-signed releases with
attested SBOM on ghcr (`.github/workflows/release.yml`), 93 ADRs, 180 test files,
`SECURITY.md`, REUSE licensing, Docker healthchecks, and a hardened API surface
(`TrustedHostMiddleware`, cross-site write refusal, body budgets, four independent
rate limits — `api/main.py:146-260`). The remaining gaps are about **exposure and
governance**, not internal quality.

## 1. Workstreams and order

Ordered by value/risk: the first two are what stops a shared enterprise deployment
today; the rest follow.

| # | Workstream | Why first / risk | Effort | New ADR |
|---|---|---|---|---|
| W1 | Authentication & RBAC on the API | Blocks any non-localhost deployment; touches every route | L | ADR-0094 |
| W2 | Observability: Prometheus metrics, structured logs, API versioning | Needed to operate at scale; additive, low risk | M | ADR-0095 |
| W3 | Distribution: PyPI package, console script, semver + deprecation policy | Makes it installable like a product | M | ADR-0096 |
| W4 | Governance: issue/PR templates, CODEOWNERS, public roadmap, support policy | Cheap, immediate trust signal | S | — |
| W5 | Product polish: `/v1` API prefix, i18n + accessibility, perf budget in CI | Adoption and compliance | L | ADR-0097 |
| W6 | Integrations: push connectors (OpenCTI/MISP/TAXII), webhooks, multi-tenancy | Biggest scope; do last, behind W1 | XL | ADR-0098 |

Dependency rule: **W6 cannot ship before W1** (connectors need an authenticated,
auditable caller). W2 is independent. W3 depends on nothing but should follow W1 so
the first published package already speaks authenticated.

---

## 2. W1 — Authentication & RBAC (blocks enterprise use)

### 2.1 Current state
`api/main.py:146` states it plainly: "The app has no authentication". The defenses
today are network/origin-level only: `TrustedHostMiddleware` (Host allowlist),
cross-site write refusal via `Sec-Fetch-Site`/`Origin` (`refuse_cross_site_writes`,
`api/main.py:201-215`), body limits, rate limits. Those stay; auth is added **on top**,
never replacing them.

### 2.2 Architecture

```
client ──► nginx proxy profile (TLS, optional) ──► uvicorn (api.main:app)
                                                        │
                              ┌─────────────────────────┘
                              ▼
                    AuthMiddleware (new: api/auth/middleware.py)
                      1. If API_AUTH_ENABLED=false → pass through (default, today's behavior)
                      2. Bearer token (API key)  → api/auth/keys.py  → principal
                      3. OIDC session cookie     → api/auth/oidc.py  → principal (later slice)
                              │
                              ▼
                    RBAC dependency: require_role("analyst"|"admin") per route
                              │
                              ▼
                    existing route handlers (unchanged signatures)
```

- **Principals** stored in Postgres, new migration `v0014_auth_principals.py`:
  table `principals(id uuid pk, name text unique, kind text check in ('apikey','oidc'),
  role text check in ('analyst','admin'), hashed_secret text null, created_at, last_used_at,
  disabled bool default false)`. API keys stored **hashed only** (argon2id via
  `argon2-cffi`, or scrypt from stdlib if we want zero new deps — decide in ADR-0094;
  repo policy is "no new dependency unless already used", and neither argon2 nor
  passlib is in `requirements/`, so **stdlib `hashlib.scrypt` with per-key salt is the
  default choice**).
- **Key format**: `ctip_<kid>_<secret>` where `kid` is a short public id used for
  lookup; the secret part is what gets hashed. Rotation = create new, disable old;
  `last_used_at` updated on each authenticated request (cheap `UPDATE`).
- **Middleware** (`api/auth/middleware.py`): reads `Authorization: Bearer …` or the
  `ctip_session` cookie (for the future OIDC slice); on success attaches
  `request.state.principal`. On failure: 401 with `WWW-Authenticate: Bearer`.
  Must run **after** `TrustedHostMiddleware` and the write-guard (those are first
  lines of defense, cheap and unauthenticated by design).
- **RBAC**: a FastAPI dependency `require_role(role)` in `api/auth/rbac.py`, applied
  per router in `api/main.py` at `include_router` time:
  - `analyst` (default): all current read routes + upload/ingest/job routes + review
    decisions (today's UI user).
  - `admin`: `settings`, `policy`, `thresholds`, `overrides`, `attack`, corpus
    management, and the new `principals` management routes (`api/routes/principals.py`:
    `POST /api/admin/principals`, `POST /api/admin/principals/{id}/disable`,
    `GET /api/admin/principals`). Creating the **bootstrap admin key** happens out of
    band: `python -m api.auth.bootstrap` prints one `ctip_…` key, writes only its hash.
- **Flag**: `API_AUTH_ENABLED` via `pipeline/env_flags.env_bool`, default `false`.
  Default-off preserves today's single-user localhost UX and every existing test;
  CI gets a new job running the suite with it `true`. `.env.example` documents it.
- **Audit**: every authenticated mutating request logs
  `principal=<kid> role=<role> method path status` through the existing
  `api/logging_config.py` request-id flow (extend, don't replace).
- **Frontend**: when auth is on, the UI shows a login field for the API key, stores it
  in `sessionStorage` (not localStorage), sends it as `Authorization`; the Vite dev
  proxy forwards it. `frontend/src/api/client.ts` gains one interceptor — no route
  changes.

### 2.3 Files touched
- New: `api/auth/__init__.py`, `api/auth/middleware.py`, `api/auth/keys.py`,
  `api/auth/rbac.py`, `api/auth/bootstrap.py`, `api/routes/principals.py`,
  `api/migrations/v0014_auth_principals.py`, tests under `tests/` mirroring the
  existing per-route test layout.
- Edited: `api/main.py` (register middleware after TrustedHost, add role per router),
  `compose.yaml` (pass `API_AUTH_ENABLED` through), `.env.example`,
  `docs/deployment.md`, `docs/api.md`, `frontend/src/api/client.ts`, `docs/adr/README.md`.

### 2.4 Acceptance
- With `API_AUTH_ENABLED=false`, the whole existing test suite passes unchanged.
- With it `true`: no key → 401 on every route; analyst key → 403 on `/api/admin/*`;
  admin key → 200; disabled key → 401; wrong secret → 401; keys never stored in
  clear (grep the DB in a test); CSRF/Host/body guards still fire before auth.
- `make ci` green including a new auth-enabled variant; pip-audit clean (no new dep
  if scrypt chosen).

---

## 3. W2 — Observability & API versioning

### 3.1 Metrics (Prometheus)
- New module `api/metrics.py` using `prometheus-client` **only if** we accept one new
  dependency (it is the ecosystem standard; ADR-0095 weighs it against a hand-rolled
  text endpoint — default: hand-rolled `/api/metrics` in Prometheus text format, zero
  deps, since the repo already avoids deps it doesn't strictly need).
- Counters: `ctiparsor_jobs_total{status}`, `ctiparsor_llm_calls_total{provider,stage}`,
  `ctiparsor_llm_tokens_total{provider,direction}`, `ctiparsor_http_requests_total{method,route,status}`,
  `ctiparsor_auth_failures_total`. Histograms: job duration per stage,
  upload size, LLM latency. Gauge: queue depth (already exposed via `/api/queue`),
  DB connections.
- Instrument at the existing seams: `api/queue_loop.py` (job lifecycle), `pipeline/stage3_llm.py`
  (LLM calls — it already centralizes provider calls per ADR-0033),
  `api/main.py` middleware (HTTP), `api/auth/middleware.py` (auth failures).
- Gate behind `METRICS_ENABLED` (default true; the endpoint itself is read-only and
  unauthenticated but returns only counters, no report content — decision in ADR-0095).
- `compose.yaml`: the `proxy` nginx profile scrapes nothing; instead document a
  `prometheus` profile addition in `docs/deployment.md` (scrape config example), do not
  add a service by default.

### 3.2 Structured logs
- `api/logging_config.py` already has request ids; add: emit JSON lines when
  `LOG_FORMAT=json` (one-line-per-request with `request_id`, `principal`, `route`,
  `status`, `duration_ms`), default stays human-readable. Ship a `docs/deployment.md`
  section on shipping logs to Loki/ELK.

### 3.3 API versioning
- Mount all routers twice: under `/api/v1/...` (new canonical) and keep `/api/...`
  as an alias that emits `Deprecation: true` + `Sunset:` headers (RFC 8594) on
  responses. Implementation: in `api/main.py`, `include_router(router, prefix="/api/v1")`
  for each existing router, then a thin alias router that re-dispatches `/api/*` →
  `/api/v1/*` internally (or simply include each router a second time with the old
  prefix and wrap responses with the deprecation headers via middleware keyed on path).
  Frontend switches to `/api/v1` in `frontend/src/api/client.ts`.
- `docs/api.md` documents both, with the sunset date policy (see W3 policy: N-1 major
  versions supported, 12 months after successor release).

### 3.4 Acceptance
- `/api/metrics` returns valid Prometheus text; counters increase after one upload
  through the API (assert in a test using a real job).
- All existing tests pass against `/api/v1` (parametrize the test client base path);
  `/api/...` still works and carries `Deprecation` header.
- `LOG_FORMAT=json` produces parseable JSON lines in a smoke test (`scripts/docker_smoke.sh`
  extension or a unit test on the formatter).

---

## 4. W3 — Distribution & release policy

### 4.1 PyPI package
- Add to `pyproject.toml`: `[build-system]` (setuptools, already the de-facto choice;
  no new build dep in CI since `pip` bundles it) and `[project]` with
  `name = "ctiparsor"`, `version` read dynamically from `pipeline/__init__.py:__version__`
  (`dynamic = ["version"]` + `[tool.setuptools.dynamic]`), `requires-python = ">=3.14"`,
  dependencies = the runtime set of `requirements/requirements.txt` (the light profile:
  pipeline + API without torch — note `requirements-full.txt` stays Docker-only).
- `[project.scripts]`: `ctiparsor = "main:main"` (the existing argparse CLI at `main.py:221`).
- Package data: `detection_corpora.yaml`, models config — exclude corpora clones and
  model weights from the wheel (they stay Docker/offline-bundle artifacts, per the
  air-gap design); document `pip install ctiparsor` + `ctiparsor --help` in README.
- Publish in `.github/workflows/release.yml` on the same `v*` tag: build wheel+sdist
  with `python -m build`, upload to PyPI via trusted publisher (OIDC), same run that
  signs the image — one tag, one release, three artifacts (image, SBOM/provenance,
  wheel). Lock the new build deps by hash per ADR-0080 (`scripts/lock_pypi_hashes.py`
  already exists for this).

### 4.2 Semver + deprecation policy (doc, then enforced)
- Write `docs/releasing.md` addition: versions are `MAJOR.MINOR.PATCH`; MAJOR bumps for
  API-incompatible changes (with 12-month overlap as in W2.3), MINOR for features,
  PATCH for fixes. CHANGELOG already exists — adopt Keep-a-Changelog headings if not
  already present.
- Enforced by a CI check: `scripts/check_changelog.py` fails the release workflow if
  the tag's version has no CHANGELOG entry.

### 4.3 Acceptance
- `pip install` from a locally built wheel in a clean venv; `ctiparsor --help` runs;
  `python -c "import pipeline; print(pipeline.__version__)"` matches the tag.
- Release workflow dry-run (workflow_dispatch on a non-tag ref) builds the wheel
  without publishing.

---

## 5. W4 — Governance (fast, no code)

- `.github/ISSUE_TEMPLATE/bug_report.yml`, `feature_request.yml`,
  `security.md` (pointing at the private channel in `SECURITY.md`),
  `.github/PULL_REQUEST_TEMPLATE.md` (summary, verification commands, ADR link,
  "Closes #" line — matching the repo's commit style seen in `git log`),
  `.github/CODEOWNERS` (`* @Stixaly` plus per-area owners as they emerge:
  `/api @…`, `/frontend @…`, `/pipeline/detection @…`).
- `ROADMAP.md` at repo root (or GitHub Projects linked from README): the six
  workstreams above as milestones with target releases.
- `docs/support.md`: what is supported (latest MAJOR + previous, per W3 policy),
  how to report (SECURITY.md for vulnerabilities), response-time **goal** stated as
  best-effort for a community project — no SLA promises.
- Enable GitHub Discussions (repo setting, noted in README "Feedback and contributing").
- No code; acceptance = files exist and `gh repo view` shows Discussions on.

---

## 6. W5 — Product polish

### 6.1 API prefix `/v1` — covered in W2.3.

### 6.2 i18n & accessibility (frontend)
- `frontend/package.json`: add `react-i18next` + `i18next` (the standard; frontend
  already uses npm with a lockfile and `npm audit` in CI, so this fits the existing
  supply-chain gates). Extract all UI strings to `frontend/public/locales/{en,fr}/…`
  (project is French-authored; en + fr first).
- Accessibility: audit against WCAG 2.1 AA with `axe-core` in the existing vitest
  setup (`frontend/src/test/`); fix the violations the audit finds (focus order in the
  review pages, graph SVG needs text alternatives — the STIX graph component already
  has accessible labels to build on); add an `eslint-plugin-jsx-a11y` rule to
  `frontend/eslint.config.js` so regressions fail CI.
- Acceptance: `npm run test` includes axe checks on the main pages; eslint a11y rules
  pass; UI renders in fr with a language switcher in `Layout.tsx`.

### 6.3 Performance budget in CI
- Add a CI job (`.github/workflows/ci.yml`) that runs `scripts/measure_cold_start.py`
  and one representative end-to-end job through the API (the existing
  `scripts/docker_smoke.sh` path) and fails if p95 duration or image size regress
  beyond thresholds defined in the script (they already exist as measure scripts —
  wire them as gates, with a baseline JSON committed and updated deliberately).
- Acceptance: CI job green; a forced regression (test-only) fails it.

---

## 7. W6 — Integrations & multi-tenancy (last, biggest)

### 7.1 Push connectors
- New package area `pipeline/export/` (alongside the existing export routes):
  `opencti.py` (OpenCTI GraphQL push with its own API key, retry + dead-letter),
  `misp.py` (MISP REST events), `taxii.py` (TAXII 2.1 collection push).
  Config per connector in `.env` (`OPENCTI_URL`, `OPENCTI_TOKEN`, …), enabled flags
  via `env_bool`. Trigger: on job completion (hook in `api/queue_loop.py` where the
  job reaches its final status) and/or manual button in the UI (`POST /api/jobs/{id}/push/{connector}`).
- Secrets never logged; connector failures never fail the job — they land in a
  `push_attempts` table (migration `v0015`) with status, and surface in the UI job
  detail.
- Acceptance: integration test against `docker/opencti-test` (already in the repo) in
  CI; unit tests with a mocked HTTP layer for MISP/TAXII.

### 7.2 Webhooks
- `webhooks` table (same migration): URL, secret, events (`job.completed`,
  `job.failed`). Delivery = HMAC-SHA256-signed POST, 3 retries with backoff, logged.
- Acceptance: a local loopback receiver in tests gets the signed payload; bad
  signature rejected.

### 7.3 Multi-tenancy
- Add `tenant_id` to `jobs` and the rule store (migration), derived from the
  principal (W1) — `principals.tenant_id`. All route queries gain `AND tenant_id=?`;
  enforced in `api/db.py` helpers so no route can forget it. UI shows the tenant's
  jobs only.
- Acceptance: two tenants in a test see disjoint job lists; cross-tenant access
  returns 404 (not 403, to avoid existence leaks).

---

## 8. Cross-cutting rules for every workstream

1. **One ADR per workstream** (0094–0098), in the existing `docs/adr/` format, linked
   from `docs/adr/README.md` before implementation starts; append-only, supersede
   rather than rewrite.
2. **Feature flags via `pipeline/env_flags.py`** (`env_bool`/`env_int`), default off
   for anything that changes behavior; `.env.example` and `docs/configuration.md`
   updated in the same PR.
3. **Migrations**: one file per change in `api/migrations/`, `v0014+`; the CI job
   "Migrate a database written by the base commit" must stay green — new tables only,
   nullable columns, no rewrites of existing rows in the same migration.
4. **Tests**: mirror the existing layout (180 test files); coverage floors in CI
   (`scripts/check_coverage.py`) apply to new code; fuzz targets added for any new
   parser of untrusted input (ADR-0081 pattern).
5. **Supply chain**: any new dependency goes into `requirements/requirements.txt`
   with a comment, then `make lock` regenerates the hashed locks; CI `pip-audit` and
   dependency-review must pass; frontend deps via `package-lock.json` + `npm audit`.
6. **Docs drift**: numbers claimed in README/docs are checked by
   `scripts/check_doc_claims.py` — run it and update claims in the same PR.
7. **Security review of new surfaces**: anything parsing external input (webhook
   payloads, OIDC tokens, connector responses) gets the same treatment as
   `api/body_limit.py` (size budgets) and the SSRF posture already used by the URL
   ingest route.

## 9. Suggested sequencing (milestones)

| Milestone | Contents | Target release |
|---|---|---|
| M1 | W4 (governance files) + W1 (auth/RBAC) + ADR-0094 | v0.3.0 |
| M2 | W2 (metrics, logs, `/api/v1`) + ADR-0095 | v0.3.x or v0.4.0 |
| M3 | W3 (PyPI, console script, semver policy) + ADR-0096 | v0.4.0 |
| M4 | W5 (i18n/a11y, perf budget) + ADR-0097 | v0.5.0 |
| M5 | W6 (connectors, webhooks, tenancy) + ADR-0098 | v1.0.0 (first "production" major) |

v1.0.0 is the natural point to declare the API stable: auth on by default in the
`proxy` profile, `/api/v1` canonical, PyPI published, support policy active.
