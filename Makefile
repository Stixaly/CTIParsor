# CTIParsor — Docker is the only supported way to build, run, test and
# develop this project (ADR-0054). Nothing here needs a Python venv or a
# local Node install; `bash setup.sh` (or `make setup`) prepares .env and
# the DB-password secret, everything else runs in containers.

.PHONY: setup package-offline setup-offline \
        test test-fast lint typecheck coverage frontend-check ci \
        run run-dir check check-docs \
        corpora detection-index backfill-rules \
        audit lock update-deps npm-outdated npm-update clean \
        docker-build docker-up docker-bootstrap docker-smoke docker-logs docker-down \
        docker-test docker-frontend-dev

CTI_ENV_FILE ?= .env

# Used by every target that runs pipeline/test code: the `dev` compose
# service (profile `dev`, ADR-0054) — the `app`/`worker` image plus the CI
# tools, with the repo bind-mounted live over /app so edits need no rebuild. `--rm` since
# these are one-shot invocations, not long-running services.
DEV_RUN = docker compose run --rm dev
# The same, with a test skipped for a missing import counted as a failure,
# as in CI (tests/conftest.py): the dev image has every dependency.
DEV_RUN_CI = docker compose run --rm -e CTIPARSOR_REQUIRE_TEST_DEPS=1 dev

# ── Setup ────────────────────────────────────────────────────────────────────

## Prepare .env and the DB-password secret, check Docker is present (runs setup.sh)
setup:
	bash setup.sh

## Build the air-gap bundle in offline/ and pack it into dist/ (ADR-0054).
## Run on a CONNECTED machine with Docker, same architecture as the target.
package-offline:
	bash scripts/package_offline_docker.sh

## Install from an extracted air-gap bundle, no network needed (ADR-0054)
setup-offline:
	bash setup.sh --offline=offline

# ── Detection-rule store (ADR-0006 / 0015 / 0022 / 0053) ─────────────────────
# One-off maintenance operations outside the full `docker compose --profile
# bootstrap run --rm bootstrap` cycle — e.g. re-syncing just the corpora
# after editing detection_corpora.local.yaml.

## Clone/pull the rule corpora (Sigma, Suricata, YARA) into ./corpora
corpora: .secrets/db_password
	$(DEV_RUN) python scripts/sync_corpora.py

## Parse the local clones into the rule store (also dedups and writes rule_bytes)
detection-index: .secrets/db_password
	$(DEV_RUN) python scripts/build_detection_index.py

## Backfill rule body sizes on a store built before ADR-0022 (no re-clone needed)
backfill-rules: .secrets/db_password
	$(DEV_RUN) python -m scripts.backfill_rule_bytes

# ── Testing ──────────────────────────────────────────────────────────────────

## Run all tests (the selection CI runs: tests/, eval_pipeline.py included)
test: .secrets/db_password
	$(DEV_RUN) pytest -v

## Quicker loop: also deselects every test whose id contains "llm" (56 in 10
## modules today, mostly Stage 3 and vision tests on a mocked LLM). Not what CI runs.
test-fast: .secrets/db_password
	$(DEV_RUN) pytest tests/ -v -k "not llm"

## Lint the Python code (scope and rules: pyproject.toml)
lint: .secrets/db_password
	$(DEV_RUN) ruff check .

## Type-check the Python code (scope and flags: pyproject.toml)
typecheck: .secrets/db_password
	$(DEV_RUN) mypy

## Run all tests with branch coverage, then the floors CI enforces: the total
## (pyproject.toml) and per area (scripts/check_coverage.py)
coverage: .secrets/db_password
	$(DEV_RUN_CI) sh -c "pytest -q -rs --cov --cov-report=term-missing:skip-covered && python scripts/check_coverage.py"

## Frontend lint, type check and unit tests (`npm run check`, as in CI)
frontend-check:
	docker compose run --rm frontend-dev sh -c "npm ci --no-audit --no-fund && npm run check"

## Every check CI runs on a pull request, locally: lint, types, tests with
## coverage floors, frontend.  (The image build and smoke test: make docker-smoke)
ci: lint typecheck coverage frontend-check

# ── Pipeline ─────────────────────────────────────────────────────────────────

## Run pipeline on the sample report
run: .secrets/db_password
	$(DEV_RUN) cli tests/fixtures/sample_report.txt --output output/sample_bundle.json

## Run pipeline on all files in input/
run-dir: .secrets/db_password
	$(DEV_RUN) cli --input-dir input/ --output-dir output/

# ── Diagnostics ──────────────────────────────────────────────────────────────

## Check which pipeline stages are available (imports + data files + rule store)
check: .secrets/db_password
	$(DEV_RUN) check

## Verify every number claimed in README.md still matches the source of truth
check-docs: .secrets/db_password
	$(DEV_RUN) python scripts/check_doc_claims.py

# ── Dependency maintenance ────────────────────────────────────────────────────
# All Python/Node dependencies live in the image now, not a host venv/
# node_modules — "upgrade" means bumping the version constraints in
# requirements.txt/package.json by hand, then rebuilding to actually resolve
# them (`docker compose build --no-cache` bypasses layer caching so pip/npm
# re-resolve against the current constraints instead of reusing old wheels).

## Scan the dependencies for known CVEs, as the CI dependency-audit job does:
## the exact versions of requirements.lock.txt (not the ranges), and the UI's
## production packages.  Accepted ones are listed in SECURITY.md.
AUDIT_IGNORE ?= --ignore-vuln PYSEC-2026-2447
audit:
	docker run --rm -v "$$(pwd)":/audit -w /audit python:3.12-slim \
	    sh -c "pip install --quiet pip-audit && python -m pip_audit -r requirements.lock.txt \
	        --no-deps --disable-pip --progress-spinner off $(AUDIT_IGNORE)"
	@echo ""
	@echo "=== npm dependency audit (production) ==="
	docker run --rm -v "$$(pwd)/frontend":/ui -w /ui node:24-bookworm-slim \
	    sh -c "npm audit --omit=dev --audit-level=high"

## Resolve requirements*.txt -> requirements.lock.txt, the exact versions the
## image and CI install (Python 3.12, CPU-only torch, every platform).
## Keeps the current pins that still fit the ranges; LOCK_FLAGS=--upgrade
## re-resolves everything to the newest allowed versions.
LOCK_FLAGS ?=
lock:
	docker run --rm --user "$$(id -u):$$(id -g)" -e HOME=/tmp -v "$$(pwd)":/w -w /w python:3.12-slim \
	    sh -c "pip install --quiet --target /tmp/uv uv && /tmp/uv/bin/uv pip compile \
	        requirements.txt requirements-api.txt requirements-optional.txt \
	        --universal --python-version 3.12 \
	        --extra-index-url https://download.pytorch.org/whl/cpu --index-strategy unsafe-best-match \
	        --emit-index-url --annotation-style line --custom-compile-command 'make lock' \
	        $(LOCK_FLAGS) -o requirements.lock.txt"
	@echo "Locked $$(grep -c '==' requirements.lock.txt) packages -> requirements.lock.txt"

## Re-resolve to the newest versions the ranges allow, rebuild the image from
## the new lock, run the fast test suite.
update-deps:
	$(MAKE) lock LOCK_FLAGS=--upgrade
	docker compose build app
	$(MAKE) test-fast
	@echo ""
	@echo "Done. Review 'git diff requirements.lock.txt' then commit if tests passed."

## Show which npm packages have newer versions available
npm-outdated:
	docker run --rm -v "$$(pwd)/frontend":/ui -w /ui node:24-bookworm-slim npm outdated || true

## Upgrade npm packages to the latest version allowed by package.json semver
## ranges, then type-check to catch regressions.
npm-update:
	docker run --rm -v "$$(pwd)/frontend":/ui -w /ui node:24-bookworm-slim \
	    sh -c "npm update && node_modules/.bin/tsc --noEmit"
	@echo "npm packages updated. Review 'git diff frontend/package-lock.json'."

# ── Maintenance ───────────────────────────────────────────────────────────────

## Remove build artefacts (host-side only; nothing here needs a container)
clean:
	rm -rf output/*.json
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null; true
	find . -name "*.pyc" -delete 2>/dev/null; true

# ── Containers (ADR-0044, ADR-0054) ───────────────────────────────────────────

## Build the container image (CPU-only torch, Chromium included)
docker-build:
	CTI_GIT_REV=$$(git rev-parse HEAD 2>/dev/null) docker compose build app

# Materializes CTI_DB_PASSWORD (from .env) into a file compose.yaml
# bind-mounts into every service at /run/secrets/db_password, so the value
# never appears in `docker inspect`/`docker compose config` output the way a
# plain `environment:` entry would. `bash setup.sh` does the same on a fresh
# checkout; this re-materializes it if .env changed since. World-readable
# (644, not 600): app/worker/bootstrap read it as uid 1001 and postgres as
# uid 70 -- none of them is the host user that creates the file, so an
# owner-only mode makes every container fail to read it. It stays out of the
# image (.dockerignore) and out of git (.gitignore); the same host access
# that could read this file could already read .env itself.
.secrets/db_password: $(CTI_ENV_FILE)
	mkdir -p .secrets
	set -a; case "$(CTI_ENV_FILE)" in /*) . "$(CTI_ENV_FILE)" ;; *) . "./$(CTI_ENV_FILE)" ;; esac; set +a; \
	: "$${CTI_DB_PASSWORD:?Set CTI_DB_PASSWORD in $(CTI_ENV_FILE) (e.g. openssl rand -hex 24, or just run: bash setup.sh)}"; \
	printf '%s' "$$CTI_DB_PASSWORD" > .secrets/db_password
	chmod 644 .secrets/db_password

## Start the full stack -- API, worker, and Postgres -- in the background
## (http://127.0.0.1:8000 by default). `app` alone would leave every upload
## stuck `queued` forever with nothing to process it (ADR-0046).
docker-up: .secrets/db_password
	docker compose up -d

## One-shot: download the NLP models, clone the corpora, build the rule store
docker-bootstrap: .secrets/db_password
	docker compose --profile bootstrap run --rm bootstrap

## Build, start, and verify the container (health, non-root, read-only, Chromium sandbox)
docker-smoke: .secrets/db_password
	bash scripts/docker_smoke.sh

## Follow the API logs
docker-logs:
	docker compose logs -f app

## Stop the stack (volumes are kept)
docker-down:
	docker compose down

## Alias for `make test` (every target runs in the `dev` container, ADR-0054)
docker-test: test

## Frontend hot-reload dev server (Vite, HMR) -- http://localhost:5173,
## proxies /api to the `app` service (must be running: `make docker-up`)
docker-frontend-dev:
	docker compose --profile dev up frontend-dev
