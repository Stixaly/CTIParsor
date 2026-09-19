# CTIParsor — Docker is the only supported way to build, run, test and
# develop this project (ADR-0054). Nothing here needs a Python venv or a
# local Node install; `bash setup.sh` (or `make setup`) prepares .env and
# the DB-password secret, everything else runs in containers.

.PHONY: setup package-offline setup-offline \
        test test-fast run run-dir check check-docs \
        corpora detection-index backfill-rules \
        audit lock update-deps npm-outdated npm-update clean \
        docker-build docker-up docker-bootstrap docker-smoke docker-logs docker-down \
        docker-test docker-frontend-dev

CTI_ENV_FILE ?= .env

# Used by every target that runs pipeline/test code: the `dev` compose
# service (profile `dev`, ADR-0054) — same image as `app`/`worker`, with the
# repo bind-mounted live over /app so edits need no rebuild. `--rm` since
# these are one-shot invocations, not long-running services.
DEV_RUN = docker compose run --rm dev

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

## Run all tests
test: .secrets/db_password
	$(DEV_RUN) pytest tests/ -v

## Run tests excluding LLM-dependent tests (no API key required)
test-fast: .secrets/db_password
	$(DEV_RUN) pytest tests/ -v -k "not llm"

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

## Scan Python deps for known CVEs (pip-audit, no image build needed)
audit:
	docker run --rm -v "$$(pwd)":/audit -w /audit python:3.12-slim \
	    sh -c "pip install --quiet pip-audit && python -m pip_audit -r requirements.txt -r requirements-api.txt"
	@echo ""
	@echo "=== npm dependency audit ==="
	docker run --rm -v "$$(pwd)/frontend":/ui -w /ui node:24-bookworm-slim \
	    sh -c "npm audit --audit-level=moderate || true"

## Freeze the image's exact installed versions -> requirements.lock.txt
## Commit this file so CI and production always install the exact same versions.
lock: .secrets/db_password
	$(DEV_RUN) pip freeze > requirements.lock.txt
	@echo "Locked $$(wc -l < requirements.lock.txt | tr -d ' ') packages -> requirements.lock.txt"

## Rebuild with no layer cache (forces pip to re-resolve against the current
## requirements.txt constraints), run the fast test suite, then re-lock.
update-deps:
	docker compose build --no-cache app
	$(MAKE) test-fast
	$(MAKE) lock
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

## Run the full test suite in the `dev` container (ADR-0054) -- alias for `make test`
docker-test: .secrets/db_password
	docker compose run --rm dev pytest tests/ --ignore=tests/eval_pipeline.py -v

## Frontend hot-reload dev server (Vite, HMR) -- http://localhost:5173,
## proxies /api to the `app` service (must be running: `make docker-up`)
docker-frontend-dev:
	docker compose --profile dev up frontend-dev
