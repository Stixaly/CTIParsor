PYTHON   = .venv/bin/python
PIP      = .venv/bin/pip

.PHONY: setup install install-api install-capture download-mitre build-indexes \
        model test test-fast run run-dir \
        api api-dev frontend-install frontend-build frontend-dev \
        check check-docs clean \
        corpora detection-index backfill-rules \
        audit lock update-deps npm-outdated npm-update \
        package-offline setup-offline

# ── Setup ────────────────────────────────────────────────────────────────────

## Full first-time setup (runs setup.sh)
setup:
	bash setup.sh

## Build the air-gap bundle in offline/ and pack it into dist/ (ADR-0040).
## Run on a CONNECTED machine with the same distro + Python as the target.
package-offline:
	bash scripts/package_offline.sh

## Install from an extracted bundle, no network needed (ADR-0040)
setup-offline:
	bash setup.sh --offline=offline

## Install / update Python packages only (skip interactive prompts)
install:
	$(PIP) install --upgrade pip
	$(PIP) install -r requirements.txt -r requirements-api.txt

## Install API packages only
install-api:
	$(PIP) install -r requirements-api.txt

## Install web capture (URL -> PDF ingestion): Playwright + a headless Chromium.
## The system libraries need root and are NOT installed here -- that step is what
## fixes the opaque "error while loading shared libraries: libasound.so.2" failure.
install-capture:
	$(PIP) install playwright
	$(PYTHON) -m playwright install chromium
	@echo ""
	@echo "System libraries need root. Run:"
	@echo "    sudo $(PYTHON) -m playwright install-deps chromium"

# ── MITRE Data ───────────────────────────────────────────────────────────────

## Download all MITRE ATT&CK + CAPEC bundle files into data/
download-mitre:
	@mkdir -p data
	@echo "Downloading enterprise-attack.json …"
	@curl -fsSL --retry 3 -o data/enterprise-attack.json \
	    https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json
	@echo "Downloading mobile-attack.json …"
	@curl -fsSL --retry 3 -o data/mobile-attack.json \
	    https://raw.githubusercontent.com/mitre/cti/master/mobile-attack/mobile-attack.json
	@echo "Downloading ics-attack.json …"
	@curl -fsSL --retry 3 -o data/ics-attack.json \
	    https://raw.githubusercontent.com/mitre/cti/master/ics-attack/ics-attack.json
	@echo "Downloading stix-capec.json …"
	@curl -fsSL --retry 3 -o data/stix-capec.json \
	    https://raw.githubusercontent.com/mitre/cti/master/CAPEC/stix-capec.json
	@echo "Done."

## Build compact MITRE index, gazetteer, and sentence embeddings from data/ bundles
build-indexes:
	$(PYTHON) scripts/build_indexes.py \
	    --enterprise data/enterprise-attack.json \
	    --mobile     data/mobile-attack.json \
	    --ics        data/ics-attack.json \
	    --capec      data/stix-capec.json

## Download bundles + build indexes in one step
mitre: download-mitre build-indexes

# ── Detection-rule store (ADR-0006 / 0015 / 0022) ────────────────────────────

## Clone/pull the rule corpora (Sigma, Suricata, YARA) into ./corpora
corpora:
	$(PYTHON) scripts/sync_corpora.py

## Parse the local clones into the rule store (also dedups and writes rule_bytes)
detection-index:
	$(PYTHON) scripts/build_detection_index.py

## Backfill rule body sizes on a store built before ADR-0022 (no re-clone needed)
backfill-rules:
	$(PYTHON) -m scripts.backfill_rule_bytes

## Download + install optional spaCy small model
model:
	$(PYTHON) -m spacy download en_core_web_sm

# ── Testing ──────────────────────────────────────────────────────────────────

## Run all tests
test:
	$(PYTHON) -m pytest tests/ -v

## Run tests excluding LLM-dependent tests (no API key required)
test-fast:
	$(PYTHON) -m pytest tests/ -v -k "not llm"

# ── Pipeline ─────────────────────────────────────────────────────────────────

## Run pipeline on the sample report
run:
	$(PYTHON) main.py tests/fixtures/sample_report.txt --output output/sample_bundle.json

## Run pipeline on all files in input/
run-dir:
	$(PYTHON) main.py --input-dir input/ --output-dir output/

# ── Web UI ───────────────────────────────────────────────────────────────────

## Install npm dependencies from the lockfile (wipes node_modules first)
frontend-install:
	cd frontend && npm ci

## Build the React frontend (output → frontend/dist/)
frontend-build:
	cd frontend && npm run build

## Production: build the frontend, then serve both it and the API on one port.
## Host and port come from .env (API_HOST / API_PORT); the default 127.0.0.1
## is local-only.  To let other machines reach it, read docs/deployment.md
## first -- there is no authentication.
api: frontend-build
	$(PYTHON) run_api.py

## Development (hot-reload API only — run 'make frontend-dev' in a second terminal)
api-dev:
	API_RELOAD=1 $(PYTHON) run_api.py

## Development (hot-reload frontend — run alongside 'make api-dev')
frontend-dev:
	cd frontend && npm run dev

# ── Diagnostics ──────────────────────────────────────────────────────────────

## Check which pipeline stages are available (imports + data files)
check:
	@$(PYTHON) scripts/check_stages.py

## Verify every number claimed in README.md still matches the source of truth
check-docs:
	@$(PYTHON) scripts/check_doc_claims.py

# ── Dependency maintenance ────────────────────────────────────────────────────

## Scan Python deps for known CVEs and vulnerabilities (uses pip-audit)
audit:
	@$(PIP) install --quiet pip-audit
	@echo ""
	@echo "=== Python dependency audit ==="
	$(PYTHON) -m pip_audit -r requirements.txt -r requirements-api.txt
	@echo ""
	@echo "=== npm dependency audit ==="
	cd frontend && npm audit --audit-level=moderate || true

## Freeze exact installed versions → requirements.lock.txt (for reproducible deploys)
## Commit this file so CI and production always install the exact same versions.
lock:
	$(PYTHON) -m pip freeze > requirements.lock.txt
	@echo "Locked $$(wc -l < requirements.lock.txt | tr -d ' ') packages → requirements.lock.txt"

## Upgrade all Python packages to the latest version allowed by requirements.txt,
## then run the fast test suite to catch regressions, then re-lock.
update-deps:
	$(PIP) install --upgrade pip
	$(PIP) install --upgrade -r requirements.txt -r requirements-api.txt
	@echo ""
	@echo "=== Running fast tests to verify upgraded deps ==="
	$(MAKE) test-fast
	$(MAKE) lock
	@echo ""
	@echo "Done. Review 'git diff requirements.lock.txt' then commit if tests passed."

## Show which npm packages have newer versions available
npm-outdated:
	cd frontend && npm outdated || true

## Upgrade npm packages to the latest version allowed by package.json semver ranges,
## then run tsc to catch type regressions.
npm-update:
	cd frontend && npm update
	cd frontend && node_modules/.bin/tsc --noEmit
	@echo "npm packages updated. Review 'git diff frontend/package-lock.json'."

# ── Maintenance ───────────────────────────────────────────────────────────────

## Remove build artefacts
clean:
	rm -rf output/*.json
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null; true
	find . -name "*.pyc" -delete 2>/dev/null; true

## Remove virtual environment (full reinstall)
clean-venv:
	rm -rf .venv

# ── Containers (ADR-0044) ────────────────────────────────────────────────────

.PHONY: docker-build docker-up docker-bootstrap docker-smoke docker-logs docker-down

CTI_ENV_FILE ?= .env

## Build the container image (CPU-only torch, Chromium included)
docker-build:
	CTI_GIT_REV=$$(git rev-parse HEAD 2>/dev/null) docker compose build app

# Materializes CTI_DB_PASSWORD (from .env) into a file compose.yaml
# bind-mounts into every service at /run/secrets/db_password, so the value
# never appears in `docker inspect`/`docker compose config` output the way a
# plain `environment:` entry would. Re-run whenever .env changes; scripts/
# docker_smoke.sh does the same for its own standalone `docker compose up`.
# World-readable (644, not 600): app/worker/bootstrap read it as uid 1001 and
# postgres as uid 70 -- none of them is the host user that creates the file,
# so an owner-only mode makes every container fail to read it. It stays out
# of the image (.dockerignore) and out of git (.gitignore); the same host
# access that could read this file could already read .env itself.
.secrets/db_password: $(CTI_ENV_FILE)
	mkdir -p .secrets
	set -a; case "$(CTI_ENV_FILE)" in /*) . "$(CTI_ENV_FILE)" ;; *) . "./$(CTI_ENV_FILE)" ;; esac; set +a; \
	: "$${CTI_DB_PASSWORD:?Set CTI_DB_PASSWORD in $(CTI_ENV_FILE) (e.g. openssl rand -hex 24)}"; \
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
