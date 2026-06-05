PYTHON   = .venv/bin/python
PIP      = .venv/bin/pip
UVICORN  = .venv/bin/uvicorn

.PHONY: setup install install-api download-mitre build-indexes \
        model test test-fast run run-dir \
        api api-dev frontend-install frontend-build frontend-dev \
        check clean \
        audit lock update-deps npm-outdated npm-update

# ── Setup ────────────────────────────────────────────────────────────────────

## Full first-time setup (runs setup.sh)
setup:
	bash setup.sh

## Install / update Python packages only (skip interactive prompts)
install:
	$(PIP) install --upgrade pip
	$(PIP) install -r requirements.txt -r requirements-api.txt

## Install API packages only
install-api:
	$(PIP) install -r requirements-api.txt

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

## Install npm dependencies
frontend-install:
	cd frontend && npm install

## Build the React frontend (output → frontend/dist/)
frontend-build:
	cd frontend && npm run build

## Production: build frontend then start API (serves UI at /app)
api: frontend-build
	$(UVICORN) api.main:app --reload --app-dir .

## Development (hot-reload API only — run 'make frontend-dev' in a second terminal)
api-dev:
	$(UVICORN) api.main:app --reload --app-dir .

## Development (hot-reload frontend — run alongside 'make api-dev')
frontend-dev:
	cd frontend && npm run dev

# ── Diagnostics ──────────────────────────────────────────────────────────────

## Check which pipeline stages are available (imports + data files)
check:
	@$(PYTHON) - <<'EOF'
import sys
GREEN = '\033[0;32m'; YELLOW = '\033[1;33m'; RED = '\033[0;31m'; NC = '\033[0m'
from pathlib import Path

def chk_import(name):
    try: __import__(name); return True
    except ImportError: return False

def chk_file(path):
    return Path(path).exists()

rows = [
    ("Stage 1  — Document ingestion",             chk_import("pdfplumber"),                 "pip install pdfplumber"),
    ("Stage 2  — Regex IoC extraction",           chk_import("iocextract"),                 "pip install iocextract"),
    ("Stage 2b — Gazetteer NER",                  chk_file("pipeline/data/gazetteer.json"), "make mitre"),
    ("Stage 2c — Semantic TTP detection",         chk_import("sentence_transformers"),      "pip install sentence-transformers"),
    ("Stage 2c — Embedding cache",                chk_file("pipeline/data/mitre_embeddings.npy"), "make build-indexes"),
    ("Stage 2d — CyNER NER",                      chk_import("transformers"),               "pip install transformers"),
    ("Stage 3  — LLM enrichment",                 chk_import("anthropic") or chk_import("openai"), "pip install anthropic"),
    ("Stage 3c — MITRE TTP normalization",        chk_file("pipeline/data/mitre_index.json"), "make mitre"),
    ("Stage 4  — STIX bundle generation",         chk_import("stix2"),                      "pip install stix2"),
    ("Stage 5  — STIX validation",                chk_import("stix2validator"),             "pip install stix2-validator"),
    ("Web API  — FastAPI backend",                chk_import("fastapi"),                    "pip install fastapi"),
]

all_ok = True
for label, ok, fix in rows:
    if ok:
        print(f"  {GREEN}✔{NC}  {label}")
    else:
        print(f"  {YELLOW}–{NC}  {label}   →  {fix}")
        all_ok = False

print()
if all_ok:
    print(f"  {GREEN}All pipeline stages available.{NC}")
else:
    print(f"  {YELLOW}Some stages need additional setup (see above).{NC}")
EOF

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
