# Dependencies

What CTIParsor depends on, how the version files fit together, and the
maintenance routine that keeps them current.

- [Packages](#packages)
- [Keeping dependencies current](#keeping-dependencies-current)

## Packages

### Core pipeline (`requirements.txt`)

| Package | Purpose |
|---|---|
| `pdfplumber` | Text-layer PDF extraction + scanned PDF detection |
| `markitdown` | PDF / DOCX → structured Markdown |
| `pdf2image` + `pytesseract` | OCR for scanned PDFs |
| `python-docx` | DOCX parsing |
| `beautifulsoup4` | HTML parsing |
| `defusedxml` | XML parsing hardened against entity-expansion attacks (DOCX internals) |
| `iocextract` | Regex IoC extraction with defang support |
| `sentence-transformers` | Semantic TTP embeddings (Stage 2c) |
| `transformers` | HuggingFace backbone (CyNER 2.0, Stage 2d) |
| `sentencepiece` | Tokenizer for CyNER 2.0's DeBERTa-v3 (Stage 2d) |
| `numpy` | Embedding cache (`.npy`) |
| `gliner` | Zero-shot NER (Stage 2e) |
| `pyahocorasick` | Aho-Corasick multi-pattern scan (Stage 2b, 50× faster) |
| `rapidfuzz` | Fuzzy string matching (Stage 3b filter + Stage 3c normalisation) |
| `anthropic` | Claude API client |
| `openai` | Client for every OpenAI-compatible provider: Gemini, Mistral AI, Ollama, vLLM, LM Studio |
| `pydantic` | LLM output schema validation |
| `stix2` | STIX 2.1 object + bundle construction |
| `stix2-validator` | Bundle JSON-schema validation |
| `jsonschema` | Not imported directly: capped below 4.25, whose extra pulls lark 1.x through `stix2-validator` and breaks `parsuricata`'s import — every Suricata rule would ship unchecked |
| `yara-python` | Compiles each YARA rule quoted in a report, as OpenCTI does on import; a rule that does not compile is left out (ADR-0067). Wheels up to CPython 3.13 |
| `pysigma`, `parsuricata` | Parse each Sigma / Suricata rule quoted in a report with the parsers OpenCTI uses (Snort: OpenCTI's own parser, copied in `pipeline/detection/opencti_snort/`); a refused rule is left out (ADR-0070) |
| `PyYAML` | Sigma rule parsing + the detection-corpus registry |
| `python-dotenv` | `.env` loading |
| `spacy` | Optional NER fallback (no model downloaded by default); listed in `requirements-optional.txt` too |
| `tenacity` | Retry with backoff on transient LLM errors |
| `pytest` | Test runner. It sits in the runtime set, so it also ships in the `app` image; the other dev tools are in `requirements-dev.txt`, installed only in the `dev` image |

### Web API (`requirements-api.txt`)

| Package | Purpose |
|---|---|
| `fastapi` | REST API framework |
| `uvicorn[standard]` | ASGI server |
| `python-multipart` | File upload (multipart/form-data) |
| `aiofiles` | Async file I/O |
| `slowapi` | Request rate limiting |
| `python-magic` | Upload content-type sniffing (libmagic) |
| `filetype` | Upload type detection fallback, pure Python |
| `psycopg` | PostgreSQL driver for both stores (ADR-0045, ADR-0053) |

### Optional (requirements-optional.txt)

| Package | Purpose |
|---|---|
| `playwright` | Headless Chromium for URL capture (ADR-0029) |
| `google-re2` | Linear-time regex engine, guards catastrophic backtracking (ADR-0049; the plain `re2` package on PyPI is abandoned and does not build on Python 3.12+) |
| `spacy` | Optional NER fallback |

Playwright and Chromium are already installed in the image, system libraries
included (`Dockerfile`) — nothing to do. The API checks for a working
Chromium install once at startup and logs a warning if it's missing, so a
misconfigured server says so in its own logs instead of waiting for the
first URL-capture request to fail; `/api/ingest/url` responds 503 until then.

### Frontend key packages

| Package | Purpose |
|---|---|
| `react` + `react-dom` | UI framework |
| `react-router-dom` | Client-side routing |
| `@tanstack/react-query` | Server state + cache invalidation |
| `d3-force` | Physics simulation for STIX graph |
| `lucide-react` | Icon library |
| `react-markdown` + `remark-gfm` | Markdown preview (VS Code-like) |
| `vite` + TypeScript | Build toolchain |

## Keeping dependencies current

### How the version files work

| File | What it is | When to edit |
|---|---|---|
| `requirements.txt` | **Human-managed** — lower bounds + major-version caps | When you want to allow a new major version |
| `requirements-api.txt` | Same, for API-only packages | Rarely |
| `requirements.lock.txt` | **Machine-generated** — exact versions of all three files above, resolved for Python 3.12 with CPU-only torch; what the image and CI install | Never by hand — run `make lock` |
| `requirements-dev.txt` | Pinned test / lint / type-check tools for CI | When you upgrade ruff, mypy or pytest-cov on purpose |
| `frontend/package.json` | npm semver ranges (`^`) | When you want to allow a new major version |
| `frontend/package-lock.json` | npm lock file | Never by hand — run `make npm-update` to update it |

Both lock files are what gets installed: the `Dockerfile` runs
`pip install -r requirements.lock.txt` and `npm ci`, and CI installs every
Python package under `-c requirements.lock.txt`, so the versions CI tested are
the versions the image ships. A rebuild never re-resolves on its own; only
`make lock` (keeps the pins that still fit the ranges) or `make update-deps`
(`--upgrade`) moves a version. The lock names the PyTorch CPU index itself,
which is what keeps the ~2.2 GB of CUDA wheels out of the image.

The lock pins versions, **not file hashes**. torch's `+cpu` wheels live on a
second index that also mirrors common packages; under `--require-hashes` pip
may pick the mirror's file for a version and reject it against PyPI's hash.
Hashing would need torch installed alone from its index first, then the rest
from PyPI only, each with its own hashed lock — not done yet.

### Quarterly maintenance workflow

```bash
# 1. Check for security vulnerabilities first
make audit

# 2. Upgrade Python packages within the capped ranges, re-run tests, re-lock
make update-deps

# 3. Review what changed
git diff requirements.lock.txt

# 4. Upgrade npm packages within package.json semver ranges
make npm-update

# 5. Commit both lock files together
git add requirements.lock.txt frontend/package-lock.json
git commit -m "chore: quarterly dependency update $(date +%Y-%m)"
```

### Bumping a capped major version

When a new major ships (e.g., `numpy 3.0`), bump the cap in `requirements.txt` **intentionally** after verifying the breaking-changes list:

```bash
# Edit requirements.txt: change numpy>=1.24.0,<3  →  numpy>=1.24.0,<4
# Then:
make update-deps   # upgrades, runs tests, re-locks
```

Four packages have explicit upper bounds today and why:

| Package | Cap | Reason |
|---|---|---|
| `numpy` | `<3` | numpy 3.x will remove more deprecated aliases (`np.bool_` etc.) |
| `openai` | `<3` | OpenAI SDK 2.x already had a breaking API rewrite from 1.x; 3.x unknown |
| `sentence-transformers` | `<6` | Each major changed `encode()` return types and model-loading API |
| `transformers` | `<6` | HuggingFace 5.x dropped several `AutoModel` keyword arguments |
