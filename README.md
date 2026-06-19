# cti-to-stix

Converts unstructured CTI reports (PDF, DOCX, HTML, TXT, MD) into valid **STIX 2.1 bundles** consumable by OpenCTI, MISP, and SIEMs.

The pipeline combines **deterministic IoC extraction** (regex + multi-layer NER) with **LLM semantic enrichment** (TTPs, relationships, malware attribution), a **post-LLM hallucination filter**, **self-verification of relationship claims**, optional **cross-model consensus**, NATO-style **evidence grading** of every relationship, and **offline MITRE ATT&CK normalisation**. Every bundle carries **STIX provenance markings** — a TLP (and optional PAP) marking plus an authoring identity (`created_by_ref`). The LLM stage is optional — the pipeline produces valid STIX even without an API key.

It also maps each report's ATT&CK techniques to a **detection-coverage matrix** against local **Sigma** rule corpora (public and private), all managed from an in-app **Settings** panel.

Two modes are available:

- **CLI** — `python main.py report.pdf` — for scripting and batch processing
- **Web UI** — React + FastAPI — for interactive review, relationship editing, STIX graph visualisation (official OASIS icons), the **detection-coverage matrix**, and **corpus settings**

---

## Quick start — CLI

```bash
# 1. Clone and enter the project
git clone <repo-url> && cd cti-to-stix

# 2. Full setup (venv, Python deps, MITRE data, Node build)
bash setup.sh

# 3. Activate the venv
source .venv/bin/activate

# 4. Add your LLM API key
cp .env.example .env
nano .env   # set ANTHROPIC_API_KEY=sk-ant-...

# 5. Process a report
python main.py input/your_report.pdf
# → output/your_report_bundle.json
```

Supported input formats: `.pdf` `.docx` `.html` `.htm` `.txt` `.md`

---

## Quick start — Web UI

```bash
# After completing CLI quick start:

# Start the server (API + pre-built frontend on one port)
uvicorn api.main:app --reload --app-dir .
# → http://localhost:8000
```

> **Development mode** (live reload on both sides):
> ```bash
> # Terminal 1 — FastAPI backend
> uvicorn api.main:app --reload --app-dir .
>
> # Terminal 2 — Vite frontend with HMR
> cd frontend && npm run dev
> # UI → http://localhost:5173
> ```

---

## Pipeline

```
┌──────────────────────────────────────────────────────────────────────┐
│  Stage 1 — INGESTION                                    (offline ✅)  │
│  PDF / DOCX / HTML / TXT / MD → normalised text + chunks            │
│  • Text PDF    : markitdown (structure-preserving) → pdfplumber      │
│  • Scanned PDF : auto-detected → OCR via Tesseract / pdf2image       │
│  • Defanging   : hxxps://, [.], (.), [at], [@] → live form          │
│  • Chunking    : paragraph-aware + 400-char sliding-window overlap   │
│  • Adaptive    : larger chunks for large docs (3 000–5 000 chars)    │
└─────────────────────────────┬────────────────────────────────────────┘
                              │
┌─────────────────────────────▼────────────────────────────────────────┐
│  Stage 2 — REGEX IOC EXTRACTION                         (offline ✅)  │
│  IPv4/v6, domains, URLs, emails, MAC, ASN, file paths               │
│  Registry keys, mutexes, MD5/SHA-1/SHA-256                          │
│  CVE IDs, raw MITRE ATT&CK technique IDs (T1234 / T1234.001)        │
└─────────────────────────────┬────────────────────────────────────────┘
                              │
┌─────────────────────────────▼────────────────────────────────────────┐
│  Stage 2b — GAZETTEER NER                               (offline ✅)  │
│  Aho-Corasick scan for 1 792 known malware families, offensive tools │
│  and APT group names (from MITRE ATT&CK Enterprise + Mobile + ICS)  │
│  • Longest-match-wins, word-boundary checked                        │
│  • Confidence: 0.92 canonical / 0.88 alias                          │
└─────────────────────────────┬────────────────────────────────────────┘
                              │
┌─────────────────────────────▼────────────────────────────────────────┐
│  Stage 2c — SEMANTIC TTP DETECTION                      (offline ✅)  │
│  Sentence-transformer cosine-similarity against 1 531 pre-embedded  │
│  MITRE technique descriptions (local .npy cache)                    │
│  • Default model: all-MiniLM-L6-v2 (80 MB)                         │
│  • Upgrade: ehsanaghaei/SecureBERT-Plus (+8-12% F1 on CTI text)     │
│  • Confidence tiers: ≥ 0.62 high / 0.48–0.61 medium                │
└─────────────────────────────┬────────────────────────────────────────┘
                              │
┌─────────────────────────────▼────────────────────────────────────────┐
│  Stage 2d — CyNER  (disabled by default — model removed from HF)    │
│  XLM-RoBERTa fine-tuned on cybersecurity NER corpora                │
│  Detects: MalwareFamily, Organization (threat actors)               │
│  Enable: CYNER_ENABLED=true (auto-falls back to Stage 2e)           │
└─────────────────────────────┬────────────────────────────────────────┘
                              │
┌─────────────────────────────▼────────────────────────────────────────┐
│  Stage 2e — GLiNER ZERO-SHOT NER                       (offline ✅)  │
│  Zero-shot NER with natural-language label descriptions              │
│  Detects entity types the gazetteer and CyNER cannot:               │
│    targeted sectors, campaign names, attack infrastructure,          │
│    novel actors & malware not yet in MITRE ATT&CK                   │
│  Default model: urchade/gliner_large-v2.1 (~800 MB)                 │
│  Configurable via GLINER_MODEL in .env                              │
└─────────────────────────────┬────────────────────────────────────────┘
                              │
┌─────────────────────────────▼────────────────────────────────────────┐
│  Stage 3 — LLM ENRICHMENT              (requires API key)            │
│  Input : chunk + pre-detected IoCs + gazetteer/NER context          │
│  Output: threat actors, malware families, tools, TTPs,              │
│          relationships (+ evidence quote), IoC→malware links,       │
│          targeted sectors/countries, course of action               │
│  • Parallel processing (configurable via LLM_PARALLELISM)           │
│  • Crash-resume: checkpoint saved every N chunks                     │
│  • Providers: Anthropic Claude | Mistral AI | Ollama                │
└─────────────────────────────┬────────────────────────────────────────┘
                              │
┌─────────────────────────────▼────────────────────────────────────────┐
│  Stage 3b — HALLUCINATION FILTER                        (offline ✅)  │
│  Verifies each LLM-returned name against source chunk text           │
│  via fuzzy sliding-window matching (rapidfuzz):                     │
│  • ≤ 5 chars (FIN7, APT1)   : 92% similarity threshold             │
│  • 6–9 chars (LummaC2)      : 80% similarity threshold             │
│  • ≥ 10 chars (Cobalt Strike): 75% similarity threshold            │
│  Campaign names: word-level fallback to avoid over-filtering        │
│  Dropped names are logged. Improves precision ~8–15%.               │
└─────────────────────────────┬────────────────────────────────────────┘
                              │
┌─────────────────────────────▼────────────────────────────────────────┐
│  Stage 3c — MITRE ATT&CK NORMALISATION                 (offline ✅)  │
│  Fuzzy-matches extracted TTPs against the full ATT&CK corpus        │
│  (Enterprise + Mobile + ICS + CAPEC, compact local JSON index)      │
│  • Score ≥ 85 : canonical name + correct MITRE ID                  │
│  • Score 70–84: keep LLM phrasing, override ID                      │
│  • Score < 70 : pass through unchanged                              │
│  Eliminates ~40% of wrong or invented MITRE IDs                     │
└─────────────────────────────┬────────────────────────────────────────┘
                              │
┌─────────────────────────────▼────────────────────────────────────────┐
│  Stage 3d — RELATIONSHIP SELF-VERIFICATION              (optional)   │
│  Second LLM call: "quote the exact sentence supporting this claim"  │
│  Unsupported relationships are removed.                             │
│  Effect: hallucination rate 27% → 8% (aCTIon paper, NEC Labs 2023) │
│  Cost: ~1.4× total LLM calls (only chunks with ≥ 1 relationship)   │
│  Enable: ENABLE_STIX_VERIFICATION=true in .env                      │
└─────────────────────────────┬────────────────────────────────────────┘
                              │
┌─────────────────────────────▼────────────────────────────────────────┐
│  Stage 4 — STIX 2.1 MAPPING                            (offline ✅)  │
│  IoC → SCO  (IPv4Address, DomainName, File, URL, Email, MACAddr…)  │
│  Malware / Actor / Tool / TTP / CVE / Campaign / Infra → SDO        │
│  Location → SDO (targeted country, ISO 3166-1 lookup, 80+ nations)  │
│  Identity → SDO (targeted sector, identity_class=class)             │
│  CourseOfAction → SDO (recommended remediations)                    │
│  All accepted IoCs → Indicator SDO (STIX pattern)                  │
│  IoC linked to malware → indicates SRO                              │
│  Threat actor → targets → Location / Identity SROs                 │
│  Semantic relations → Relationship SRO (deduplicated, spec-valid)   │
└─────────────────────────────┬────────────────────────────────────────┘
                              │
┌─────────────────────────────▼────────────────────────────────────────┐
│  Stage 5 — VALIDATION & EXPORT                         (offline ✅)  │
│  stix2 library validates every object at construction time           │
│  stix2-validator JSON-schema check (when schemas installed)          │
│  Valid bundle → output/{report}_bundle.json                         │
│  Invalid bundle → output/{report}_bundle_invalid.json (for debug)   │
└──────────────────────────────────────────────────────────────────────┘

On Finalize (web UI):
  + Report Lexicon Re-scan: accepted named entities used as a per-report
    domain lexicon to find additional occurrences missed by NER/LLM.
    Source tagged "report_lexicon". Zero ML cost, pure string matching.
```

---

## Usage

### CLI — single file
```bash
python main.py input/report.pdf
python main.py input/report.pdf --output output/apt29.json
```

### CLI — batch folder
```bash
python main.py --input-dir input/
python main.py --input-dir input/ --output-dir output/
```

### Run tests
```bash
pytest tests/ -v               # all tests
pytest tests/ -v -k "not llm"  # skip LLM tests (no key needed)
```

### make shortcuts

A `Makefile` wraps the most common workflows. Requires `make` (standard on Linux/macOS/WSL).

| Command | Description |
|---|---|
| `make setup` | Full first-time setup (runs `setup.sh`) |
| `make install` | Install / update Python packages only |
| `make install-api` | Install / update API packages only (`requirements-api.txt`) |
| `make download-mitre` | Download MITRE bundle files only (no index build) |
| `make mitre` | Download MITRE bundle files + build all indexes |
| `make build-indexes` | Build indexes from already-downloaded bundle files |
| `make model` | Download spaCy `en_core_web_sm` model |
| `make frontend-install` | `npm install` only (no build) |
| `make frontend-build` | Build frontend static assets only |
| `make test` | Run all tests |
| `make test-fast` | Run tests without LLM calls (no API key needed) |
| `make run` | Run pipeline on `tests/fixtures/sample_report.txt` |
| `make run-dir` | Run pipeline on every file in `input/` |
| `make api` | Build frontend, then start API (production) |
| `make api-dev` | Start API with hot-reload (dev backend) |
| `make frontend-dev` | Start Vite dev server with HMR (dev frontend) |
| `make check` | Diagnostic: list which pipeline stages are available |
| `make audit` | Scan Python + npm deps for known CVEs (`pip-audit` + `npm audit`) |
| `make lock` | Freeze exact installed versions → `requirements.lock.txt` |
| `make update-deps` | Upgrade Python packages, run tests, re-lock |
| `make npm-outdated` | Show which npm packages have newer versions available |
| `make npm-update` | Upgrade npm packages within semver ranges, verify TypeScript |
| `make clean` | Remove generated bundle JSONs and `__pycache__` |
| `make clean-venv` | Remove `.venv` for a full reinstall |

---

## Web UI

### Workflow

```
Upload (drag-and-drop or file picker)
  │
  ▼
Processing  ─── Real-time 5-stage progress bar (SSE)
  │               Stage 1: Ingestion   → chars + chunks
  │               Stage 2: Extraction  → IoCs + NER counts
  │               Stage 3: LLM         → chunk N/total (live)
  │               Stage 4: STIX mapping
  │               Stage 5: Validation
  ▼
For Review  ──►  Reviewing  ──►  Completed
  (Kanban)       (Review page)   (Graph + Download)
```

### Review page

Three view modes toggled at the top of the document pane:

| Mode | Content |
|---|---|
| **Text** | Annotated source text — entity occurrences highlighted by type, click to focus in marginalia, keyboard shortcuts |
| **Preview** | Rendered markdown — VS Code-like typography (headings, tables, code blocks, task lists). Works on all file types; most useful for `.md` reports |
| **Source** | Original file — inline PDF iframe or download link for other formats |

**Entity interaction:**
- Entities highlighted inline with type-colour coding
- Click a mark in the text → scroll + focus in the marginalia panel
- Click a card in the marginalia → scroll + highlight in the text
- Entities not found verbatim in text (e.g. LLM-paraphrased campaign names) → brief "not found" hint displayed

**Keyboard shortcuts:**

| Key | Action |
|---|---|
| `J` / `↓` | Next pending entity |
| `K` / `↑` | Previous pending entity |
| `A` | Accept focused entity |
| `R` | Reject focused entity |
| `U` | Reset to pending |
| `G` | Open STIX graph |
| `F` | Finalize bundle |
| `?` | Show shortcut help |

**Entity states:**
- **Pending** (default) — included in bundle
- **Accepted** ✓ — explicitly confirmed, included
- **Rejected** ✗ — excluded from bundle

**Auto-accept:** Entities with confidence ≥ 90% are auto-accepted on load. A banner shows the count with an Undo option.

**Drag-to-relate:** Drag from one entity mark to another → opens relationship creator pre-filled with source and target.

**Shift-click:** Shift-click two entity marks → opens relationship creator.

**Text selection:** Select text spanning two entities → opens relationship creator with the selected text as evidence.

### Graph page

Custom **d3-force SVG graph** (not the OASIS stix-visualization iframe):

| Feature | Details |
|---|---|
| **Node icons** | Official OASIS STIX 2.1 icons (White/normal/SVG) for all SDO types; lucide-react stroke paths for SCO types (IPv4, Domain, URL, …) |
| **Layout modes** | Force (physics simulation) · Hierarchical (tier-based) · Radial (BFS from root) |
| **Type legend** | Click to toggle visibility · Double-click to solo a type |
| **Node search** | Search by name or type, jump-animate to result |
| **Relationship editor** | Accept / Reject / Reset / Delete relationships in the side panel; Add new relationships with evidence text |
| **Labels** | Toggle all labels; strategic nodes (tier 0–1) always show labels |
| **Fit button** | Animate to fit all nodes in viewport |
| **Download** | Download STIX bundle directly from the graph page |

### Coverage page

Per-report **detection-coverage matrix** (`/coverage/:jobId`). The report's
extracted ATT&CK techniques are laid out in ATT&CK-tactic columns and coloured by
a **readiness score** (not lab validation):

| Score | Meaning |
|---|---|
| 3 — Corroborated | a rule exists in **≥ 2** corpora |
| 2 — Covered | a rule exists in **1** corpus |
| 1 — Telemetry only | ATT&CK data-source mapping, no rule yet |
| 0 — No coverage | technique extracted, no rule |

Cells show the technique, rule count, and contributing corpora. A banner makes
the "readiness ≠ validation" distinction explicit.

### Settings page

Manage **detection-rule corpora** (`/settings`): list configured Sigma repos with
live rule counts, add a repo (written to the gitignored local overlay), remove /
disable one, and **Rebuild index** to re-ingest the local clones. See
[Detection coverage](#detection-coverage-sigma).

---

## STIX objects produced

| Source | STIX object |
|---|---|
| IPv4 / IPv6 | `ipv4-addr` / `ipv6-addr` SCO |
| Domain | `domain-name` SCO |
| URL | `url` SCO |
| Email | `email-addr` SCO |
| File hash (MD5 / SHA-1 / SHA-256) | `file` SCO |
| MAC address | `mac-addr` SCO |
| ASN | `autonomous-system` SCO |
| File path (Windows/Unix) | `file` SCO |
| Registry key | `windows-registry-key` SCO |
| Mutex | `mutex` SCO |
| User account | `user-account` SCO |
| CVE | `vulnerability` SDO |
| MITRE ATT&CK technique / tactic | `attack-pattern` SDO + external reference |
| Malware family | `malware` SDO (`is_family: true`) |
| Threat actor | `threat-actor` SDO |
| Offensive tool | `tool` SDO |
| Campaign | `campaign` SDO |
| Intrusion set | `intrusion-set` SDO |
| Targeted country | `location` SDO (ISO 3166-1, 80+ countries) |
| Targeted sector | `identity` SDO (`identity_class: class`) |
| Infrastructure | `infrastructure` SDO |
| Remediation step | `course-of-action` SDO |
| Any accepted IoC | `indicator` SDO (STIX pattern) + `based-on` SRO |
| IoC linked to malware | extra `indicates` SRO Indicator → Malware |
| Threat actor → country / sector | `targets` SRO |
| Semantic relationship | `relationship` SRO (confidence score) |
| Relationship evidence grade | `x_evidence_label` custom property on each `relationship` (`observed` / `reported` / `assessed` / `inferred` / `gap`) |
| Sharing markings | TLP `marking-definition` (+ optional PAP statement marking) referenced by `object_marking_refs` on every object |
| Pipeline authorship | one authoring `identity` SDO; `created_by_ref` on every SDO/SRO (the pipeline, **not** the threat actor) |
| Report wrapper | `report` SDO |

---

## Detection coverage (Sigma)

Each report's extracted ATT&CK techniques are scored against local **Sigma** rule
corpora — a mix of **public** repos (committed, reproducible) and **private**
repos (local overlay). This is detection *readiness*, not lab validation.

### Configure corpora — two-tier registry

| File | Tracked | Holds |
|---|---|---|
| `detection_corpora.yaml` | committed | public corpora (ships with SigmaHQ) |
| `detection_corpora.local.yaml` | gitignored | private corpora + local overrides |

The overlay is merged over the committed file (override by `name`, append new).
Manage both from the **Settings** page, or copy `detection_corpora.local.yaml.example`
and edit the YAML directly.

### Fetch + build

```bash
python scripts/sync_corpora.py          # clone/pull each repo (public: no auth; private: SSH agent)
python scripts/build_detection_index.py # parse local clones → detection-rule store (in cti_stix.db)
```

Then open `/coverage/:jobId` for any report. The **Rebuild index** button on the
Settings page re-runs the build step from already-cloned repos.

**Corroboration is fork-safe:** rules are deduplicated by their Sigma `id` across
corpora, so the same rule mirrored in two repos counts once (score 2), while two
independent rules for a technique corroborate it (score 3).

Walkthrough: [`docs/detection-coverage.md`](docs/detection-coverage.md). Design:
ADR [0006](docs/adr/0006-multi-corpus-detection-ingestion.md) /
[0007](docs/adr/0007-in-app-configuration-panel.md) /
[0008](docs/adr/0008-detection-coverage-matrix.md).

---

## Configuration

All configuration lives in `.env`. Copy `.env.example` to get started:

```bash
cp .env.example .env
```

### LLM provider

Set `LLM_PROVIDER` to choose your backend.

#### Anthropic (default)
```env
LLM_PROVIDER=anthropic
ANTHROPIC_API_KEY=sk-ant-xxxxxxx
ANTHROPIC_MODEL=claude-sonnet-4-6
```

#### Mistral AI
```env
LLM_PROVIDER=mistral
MISTRAL_API_KEY=xxxxxxxxxxxxxxxx
MISTRAL_MODEL=mistral-small-latest
```

#### Ollama (local, free)
```env
LLM_PROVIDER=ollama
OLLAMA_BASE_URL=http://localhost:11434
OLLAMA_MODEL=mistral
```
Pull a model first: `ollama pull mistral`. Models smaller than ~13B may produce malformed JSON.

#### Running without an LLM
Leave `ANTHROPIC_API_KEY` unset. Stage 3 is skipped. The pipeline still produces a valid STIX bundle from Stages 1–2b–2c–2e results.

### NLP stages

```env
# Stage 2c — Semantic TTP embedding model
# Default: all-MiniLM-L6-v2 (80 MB, fast)
# Upgrade: ehsanaghaei/SecureBERT-Plus (500 MB, +8-12% F1 on CTI text)
# After changing: python scripts/build_indexes.py --only embeddings
TTP_EMBEDDING_MODEL=all-MiniLM-L6-v2

# Stage 2d — CyNER (disabled — model removed from HuggingFace)
CYNER_ENABLED=false

# Stage 2e — GLiNER zero-shot NER
# urchade/gliner_large-v2.1  (recommended, best accuracy, ~800 MB)
# urchade/gliner_medium-v2.1 (good accuracy/speed balance, ~300 MB)
# urchade/gliner_small-v2.1  (fastest, lower recall, ~120 MB)
GLINER_MODEL=urchade/gliner_large-v2.1
GLINER_THRESHOLD=0.40
GLINER_ENABLED=true
```

### Advanced

```env
# Stage 3 — Parallelism (LLM chunks processed concurrently)
LLM_PARALLELISM=3
# Stage 3 — Checkpoint frequency (save every N chunk completions)
CHECKPOINT_EVERY=5
# Stage 3 — Per-request timeout (seconds)
LLM_TIMEOUT=120

# Stage 3d — Self-verification of relationships
# Adds ~1.4× LLM calls; reduces relationship hallucination 27% → 8%
ENABLE_STIX_VERIFICATION=false
STIX_VERIFY_MIN_RELS=1

# Stage 3e — Cross-model consensus (anti-hallucination)
# Re-runs relationship-bearing chunks through a SECOND provider; agreement
# boosts confidence, single-model claims are penalised and can't auto-promote.
# CONSENSUS_PROVIDER must differ from LLM_PROVIDER and have its key set.
ENABLE_CONSENSUS=false
CONSENSUS_PROVIDER=mistral

# Stage 4 — STIX provenance & sharing metadata
# Every object is stamped with a TLP marking (object_marking_refs) and a
# created_by_ref pointing at an authoring Identity (the pipeline, not the actor).
STIX_TLP=clear               # clear | green | amber | red
STIX_AUTHOR_NAME=CTIParsor

# HuggingFace token (removes rate limits on model downloads)
HF_TOKEN=
```

---

## MITRE ATT&CK data

Stages 2b, 2c, and 3c use pre-built local indexes in `pipeline/data/`.

### Build the indexes

```bash
# Download MITRE bundle files first (done automatically by setup.sh)
python scripts/build_indexes.py

# Or build only specific indexes
python scripts/build_indexes.py --only mitre      # mitre_index.json
python scripts/build_indexes.py --only gazetteer  # gazetteer.json
python scripts/build_indexes.py --only embeddings # mitre_embeddings.npy
```

The script auto-discovers bundle files in `data/`, `~/Downloads/`, and `~/Documents/`. Accepts `--enterprise`, `--mobile`, `--ics`, `--capec` flags for explicit paths.

| File | Stage | Size |
|---|---|---|
| `pipeline/data/mitre_index.json` | 3c normalisation | ~430 KB |
| `pipeline/data/gazetteer.json` | 2b gazetteer NER | ~194 KB |
| `pipeline/data/mitre_embeddings.npy` | 2c semantic TTP | ~2.3 MB |
| `pipeline/data/mitre_embeddings_meta.json` | 2c semantic TTP | ~60 KB |

These files are not gitignored — commit them to your repo to avoid a per-clone rebuild.

---

## Extraction quality layers

### 1. Multi-layer NER (Stages 2b–2e)

Each NER stage adds a different capability:

| Stage | Method | Entities found |
|---|---|---|
| 2 | Regex | IoCs (IPs, hashes, domains, CVEs, paths…) |
| 2b | Aho-Corasick gazetteer | Known malware/tools/APT groups |
| 2c | Semantic embeddings | MITRE techniques by meaning, not name |
| 2d | CyNER (optional) | Cybersecurity NER (if model available) |
| 2e | GLiNER zero-shot | Sectors, campaigns, infrastructure, novel actors |

### 2. Sliding-window chunk overlap (Stage 1)

```
Chunk N:   [...──────── entity ─────]
Chunk N+1:       [──── entity ─────────...]
                ↑ 400-char overlap
```

Named entities at chunk boundaries appear in both adjacent chunks. De-duplicated at merge. Estimated: +5–12% recall on long documents.

### 3. Hallucination filter (Stage 3b)

After every LLM call, each returned name is fuzzy-matched against the source chunk text. Names below the length-adjusted threshold are dropped and logged.

| Name length | Strategy | Threshold |
|---|---|---|
| ≤ 5 chars | Exact + fuzzy | 92% |
| 6–9 chars | Exact + fuzzy | 80% |
| ≥ 10 chars | Exact + fuzzy | 75% |
| Campaign names | Word-level keyword fallback | — |

### 4. MITRE normalisation (Stage 3c)

Fuzzy-matched against the full ATT&CK corpus. Eliminates ~40% of wrong or invented MITRE IDs.

### 5. Relationship self-verification (Stage 3d)

Second LLM call per chunk quotes the exact supporting sentence for every relationship. Unsupported relationships are dropped. Reduces hallucination rate from ~27% to ~8% (aCTIon paper benchmark).

### 6. Report lexicon re-scan (Finalize)

On **Finalize**, accepted named entities form a per-report domain lexicon. The full text is re-scanned with word-boundary string matching to find additional occurrences that NER or the LLM missed. New occurrences are inserted with `source="report_lexicon"` and `accepted=True`.

---

## Project structure

```
cti-to-stix/
│
├── main.py                        # CLI entry point
│
├── pipeline/
│   ├── stage1_ingestion.py        # Parsing, defanging, chunking + overlap
│   ├── stage2_extraction.py       # Regex IoC extraction + spaCy fallback
│   ├── stage2b_gazetteer.py       # Aho-Corasick gazetteer NER (1 792 entities)
│   ├── stage2c_ttp_semantic.py    # Sentence-transformer TTP detection
│   ├── stage2d_cyner.py           # CyNER (optional, disabled by default)
│   ├── stage2e_gliner.py          # GLiNER / NuNER zero-shot NER
│   ├── stage3_llm.py              # LLM enrichment, parallel + checkpoint
│   ├── stage3b_validate.py        # Post-LLM hallucination filter
│   ├── stage3c_mitre.py           # MITRE ATT&CK TTP normalisation
│   ├── stage3d_verify.py          # Relationship self-verification
│   ├── stage3e_consensus.py       # Cross-model consensus (opt-in)
│   ├── stage4_stix_mapping.py     # STIX 2.1 mapping + TLP/PAP + authoring identity
│   ├── stage5_validation.py       # Bundle validation + export
│   ├── mitre_db.py                # Lazy-loaded MITRE index (techniques + tactics)
│   ├── detection/                 # Detection-rule ingestion + coverage (ADR-0006)
│   │   ├── base.py                # RuleCorpusAdapter (pluggable format seam)
│   │   ├── sigma.py               # SigmaAdapter (YAML → DetectionRule)
│   │   ├── registry.py            # Two-tier corpus registry + overlay writes
│   │   ├── store.py               # detection_rules / rule_techniques persistence
│   │   ├── coverage.py            # Technique → 0–3 readiness scoring
│   │   └── builder.py             # Rebuild the rule store from local clones
│   └── data/
│       ├── mitre_index.json       # Compact ATT&CK index (built by build_indexes.py)
│       ├── gazetteer.json         # Named-entity dictionary
│       ├── mitre_embeddings.npy   # Pre-computed TTP embeddings
│       └── mitre_embeddings_meta.json
│
├── scripts/
│   ├── build_indexes.py           # Build all pipeline/data/ indexes
│   ├── download_attack.py         # Download enterprise-attack.json
│   ├── sync_corpora.py            # Clone/pull Sigma corpora (ambient git auth)
│   └── build_detection_index.py   # Parse clones → detection-rule store
│
├── models/
│   ├── schemas.py                 # Pydantic: RawEntity, EntityType, EvidenceLabel
│   └── detection.py               # Pydantic: DetectionRule, Severity
│
├── api/
│   ├── main.py                    # FastAPI app, CORS, SPA static serving
│   ├── db.py                      # SQLite (WAL, thread-local connections)
│   ├── worker.py                  # Background pipeline + SSE emitter
│   │                              #   └─ _lexicon_rescan() on Finalize
│   └── routes/
│       ├── upload.py              # POST /api/upload (50 MB limit, streamed)
│       ├── jobs.py                # CRUD /api/jobs + finalize + source + bundle
│       ├── entities.py            # CRUD /api/jobs/{id}/entities
│       ├── relationships.py       # CRUD /api/jobs/{id}/relationships
│       ├── progress.py            # GET /api/jobs/{id}/progress (SSE)
│       ├── coverage.py            # GET /api/jobs/{id}/coverage + detection-corpora
│       └── settings.py            # Corpora management (ADR-0007)
│
├── frontend/                      # React 18 + TypeScript + Vite 6
│   ├── src/
│   │   ├── pages/
│   │   │   ├── Dashboard.tsx      # Kanban, drag-and-drop upload, progress modal
│   │   │   ├── Review.tsx         # Text / Preview / Source view + marginalia
│   │   │   ├── Graph.tsx          # d3-force graph + relationship editor
│   │   │   ├── Coverage.tsx       # Detection-coverage matrix
│   │   │   └── Settings.tsx       # Corpus management panel
│   │   ├── components/
│   │   │   ├── MarkdownPreview.tsx # VS Code-like .md renderer (react-markdown)
│   │   │   ├── ProgressModal.tsx   # 5-stage SSE progress display
│   │   │   ├── EntityPopover.tsx   # Entity type picker
│   │   │   └── review/
│   │   │       ├── DocumentReader.tsx  # Annotated text with entity marks
│   │   │       ├── Marginalia.tsx      # Sidebar entity cards
│   │   │       ├── RelationshipRail.tsx# Sticky relationships panel
│   │   │       └── …
│   │   ├── components/graph/
│   │   │   ├── GraphCanvas.tsx    # d3-force SVG renderer, STIX icons
│   │   │   └── graphLayout.ts     # Tier map, radii, static layouts, icon paths
│   │   ├── hooks/
│   │   │   ├── useSSE.ts          # EventSource (5-retry on transient error)
│   │   │   ├── useMitreSearch.ts  # Client-side ATT&CK search
│   │   │   └── useCoverage.ts     # Coverage data hook (view ↔ source seam)
│   │   ├── api/client.ts          # Typed fetch wrappers
│   │   ├── context/ThemeContext.tsx # 5 themes × 7 accent palettes
│   │   └── types/index.ts         # Shared TS types
│   └── public/
│       ├── stix-icons/            # 27 official OASIS STIX 2.1 White SVG icons
│       └── mitre_index.json       # ATT&CK index served to the frontend
│
├── tests/
│   ├── test_stage1.py             # Ingestion, chunking, overlap, defanging
│   ├── test_stage2.py             # IoC extraction, refanging, deduplication
│   ├── test_stage4.py             # STIX mapping
│   └── fixtures/sample_report.txt
│
├── input/                         # Drop CTI reports here (gitignored)
├── output/                        # Generated STIX bundles (gitignored)
├── uploads/                       # Web UI uploads (gitignored)
├── cti_stix.db                    # SQLite database (gitignored)
│
├── detection_corpora.yaml         # Public Sigma corpus registry (committed)
├── detection_corpora.local.yaml.example  # Private corpus overlay template
├── docs/adr/                      # Architecture Decision Records (see docs/adr/README.md)
├── TESTING.md                     # Test strategy
├── .env                           # Secrets (gitignored)
├── .env.example                   # Configuration template
├── requirements.txt               # Pipeline dependencies
├── requirements-api.txt           # API server dependencies
└── setup.sh                       # One-shot setup for Linux / WSL
```

---

## REST API

Interactive docs at `http://localhost:8000/docs`.

### Jobs

| Method | Path | Description |
|---|---|---|
| `POST` | `/api/upload` | Upload a file (multipart `file=`). Returns `{ job_id }`. Starts pipeline. |
| `GET` | `/api/jobs` | List all jobs |
| `GET` | `/api/jobs/{id}` | Get a single job (includes entity/relationship counts) |
| `PATCH` | `/api/jobs/{id}` | Update status |
| `DELETE` | `/api/jobs/{id}` | Delete job, all DB rows, and all associated files |
| `POST` | `/api/jobs/{id}/finalize` | Re-run lexicon re-scan + Stages 4–5; sets status `completed` |
| `GET` | `/api/jobs/{id}/bundle` | Download the STIX 2.1 bundle JSON |
| `GET` | `/api/jobs/{id}/source` | Stream the original uploaded file |

Job status lifecycle: `uploaded` → `processing` → `for_review` → `reviewing` → `completed` / `failed`

### Entities

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/jobs/{id}/entities` | List all entities |
| `POST` | `/api/jobs/{id}/entities` | Create an entity manually |
| `PATCH` | `/api/jobs/{id}/entities/{eid}` | Update (`accepted`, `entity_type`, `value`, `mitre_id`) |
| `DELETE` | `/api/jobs/{id}/entities/{eid}` | Remove |
| `POST` | `/api/jobs/{id}/entities/accept-pending` | Accept all NULL-state entities in one query |
| `POST` | `/api/jobs/{id}/entities/bulk` | Bulk accept / reject / reset entities by type (see below) |

#### Bulk entity update

```json
{ "entity_type": "malware", "action": "accept", "scope": "pending" }
```

- `action`: `"accept"` · `"reject"` · `"reset"` (back to pending)
- `scope`: `"pending"` (default, only NULL-state rows) · `"all"` (every row of that type)
- Returns `{ "updated": N, "entity_type", "action", "scope" }`

### Relationships

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/jobs/{id}/relationships` | List all relationships |
| `POST` | `/api/jobs/{id}/relationships` | Create a relationship |
| `PATCH` | `/api/jobs/{id}/relationships/{rid}` | Update (`accepted`, `source_value`, `relationship_type`, `target_value`, `evidence_text`) |
| `DELETE` | `/api/jobs/{id}/relationships/{rid}` | Remove |
| `GET` | `/api/jobs/{id}/relationships/valid-types` | List valid STIX relationship type strings |

#### Relationship object

```json
{
  "id": "uuid",
  "job_id": "uuid",
  "source_value": "APT29",
  "relationship_type": "uses",
  "target_value": "Cobalt Strike",
  "confidence": 0.92,
  "accepted": true,
  "evidence_text": "APT29 was observed deploying Cobalt Strike Beacon…",
  "evidence_label": "observed"
}
```

Valid `relationship_type` values: `uses`, `attributed-to`, `targets`, `indicates`, `mitigates`, `remediates`, `delivers`, `drops`, `downloads`, `exploits`, `originates-from`, `compromises`, `beacons-to`, `communicates-with`, `exfiltrates-to`, `controls`, `has`, `hosts`, `owns`, `authored-by`, `impersonates`, `located-at`, `resolves-to`, `belongs-to`, `variant-of`, `duplicate-of`, `derived-from`, `related-to`.

### Relationship policy

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/relationship-policy` | Return the current policy (or factory default) |
| `PUT` | `/api/relationship-policy` | Replace the policy (full replacement) |

```json
{
  "version": 1,
  "global": "enforce",
  "rules": [
    { "src": "threat-actor", "verb": "uses", "tgt": "malware", "mode": "pin", "enabled": true }
  ]
}
```

- `global`: `"enforce"` (apply rules) · `"auto"` (ignore rules)
- `mode`: `"pin"` (lock relationship type) · `"auto"` (allow free editing)

### Progress (SSE)

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/jobs/{id}/progress` | SSE stream. Events: `connected`, `stage`, `done`. |

```
event: stage
data: {"stage":3,"label":"LLM enrichment","chunk":7,"total":22,"malware":3,"actors":2,"relationships":8}

event: done
data: {"status":"for_review"}
```

### Coverage (detection)

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/jobs/{id}/coverage` | Per-report coverage matrix: each technique's 0–3 score + contributing corpora |
| `GET` | `/api/jobs/{id}/coverage/{technique}/rules` | License-aware drill-down: which rules cover a technique |
| `GET` | `/api/detection-corpora` | Per-corpus rule counts in the store |

```json
// GET /api/jobs/{id}/coverage
{ "techniques_total": 12, "validated": false,
  "by_score": { "0": 4, "1": 0, "2": 5, "3": 3 },
  "cells": [ { "technique_id": "T1059.001", "score": 3, "corpora": ["sigmahq","team"], "rule_count": 4 } ] }
```

### Settings (corpora)

Manages the gitignored local overlay only — the committed registry is never edited by the app.

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/settings/corpora` | List configured corpora (committed + overlay) with rule counts |
| `POST` | `/api/settings/corpora` | Add a Sigma corpus to the local overlay |
| `DELETE` | `/api/settings/corpora/{name}` | Remove (or disable, if committed) a corpus |
| `POST` | `/api/settings/corpora/rebuild` | Re-ingest all enabled corpora from their local clones |

---

## Database schema

```sql
CREATE TABLE jobs (
    id              TEXT PRIMARY KEY,
    original_filename TEXT NOT NULL,
    status          TEXT NOT NULL DEFAULT 'uploaded',
    report_text     TEXT,           -- refanged extracted text (stored once)
    bundle_json     TEXT,           -- serialised STIX bundle
    llm_result_json TEXT,           -- LLM result snapshot for finalize
    tlp_level       TEXT,           -- per-job TLP marking (clear|green|amber|red)
    pap_level       TEXT,           -- per-job PAP statement marking
    created_at      TEXT NOT NULL,
    updated_at      TEXT NOT NULL
);

CREATE TABLE entities (
    id          TEXT PRIMARY KEY,
    job_id      TEXT NOT NULL,
    value       TEXT NOT NULL,
    entity_type TEXT NOT NULL,
    context     TEXT DEFAULT '',
    confidence  REAL DEFAULT 1.0,
    mitre_id    TEXT,
    accepted    INTEGER,            -- NULL=pending  1=accepted  0=rejected
    source      TEXT DEFAULT 'auto' -- ioc | gazetteer | semantic | cyner |
                                    -- gliner | llm | manual | report_lexicon
);

CREATE TABLE relationships (
    id                TEXT PRIMARY KEY,
    job_id            TEXT NOT NULL,
    source_value      TEXT NOT NULL,
    relationship_type TEXT NOT NULL,
    target_value      TEXT NOT NULL,
    confidence        REAL DEFAULT 0.8,
    accepted          INTEGER DEFAULT 1,  -- NULL=pending  1=accepted  0=rejected
    evidence_text     TEXT,               -- verbatim supporting quote
    evidence_label    TEXT DEFAULT 'reported'  -- observed|reported|assessed|inferred|gap
);

CREATE TABLE progress_events (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    job_id     TEXT NOT NULL,
    event_type TEXT NOT NULL,
    data       TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE relationship_policy (
    id          INTEGER PRIMARY KEY,  -- always 1 (singleton row)
    policy_json TEXT NOT NULL         -- serialised policy object
);

-- Detection-rule store (ADR-0006) — corpus-derived, not per-job.
-- Built by scripts/build_detection_index.py from local Sigma clones.
CREATE TABLE detection_rules (
    id           TEXT PRIMARY KEY,    -- corpus:native_key
    corpus       TEXT NOT NULL,
    native_key   TEXT NOT NULL,       -- Sigma id / content hash (cross-corpus dedup)
    format       TEXT DEFAULT 'sigma',
    title        TEXT NOT NULL,
    severity     TEXT, license TEXT, source_ref TEXT,
    content_hash TEXT, data_sources TEXT, raw TEXT
);

CREATE TABLE rule_techniques (
    rule_id      TEXT NOT NULL,
    technique_id TEXT NOT NULL,       -- ATT&CK id, indexed for coverage lookup
    PRIMARY KEY (rule_id, technique_id)
);
```

Schema migrations run automatically on startup (`ALTER TABLE` wrapped in try/except).

---

## Offline support

| Component | Offline |
|---|---|
| Stages 1, 2, 4, 5 | ✅ fully offline |
| Stage 2b — gazetteer NER | ✅ after `build_indexes.py` |
| Stage 2c — semantic TTP | ✅ after `build_indexes.py` + model download |
| Stage 2e — GLiNER | ✅ after first model download (~800 MB cached) |
| Stage 3b — hallucination filter | ✅ fully offline (rapidfuzz) |
| Stage 3c — MITRE normalisation | ✅ after `build_indexes.py` |
| Stage 3 — Anthropic / Mistral | ❌ requires internet |
| Stage 3 — Ollama | ✅ if instance is local |
| OCR (Tesseract) | ✅ local binary |
| Web UI (frontend assets) | ✅ served from local dist/ |
| Detection coverage (Sigma) | ✅ after `sync_corpora` (one-time clone) + `build_detection_index` |

---

## Dependencies

### Core pipeline (`requirements.txt`)

| Package | Purpose |
|---|---|
| `pdfplumber` | Text-layer PDF extraction + scanned PDF detection |
| `markitdown` | PDF / DOCX → structured Markdown |
| `pdf2image` + `pytesseract` | OCR for scanned PDFs |
| `python-docx` | DOCX parsing |
| `beautifulsoup4` | HTML parsing |
| `iocextract` | Regex IoC extraction with defang support |
| `sentence-transformers` | Semantic TTP embeddings (Stage 2c) |
| `transformers` | HuggingFace backbone (CyNER Stage 2d) |
| `numpy` | Embedding cache (`.npy`) |
| `gliner` | Zero-shot NER (Stage 2e) |
| `pyahocorasick` | Aho-Corasick multi-pattern scan (Stage 2b, 50× faster) |
| `rapidfuzz` | Fuzzy string matching (Stage 3b filter + Stage 3c normalisation) |
| `anthropic` | Claude API client |
| `openai` | Mistral AI / Ollama client (OpenAI-compatible) |
| `pydantic` | LLM output schema validation |
| `stix2` | STIX 2.1 object + bundle construction |
| `stix2-validator` | Bundle JSON-schema validation |
| `PyYAML` | Sigma rule parsing + the detection-corpus registry |
| `python-dotenv` | `.env` loading |
| `spacy` | Optional NER fallback (no model downloaded by default) |

### Web API (`requirements-api.txt`)

| Package | Purpose |
|---|---|
| `fastapi` | REST API framework |
| `uvicorn[standard]` | ASGI server |
| `python-multipart` | File upload (multipart/form-data) |
| `aiofiles` | Async file I/O |

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

---

## Setup script

`setup.sh` runs on Ubuntu, Debian, AlmaLinux, RHEL, Fedora, and WSL (WSL1 + WSL2):

```
[1]   System packages  — python3, tesseract-ocr, poppler-utils, build tools
[1b]  Node.js check    — prints install instructions if missing
[2]   Python venv      — creates .venv/
[3]   Python packages  — pip install requirements.txt + requirements-api.txt
[4]   MITRE data       — downloads bundle files + runs build_indexes.py
[5]   spaCy model      — optional en_core_web_sm (~12 MB)
[6]   API key          — creates .env from .env.example
      STIX icons       — checks/downloads 27 official OASIS SVG icons
      Frontend build   — npm install + npm run build
      Import check     — verifies all packages importable
```

```bash
bash setup.sh              # full setup
bash setup.sh --no-torch   # skip sentence-transformers / GLiNER (faster, minimal)
bash setup.sh --no-mitre   # skip MITRE bundle download
bash setup.sh --no-spacy   # skip spaCy model download
```

---

## Keeping dependencies current

### How the version files work

| File | What it is | When to edit |
|---|---|---|
| `requirements.txt` | **Human-managed** — lower bounds + major-version caps | When you want to allow a new major version |
| `requirements-api.txt` | Same, for API-only packages | Rarely |
| `requirements.lock.txt` | **Machine-generated** — exact pinned versions | Never by hand — run `make lock` |
| `frontend/package.json` | npm semver ranges (`^`) | When you want to allow a new major version |
| `frontend/package-lock.json` | npm lock file | Never by hand — run `npm install` |

Fresh install for production (reproducible):
```bash
pip install -r requirements.lock.txt   # exact versions, no surprises
cd frontend && npm ci                  # uses package-lock.json
```

Fresh install for development (picks up allowed updates):
```bash
pip install -r requirements.txt -r requirements-api.txt
cd frontend && npm install
```

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

---

## Extending the pipeline

### Add a new LLM provider
1. Add client init in `pipeline/stage3_llm.py` (follow the Ollama pattern)
2. Add a branch in `_call_llm()` and `_provider_ready()`
3. Add env vars to `.env.example`

### Add a new input format
1. Add `_read_xxx()` in `pipeline/stage1_ingestion.py`
2. Add the extension to the `if/elif` chain in `ingest()`
3. Add the extension to `SUPPORTED_EXTENSIONS` in `main.py`

### Add a new IoC type
1. Add the value to `EntityType` in `models/schemas.py`
2. Add a regex / extraction function in `pipeline/stage2_extraction.py`
3. Add the SCO mapping in `_entity_to_sco()` in `pipeline/stage4_stix_mapping.py`
4. Add a pattern builder in `_build_stix_pattern()`

### Tune the hallucination filter
```python
# pipeline/stage3b_validate.py
_THRESHOLD_SHORT  = 92   # ≤ 5 chars (FIN7, APT1)
_THRESHOLD_MEDIUM = 80   # 6–9 chars (LummaC2, APT29)
_THRESHOLD_LONG   = 75   # ≥ 10 chars (Cobalt Strike)
```
Lower = more permissive (hallucination risk). Higher = stricter (false-negative risk).

### Switch NER model for Stage 2e
```env
# .env — no code change required
GLINER_MODEL=urchade/gliner_large-v2.1   # default — best accuracy (~800 MB)
GLINER_MODEL=urchade/gliner_medium-v2.1  # good accuracy/speed balance (~300 MB)
GLINER_MODEL=urchade/gliner_small-v2.1   # fastest, less accurate (~120 MB)
```

### Use a domain-specific TTP embedding model
```env
# .env
TTP_EMBEDDING_MODEL=ehsanaghaei/SecureBERT-Plus
# Then rebuild the embedding cache:
python scripts/build_indexes.py --only embeddings
```
