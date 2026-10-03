# Configuration

Every setting CTIParsor reads from `.env`. The [README](../README.md#configuration)
covers the minimum to get a first report through; `.env.example` carries every
variable with its default.

All configuration lives in `.env`. Copy `.env.example` to get started:

```bash
cp .env.example .env
```

Every on/off flag below reads the same vocabulary, case- and whitespace-
insensitive: `1`, `true`, `yes`, `on` enable; `0`, `false`, `no`, `off` disable.
Anything else, including an empty value, leaves the flag at its documented
default rather than being read as "on". (Each flag used to parse its own
spelling — `ENABLE_CONSENSUS=1` did *not* enable consensus, while
`ENABLE_STIX_VERIFICATION=1` did. `scripts/check_flag_equivalence.py` reports
every value whose meaning differs between the old and current readings.)

## Database — PostgreSQL, required

One store, PostgreSQL only (ADR-0045, ADR-0053 — CTIParsor no longer
supports SQLite at all). The **rule store** — the detection corpus, a
`tsvector`/GIN full-text index rebuilt by `make detection-index` — and the
**job store** — jobs, entities, relationships, progress events, the
relationship policy, figure provenance, the figure and CVE caches — are the
same PostgreSQL database:

```dotenv
DATABASE_URL=postgresql://ctiparsor@localhost:5432/ctiparsor
PGPASSWORD=...          # read by the driver; keeps the password out of the URL
```

`DATABASE_URL` is mandatory: the API/worker and `pytest` both fail fast
with a clear message if it is unset — already set for you by `compose.yaml`
for every service, `dev` included (ADR-0054). Rows are read by column name
through a small adapter (`api/db_backend.py`) that translates `?`
placeholders to `%s`, and every upsert uses the standard `ON CONFLICT`
syntax. An install still on the pre-ADR-0053 single-SQLite-file layout
moves its rows once, with both scripts (they cover different tables):

```bash
docker compose run --rm dev python scripts/migrate_jobs_to_postgres.py   # --dry-run first if you like
docker compose run --rm dev python scripts/migrate_rules_to_postgres.py  # --dry-run first if you like
```

The compose stack runs PostgreSQL for you (`docker compose up` starts a
hardened `postgres` service; set `CTI_DB_PASSWORD` in `.env`). `pg_dump` is
the backup tool for both stores now.

## LLM provider

Set `LLM_PROVIDER` to choose your backend.

### Anthropic (default)
```env
LLM_PROVIDER=anthropic
ANTHROPIC_API_KEY=sk-ant-xxxxxxx
ANTHROPIC_MODEL=claude-sonnet-4-6
```
The system prompt is sent with `cache_control` so Anthropic caches it across
chunks — it is identical on every call, which is what makes it cacheable at all.
Whether the cache actually fires is worth checking rather than assuming: the
minimum cacheable prefix is model-dependent (512–4096 tokens) and this prompt
sits at roughly 1 170, so `usage.cache_read_input_tokens` is the only proof. The
chunk text itself is never cached — it differs every call by construction.

### Google Gemini
```env
LLM_PROVIDER=gemini
GEMINI_API_KEY=xxxxxxxxxxxxxxxx
GEMINI_MODEL=gemini-2.5-pro
```

### Mistral AI
```env
LLM_PROVIDER=mistral
MISTRAL_API_KEY=xxxxxxxxxxxxxxxx
MISTRAL_MODEL=mistral-small-latest
```

### LM Studio (local)
```env
LLM_PROVIDER=lmstudio
LMSTUDIO_BASE_URL=http://localhost:1234
LMSTUDIO_MODEL=lmstudio-model
```

### vLLM (local)
```env
LLM_PROVIDER=vllm
VLLM_BASE_URL=http://localhost:8000
VLLM_MODEL=vllm-model
VLLM_ENABLE_THINKING=false
```
`VLLM_MODEL` must match the id the server lists at `/v1/models`, organisation
prefix included (e.g. `Inferact/Qwen3.8-27B-NVFP4`); a wrong name 404s and
Stage 3 comes back empty. `VLLM_ENABLE_THINKING=false` (the default) turns off
Qwen3-style thinking, which on the Stage 3 prompt used the whole output budget
without returning JSON. The same server can read figures: `VISION_PROVIDER=vllm`.

### Ollama (local, free)
```env
LLM_PROVIDER=ollama
OLLAMA_BASE_URL=http://localhost:11434
OLLAMA_MODEL=mistral
```
Pull a model first: `ollama pull mistral`. Models smaller than ~13B may produce malformed JSON.
If `OLLAMA_MODEL` is left unset the code falls back to `llama3.2`, not `mistral` — set it explicitly.

### Running without an LLM
Leave `ANTHROPIC_API_KEY` unset. Stage 3 is skipped. The pipeline still produces a valid STIX bundle from the Stage 1, 2, 2b, 2c, 2d and 2e results (every offline stage).

## NLP stages

```env
# Stage 2c — Semantic TTP embedding model
# Default: all-MiniLM-L6-v2 (80 MB, fast)
# Upgrade: ehsanaghaei/SecureBERT-Plus (500 MB, +8-12% F1 on CTI text)
# After changing: docker compose run --rm dev python scripts/build_indexes.py --only embeddings
TTP_EMBEDDING_MODEL=all-MiniLM-L6-v2

# Stage 2c — semantic precision tuning (ADR-0011 Phase A). Thresholds are
# model-specific and resolved automatically (per-model defaults → embedding
# manifest → these overrides). Set only to hand-tune; leave unset for defaults.
# TTP_HIGH_THRESHOLD=0.62     # ≥ this → high confidence (wins over the LLM)
# TTP_MEDIUM_THRESHOLD=0.48   # ≥ this → medium candidate; < this → discarded
# TTP_TOP2_MARGIN=0.05        # drop a 2nd match for the same sentence beyond this
#                             # cosine gap from the top match

# Stage 2d — CyNER 2.0 cybersecurity NER (DeBERTa-v3, F1 91.88%)
CYNER_ENABLED=true
# CYNER_MODEL=PranavaKailash/CyNER-2.0-DeBERTa-v3-base   # default; override to swap models

# Stage 2e — GLiNER zero-shot NER
# urchade/gliner_large-v2.1  (recommended, best accuracy, ~800 MB)
# urchade/gliner_medium-v2.1 (good accuracy/speed balance, ~300 MB)
# urchade/gliner_small-v2.1  (fastest, lower recall, ~120 MB)
GLINER_MODEL=urchade/gliner_large-v2.1
GLINER_THRESHOLD=0.40
GLINER_ENABLED=true

# ADR-0051 — per-(source, entity_type) cutoffs calibrated from the analysts'
# accept/reject decisions override GLINER_THRESHOLD / CyNER's 0.70 once stored
# (`docker compose run --rm dev python -m scripts.calibrate_thresholds --apply`,
# or POST /api/thresholds/recalibrate).  false ignores every stored row.
THRESHOLD_CALIBRATION_ENABLED=true
# ADR-0052 — deny / promote rows grown from the same decisions (a value the
# analysts keep rejecting is dropped at every NER stage; a name they keep
# accepting joins the gazetteer), proposed by `docker compose run --rm dev
# python -m scripts.promote_overrides` and activated by a person.  false ignores them.
ENTITY_OVERRIDES_ENABLED=true
```

## Vision (Stage 1f — figures)

Stage 1f reads the figures in a PDF and injects their transcription into
`report_text`. It is **off by default** — set a provider to turn it on.

```env
# Vision backend for Stage 1f, deliberately separate from LLM_PROVIDER:
# none       (default) Stage 1f is off; figures are not read
# anthropic  default model claude-haiku-4-5
# ollama     default model qwen3.8 — needs a model with the `vision`
#            capability; check with: curl -s $OLLAMA_BASE_URL/api/tags
# mistral    VISION_MODEL is REQUIRED — no default is assumed, because no
#            vision-capable Mistral model name was verified against a live
#            account and a guessed one fails confusingly
# vllm       default model VLLM_MODEL, on VLLM_BASE_URL — must be a multimodal
#            model; the probe checks the name is served, then sends one image
#
# The model is probed for image support before any figure is sent. A model that
# cannot see disables Stage 1f with a warning; it is never called anyway.
VISION_PROVIDER=none
VISION_MODEL=
VISION_TIMEOUT_S=120

# Figure reads kept in flight. Ollama sits at 1 — one GPU, shared with other
# local workloads (ADR-0033 §5), and measured: raising it to 4 overlapped the
# work (1.89x) but inflated each call ~43s -> ~127s, so per-figure throughput got
# worse. Raise it for a hosted endpoint. anthropic and mistral use 4 regardless.
# VISION_CONCURRENCY=1

# Waives the capability probe above. Only set this when you KNOW your model
# reads images and its provider does not publish a capability endpoint we can
# read (Mistral). It logs a warning every time it fires.
# VISION_ASSUME_CAPABLE=1
```

`docker compose run --rm dev python -m pipeline.vlm` reports what the current
environment resolves to and why, without starting the pipeline.

## Advanced

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

# Stage 3f — Self-verification of TTPs (ADR-0011 Phase B).  Recommended ON:
# TTP analogue of 3d: each LLM-extracted technique must be supported by a quoted
# sentence describing its use.  Only a HIGH-confidence semantic match waives the
# check — a medium one (≥ 0.48) is the nearest-but-wrong tier and must not grant
# a bypass.  Without this stage TTPs have no evidence gate at all.
ENABLE_TTP_VERIFICATION=true
TTP_VERIFY_MIN=1

# TTP mode (ADR-0072).  verify (default): the measured baseline above.  select:
# Stage 2c only retrieves candidates and 3f selects among them with a quote.
# Needs `python scripts/build_indexes.py --only retrieval`; evaluate on dev first.
# TTP_MODE=verify

# Stage 2c — taxonomies the semantic matcher may return (ATT&CK-only default;
# "all" restores CAPEC, which otherwise shadows the real ATT&CK technique)
# TTP_SEMANTIC_DOMAINS=enterprise-attack,mobile-attack,ics-attack

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
