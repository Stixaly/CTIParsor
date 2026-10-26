# Configuration

Every setting CTIParsor reads from `.env`. The [README](../README.md#configuration)
covers the minimum to get a first report through. `.env.example` carries every
variable with its default and is the reference when this page and it differ;
`bash setup.sh` copies it to `.env` on a fresh clone. The containers receive the
whole file, so a change takes effect at the next `docker compose up -d`.

- [Database](#database--postgresql-required)
- [LLM provider](#llm-provider)
- [NLP stages](#nlp-stages)
- [Vision (Stage 1f)](#vision-stage-1f--figures)
- [Advanced: checking passes, throughput, STIX output](#advanced)
- [TTP mode: verify or select](#ttp-mode-verify-or-select)
- [Document-level relations (Stage 3doc)](#document-level-relations-stage-3doc)
- [LLM request limits and sampling](#llm-request-limits-and-sampling)
- [CVE enrichment (Stage 2f)](#cve-enrichment-stage-2f)
- [Analyst feedback](#analyst-feedback)
- [Worker, queue and retention](#worker-queue-and-retention)
- [OCR](#ocr)
- [Logging](#logging)
- [Expert tuning](#expert-tuning)
- [Web server and Docker Compose](#web-server-and-docker-compose)

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

Every start of the API, of a worker and of `bootstrap` brings the schema up to
date (ADR-0077). The first process to start migrates, under a PostgreSQL
advisory lock; the others wait for it, then find nothing left to do. They wait
at most this long, then stop with an error. Compose restarts the API and
the worker (`restart: unless-stopped`), not `bootstrap`:

```env
# Seconds a starting process waits for another one's migration.  Raise it
# before an upgrade whose data migration is known to be long.
# DB_MIGRATION_LOCK_TIMEOUT_S=600
```

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
# Alternative: ehsanaghaei/SecureBERT-Plus (500 MB; its paper's +8-12% F1 on CTI text
# did not carry over: ADR-0023 measured no gain here, so it is not recommended)
# After changing: docker compose run --rm dev python scripts/build_indexes.py --only embeddings,
# then make docker-build: the cache lives in pipeline/data/, baked into the image
TTP_EMBEDDING_MODEL=all-MiniLM-L6-v2

# Stage 2c — semantic precision tuning (ADR-0011 Phase A). Thresholds are
# model-specific and resolved automatically (per-model defaults → embedding
# manifest → these overrides). Set only to hand-tune; leave unset for defaults.
# TTP_HIGH_THRESHOLD=0.62     # ≥ this → high confidence (wins over the LLM)
# TTP_MEDIUM_THRESHOLD=0.48   # ≥ this → medium candidate; < this → discarded
# TTP_TOP2_MARGIN=0.05        # drop a 2nd match for the same sentence beyond this
#                             # cosine gap from the top match

# Stage 2d — CyNER 2.0 cybersecurity NER (DeBERTa-v3; model card F1 91.88%, not measured here)
CYNER_ENABLED=true
# CYNER_MODEL=PranavaKailash/CyNER-2.0-DeBERTa-v3-base   # default; override to swap models

# Stage 2 and 2d, precision filters (ADR-0088, docs/eval/ner-precision-2026-10.md):
# a CyNER threat actor written as ordinary language ("cybercriminals",
# "Chinese threat actors", "Iran") is dropped, and a spaCy location is kept
# only when it can be a place name ("C&C", "XSS" go; "the United States"
# becomes "United States").  false = the behaviour before the filters.
# NER_PRECISION_FILTERS=true

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
# Stage 2b — the ordinary-word policy (docs/gazetteer-ordinary-words.md).
# shadow: match as before, count what the policy would withhold (the stage
# report's policy_* counts); apply: withhold it, for measurement until the
# acceptance gates pass (scripts/measure_gazetteer_policy.py); off: no policy.
# GAZETTEER_POLICY=shadow
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
# Adds ~1.4× LLM calls.  The aCTIon paper reports 27% → 8% hallucination on its
# own benchmark; CTIParsor's measured figure is the grounding harness's (docs/eval/)
ENABLE_STIX_VERIFICATION=false
STIX_VERIFY_MIN_RELS=1

# Stage 3f — Self-verification of TTPs (ADR-0011 Phase B).  Recommended ON:
# TTP analogue of 3d: each LLM-extracted technique must be supported by a quoted
# sentence describing its use.  Only a HIGH-confidence semantic match waives the
# check — a medium one (≥ 0.48) is the nearest-but-wrong tier and must not grant
# a bypass.  Without this stage TTPs have no evidence gate at all.
ENABLE_TTP_VERIFICATION=true
TTP_VERIFY_MIN=1

# TTP mode (ADR-0072) — see "TTP mode: select or verify" below.
# TTP_MODE=select

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
STIX_TLP=amber               # clear | green | amber | amber+strict | red (ADR-0073)
STIX_AUTHOR_NAME=CTIParsor

# HuggingFace token (removes rate limits on model downloads)
HF_TOKEN=
```

## TTP mode: select or verify

`TTP_MODE` (ADR-0072) decides how techniques are found.

| | `select` (default) | `verify` |
|---|---|---|
| Stage 2c | only **retrieves** ranked candidates per passage, from ATT&CK descriptions *and* procedure examples, BM25 and dense rankings fused — it emits no technique | emits techniques from cosine similarity to ATT&CK descriptions |
| Stage 3f | **chooses** among those candidates and the LLM's own proposals, each with a quote the code must find in the text; a failed call ships nothing and sends its candidates to review | checks the LLM's techniques after the fact; a high-confidence 2c match skips the check; a failed call keeps the claims |
| Measured on AnnoCTR dev ([baseline-2026-10](eval/baseline-2026-10.md)) | technique F1 **0.607** (P 0.587, R 0.628), +18% time per report | 0.465 with Stage 2c off, the best `verify` configuration |

Keep `ENABLE_TTP_VERIFICATION=true`: with 3f off, select mode drops the
retrieved candidates and lets the LLM's techniques through unchecked.

Retrieval reads its corpus from `pipeline/data/attack_retrieval_*` (~35 MB),
committed and baked into the image. Rebuild it after a MITRE ATT&CK release,
then rebuild the image:

```bash
docker compose run --rm dev python scripts/build_indexes.py --only retrieval
make docker-build && docker compose up -d
```

Without the corpus, Stage 2c reports itself unavailable and 3f selects among
the LLM's own proposals only: technique F1 0.443 on dev, recall 0.364, below
`verify` without 2c ([baseline-2026-10](eval/baseline-2026-10.md)).

Without an LLM provider, select mode cannot select: Stage 2c falls back to the
`verify` detector and the run records it as an offline fallback.

```env
# Corpus retrieved from: short (the legacy cache), description, procedure or both
# TTP_RETRIEVAL_CORPUS=both
# Retriever: dense, bm25, minrank or rrf
# TTP_RETRIEVAL_METHOD=rrf
# Candidates kept per passage, then per chunk (the LLM's own proposals are added
# on top, never cut).  10 / 40 put 86% of the gold techniques in their own
# chunk's list on AnnoCTR dev, 21 per chunk on average.
# TTP_CANDIDATES_PER_PASSAGE=10
# TTP_CANDIDATES_PER_CHUNK=40
# The technical-keyword allow-list, applied to retrieval
# TTP_RETRIEVAL_KEYWORD_GATE=true
# Chunks Stage 3 skips (no IoC, no known name) but with candidates get a
# selection call each: 36 more calls for at most 4% more recall on dev
# TTP_SELECT_SKIPPED_CHUNKS=false
# A selection quote shorter than this many words goes to review
# TTP_SELECT_MIN_QUOTE_WORDS=3
# Output-token ceiling of the selection call, never above LLM_MAX_OUTPUT_TOKENS:
# a looping answer stops there and keeps its complete choices (ADR-0072).
# Unset: 4096 on vLLM with thinking off, where it was measured; any other
# provider keeps LLM_MAX_OUTPUT_TOKENS (a model that reasons first can spend
# part of the budget before it answers)
# TTP_SELECT_MAX_OUTPUT_TOKENS=
# File of URL fragments: procedure examples citing one are not retrieved (the
# evaluation sets it so examples written from a scored report stay out)
# TTP_RETRIEVAL_EXCLUDE_CITED=
```

## ATT&CK release

`ATTACK_RELEASE` (ADR-0087) selects the ATT&CK release the pipeline reads. A
release is a **track**: the files built from MITRE's bundles
(`mitre_index.json`, `gazetteer.json`, `attack_relationships.json`,
`attack_revoked.json`, the embeddings of `mitre_index.json` with their meta file,
and the retrieval corpus with its embeddings), which Stages 2b, 2c, 3c and 4b
read, and which the interface reads through `GET /api/attack/index`.

| `ATTACK_RELEASE` | Files read |
|---|---|
| unset, empty, `19.2`, `v19.2`, `default` | `pipeline/data/` (the default track, release 19.2) |
| `20.0`, `v20.0` | `pipeline/data/attack/20.0/` (ATT&CK v20.0, released 2026-10-13) |

```env
# ATTACK_RELEASE=20.0
```

* **The default track is 19.2.** `pipeline/data/attack_manifest.json` names the
  release and lists, per file, what was checked against a rebuild from the
  official v19.2 assets. Two files are older than 19.2 and say so under
  `exceptions`: `gazetteer.json` (14 name variants of 19.2 missing) and
  `attack_relationships.json` (237 pairs missing, 1 extra).
* **An unknown value stops the run.** A value that names no track, or that is
  not a version number, raises `UnknownAttackRelease` before Stage 1, before
  Stage 4 (so a finalize too) and when the run manifest is built. The message
  lists the releases this installation has. There is no fallback to the default:
  a run is never given another release than the one it asked for (ADR-0073's
  rule for a TLP level). `python -c "from pipeline import attack_data;
  print(attack_data.available())"` lists them.
* **It is read when the process starts.** The loaders cache what they read, like
  `TTP_EMBEDDING_MODEL`. Set it in `.env` (the `app`, `worker` and `dev`
  services read that file) and restart. The first use fixes the release for the
  process: a later call that resolves another version raises, so a value loaded
  late from `.env` cannot split a process across two tracks. The API and the
  worker check it at start and log `ATT&CK release: <version>`.
* **A finalize uses the release of the process that serves it**, which is not
  necessarily the run's. The build record (ADR-0086) holds the finalize's own
  manifest.
* **The interface follows the API's release.** The Coverage page takes technique
  names and tactics from `GET /api/attack/index`: the `mitre_index.json` of the
  track the API runs, with its version in `X-Attack-Release`. The page shows
  that version (`ATT&CK 20.0`) next to the report's name. Like the pipeline, it
  shows the release of the process that serves it, which may not be the
  release of the job's run.
* **Measured on AnnoCTR dev** ([attack-v20-2026-10](eval/attack-v20-2026-10.md)):
  20.0 against 19.2, technique F1 0.584 → 0.609, a difference that is not
  significant ([−0.019, +0.076]). No technique new in v20 reaches a candidate
  list on dev. The default stays 19.2 until a comparison meets ADR-0060's
  rule.

### Build a track for a new release

```bash
# from the host: the three bundles of the release, into data/attack-stix/v20.1/
# (git-ignored; 67 MB for v20.0). Each is checked against the sha256 GitHub
# publishes for it
python scripts/download_attack.py --release 20.1
# pipeline/data/attack/20.1/; needs sentence-transformers for the embeddings
docker compose run --rm dev python scripts/build_attack_release.py --release 20.1
make docker-build && docker compose up -d
```

The build refuses a bundle that is not the file GitHub published or whose
`x-mitre-collection` says another release, and refuses to overwrite a track
without `--force`. It writes next to the target and renames, so a failure leaves
no half-built track. Embeddings use `TTP_EMBEDDING_MODEL`; with a model other
than the default, the track gets a `mitre_embeddings_manifest.json` (model,
dimensions, thresholds) for Stage 2c. The CAPEC entries of
`mitre_index.json` are carried over from the default track
(`--capec-index` names another file, `--out-dir` another directory, and
`--stix-dir` another place for the bundles). Commit the directory: a track that
is not in the repository cannot be selected from the image. Each track is about
40 MB (v20.0: 39,900,662 bytes).

`scripts/download_attack.py` without `--release` still fetches the master branch
of mitre/cti, which is the latest release (20.0 on 2026-10-18), not necessarily
the default track's. The evaluation protocol maps its gold against a bundle it
finds by sha256 (docs/eval/README.md), so that file is refused for the default
track.

### What the run manifest records

`api/run_config.build_manifest` (ADR-0059, ADR-0086) holds, for the release:

* an `attack` block: `release`, `default`, `requested` (the raw setting),
  `directory`, `manifest_sha256`, the sha256 of the source bundles per domain
  (16 hex characters, like the other hashes), `exceptions`, and
  `built_with` (how the track was built), and `modified_files`, the files whose
  hash is no longer the one the track's manifest records, or that it does not
  know (`<name> (not in the manifest)`). For those, the announced release is no
  longer proven;
* `data`: the hash of the files the process actually loads, `attack_manifest.json`
  included;
* `ATTACK_RELEASE` in the captured environment;
* the Stage 3 checkpoint's fingerprint carries `attack_release`, so a checkpoint
  does not resume on another track.

## Document-level relations (Stage 3doc)

One extra LLM call per report reads the **whole** document and extracts
relationships only, linking facts stated far apart ("X is a variant of Y" in
paragraph 2, "Y is attributed to Z" in paragraph 40) — ADR-0057, ADR-0064.
Measured on 7 real reports: about 60% more correct relationships, but only 40%
of the ones it adds are strictly correct (vague `related-to`, generic
endpoints). When Stage 3d is on, its result goes through 3d like the chunks'.

It needs a context window that fits the whole report and room for a long
answer: on a 37 000-character report it wrote 50 000 characters, 11 minutes at
~15 tokens/s. Raise `LLM_TIMEOUT` and `LLM_MAX_OUTPUT_TOKENS` with it, or the
call times out and adds nothing.

```env
ENABLE_DOCUMENT_LEVEL_RELATIONS=false
# Prompt ceiling for this pass only (largest report of this project's corpus: ~110k chars)
# LLM_DOC_MAX_PROMPT_LENGTH=300000
```

## LLM request limits and sampling

```env
# Keep LLM_MAX_RESPONSE_LENGTH above ~4 x LLM_MAX_OUTPUT_TOKENS: a response cut
# shorter than the model may write loses its JSON, and the chunk with it.
# LLM_MAX_OUTPUT_TOKENS=8192
# LLM_MAX_PROMPT_LENGTH=32000
# LLM_MAX_RESPONSE_LENGTH=48000
# Claims per Stage 3d call: a document-level pass's ~100 claims in one call
# would outgrow the output budget (ADR-0064)
# STIX_VERIFY_BATCH_SIZE=40

# Unset: each provider's default (temperature 0.7 for Qwen on vLLM, 1.0 on
# Anthropic), so two runs of one report can differ.  Set them to make runs
# repeatable, e.g. for an evaluation.  The seed reaches vLLM, Ollama and LM Studio only.
# LLM_TEMPERATURE=0
# LLM_SEED=13
```

`CHUNK_MAX_CHARS`, `CHUNK_OVERLAP` and `LLM_MAX_RETRIES` appear in
`.env.example` but **have no effect**: the worker picks the chunk size itself
(3 000 characters, 4 000 above 30k, 5 000 above 60k, with a 400-character
overlap) and Stage 3 retries a failed call 3 times. They are read into a
config object nothing uses.

## CVE enrichment (Stage 2f)

Stage 2f adds a description and a CVSS v3 score to each CVE's `vulnerability`
object (`x_cvss_v3_score`, `x_cvss_v3_vector`). It always reads the
`cve_cache` table; with the flag on, it also looks up what the cache does not
hold on the public CIRCL API — at most 25 lookups and 30 s per report — and
caches the answer, a CVE CIRCL has no record of included. A lookup that gets no
answer (CIRCL unreachable, a 5xx, an unreadable reply) is not cached and ends
that report's lookups: the next run asks again. Off by default, because Stages 1, 2, 4
and 5 otherwise run fully offline.

```env
# CVE_ENRICHMENT=false
```

## Benign values without an Indicator (Stage 4)

A value the report names without accusing it ships as an observable without
an Indicator, so no consumer alerts on it: a non-routable address, the four
big public DNS resolvers, a security vendor's or sandbox's site (a reference
link), one of the 10,000 most popular domains (that exact domain only). The
lists are MISP warninglists (CC0 1.0), vendored by
`scripts/build_warninglists.py` into `pipeline/data/warninglists.json`; the
ledger records why each value has no Indicator. On by default.

```env
# BENIGN_IOC_FILTER=true
```

## Analyst feedback

Besides `THRESHOLD_CALIBRATION_ENABLED` and `ENTITY_OVERRIDES_ENABLED` above:

```env
# ADR-0058: the worker auto-accepts entities at >= 90% confidence when a job
# finishes, but leaves this share of them pending ("confirm" chip).  Analysts'
# verdicts on those measure how often auto-accept is right
# (GET /api/thresholds -> auto_accept_audit).  0 disables.
# REVIEW_CONTROL_SAMPLE_RATE=0.10
```

## Enriching a STIX bundle

```env
# ADR-0090: let a report come with a STIX 2.1 bundle the analyst already holds
# (/api/upload baseline_stix, /api/ingest/* baseline_bundle), and answer
# POST /api/baselines/inspect.  On by default (lot 7); false turns it off, and
# a request that carries a bundle then gets 400.  Read on every request.
# STIX_ENRICHMENT_ENABLED=true
```

The limits are not settings: a bundle is at most 20 MB and 10 000 objects
(`pipeline/baseline_stix.py`; `GET /api/baselines/status` reports them). The
report and the bundle travel in one request, so while `STIX_ENRICHMENT_ENABLED`
is on, a route's request budget has room for both: 70 MB for an upload, a 50 MB
report and a 20 MB bundle. The budget is counted as the body arrives, with or
without `Content-Length`; with the mode off, the bundle's room goes (the
budgets, route by route: [api.md](api.md#how-large-a-request-may-be)). The
reverse proxy (`client_max_body_size` in `docker/nginx/default.conf`) accepts
72 MB, the largest budget and a little more, and it is 72 MB **because of this
feature** (it was 50 MB). Behind another proxy, allow as much: 72 MiB, that is
75,497,472 bytes.

## Worker, queue and retention

```env
# Reports processed at the same time, per worker container.  Each holds ~4.4 GB
# (mostly GLiNER): size it from RAM, floor((RAM_GB - 4) / 4.4), and raise
# CTI_WORKER_MEMORY with it.  1 for the compose worker.
# WORKER_MAX_CONCURRENT=1
# Seconds one report may run (figures and LLM included) before it is cancelled.
# A local LLM needs more: ~100 s for one short chunk with 3d and 3f on was
# measured with Qwen3.8-27B on vLLM.
# WORKER_JOB_TIMEOUT=1800
# Reports allowed to wait once every slot is busy; beyond it an upload gets
# HTTP 503 instead of being silently dropped.  0 = unbounded.
# API_QUEUE_MAX_DEPTH=50

# Delete finished jobs (rows and files) older than N days.  0 = never.  Queued
# and running jobs are never swept.  The sweep runs at most every
# JOB_RETENTION_SWEEP_S seconds.
# JOB_RETENTION_DAYS=0
# JOB_RETENTION_SWEEP_S=3600

# A running job whose heartbeat is older than the lease goes back to the queue
# (keep the lease at least 3x the heartbeat); poll interval; how long a
# stopping worker lets running reports finish before requeueing them.
# WORKER_HEARTBEAT_S=30
# WORKER_LEASE_TIMEOUT_S=180
# WORKER_POLL_S=2
# WORKER_DRAIN_S=60

# The file the worker touches on every poll: its liveness.  The compose
# healthcheck reads the same variable and fails once the file is two minutes
# old.  It must be writable (the container's /tmp is a tmpfs).
# WORKER_ALIVE_FILE=/tmp/ctiparsor-worker.alive

# Stages to skip for every report this process runs (worker and CLI alike), to
# measure what a stage contributes.  Ids: 1f 2 2b 2c 2d 2e 2g 3 3d 3f 3e 3doc 2f 4 4b 4c 5
# PIPELINE_DISABLED_STAGES=
```

`CTIPARSOR_ROLE` (`api`, `worker`, or `all` on a legacy host install) is set
per service by `compose.yaml`; leave it alone.

## OCR

```env
# Tesseract language(s) for scanned PDF pages, e.g. eng+fra.  OCR is decided page by page.
# OCR_LANG=eng
```

The image installs Debian's `tesseract-ocr`, which brings English only. Another
language needs its `tesseract-ocr-<lang>` package added to the `Dockerfile`
and an image rebuild.

## Logging

```env
# DEBUG | INFO | WARNING | ERROR
# LOG_LEVEL=INFO
# text | json
# LOG_FORMAT=text
# Also write to this file (empty = stdout only), rotated at MAX_LOG_SIZE bytes,
# LOG_BACKUP_COUNT old files kept
# LOG_FILE=
# MAX_LOG_SIZE=10485760
# LOG_BACKUP_COUNT=5
```

Under Docker, `docker compose logs -f app worker` reads stdout. The root
filesystem is read-only, so a `LOG_FILE` has to point into a volume, e.g.
`/app/state/ctiparsor.log`.

## Expert tuning

Calibrated values: change them only alongside a measurement
(`tests/eval_pipeline.py` is the harness for the TTP ones).

```env
# Stage 2c gates
# TTP_KEYWORD_GATE=true        # require technical keywords before proposing a technique
# TTP_ADVISORY_GATE=true       # ignore mitigation text and table captions
# TTP_UNWRAP_LINES=true        # rejoin lines broken by newlines before matching
# TTP_MAX_CANDIDATES=200       # candidates kept per document

# Stage 2d / 2e batching: phrases per batch, window size in characters
# CYNER_BATCH_SIZE=4
# CYNER_CHUNK_CHARS=1600
# GLINER_BATCH_SIZE=4
# GLINER_CHUNK_CHARS=1600

# Tests and audit scripts only: skip spaCy, CyNER, GLiNER and the
# sentence-transformers models, so nothing is downloaded.  Never in production.
# SKIP_HEAVY_MODELS=
```

The Stage 2c thresholds and `TTP_SEMANTIC_DOMAINS` are in [NLP stages](#nlp-stages)
and [Advanced](#advanced).

## Web server and Docker Compose

`API_HOST`, `API_PORT`, `API_WORKERS`, `API_RELOAD` and `FORWARDED_ALLOW_IPS`
configure the single API process; under Docker, compose forces the first three
and publishes with `CTI_BIND` / `CTI_PORT`.

`API_ALLOWED_HOSTS` (default `localhost,127.0.0.1,[::1]`) is the list of
`Host` names the API answers to; any other gets 400 before a handler runs,
which is what stops DNS rebinding against an unauthenticated app. **List the
name or address you reach the app on** when it is not loopback: the LAN
address behind `API_HOST=0.0.0.0`, the public name behind the `proxy`
profile. `*.example.org` patterns work; `*` turns the check off. The same
list decides which `Origin` a browser may write from. Cross-site writes
(`Sec-Fetch-Site: cross-site`, or a foreign `Origin`) are refused with 403;
curl and scripts send neither header and are not affected.

The compose-level settings —
published ports, image name, `CTI_INSTALL_CAPTURE`, per-container CPU and memory
(`CTI_<SERVICE>_CPUS`, `CTI_<SERVICE>_MEMORY`) — are in sections 9 and 12 of
`.env.example`, with what each exposure means in
[docs/deployment.md](deployment.md) and the sizing in [docs/docker.md](docker.md).
