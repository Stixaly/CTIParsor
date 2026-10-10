# CTIParsor — Test Strategy

This document is the source of truth for how CTIParsor is tested: what each layer
covers, how to run it, the coverage targets, and the open gaps. Update it whenever
a feature lands so the gap list stays honest.

_Last reviewed: 2026-10-03 — CI now blocks on every deterministic test
(eval_pipeline.py and the OpenCTI parser tests included), on branch coverage
floors and on the frontend lint; tests write only under their tmp_path.
Carries forward the 2026-09-16 review (container/PostgreSQL/worker-queue
split, ADR-0044/0045/0046) and the 2026-06-18 one (evidence labels,
cross-model consensus, STIX provenance)._

---

## 1. Philosophy

CTIParsor is a **deterministic-core / probabilistic-edge** system: Stages 1, 2,
2b–2e, 3b–3e, 4, 5 are deterministic given their inputs; only the raw LLM call
(Stage 3) is non-deterministic, and it is **mocked in tests** (`conftest.mock_llm`)
so the suite needs no API key and is fully reproducible.

That shape dictates the pyramid:

```
            ┌───────────────────────┐
            │  Integration (API +   │   few — HTTP layer, DB round-trips
            │  pipeline end-to-end) │
        ┌───┴───────────────────────┴───┐
        │   Stage / unit tests          │   many — one file per pipeline stage,
        │   (deterministic, mocked LLM) │   the bulk of the suite
        └───────────────────────────────┘
   Frontend: Vitest + Testing Library (pages, rail, graph helpers), tsc, ESLint
```

**Cover:** transformation correctness, idempotency, error handling, STIX 2.1 spec
compliance, security boundaries (prompt-injection sanitiser, upload filter),
provenance/grading integrity.
**Skip:** the live LLM provider, framework internals, trivial getters.

---

## 2. How to run

Docker is the only supported way to run the suite (ADR-0054) — the `dev`
compose service already has `CTIPARSOR_TEST_DATABASE_URL` pointed at a
disposable PostgreSQL schema per run, no manual setup needed:

```bash
make ci               # what the pull-request CI runs: lint, types, tests + coverage floors, frontend
make test             # the whole suite (docker compose run --rm dev pytest -v), no coverage
make coverage         # the whole suite with branch coverage, then the floors (§8)
make frontend-check   # eslint + tsc + vitest (npm run check), in the frontend-dev container
```

`make test`, `make docker-test` (its alias) and CI select the same tests:
`pytest.ini` names `tests/` and collects `eval_pipeline.py` as well.
`make test-fast` adds `-k "not llm"`, which drops every test whose id contains
`llm`: 56 in 10 modules on 2026-10-03, mostly Stage 3 and vision tests that
run on the mocked LLM anyway. It is a quicker loop, not the gate.

The `mock_llm` fixture patches `pipeline.stage3_llm._call_llm`, so Stage 3 tests
run offline; no test needs an API key.

Two rules hold for every test, enforced in `tests/conftest.py`:

- **Files stay in `tmp_path`.** `api/paths.py` reads the uploads and output
  directories from `CTIPARSOR_UPLOADS_DIR` / `CTIPARSOR_OUTPUT_DIR`, which an
  autouse fixture points at the test's `tmp_path`. A run that still adds a
  file to the checkout's `uploads/` or `output/` lists it at the end, and
  fails under CI.
- **A missing dependency is not a skip in CI.** With
  `CTIPARSOR_REQUIRE_TEST_DEPS=1` (CI's fast job, `make coverage`), a test
  skipped by `pytest.importorskip` fails instead. Use `importorskip` (not a
  `skipif` on `find_spec`) for an optional import, so this applies to it.

### Measuring TTP precision (ATE benchmark)

`tests/eval_pipeline.py` doubles as a CLI for the **ATT&CK Technique Extraction
(ATE)** benchmark — the harness for the ADR-0011 precision work. It scores MITRE
technique extraction (P/R/F1) against the GPT-4 baseline (F1 = 0.64):

```bash
# Regex + semantic + Stage 3c subsumption (offline, no API key)
docker compose run --rm dev python tests/eval_pipeline.py --benchmark ate --stage all --verbose

# Semantic stage only (needs the embedding cache; tune thresholds here)
docker compose run --rm dev python tests/eval_pipeline.py --benchmark ate --stage 2c --verbose

# The full shipping path: regex + semantic + LLM + Stage 3c normalize (needs API key)
docker compose run --rm dev python tests/eval_pipeline.py --benchmark ate --stage full

# Against the public CTIBench ATE dataset (github.com/xashru/cti-bench)
docker compose run --rm dev python tests/eval_pipeline.py --benchmark ate --stage full --dataset ctibench_ate.json
```

Use `--stage full` to calibrate per-model thresholds (e.g. the SecureBERT-Plus
row in `pipeline/stage2c_ttp_semantic._MODEL_THRESHOLDS`) before changing
`TTP_EMBEDDING_MODEL` in production.

### Measuring graph completion (REL benchmark)

The same CLI scores **Stage 4b graph completion** at the edge level (ADR-0013).
Given a base graph of verified objects + edges and gold accept/reject judgments,
it runs `complete_graph` and reports per-engine judged precision, recall, and F1:

```bash
# Built-in fixtures (offline, no API key)
docker compose run --rm dev python tests/eval_pipeline.py --benchmark rel --verbose

# Against your own annotated reports
docker compose run --rm dev python tests/eval_pipeline.py --benchmark rel --dataset gold_edges.json
```

Dataset format (one object per sample):

```json
[{
  "description": "APT29 report",
  "objects":     [{"type": "threat-actor", "name": "APT29"},
                  {"type": "malware", "name": "WellMess"},
                  {"type": "attack-pattern", "name": "Phishing", "mitre_id": "T1566"}],
  "edges":       [["APT29", "uses", "WellMess"]],
  "gold_accept": [["APT29", "uses", "Phishing"]],
  "gold_reject": [["APT29", "targets", "Phishing"]],
  "closed":      false
}]
```

- `edges` — the base (already-verified) graph completion runs on top of.
- `gold_accept` — edges completion **must** add (missing one ⟹ FN).
- `gold_reject` — edges it **must not** add (adding one ⟹ FP).
- `closed` — `true` means the judgments are exhaustive, so any *unjudged* added
  edge counts as a FP. Leave `false` while an annotation set is still partial;
  unjudged edges are then just counted and reported, not penalised.
- `completion` *(optional)* — per-sample engine config, e.g. `{"alias": true}`,
  for measuring an engine that ships **off** by default. Omit to score the
  default configuration (what actually runs in production).

Run this **before** changing a threshold or the transitive rule table — it is
what turns "no accuracy loss" from a design claim into a measured number.
Reference point: CTINexus reports ≈ 0.91 relation-prediction precision
(IEEE EuroS&P 2025).

---

## 3. Current coverage map

CI's fast job passes 2128 tests on 2026-10-03 (110 `test_*.py` modules plus
`eval_pipeline.py`) and skips 4: tesseract/poppler and the STIX JSON schemas
are not in that job, one benchmark needs the embedding cache, and one test
waits for a multi-tactic T1059 in the ATT&CK index; `test_doc_claims.py`,
added after that count, adds 2. The table
lists the main modules with counts from an earlier `pytest --collect-only`
(they include `parametrize` expansion); `pytest --collect-only -q` is the
current truth.

| Layer | File | ~Tests | Covers |
|---|---|---:|---|
| Ingestion | `test_stage1.py` | 8 | text ingestion, chunking, overlap, unsupported formats |
| Ingestion | `test_stage1_pdf_paths.py` | 31 | per-page scan detection, mixed and fully scanned PDFs (OCR in page batches, failures degrade to the text layer), markitdown fallback, PDF/DOCX creation dates, the document anchor from a capture sidecar or HTML metadata |
| Ingestion | `test_upload_route.py` | 17 | `/api/upload`: TLP/PAP markings, extension and MIME checks, the `filetype` fallback without libmagic, size limit, full queue, disk errors |
| Ingestion | `test_ingest_routes.py` | 26 | job creation, TLP validation, URL capture, HTML detection |
| Ingestion | `test_web_capture.py` | 38 | URL sanitization, SSRF guards, PDF rendering, lazy loading |
| **Figures** | `test_figure_triage.py` | 12 | size filtering, aspect guards, PDF source detection |
| **Figures** | `test_stage1f_figures.py` | 29 | figure injection, verbatim rendering, edge rendering |
| **Figures** | `test_figure_store.py` | 12 | JSON round-trip, cache management, span loading |
| **Figures** | `test_figure_reading_order.py` | 5 | reading order, page ordering, span delimitation |
| **Figures** | `test_vlm.py` | 18 | payload parsing, backend selection, figure reading, `VISION_CONCURRENCY` parsing and override |
| **Figures** | `test_figure_context.py` | 12 | prompt context blocks, the ban on copying context into `verbatim_text`, per-figure bands, cache-key separation |
| Extraction | `test_stage2.py` | 75 | IoC extraction, refang/defang, hash recovery, filename handling |
| NER | `test_stage2d_cyner.py` | 4 | CyNER label mapping, entity extraction, model fallback |
| NER | `test_stage2e_gliner.py` | 16 | per-type cutoffs, model loading (no deprecated `resume_download`), batch fallback, merge precedence |
| NER | `test_stage_registry.py` | 4 | registry merging, deduplication, case insensitivity |
| **Aliases** | `test_aliases.py` | 6 | alias resolution, MITRE ID mapping, surface forms |
| **Aliases** | `test_alias_disambiguation.py` | 11 | type-aware resolution, alias isolation, canonical name handling |
| LLM enrich | `test_stage3.py` | 80 | LLM enrichment, JSON parsing, deduplication, prompt sanitization, the document-level pass reaching the provider whole |
| Relationship verification | `test_stage3d_verify.py` | 9 | Stage 3d sees the whole text, cuts the text not the claims, batches, document mode (reference sentence yes, chain no) |
| LLM enrich | `test_stage3_providers.py` | 5 | readiness gating for anthropic, gemini, mistral and the OpenAI-compatible local providers |
| LLM enrich | `test_stage3_calls.py` | 75 | client construction, provider diagnostics, Anthropic/OpenAI-compatible calls and retries, dispatch, repair of a truncated answer (never collapsed to one nested object), `enrich_chunk`/`enrich_all_chunks`/`enrich_document_relations` branches |
| **CVE enrichment** | `test_cve_enrichment.py` | 25 | CVE id validation, the path-traversal guard before any URL, opt-in network flag, fetch and time caps, CIRCL CVE 5.x parsing (ADP then CNA scores), the PostgreSQL cache and its remembered misses |
| Hallucination filter | `test_stage3b.py` | 11 | hallucination filtering, entity presence checks, allow-list bypass |
| **TTP precision** | `test_ttp_precision.py` | 36 | threshold resolution, semantic confidence, subsumption, verification (whole chunk sent) |
| **TTP precision** | `test_ttp_volume_controls.py` | 16 | cross-source dedup, corroboration floors, taxonomy filtering |
| **TTP precision** | `test_ttp_sentence_gates.py` | 14 | sentence unwrapping, keyword gating, candidate selection |
| **TTP precision** | `test_ttp_evidence_merge.py` | 11 | evidence preference, semantic fallback, label preservation |
| **TTP precision** | `test_ate_scoring.py` | 13 | ATE scoring, partial credit, macro averaging, diagnostics |
| **Evidence spans** | `test_evidence_span.py` | 19 | offset normalization, quote location, sentence bounds |
| **Evidence spans** | `test_evidence_span_offsets.py` | 11 | index mapping, coverage calculation, quote matching |
| **Evidence spans** | `test_merge_keeps_evidence.py` | 10 | evidence preservation, confidence ranking, deduplication |
| **Evidence labels** | `test_evidence_consensus.py` | 4 | label normalization, STIX properties, consensus boosting |
| STIX mapping | `test_stage4.py` | 66 | SDO/SCO/SRO build, alias merging, IoC coverage, observable routing (ADR-0041, ADR-0062) |
| STIX mapping | `test_stage4_paths.py` | 52 | every observable to its SCO and pattern, named SDOs, PAP, embedded-rule Indicators, pin budget/grounding/malformed policies, relationship guards, CVE/CVSS and campaign merges, stix2 refusals |
| STIX mapping | `test_stix_rel_spec.py` | 4 | listed vs allowed relationships: common verbs, unknown types, direction |
| STIX mapping | `test_stix_ids.py` | 19 | ids equal to OpenCTI's standard ids: 15 values produced by pycti's own `generate_id` (ADR-0066), case and CAPEC rules |
| STIX mapping | `test_bundle_ledger.py` | 24 | mapping ledger: every row outcome and change, origins, 4b alias merge, API round-trip (ADR-0061); an IoC `indicates` a technique through its Indicator, turned around when written backwards (ADR-0065) |
| STIX mapping | `test_stix_self_edges.py` | 4 | self-edge prevention, endpoint validation, bundle integrity |
| **Graph completion** | `test_stage4b_completion.py` | 18 | transitive completion, alias merging, grounding, pins |
| **Graph completion** | `test_stage4c_long_distance.py` | 16 | long-distance inference, direction swap, evidence recording, passages naming the entities in a long report |
| **Graph completion** | `test_grounding_by_label.py` | 8 | STIX display names, edge scoring, bundle validation |
| Validation/export | `test_stage5.py` | 8 | bundle validation, file writing, nested directories |
| **Provenance** | `test_provenance.py` | 5 | authoring identity, TLP marking, created_by_ref |
| **Provenance** | `test_edge_provenance.py` | 10 | relationship properties, pinned edges, run config |
| **Provenance** | `test_bundle_staleness.py` | 15 | `git_rev` extraction from malformed run configs, ancestry verdicts, an undecidable git result never marking a bundle stale (ADR-0035) |
| **Relationship policy** | `test_pin_budget.py` | 23 | fair share allocation, edge key validation, materialization, observable routing |
| **Relationship policy** | `test_pin_evidence.py` | 31 | term extraction, sentence indexing, grounding gates, pins on listed observable pairs |
| **Relationship policy** | `test_policy_last_run.py` | 17 | stats extraction, database queries, bundle handling |
| **Relationship policy** | `test_policy_rule_validation.py` | 15 | policy validation, API rejection, graph survival |
| **Rule adapters** | `test_sigma_adapter.py` | 8 | rule parsing, tactic skipping, registry loading |
| **Rule adapters** | `test_suricata_yara_adapters.py` | 17 | Suricata and YARA corpora end to end: ids, severity, header atoms from bracketed lists, dedup keys, private rules, file extensions |
| **Rule adapters** | `test_sigma_negation.py` | 15 | negation logic, selector expansion, condition parsing |
| **Rule adapters** | `test_multiformat_atoms.py` | 47 | atom extraction, buffer handling, negation, metadata |
| **Rule adapters** | `test_escape_unescaping.py` | 12 | YARA/Suricata unescaping, backslash handling, edge cases |
| **Rule adapters** | `test_atom_normalisation.py` | 6 | basename stripping, lowercase enforcement, atom trimming |
| **Rule dedup** | `test_detection_dedup.py` | 10 | dedup key logic, canonical election, provenance folding |
| **Rule dedup** | `test_provenance_dedup.py` | 18 | dedup clustering, provenance folding, deterministic merging |
| **Rule relevance** | `test_detection_relevance.py` | 29 | atom mapping, platform factors, IDF weighting, ranking |
| **Rule relevance** | `test_technique_idf.py` | 21 | technique counting, IDF calculation, rule mapping |
| **Rule relevance** | `test_relevance_corroboration.py` | 8 | corroboration scoring, match weighting, proposal flags |
| **Rule relevance** | `test_control.py` | 17 | value discrimination, domain guards, host classification |
| **Rule relevance** | `test_brands.py` | 12 | brand detection, domain themes, evidence preference |
| **Rule relevance** | `test_observables_domain_guard.py` | 10 | domain validation, filename rejection, URL handling |
| **Detection coverage** | `test_detection_coverage.py` | 48 | scoring policy, format splitting, export selection, evidence |
| **Detection coverage** | `test_detection_artifacts.py` | 26 | artifact scoring, evidence capping, folding, vocabulary |
| **Detection coverage** | `test_detection_phases.py` | 13 | tactic mapping, off-matrix handling, phase counting |
| **Detection coverage** | `test_mitre_db.py` | 8 | ATT&CK/CAPEC index lookup and search ranking, missing or corrupt index |
| **Detection coverage** | `test_coverage_artifacts_api.py` | 5 | artifact coverage routes, payload shape, 404 handling |
| **Export filters** | `test_export_filters.py` | 13 | facet totals, format filtering, license exclusion, manifest |
| **Export filters** | `test_rule_lookup.py` | 8 | rule lookup, metadata retrieval, license handling |
| **Rule synthesis** | `test_synth_sigma.py` | 47 | rule synthesis, value validation, path escaping, stability |
| API | `test_api_routes.py` | 11 | health checks, job listing, upload validation, progress |
| API | `test_relationships_api.py` | 18 | relationship creation, label coercion, patch validation, dates, `POST /relationships/bulk` (`human_bulk`, journaled, other jobs untouched — ADR-0065) |
| API | `test_settings_api.py` | 31 | corpus listing, overlay management, rebuild ingestion, formats, unsafe paths/remotes/tarballs, enable/disable, per-corpus sync |
| API | `test_jobs_routes.py` | 23 | job list/get/status, finalize, delete (rows and every file), retention sweep, source file, bundle and ledger |
| API | `test_entities_api.py` | 13 | manual entities, edit, bulk accept/reject/reset, delete, refusals |
| API | `test_policy_api.py` | 22 | relationship policy round trip, default fallback, every refused shape |
| API | `test_logging_config.py` | 9 | request ids, JSON/text formatters, `setup_logging` handlers, log helpers |
| Persistence | `test_persistence.py` | 7 | backup consistency, migration idempotency, label persistence |
| Persistence | `test_db_transaction.py` | 6 | transaction rollback, commit, exception handling |
| Persistence | `test_container_env.py` | 4 | `CTIPARSOR_GIT_REV` fallback when `git` is absent or fails (ADR-0044) — `_path_from_env`/`BACKUP_DIR` and `CTIPARSOR_DB_PATH` were removed along with SQLite (ADR-0053) |
| Queue | `test_worker.py` | 30 | the worker's terminal states (no bundle, timeout, abort, reclaimed, failed backup), hook guards, subprocess thread caps, the crash watcher, the finalize rebuild applying reviewer rejections and reading legacy/ADR-0063 dates |
| Queue | `test_job_queue.py` | 14 | the queue loop (ADR-0046): atomic claim under 8 threads, lease-based orphan requeue, heartbeat scoping, slot accounting with a fake spawn, `run_pipeline_async` under roles `api` and `all`, `--once` |
| Persistence | `test_db_backend.py` | 12 | the PostgreSQL adapter without a server: `?`→`%s` outside literals, `%`→`%%`, the `Row` type, `backend()`/`get_conn()` requiring `DATABASE_URL` (ADR-0053), a fake psycopg connection proving `with` never closes and `transaction()` issues plain `BEGIN` (ADR-0045) |
| Persistence | `test_db_postgres.py` | 10 | skipped unless `CTIPARSOR_TEST_DATABASE_URL` is set (every other DB-touching test needs it too, via `temp_db` — ADR-0053): round trips, SSE resume ids, upserts, cascade, the coverage call without `jobs_conn`, the API through `temp_db_client`, and both migration scripts end to end (ADR-0045, ADR-0053) |
| Shared helpers | `test_shared_helpers.py` | 27 | environment parsing, claim extraction, unescaping logic |
| Fuzzing | `test_fuzz_targets.py` | 5 | every Atheris target (ADR-0081) over its seed corpus, `fuzz/corpus/<target>/`, and the empty input: a target that stops importing, or whose invariant a seed breaks, fails here between fuzzing runs; skipped off Linux x86_64 (no Atheris wheel) |
| Docs | `test_doc_claims.py` | 2 | every number `scripts/check_doc_claims.py` checks in README.md and docs/pipeline.md still matches its source, and is still found (what `make check-docs` did on demand only) |
| Benchmarks | `eval_pipeline.py` | 10 | NER F1, ATE precision, grounding metrics, adversarial tests |

`CTIPARSOR_TEST_DATABASE_URL=postgresql://user:pw@host/db` is **required**,
not optional (ADR-0053: CTIParsor has no SQLite fallback) — the `temp_db`
fixture creates a disposable schema per test on that server and fails the
test run with a clear message if the variable is unset. CI sets it in both
`fast-tests` and `model-tests`.

**Shared infra** (`conftest.py`): `sample_cti_text`, `sample_entities`,
`mock_llm` / `mock_llm_empty` / `mock_llm_bad_json`, `storage`, `api_client`.

---

## 4. Strategy by component

### Pipeline stages (unit, deterministic)
One file per stage. Each new stage **must** ship a `test_stageN.py` covering:
input validation, the transform's correctness on a known fixture, idempotency
(running twice = same result), and the empty/malformed-input path.

### API routes (integration via `TestClient`)
HTTP contract per endpoint: success shape, 404/400 boundaries, and validation
rejections. `init_db` is patched in `api_client` (no real database — for tests
that do need one, e.g. anything touching `/api/health`, use `temp_db_client`
instead, which runs against a real disposable PostgreSQL schema).

### The API against its OpenAPI schema (Schemathesis)
`tests/test_api_schema.py` generates requests for every operation from the
schema FastAPI publishes (`/openapi.json`), with Schemathesis: valid ones,
and ones that break a declared constraint (wrong types, missing fields,
odd Unicode, unexpected methods). Each response must not be a server error
and must match the schema its operation declares. About 20 examples per
operation and mode; 51 operations in about 30 s.

- **Deterministic.** Generation is derandomized: every run sends the same
  requests, so the test is a gate like the others (ADR-0071), and a failure
  comes back with the command that found it (in CI, the whole suite). An
  operation's examples depend on what ran before it in the process: `-k` on
  one operation, or the module alone, sends other requests. A route change
  changes the requests too. Measured: two runs of the module send the same
  1,991 requests, also after other code has consumed Python's global
  `random` state; only the multipart boundary, drawn when a request is
  sent, differs.
- **Against real data.** Through `temp_db_client`, with one reviewed job,
  two entities and a relationship: `job_id`, `entity_id` and `rel_id` take
  their ids, so the handlers run instead of answering 404.
- **Offline.** The corpus routes write to a copy of the registry under
  `tmp_path`, and URL validation answers without DNS. Left out: URL capture
  (a browser on the network), corpus sync and rebuild (clones), the progress
  stream (Server-Sent Events, open while a job runs).

Its first run found `GET /api/jobs/{job_id}/relationships/valid-types`
published without its `job_id` parameter: an OpenAPI schema that
generated clients reject.

### Persistence / worker (integration)
The write→read round-trip through PostgreSQL (`worker._save_entities` →
`re_run_final_stages`) and schema migrations. **Currently the weakest layer** (see §6).

### Attacker-facing parsers (fuzzing, ADR-0081)
Four Atheris targets in `fuzz/` mutate their seeds for 60 s on every pull
request and push to `main`, and for 10 minutes weekly:

- `report_text`: refang and extraction;
- `dates`: date parsing;
- `rule_gates`: the Sigma, Suricata, Snort, YARA and STIX-literal gates;
- `spotlight`: the prompt enclosure.

A failure is one of:

- an exception;
- a broken invariant;
- a native crash;
- an input slower than 10 s;
- more than 2 GB of memory.

The four jobs are required checks (ADR-0078, amendment of 2026-10-10), so a
failure is fixed before the merge:

1. Reproduce it from the uploaded artifact: `python fuzz/fuzz_<target>.py <file>`.
2. Fix it.
3. Add the input to `fuzz/corpus/<target>/`.

From then on, `test_fuzz_targets.py` replays that input in the fast tests.

### Frontend (Vitest, ESLint, tsc)
17 Vitest files (141 tests on 2026-10-03) with Testing Library and jsdom: the
Review and Dashboard pages, the relationship rail, the document reader, the
graph builders and layout, the API client, a dependency audit. ESLint runs
the TypeScript rules, `rules-of-hooks` and `exhaustive-deps` as errors, and
the formatting the code already follows (`frontend/eslint.config.js`).
`npm run check` runs lint, `tsc` and Vitest, the three steps of CI's frontend
job. Still untested as a unit: the review-page promotion gate (§6, P1-d).

---

## 5. Coverage of the June 2026 features (evidence labels, consensus, provenance)

| Feature | Unit | Integration | End-to-end | Status |
|---|---|---|---|---|
| Evidence labels (schema, prompt, normalize, STIX) | ✅ | ✅ persistence round-trip + route CRUD | ✅ via mock_llm | **good** |
| Cross-model consensus | ✅ `reconcile()` | ❌ worker wiring (`consensus_enabled` gate, double-run) | n/a | **partial** |
| STIX provenance (TLP + author) | ✅ | ✅ (built into `build_stix_bundle`, covered) | ✅ in bundle | **good** |

---

## 6. Open gaps — prioritized

### P1 — introduced by the new features (close these first)

- **a. ✅ DONE — `mock_llm` now carries `evidence_label`.** `conftest.mock_llm_response`
  labels its relationship `observed`; `test_stage3.py::test_relationship_carries_evidence_label`
  asserts it survives `enrich_chunk`'s normalise → validate → filter path.
- **b. ✅ DONE — persistence round-trip covered.** `test_persistence.py` writes via
  `worker._save_entities`, reads back through `re_run_final_stages` into the bundle,
  covers the NULL-label legacy default, and asserts migration idempotency.
- **c. ✅ DONE — relationships route covered.** `test_relationships_api.py` covers
  create/read/patch of `evidence_label`, the default + unknown-label coercion, and
  `PATCH evidence_label="bogus"` → 400.
- **d. Promotion gate (frontend) untested.** The evidence-graded auto-accept in
  `Review.tsx` is now real logic (`observed` auto-promotes; `inferred`/`gap` never
  do). → Extract it to a pure `shouldAutoAcceptRelationship(conf, label, accepted)`
  helper and unit-test it with Vitest (see §7 for the table).
- **e. Consensus worker wiring untested.** Only `reconcile()` is covered; the
  `consensus_enabled()` gate and the "only double-run chunks with relationships"
  guard are not. → Unit-test `consensus_enabled()` across env combinations
  (off; provider unset; provider == primary → disabled).

### P2 — pre-existing gaps the new work made visible

- **f. Stage 3c (MITRE normalisation)** has no test file. Consensus and evidence
  grading both feed it. → `test_stage3c.py`: fuzzy-match score tiers (≥85 canonical,
  70–84 keep-phrasing, <70 passthrough).
- **g. ✅ DONE — Stage 3d (relationship self-verification)** is covered by
  `test_stage3d_verify.py` (whole text, batching, document mode).
- **h. ✅ DONE — Strict STIX validator path.** The JSON schemas ship with the
  repository (ADR-0069, amendment of 2026-10-10). `test_stage5.py` validates
  Stage 4's bundles, `x_evidence_label` and `x_synthesis_stats` included, with
  the network blocked. It also checks that the validator refuses what the
  stix2 library lets through.

### P3 — longer horizon

- **i. Full-pipeline integration test** — done (ADR-0059):
  `tests/test_orchestrator.py::test_worker_and_cli_run_the_same_pipeline` runs
  `worker._run_pipeline` and the `main.py` CLI on one fixture with the LLM mocked
  and checks both build the same bundle.
- **j. Frontend interaction tests** for the relationship rail / graph editor.
  The rail has some (vitest, `RelationshipRail.test.tsx`): dates (ADR-0063),
  "to review", groups by target and their one-click decision (ADR-0065).

---

## 7. Example test cases for P1

**Promotion gate (P1-d)** — once extracted to a pure helper:

| confidence | evidence_label | accepted | expected auto-accept |
|---:|---|---|---|
| 0.95 | observed | null | ✅ true |
| 0.50 | observed | null | ✅ true (label wins) |
| 0.95 | reported | null | ✅ true (high conf) |
| 0.95 | inferred | null | ❌ false (weak label blocks) |
| 0.95 | gap | null | ❌ false |
| 0.95 | observed | false | ❌ false (already decided) |

**Persistence round-trip (P1-b):**
```python
def test_relationship_evidence_label_survives_db_roundtrip(tmp_job):
    # _save_entities writes a relationship with evidence_label="observed"
    # re_run_final_stages reads it back into RelationshipExtracted
    # assert the rebuilt relationship.evidence_label == EvidenceLabel.OBSERVED
```

**Route validation (P1-c):**
```python
def test_patch_rejects_unknown_evidence_label(api_client, job_with_rel):
    r = api_client.patch(f"/api/jobs/{job}/relationships/{rid}",
                         json={"evidence_label": "bogus"})
    assert r.status_code == 400
```

---

## 8. Coverage floors & CI

Coverage is measured with branches (`[tool.coverage.run] branch = true`) over
`pipeline/`, `api/` and `models/`, minus the copied OpenCTI Snort parser.
The floors are what CI's fast job measured on 2026-10-03, rounded down:
they stop a slide, they are not targets. Raise one when its area gains tests.

| Floor | Measured | Enforced by |
|---|---:|---|
| Total | 87% (88.0%) | `fail_under` in `pyproject.toml`, through `pytest --cov` |
| STIX mapping and validation (Stage 4, Stage 5, the ledger, ids, the OpenCTI pattern gates) | 92% (92.7%) | `scripts/check_coverage.py` |
| Persistence (`api/db*.py`, `api/storage.py`, `api/worker.py`, `api/paths.py`) | 91% (91.8%) | `scripts/check_coverage.py` |

**CI jobs** (`.github/workflows/ci.yml`). The image is published only when
the first four pass:
1. **fast-tests** (every push and PR): `ruff check .`, `mypy` (scope and flags
   in `pyproject.toml`), every test with `CTIPARSOR_REQUIRE_TEST_DEPS=1`, the
   coverage floors. Installs the OpenCTI pattern parsers, google-re2 and
   numpy, but not torch/transformers (`SKIP_HEAVY_MODELS=1`). No secrets. On
   a PR, also migrates a database written by the base commit's code
   (`scripts/check_migration_from.py`, ADR-0077).
2. **frontend-tests**: `npm run lint`, `npm run typecheck`, `npm test`.
3. **container-image**: builds the image, runs `scripts/docker_smoke.sh`, and
   scans the image with Grype into Code scanning (not a gate, ADR-0078).
4. **dependency-audit**: `pip-audit` on the Python locks and `npm audit` on the
   UI's production packages (ADR-0075, ADR-0080). It also runs weekly.
5. **dependency-review** (pull requests only): fails a PR that adds a
   dependency with a known high or critical vulnerability (ADR-0078).
6. **model-tests** (pushes to main only, not a gate): the same suite with the
   models downloaded and a live API key; it may fail for reasons outside the code.
7. **publish-image** (pushes to main only): pushes the image to GHCR with its
   SBOM and signed attestations, after jobs 1 to 4.

Three more workflows run beside it. **Fuzzing** (`fuzz.yml`) runs the four
targets above, and its four jobs are required checks. **CodeQL**
(`codeql.yml`) analyses Python, TypeScript and the workflows. **Scorecard**
(`scorecard.yml`) rates the repository's practices; it tests nothing.

`make ci` runs jobs 1 and 2 locally, in the `dev` and `frontend-dev` containers.
