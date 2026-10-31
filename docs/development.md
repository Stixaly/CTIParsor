# Development guide

How to work on CTIParsor: the `make` targets, the tests and quality benchmarks,
where everything lives, and the usual extension points. Conventions and the
green-build checklist are in [CONTRIBUTING.md](../CONTRIBUTING.md); the test
strategy is in [TESTING.md](../TESTING.md).

- [make shortcuts](#make-shortcuts)
- [Run tests](#run-tests)
- [Measure extraction quality (offline)](#measure-extraction-quality-offline)
- [Project structure](#project-structure)
- [Extending the pipeline](#extending-the-pipeline)

## make shortcuts

A `Makefile` wraps the most common workflows — every target that touches
Python routes through `docker compose run --rm dev`, Node through
`frontend-dev` (ADR-0054), so `make` itself is the only thing that needs to
be on the host besides Docker.

| Command | Description |
|---|---|
| `make setup` | Prepare `.env` + the DB-password secret, check Docker (runs `setup.sh`) |
| `make package-offline` | Build the air-gap bundle in `offline/`, pack it into `dist/` (ADR-0054) |
| `make setup-offline` | Install from an extracted air-gap bundle, no network needed |
| `make corpora` | Clone/pull the rule corpora (Sigma, Suricata, YARA) |
| `make detection-index` | Parse the clones into the rule store (dedups, writes rule sizes) |
| `make backfill-rules` | Backfill rule body sizes on a store built before ADR-0022 |
| `make test` | Run all tests, in the `dev` container |
| `make test-fast` | Quicker loop: also skips every test whose id contains `llm` (not what CI runs) |
| `make lint` / `make typecheck` | `ruff check .` / `mypy`, scope and rules from `pyproject.toml` |
| `make coverage` | All tests with branch coverage, then the floors CI enforces (total and per area) |
| `make frontend-check` | ESLint, `tsc` and Vitest (`npm run check`), in the `frontend-dev` container |
| `make ci` | Every check the pull-request CI runs, locally (the four above) |
| `make run` | Run pipeline on `tests/fixtures/sample_report.txt` |
| `make run-dir` | Run pipeline on every file in `input/` |
| `make check` | Diagnostic: list which pipeline stages are available |
| `make check-docs` | Verify every number claimed in the README and `docs/pipeline.md` against the source of truth (CI runs the same check through `tests/test_doc_claims.py`) |
| `make contract` | Record the stable contract of `docs/support-policy.md` in `contract/*.json`; refuses a breaking change unless `ACCEPT_BREAKING=1` (`scripts/contract.py`, ADR-0094 item 1). CI checks it through `tests/test_contract.py` |
| `make audit` | Scan Python + npm deps for known CVEs (`pip-audit` + `npm audit`), no image build needed |
| `make lock` | Resolve `requirements/requirements*.txt` into the hashed locks the image, CI and the audit install with `pip install --require-hashes` (`scripts/lock.sh`, ADR-0080) |
| `make update-deps` | Re-resolve to the newest versions the ranges allow, rebuild the image from the new lock, run tests |
| `make npm-outdated` | Show which npm packages have newer versions available |
| `make npm-update` | Upgrade npm packages within semver ranges, verify TypeScript |
| `make clean` | Remove generated bundle JSONs and `__pycache__` (host-side only) |
| `make docker-build` | Build the container image, stamping the git revision (ADR-0044) |
| `make docker-up` | Start the container stack on `http://127.0.0.1:8000` |
| `make docker-bootstrap` | One-shot in the container: download models, clone corpora, build the rule store |
| `make docker-smoke` | Build, start and verify the image (health, non-root, read-only root, Chromium sandbox) |
| `make docker-logs` / `make docker-down` | Follow the API logs / stop the stack (volumes are kept) |
| `make docker-test` | Alias for `make test` |
| `make docker-frontend-dev` | Start the Vite dev server with HMR, in a container — `http://localhost:5173` |

## Run tests

```bash
docker compose run --rm dev pytest -v      # all tests (make test); no API key needed, the LLM is mocked
make ci                                    # lint, types, tests + coverage floors, frontend (what it leaves to CI: CONTRIBUTING.md)
```

`CTIPARSOR_TEST_DATABASE_URL` is already set for the `dev` service in
`compose.yaml` (ADR-0054) — no manual export needed.

## Fuzzing

`fuzz/` holds five Atheris targets for the code that reads attacker-controlled
input (ADR-0081): report text (`fuzz_report_text`), dates (`fuzz_dates`), the
gates quoted rules go through (`fuzz_rule_gates`), the prompt enclosure
(`fuzz_spotlight`), and the baseline STIX bundle an analyst supplies
(`fuzz_baseline_intake`, ADR-0090; the workflow gives it `-max_len=65536`, the
others 16384). The `Fuzzing` workflow runs each for 60 s on a pull
request and 10 minutes weekly; `tests/test_fuzz_targets.py` runs them over
their seeds in the ordinary suite. Atheris installs on Linux x86_64 only
(`requirements/requirements-dev.txt`). To fuzz locally, give libFuzzer a *copy* of the
seeds — it writes what it finds into the corpus directory:

```bash
cp -r fuzz/corpus/rule_gates /tmp/corpus && python fuzz/fuzz_rule_gates.py -max_total_time=300 -timeout=10 /tmp/corpus
```

A failing run in CI uploads the input as the `fuzz-crash-<target>` artifact;
`python fuzz/fuzz_<target>.py <that file>` replays it. Add the input to
`fuzz/corpus/<target>/` once fixed, so the seed test keeps it fixed.

## Measure extraction quality (offline)

Three benchmarks live in `tests/eval_pipeline.py` — recall (`ner`, `ate`) and a
**hallucination-rate** benchmark (`grounding`) that scores how much emitted output
is *not* supported by the source text (ADR-0012). It reuses the pipeline's own
grounding primitive, runs fully offline, and can score reports you have already
processed straight from the job store (`DATABASE_URL`):

```bash
# Hallucination rate on your real processed reports, segmented + alias/technique-aware
docker compose run --rm dev python tests/eval_pipeline.py -b grounding --from-db all \
    --rel-window 1 --alias-aware --rel-proximity 200

# ATT&CK Technique Extraction recall vs the GPT-4 baseline
docker compose run --rm dev python tests/eval_pipeline.py -b ate --stage all

# The same, through the application's pipeline (LLM required; ADR-0059)
docker compose run --rm dev python tests/eval_pipeline.py -b ate --stage full
```

`--stage full` stops with an error when no LLM provider is configured instead of
quietly scoring regex + semantic; `--allow-degraded` scores it anyway and lists
the stages that did not run.

**Document-level evaluation (ADR-0060).** `python -m evaluation` scores the
application's pipeline on AnnoCTR (120 annotated vendor reports, official
temporal split) and on an in-house set annotated from the original files
(IoCs, relationships, negative cases), compares configurations with a paired
bootstrap on the same documents, and measures Stage 2c's candidate recall.
Protocol, commands and the decision rule: [docs/eval/README.md](eval/README.md).

Relationships are reported in two segments — **named-entity** vs **IoC/technical**
— because a single global number blends two very different regimes. Use this to
validate any extraction change before/after.

## Project structure

```
CTIParsor/
│
├── main.py                        # CLI entry point
├── evaluation/                    # Evaluation protocol: AnnoCTR, in-house set, paired comparisons (ADR-0060)
├── contract/                      # The stable contract, recorded by make contract and checked by tests/test_contract.py (ADR-0094 item 1)
│
├── pipeline/
│   ├── stage1_ingestion.py        # Parsing, defanging, chunking + overlap
│   ├── stage1f_figures.py         # Figure triage, crop rendering and report_text injection (ADR-0032)
│   ├── stage2_extraction.py       # Regex IoC extraction + spaCy fallback
│   ├── stage2b_gazetteer.py       # Aho-Corasick gazetteer NER (1 114 entities)
│   ├── gazetteer_policy.py        # The ordinary-word policy: RETAIN, CASE, CONTEXT per form, GAZETTEER_POLICY off/shadow/apply
│   ├── gazetteer_context.py       # Its step 2: the naming constructions that let a CONTEXT form count as a name
│   ├── stage2c_ttp_semantic.py    # Sentence-transformer TTP detection
│   ├── stage2d_cyner.py           # CyNER 2.0 cybersecurity NER (DeBERTa-v3)
│   ├── ner_precision.py           # CyNER actors and spaCy places must look like names (ADR-0088)
│   ├── stage2e_gliner.py          # GLiNER / NuNER zero-shot NER
│   ├── stage2g_alias_list.py      # "X (aka Y, Z)" alias lists → threat actors (regex)
│   ├── stage2f_cve_enrichment.py  # CVE description + CVSS v3 from the cve_cache table / CIRCL (opt-in)
│   ├── stage3_llm.py              # LLM enrichment, parallel + checkpoint
│   ├── stage3b_validate.py        # Post-LLM hallucination filter
│   ├── stage3c_mitre.py           # MITRE ATT&CK TTP normalisation
│   ├── stage3d_verify.py          # Relationship self-verification
│   ├── stage3e_consensus.py       # Cross-model consensus (opt-in)
│   ├── stage3f_ttp_verify.py      # TTP self-verification (ADR-0011) — TTP_MODE=verify
│   ├── stage3f_ttp_select.py      # Choose techniques among retrieved candidates, with a quote (ADR-0072) — TTP_MODE=select
│   ├── ttp_retrieval.py           # ATT&CK candidate retrieval: BM25 + dense over descriptions and procedures (ADR-0072)
│   ├── stage4_stix_mapping.py     # STIX 2.1 mapping + TLP/PAP + authoring identity
│   ├── named_entities.py          # The detectors' names reach the bundle on every path; one type per name (ADR-0092)
│   ├── benign.py                  # Values a report names without accusing them: their SCO, no Indicator
│   ├── stix_ids.py                # STIX ids computed the way OpenCTI computes its standard ids (ADR-0066)
│   ├── bundle_ledger.py           # What Stage 4 did with each row: kept, rewritten, dropped, why (ADR-0061)
│   ├── temporal.py                # Relationship dates as the source states them (ADR-0063)
│   ├── network_traffic.py         # Analyst-typed traffic ("tcp/443 to evil.example") → network-traffic SCO (ADR-0069)
│   ├── stage4b_graph_completion.py # Alias merge + ATT&CK grounding + transitive (ADR-0013)
│   ├── stage4c_long_distance.py   # LLM long-distance relation inferer (opt-in)
│   ├── stix_rel_spec.py           # STIX 2.1 suggested-relationship table (spec guard)
│   ├── stage5_validation.py       # Bundle validation + export
│   ├── baseline_stix.py           # Reads an analyst's STIX 2.1 baseline; Stage 3r matches the run to it, Stage 4 merges it into the bundle (ADR-0090)
│   ├── bundle_revisions.py        # Which stored bundles predate an output fix, judged on the run or the build by the fix's scope (ADR-0035, ADR-0086)
│   ├── mitre_db.py                # Lazy-loaded MITRE index (techniques + tactics)
│   ├── vlm.py                     # Provider-agnostic vision backends + capability probe (ADR-0033)
│   ├── vllm_options.py            # vLLM request options shared by Stage 3 and Stage 1f
│   ├── llm_stats.py               # Counts what the LLM stages actually got back (ADR-0060)
│   ├── figure_store.py            # report_figures / figure_reads persistence + span lookup
│   ├── web_capture.py             # Render an arbitrary web page to PDF, safely (ADR-0029)
│   ├── aliases.py                 # Alias canonicalisation for named entities (ADR-0012)
│   ├── attack_data.py             # Which ATT&CK release the pipeline reads: the default track or pipeline/data/attack/<X.Y>/, by ATTACK_RELEASE (ADR-0087)
│   ├── evidence_span.py           # Locate LLM quotes in source text, return char offsets
│   ├── llm_parse.py               # Parsing helpers for LLM responses shared by verification stages
│   ├── stix_access.py             # Uniform field access for STIX objects (dict or stix2 instance)
│   ├── orchestrator.py            # The one pipeline (Stages 1-5) for worker, CLI and benchmark (ADR-0059)
│   ├── decisions.py               # Who decided each accept/reject; server-side auto-accept (ADR-0058)
│   ├── thresholds.py              # Per-(source, type) NER cutoffs at runtime (ADR-0051)
│   ├── calibration.py             # Fit those cutoffs from analyst decisions (ADR-0051)
│   ├── overrides.py               # Deny / promote lists at runtime (ADR-0052)
│   ├── promotion.py               # Grow those lists from analyst decisions (ADR-0052)
│   ├── registry.py                # Stage Registry — unused since ADR-0059 (orchestrator.py owns Stage 2)
│   ├── base.py                    # ExtractionStage protocol + BaseExtractionStage
│   ├── env_flags.py               # Single vocabulary for boolean environment flags
│   ├── regex_safety.py            # ReDoS-safe regex compilation through re2 (ADR-0049)
│   ├── security.py                # Path-containment check (Zip Slip / path traversal guard)
│   ├── detection/                 # Detection-rule ingestion + coverage (ADR-0006)
│   │   ├── base.py                # RuleCorpusAdapter (pluggable format seam)
│   │   ├── sigma.py               # SigmaAdapter (YAML → DetectionRule)
│   │   ├── suricata.py            # SuricataAdapter (rule text → DetectionRule, ADR-0015)
│   │   ├── yara.py                # YaraAdapter (rule text → DetectionRule, ADR-0015)
│   │   ├── registry.py            # Two-tier corpus registry + overlay writes
│   │   ├── store.py               # detection_rules / rule_techniques / rule_atoms persistence
│   │   ├── coverage.py            # Technique → 0–3 readiness scoring (superseded by ADR-0025)
│   │   ├── artifacts.py           # Artifact → 0–3 evidence scoring, Pyramid tiers (ADR-0025)
│   │   ├── phases.py              # ATT&CK phase band: report row vs covered row (ADR-0025)
│   │   ├── atoms.py               # Sigma detection block → atoms + platform (ADR-0014)
│   │   ├── suricata_atoms.py      # Suricata sticky-buffer → atoms (ADR-0015)
│   │   ├── yara_atoms.py          # YARA strings/condition → atoms (ADR-0015)
│   │   ├── observables.py         # Report entities → normalized observables (ADR-0014)
│   │   ├── relevance.py           # IDF-weighted rule ranking + evidence (ADR-0014)
│   │   ├── dedup.py               # Cross-corpus rule dedup, `related:` folding (ADR-0017)
│   │   ├── synth_sigma.py         # Report-derived Sigma synthesis (ADR-0016)
│   │   ├── yara_check.py          # A quoted YARA rule ships only if it compiles (ADR-0067)
│   │   ├── pattern_check.py       # A quoted Sigma/Suricata/Snort rule ships only if OpenCTI's parser accepts it (ADR-0070)
│   │   ├── opencti_snort/         # OpenCTI's own Snort parser, copied in (ADR-0070)
│   │   ├── tlds.py                # TLD table backing the hostname gate (ADR-0015)
│   │   ├── sync.py                # Corpus clone/pull driver
│   │   ├── builder.py             # Rebuild the rule store from local clones
│   │   ├── brands.py              # Brand token extraction from campaign domains (ADR-0031)
│   │   ├── control.py             # Observable discrimination (ADR-0030)
│   │   └── textutil.py            # Text primitives shared by the atom extractors
│   └── data/
│       ├── mitre_index.json       # Compact ATT&CK index (built by build_indexes.py)
│       ├── gazetteer.json         # Named-entity dictionary
│       ├── gazetteer_policy.json  # Decision per gazetteer form (CASE, CONTEXT, RETAIN), built by build_gazetteer_policy.py
│       ├── gazetteer_context_rules.json # The naming constructions that qualify each CONTEXT form (step 2)
│       ├── warninglists.json      # MISP warninglists (CC0) behind benign.py: security vendors' blogs, sandboxes, the 10,000 most popular domains
│       ├── attack_revoked.json    # Revoked ATT&CK ids and what replaced them
│       ├── attack_relationships.json # 20 015 curated ATT&CK edges (Stage 4b grounding)
│       ├── attack_manifest.json   # The default track's release (19.2), what was checked against a rebuild, sha256 of its files (ADR-0087)
│       ├── attack/20.0/           # The v20.0 track: the same index files built from ATT&CK v20.0, with its own attack_manifest.json (ADR-0087)
│       ├── mitre_embeddings.npy   # Pre-computed TTP embeddings
│       ├── mitre_embeddings_meta.json
│       ├── mitre_embeddings_manifest.json # Model + thresholds of the cache (generated, not in git)
│       └── attack_retrieval_*     # TTP_MODE=select corpus (built by --only retrieval, committed)
│
├── scripts/
│   │  ── build and operate ──
│   ├── build_indexes.py           # Build the pipeline/data/ indexes (--only retrieval for TTP_MODE=select; --out-dir, --capec-index for a track)
│   ├── download_attack.py         # Download enterprise-attack.json from mitre/cti master, or with --release X.Y the three bundles of an attack-stix-data release, sha256-checked; `--out DIR` (with `--release`) picks the folder, default `data/attack-stix/v<X.Y>/` (ADR-0087)
│   ├── build_attack_release.py    # Build the ATT&CK track pipeline/data/attack/<X.Y>/ from those bundles (ADR-0087)
│   ├── sync_corpora.py            # Clone/pull rule corpora (ambient git auth) + tarball fetch (ET Open)
│   ├── build_detection_index.py   # Parse clones → detection-rule store
│   ├── build_rule_atoms.py        # Backfill rule_atoms from stored bodies (ADR-0014)
│   ├── build_rule_text.py         # tsvector index over rule titles, for brand evidence (ADR-0031/0053)
│   ├── backfill_rule_bytes.py     # Backfill rule_bytes on an older store (ADR-0022)
│   ├── calibrate_thresholds.py    # Propose / --apply NER cutoffs from analyst decisions (ADR-0051)
│   ├── promote_overrides.py       # Propose / --apply deny + promote rules from decisions (ADR-0052)
│   ├── package_offline_docker.sh  # Build the air-gap bundle (ADR-0054)
│   ├── check_offline_bundle_docker.sh # Verify an air-gap bundle restores and runs
│   ├── check_offline_images.sh    # Air-gap bundle images resolve by the names Compose uses after save/load (CI)
│   ├── offline_lib_docker.sh      # Functions shared by check_offline_bundle_docker.sh and setup.sh --offline
│   ├── package_offline_corpora.sh # Corpora-only refresh bundle (cti-cache's corpora/) for an air-gapped install
│   ├── update_offline_corpora.sh  # Install a corpora bundle and rebuild the rule store; the job store is not touched
│   ├── docker_smoke.sh            # Build, start and verify the container stack (make docker-smoke)
│   ├── smoke_stage_report.py      # The --job judge of docker_smoke.sh: reads a job's stage report, standard library only (ADR-0054)
│   ├── release.py                 # Release process: the version, the tag check, the notes, the release PR (ADR-0085, docs/releasing.md)
│   ├── release_files.sh           # A release's files and notes, from the image main's CI built and attested (ADR-0085)
│   ├── migrate_jobs_to_postgres.py # One-shot copy of a cti_stix.db job store into PostgreSQL (ADR-0045)
│   ├── migrate_rules_to_postgres.py # The same for the rule store (ADR-0053)
│   ├── build_gazetteer_policy.py  # The ordinary-word policy, pipeline/data/gazetteer_policy.json, from docs/gazetteer-ordinary-words.md
│   │  ── checks and diagnostics ──
│   ├── check_stages.py            # Diagnostic: which stages are available (make check)
│   ├── check_doc_claims.py        # Doc drift guard: documented numbers vs source (make check-docs)
│   ├── check_coverage.py          # Per-area coverage floors on top of the total one (make coverage)
│   ├── contract.py                # Record (make contract) or check the stable contract in contract/ (ADR-0094 item 1)
│   ├── check_flag_equivalence.py  # env_bool vs the old per-flag parsing, value by value
│   ├── check_unescape_equivalence.py # A/B of the atom unescape refactor on real corpus data
│   ├── check_evidence_gate.py     # Validate the coverage evidence gate on the store (ADR-0030)
│   ├── opencti_import_check.py    # Check A4 (ADR-0090): what OpenCTI keeps of an enriched bundle, in a throwaway instance (TESTING.md § Measuring baseline reconciliation and the OpenCTI import)
│   │  ── read-only audits and measurements (the numbers quoted in the ADRs) ──
│   ├── audit_api_edge_cases.py    # GET-only API edge-case conformance harness
│   ├── audit_bundle_invariants.py # Invariants over every stored STIX bundle
│   ├── audit_coverage_formats.py  # Per-format breakdown + drill-down latency
│   ├── audit_edge_provenance.py   # Share of bundle edges carrying x_evidence_label, by label
│   ├── audit_graph_completion.py  # Replay Stage 4b over stored bundles (ADR-0013)
│   ├── audit_store_invariants.py  # Invariants over the rule/entity store
│   ├── audit_yara_escape_impact.py # Impact of the YARA unescape-order defect (ADR-0015)
│   ├── audit_yara_parsing.py      # The YARA parser against real corpora (ADR-0015)
│   ├── baseline_ablation.py       # Recovery and duplicates of the baseline reconciliation, read only (ADR-0090; TESTING.md § Measuring baseline reconciliation and the OpenCTI import)
│   ├── baseline_round_trip.py     # Round trip of the enriched bundles on the real reports, offline (ADR-0090; TESTING.md § Measuring baseline reconciliation and the OpenCTI import)
│   ├── measure_advisory_gate.py   # What the TTP advisory gate drops on real reports
│   ├── measure_cold_start.py      # Import + model-load cost of a worker process
│   ├── measure_corpus_ingest.py   # Ingest chosen corpora into a scratch DB, report per-format stats
│   ├── measure_figure_iocs.py     # Are the vision model's `iocs` grounded in its own transcription
│   ├── measure_gazetteer_policy.py # Stage 2b with and without the ordinary-word policy, on AnnoCTR train and dev (docs/eval/gazetteer-policy-2026-10.md)
│   ├── measure_graph_links.py     # Bundle connectivity and sentence co-mention candidates
│   ├── measure_image_surface.py   # How much of a corpus is images, and how many survive triage
│   ├── measure_negated_atoms.py   # Before/after of the ADR-0034 negation fix on the store
│   ├── measure_ner_precision.py   # Entity precision filters on AnnoCTR: run, status, replay, compare, gates (ADR-0088, ADR-0089)
│   ├── measure_normalize_divergence.py # Divergences between the three atom normalizers
│   ├── measure_pin_allocation.py  # Pin edges under sequential vs fair-share budgets (ADR-0026)
│   ├── measure_relevance.py       # Proposed-rule relevance on real reports
│   ├── measure_review_revision_trigger.py # Row vs statement trigger for review_revision, in a throwaway schema (ADR-0086)
│   ├── measure_stage1f_tradeoffs.py # Crop vs whole page: tokens, latency, kind accuracy
│   ├── measure_ttp_vs_observable_coverage.py # Technique coverage vs evidence-backed coverage
│   ├── measure_web_capture.py     # PDF capture and ingestion quality of the URL tab
│   ├── probe_ttp_recall_caps.py   # Stage 2c's two recall caps on real reports (ADR-0023)
│   ├── probe_vlm_figures.py       # Compare vision providers on a PDF's figures, no DB write
│   ├── rebuild_bundle_provenance.py # Rebuild a bundle in memory, audit edge provenance
│   ├── validate_artifact_coverage.py # Validation harness for artifact coverage (ADR-0025)
│   ├── verify_ate_scorer.py       # Mutation harness for the ATE scorer (ADR-0023)
│   └── verify_ner_scorer.py       # Mutation harness for the NER scorer
├── models/
│   ├── schemas.py                 # Pydantic: RawEntity, EntityType, EvidenceLabel
│   ├── config.py                  # PipelineConfig (chunk size, model ids, env binding)
│   └── detection.py               # Pydantic: DetectionRule, Severity
│
├── api/
│   ├── main.py                    # FastAPI app, SPA static serving
│   ├── body_limit.py              # Request body budgets, per route and 1 MB for the rest, counted as the body arrives (413)
│   ├── db.py                      # Job store + rule store, both PostgreSQL via DATABASE_URL — ADR-0045, ADR-0053
│   ├── db_backend.py              # PostgreSQL adapter: `?`→`%s`, sqlite3.Row-like rows, non-closing `with`
│   ├── migrate.py                 # Bring the database to this code's schema version, under an advisory lock (ADR-0077)
│   ├── db_identity.py             # Which PostgreSQL cluster each database was on, to tell an empty new major from a fresh install (ADR-0077)
│   ├── baseline_store.py          # The job store's side of a baseline: job_baselines, logged exclusions, the worker's schema check (ADR-0090)
│   ├── worker.py                  # The pipeline subprocess: spawn, crash-to-`failed`, SSE emitter
│   │                              #   └─ re_run_final_stages(): Finalize, Stages 4–5 on the accepted rows,
│   │                              #      read in one snapshot, published by one conditional UPDATE (ADR-0086)
│   ├── queue_loop.py              # Claims queued jobs, heartbeats, requeues orphans (ADR-0046)
│   ├── run_config.py              # Capture a job's execution config so its bundle is reproducible (ADR-0024),
│   │                              #   and the record of each build, run or finalize (ADR-0086)
│   ├── storage.py                 # Storage abstraction for pipeline job state
│   ├── paths.py                   # Where uploads and bundles live (CTIPARSOR_UPLOADS_DIR / _OUTPUT_DIR)
│   ├── logging_config.py          # Centralized logging configuration
│   └── routes/
│       ├── upload.py              # POST /api/upload (50 MB limit, streamed)
│       ├── ingest.py              # POST /api/ingest/{text,url} — paste + URL capture
│       ├── jobs.py                # CRUD /api/jobs + finalize + source + bundle + bundle ledger
│       ├── entities.py            # CRUD /api/jobs/{id}/entities
│       ├── relationships.py       # CRUD /api/jobs/{id}/relationships + bulk decisions
│       ├── progress.py            # GET /api/jobs/{id}/progress (SSE)
│       ├── coverage.py            # GET /api/jobs/{id}/coverage + detection-corpora
│       ├── queue.py               # GET /api/queue/status — backlog + worker liveness (ADR-0048)
│       ├── settings.py            # Corpora management (ADR-0007)
│       ├── policy.py              # Relationship policy: pinned rules + completion block
│       ├── thresholds.py          # /api/thresholds — NER cutoffs, recalibration (ADR-0051)
│       ├── overrides.py           # /api/overrides — deny / promote lists (ADR-0052)
│       ├── attack.py              # GET /api/attack/index — the selected ATT&CK track's index (ADR-0087)
│       ├── baselines.py           # GET /api/baselines/status, POST /api/baselines/inspect — the STIX bundle to enrich (ADR-0090)
│       └── _common.py             # Guards shared by the job-scoped route modules
│
├── frontend/                      # React 18 + TypeScript + Vite 6
│   ├── src/
│   │   ├── pages/
│   │   │   ├── Dashboard.tsx      # Kanban, stat ribbon, progress modal
│   │   │   ├── Review.tsx         # Text / Preview / Source view + marginalia
│   │   │   ├── Graph.tsx          # d3-force graph + relationship editor
│   │   │   ├── Coverage.tsx       # Coverage matrix + granular rule selection
│   │   │   ├── Settings.tsx       # Corpus management panel
│   │   │   └── Policy.tsx         # Relationship policy editor (pin / auto, completion flags)
│   │   ├── components/
│   │   │   ├── MarkdownPreview.tsx # VS Code-like .md renderer (react-markdown)
│   │   │   ├── SourceViewer.tsx    # Inline original-file view (PDF/HTML/TXT/MD)
│   │   │   ├── PdfViewer.tsx       # pdf.js pages + entity-highlight overlay
│   │   │   ├── ProgressModal.tsx   # 5-stage SSE progress display
│   │   │   ├── EntityPopover.tsx   # Entity type picker
│   │   │   └── review/
│   │   │       ├── DocumentReader.tsx  # Annotated text with entity marks
│   │   │       ├── Marginalia.tsx      # Sidebar entity cards
│   │   │       ├── RelationshipRail.tsx# Sticky relationships panel
│   │   │       └── …
│   │   ├── components/coverage/   # Detection coverage (ADR-0022)
│   │   │   ├── FormatBoard.tsx    # One card per format: counts, size, per-technique ticks
│   │   │   ├── DrillInStrip.tsx   # A technique's rules in three format columns
│   │   │   ├── CoverageExportPanel.tsx # Selection table + live archive preview
│   │   │   ├── TriCheckbox.tsx    # ✓ / – / empty marker used at every scope
│   │   │   ├── tactics.ts         # The fifteen tactic columns, checked against every ATT&CK track
│   │   │   └── model.ts           # TechEntry — the shared per-technique shape
│   │   ├── components/graph/
│   │   │   ├── GraphCanvas.tsx    # d3-force SVG renderer, STIX icons
│   │   │   └── graphLayout.ts     # Tier map, radii, static layouts, icon paths
│   │   ├── hooks/
│   │   │   ├── useSSE.ts          # EventSource (5-retry on transient error)
│   │   │   ├── useAttackIndex.ts  # The ATT&CK index of the release the API runs (ADR-0087)
│   │   │   ├── useMitreSearch.ts  # Client-side ATT&CK search over that index
│   │   │   ├── useCoverage.ts     # Coverage data hook (view ↔ source seam)
│   │   │   ├── useRuleSelection.ts # Rule selection as an exclusion set (ADR-0022)
│   │   │   ├── usePromotedRules.ts # Rules promoted from the Detections tab into the coverage selection
│   │   │   ├── usePref.ts         # A UI preference kept in localStorage
│   │   │   └── sets.ts            # Set<string> load/save helpers shared by the two hooks above
│   │   ├── api/client.ts          # Typed fetch wrappers
│   │   ├── context/ThemeContext.tsx # 5 themes × 7 accent palettes
│   │   └── types/index.ts         # Shared TS types
│   └── public/
│       ├── stix-icons/            # 27 white STIX 2.1 SVG icons, EclecticIQ's stix-icons (CC BY-SA 4.0)
│       └── stix-viz/              # OASIS cti-stix-visualization, for the graph view (THIRD_PARTY_NOTICES.md)
│
├── tests/                         # test_*.py modules — map and counts in TESTING.md
│   ├── test_stage1.py             # Ingestion, chunking, overlap, defanging
│   ├── test_stage2.py             # IoC extraction, refanging, deduplication
│   ├── test_stage4.py             # STIX mapping
│   ├── …                          # one module per stage + per ADR feature
│   ├── eval_pipeline.py           # Offline quality benchmarks (ATE, grounding)
│   ├── fixtures/sample_report.txt
│   └── fixtures/baselines/        # Hand-written STIX bundles of the baseline tests (ADR-0090, see the README there)
│
├── input/                         # Drop CTI reports here (gitignored)
├── output/                        # Generated STIX bundles (gitignored)
├── uploads/                       # Web UI uploads (gitignored)
│
├── detection_corpora.yaml         # Public corpus registry — Sigma, YARA, Suricata (committed)
├── detection_corpora.local.yaml.example  # Private corpus overlay template
├── docs/
│   ├── architecture.md            # Deployment architecture: processes, stores, data flow, sizing
│   ├── docker.md                  # Running the container stack day to day
│   ├── upgrading.md               # Runbook: moving an existing install to PostgreSQL / workers
│   ├── deployment.md              # Serving several analysts: bind address, exposure, TLS proxy, systemd
│   ├── detection-coverage.md      # The coverage matrix, walkthrough
│   ├── pipeline.md                # Every stage, the quality layers, ATT&CK data, offline support
│   ├── configuration.md           # The full `.env` reference
│   ├── web-ui.md                  # The analyst interface, page by page
│   ├── stix-output.md             # Which STIX object each extracted value becomes
│   ├── api.md                     # REST API reference
│   ├── database-schema.md         # Job store + rule store tables
│   ├── development.md             # This guide
│   ├── dependencies.md            # Packages, lock files, maintenance routine
│   ├── openssf-best-practices.md  # The OpenSSF Best Practices self-assessment, criterion by criterion
│   ├── eval/                      # Evaluation protocol and baselines (ADR-0060)
│   └── adr/                       # Architecture Decision Records (see docs/adr/README.md)
├── TESTING.md                     # Test strategy
├── LICENSE                        # Apache-2.0, CTIParsor's licence
├── LICENSES/                      # Every licence a file in the repository is under
├── REUSE.toml                     # Copyright and licence per file, checked by `reuse lint`
├── THIRD_PARTY_NOTICES.md         # The files copied from other projects, their sources and licences
├── .env                           # Secrets (gitignored)
├── .env.example                   # Configuration template
├── requirements/                  # Python dependencies (README.md: which file is for what)
│   ├── requirements.txt           # The light runtime: pipeline without ML models, and the API (+ dev = CI)
│   ├── requirements-full.txt      # -r requirements.txt + ML models, OCR, openai, Playwright: the image
│   ├── requirements-dev.txt       # ruff, mypy, pytest-cov, reuse, schemathesis, atheris (fuzzing), httpx
│   ├── requirements-audit.txt     # pip-audit, pinned
│   ├── requirements*.lock.txt     # Hashed locks: image (PyPI), torch (PyTorch index), CI, audit, uv (make lock)
│   └── osv-scanner.toml           # Scorecard's accepted vulnerabilities for these files (SECURITY.md)
├── setup.sh                       # Prepares .env + the DB secret, checks Docker; --offline installs a bundle
├── Dockerfile                     # UI build, venv build, slim runtime, + a `dev` target with the CI tools (ADR-0044, ADR-0054)
├── compose.yaml                   # app, worker, postgres, capture-proxy + profiles bootstrap / dev / ollama / proxy, hardened
└── docker/                        # entrypoint, model warm-up, seccomp profile, nginx + squid config
    └── opencti-test/              # Throwaway OpenCTI stack for scripts/opencti_import_check.py; no service of compose.yaml uses it (TESTING.md)
```

## Database migrations

The schema is versioned (ADR-0077). Every change to a table — a column, an
index, a constraint, a backfill, a rewrite of stored JSON — is a new module
in `api/migrations/`, never an edit of an existing one: the API, the workers
and `bootstrap` apply what a database lacks at start, and refuse to start if
an applied migration's statements changed (its checksum is recorded).

```bash
python -m api.migrate status   # where this database is, what is pending
python -m api.migrate up       # apply what is pending (start does it too)
python -m api.migrate check    # exit 1 unless the database is at the code's version
```

To add version N:

1. `api/migrations/vNNNN_short_name.py` defining `MIGRATION = Migration(...)`:
   `version`, `name`, `store` (`jobs` or `rules`), `statements` (SQL, run in
   order inside one transaction), and `is_applied(conn)` — the check that
   finds this version's changes in a database (`column_exists`,
   `table_exists`, `index_exists`, `constraint_exists`, `trigger_exists`, or a
   query on the data). The runner runs it after applying, and rolls the version back if it
   does not see the changes; it also recognises with it how far a database
   created before versioning had got.
2. Data: a `data(conn)` function for what SQL alone does not express —
   rewriting JSON columns with the project's models, backfills in batches.
   Its source is part of the checksum.
3. **Expand, then contract.** A worker of the previous revision may still run
   during a restart: add a column nullable, fill it, and only make it required
   or drop the old one in a later version.
4. **Destructive steps** (drop, rename, retype, rewrite in place): list the
   tables in `snapshot_tables`; the runner copies each to
   `_pre_vNNNN_<table>` in the same transaction before running. There are no
   down-migrations: the snapshot, or a `pg_dump`, is the way back.
5. A test in `tests/test_migrations.py`, from a database at version N-1 with
   data written the way that version wrote it. `test_a_deployment_stopped_at_any_version_is_brought_up_to_date`
   and the schema-equivalence test cover the whole line.
6. On every run, CI writes a database with the last release's own code, and
   on a pull request one with the base commit's, seeds it, and migrates it with
   yours (`scripts/check_migration_from.py`; run it locally against
   `CTIPARSOR_TEST_DATABASE_URL` with `--last-release origin/main`). A new
   table needs rows in `scripts/migration_seed.py`, and a new column a
   non-NULL value in at least one of them (`tests/test_migration_seed.py`
   fails until it has them, or until `NOT_SEEDED` says why); a migration that
   rewrites or retypes stored values on purpose declares them in
   `EXPECTED_CHANGES`, in the script.

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

### Try another TTP embedding model

ADR-0023 measured SecureBERT-Plus against the default and found no gain
(its paper's +8-12% did not carry over); the candidate it names is
ATT&CK-BERT. Whatever the model, the change goes through the evaluation
(`docs/eval/README.md`) before it becomes the default.

```env
# .env
TTP_EMBEDDING_MODEL=<another sentence-transformers model>
# Then rebuild the embedding cache:
docker compose run --rm dev python scripts/build_indexes.py --only embeddings
# and bake it into the image app and worker run:
make docker-build && docker compose up -d
```
