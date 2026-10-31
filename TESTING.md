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
make ci               # lint, types, tests + coverage floors, frontend: the CI's fast tests and frontend checks, without reuse lint, the migration check and the backup check
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

### Measuring baseline reconciliation and the OpenCTI import (ADR-0090, A2 to A4)

Two on-demand measurements back ADR-0090's acceptance. Neither runs in CI.

**Round trip on the real reports (A2).** `scripts/baseline_round_trip.py` gives
each job's enriched bundle over its own stored bundle, offline: Stage 4 on the
job's rows, then Stage 5 and the audit's invariant checks, in memory. It writes
`output/baseline_round_trip.json` and `.md` (git-ignored), reads the same
measurement database as the ablation (read only), and calls no LLM. It differs
from the worker in two places, which its output names: that database has no
`held_reason` and no `enrichment_status` column.

```bash
wsl -e bash -lc "cd /mnt/c/Users/parra/Documents/tools-NLP/CTIParsor && .venv/bin/python scripts/baseline_round_trip.py"
# --db DSN, --out FILE and --jobs ID (repeatable) override the defaults
```

Reference result, 7 real reports, 2026-10-25: 6 of 7 enriched bundles pass
Stage 5. The 7th (job 07d1fd30) does not: Stage 4 builds a `url` whose value is
not a valid `uri`, which its stored bundle already had (a defect of Stage 4 that
predates the feature, to fix separately). 0 duplicate rows. At object level, 11
objects duplicate a baseline object by name: the CTIParsor author identity in
each of the 7 jobs, and two attack-patterns in two jobs. The detail per job is
in the `.md` file.

**Recovery and duplicates (A2, A3).** `scripts/baseline_ablation.py` takes each
job of the measurement database as its own baseline, removes 30 % of its index
entries (seed 20261025 by default), replays the job's stored extraction through
Stage 3r offline (no LLM, no network), and writes the evidence to
`output/baseline_ablation.json` (git-ignored; with `--fixture`,
`output/baseline_ablation_<fixture stem>.json`). The connection is read only.
The database is `ctiparsor_measure` on the test PostgreSQL (`cti-pg-test`, port
5433), never the main one; start it with `wsl -u root -e docker start cti-pg-test`.
Its jobs must hold their bundle, their baseline index and their extraction rows;
the script exits 2 when it cannot read them.

```bash
wsl -e bash -lc "cd /mnt/c/Users/parra/Documents/tools-NLP/CTIParsor && .venv/bin/python scripts/baseline_ablation.py"
# --ratio, --seed, --out, --jobs ID (repeatable) and --db DSN override the defaults
```

The external control reads a fixture bundle instead of the measured jobs
(`--fixture`, one job's extraction from `--fixture-db`, read only, named by
`--fixture-job`), once per seed (`--seeds 5`, from `--seed` on):

```bash
wsl -e bash -lc "cd /mnt/c/Users/parra/Documents/tools-NLP/CTIParsor && .venv/bin/python scripts/baseline_ablation.py --fixture tests/fixtures/baselines/opencti_report.json --fixture-db <dsn> --fixture-job <job-id> --seeds 5"
```

Reference result, 7 real reports, 2026-10-25: 179 of 601 candidate entries
removed, 175 recovered as `new` (97.8 %), 196 `new` rows, 0 duplicates (0.0 %)
on the ablation. On the round trip, 0 duplicate rows (A2; object level, see
above). A later run on other data is compared with these figures; the duplicate
rate is the one to watch (targets: at most 1 % on the ablation, 0 duplicate rows
on the round trip).

**OpenCTI import (A4).** `scripts/opencti_import_check.py` imports a baseline,
then CTIParsor's enriched bundle, into a throwaway OpenCTI and reads back what it
kept. The stack is `docker/opencti-test/compose.yaml`: OpenCTI 7.260930.0 and its
backing services, about 8 GB of RAM under WSL, only the platform's port published,
on `127.0.0.1:4000`.

```bash
cp docker/opencti-test/.env.example docker/opencti-test/.env   # test values only: fill them in (a UUID v4 token, 32 random bytes in base64)
wsl -u root -e docker compose -f docker/opencti-test/compose.yaml up -d   # the platform takes minutes to start
# pycti 7.260930.0 in a venv of its own, never the project's .venv
<pycti-venv>/bin/python scripts/opencti_import_check.py \
    --baseline tests/fixtures/baselines/opencti_report.json \
    --enriched <enriched.json> --rejected <rejected.json> --out <results.json>
wsl -u root -e docker compose -f docker/opencti-test/compose.yaml down -v   # removes the volumes: the instance is throwaway
```

`<enriched.json>` is the bundle an `enrich` job on `tests/fixtures/baselines/opencti_report.txt`
produces with `opencti_report.json` as its baseline; `<rejected.json>` is the same
job's bundle after rejecting the malware WellMess, exported after the full one.
The compose file takes every secret as `${VAR:?…}`: it refuses to start while a
value is missing from `.env`. RabbitMQ is pinned to `4.3.7-management`, OpenCTI
to `7.260930.0`.

The script reads the admin token from `docker/opencti-test/.env` (`--env-file`)
and never prints it. It creates a role, a group, a user whose maximum confidence
is 50 (for the counter-test), and an API token of unlimited duration, and it
never revokes them. Run it on this throwaway instance only. It exits 0 when every
expectation holds (12 of 12 on 2026-10-25, OpenCTI 7.260930.0), 1 otherwise. The
`.env` file is git-ignored.

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
| NER | `test_ner_precision.py` | 85 | ADR-0088 filters: the switch (default on); CyNER threat actors dropped (no capital and no digit, countries, nationalities, platforms, category words) or kept (APT27, Shell Crew, `apt29`); malware untouched; the lowercase-text exception and the hash appendix that must not trigger it; spaCy places (article, wrapped line, acronyms, camel case, "the US"); Stages 2d and 2 with stubbed models, switch on and off, the lowercase copy dropped before the dedup |
| Evaluation | `test_measure_ner_precision.py` | 71 | ADR-0089's decision rule in `scripts/measure_ner_precision.py`: each gate's threshold at its boundary (M1 +5 points, M2 and M4a one gold entity net, M4a and M4b one point, M5 2%), the float edge cases, void when M0 fails, incomplete when the train replay is missing or is not the one named; which records are run again (error or unreadable, a Stage 3 request with no answer, a CyNER or spaCy pass that did not run) and which are the model's answer; documents left out, a document missing from both runs included; the configuration and `run.json` differences between two runs |
| NER | `test_stage2e_gliner.py` | 16 | per-type cutoffs, model loading (no deprecated `resume_download`), batch fallback, merge precedence |
| NER | `test_stage_registry.py` | 4 | registry merging, deduplication, case insensitivity |
| **Aliases** | `test_aliases.py` | 6 | alias resolution, MITRE ID mapping, surface forms |
| **Aliases** | `test_alias_disambiguation.py` | 11 | type-aware resolution, alias isolation, canonical name handling |
| LLM enrich | `test_stage3.py` | 80 | LLM enrichment, JSON parsing, deduplication, prompt sanitization, the document-level pass reaching the provider whole |
| Relationship verification | `test_stage3d_verify.py` | 9 | Stage 3d sees the whole text, cuts the text not the claims, batches, document mode (reference sentence yes, chain no) |
| LLM enrich | `test_stage3_providers.py` | 5 | readiness gating for anthropic, gemini, mistral and the OpenAI-compatible local providers |
| LLM enrich | `test_stage3_calls.py` | 84 | client construction, provider diagnostics, Anthropic/OpenAI-compatible calls and retries, the provider's finish reason counted per call (also with no content) and the per-call output ceiling, dispatch, repair of a truncated answer (never collapsed to one nested object), `enrich_chunk`/`enrich_all_chunks`/`enrich_document_relations` branches |
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
| STIX mapping | `test_stage4.py` | 84 | SDO/SCO/SRO build, alias merging, IoC coverage, observable routing (ADR-0041, ADR-0062), a URL that is not a URI left out with its ledger reason |
| STIX mapping | `test_stage4_paths.py` | 52 | every observable to its SCO and pattern, named SDOs, PAP, embedded-rule Indicators, pin budget/grounding/malformed policies, relationship guards, CVE/CVSS and campaign merges, stix2 refusals |
| STIX mapping | `test_stix_rel_spec.py` | 4 | listed vs allowed relationships: common verbs, unknown types, direction |
| STIX mapping | `test_stix_ids.py` | 19 | ids equal to OpenCTI's standard ids: 15 values produced by pycti's own `generate_id` (ADR-0066), case and CAPEC rules |
| STIX mapping | `test_bundle_ledger.py` | 24 | mapping ledger: every row outcome and change, origins, 4b alias merge, API round-trip (ADR-0061); an IoC `indicates` a technique through its Indicator, turned around when written backwards (ADR-0065) |
| STIX mapping | `test_stix_self_edges.py` | 4 | self-edge prevention, endpoint validation, bundle integrity |
| **Graph completion** | `test_stage4b_completion.py` | 18 | transitive completion, alias merging, grounding, pins |
| **Graph completion** | `test_stage4c_long_distance.py` | 16 | long-distance inference, direction swap, evidence recording, passages naming the entities in a long report |
| **Graph completion** | `test_grounding_by_label.py` | 8 | STIX display names, edge scoring, bundle validation |
| Validation/export | `test_stage5.py` | 23 | bundle validation (the three verdicts, the schemas shipped with the repository and their install), file writing, nested directories; `validate_bundle` writes nothing and judges as `validate_and_export` does, `export_path` names the file by verdict (`_invalid` suffix), `export_bundle` writes where the verdict says (ADR-0086) |
| Baseline STIX (ADR-0090) | `test_baseline_stix.py` | 452 | `pipeline/baseline_stix.py`: the entity-type table against what Stage 4 builds, normalisation, the keys of a row, an object and a STIX pattern, families, `resolve` / `lookup` (exact-type tie-break, `AMBIGUOUS`), intake (limits, 2.0 refusal, ids and versions, scope by Report, including a relationship between two in-scope objects the Report omits, rules, id collisions, reference closure, TLP/PAP minimum, the index), the bounded search for objects the schemas refuse, hostile input, and `validate_bundle(quiet=True)` returning the verdict silently; since lot 7, the file name as a weak key (`lookup_weak`: one entry holding a file object, none for two carriers or for an Indicator alone) and a name-only Indicator joining the observable its `based-on` names when exactly one such observable is named and shares a key with the pattern |
| Baseline STIX (ADR-0090) | `test_baseline_api.py` | 66 | the flag (`/api/baselines/status`, 400 on every baseline route while off, a request without a baseline unchanged), `/api/baselines/inspect` (summary, report choice, refusals, 413, stores and logs nothing), the baseline on the three ingestion routes (the `enrich` job and its stored bundle, refusal before the report is written and before the URL capture, the Report choice, the TLP/PAP minimum, one WARNING per excluded object, NUL and lone surrogates, non-UTF-8 as 400), `pipeline_mode` and `enrichment` on the job, the bundle download, deletion and the retention sweep, 409 on editing or deleting an imported entity or relationship while accepting and rejecting still work, and the `baseline_stix` origin a client cannot claim, no TLP never below the server default, the cheap refusals before the baseline is read (short text, report over its limit, mode off), blank baselines, at most two bundles read at once (503), a long list of exclusions logged and shown in part, an upload that fails for any reason leaving no report file, the baseline read on its own threads, and a job the full queue rejects keeping no baseline |
| Baseline STIX (ADR-0090) | `test_baseline_worker.py` | 8 | the worker runs the JSON schemas before the pipeline starts, excludes with a WARNING an object only they refuse, fails the job with the reason when the baseline cannot be used or is missing, leaves a `full` job alone, does not validate a validated baseline again, logs an unusable baseline as a warning without a traceback, and caps its exclusion lines |
| Baseline STIX (ADR-0090) | `test_baseline_reconcile.py` | 31 | Stage 3r's `reconcile` (pure): the four passes, a match by key and by alias, families, the whole-word search in the report text with the earliest form as evidence, a relationship matched by its ends and verb, endpoints resolved through the baseline's forms, a value two entries share resolving to none, the stats, blank values, no offset when lowering changes the length, held TTPs matched like extracted ones; since lot 7, a file matched through its name when exactly one baseline entry carries it, and left `new` when two do or when the one carrier is an Indicator alone |
| Baseline STIX (ADR-0090) | `test_orchestrator_baseline.py` | 5 | Stage 3r in the orchestrator: its place after 3doc and its label, skipped and never called in full mode, reconciled once before `extraction_ready` in enrich mode, given the extractions and the baseline, a failing reconciliation failing the run before any write |
| Baseline STIX (ADR-0090) | `test_baseline_persistence.py` | 11 | what a run stores against a baseline: the Stage 3r columns NULL in full mode, matched rows pre-accepted with origin `baseline_stix`, imported rows stored pre-accepted with source `baseline_stix`, relationships' status and origin, auto-accept leaving the imported and matched rows alone, `load_index` (none for a full job or a missing row), the worker's hook handing the reconciliation to the save |
| Baseline STIX (ADR-0090) | `test_baseline_exclusions.py` | 3 | the `baseline_stix` source constant, `load_decisions` never reading a baseline row, the grounding harness reading full jobs only |
| Baseline STIX (ADR-0090) | `test_baseline_merge.py` | 30 | the merge of Stage 4 (`merge_baseline`, `reissue_report`, pure): a CTIParsor object replaced by the baseline object it matches (an Indicator, an observable through its entry, an object sharing its id), references rewritten, a relationship identical to a baseline one dropped and the baseline kept, two that become one kept first, a self-loop dropped, a rejected object and what refers to it left out, the chosen Report never added or kept, the kept objects written back as received, the re-issued Report's `modified` (+1 ms when the clock is behind, the build time without a valid original), `validation_json` dropping exactly the trusted objects, the in-text entities, `newest_versions` (the version of an id the intake keeps), a lone surrogate in a verbatim object written as an escape, non-ASCII text left unescaped otherwise; since lot 7, a name-only file remapped onto the one baseline file of its name, and a file with a hash of its own never merged on its name; a name-only `[file:name = …]` Indicator remapped onto the kept Indicator of its file, never onto a hash Indicator; a course of action or a rule Indicator of the same content remapped onto the one kept baseline object of that content, and nothing merged when two such objects exist |
| Baseline STIX (ADR-0090) | `test_stage4_baseline.py` | 6 | `build_stix_bundle` with a baseline, `merge_baseline` and `reissue_report` replaced by fakes: unchanged without one, the chosen Report re-issued in place of a CTIParsor Report, a CTIParsor Report with its enrichment when there is none, kept objects not stamped, the ledger recording the merge without `changes`, one marking-definition in the bundle |
| Baseline STIX (ADR-0090) | `test_baseline_finalize.py` | 20 | the baseline's share of `re_run_final_stages` and of a run: a full job finalized as before, Stage 4 given the baseline index and its objects as received, an object left only when all its rows are rejected, the imported rows not Stage 4 inputs, the bundle written with the verbatim objects and checked without the trusted ones, the build record naming the baseline's `sha256` (none for a full job), an `enrich` job without its baseline built without it, the run's verbatim objects and record, `load_baseline` and `baseline_sha256`, `objects_by_id` giving the version of an id the intake kept |
| Baseline STIX (ADR-0090) | `test_run_baseline.py` | 7 | the orchestrator and Stage 5 with a baseline: a full run builds as before and gets no baseline, an enrich run gives Stage 4 the baseline and the in-text rows, `validate_and_export` exports the trusted objects as received without checking them again, the verbatim objects not trusted are checked as written, `validate` passes the build's `verbatim` and `trusted`, a full run passes no baseline argument |
| Baseline STIX (ADR-0090) | `test_baseline_e2e.py` | 16 | the real merge end to end (`build_bundle`, `merge_baseline`, `reissue_report`, `serialize_bundle`, on the intake of the bundles they write): a round trip, where a CTIParsor bundle given back as its own baseline keeps its objects and ids, its one Report re-issued with every reference kept, and the objects written as first built; the OpenCTI-style fixture, where a threat actor named in the baseline becomes its intrusion set, the new malware's edge starts at that intrusion set, the kept objects keep their provenance, and the Report re-issued states the new malware; a baseline with no Report; the audit invariants of `scripts/audit_bundle_invariants.py`; and a finalize (`re_run_final_stages`) with a rejected object that leaves with its relationships and is ledgered; a chosen Report whose references all leave not re-issued, no Report when the document states nothing, and `outside_report` left off what the re-issued Report lists |
| Baseline STIX (ADR-0090) | `test_baseline_ablation.py` | 25 | `scripts/baseline_ablation.py` (A2, A3; read only, no LLM): the draw (a fixed seed per job, so the same job gives the same draw; round of the ratio times the candidate entries), the candidates (entries holding a ledger object, not the Report, identities or markings), an observable and its Indicator leaving together, a removed entry's relationships and Report references dropped, the classification of rows (recovered, duplicate, ambiguous, unmapped, mismatch), the fixture mode and its seeds, and the rates |
| Baseline STIX (ADR-0090) | `test_baseline_round_trip.py` | 8 | `scripts/baseline_round_trip.py` (A2; read only, offline): which rows ship (accepted or unreviewed, not held; rejected countries and locations kept out of Stage 4), the legacy dates of a relationship row, the malware rows read through the named lists, the folded comparison of names and values, the lost, altered and added objects read against the baseline, canonical JSON, and an offline build over a fixture that keeps every baseline object verbatim but the Report |
| **Provenance** | `test_audit_bundle_patterns.py` | 2 | `scripts/audit_bundle_invariants.py` (ADR-0090, ADR-0067/0070): an Indicator whose `pattern_type` is a detection-rule type (yara, sigma, suricata, snort, pcre) is neither audited as a STIX pattern nor flagged as a bad `pattern_type`; a `stix` pattern is still checked and an unknown type still flagged |
| **Provenance** | `test_provenance.py` | 5 | authoring identity, TLP marking, created_by_ref |
| **Provenance** | `test_edge_provenance.py` | 10 | relationship properties, pinned edges, run config |
| **Provenance** | `test_bundle_staleness.py` | 26 | `git_rev` extraction from malformed run configs, ancestry verdicts, an undecidable git result never marking a bundle stale (ADR-0035); a `mapping` fix judged on the build's revision, an `extraction` fix on the run's and the build's, the audit line naming both (ADR-0086) |
| **Provenance** | `test_bundle_builds.py` | 33 | which build is stored (ADR-0086): two overlapping finalizes publish in the order of their reads, never in the order they finish (the race reproduced first); a refused build returns the stored bundle and acts on nothing of its own; every read inside one snapshot; the trigger bumping `review_revision` on every write; the build record of a finalize and of a run, without secrets, and when it cannot be built; only a build that publishes writes the export file (a refused build or a deleted job leaves none, a failed write publishes nothing, an invalid build writes only the `_invalid` file) |
| **Provenance** | `test_audit_store_invariants.py` | 3 | `job.bundle_revision` of `scripts/audit_store_invariants.py` (ADR-0086): a bundle built from a revision ahead of its job's fails and names its job, jobs with no bundle or a bundle behind pass, the check is part of `run_all` |
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
| **Detection coverage** | `test_detection_phases.py` | 15 | tactic mapping, off-matrix handling, phase counting, a column for every enterprise tactic on every committed ATT&CK track (ADR-0087) |
| **Detection coverage** | `test_mitre_db.py` | 8 | ATT&CK/CAPEC index lookup and search ranking, missing or corrupt index |
| **Detection coverage** | `test_coverage_artifacts_api.py` | 5 | artifact coverage routes, payload shape, 404 handling |
| **Export filters** | `test_export_filters.py` | 13 | facet totals, format filtering, license exclusion, manifest |
| **Export filters** | `test_rule_lookup.py` | 8 | rule lookup, metadata retrieval, license handling |
| **Rule synthesis** | `test_synth_sigma.py` | 47 | rule synthesis, value validation, path escaping, stability |
| API | `test_api_routes.py` | 11 | health checks, job listing, upload validation, progress |
| API | `test_attack_api.py` | 5 | `GET /api/attack/index`: each committed ATT&CK track served byte for byte with `X-Attack-Release`, the sha256 ETag and its 304, the 19.2 ETag sent to an API on 20.0 gets the 20.0 index, a track without an index answers 404 (ADR-0087) |
| API | `test_relationships_api.py` | 18 | relationship creation, label coercion, patch validation, dates, `POST /relationships/bulk` (`human_bulk`, journaled, other jobs untouched — ADR-0065) |
| API | `test_settings_api.py` | 31 | corpus listing, overlay management, rebuild ingestion, formats, unsafe paths/remotes/tarballs, enable/disable, per-corpus sync |
| API | `test_jobs_routes.py` | 23 | job list/get/status, finalize, delete (rows and every file), retention sweep, source file, bundle and ledger |
| API | `test_entities_api.py` | 13 | manual entities, edit, bulk accept/reject/reset, delete, refusals |
| API | `test_policy_api.py` | 22 | relationship policy round trip, default fallback, every refused shape |
| API | `test_logging_config.py` | 9 | request ids, JSON/text formatters, `setup_logging` handlers, log helpers |
| Persistence | `test_persistence.py` | 7 | backup consistency, migration idempotency, label persistence |
| Persistence | `test_db_transaction.py` | 6 | transaction rollback, commit, exception handling |
| Persistence | `test_container_env.py` | 4 | `CTIPARSOR_GIT_REV` fallback when `git` is absent or fails (ADR-0044) — `_path_from_env`/`BACKUP_DIR` and `CTIPARSOR_DB_PATH` were removed along with SQLite (ADR-0053) |
| Queue | `test_worker.py` | 47 | the worker's terminal states (no bundle, timeout, abort, reclaimed, failed backup), hook guards, subprocess thread caps, the crash watcher, the finalize rebuild applying reviewer rejections and reading legacy/ADR-0063 dates, Stage 5's verdict deciding what a rebuild may complete (ADR-0084), a run storing its build record (ADR-0086) |
| Queue | `test_job_queue.py` | 14 | the queue loop (ADR-0046): atomic claim under 8 threads, lease-based orphan requeue, heartbeat scoping, slot accounting with a fake spawn, `run_pipeline_async` under roles `api` and `all`, `--once` |
| Persistence | `test_db_backend.py` | 12 | the PostgreSQL adapter without a server: `?`→`%s` outside literals, `%`→`%%`, the `Row` type, `backend()`/`get_conn()` requiring `DATABASE_URL` (ADR-0053), a fake psycopg connection proving `with` never closes and `transaction()` issues plain `BEGIN` (ADR-0045) |
| Persistence | `test_db_postgres.py` | 10 | skipped unless `CTIPARSOR_TEST_DATABASE_URL` is set (every other DB-touching test needs it too, via `temp_db` — ADR-0053): round trips, SSE resume ids, upserts, cascade, the coverage call without `jobs_conn`, the API through `temp_db_client`, and both migration scripts end to end (ADR-0045, ADR-0053) |
| Shared helpers | `test_shared_helpers.py` | 27 | environment parsing, claim extraction, unescaping logic |
| Fuzzing | `test_fuzz_targets.py` | 6 | every Atheris target (ADR-0081) over its seed corpus, `fuzz/corpus/<target>/`, and the empty input: a target that stops importing, or whose invariant a seed breaks, fails here between fuzzing runs; skipped off Linux x86_64 (no Atheris wheel) |
| Docs | `test_doc_claims.py` | 2 | every number `scripts/check_doc_claims.py` checks in README.md and docs/pipeline.md still matches its source, and is still found (what `make check-docs` did on demand only) |
| Release | `test_release.py` | 83 | the version is one number in `pipeline/__init__.py`, `frontend/package.json` and `frontend/package-lock.json`, and the CHANGELOG opens with `## [Unreleased]`; `scripts/release.py` (`version`, `check`, `notes`, `unreleased`, `prepare`, `predicate`) on throwaway trees: every refusal, every mismatch reported, the notes' length limit, no file written when `prepare` refuses, only the standard library imported (ADR-0085) |
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

### Stage 4 reference bundles (ADR-0090)
`tests/test_stage4_reference.py` builds five scenarios
(`tests/fixtures/stage4_reference/scenarios/`) through `build_bundle` and
compares the result, bundle and ledger, to a frozen canonical form in
`expected/`. The canonical form (`tests/stage4_reference.py`) replaces the
timestamps that fall within the build window by `<build-time>`, renames by
content the ids stix2 draws at random (relationships, the Report, an
attack-pattern built from a legacy technique row; any other id, the standard
TLP marking ids included, is compared as is), and sorts objects. Everything else counts: deterministic ids, verbs, refs, ledger
outcomes. A failure names the first differing object.

`tests/test_baseline_fixtures.py` checks the STIX bundles of
`tests/fixtures/baselines/` (README there) that the enrichment lots parse: the
valid ones pass Stage 5, the invalid ones fail for the intended reason.

A change to Stage 4 or 5 that is meant to change the output regenerates the
references and adds a `BUNDLE_AFFECTING` entry in the same PR:

```bash
UPDATE_STAGE4_REFERENCE=1 SKIP_HEAVY_MODELS=1 python -m pytest -q tests/test_stage4_reference.py
```

The test pins what the output reads from the environment (`ATTACK_RELEASE`,
`STIX_TLP`, `STIX_AUTHOR_NAME`, `BENIGN_IOC_FILTER`). It also checks that the
canonical form does not depend on `PYTHONHASHSEED`, in two subprocesses: about
50 s on `/mnt/c`, most of it import time.

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
operation and mode; 52 operations in about 30 s. Since ADR-0090 lot 2 the
schema has 60 operations and 56 are exercised, the new baseline routes
(`/api/baselines/status`, `/api/baselines/inspect`, `/api/jobs/{id}/baseline`,
`/api/jobs/{id}/baseline/intake`) among them; the 52 operations and 30 s are not re-measured (`TODO(chiffre)`).

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

### The stable contract (ADR-0094 item 1)
`docs/support-policy.md` lists the stable surfaces. `contract/` records them,
one file each, and `tests/test_contract.py` runs
`python scripts/contract.py check` in the fast-tests job:

- `openapi.json`: the schema the API publishes at `/openapi.json`, one entry
  per operation, parameter, body field, response and response field (types,
  whether required, allowed values; on the request side, a default, limits,
  formats, patterns and whether an object refuses unknown fields). It is
  built in a subprocess with an empty working directory, no `.env` and only
  `PATH`, `HOME`, `PYTHONPATH` and `SKIP_HEAVY_MODELS`, so a developer's
  settings and CI's give the same schema. A path parameter is known by its
  position.
- `cli.json`: `main.py`'s arguments (`build_parser()`), the stage ids, the
  commands and `bootstrap` options of `docker/entrypoint.sh`, `make db-upgrade`.
- `config.json`: the variables of `.env.example` (set or shown, and their
  values), the Compose project name, the services with their profiles and the
  named volumes with their `name:`, the `dev` profile left out.
- `stix.json`: read from the Stage 4 reference bundles above, the custom
  properties with their JSON types, and the ids of their objects (`random`
  for a random one, such as the Report's).

Each difference is `breaking`, `default` or `compatible`, by the rules of the
support policy (`tests/test_contract_rules.py` checks each rule both ways); any
difference fails the test. After a deliberate change:

```bash
make contract                     # record it in contract/, commit it with the change
make contract ACCEPT_BREAKING=1   # a breaking change: a CHANGELOG entry, and from 1.0 on a major version
```

The extractors have tests of their own (`tests/test_contract_openapi.py`,
`tests/test_contract_cli_config.py`, `tests/test_contract_stix.py`). The CLI's
exit codes are checked by behaviour, not recorded: `tests/test_cli_exit_codes.py`
runs `main()` for each row of the policy's table. `check` takes about 90 s on
`/mnt/c`: the OpenAPI subprocess imports the app, the CLI extractor imports
`main.py`. Not covered: the fields of a response whose schema declares none
(59 of the 60 operations), the 409 body, the job statuses, the
`X-Bundle-Validation` values, the SSE event names and the export archive's
layout (strings in the code, checked by route tests), a variable the code
stops reading or a code default that no longer matches `.env.example` (only
the file is read), and `x_ctiparsor_enrichment` (no enriched reference
bundle). A new alias of an option, or a `case` label that names two
commands, reads as breaking: record it with `ACCEPT_BREAKING=1`.

### Migration from a release (ADR-0094 item 2)
`python scripts/check_migration_from.py REF [REF ...]` (`--last-release` adds
the highest tag `vX.Y.Z` reachable from HEAD) runs each ref's own code from a
`git archive`, in a throwaway database and state directory, then:

- seeds the database that code built (`scripts/migration_seed.py`): four
  reports (one completed with its decisions, their journal, a held claim and
  dated relationships; one whose bundle the schemas refused; one enriching a
  STIX baseline; one that failed), the overrides, thresholds, relationship
  policy, a detection rule, the figure and CVE caches, and the uploaded sources
  and exported bundles of the state volume. Only the columns that release had
  are written; every table gets rows, and every column a non-NULL value in at
  least one of them, unless `NOT_SEEDED` says why not. The bundles and ledgers
  are the ref's own Stage 4 reference builds when its tree has them, this
  code's otherwise (`v0.1.0` has none): the report's `payloads:` line says
  which;
- reads every table, migrates with this code (`python -m api.migrate up`),
  reads them again and compares every row, value and column type, and checks
  that each identity column's sequence still gives a value above the highest
  stored (`scripts/migration_compare.py`). A change a migration makes on
  purpose is declared in `EXPECTED_CHANGES`, in the script;
- starts this code's app on it (`scripts/migration_readback.py`, in its own
  process, `CTIPARSOR_ROLE=api`) and reads the seed back through the routes:
  jobs, entities and relationships with their decisions, bundles with their
  verdict and ledger, the baseline, the source files, the progress events, the
  overrides, thresholds, relationship policy and detection rule. A read-back
  that breaks fails the ref with the end of its stderr;
- reads every table a third time and compares it with the second, sequences
  included: the app's first start and its read routes change nothing;
- checks the state directory's files: unchanged, but `db-identity.json`, which
  each start rewrites (same cluster, this code's schema version).

Every process of both trees runs with `PYTHON_DOTENV_DISABLED=1`: a
developer's `.env` changes nothing. A server the script cannot create a
database on exits 2 with one line.

The fast-tests job runs it from the last release on every run and from the
base commit on a pull request; it takes about 70 s per ref under WSL on
`/mnt/c`. Its parts are tested without a `git archive`:
`tests/test_migration_seed.py` (this code's schema seeded whole, version 11's
adapted, a table left empty, a column NULL in every row and a required column
left out refused, a release's own Stage 4 builds seeded),
`tests/test_migration_compare.py` (from versions 11 and 13 every value kept, a
lossy migration caught value by value, a retyped column, a restarted
sequence), `tests/test_migration_readback.py` (every seeded row through the
routes, a value a route stops returning named, the expectations taken from the
payloads seeded) and `tests/test_check_migration_from.py` (refs, exit codes,
an unreachable server, the throwaway database dropped, the files, no `.env`,
and `_check` itself with its steps stubbed: each difference returned, a
read-back that breaks). Not covered: the tables no route reads (the decision
journal, figures, the figure and CVE caches, the rules' side tables) are
compared in the database only; `detection_corpora.local.yaml`, whose path is
the checkout's. Known limits:

- `EXPECTED_CHANGES` names a column or a whole table (`table.*`), not rows: a
  declared change excuses every change there, deleted rows included, and a
  declared drop or rename stops the comparison of that data.
- A run killed by a signal other than Ctrl-C (SIGTERM, SIGKILL, a WSL
  distribution powered off) leaves its `ctiparsor_migcheck_*` database on the
  server; nothing sweeps them.
- CI takes the highest `vX.Y.Z` on origin, whether or not the commit under
  test contains it: a pull request re-run after a release with a newer schema
  fails ("the database is at schema version N ... this code knows up to M")
  until it is rebased.

```bash
CTIPARSOR_TEST_DATABASE_URL=postgresql://user:pw@host/db \
  python scripts/check_migration_from.py --last-release origin/main
```

### Backup and restore (ADR-0094 item 3)
`python scripts/check_backup_restore.py [--pg-container NAME]` backs up a used
install and restores it into an empty one, with the flags of
[docs/docker.md](docs/docker.md#data-and-backups), on the server
`CTIPARSOR_TEST_DATABASE_URL` names:

- the source is a new database built by this code's first start
  (`db-identity.json` recorded) and seeded by `scripts/migration_seed.py`,
  every table covered, with its state directory;
- the backup is `pg_dump -U <user> -d <db> -Fc`, which `pg_restore -l` must
  list whole, and `tar czf - -C <state> .`; `pg_dump` and `pg_restore` run in
  the server's own container (`docker exec`: `--pg-container` or
  `CTIPARSOR_TEST_PG_CONTAINER`), as the docs run them in the stack's; without
  one, on the host, when its `pg_dump` and `pg_restore` are as new as the
  server (exit 2 otherwise); the dump and the archive are readable by their
  owner only, as the docs' `umask 077` makes them;
- the restore goes database first: `pg_restore -U <user> -d <new db>
  --single-transaction`, which must exit 0 and print nothing, then `tar xzf
  --keep-old-files` into an empty directory;
- the comparison is strict (`migration_compare.compare(..., strict=True)`):
  every table, row, value and column type, and no table, column or row more;
  each sequence's `last_value` and `is_called`; the definition of every table,
  column, constraint, index, trigger and function
  (`migration_compare.schema_objects`); every file and directory of the state
  directory, byte for byte;
- this code's app starts on the restored database and directory and reads the
  seed back (`scripts/migration_readback.py`); the database is compared again
  after it, and `db-identity.json` keeps the source's entry and gains the
  target's, on the same cluster.

The fast-tests job runs it against its `postgres:18-alpine` service
(`CTIPARSOR_TEST_PG_CONTAINER: ${{ job.services.postgres.id }}`); the
runner's own `pg_dump` is never used. It takes about 70 s under WSL on
`/mnt/c`. pg_dump writes triggers and foreign keys after the rows, so the
version 12 triggers do not fire during a restore: a review revision that
drifted would show as a changed `jobs.review_revision`.

`scripts/check_backup_restore_docker.sh`, which `scripts/docker_smoke.sh
--backup-restore` runs in the container-image job, runs the commands of
docs/docker.md themselves, as written there, on the smoke's Compose stack: a
report written into it, the backup and its check, a restore into a second
project (`<project>-restored`, empty volumes, `CTI_PORT` + 1), then every
table's row count and checksum, every file of `cti-state` but
`db-identity.json`, the report and its source through the API, and the new
cluster recorded in `db-identity.json`. The restore's `pg_restore` line fails
it when it prints anything, as the docs require; if it stops after `docker
compose stop app worker`, it starts the smoke stack's `app` and `worker` again.
`tests/test_check_backup_restore.py` fails when its copy of the commands and
docs/docker.md's differ.

Neither script touches a Compose project that is not the smoke's own,
`ctiparsor-smoke`. `docker_smoke.sh` takes another only when the shell names it
in both `COMPOSE_PROJECT_NAME` and `SMOKE_ALLOW_PROJECT`, never from `.env`,
and never with `--clean` or `--backup-restore`. `check_backup_restore_docker.sh`
checks that the restore's project is empty before it writes anything.
`tests/test_smoke_project_guard.py` runs both against a fake `docker` that
records the project of each call, in about 10 s, without Docker.

Their parts are tested in `tests/test_check_backup_restore.py` (where the
tools run and with which password, the exit codes, the databases and
directory removed, and `_check` with `pg_dump` and `pg_restore` replaced by a
copy of the source database: the documented flags, `pg_restore` the one
command that must print nothing, and a lost row, a row added in a table
without a sequence, a dropped trigger, a reset sequence, a changed file and an
added file each caught) and
`tests/test_migration_compare.py` (strict mode, sequence states, schema
objects). Known limits:

- the Python check restores into another database of the same server: a
  restore onto a new cluster at the same address, what an empty project
  gets, is run by the Compose check only (and `tests/test_db_identity.py`);
- the Compose check writes one report with SQL, not the whole seed
  (`tests/fixtures/`, which the seed reads, is not in the image);
- a backup taken while `app` or `worker` run, and a restore across
  PostgreSQL majors (`make db-upgrade`, docs/upgrading.md §7), are not
  checked;
- the strict comparison leaves out the ACLs of sequences and functions and
  the owners of sequences (the tables' ACLs and owners and the functions'
  owners are compared), comments, types and domains, table options
  (`reloptions`, `UNLOGGED`), objects outside the app's schema, and
  file modes and owners: the schema this code creates uses none of the first
  five (no GRANT, COMMENT, CREATE TYPE or DOMAIN, UNLOGGED in its migrations),
  and every file is the app user's;
- not observed, a hypothesis: on a new volume, `docker compose up -d --wait
  postgres` could report healthy while the image's first-start server still
  runs (`pg_isready` reaches it on the socket). A `pg_restore` cut short by
  that restart fails loudly, and `--single-transaction` leaves the database
  empty: start again, as the docs say for any failed restore.

```bash
CTIPARSOR_TEST_DATABASE_URL=postgresql://user:pw@host/db \
  python scripts/check_backup_restore.py --pg-container <the server's container>
```

### Persistence / worker (integration)
The write→read round-trip through PostgreSQL (`worker._save_entities` →
`re_run_final_stages`) and schema migrations. **Currently the weakest layer** (see §6).

### Attacker-facing parsers (fuzzing, ADR-0081)
Five Atheris targets in `fuzz/` mutate their seeds for 60 s on every pull
request and push to `main`, and for 10 minutes weekly:

- `report_text`: refang and extraction;
- `dates`: date parsing;
- `rule_gates`: the Sigma, Suricata, Snort, YARA and STIX-literal gates;
- `spotlight`: the prompt enclosure;
- `baseline_intake`: the reading of an analyst's STIX bundle and of the
  patterns in it (`pipeline/baseline_stix.py`, ADR-0090). Only
  `BaselineError` may escape `intake`, and `pattern_keys` never raises. Its
  seeds are bundles, the largest 16.6 KB, so the workflow gives this target
  `-max_len=65536` where the others keep 16384.

A failure is one of:

- an exception;
- a broken invariant;
- a native crash;
- an input slower than 10 s;
- more than 2 GB of memory.

The jobs of the first four targets are required checks (ADR-0078, amendment of
2026-10-10), so a failure is fixed before the merge. Whether the
`baseline_intake` job is one is a repository setting, not something the
workflow file decides. To fix a failure:

1. Reproduce it from the uploaded artifact: `python fuzz/fuzz_<target>.py <file>`.
2. Fix it.
3. Add the input to `fuzz/corpus/<target>/`.

From then on, `test_fuzz_targets.py` replays that input in the fast tests.

### Frontend (Vitest, ESLint, tsc)
27 Vitest files (285 tests on 2026-10-25 after lot 6, `npm test` in `frontend/`;
224 after lot 5; 162 in 20 files on 2026-10-19) with Testing Library and jsdom: the
Review and Dashboard pages, the New report modal, the relationship rail, the
margin notes and their ribbon, the document reader, the
graph builders and layout, the API client, the ATT&CK search, the Coverage
columns against the index of every committed ATT&CK track (read from
`pipeline/data/`), a dependency audit. Lot 5 of ADR-0090 (2026-10-25) adds
`NewReportModal.test.tsx` (18 tests), `review/Marginalia.test.tsx` (9) and
`review/PipelineRibbon.test.tsx` (4), and ADR-0090 cases to `api/client.test.ts`
(18 tests in the file), `review/RelationshipRail.test.tsx` (22) and
`pages/Review.test.tsx` (16). Lot 6 of ADR-0090 (2026-10-25) adds four files:
`components/graph/BaselinePanel.test.tsx` (7 tests), `components/dropFiles.test.ts`
(12), `pages/Graph.test.tsx` (6, the relationship editor's Delete) and
`components/review/InlineHoverChip.test.tsx` (3). It adds ADR-0090 cases to
`NewReportModal.test.tsx` (31 tests in the file, 18 before lot 6),
`components/graph/buildBundleGraph.test.ts` (22, 12 before),
`components/graph/provenance.test.ts` (10, 3 before) and `pages/Dashboard.test.tsx`
(7, 4 before); `pages/Review.test.tsx` (16) keeps its count and one case now
checks the disabled Change type. The browser journey (2026-10-31) adds
`components/ProgressModal.test.tsx` (4 tests): the progress dialog's focus
moves in, stays in under Tab and Shift+Tab, Escape closes it, and on close the
focus goes back to what had it at the opening, or to New report when that is
gone. ESLint runs
the TypeScript rules, `rules-of-hooks` and `exhaustive-deps` as errors, and
the formatting the code already follows (`frontend/eslint.config.js`).
`npm run check` runs lint, `tsc` and Vitest, the three steps of CI's frontend
job. Still untested as a unit: the review-page promotion gate (§6, P1-d).

### Browser journey (ADR-0094 item 4)

Playwright (`@playwright/test`, Chromium) drives the built interface against
the real API, its worker and PostgreSQL, as an analyst does:
`frontend/playwright.config.ts` and `frontend/e2e/`, run by
`scripts/check_browser_e2e.sh` (CI job `browser-e2e` on every push, pull
request and weekly run; the image is published only after it). Each journey
works on reports of its own, three at a time; none pauses for a fixed time,
each waits for a state the page or the API shows, within a bound.

| Spec | What it checks |
|---|---|
| `main-journey.spec.ts` | `tests/fixtures/sample_report.txt` imported through "Browse files…" with its TLP and PAP; the progress dialog shows Stage 1's event (its "… chars → … chunks" line, which only an event of the run draws: a dead event stream fails); a reload, after which the dashboard still lists the report, from the server, and its run reaches review (whether it still runs at the reload is recorded, not asserted: on a warm API the run ends 0.6 to 0.8 s after that event); its card in For review; Analyse; one row accepted (APT29, left pending), one rejected (update-service.net, auto-accepted), one retyped (Cobalt Strike, malware → tool); Complete Review; Download STIX. The file is a STIX 2.1 bundle (ids, `spec_version`, one object per id, every `*_ref` and `*_refs` inside it); the accepted actor ships, the rejected domain and its indicator do not, the retyped row ships as a tool. `GET /api/jobs/{id}/bundle` serves the same bundle with `X-Bundle-Validation: validated`; the report is completed and the three decisions are `human` |
| `enrichment.spec.ts` | `tests/fixtures/baselines/opencti_report.json` and its text in enrich mode (the TLP raised to the bundle's AMBER); completed; the analyst's Report re-issued in the bundle; on the graph, "Differences", then "Against your bundle", whose matched rows are the ledger's `baseline_match` removals, checked one by one (offline: the file name and its SHA-256, merged into the analyst's file, and APT29, into the analyst's intrusion set; every replacement one of the analyst's objects), with SUNBURST added by the report |
| `failed-job.spec.ts` | the same bundle with its Report's `lang` set to `not a lang!`: the preview accepts it (it does not run the schemas), the worker refuses it, the job fails and the dashboard says "Pipeline failed". The reason, read from the run's last progress event (the page does not show it), is the baseline error: `'not a lang!' is not a valid RFC 5646 language code` |
| `refused-bundle.spec.ts` | the report `scripts/browser_e2e_db.py seed` writes as the worker stores a run whose Stage 5 refused the bundle: `GET /bundle` answers 409 with `{"validation": "invalid", "errors": [...]}`; the graph says the build was refused and shows the first error; its Download STIX raises the refusal with that error and saves nothing |
| `keyboard.spec.ts` | the main journey's operations with the keyboard alone (checklist below) |
| `accessibility.spec.ts` | axe on each page and dialog of the journey (below) |

**The offline profile.** The script starts `python run_api.py` (role `all`:
the API and its worker, a subprocess per report) on 127.0.0.1:8765 with
`env -i` and these variables only: `PYTHON_DOTENV_DISABLED=1` (no `.env`),
`SKIP_HEAVY_MODELS=1`, `PIPELINE_DISABLED_STAGES=1f,2c,2d,2e,3,3d,3f,3e,3doc,2f,4c`
(every stage of `pipeline/orchestrator.py` that loads a model, calls an LLM
or reaches the network), `VISION_PROVIDER=none`, `CVE_ENRICHMENT=false`,
`HF_HUB_OFFLINE=1`, `TRANSFORMERS_OFFLINE=1`, `REVIEW_CONTROL_SAMPLE_RATE=0`
(no control sample drawn: the rows a journey decides start in a known
state), `STIX_ENRICHMENT_ENABLED=true`, `WORKER_MAX_CONCURRENT=3` (as many as
Playwright's workers), a new database and throwaway directories, and no key.
Stages 1, 2, 2b, 2g, 3r (enrich jobs), 4, 4b and 5 run. After the journeys
the script prints every report's stage report (which stage ran, which was
skipped and why) and fails if a disabled stage ran.

**No external network.** With `--network-guard` (CI), the API, its worker's
subprocesses and the seed run under a group of their own (gid 64999, through
`setpriv`), and an `iptables`/`ip6tables` owner match, inserted first in
`OUTPUT` so that no ACCEPT of the host's firewall comes before it, rejects and
counts every packet that group sends anywhere but loopback; the run fails
unless both counts are 0. A canary connection from that group to 192.0.2.1 is
refused and counted first, so the guard is shown to work. The browser is not
in the group: its own traffic is not the subject. A DNS lookup is counted
only when the resolver is off loopback: where it is a local stub
(systemd-resolved on 127.0.0.53, Ubuntu's default), the lookup goes over
loopback and the stub sends it on as its own, uncounted; any connection made
after it is counted. The guard needs root or sudo without a password. Run as
root, the script builds the interface and runs the API as the checkout's
owner: nothing in the checkout is left to root, and the API cannot leave the
guard's group. A chain left by a run that was killed stops the next one
(exit 2) with the commands that remove it. Turning CVE enrichment on
(Stage 2f, which calls NVD) makes it fail: 2 packets on 2026-10-31.

**Run it locally** (Linux or WSL; Python with `requirements/requirements-ci.lock.txt`
or the full one, Node 24 and npm 11, a PostgreSQL server you may create
databases on):

```bash
(cd frontend && npm ci)
CTIPARSOR_TEST_DATABASE_URL=postgresql://ctiparsor:ctitest@127.0.0.1:5433/ctiparsor \
  PYTHON=.venv/bin/python bash scripts/check_browser_e2e.sh --docker
```

`--docker` runs Playwright in `mcr.microsoft.com/playwright:v<version>-noble`
(the version `frontend/node_modules` holds) with `--network host`, so neither
Chromium nor its system libraries go on the host; without it, run
`npx playwright install --with-deps chromium` in `frontend/` once.
`--no-build` reuses `frontend/dist`; arguments after `--` go to
`npx playwright test` (`-- e2e/keyboard.spec.ts`). `E2E_PORT` moves the API
off 8765. The HTML report is in `frontend/playwright-report/`; a failed
journey's trace, screenshot and video, and the API's log, in
`frontend/test-results/` (CI uploads both, on failure only). Exit 2 means the
journey could not run (a missing tool or variable, a port in use, the guard's
chain left by a killed run, a build, database or API that would not start).
Measured on 2026-10-31 under WSL with the CI lock: the six journeys in 21 s,
the script in 30 s with `--no-build` and 52 s with the build; three runs in a
row green.

**Accessibility gate.** `accessibility.spec.ts` runs axe-core
(`@axe-core/playwright`, tags `wcag2a`, `wcag2aa`, `wcag21a`, `wcag21aa`) on
the dashboard (as the run finds it: the seeded refused report and what the
journeys running beside it have imported so far), the new-report dialog
(empty, then filled), the progress dialog, the dashboard again with this
journey's report in review, the review page and the graph, each once its
finite animations are over. A violation of impact serious or critical fails,
unless `frontend/e2e/a11y-allowlist.json` names it by its rule, its page and
its element (axe's target selector), with why and the follow-up: another
element breaking the same rule on the same page fails. An entry that no
longer matches fails too, so the list only shrinks. The run attaches every
finding, any impact. On 2026-10-31 axe found 3
serious ones: two contrasts in the new-report dialog's markings band (the
"required" badge and the line beside it, fixed), and the review page's theme
button, named "Toggle theme" while it shows the theme in force (allowlisted
as `.theme-toggle`, WCAG 2.5.3). Nothing else, of any impact. Axe is not a
certification.

**Keyboard checklist.** `keyboard.spec.ts` presses keys only, no click and no
pointer:

- dashboard: Tab to New report, Enter;
- new-report dialog: the text area has the focus; Shift+Tab to "Browse
  files…", Enter (the file chooser is the system's: Playwright stands in for
  it); Tab to a TLP and a PAP level, Space; Tab to Create job, Enter;
- progress dialog: its Close button takes the focus, and Tab and Shift+Tab
  leave it there; Escape closes it, and the focus goes back to New report
  (Create job, which opened it, closed with the new-report dialog);
- dashboard: Tab to the report's Analyse, Enter;
- review: `j` (next pending row), `a` (accept it), `r` (reject the next); Tab
  to a row's Change type (⋯), Enter, Tab to a type, Enter; `f` (Complete
  Review), `f` again (Download STIX).

By hand, before a release: the system file chooser; a visible focus on each
control above and the focus order across the review page's columns; the
graph page (view switch, Differences, Against your bundle, Download STIX);
what a screen reader says of the progress (no live region) and of the
cards' ✓, ✗ and ⋯ buttons (named by those characters, their titles only
describe them); 200 % zoom, and a window 720 px high, where the relationship
rail covers part of the review margin.

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
the first five pass:
1. **fast-tests** (every push and PR): `ruff check .`, `mypy` (scope and flags
   in `pyproject.toml`), every test with `CTIPARSOR_REQUIRE_TEST_DEPS=1`, the
   coverage floors. Installs the OpenCTI pattern parsers, google-re2 and
   numpy, but not torch/transformers (`SKIP_HEAVY_MODELS=1`). No secrets. It
   also migrates a database written by the last release, and on a PR one
   written by the base commit's code, and compares their content
   (`scripts/check_migration_from.py`, ADR-0077, ADR-0094 item 2), and backs
   up a seeded database and restores it into an empty one
   (`scripts/check_backup_restore.py`, ADR-0094 item 3).
2. **frontend-tests**: `npm run lint`, `npm run typecheck`, `npm test`.
3. **container-image**: builds the image, runs `scripts/docker_smoke.sh
   --backup-restore` (with the backup and restore commands of docs/docker.md,
   ADR-0094 item 3), and
   scans the image with Grype into Code scanning (not a gate, ADR-0078).
4. **dependency-audit**: `pip-audit` on the Python locks and `npm audit` on the
   UI's production packages (ADR-0075, ADR-0080). It also runs weekly.
5. **browser-e2e**: the browser journey, offline, with the network guard
   (`scripts/check_browser_e2e.sh --network-guard`, §4 "Browser journey",
   ADR-0094 item 4). It also runs weekly.
6. **dependency-review** (pull requests only): fails a PR that adds a
   dependency with a known high or critical vulnerability (ADR-0078).
7. **model-tests** (pushes to main only, not a gate): the same suite with the
   models downloaded and a live API key; it may fail for reasons outside the code.
8. **publish-image** (pushes to main only): pushes the image to GHCR with its
   SBOM and signed attestations, after jobs 1 to 5.

Four more workflows run beside it. **Fuzzing** (`fuzz.yml`) runs the five
targets above, and the jobs of the first four are required checks. **CodeQL**
(`codeql.yml`) analyses Python, TypeScript and the workflows. **Scorecard**
(`scorecard.yml`) rates the repository's practices; it tests nothing.
**Release** (`release.yml`) publishes a GitHub Release when a tag `v*` is
pushed. A pull request that changes it, `scripts/release.py` or
`scripts/release_files.sh`, and a weekly run (Monday), get a dry run instead,
with nothing published (ADR-0085, `docs/releasing.md`).

`make ci` runs jobs 1 and 2 locally, in the `dev` and `frontend-dev` containers,
except three steps of job 1: `reuse lint`, the migration check from the
last release and the pull request's base commit
(`scripts/check_migration_from.py`), and the backup and restore check
(`scripts/check_backup_restore.py`).
