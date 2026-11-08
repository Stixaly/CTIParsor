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
.venv/bin/python scripts/baseline_round_trip.py
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
.venv/bin/python scripts/baseline_ablation.py
# --ratio, --seed, --out, --jobs ID (repeatable) and --db DSN override the defaults
```

The external control reads a fixture bundle instead of the measured jobs
(`--fixture`, one job's extraction from `--fixture-db`, read only, named by
`--fixture-job`), once per seed (`--seeds 5`, from `--seed` on):

```bash
.venv/bin/python scripts/baseline_ablation.py --fixture tests/fixtures/baselines/opencti_report.json --fixture-db <dsn> --fixture-job <job-id> --seeds 5
```

Reference result, 7 real reports, 2026-10-25: 179 of 601 candidate entries
removed, 175 recovered as `new` (97.8 %), 196 `new` rows, 0 duplicates (0.0 %)
on the ablation. On the round trip, 0 duplicate rows (A2; object level, see
above). A later run on other data is compared with these figures; the duplicate
rate is the one to watch (targets: at most 1 % on the ablation, 0 duplicate rows
on the round trip).

**OpenCTI import (A4).** `scripts/check_opencti_candidate.sh` checks what a
throwaway OpenCTI keeps of the bundles a candidate image produces (ADR-0094
item 8). It runs two Compose stacks in turn, never together, and removes each
with its volumes:

1. the candidate, given by digest or by a tag it resolves to its digest; its
   commit is the image's label `org.opencontainers.image.revision`;
2. the candidate's app, worker and database from `compose.yaml`, in the project
   `ctiparsor-opencti-candidate`, with the browser journey's offline profile and
   a database password made for the run: the checkout's `.env` and `.secrets/`
   are not read. Through its API (`scripts/opencti_candidate_bundles.py`), three
   bundles, all marked TLP:AMBER and PAP:GREEN: `full`,
   `tests/fixtures/sample_report.txt` with APT29 accepted and
   update-service.net rejected; `enriched`, an `enrich` job on
   `tests/fixtures/baselines/opencti_report.txt` with `opencti_report.json` as
   its baseline; `rejected`, the same job exported again after the malware
   WellMess is rejected. Each job's `git_rev` is read from the database;
3. OpenCTI 7.260930.0 and its backing services from
   `docker/opencti-test/compose.yaml`, in the project `ctiparsor-opencti-check`,
   only the platform's port published, on `127.0.0.1:4000`, with secrets made for
   the run: `docker/opencti-test/.env` is not read;
4. `scripts/opencti_import_check.py`, with pycti 7.260930.0 in a venv of its
   own: the analyst's baseline, then `enriched` as a user whose maximum
   confidence is 50, then `enriched`, `rejected` and `full` as admin.

```bash
# once: the pycti venv, outside the project's .venv, from its hashed lock
python3 -m venv ~/.cache/ctiparsor-pycti-7.260930.0
~/.cache/ctiparsor-pycti-7.260930.0/bin/pip install --require-hashes --no-deps -r requirements/requirements-opencti.lock.txt
# from the checkout, as root when Docker needs root (sudo)
bash scripts/check_opencti_candidate.sh --image ghcr.io/stixaly/ctiparsor:sha-<commit>
```

The expectations, 83 on a run:

- step 0, the candidate: each job ran on the image's commit (a job that
  recorded none fails); Stage 5 gave each bundle `validated`
  (`X-Bundle-Validation`); OpenCTI received the candidate's bytes (sha256);
- steps 1 to 4, A4's twelve: nothing refused; the low-confidence user's import
  leaves the Report's 9 references as they are, since OpenCTI adds references on
  an upsert only at a confidence at least the stored one (ADR-0090 §6); as
  admin, the Report holds the baseline's references and the additions, one
  Report, each baseline object once by id and by type and name or value, every
  object of the bundle present; after the rejection, WellMess still referenced,
  since OpenCTI never removes a reference;
- for each bundle imported as admin, after a second import, against the whole
  platform read back with OpenCTI's own STIX export of each object
  (`scripts/opencti_expectations.py`): nothing refused and nothing added; every
  object there once, found by one of its ids or, once OpenCTI renamed it, by its
  name or aliases; no two objects, and no two relationships, of the bundle on one
  OpenCTI object (OpenCTI merges an object into another that holds its name as
  an alias); no second object of its type answering to its name, value or
  aliases, and no second relationship of its type between the same objects; each
  relationship joining the objects the bundle names; the author
  (`created_by_ref`) and the markings, TLP and PAP, that the bundles imported so
  far set; no description of an object or relationship emptied (a changed one is
  recorded below); the Report holding each of the bundle's references, none
  merged into another, its description (ADR-0093), its attached file
  (`x_opencti_files`: name and MIME type, once) and its confidence;
- step 6, after the last import: every object of every bundle still there, each
  on an OpenCTI object of its own, and every reading of the platform settled (two
  readings in a row agree before the poll's 120 s; one that never settles fails).

A WARN does not fail the run: one name held by OpenCTI objects of two types. On
2026-11-01, APT29: the analyst's Intrusion-Set and `full`'s Threat-Actor-Group
(the `full` job extracts APT29 as a `threat_actor` row). Which type CTIParsor
gives an actor is a product decision, not an import loss; the report lists both
objects with their types.

What OpenCTI holds differently is recorded with the whole values in
`report.json` (a changed list with what it lost and gained), not judged. On
2026-11-01 it drops the `x_` properties, the Report's `original_document`
reference (it has no URL and no external id: the file name and SHA-256 stay in
the description's "Source document" block, and the file is attached) and, from
its export, an artifact's `payload_bin`. It adds a confidence of 100 where the
bundle sets none, replaces an Indicator's `valid_until` with one it computes (the
baseline's 2027-03-02 becomes 2026-03-30), and gives the analyst's Report its
`published` date as `created`. Admin imports at confidence 100, above the
baseline's 85, so a later bundle rewrites the object it reaches by its standard
id:

- `full`'s WellMess carries the id OpenCTI gives the analyst's WellMess (both
  derive it from the name, ADR-0066): it replaces its author, its confidence and
  its description, adds `full`'s markings, and the analyst's `first_seen`
  (2018-07-01) is gone;
- on 2026-11-01, on the image at 4df5cbd, `full`'s technique T1059.001 reached
  the analyst's PowerShell by its ATT&CK id and renamed it `T1059.001`
  (PowerShell became an alias). That name was CTIParsor's: a technique found in
  the text with no Stage 3 entry for it was exported named as the text writes
  it, under a random id. Fixed since: such a technique takes its standard id
  and its ATT&CK name (ADR-0066; the ledger records the rename,
  `attack_id_named`), and a run on an image that has the fix no longer shows
  this row.

A merge is an expectation, not a record: on 2026-11-01 the baseline fixture gave
the analyst's WellMess the alias WellMail, which ATT&CK does not (WellMess S0514
and WellMail S0515 are two families). OpenCTI then took `full`'s WellMail and
WellMess for that one object, and their two `uses` relationships for one: the
first version of this check passed it. The fixture no longer carries the alias,
and the check fails on such a merge.

The report goes to `output/opencti-candidate/<UTC time>/`: `report.md` and
`report.json` (the candidate's digest and commit, where the bundles come from,
the checkout that ran the check with its commit, whether tracked files are
modified and the sha256 of the check's scripts and fixtures, the digests of
OpenCTI's images, pycti's version, each bundle's sha256 and
`X-Bundle-Validation`, every expectation, the warnings, what OpenCTI refused and
changed, durations, memory), with the bundles, the run's record and the logs.
Exit 0 when every expectation holds (a WARN included), 1 otherwise, 2 when the
check cannot run. Every `docker compose` call runs under `env -i`: an exported
`CTI_IMAGE`, `CTI_ENV_FILE` or `OPENCTI_*` is not seen. On 2026-11-01, on main's
image at 4df5cbd, given by digest
(`ghcr.io/stixaly/ctiparsor@sha256:3301b5c43038a8ef3dcc8948ee8c6c84c2aa1ec5b5cb90fa17047b574ae0408f`):
83 of 83 and 1 WARN in 122 s (the candidate 35 s, OpenCTI ready 46 s after its
start with its images present, the check 39 s); memory in use (`free -m`) rose
from 1.7 to 5.8 GB while OpenCTI ran, and the script refuses to start OpenCTI
with less than 8000 MB available (`OPENCTI_MIN_AVAILABLE_MB`). The first version
of the check, 66 expectations, failed 6 on a tampered copy of the bundles (a byte
added to one, a relationship to a missing object, a second Indicator under an
existing name); the expectations added since fail on their counter-examples in
`tests/test_opencti_expectations.py`. It is not in CI: two stacks, and about
4 GB for OpenCTI.

The check creates in OpenCTI a role, a group, a user and an API token of
unlimited duration, and never revokes them; the instance is deleted at the end.
`--bundles DIR` imports the bundles of an earlier run again; its report says
they were not produced by that run, and names DIR and the run that made them.
`scripts/opencti_import_check.py` still runs alone against a stack started by
hand (`--env-file`, by default `docker/opencti-test/.env`, filled in from
`.env.example`; git-ignored).

**Any bundle (ADR-0094 item 10).** `scripts/opencti_import_bundle.py` imports one
bundle into a running OpenCTI, as the token's user, waits until OpenCTI shows
its objects, then reads back every object by STIX id. It needs the pycti venv
above and an admin token (the import of marking definitions and of the
bundle's objects needs the capabilities the A4 check grants):

```bash
~/.cache/ctiparsor-pycti-7.260930.0/bin/python scripts/opencti_import_bundle.py BUNDLE.json \
    --token-file TOKEN_FILE [--url http://127.0.0.1:4000] [--timeout 120]
```

`--token-file` holds the token alone, or a `KEY=VALUE` file with
`OPENCTI_ADMIN_TOKEN`; without it the token is read from
`docker/opencti-test/.env`. The token is never printed. The report gives, per
STIX type, the objects sent, found, missing and refused (the import's errors,
as OpenCTI returned them). It goes to `output/opencti-import/<UTC time>/`:
`report.md` and `report.json`, written whatever the result. Exit 0 when nothing
is missing or refused, 1 otherwise, 2 when the run cannot start or OpenCTI fails
a call. It does not check duplicates by name or alias, a second import, markings
or the Report's fields: `scripts/opencti_import_check.py` does, for its fixtures.
Use it on the throwaway instance only.

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
| Ingestion | `test_stage1_pdf_paths.py` | 39 | per-page scan detection (an image over half the page, or text drawn as glyph outlines), mixed and fully scanned PDFs (OCR in page batches, failures degrade to the text layer), markitdown fallback, PDF/DOCX creation dates, the document anchor from a capture sidecar or HTML metadata |
| Ingestion | `test_upload_route.py` | 17 | `/api/upload`: TLP/PAP markings, extension and MIME checks, the `filetype` fallback without libmagic, size limit, full queue, disk errors |
| Ingestion | `test_upload_fallback_issues_489_490.py` | 9 | libmagic-free fallback: a character cut at the 1 MiB boundary; HTML recognised by its markup (#489, #490) |
| Ingestion | `test_ingest_routes.py` | 26 | job creation, TLP validation, URL capture, HTML detection |
| Ingestion | `test_web_capture.py` | 38 | URL sanitization, SSRF guards, PDF rendering, lazy loading |
| Ingestion | `test_web_capture_issue_511.py` | 7 | inline `data:` images/fonts pass the capture filter; private/loopback subresources and `data:` scripts stay blocked (#511) |
| Ingestion | `test_ingest_capture_timeout_issue_480.py` | 1 | a capture finishing after the deadline removes its staging PDF (#480) |
| **Figures** | `test_figure_triage.py` | 12 | size filtering, aspect guards, PDF source detection |
| **Figures** | `test_stage1f_figures.py` | 29 | figure injection, verbatim rendering, edge rendering |
| **Figures** | `test_figure_store.py` | 12 | JSON round-trip, cache management, span loading |
| **Figures** | `test_figure_reading_order.py` | 5 | reading order, page ordering, span delimitation |
| **Figures** | `test_vlm.py` | 83 | payload parsing, backend selection, figure reading, `VISION_CONCURRENCY` parsing and override; `VISION_PROVIDER=auto` (the provider of `LLM_PROVIDER`, never another, the skip reasons and their log level), a probe that raised not kept for the next document, credentials kept out of reasons, the config check reading `.env` |
| **Figures** | `test_figure_context.py` | 12 | prompt context blocks, the ban on copying context into `verbatim_text`, per-figure bands, cache-key separation |
| **Figures** | `test_vlm_parse_issue_509.py` | 7 | `_parse_payload` takes the object when a note follows it and skips `<think>` (#509) |
| **Figures** | `test_figures_issue_376_388.py` | 13 | an image wholly off the page is no candidate, one partly off keeps its clamped box (#376); an injected figure block adds one blank line before it, also after text with no trailing newline (#388) |
| Extraction | `test_stage2.py` | 75 | IoC extraction, refang/defang, hash recovery, filename handling |
| Extraction | `test_extraction_issues_496_497_506_507_508_510.py` | 25 | FTP URL keeps its path; quoted URLs keep trailing punctuation; `sentence_bounds` slices the original text across `\n\n\n` and blank lines with spaces; outer spaces hide no type conflict; stripped promoted canonical; a NULL source ranks last (#496, #497, #506, #507, #508, #510) |
| NER | `test_stage2d_cyner.py` | 4 | CyNER label mapping, entity extraction, model fallback |
| NER | `test_ner_precision.py` | 85 | ADR-0088 filters: the switch (default on); CyNER threat actors dropped (no capital and no digit, countries, nationalities, platforms, category words) or kept (APT27, Shell Crew, `apt29`); malware untouched; the lowercase-text exception and the hash appendix that must not trigger it; spaCy places (article, wrapped line, acronyms, camel case, "the US"); Stages 2d and 2 with stubbed models, switch on and off, the lowercase copy dropped before the dedup |
| Evaluation | `test_measure_ner_precision.py` | 71 | ADR-0089's decision rule in `scripts/measure_ner_precision.py`: each gate's threshold at its boundary (M1 +5 points, M2 and M4a one gold entity net, M4a and M4b one point, M5 2%), the float edge cases, void when M0 fails, incomplete when the train replay is missing or is not the one named; which records are run again (error or unreadable, a Stage 3 request with no answer, a CyNER or spaCy pass that did not run) and which are the model's answer; documents left out, a document missing from both runs included; the configuration and `run.json` differences between two runs |
| Evaluation | `test_annoctr_time_issue_461.py` | 3 | TimeML scoring counts an unverified year repair's candidate; every expression is read or has one reason (#461) |
| Evaluation | `test_eval_attack_issue_462.py` | 7 | ATT&CK eval: a chain ending on a deprecated or revoked id resolves to nothing, an active id still resolves; a technique new in the release is no extra procedure (#462) |
| Evaluation | `test_eval_issue_458_459.py` | 5 | `general_only` excludes the cyber reports of every split (#459); two gold locations that read the same are one entity (#458) |
| Evaluation | `test_evidence_in_gold_issue_463.py` | 6 | the support sample's `in_gold` counts every gold technique, unlocated ones included; the CSV carries `in_gold` and `gold_located` (#463) |
| Evaluation | `test_retrieval_long_passage_issue_460.py` | 3 | a gold passage longer than a chunk is found when a chunk lies inside it; sentence passages still found (#460) |
| Evaluation | `test_calibration_issue_400_401.py` | 5 | calibration reads skip a non-finite confidence and empty sources or origins (#401); a cutoff's support counts only the calibrated band below auto-accept, and a cutoff above auto-accept stays `above_auto_accept` (#400) |
| Evaluation | `test_eval_issues_481_482_528_529_530.py` | 9 | order-independent entity matching, symmetric agreement, negative TTP and relation normalisation, CVE/MAC/IPv6 case (#481, #482, #528, #529, #530) |
| Evaluation | `test_calibration_issue_501_527.py` | 2 | a stored cutoff for a source without a stage default is used; a failed apply writes no earlier row (#501, #527) |
| NER | `test_stage2e_gliner.py` | 16 | per-type cutoffs, model loading (no deprecated `resume_download`), batch fallback, merge precedence |
| NER | `test_stage_registry.py` | 4 | registry merging, deduplication, case insensitivity |
| NER | `test_gazetteer_context.py` | 113 | gazetteer context: a contracted negation is no alias (#359), a preposition before the type is no apposition (#360), one line break is a blank in a construction, a blank line is not (#408), an ATT&CK id after the name is no obstacle (#410), a URL ends at an unbalanced mark (#407) |
| NER | `test_gliner_casing_issue_394.py` | 8 | GLiNER keeps the span's casing from its offsets; a value matches as a whole word only, so `rat` is not found inside `crates` nor a name inside a longer number (#394) |
| NER | `test_ner_precision_issue_396.py` | 18 | a lowercase country is no place, a capitalised one still is; Active Directory is no threat actor (#396) |
| NER | `test_stage2c_cache_issue_389.py` | 4 | the Stage 2c corpus cache is keyed on its domains and the model loaded; a fallback model never reads the primary's cache (#389) |
| NER | `test_type_conflict_ledger_issue_397.py` | 5 | a type loser resolved away is recorded in the ledger as outranked by the kept type, once; the run's ledger and the bundle agree (#397) |
| NER | `test_type_conflict_ledger_api_issue_397.py` | 11 | the worker stores Stage 2's losers (`jobs.resolved_types_json`, `baseline_stix` for a loser the baseline holds) and a finalize records them; NULL, unreadable rows, a rejected winner or a losing type the analyst brought back leave no outranked entry (#397) |
| **Aliases** | `test_aliases.py` | 6 | alias resolution, MITRE ID mapping, surface forms |
| **Aliases** | `test_alias_disambiguation.py` | 11 | type-aware resolution, alias isolation, canonical name handling |
| **Aliases** | `test_alias_list_spaces_issue_393.py` | 10 | a no-break space joins the anchor words of an alias list and a CyNER name; a line break or a blank line ends the anchor; every emitted name has single spaces (#393) |
| **Aliases** | `test_technique_id_domain_rank_issue_377.py` | 7 | a technique name shared across MITRE domains resolves to Enterprise first, as in Stage 3c; a CAPEC-only name still resolves to CAPEC (#377) |
| LLM enrich | `test_stage3.py` | 80 | LLM enrichment, JSON parsing, deduplication, prompt sanitization, the document-level pass reaching the provider whole |
| Relationship verification | `test_stage3d_verify.py` | 20 | Stage 3d sees the whole text, cuts the text not the claims, batches, document mode (reference sentence yes, chain no) |
| Relationship verification | `test_stage3d_issue_398.py` | 7 | a gap claim backed by a quote becomes `reported`, one held for review keeps `gap`; a long quote is cut at a word boundary (#398) |
| LLM enrich | `test_stage3_providers.py` | 5 | readiness gating for anthropic, gemini, mistral and the OpenAI-compatible local providers |
| LLM enrich | `test_stage3_calls.py` | 84 | client construction, provider diagnostics, Anthropic/OpenAI-compatible calls and retries, the provider's finish reason counted per call (also with no content) and the per-call output ceiling, dispatch, repair of a truncated answer (never collapsed to one nested object), `enrich_chunk`/`enrich_all_chunks`/`enrich_document_relations` branches |
| LLM enrich | `test_stage3f_empty_preamble_issue_378.py` | 8 | an empty list in the preamble does not hide the selection that follows; a bare list after it is read; an answer of only empty choices is still an abstention (#378) |
| LLM enrich | `test_stage3f_quotes_issue_402.py` | 8 | a quote is found past a zero-width space in the report, the prompt's invisible characters are dropped the same way, the spotlight markers count toward the prompt limit (#402) |
| LLM enrich | `test_stage3f_quote_issue_493.py` | 4 | a `verified: true` whose quote is empty or absent from the report counts as unverified and the technique is removed; the quote is never copied into the description (#493) |
| LLM enrich | `test_model_config_issue_531.py` | 8 | `PipelineConfig.from_env()` reads the model variable of the selected provider (#531) |
| LLM enrich | `test_strip_reasoning_prefix_issue_379.py` | 8 | a `<think>` block after a log prefix or a newline is removed and the prefix kept; every block before the answer is removed; a think tag inside the JSON answer is kept (#379) |
| **CVE enrichment** | `test_cve_enrichment.py` | 30 | CVE id validation, the path-traversal guard before any URL, opt-in network flag, fetch and time caps, CIRCL CVE 5.x parsing (ADP then CNA scores), the PostgreSQL cache and its remembered misses |
| **CVE enrichment** | `test_cve_enrichment_issue_395.py` | 8 | an answer with no description and no score is a miss, and the first and second lookup agree on it; a `None` score does not hide the CVSS 3.0 or the later metrics, nor the CNA score behind an ADP one (#395) |
| Hallucination filter | `test_stage3b.py` | 11 | hallucination filtering, entity presence checks, allow-list bypass |
| Hallucination filter | `test_mitre_aliases_stage3b_issues_512_514.py` | 15 | `get_tactics` copy, non-string lookup and search, non-object index read as unreadable, `doc_context=None` (#512, #513, #514) |
| **TTP precision** | `test_ttp_precision.py` | 36 | threshold resolution, semantic confidence, subsumption, verification (whole chunk sent; the fake verifier quotes the report, #493) |
| **TTP precision** | `test_ttp_volume_controls.py` | 16 | cross-source dedup, corroboration floors, taxonomy filtering |
| **TTP precision** | `test_ttp_sentence_gates.py` | 14 | sentence unwrapping, keyword gating, candidate selection |
| **TTP precision** | `test_ttp_evidence_merge.py` | 11 | evidence preference, semantic fallback, label preservation |
| **TTP precision** | `test_ate_scoring.py` | 13 | ATE scoring, partial credit, macro averaging, diagnostics |
| **TTP precision** | `test_ttp_retrieval_issue_391_392.py` | 15 | BM25: singular and plural share a stem; a query sharing no token gives no candidate, and one hit gives one (#391, #392) |
| **Evidence spans** | `test_evidence_span.py` | 19 | offset normalization, quote location, sentence bounds |
| **Evidence spans** | `test_evidence_span_offsets.py` | 11 | index mapping, coverage calculation, quote matching |
| **Evidence spans** | `test_merge_keeps_evidence.py` | 10 | evidence preservation, confidence ranking, deduplication |
| **Evidence labels** | `test_evidence_consensus.py` | 4 | label normalization, STIX properties, consensus boosting |
| **Evidence labels** | `test_consensus_gap_issue_399.py` | 3 | a triplet the second model proposes only as `gap` is neither boosted nor penalised; one non-gap proposal still corroborates, an absent one is still penalised (#399) |
| Evidence labels | `test_stage3e_issue_399.py` | 5 | with no second provider there is no consensus, and `enable_consensus=False` turns it off (#399) |
| STIX mapping | `test_stage4.py` | 84 | SDO/SCO/SRO build, alias merging, IoC coverage, observable routing (ADR-0041, ADR-0062), a URL that is not a URI left out with its ledger reason |
| STIX mapping | `test_stage4_paths.py` | 52 | every observable to its SCO and pattern, named SDOs, PAP, embedded-rule Indicators, pin budget/grounding/malformed policies, relationship guards, CVE/CVSS and campaign merges, stix2 refusals |
| STIX mapping | `test_stix_rel_spec.py` | 4 | listed vs allowed relationships: common verbs, unknown types, direction |
| STIX mapping | `test_network_traffic.py` | 22 | network flows: a flow and its host are one observable (#364); TCP and UDP flows to one host are two Indicators, a single flow keeps its protocol in the pattern, and two observables with one pattern share one Indicator (#365); what the text states is read, nothing is guessed, an out-of-range port is dropped |
| STIX mapping | `test_stix_ids.py` | 19 | ids equal to OpenCTI's standard ids: 15 values produced by pycti's own `generate_id` (ADR-0066), case and CAPEC rules |
| STIX mapping | `test_bundle_ledger_merged_via_issue_416.py` | 4 | an entity merged by the alias merge then the baseline keeps `merged_via`, one merged once has none; a removed relationship's refs follow the alias and the baseline merge (#416) |
| STIX mapping | `test_bundle_ledger.py` | 24 | mapping ledger: every row outcome and change, origins, 4b alias merge, API round-trip (ADR-0061); an IoC `indicates` a technique through its Indicator, turned around when written backwards (ADR-0065) |
| STIX mapping | `test_bundle_ledger_issues_504_505.py` | 7 | dict objects; merge reasons on absorbed relationships (#504, #505) |
| STIX mapping | `test_stix_self_edges.py` | 4 | self-edge prevention, endpoint validation, bundle integrity |
| STIX mapping | `test_targets_explicit_issue_383.py` | 4 | an explicit `targets` row replaces the edge the targeted lists built, keeping its quote and confidence (#383) |
| **Graph completion** | `test_stage4b_completion.py` | 18 | transitive completion, alias merging, grounding, pins |
| **Graph completion** | `test_stage4c_long_distance.py` | 16 | long-distance inference, direction swap, evidence recording, passages naming the entities in a long report |
| **Graph completion** | `test_stage4c_issues_502_503.py` | 7 | dict objects give an edge with their ids, a missing id none; a `<think>` draft is not the answer (#502, #503) |
| **Graph completion** | `test_long_distance_sdo_only_issue_417_412.py` | 5 | long-distance completion links SDOs only: an isolated domain gets no direct edge (#412); an artifact of the source PDF is no central node, and an edge to a non-SDO is refused into the ledger (#417) |
| **Graph completion** | `test_grounding_by_label.py` | 8 | STIX display names, edge scoring, bundle validation |
| Validation/export | `test_stage5.py` | 23 | bundle validation (the three verdicts, the schemas shipped with the repository and their install), file writing, nested directories; `validate_bundle` writes nothing and judges as `validate_and_export` does, `export_path` names the file by verdict (`_invalid` suffix), `export_bundle` writes where the verdict says (ADR-0086) |
| Validation/export | `test_validate_bundle_issue_500.py` | 6 | `validate_bundle` returns INVALID, not an exception, for non-bundle input (#500) |
| Baseline STIX (ADR-0090) | `test_baseline_stix.py` | 454 | `pipeline/baseline_stix.py`: the entity-type table against what Stage 4 builds, normalisation (a URL's path keeps its case, #483), the keys of a row, an object and a STIX pattern, families, `resolve` / `lookup` (exact-type tie-break, `AMBIGUOUS`), intake (limits, 2.0 refusal, ids and versions, scope by Report, including a relationship between two in-scope objects the Report omits, rules, id collisions, reference closure, TLP/PAP minimum, the index), the bounded search for objects the schemas refuse, hostile input, and `validate_bundle(quiet=True)` returning the verdict silently; since lot 7, the file name as a weak key (`lookup_weak`: one entry holding a file object, none for two carriers or for an Indicator alone) and a name-only Indicator joining the observable its `based-on` names when exactly one such observable is named and shares a key with the pattern |
| Baseline STIX (ADR-0090) | `test_baseline_issue_413_416.py` | 6 | a baseline object the document states is listed by the re-issued report (#413, with the refs it gained counted); an inferred edge names the baseline edge its premise became (#414); a baseline actor is found by the MITRE name of its intrusion set (#415) |
| Baseline STIX (ADR-0090) | `test_baseline_api.py` | 66 | the flag (`/api/baselines/status`, 400 on every baseline route while off, a request without a baseline unchanged), `/api/baselines/inspect` (summary, report choice, refusals, 413, stores and logs nothing), the baseline on the three ingestion routes (the `enrich` job and its stored bundle, refusal before the report is written and before the URL capture, the Report choice, the TLP/PAP minimum, one WARNING per excluded object, NUL and lone surrogates, non-UTF-8 as 400), `pipeline_mode` and `enrichment` on the job, the bundle download, deletion and the retention sweep, 409 on editing or deleting an imported entity or relationship while accepting and rejecting still work, and the `baseline_stix` origin a client cannot claim, no TLP never below the server default, the cheap refusals before the baseline is read (short text, report over its limit, mode off), blank baselines, at most two bundles read at once (503), a long list of exclusions logged and shown in part, an upload that fails for any reason leaving no report file, the baseline read on its own threads, and a job the full queue rejects keeping no baseline |
| Baseline STIX (ADR-0090) | `test_baseline_worker.py` | 8 | the worker runs the JSON schemas before the pipeline starts, excludes with a WARNING an object only they refuse, fails the job with the reason when the baseline cannot be used or is missing, leaves a `full` job alone, does not validate a validated baseline again, logs an unusable baseline as a warning without a traceback, and caps its exclusion lines |
| Baseline STIX (ADR-0090) | `test_baseline_reconcile.py` | 31 | Stage 3r's `reconcile` (pure): the four passes, a match by key and by alias, families, the whole-word search in the report text with the earliest form as evidence, a relationship matched by its ends and verb, endpoints resolved through the baseline's forms, a value two entries share resolving to none, the stats, blank values, no offset when lowering changes the length, held TTPs matched like extracted ones; since lot 7, a file matched through its name when exactly one baseline entry carries it, and left `new` when two do or when the one carrier is an Indicator alone |
| Baseline STIX (ADR-0090) | `test_orchestrator_baseline.py` | 5 | Stage 3r in the orchestrator: its place after 3doc and its label, skipped and never called in full mode, reconciled once before `extraction_ready` in enrich mode, given the extractions and the baseline, a failing reconciliation failing the run before any write |
| Baseline STIX (ADR-0090) | `test_baseline_persistence.py` | 11 | what a run stores against a baseline: the Stage 3r columns NULL in full mode, matched rows pre-accepted with origin `baseline_stix`, imported rows stored pre-accepted with source `baseline_stix`, relationships' status and origin, auto-accept leaving the imported and matched rows alone, `load_index` (none for a full job or a missing row), the worker's hook handing the reconciliation to the save |
| Baseline STIX (ADR-0090) | `test_baseline_exclusions.py` | 3 | the `baseline_stix` source constant, `load_decisions` never reading a baseline row, the grounding harness reading full jobs only |
| Baseline STIX (ADR-0090) | `test_baseline_merge.py` | 30 | the merge of Stage 4 (`merge_baseline`, `reissue_report`, pure): a CTIParsor object replaced by the baseline object it matches (an Indicator, an observable through its entry, an object sharing its id), references rewritten, a relationship identical to a baseline one dropped and the baseline kept, two that become one kept first, a self-loop dropped, a rejected object and what refers to it left out, the chosen Report never added or kept, the kept objects written back as received, the re-issued Report's `modified` (+1 ms when the clock is behind, the build time without a valid original), `validation_json` dropping exactly the trusted objects, the in-text entities, `newest_versions` (the version of an id the intake keeps), a lone surrogate in a verbatim object written as an escape, non-ASCII text left unescaped otherwise; since lot 7, a name-only file remapped onto the one baseline file of its name, and a file with a hash of its own never merged on its name; a name-only `[file:name = …]` Indicator remapped onto the kept Indicator of its file, never onto a hash Indicator; a course of action or a rule Indicator of the same content remapped onto the one kept baseline object of that content, and nothing merged when two such objects exist |
| Baseline STIX (ADR-0090) | `test_baseline_merge_issues_483_484_492.py` | 11 | URL path case, compound Indicator not folded; a duplicate's dates and description re-issue the baseline edge, nothing added = untouched, inverted dates refused (#483, #484, #492) |
| Baseline STIX (ADR-0090) | `test_baseline_merge_remap_issue_414.py` | 7 | a CTIParsor observable whose id the analyst excluded is left out with the relationship naming it (ledger `baseline_rejected`); a kept twin absorbs its copy despite the excluded entry; controls: an out-of-closure object still comes back, a kept observable is written once, two kept twins stay unmerged, an unrelated observable stays (#414) |
| Baseline STIX (ADR-0090) | `test_stage4_baseline.py` | 7 | `build_stix_bundle` with a baseline, `merge_baseline` and `reissue_report` replaced by fakes: unchanged without one, the chosen Report re-issued in place of a CTIParsor Report, a CTIParsor Report with its enrichment when there is none, kept objects not stamped, the ledger recording the merge without `changes`, one marking-definition in the bundle, a re-issued baseline edge (#492) ships re-issued, leaves `trusted`, and the ledger names its changes |
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
| **Provenance** | `test_rebuild_bundle_provenance_issue_465.py` | 1 | a rebuilt provenance bundle leaves out rejected objects and keeps the named ones, built as finalize builds it (#465) |
| **Relationship policy** | `test_pin_budget.py` | 23 | fair share allocation, edge key validation, materialization, observable routing |
| **Relationship policy** | `test_pin_evidence.py` | 31 | term extraction, sentence indexing, grounding gates, pins on listed observable pairs |
| **Relationship policy** | `test_policy_last_run.py` | 17 | stats extraction, database queries, bundle handling |
| **Relationship policy** | `test_policy_rule_validation.py` | 15 | policy validation, API rejection, graph survival |
| **Rule adapters** | `test_sigma_adapter.py` | 18 | rule parsing, tactic skipping, registry loading, a non-UTF-8 file or a broken document logged by path while the valid rules are kept (#372, #373), two documents without `id` in one file get distinct ids (#375) |
| **Rule adapters** | `test_suricata_yara_adapters.py` | 17 | Suricata and YARA corpora end to end: ids, severity, header atoms from bracketed lists, dedup keys, private rules, file extensions |
| **Rule adapters** | `test_sigma_negation.py` | 15 | negation logic, selector expansion, condition parsing |
| **Rule adapters** | `test_multiformat_atoms.py` | 47 | atom extraction, buffer handling, negation, metadata |
| **Rule adapters** | `test_escape_unescaping.py` | 12 | YARA/Suricata unescaping, backslash handling, edge cases |
| **Rule adapters** | `test_atom_normalisation.py` | 6 | basename stripping, lowercase enforcement, atom trimming |
| **Rule adapters** | `test_rebuild_store_issue_384.py` | 1 | a failure in the middle of a rebuild keeps the `rule_text` title index (#384) |
| **Rule adapters** | `test_registry_shapes_issue_436.py` | 6 | a registry of the wrong shape is unreadable, a non-mapping entry is skipped, a bad priority falls back to the default (#436) |
| **Rule adapters** | `test_snort_parser_patch_issue_422.py` | 5 | the copied Snort parser refuses a sticky buffer after `content` as unrecognized; a Suricata sticky buffer typed as Snort is retyped (#422) |
| **Rule adapters** | `test_store_duplicate_ids_issue_430.py` | 3 | a batch repeating a Sigma id or a Suricata sid keeps only the last rule's atoms (#430) |
| **Rule adapters** | `test_suricata_buffers_issue_428.py` | 7 | `pkt_data` closes the sticky buffer; `fast_pattern` and `nocase` are not part of the literal (#428) |
| **Rule adapters** | `test_suricata_metadata_issue_421.py` | 5 | every ATT&CK technique in a Suricata rule's metadata is kept, including a key repeated in one option or across two (#421) |
| **Rule adapters** | `test_yara_rule_end_issue_427.py` | 6 | a brace, a closing brace, a quote or a slash in a `matches` regex does not end the YARA rule early (#427) |
| **Rule adapters** | `test_yara_issue_426_425.py` | 12 | a FQDN with a final dot is a domain and a lone label after `www.` is not (#426); a commented line or a `condition:`/`strings:` word inside a literal is not read as a section (#425); a `/*` after a `matches` regex is no comment (#427) |
| **Rule adapters** | `test_yara_dedup_issue_420.py` | 4 | blanks inside a condition literal or a `matches` regex keep rules apart; blanks between tokens are still ignored (#420) |
| **Rule adapters** | `test_yara_check_issue_435.py` | 4 | a meta string cut after an escaping backslash is joined with no space; a doubled backslash and a plain wrap keep the space (#435) |
| **Rule adapters** | `test_yara_check_empty_issue_517.py` | 10 | a blank YARA rule is refused for Stage 4, the baseline and `compile_status` (#517) |
| **Rule adapters** | `test_yara_export_body_issues_478_479.py` | 8 | the exported body compiles with yara-python: imports, private rules, `global` scope, stable id (#478, #479) |
| **Rule adapters** | `test_snort_parser_issues_519_521.py` | 31 | single bracketed address or variable parses; out-of-range and unknown ports refused, valid ones kept; `depth` and `sanitize` (#519, #520, #521) |
| **Rule adapters** | `test_pattern_check_empty_issue_434.py` | 15 | a blank Sigma, Suricata or baseline rule is refused for every type, and a blank Suricata rule is not retyped (#434) |
| **Rule adapters** | `test_detection_builder_issue_373.py` | 2 | `rebuild_store` after a broken YAML document keeps the valid rules and lists the file in `file_errors`; a non-UTF-8 file is listed by its path (#373) |
| **Rule adapters** | `test_sigma_ids_issue_375.py` | 2 | two Sigma documents without `id` in one file become two rows with their own atoms, and a rebuild keeps both (#375) |
| **Rule adapters** | `test_registry_concurrency_issue_371.py` | 2 | overlapping `add_corpus` calls keep both overlay entries (the overlay write is locked); a failed overlay write keeps the previous overlay (#371) |
| **Rule adapters** | `test_registry_source_issue_368.py` | 4 | the merged registry entry carries one source only, the one the overlay chose (tarball over Git remote and back), also after `add_corpus` (#368) |
| **Rule adapters** | `test_detection_sync.py` | 35 | corpus sync: tarball members that are unsafe are skipped, the Git and tarball dispatch, the clone check stubbed out here (its own tests are in `test_sync_remote_issue_367.py`) |
| **Rule dedup** | `test_detection_dedup.py` | 10 | dedup key logic, canonical election, provenance folding |
| **Rule dedup** | `test_sigma_dedup_case_issue_429.py` | 8 | base64 values keep their case in the Sigma dedup key; `contains` keeps a leading or trailing space and still folds the case of its value (#429) |
| **Rule dedup** | `test_also_in_transitive_issue_431.py` | 2 | `also_in` follows a chain of provenance folds and of dedup-key folds (#431) |
| **Rule dedup** | `test_provenance_dedup.py` | 18 | dedup clustering, provenance folding, deterministic merging |
| **Rule dedup** | `test_dedup_propagated_issue_432.py` | 4 | inherited techniques are marked `propagated` and recomputed each pass: a removed corpus or a split cluster leaves none behind, a rule's own technique stays (#432) |
| **Rule relevance** | `test_detection_relevance.py` | 29 | atom mapping, platform factors, IDF weighting, ranking |
| **Rule relevance** | `test_technique_idf.py` | 21 | technique counting, IDF calculation, rule mapping |
| **Rule relevance** | `test_relevance_corroboration.py` | 8 | corroboration scoring, match weighting, proposal flags |
| **Rule relevance** | `test_control.py` | 19 | value discrimination, domain guards, host classification |
| **Rule relevance** | `test_brands.py` | 23 | brand detection, domain themes, evidence preference, three TLDs of one name counted as three domains and one host spelled several ways counted once (#361), `rebuild_rule_text` over canonical rules and in batches, a demoted rule never a brand or CVE match (#362) |
| **Rule relevance** | `test_observables_domain_guard.py` | 10 | domain validation, filename rejection, URL handling |
| **Rule relevance** | `test_benign_issue_411.py` | 15 | a host anyone publishes on (gist, raw.github.com, Google Sites) is no reference; `www.` is ignored on both sides; the other references and popular domains unchanged (#411) |
| **Rule relevance** | `test_brand_maximal_issue_423.py` | 3 | brand maximality applied after the rule filter: a brand survives a longer token that names no rule, a multi-TLD brand is found (#423) |
| **Rule relevance** | `test_cve_title_tokens_issue_424.py` | 6 | a CVE written with underscores, spaces or hyphens is found in a title; a run of digits is no brand token (#424) |
| **Rule relevance** | `test_promotion_issue_418.py` | 4 | a null promotion source is not listed and does not break sorting; an active promotion keeps its counts current (#418) |
| **Rule relevance** | `test_rule_text_rebuild_issue_363.py` | 2 | `rebuild_store` refills the `rule_text` title index it erased, so the CVE title match survives a Rebuild index; a rule demoted by dedup is not indexed (#363) |
| **Rule relevance** | `test_stale_rule_text_issue_362.py` | 1 | a re-elected canonical rule is not served from a stale `rule_text` index: every title read joins on `is_canonical = 1` (#362) |
| **Rule relevance** | `test_detection_issues_515_516_518_522_523.py` | 15 | limit 0; evidence-admitted untagged rules kept; host normalisation from URLs, emails, files; mixed-case ids; artifact label (#515, #516, #518, #522, #523) |
| **Detection coverage** | `test_detection_coverage.py` | 51 | scoring policy, format splitting, export selection (a canonical rule outside the report's techniques is packaged, #366), evidence |
| **Detection coverage** | `test_detection_artifacts.py` | 26 | artifact scoring, evidence capping, folding, vocabulary |
| **Detection coverage** | `test_detection_phases.py` | 15 | tactic mapping, off-matrix handling, phase counting, a column for every enterprise tactic on every committed ATT&CK track (ADR-0087) |
| **Detection coverage** | `test_attack_data_issue_405.py` | 8 | a track with an empty, unusable or other-release manifest is not listed; a track named like the default is listed once; listed tracks in version order, each resolving (#405) |
| **Detection coverage** | `test_mitre_db_issue_404.py` | 9 | a valid JSON index of the wrong shape is empty, not a crash; `get_techniques` returns a new list, so a caller clearing it does not empty the cache (#404) |
| **Detection coverage** | `test_build_revoked_domains_issue_464.py` | 3 | the revoked-name index is built from Enterprise only: a Mobile active name does not hide an Enterprise revoked name (#464) |
| **Detection coverage** | `test_mitre_db.py` | 8 | ATT&CK/CAPEC index lookup and search ranking, missing or corrupt index |
| **Detection coverage** | `test_coverage_artifacts_api.py` | 5 | artifact coverage routes, payload shape, 404 handling |
| **Export filters** | `test_export_filters.py` | 13 | facet totals, format filtering, license exclusion, manifest |
| **Export filters** | `test_rule_lookup.py` | 8 | rule lookup, metadata retrieval, license handling |
| **Export filters** | `test_export_promoted_issue_366.py` | 4 | the rule-id export packages a promoted rule next to a covered one, alone (no 404), an unknown id is ignored, promoted ids are capped at the lookup maximum; the manifest marks promotions (#366) |
| **Export filters** | `test_rule_ids_nul_issue_526.py` | 6 | a NUL or lone-surrogate rule id gets a 422 on lookup and export (#526) |
| **Rule synthesis** | `test_synth_sigma.py` | 47 | rule synthesis, value validation, path escaping, stability |
| API | `test_api_routes.py` | 11 | health checks, job listing, upload validation, progress |
| API | `test_attack_api.py` | 5 | `GET /api/attack/index`: each committed ATT&CK track served byte for byte with `X-Attack-Release`, the sha256 ETag and its 304, the 19.2 ETag sent to an API on 20.0 gets the 20.0 index, a track without an index answers 404 (ADR-0087) |
| API | `test_relationships_api.py` | 18 | relationship creation, label coercion, patch validation, dates, `POST /relationships/bulk` (`human_bulk`, journaled, other jobs untouched — ADR-0065) |
| API | `test_settings_api.py` | 53 | corpus listing, overlay management, rebuild ingestion, formats, unsafe paths/remotes/tarballs, enable/disable, per-corpus sync |
| API | `test_sync_remote_issue_367.py` | 12 | a Redownload refuses a folder that is not a clone of the configured remote (409, no fetch), compares remotes without credentials, accepts the same remote spelled differently, clones a missing path, skips tarball corpora (#367) |
| API | `test_sync_corpora.py` | 9 | `sync_corpora`: a folder that is not its remote's clone fails before git runs (#367), a corpus managed by hand is skipped and is not a failure |
| API | `test_sync_subdir_issue_374.py` | 5 | a sync whose `subdir` is missing answers 422 naming it and keeps the index; a correct subdir answers 200 with its rule count and `file_errors` (#374) |
| API | `test_nul_path_issue_386.py` | 6 | a NUL byte in a job id, a job-scoped path or the progress path is a 404, not a 500 (#386) |
| API | `test_patch_empty_values_issue_438.py` | 8 | PATCH refuses an empty relationship type or entity value and stores nothing; an absent value is a partial patch (#438) |
| API | `test_blank_and_nul_endpoints_issues_494_495_525.py` | 26 | blank entity values and relationship ends refused with 400; NUL and lone surrogates in every text field refused with 422; valid values and partial patches unchanged (#494, #495, #525) |
| API | `test_bundle_publish_issue_499.py` | 3 | an overtaken finalize publishes the rebuilt bundle, not the stale one; overtaken at every build it stops with `FinalizeOvertaken` (#499) |
| API | `test_patch_processing_job_issue_385.py` | 8 | a status change of a running job is refused whatever the lease says; a job not running can still be set (#385) |
| API | `test_progress_threads_issue_387.py` | 2 | the progress stream reads the database off the event loop and answers the same events as before (#387) |
| API | `test_tarball_truncated_issue_433.py` | 5 | a truncated or damaged tarball is a failed sync, its reason named in the server log; an intact archive still extracts (#433) |
| API | `test_upload_orphan_issue_439.py` | 5 | a job that fails to start leaves no uploaded file (upload, pasted text or capture); a started upload keeps its file (#439) |
| API | `test_jobs_routes.py` | 23 | job list/get/status, finalize, delete (rows and every file), retention sweep, source file, bundle and ledger |
| API | `test_entities_api.py` | 13 | manual entities, edit, bulk accept/reject/reset, delete, refusals |
| API | `test_policy_api.py` | 22 | relationship policy round trip, default fallback, every refused shape |
| API | `test_logging_config.py` | 9 | request ids, JSON/text formatters, `setup_logging` handlers, log helpers |
| Persistence | `test_persistence.py` | 13 | backup consistency, migration idempotency, label persistence |
| Persistence | `test_db_transaction.py` | 6 | transaction rollback, commit, exception handling |
| Persistence | `test_container_env.py` | 4 | `CTIPARSOR_GIT_REV` fallback when `git` is absent or fails (ADR-0044) — `_path_from_env`/`BACKUP_DIR` and `CTIPARSOR_DB_PATH` were removed along with SQLite (ADR-0053) |
| Persistence | `test_entrypoint_pgpass_issue_469.py` | 5 | the container entrypoint escapes a backslash, then a colon, in `.pgpass`; the entrypoint is valid `sh` (#469) |
| Persistence | `test_migrate_jobs_backfill_issue_466.py` | 1 | `decision_origin` is backfilled after the copy; orphan rows are skipped (#466) |
| Persistence | `test_migrate_lock_timeout_issue_443.py` | 2 | `lock_timeout` is reset when the migration lock is not taken, and after a successful upgrade (#443) |
| Persistence | `test_translate_placeholders_issue_440.py` | 20 | `?` is translated only outside SQL comments, quotes and dollar-quoted bodies (#440) |
| Persistence | `test_translate_named_placeholders_issue_524.py` | 6 | `%(name)s` placeholders survive `translate_placeholders`; `%` inside strings still escaped (#524) |
| Persistence | `test_retention_issue_488.py` | 3 | a job requeued or touched after the sweep chose it is kept with its rows (#488) |
| Queue | `test_deny_cli_path_issue_382.py` | 5 | the analyst's deny rows drop the denied names and targets from the LLM lists on both bundle paths, the CLI and the worker (#382) |
| Queue | `test_cli_stage_disabled_issue_457.py` | 4 | the CLI exits 0 when the user disabled Stage 4 or 5; a Stage 5 answer still decides (#457) |
| Queue | `test_requeue_returning_issue_442.py` | 2 | `requeue_orphans` announces only the rows it requeued (#442) |
| Queue | `test_queue_claim_issue_491.py` | 3 | a launch carries its claim's identity and is abandoned when the claim is gone (#491) |
| Queue | `test_worker.py` | 51 | the worker's terminal states (no bundle, timeout, abort, reclaimed, failed backup), hook guards, subprocess thread caps, the crash watcher, the finalize rebuild applying reviewer rejections and reading legacy/ADR-0063 dates, Stage 5's verdict deciding what a rebuild may complete (ADR-0084), a run storing its build record (ADR-0086) |
| Queue | `test_job_queue.py` | 30 | the queue loop (ADR-0046): atomic claim under 8 threads, lease-based orphan requeue, heartbeat scoping, slot accounting with a fake spawn, `run_pipeline_async` under roles `api` and `all`, `--once`; its `worker_heartbeats` row (ADR-0094 item 7): written at start and while idle (on the first pass, however young the clock), its `started_at` kept, deleted when a worker process or the API loop stops and not written back by a late pass, deleted by a running loop once silent for an hour, a failed write logged while the job still starts; the liveness file left alone while the job store does not answer, touched again after one good write |
| Queue | `test_queue_status_api.py` | 16 | `GET /api/queue/status` (ADR-0048, ADR-0094 item 7): counts by status, the oldest queued report, `max_depth`, role and backend; every worker listed `busy`, `idle` or `stale`, the latest of its row and job heartbeats deciding, a worker without a row listed from the job it holds, the summary of live workers and free slots, a running loop listed, then gone once it stops |
| Persistence | `test_db_backend.py` | 12 | the PostgreSQL adapter without a server: `?`→`%s` outside literals, `%`→`%%`, the `Row` type, `backend()`/`get_conn()` requiring `DATABASE_URL` (ADR-0053), a fake psycopg connection proving `with` never closes and `transaction()` issues plain `BEGIN` (ADR-0045) |
| Persistence | `test_db_postgres.py` | 10 | skipped unless `CTIPARSOR_TEST_DATABASE_URL` is set (every other DB-touching test needs it too, via `temp_db` — ADR-0053): round trips, SSE resume ids, upserts, cascade, the coverage call without `jobs_conn`, the API through `temp_db_client`, and both migration scripts end to end (ADR-0045, ADR-0053) |
| Shared helpers | `test_shared_helpers.py` | 27 | environment parsing, claim extraction, unescaping logic |
| Fuzzing | `test_fuzz_targets.py` | 6 | every Atheris target (ADR-0081) over its seed corpus, `fuzz/corpus/<target>/`, and the empty input: a target that stops importing, or whose invariant a seed breaks, fails here between fuzzing runs; skipped off Linux x86_64 (no Atheris wheel) |
| Docs | `test_doc_claims.py` | 2 | every number `scripts/check_doc_claims.py` checks in README.md and docs/pipeline.md still matches its source, and is still found (what `make check-docs` did on demand only) |
| Release | `test_release.py` | 94 | the version is one number in `pipeline/__init__.py`, `frontend/package.json` and `frontend/package-lock.json`, and the CHANGELOG opens with `## [Unreleased]`; `scripts/release.py` (`version`, `check`, `notes`, `unreleased`, `prepare`, `predicate`) on throwaway trees: every refusal, every mismatch reported, the notes' length limit, no file written when `prepare` refuses, only the standard library imported (ADR-0085); `ci.yml`, read as the lines its scripts run (comments out, `set -euo pipefail` first): both image jobs on `ubuntu-26.04` and refusing any image store but containerd, no container of their own, the image built once into an OCI archive with its provenance stated, scanned and smoke-tested as loaded from it, `publish-image` building nothing, pushing that archive and failing unless GHCR holds the digest `container-image` reported, `latest` moved last and only for main's head, every action pinned to a commit with its version (ADR-0047); a CRLF version line is read with its CRLF kept, and a fourth-level title before the first group stays in the opening (#470) |
| Interoperability | `test_opencti_expectations.py` | 30 | `scripts/opencti_expectations.py` (ADR-0094 item 8) on a platform built as the OpenCTI check reads it back, without pycti or OpenCTI: an object found by any id it answers to, or by its name or aliases once OpenCTI renamed it; each expectation failing on its counter-example (an object missing, two objects or two relationships of a bundle merged into one, a second object under a name or an alias, a second relationship between the same objects, a relationship joined elsewhere, an author or a marking no bundle set, a description emptied, the Report's description, file, references (one merged into another included) or confidence changed, a second import that refuses or adds, an object gone after a later import, a reading that never settled); a marking another bundle set on the same object expected; one name under two types a WARN, not a failure; OpenCTI's defaults and its millisecond timestamps not reported as changes, whole values and list diffs kept; step 0 (the jobs' commit, a job without one failing, `validated`, the sha256 of what was imported); where the bundles and the checkout come from in the report; the report and its exit codes; `scripts/check_opencti_candidate.sh` refusing a run without a candidate, and running Compose without the caller's `CTI_IMAGE`, `CTI_ENV_FILE` and `OPENCTI_*`, with a digest as given (a fake `docker`) |
| Installation | `test_check_clean_install.py` | 28 | `scripts/check_clean_install.sh` (ADR-0094 item 9) bound to the documents it runs, without Docker: the eight blocks found where README.md, docs/docker.md and docs/upgrading.md write them, once, and `--print-blocks` showing the same; a missing, doubled or malformed block refused; the values lines naming the latest release and the digest docker.md gives it; no block deleting data or naming a project; the downloads through the Releases page the check stands in for, `pull` before `up -d`, no `build`; the backup block leaving the shell's umask alone and its files private; the options; a project, volume, directory or port left in use refused, nothing left when the candidate cannot be pulled (a fake `docker`); the `docker` wrapper letting through the run's two projects only; every documented command under `env -i`; the report; no public document naming a checkout in someone's Windows profile |
| Installation | `test_setup_crlf_issue_468.py` | 5 | `setup.sh` strips the CR of a CRLF `.env` value; a CRLF empty value reads as empty, a missing key does not abort under `set -e`, an LF value is unchanged (#468) |
| Scripts | `test_check_stages_issue_533.py` | 2 | `chk_browser` checks the Chromium browser (#533) |
| Scripts | `test_migrate_rules_issue_534.py` | 1 | `rule_text` rows with no rule in the SQLite source are skipped and counted (#534) |
| Scripts | `test_check_requirement_floors_issue_535.py` | 2 | an OSV advisory whose `affected` entry has no `package` (#535) |
| Scripts | `test_build_indexes_issue_536.py` | 2 | no embeddings manifest for the default model (#536) |
| Scripts | `test_db_upgrade_issue_539.py` | 8 | `db_upgrade.sh` says there is nothing to do and exits 0 when the volume already holds the target major alone (#539) |
| Scripts | `test_audit_scripts_issues_540_541.py` | 2 | both audit scripts run from the repository root (#540, #541) |
| Scripts | `test_docker_smoke_env_issues_542_543.py` | 4 | `docker_smoke.sh` reads `.env` and writes `.secrets/` at the repository root; `.env` read as data, CRLF stripped, the shell wins over `.env` (#542, #543) |
| Backup | `test_backup_commands_issues_485_487.py` | 6 | backup commands name files to the second and run with `pipefail` (#485, #487) |
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
`tests/test_stage4_reference.py` builds six scenarios
(`tests/fixtures/stage4_reference/scenarios/`) through `build_bundle` and
compares the result, bundle and ledger, to a frozen canonical form in
`expected/`. The canonical form (`tests/stage4_reference.py`) replaces the
timestamps that fall within the build window by `<build-time>`, renames by
content the ids stix2 draws at random (relationships and the Report; any
other id, an attack-pattern's and the standard TLP marking ids included, is
compared as is), and sorts objects. Everything else counts: deterministic ids, verbs, refs, ledger
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
`tests/test_migration_compare.py` (from versions 11, 13 and 14 every value kept, a
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

### Clean install from the published image

`scripts/check_clean_install.sh` is the clean install of ADR-0094 item 9: a
release installed from its archive and its published image as a newcomer
would, with the commands of the public documentation as they are written,
then a first report, a restart, the upgrade to the candidate image and a
restore. It is a release step ([docs/releasing.md](docs/releasing.md), step
4), not CI: it downloads two images and, in full, the models and corpora.

What it runs, and the only things it changes:

- the blocks marked `<!-- scripts/check_clean_install.sh: NAME -->`:
  `INSTALL_FILES` and `INSTALL_START` (README, *Quick start*),
  `RESTART_COMMANDS` and `STOP_START_COMMANDS` (docs/docker.md, *Day-to-day
  operations*), `UPGRADE_COMMANDS` (docs/upgrading.md), and the three backup
  and restore blocks of docs/docker.md. It reads them from the documents when
  it starts: what a page says is what the next run runs;
- each block in one shell, line after line, stopping at the first that
  fails; the directory and the umask a block ends with carry over to the next,
  as in a terminal. Every line runs under `env -i` with a new `HOME` (no
  Docker login: the images must pull anonymously), through a `docker` wrapper
  that is an allowlist: `docker compose` on the run's two projects, and the
  `docker info` and `docker --version` that `setup.sh` calls; anything else is
  refused, as is any `-p` and `down -v`;
- the values line of `INSTALL_FILES` and `UPGRADE_COMMANDS` (versions and
  digests); the candidate's archive, `git archive` of the commit its image
  names, served from a `file://` stand-in of the Releases page, since a
  candidate has no Release yet (the previous release's archive comes from
  GitHub); the prose between the blocks: no LLM provider in `.env`, and the
  directory each block starts in; `WORKER_DRAIN_S=5` (step 3); with
  `--quick`, `bootstrap bootstrap --no-models --no-corpora` and the model
  stages off.

The journey, in projects `ctiparsor-clean-install` and
`ctiparsor-clean-install-restored` (ports 8795 and 8796):

1. the previous release (by default the one the README installs): archive and
   `SHA256SUMS` from the Releases page, `setup.sh`, the image by digest,
   `pull`, `up -d`, `bootstrap`; no image built; `/api/health`;
2. report A: `tests/fixtures/sample_report.txt` uploaded, APT29 accepted, the
   review completed, the bundle downloaded with `X-Bundle-Validation:
   validated`; its stage report with no stage failed and, in full, 2c, 2d and
   2e run;
3. report B uploaded and, once `processing`, `docker compose restart app
   worker`, with `WORKER_DRAIN_S=5` in `.env` so that the restart puts B back
   in the queue (with the default 60 s, a 20 s report finishes during the
   drain, as two runs showed): each change of B's status recorded. In full the
   step fails unless B was `processing` at the restart, was put back in the
   queue (`queued` after `processing` in its timeline, or the worker's drain
   timeout in its log) and ends reviewable; a B that only ends reviewable is
   not a pass. `--quick` reports the same facts as `INFO` when B was not
   requeued. Then `down` and `up -d`; A, its status and its bundle's sha256
   unchanged;
4. the backup and its check from the old directory, the shell's umask
   unchanged after it, then the upgrade from the parent directory; the new
   release's `docker/squid/squid.conf` present (its mode is reported, `INFO`:
   as root `tar` keeps the archive's modes, so the umask step is the check),
   `/api/health`, `app` on the candidate's image, the schema migrated (`[db]
   schema version X -> Y` in the logs; a version that cannot be read fails),
   A, its status and its bundle unchanged; report C on the candidate;
5. the backup restored with the previous release into the second project,
   from the old directory: A, its status and its bundle there, the schema the
   backup's, report C absent.

It refuses to start (exit 2) on a missing tool, a Docker context other than
`default` or a `DOCKER_HOST` (the documented commands run with a new `HOME`,
where they reach the default context), a port in use, a project or a
directory left by an earlier run, less than 6 GB of memory available or
20 GB free for Docker. It removes both projects with their volumes and its
directory at the end, on success, failure or Ctrl-C; the pulled images stay.
The report, `output/clean-install/<UTC time>/report.md` and `report.json`,
holds both digests and commits, each step PASS or FAIL, each documented
command with its exit status and duration, sizes, peak memory, report B's
timeline and the logs.

```bash
# from the checkout, as root when Docker needs root (sudo); the candidate is main's image of the release commit
bash scripts/check_clean_install.sh --candidate ghcr.io/stixaly/ctiparsor:sha-<commit>
bash scripts/check_clean_install.sh --candidate ghcr.io/stixaly/ctiparsor:sha-<commit> --quick   # not the gate
```

Reference runs, 2026-11-01, WSL2 (16 GB, 12 CPUs), 0.2.0 to main's 248382c
(`sha256:d3ee078f…`), run as root:

- full, four runs, every step passed; the third on the files before the
  review fixes of the check, the fourth on the files as written here (their
  sha256 are in each `report.json`). The third: 827 s with both images present (each is
  1.19 GB to download: 54 and 59 s on a first run). `bootstrap` took 387 s on
  the new install: the models (2.5 GB) and the 14 corpora in 2 min 27 s
  without an `HF_TOKEN`, then the rule store (88,127 rules) in 4 min; and
  272 s after the upgrade (models kept, corpora pulled, rule store rebuilt),
  which migrated the schema from 13 to 14 before `app` and `worker` got to
  it. Reports A and C took 19 and 20 s, `validated`, 2c, 2d and 2e run,
  Stage 3 skipped. `restart app worker` took 7 s, and B went `processing`,
  `queued` 5 s later (the drain), `processing` again 5 s after that and
  `for_review` at 27 s; with the default 60 s drain (the first two runs, which
  the step as it is now would have failed) B finished during the drain and the
  restart took 21 and 29 s. `down` and
  `up -d` 18 s; the backup 10 s (a 56 MB dump); the upgrade block 295 s; the
  restore 18 s. After bootstrap, `cti-cache` held 3.2 GB and `pg-data-18`
  1.6 GB; each image 4.4 GiB. Memory in use on the host rose from 1.9 to
  6.4 GB; the containers' peaks: worker 4.0 GB, bootstrap 3.9 GB, postgres
  0.45 GB, app 0.35 GB. The fourth: 830 s, 26 `PASS` and 2 `INFO` (`.env`,
  which says what the run chose, and `files of the new release`, whose mode
  is reported); `bootstrap` 385 s then 276 s; B `processing`, `queued` at
  5.2 s, `processing` at 10.3 s and `for_review` at 27.4 s, the worker's log
  holding `Drain timeout: 1 job(s) still running, requeued`;
- `--quick`, on the same files: 117 s, 25 `PASS` and 3 `INFO`: `.env`, `files
  of the new release`, and `report B through restart`: B, a report of 5 s,
  finishes during the 5 s drain and is not requeued (the gate is the full
  run).

What the runs found and the documents now say: the backup block left
`umask 077` in the shell, so a release unpacked there next came out mode 600
and the capture proxy (uid 13) could not read `docker/squid/squid.conf` (shown
by hand as a user in the `docker` group: as root `tar` keeps the archive's
modes, so the check cannot see it, and `tests/test_check_clean_install.py`
holds it); `run --rm bootstrap --no-corpora` in docs/docker.md stopped on
`exec: --: invalid option`; the bootstrap that follows `up -d` migrates the
schema before `app` and `worker`; the volumes hold nearly 5 GB after bootstrap, not
3.5; and the candidate's `setup.sh` said "API key configured" for an empty
key.

`tests/test_check_clean_install.py` (67 tests, no Docker, 6 s) holds what
can drift without a run: every block found where the docs write it, once, and
`--print-blocks` showing the same; the values lines naming the latest release
and the digest docker.md gives it; no block deleting data, running under
`sudo`, calling `docker` by a path or naming a project (`-p X`, `-pX`,
`-p=X`); the downloads going through the Releases page the check stands in
for, `pull` before `up -d`, no `build`; the backup block leaving the shell's
umask as it was and its files private (the block run with a fake `docker`);
the options; the guards against a Docker context or `DOCKER_HOST` other than
the default, a project, a directory or a port left in use, and nothing left
behind when the candidate cannot be pulled (a fake `docker`); the wrapper
letting through `docker compose` on the run's projects only (and `info`,
`--version`), refusing `-p` in any spelling, a global option before `compose`,
`volume remove`, `rm` and `run -v`; the lines that judge report B (requeued or
not, full and `--quick`) run with a stubbed `step`; report A compared by
status and sha256; every documented command run under `env -i`; the report;
and no public document naming a maintainer's machine.

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
gone. Branch `claude/fix-issues-359-375` (2026-11-06) adds
`pages/Settings.test.tsx` (17 `it(` cases: the Redownload and rebuild warnings and
the 422 of a missing `subdir`, #367, #374) and `hooks/usePromotedRules.test.ts`
(5: promotions shared between two instances of the hook and kept per job in
localStorage, #366). It adds two #366 cases to `pages/Review.test.tsx`, which
now holds 22 `it(` calls (20 before the branch, static count; `npm test` was not
run for this count). Branch `claude/fix-issues-376-470` (2026-11-07) adds
`components/graph/GraphCanvas.test.tsx` (new, 2 `it(`/`test(` calls) and changes
`components/review/DocumentReader.test.tsx` (13 calls), `pages/Graph.test.tsx` (14),
`pages/Review.test.tsx` (27) and `pages/Settings.test.tsx` (22). These are static
counts of the calls in each file; `npm test` was not run for them.
Branch `claude/fix-issues-478-571` (2026-11-07, issues #486, #498 and #544-#571) adds `components/EntityPopover.test.tsx` (2 `it(` calls plus one `.each`: defanged IoCs accepted by their type, Escape on the format warning, #554, #559), `components/coverage/CoverageExportPanel.test.tsx` (5: ZIP link attached during the click, pending or failed promoted metadata disables the download, empty format headers keep their badge, tactic header counts all corpora, #486, #546, #566, #567), `components/review/MarginaliaCard.test.tsx` (3: type menu closes on Escape and outside click, #563), `components/review/RelationshipCreator.test.tsx` (4: the picked verb survives an entities refresh and an endpoint change, #555) and `pages/Coverage.test.tsx` (2: the ZIP waits for a promoted rule's metadata, #486). It changes `api/client.test.ts` (20 calls plus one `.each`: path segments encoded in every id-built route, export error message, #547, #551), `hooks/useRuleSelection.test.ts` (9, #545), `hooks/useSSE.test.ts` (4, #548), `hooks/useMitreSearch.test.tsx` (4, #552), `components/graph/buildGraphData.test.ts` (7, #565), `components/graph/buildBundleGraph.test.ts` (29, #569), `components/graph/BaselinePanel.test.tsx` (8, #564), `components/graph/GraphCanvas.test.tsx` (7, #568, #570), `pages/Graph.test.tsx` (15, with the pin test of #550), `components/review/tokens.test.ts` (31, #553), `components/review/RelationshipRail.test.tsx` (23, #561), `components/review/InlineHoverChip.test.tsx` (6 plus one `.each`, #558), `components/NewReportModal.test.tsx` (33, with the pin test of #556, and #560), `components/PdfViewer.test.tsx` (2, #562), `components/dashboard/relTime.test.ts` (4, #571) and `pages/Policy.test.tsx` (5, #498, #544, #546). Same static count. On that branch `npm run check` ran the whole suite on 2026-11-07: 45 Vitest files, 464 tests, all passed. ESLint runs
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
3. **container-image** (on `ubuntu-26.04`, containerd image store required):
   builds the image once, into an OCI archive, and loads it as `ctiparsor:ci`,
   failing unless the loaded image's ID is the archive's.
   Then it scans that image with Grype into Code scanning (not a gate,
   ADR-0078), runs `scripts/docker_smoke.sh --backup-restore` on it (with the
   backup and restore commands of docs/docker.md, ADR-0094 item 3) and the
   air-gap image check. On a push to main it hands the archive to job 8.
4. **dependency-audit**: `pip-audit` on the Python locks and `npm audit` on the
   UI's production packages (ADR-0075, ADR-0080). It also runs weekly.
5. **browser-e2e**: the browser journey, offline, with the network guard
   (`scripts/check_browser_e2e.sh --network-guard`, §4 "Browser journey",
   ADR-0094 item 4). It also runs weekly.
6. **dependency-review** (pull requests only): fails a PR that adds a
   dependency with a known high or critical vulnerability (ADR-0078).
7. **model-tests** (pushes to main only, not a gate): the same suite with the
   models downloaded and a live API key; it may fail for reasons outside the code.
8. **publish-image** (pushes to main only, on `ubuntu-26.04`): after jobs 1
   to 5, pushes the archive job 3 built and tested to GHCR unchanged, with its
   SBOM and signed attestations. It builds nothing, fails unless GHCR holds the
   digest job 3 reported, and moves `latest` only while the commit is main's
   head (docs/releasing.md, "The image main's CI publishes").

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
