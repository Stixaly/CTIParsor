# ADR-0039: Per-stage observability — a `job_stages` record, one instrumentation point, and stage-attributed failures

**Status:** Proposed
**Date:** 2026-09-02
**Deciders:** maintainer
**Depends on:** ADR-0002 (worker subprocess model), ADR-0024 (`run_config_json` records the *configuration* of a run; this records its *execution*), ADR-0026 (`x_synthesis_stats`, which already computes half of what this ADR surfaces).

## Context

The pipeline has **18 stage modules**. Six of them report anything to the API:

| Reported | `1f` Figures · `1` Ingestion · `2` Extraction · `3` LLM enrichment · `4` STIX mapping · `5` Validation |
|---|---|
| **Silent** | `2b` gazetteer · `2c` TTP semantic · `2d` CyNER · `2e` GLiNER · `2f` CVE enrichment · `3b` hallucination filter · `3c` MITRE normalisation · `3d` relationship self-verify · `3e` consensus · `3f` TTP self-verify · `4b` graph completion · `4c` long-distance |

Stage 2's single event does carry per-extractor counts (`gazetteer`, `semantic_ttps`, `cyner`, `gliner`), so 2b–2e are partially covered. Nothing else is.

**The stages that change the data most are the ones that report least.** Stage 3b drops entities it judges hallucinated. Stage 3d *deletes* every relationship whose supporting sentence the model cannot quote — the single highest-impact filter in the pipeline (ADR-0009: 27 % → 8 % hallucination), and ADR-0038 has just shown it also deletes every `gap` edge as a side effect. Stage 3f does the same for TTPs. Stage 4b adds up to 200 edges. Not one of these emits a progress event, so from outside the process the deletion and the addition are both invisible.

Worse, **the numbers already exist and are thrown away.** Stage 3d logs `removed N/M unsupported relationships`. Stage 4b builds a full `CompletionStats` (`aliases_merged`, `reference_added`, `transitive_added`, `long_distance_added`, `skipped_not_suggested`, `capped`), returns it, logs one line, and the caller discards it. Stage 4 builds `PinStats` and buries it in `x_synthesis_stats` on the Report SDO — readable only by parsing a 475 KB–1.3 MB bundle, which is why ADR-0026 had to add a dedicated endpoint to get at it.

### Measured, on this repository

1. **209 `logger.*` call sites** across `api/` and `pipeline/`, and **not one carries a job id**. The formatter is `%(asctime)s [%(levelname)s] [%(request_id)s] %(name)s: %(message)s`, and `set_request_id` is called in exactly one place: the HTTP middleware at `api/main.py:81`. The pipeline runs in a spawned subprocess that never calls it, so **every pipeline log line reads `[none]`** — verified across every log captured on 2026-09-02. With two jobs in flight their lines interleave with nothing to tell them apart.

2. **`LOG_FILE` defaults to `""` — no file logging at all.** Logs exist only on the stdout of whatever launched the API. Run it detached and the record of the run is gone.

3. **The traceback is computed, then discarded.** `api/worker.py:1018` does `error_msg = traceback.format_exc()`, sends it to the logger, and stores only `str(exc)` in `progress_events`. The database keeps the weakest available form of the error and the strongest form goes to a stream that is not persisted.

4. **A crashed job does not say where it crashed.** When the subprocess dies on a signal, the parent watcher emits `{"status": "failed", "error": "Pipeline worker process terminated unexpectedly (SIGKILL (OS out-of-memory killer))"}` — no stage, although `progress_events` already holds the last stage event that *would* name it. On 2026-09-02 this cost seven manual greps of stdout to establish that four jobs all died at the first Stage 3 LLM call; the job records themselves could not answer it.

5. **No stage is timed except Stage 3**, which measures per-chunk elapsed and logs it without persisting it. There is therefore no data anywhere to answer "which stage is slow" — the exact question ADR-0036 Phase 0 and ADR-0037 had to answer with external instrumentation.

6. **The progress bar is `Math.max(6, (stage / 5) * 100)`** (`frontend/src/components/dashboard/ActivityCard.tsx:10`). Three defects in one expression: the stage count is hardcoded to 5; every stage is weighted equally although Stage 3 alone runs for minutes while Stage 5 runs in milliseconds, so the bar sits at 60 % for most of the job; and `stage` is the string `"1f"` for the figures stage, so `"1f" / 5` is `NaN` and the width becomes `NaN%`, an invalid declaration the browser drops. `ProgressEvent.stage` is typed `number` in `frontend/src/types/index.ts:222` while the backend sends a string for that stage.

7. **`queued` is emitted and nothing listens.** `api/worker.py:1175` emits a `queued` event with a queue position; `useSSE` registers listeners for `stage`, `done` and `partial_graph` only. A user whose job is queued behind another sees a spinner at 6 % with no explanation — and ADR-0036 item 4 separately notes the stream closes on such a job.

8. **No retention.** `progress_events` rows are deleted only when their job is deleted.

### What this is not

This is not distributed tracing. CTIParsor is a single node running one subprocess per job, and ADR-0036 and ADR-0037 both concluded that measuring the existing stack beats re-architecting it. The requirement is narrow: **for one job, know what every stage did, how long it took, and which one failed** — from the database, without reading a terminal.

## Options considered

### Option A: More log lines, structured as JSON

| Dimension | Assessment |
|---|---|
| Complexity | Low |
| Cost | Near zero (`LOG_FORMAT=json` already exists) |
| Scalability | Poor — no aggregation without a log stack |
| Team familiarity | High |

**Pros:** the formatter already supports it; no schema change.
**Cons:** does not answer a query. "Which stage failed for job X" would still mean grepping a file that by default is not written. Does not reach the UI or the API. Leaves finding 1 (`[none]`) unfixed.
**Verdict:** rejected as the primary record; adopted as a *sink* (findings 1 and 2 are fixed regardless).

### Option B: Emit a progress event from all 18 stages

| Dimension | Assessment |
|---|---|
| Complexity | Low |
| Cost | 18 call sites |
| Scalability | Poor as a record — `progress_events.data` is an untyped blob |
| Team familiarity | High |

**Pros:** the SSE transport already exists and the UI already consumes it.
**Cons:** `progress_events` is an append-only stream designed for replay to a browser. Asking "median Stage 3 duration across all jobs" or "how often does 3d drop everything" means JSON-parsing every row of a table with no retention policy. It is the transport, not the record.
**Verdict:** necessary but insufficient — adopted *as part of* option C.

### Option C: A typed `job_stages` table, written through one `stage_span` context manager

| Dimension | Assessment |
|---|---|
| Complexity | Medium |
| Cost | One table, one helper, 18 call sites, one endpoint |
| Scalability | Good — indexed, queryable, bounded by retention |
| Team familiarity | High (same SQLite patterns as `jobs`/`entities`) |

**Pros:** one insertion point sets the log context, times the stage, writes the row, emits the event, and attributes the exception — so the 209 existing log statements gain a job id with no edits. Answers the failure question and the slow-stage question with a `SELECT`.
**Cons:** a new table on the write path; the stage list becomes a contract the frontend depends on.
**Verdict:** **chosen.**

### Option D: OpenTelemetry spans exported over OTLP

| Dimension | Assessment |
|---|---|
| Complexity | High |
| Cost | New dependency, a collector to run and operate |
| Scalability | Excellent, far beyond the need |
| Team familiarity | Low |

**Pros:** the industry-standard answer; spans nest naturally over stages; free flame graphs.
**Cons:** requires a collector and a backend to be of any use, which is infrastructure this project does not have and ADR-0036 argued against acquiring. The consumer here is a React page and an operator, both of which want a table, not a trace viewer. Nothing in the spans would reach the UI without writing option C anyway.
**Verdict:** rejected now; the `stage_span` boundary is deliberately span-shaped so it can become an OTel span later without touching call sites.

### Option E: One log file per job

| Dimension | Assessment |
|---|---|
| Complexity | Low |
| Cost | A handler per job |
| Scalability | Poor — files, and ADR-0036 item 12 already wants files off local disk |
| Team familiarity | High |

**Pros:** trivially complete; the whole run in one place.
**Cons:** unqueryable and unaggregatable; multiplies the per-job-file problem ADR-0036 item 12 is trying to remove.
**Verdict:** rejected as the record; available as an opt-in sink.

## Trade-off analysis

The real choice is between **B and C**, and it turns on who asks the questions. B serves one consumer, the browser watching a job run, and serves it well. C serves three: the browser, the operator asking why a job failed yesterday, and the maintainer asking which stage to optimise before adding a worker pool. The second and third are the ones that have gone unanswered all year — ADR-0036 and ADR-0037 both had to write throwaway scripts to get numbers this table would have held.

C's cost over B is one table and one helper. Because both write through the same `stage_span`, B is not an alternative that C rejects; it is a line inside it.

The argument against D is not that tracing is wrong, it is that tracing without a backend is a dependency with no reader. The mitigation is to keep the instrumentation boundary span-shaped so adopting D later is a change of sink, not of call sites.

## Decision

### 1. `STAGE_PLAN` — one ordered, weighted list of stages

A single module-level constant, the source of truth for both backend and frontend:

```python
# (id, label, weight)  — weight is a share of expected wall-clock, not of count.
STAGE_PLAN = [("1", "Ingestion", 2), ("1f", "Figures", 6), ("2", "Extraction", 8),
              ("2f", "CVE enrichment", 2), ("3", "LLM enrichment", 55),
              ("3b", "Hallucination filter", 1), ("3c", "MITRE normalisation", 1),
              ("3d", "Relationship verify", 8), ("3e", "Consensus", 6),
              ("3f", "TTP verify", 6), ("4", "STIX mapping", 3),
              ("4b", "Graph completion", 1), ("4c", "Long-distance", 0), ("5", "Validation", 1)]
```

Weights are placeholders until action item 1 measures them. `GET /api/stage-plan` serves the list so the UI stops hardcoding `/ 5`. Stage ids are **strings** (`"1f"`, `"3d"`, `"4b"`), and `ProgressEvent.stage` is retyped accordingly.

### 2. `job_stages` — the record

```sql
CREATE TABLE IF NOT EXISTS job_stages (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    job_id      TEXT NOT NULL,
    stage       TEXT NOT NULL,           -- "1", "1f", "2c", "3d", "4b"
    label       TEXT NOT NULL,
    status      TEXT NOT NULL,           -- running | ok | skipped | failed | crashed
                                         -- failed = our code raised; crashed = the host killed the process
    started_at  TEXT NOT NULL,
    ended_at    TEXT,
    duration_ms INTEGER,
    detail_json TEXT NOT NULL DEFAULT '{}',
    error       TEXT                     -- full traceback, failures only
);
CREATE INDEX IF NOT EXISTS idx_job_stages_job ON job_stages(job_id, id);
```

`detail_json` is per-stage and typed by convention, not by schema — the counts below.

### 3. `stage_span` — the single instrumentation point

```python
with stage_span(job_id, "3d", "Relationship verify") as span:
    result = verify_relationships(text, result, _call_llm)
    span.record(claims=n_in, verified=n_kept, dropped=n_in - n_kept)
```

On entry it sets the logging `ContextVar` to the job id, starts the clock, inserts a `running` row and emits a `stage` progress event with `status="running"`. On exit it updates the row, emits the completed event with `detail_json` inline, and on exception records `status="failed"` plus the **full traceback** in `error` before re-raising. `span.skip(reason)` marks a stage `skipped` (disabled by env flag, no figures in the document, provider unavailable) so a stage that did not run is distinguishable from one that ran and found nothing.

Setting the ContextVar here is what fixes finding 1 for all 209 existing log statements without editing any of them.

### 4. What each stage records

The stages whose numbers already exist and are being discarded come first, because they are wiring, not new computation:

| Stage | `detail_json` | Source |
|---|---|---|
| `3d` | `claims`, `verified`, **`dropped`** | already logged, not persisted |
| `3f` | `ttps`, `kept`, `dropped` | already logged |
| `3b` | `dropped_actors`, `dropped_malware`, `dropped_tools`, `dropped_rels` | computed, not surfaced |
| `4` | `objects`, `scos`, `sdos`, `sros`, `pin` (budget/emitted/truncated/blocked) | `PinStats`, currently bundle-only |
| `4b` | `reference_added`, `transitive_added`, `long_distance_added`, `aliases_merged`, `skipped_not_suggested`, `capped` | `CompletionStats`, currently discarded |
| `3` | `chunks`, `llm_calls`, `skipped`, `gen_ai.provider.name`, `gen_ai.request.model`, `gen_ai.usage.input_tokens`, `gen_ai.usage.output_tokens`, `elapsed_s` — OpenTelemetry GenAI attribute names, so a later exporter is a rename-free mapping | partly logged |
| `2c` | `sentences_total`, `kept_by_keyword`, `scored`, `above_threshold` | ADR-0023 Phase 2 asked for exactly these as first-class output |
| `2b`/`2d`/`2e` | `entities_added`, `model_loaded` | in the Stage 2 aggregate today |
| `2f` | `cves`, `cache_hits`, `cache_misses` | new |
| `3c` | `normalised`, `unresolved` | new |
| `3e` | `agreements`, `disagreements`, `provider` | new |
| `4c` | `components`, `llm_calls`, `edges_proposed`, `edges_accepted` | new |
| `1f` | `figures`, `read`, `skipped_icons` | already emitted |
| `5` | `valid`, `errors` | already emitted |

### 5. Failures name their stage

On any exception the `stage_span` has already written the failing stage and its traceback. For a signal death, where no Python code runs in the child, the parent watcher reads the newest `job_stages` row with `status='running'` for that job and emits `{"status": "failed", "stage": "3", "label": "LLM enrichment", "error": "..."}`, marking that row **`crashed`** — Prefect's distinction: `failed` is our code raising, `crashed` is the host killing the process (SIGKILL, OOM, SIGTERM), and the two need different responses. This is the finding-4 fix, and it is what turns seven manual greps into one API response.

### 6. `GET /api/jobs/{job_id}/stages`

Returns the rows for one job, ordered, with durations. Feeds a per-job detail panel and makes the record reachable without SSE — the stream answers "what is happening now", this answers "what happened".

### 7. Logging fixes, independent of the table

`LOG_FILE` gains a default under `logs/` so a detached run keeps its record; `LOG_FORMAT=json` documented; retention added for `progress_events` and `job_stages` (delete rows for jobs finished more than `LOG_RETENTION_DAYS` ago, default 30), since neither table has any today.

### 8. Frontend

`ProgressRail` computes its percentage from completed `STAGE_PLAN` weight instead of `stage / 5`, which removes the hardcoded count, the equal weighting and the `NaN`. `useSSE` gains a `queued` listener so a queued job shows its position. A stage list on the job detail view renders `job_stages` with durations and counts, and marks the failed stage.

## Consequences

- **Easier:** "where did it fail" is one query instead of a grep of a file that may not exist. "Which stage is slow" becomes answerable from data the application already holds, which is what ADR-0036 Phase 0 and ADR-0037 needed and had to obtain with throwaway scripts. The Review UI can finally say *how many* relationships Stage 3d removed — directly relevant to ADR-0038 decision 2, which changes that number on purpose. Every existing log line gains a job id for free.
- **Harder:** one more table on the write path (roughly 14 inserts and 14 updates per job, against a pipeline that runs for minutes — negligible, but it is on the critical path and should be measured, not assumed). `STAGE_PLAN` becomes a contract between backend and frontend; adding a stage now means updating one list rather than nothing. Weights need re-measuring when stage costs change.
- **To watch:** `detail_json` is schemaless by design, which is the same trade `run_config_json` and `x_synthesis_stats` already make. If a consumer starts depending on a key, that key needs a test.
- **Revisit:** when the persistent pool lands (ADR-0036 Phase 2), a stage row is the natural place to record which worker ran it and whether that worker was recycled mid-job. When and if a collector ever exists, `stage_span` becomes an OTel span with no call-site change.
- **Independent of tenancy.** Nothing here waits on ADR-0036 Phase 4. When `user_id` arrives, `job_stages` inherits scoping through `job_id` like every other per-job table.

## Action items

1. [ ] Measure before weighting: instrument `stage_span` first with logging only, run the four ADR-0038 reports on the Linux host, and set `STAGE_PLAN` weights from the observed durations. Same trip as ADR-0038 item 0.
2. [ ] `job_stages` table + migration in `api/db.py`; `STAGE_PLAN` and `stage_span` in a new `api/observability.py` (schema and helper are fully specified above; tests must cover ok / skipped / failed / exception-re-raised, and that the log ContextVar is set inside the span and cleared after).
3. [ ] Wire the 14 spans in `api/worker.py::_run_pipeline`, starting with `3d`, `3f`, `3b`, `4` and `4b`, whose numbers already exist (one group of stages at a time).
4. [ ] Parent-watcher stage attribution on signal death (`api/worker.py`; test with a subprocess that SIGKILLs itself mid-stage — verify the test bites by reverting the attribution).
5. [ ] `GET /api/jobs/{job_id}/stages` and `GET /api/stage-plan` (`api/routes/jobs.py`).
6. [ ] Logging: `LOG_FILE` default, retention job for both event tables, `.env.example` and `docs/deployment.md`.
7. [ ] Frontend: weighted `ProgressRail`, `queued` listener, `ProgressEvent.stage` retyped to `string`, stage list on the job detail view (`ActivityCard.tsx`, `useSSE.ts`, `types/index.ts`).
8. [ ] README observability section; CHANGELOG entry.

## Confrontation with external practice (2026-09-02)

| Source | What they do | Bearing on this ADR |
|---|---|---|
| **Prefect run states** ([docs](https://docs.prefect.io/v3/concepts/states)) | Distinguishes **`Failed`** ("did not complete because of a code issue") from **`Crashed`** ("did not complete because of an infrastructure issue": SIGTERM, OOM, evicted pod); keeps a state history per run. | Exactly the distinction that cost seven greps in §Context. **Amendment:** `job_stages.status` becomes `running \| ok \| skipped \| failed \| crashed`; the parent watcher writes `crashed` on signal death, `stage_span` writes `failed` on an exception. Consumers can then tell "our code broke" from "the host killed us" without reading the error string. |
| **OpenTelemetry GenAI semantic conventions** ([OTel blog, 2026](https://opentelemetry.io/blog/2026/genai-observability/), [Uptrace](https://uptrace.dev/blog/opentelemetry-ai-systems)) | Still experimental in 2026; span per LLM call with `gen_ai.request.model`, `gen_ai.usage.input_tokens`, `gen_ai.usage.output_tokens`, `gen_ai.response.finish_reasons`; large content as span *events*, not attributes. | **Amendment:** the Stage `3`, `3d`, `3e`, `3f`, `4c` and `1f` `detail_json` use those attribute names verbatim (`gen_ai.request.model`, `gen_ai.usage.input_tokens`, …) so a future OTel exporter is a rename-free mapping. `detail_json` holds counts and ids only, never prompts or completions — the convention's own advice. |
| **MLflow tracing** ([backend stores](https://mlflow.org/docs/latest/self-hosting/architecture/backend-store/), [2026 guide](https://mlflow.org/articles/setting-up-llm-observability-pipelines-in-2026/)) | SQLite is the **default** backend for traces; single-host mode with no collector is the documented starting point, scaled later by swapping the store. Per step: inputs, outputs, latency, counts, errors. | Independent confirmation that option C (a SQLite table, no collector) is the normal single-node answer, not a shortcut. Adopting MLflow itself would add a server for the same table; not taken. |
| **OpenCTI inferences** ([docs](https://docs.opencti.io/latest/usage/inferences/)) | Every inferred object is visibly marked and attributable to the rule that made it. | Same principle as recording per-stage `detail_json` for `4b`: what a stage added must be countable after the fact. |

**Net effect:** the design holds; two amendments — a `crashed` status and OTel attribute names — cost nothing now and remove a migration later.
