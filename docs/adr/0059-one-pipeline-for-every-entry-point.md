# ADR-0059 — One pipeline for every entry point: `pipeline/orchestrator.py`

**Status:** Accepted in part (implemented 2026-09-27; multi-evidence merge and
schema-constrained LLM output still open)
**Date:** 2026-09-27
**Amended by:** [0086](0086-a-bundle-names-its-build-and-a-slower-build-does-not-overwrite-it.md)
(2026-10-17). A finalize records the build it made (`jobs.bundle_build_json`)
and publishes it only if no newer build is stored.
**Relates to:** [pipeline/orchestrator.py](../../pipeline/orchestrator.py),
[api/worker.py](../../api/worker.py), [main.py](../../main.py),
[tests/eval_pipeline.py](../../tests/eval_pipeline.py),
[api/run_config.py](../../api/run_config.py), ADR-0023 (TTP measurement),
ADR-0024 (run config)

## Context

Three entry points ran three different pipelines.

| | API worker (`_run_pipeline`) | CLI (`main.py`) | ATE benchmark `--stage full` |
|---|---|---|---|
| Stage 1 chunking | adaptive (3000 / 4000 / 5000) | fixed 3000 | whole text as one chunk |
| 1f figures | yes | no | no |
| 2 regex | per chunk, max confidence | per chunk, max confidence | whole text |
| 2b gazetteer, 2c semantic, 2d CyNER, 2e GLiNER, 2g alias lists | yes | **no** | 2c only |
| type-conflict resolution | yes | no | no |
| 3 LLM | per chunk, signal filter, parallel, checkpoint | per chunk, no filter, sequential | one call |
| document context / NER allow-list for Stage 3 | yes | no | no |
| 3e consensus | yes (opt-in) | no | no |
| 3doc document relations | yes (opt-in) | yes, different entity list | no |
| 2f CVE metadata | yes | no | no |
| without an LLM provider | silently empty Stage 3 | silently empty Stage 3 | silently scores regex + semantic |

So a benchmark number did not describe the application, and a CLI run did not
reproduce a web run. The worker's `_run_pipeline` was also 750 lines inside a
1,750-line module mixing the stages with job-store plumbing. `pipeline/registry.py`
existed to load Stage 2 declaratively but nothing in production used it, and it
merges differently from the worker (whole text, first-writer), so routing the
worker through it would have changed the output.

The Stage 3 crash-resume checkpoint was matched on the chunk count alone: a job
re-run on another document, model or prompt with the same number of chunks
resumed results from the earlier run.

## Decision

**1. `run_document(document, options, hooks) -> RunResult`** is the sequence,
written once, taken verbatim from the worker (the most complete of the three):
1 → 1f → 2 → 2b → 2c → 2d → 2e → 2g → type resolution → 3 (+3e, 3doc) → 3c
merge → 2f → 4 → 5.

* `Document` — a file to ingest, or text already extracted; filename, TLP/PAP,
  output path (none = Stage 5 skipped).
* `RunOptions` — `disabled` and `required` stage ids, consensus,
  document relations, LLM parallelism, checkpoint cadence. `from_env()` is the
  one place these are read from the environment; `PIPELINE_DISABLED_STAGES`
  turns stages off for every run of a process, API included.
* `Hooks` — what a caller does around the stages: progress events,
  timeout, the final text, the first hard-to-undo write (`extraction_ready`,
  which may raise `RunAborted`), the relationship policy and the run config,
  and a Stage 3 checkpoint store.
* `RunResult.stages` — one `StageOutcome` per stage: `ran`, `skipped`
  (disabled, model or index unavailable, no LLM provider, no PDF…) or
  `failed`, with a reason, a duration and counts. A stage listed in
  `required` that does not run raises `StageRequired` at once.

**2. The three entry points call it.**

* The worker keeps its lease, subprocess, persistence and events in
  `_WorkerHooks`; `_run_pipeline` is 85 lines (a quarter of them the RLIMIT_AS
  comment) and `api/worker.py` went from 1,777 to 1,077 lines. Finalize (`re_run_final_stages`) builds its
  bundle through the same `build_bundle()`.
* The CLI prints each stage as it completes and the stage report at the end;
  `--disable-stage`, `--require-stage` and `--no-llm` choose stages.
* `--stage full` runs the benchmark text through `run_document` (Stages 4–5
  off) and **requires Stage 3**: without an LLM provider it stops with an error
  instead of scoring a different pipeline. `--allow-degraded` scores anyway and
  prints every stage that did not run.

**3. A run is reproducible, or says why not.** The job's run config gains
`manifest` — the LLM `provider/model`, a hash of the Stage 3 prompts, the NER
and embedding model ids, a content hash of each ATT&CK / gazetteer /
embedding data file and the version of each package that shapes a bundle —
and, once the run ends, `stage_report`. (`stages` was already taken by the
model-availability predicates, and keeps that meaning.)

**4. The checkpoint resumes only its own run.** Its fingerprint covers every
setting that changes Stage 3's output — model, consensus model, every prompt
(extraction, document relations, 3d and 3f verification), sampling, the vLLM
thinking switch, the 3d/3f switches, output and prompt limits — and every
input `enrich_chunk` receives: chunk texts, each chunk's entities, the
gazetteer, CyNER and semantic entities, document context, allow-list,
reference date. Any difference starts Stage 3 from scratch. (A first version
missed the 3d/3f switches and the consensus model: turning verification on
after a crash resumed unverified results.)

**4b. Stage 3 says whether it got anything usable.** Every extraction call is
counted as ok, failed request, empty answer or unparseable answer, and the
3d/3f verifications as ok, failed or unparseable (`pipeline/llm_stats.py`).
Stage 3 is `failed` when no extraction call returned a usable answer; 3d and
3f are `failed` when requested and none of their answers could be used (every
claim then stays unverified). Partial losses are in the reason and counts.

**5. A failure of the CVE cache no longer fails a run.** Stage 2f reads the job
store's cache even with the network lookup off; the CLI now runs it too, and
without a database it is recorded as `failed` and the bundle is built without
CVE descriptions.

## Consequences

* **Stages 3d, 3f, 4b and 4c are stage ids too**, so an ablation can turn
  each off (`--disable-stage 3f`, `PIPELINE_DISABLED_STAGES=4b`); 4c is also
  reported as skipped when the policy does not enable long-distance inference.
* **The CLI applies the same relationship policy as the worker**: the one saved
  in the job store by default (`--policy db`), or `--policy none` / a JSON
  file; it says which one it used. The equivalence test saves a non-default
  policy and compares the two bundles object by object after replacing ids by
  stable keys — relationship endpoints, evidence and confidences included.
* The CLI now does everything the worker does, so it is slower and uses the
  NER models when they are installed. `--disable-stage 2c,2d,2e` restores the
  old, lighter behaviour.
* The benchmark's `full` numbers will move: chunking, the signal filter and the
  NER context are now the application's. Earlier `full` results are not
  comparable.
* `tests/test_orchestrator.py` runs `worker._run_pipeline` and the CLI on the
  same fixture (LLM mocked) and checks that both build the same bundle.
* `pipeline/registry.py` is now unused. Deleting it (its Stage classes and
  their tests stay) is a separate, one-line decision.
* **Still open:**
  * keeping every occurrence and source of an entity (Stage 2's merge keeps the
    first, `base.py`) — needs a table and review-page changes;
  * schema-constrained LLM output — provider-specific and has to be measured
    against the current JSON repair on real reports;
  * stage-internal settings (thresholds, verification flags) are still read
    from the environment inside each stage; `RunOptions` covers only the
    choices the orchestrator makes.

## Amendment (2026-10-17): the manifest records what a run reads

Decision 3 gave the run config a `manifest` of the model ids, the prompts, the
data files and the packages that shape a bundle. The audit of 2026-10-17 (Q04)
found settings, data files and packages a run reads that neither the manifest
nor `env` recorded. `api/run_config.py` now captures, in addition:

- **Settings** (`_CAPTURED_ENV`, recorded when set):
  - the bundle's marking and author: `STIX_TLP`, `STIX_AUTHOR_NAME`;
  - Stage 2: `GAZETTEER_POLICY`, `BENIGN_IOC_FILTER`, `GLINER_ENABLED`,
    `GLINER_CHUNK_CHARS`, `CYNER_CHUNK_CHARS`;
  - Stage 3's bounds and verification gates: `LLM_MAX_PROMPT_LENGTH`,
    `LLM_DOC_MAX_PROMPT_LENGTH`, `LLM_MAX_RESPONSE_LENGTH`,
    `LLM_MAX_OUTPUT_TOKENS`, `LLM_TIMEOUT`, `STIX_VERIFY_MIN_RELS`,
    `STIX_VERIFY_BATCH_SIZE`, `TTP_VERIFY_MIN`;
  - the vision provider: `VISION_PROVIDER`, `VISION_MODEL`,
    `VISION_ASSUME_CAPABLE`, `VISION_TIMEOUT_S`;
  - the model each provider would use: `ANTHROPIC_MODEL`, `GEMINI_MODEL`,
    `MISTRAL_MODEL`, `OLLAMA_MODEL`, `LMSTUDIO_MODEL`, `VLLM_MODEL`. Names
    only, never a key or a base URL.
- **Data files** (`_DATA_FILES`, hashed): `warninglists.json`,
  `attack_revoked.json`, `gazetteer_policy.json`,
  `gazetteer_context_rules.json`, `mitre_embeddings_manifest.json`.
  `tests/test_run_config.py` now fails when a file in `pipeline/data/` is not
  fingerprinted. It lists files only: the `stix2_json_schemas/` directory is
  not hashed.
- **Packages** (`_PACKAGES`, versions): `yara-python`, `pysigma`,
  `parsuricata`, `lark-parser`, `lark`, `stix2-validator`, `spacy`,
  `rapidfuzz`. They decide whether a quoted rule leaves as an Indicator
  (ADR-0067, ADR-0070) and the validation status. `parsuricata` runs on
  `lark`, the module actually imported: lark 1.x overwrites lark-parser's files
  and leaves its metadata behind, so both versions are read.

**Still not done** (a later lot; ADR-0086 took them up, see the next amendment):

- A manifest per finalize or rebuild. A rebuild reads the current policy and
  data without recording a new configuration.
- Overrides recorded by content. `entity_overrides` (ADR-0052) counts the
  analyst's deny and promote rows; it does not say which.

## Amendment (2026-10-17, second): a finalize records its build and publishes in order

Decision 2 had finalize (`re_run_final_stages`) build its bundle through the
same `build_bundle()` as a run. It recorded nothing about that build, and two
finalizes of one job could publish in the reverse order of their reads (audit of
2026-10-17, lot L1). ADR-0086 changes `re_run_final_stages` and takes up the two
items above:

- **The build is recorded.** `jobs.bundle_build_json` holds the build's kind
  (`run`, `finalize` or `quick`), time, `git_rev`, policy, `env` and manifest,
  taken from the process that built the bundle. A run writes its own record,
  copied from its run config. `run_config_json` keeps describing the run.
- **Overrides are recorded by content, in part.** `entity_overrides` gains
  `fingerprint`, a hash of the active rows. It says whether the same rows
  applied, not which. The build record carries no overrides: Stages 4 and 5 do
  not read them.
- **A finalize reads one snapshot and publishes conditionally.** The rows and the
  job's `review_revision` are read in one transaction. One `UPDATE` writes the
  bundle, ledger, verdict, record and revision, and is refused when the stored
  bundle was built from newer rows. The refused build returns the stored bundle.
