# CTIParsor — Test Strategy

This document is the source of truth for how CTIParsor is tested: what each layer
covers, how to run it, the coverage targets, and the open gaps. Update it whenever
a feature lands so the gap list stays honest.

_Last reviewed: 2026-06-18 — after the evidence-labels, cross-model consensus, and
STIX provenance features landed, plus the P1-a/b/c persistence + route coverage._

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
   Frontend: type-check only today (gap — see §6)
```

**Cover:** transformation correctness, idempotency, error handling, STIX 2.1 spec
compliance, security boundaries (prompt-injection sanitiser, upload filter),
provenance/grading integrity.
**Skip:** the live LLM provider, framework internals, trivial getters.

---

## 2. How to run

```bash
# Fast lane — no API key, deterministic. This is the gate for every push.
pytest tests/ -q -k "not llm"

# Full suite (includes transient-error/retry tests marked "llm")
pytest tests/ -q

# Frontend (type safety only, today)
cd frontend && npx tsc --noEmit
```

The `mock_llm` fixture patches `pipeline.stage3_llm._call_llm`, so Stage 3 tests
run offline. Tests that exercise real retry/timeout behaviour are name-tagged
`llm` and deselected by `-k "not llm"`.

### Measuring TTP precision (ATE benchmark)

`tests/eval_pipeline.py` doubles as a CLI for the **ATT&CK Technique Extraction
(ATE)** benchmark — the harness for the ADR-0011 precision work. It scores MITRE
technique extraction (P/R/F1) against the GPT-4 baseline (F1 = 0.64):

```bash
# Regex + semantic + Stage 3c subsumption (offline, no API key)
python tests/eval_pipeline.py --benchmark ate --stage all --verbose

# Semantic stage only (needs the embedding cache; tune thresholds here)
python tests/eval_pipeline.py --benchmark ate --stage 2c --verbose

# The full shipping path: regex + semantic + LLM + Stage 3c normalize (needs API key)
python tests/eval_pipeline.py --benchmark ate --stage full

# Against the public CTIBench ATE dataset (github.com/xashru/cti-bench)
python tests/eval_pipeline.py --benchmark ate --stage full --dataset ctibench_ate.json
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
python tests/eval_pipeline.py --benchmark rel --verbose

# Against your own annotated reports
python tests/eval_pipeline.py --benchmark rel --dataset gold_edges.json
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

## 3. Current coverage map (1059 tests, 65 modules)

`make test` executes `pytest tests/`. The counts below come from
`pytest --collect-only` and therefore include `parametrize` expansion. A bare
`pytest` from the repo root also collects 14 tests vendored under
`corpora/sigmahq/tests/`, which are not this project's.

| Layer | File | ~Tests | Covers |
|---|---|---:|---|
| Ingestion | `test_stage1.py` | 8 | text ingestion, chunking, overlap, unsupported formats |
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
| NER | `test_stage_registry.py` | 4 | registry merging, deduplication, case insensitivity |
| **Aliases** | `test_aliases.py` | 6 | alias resolution, MITRE ID mapping, surface forms |
| **Aliases** | `test_alias_disambiguation.py` | 11 | type-aware resolution, alias isolation, canonical name handling |
| LLM enrich | `test_stage3.py` | 42 | LLM enrichment, JSON parsing, deduplication, prompt sanitization |
| Hallucination filter | `test_stage3b.py` | 11 | hallucination filtering, entity presence checks, allow-list bypass |
| **TTP precision** | `test_ttp_precision.py` | 14 | threshold resolution, semantic confidence, subsumption, verification |
| **TTP precision** | `test_ttp_volume_controls.py` | 16 | cross-source dedup, corroboration floors, taxonomy filtering |
| **TTP precision** | `test_ttp_sentence_gates.py` | 14 | sentence unwrapping, keyword gating, candidate selection |
| **TTP precision** | `test_ttp_evidence_merge.py` | 11 | evidence preference, semantic fallback, label preservation |
| **TTP precision** | `test_ate_scoring.py` | 13 | ATE scoring, partial credit, macro averaging, diagnostics |
| **Evidence spans** | `test_evidence_span.py` | 19 | offset normalization, quote location, sentence bounds |
| **Evidence spans** | `test_evidence_span_offsets.py` | 11 | index mapping, coverage calculation, quote matching |
| **Evidence spans** | `test_merge_keeps_evidence.py` | 10 | evidence preservation, confidence ranking, deduplication |
| **Evidence labels** | `test_evidence_consensus.py` | 4 | label normalization, STIX properties, consensus boosting |
| STIX mapping | `test_stage4.py` | 38 | SDO/SCO/SRO build, alias merging, IoC coverage |
| STIX mapping | `test_stix_self_edges.py` | 4 | self-edge prevention, endpoint validation, bundle integrity |
| **Graph completion** | `test_stage4b_completion.py` | 18 | transitive completion, alias merging, grounding, pins |
| **Graph completion** | `test_stage4c_long_distance.py` | 10 | long-distance inference, direction swap, evidence recording |
| **Graph completion** | `test_grounding_by_label.py` | 8 | STIX display names, edge scoring, bundle validation |
| Validation/export | `test_stage5.py` | 8 | bundle validation, file writing, nested directories |
| **Provenance** | `test_provenance.py` | 5 | authoring identity, TLP marking, created_by_ref |
| **Provenance** | `test_edge_provenance.py` | 10 | relationship properties, pinned edges, run config |
| **Provenance** | `test_bundle_staleness.py` | 15 | `git_rev` extraction from malformed run configs, ancestry verdicts, an undecidable git result never marking a bundle stale (ADR-0035) |
| **Relationship policy** | `test_pin_budget.py` | 16 | fair share allocation, edge key validation, materialization |
| **Relationship policy** | `test_pin_evidence.py` | 27 | term extraction, sentence indexing, grounding gates |
| **Relationship policy** | `test_policy_last_run.py` | 17 | stats extraction, database queries, bundle handling |
| **Relationship policy** | `test_policy_rule_validation.py` | 15 | policy validation, API rejection, graph survival |
| **Rule adapters** | `test_sigma_adapter.py` | 8 | rule parsing, tactic skipping, registry loading |
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
| **Detection coverage** | `test_coverage_artifacts_api.py` | 5 | artifact coverage routes, payload shape, 404 handling |
| **Export filters** | `test_export_filters.py` | 13 | facet totals, format filtering, license exclusion, manifest |
| **Export filters** | `test_rule_lookup.py` | 8 | rule lookup, metadata retrieval, license handling |
| **Rule synthesis** | `test_synth_sigma.py` | 47 | rule synthesis, value validation, path escaping, stability |
| API | `test_api_routes.py` | 11 | health checks, job listing, upload validation, progress |
| API | `test_relationships_api.py` | 4 | relationship creation, label coercion, patch validation |
| API | `test_settings_api.py` | 5 | corpus listing, overlay management, rebuild ingestion |
| Persistence | `test_persistence.py` | 7 | backup consistency, migration idempotency, label persistence |
| Persistence | `test_db_transaction.py` | 6 | transaction rollback, commit, exception handling |
| Shared helpers | `test_shared_helpers.py` | 27 | environment parsing, claim extraction, unescaping logic |
| Benchmarks | `eval_pipeline.py` | 10 | NER F1, ATE precision, grounding metrics, adversarial tests |

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
rejections. DB is real SQLite but `init_db` is patched in `api_client`.

### Persistence / worker (integration)
The write→read round-trip through SQLite (`worker._save_entities` →
`re_run_final_stages`) and schema migrations. **Currently the weakest layer** (see §6).

### Frontend (type-check only)
`tsc --noEmit` runs in CI. No behavioural tests yet — the review-page promotion
logic is untested (see §6, P1-d).

---

## 5. Coverage of the three new features

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
  helper and unit-test it (see §7 for the table). Requires standing up Vitest.
- **e. Consensus worker wiring untested.** Only `reconcile()` is covered; the
  `consensus_enabled()` gate and the "only double-run chunks with relationships"
  guard are not. → Unit-test `consensus_enabled()` across env combinations
  (off; provider unset; provider == primary → disabled).

### P2 — pre-existing gaps the new work made visible

- **f. Stage 3c (MITRE normalisation)** has no test file. Consensus and evidence
  grading both feed it. → `test_stage3c.py`: fuzzy-match score tiers (≥85 canonical,
  70–84 keep-phrasing, <70 passthrough).
- **g. Stage 3d (relationship self-verification)** has no test file — and it's the
  exact behaviour consensus (3e) improves on. → `test_stage3d.py` with `mock_llm`
  returning a supporting / non-supporting quote.
- **h. Strict STIX validator path.** `.stix2_schemas_missing` means the JSON-schema
  validator is skipped, so the `x_evidence_label` custom-prop + `allow_custom` path
  is only asserted via `serialize()`. → When schemas are installed, add a Stage 5
  test that the provenance-stamped, custom-prop bundle still validates.

### P3 — longer horizon

- **i. Full-pipeline integration test** (`worker._run_pipeline` or `main.py` CLI on
  a fixture with mocked LLM) producing a bundle with provenance + labels end-to-end.
- **j. Frontend interaction tests** for the relationship rail / graph editor.

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

## 8. Coverage targets & CI

| Area | Target | Rationale |
|---|---|---|
| Pipeline stages | ≥ 85% line | core correctness |
| API routes | ≥ 80% line | contract + boundaries |
| New-feature branches (labels, consensus, provenance) | 100% of decision branches | regressions here corrupt intel grading |
| Worker / persistence | establish ≥ 70% (from ~0) | biggest current risk |
| Frontend gate logic | 100% of the helper's table | pure logic, cheap to cover |

**CI lanes:**
1. **Fast** (every push): `pytest -k "not llm"` + `tsc --noEmit`. No secrets.
2. **Full** (pre-merge / nightly): full `pytest` + Vitest + coverage gate.

Add `pytest --cov=pipeline --cov=api --cov-report=term-missing` and fail the build
below the stage target once P1 gaps are closed.
