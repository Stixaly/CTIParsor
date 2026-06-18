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

---

## 3. Current coverage map (172 tests)

| Layer | File | ~Tests | Covers |
|---|---|---:|---|
| Ingestion | `test_stage1.py` | 8 | parse, chunking, sliding-window overlap, bad input |
| Extraction | `test_stage2.py` | 60 | regex IoCs, refang/defang matrix, IoC-appendix patterns, hyphen line-breaks |
| LLM enrich | `test_stage3.py` | 40 | `enrich_chunk` happy/error/transient, `_merge_results`, dedup, prompt sanitiser, `_normalize_llm_json` |
| Hallucination filter | `test_stage3b.py` | 12 | actor/malware/relationship presence checks, allow-list bypass |
| STIX mapping | `test_stage4.py` | 33 | SDO/SCO/SRO build, policy pins, IoC coverage, external-ref routing |
| Validation/export | `test_stage5.py` | 8 | bundle validity, file write, nested dirs |
| API | `test_api_routes.py` | 8 | health, jobs 404/list, upload filter, progress, policy |
| **Evidence labels** | `test_evidence_consensus.py` | 4 | default label, normalize coercion, `x_evidence_label` in STIX, consensus reconcile |
| **Provenance** | `test_provenance.py` | 5 | authoring Identity, TLP marking, `created_by_ref` on SDO/SRO, SCO marked-only, `STIX_TLP` switch |
| **Persistence / worker** | `test_persistence.py` | 4 | migration idempotency, `_save_entities` write, finalize read→bundle, NULL-label default |
| **Relationships API** | `test_relationships_api.py` | 4 | create/read/patch evidence_label, default + unknown-label coercion, PATCH 400 |

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
