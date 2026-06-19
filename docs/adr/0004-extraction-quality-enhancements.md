# ADR-0004: Extraction Quality Enhancements

**Status:** Accepted (retroactively documented — already implemented)
**Date:** documented 2026-06-19
**Deciders:** maintainer

> This ADR records decisions referenced throughout the code as `ADR-004 P*` but
> never filed. It documents what was implemented and why, faithfully to those
> references.

## Context

The baseline pipeline (regex IoCs → gazetteer → LLM → STIX) had recall/precision
gaps on real CTI reports: TTPs phrased in domain language, novel entities the
gazetteer never saw, IoCs buried in appendix tables, and LLM-invented
relationships. Each gap had a research-backed fix; they were grouped into phases.

## Decision

Add research-backed quality layers in three phases, each independently toggleable
and offline-capable.

| Phase | Enhancement | Source | Implementation |
|---|---|---|---|
| **P1-A** | Domain-specific TTP embeddings (`SecureBERT-Plus`) over `all-MiniLM-L6-v2` | CTiKG, Windsor 2025 | `pipeline/stage2c_ttp_semantic.py` (+ cache manifest in `build_indexes.py`) |
| **P1-B** | NER / extraction evaluation harness | — | `tests/eval_pipeline.py` |
| **P1-C** | IoC appendix / list-pattern extraction (defanged tables, one-per-line) | Croquet & Thorne 2025 | `pipeline/stage2_extraction.py` (tested in `test_stage2.py`) |
| **P2-A** | GLiNER / NuNER zero-shot NER for novel entities (sectors, campaigns, infra) | 0-CTI, CY4GATE / Noi et al. 2025 | `pipeline/stage2e_gliner.py` |
| **P2-B** | Document-level entity context passed to every LLM chunk (solves the "IoC appendix" problem) | CyNER / Fujii 2024 | `api/worker.py::_build_doc_context` |
| **P3-A** | Relationship self-verification (second LLM pass quotes the supporting sentence) | aCTIon, NEC Labs 2023 | `pipeline/stage3d_verify.py` |
| **P3-C** | ATT&CK Technique Extraction (ATE) benchmark | — | `tests/eval_pipeline.py` |

## Consequences

- **Easier:** measurable extraction quality; novel-entity discovery beyond the gazetteer; far fewer hallucinated relationships.
- **Harder / revisit:** more models to download/cache (mitigated by lazy load + offline caches); a model-manifest is needed so embedding caches invalidate when `TTP_EMBEDDING_MODEL` changes (P1-A).
- Each layer degrades gracefully — disabled or model-absent layers are skipped, the pipeline still produces valid STIX.

## Related
Superseded numbering note: the **coverage matrix** is ADR-0008 (earlier drafts
referenced it as "ADR-0005"; ADR-0005 is IoC/defang robustness — see the index).
