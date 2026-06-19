# ADR-0009: STIX Trust & Provenance

**Status:** Accepted (documented alongside implementation)
**Date:** 2026-06-19
**Deciders:** maintainer

> Records three related trust/provenance features that shipped together. Inspired
> by the Operation Desert Hydra CTI methodology (evidence grading, source markings).

## Context

A bundle is only as useful as it is trustworthy. The pipeline emitted relationships
with a single flat `confidence` number — no way to distinguish a directly-observed
fact from an LLM inference — no record of *who authored* the intel, and no sharing
markings. Three gaps, addressed together.

## Decision

### 1. Evidence labels (NATO/Admiralty-style grading)
Every relationship carries an `EvidenceLabel`:
`observed` / `reported` / `assessed` / `inferred` / `gap`. The LLM emits and grades
it (with anti-hallucination prompt rules), it's persisted, exposed/validated on the
API, carried into STIX as `x_evidence_label`, and the review-UI auto-accept gate is
**evidence-graded** — only `observed` auto-promotes; `inferred`/`gap` always wait
for a human.

### 2. Cross-model consensus (opt-in, anti-hallucination)
With `ENABLE_CONSENSUS=true`, relationship-bearing chunks are re-run through a
**second** provider; agreement boosts confidence, single-model claims are penalised
and downgraded from `observed`. Stronger than Stage 3d self-verification (two
different models, not a model judging itself). Reuses the existing `_call_llm`
provider abstraction.

### 3. Provenance & sharing markings (Option: post-processing stamp)
Every bundle object is stamped with an authoring `Identity` (`created_by_ref` → the
**pipeline**, not the actor) and a TLP marking (per-job `tlp_level`, falling back to
`STIX_TLP`); PAP is a statement marking. SCOs are marked-only (STIX 2.1 cyber
observables have no `created_by_ref`). Implemented as a single post-processing pass
(`_stamp_objects`) rather than touching ~15 object constructors.

## Trade-offs

- **Evidence labels:** one extra field per relationship, no new LLM calls; the value
  is a defensible basis for every accept/reject decision.
- **Consensus:** ~2× LLM cost/latency on relationship-bearing chunks; opt-in, and
  bounded to the highest-risk output. Off by default → behaviour is byte-identical.
- **Provenance:** the stamp pass adds two objects + properties; makes bundles
  "ingestion-grade" for OpenCTI/MISP (which apply sharing policy from TLP and group
  by author). The `x_evidence_label` custom property is spec-legal (`allow_custom`).

## Consequences

- **Easier:** graded, attributable, shareable intel out of the box.
- **Harder / revisit:** a second provider key is needed for consensus; the strict
  `stix2-validator` is skipped today (`.stix2_schemas_missing`) so the custom
  property is only asserted via serialize — revisit when schemas are installed.

## Implementation
`models/schemas.py::EvidenceLabel`, `pipeline/stage3_llm.py`,
`pipeline/stage3e_consensus.py`, `pipeline/stage4_stix_mapping.py`
(`_authoring_identity` / `_tlp_marking` / `_pap_marking` / `_stamp_objects`).
Tests: `tests/test_evidence_consensus.py`, `tests/test_provenance.py`,
`tests/test_persistence.py`.
