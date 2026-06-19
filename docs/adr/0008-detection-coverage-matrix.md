# ADR-0008: Per-Report Detection-Coverage Matrix

**Status:** Accepted
**Date:** 2026-06-19
**Deciders:** maintainer
**Relates:** implemented by ADR-0006 (multi-corpus rule store) + ADR-0007 (settings)

> Numbering note: earlier drafts (and ADR-0006/0007) referenced this as
> "ADR-0005". ADR-0005 is IoC/defang robustness; the coverage matrix is **0008**.

## Context

Map each report's extracted ATT&CK techniques to a coverage view — Desert Hydra's
signature artifact. Hard constraint: **CTIParsor has no validation lab**, so it
cannot claim lab-validated coverage (a Kibana-proof "5"). Reusing that scale would
overclaim. The real decision is *what "coverage" means for a non-validating tool
and where the signal comes from*.

Forces: offline-first; deterministic (no LLM in scoring); reuse existing patterns
(the `mitre_index.json` build + client load, SQLite, stage modules). We already
have extracted techniques (`attack-pattern` SDOs with `mitre_id` + `tactics[]`)
and a client-loaded ATT&CK index.

## Decision

Redefine coverage as **detection readiness, explicitly not validation**, and ship
in two phases:

- **Phase 1:** enrich `mitre_index.json` with ATT&CK data sources; render the
  matrix as a pure frontend join (coverage = "telemetry-mapped"). No backend change.
- **Phase 2 (ADR-0006, shipped):** real detection rules from local Sigma corpora,
  a persisted rule store, and a 0–3 score (see below). The `useCoverage(jobId)`
  hook is the seam between the view and the source, so Phase 1→2 is invisible to the view.

A persistent banner states "readiness ≠ validation."

## Options Considered

| Option | Coverage signal | Verdict |
|---|---|---|
| **A — static ATT&CK data-source join, frontend-computed** | telemetry-mapped | Phase 1 — cheap, offline, honest, no backend |
| **B — Sigma rule-library match, pipeline + persisted** | rule exists | Phase 2 (ADR-0006) — richer, bigger surface |
| **C — LLM-drafted detections, self-scored** | model guess | **Rejected** — injects hallucination into the one artifact that must be trustworthy |

## Coverage scale (NOT lab-validated)

| Score | Meaning |
|---|---|
| 3 | rules from ≥2 corpora (corroborated) |
| 2 | rule from 1 corpus |
| 1 | telemetry-mapped only (ATT&CK data source, no rule) — Phase 1 fallback |
| 0 | technique extracted, no coverage |

Deliberately disjoint from Desert Hydra's lab `0/3/4/5` to avoid confusion.

## Consequences

- **Easier:** the matrix is the home of the detection-engineering roadmap; Phase 2
  slotted in by upgrading cell state, not rebuilding.
- **Harder / revisit:** keep the readiness/validation distinction loud; coverage is
  computed **live** in the API (always reflects current accept/reject + rule store)
  rather than persisted — revisit if performance demands precomputation.
- Pairs with the coverage-score design token (`tokens.ts::coverageColor`).

## Implementation
`pipeline/detection/coverage.py`, `api/routes/coverage.py`,
`frontend/src/hooks/useCoverage.ts`, `frontend/src/pages/Coverage.tsx`.
