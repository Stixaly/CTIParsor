# ADR-0012 — Hallucination measurement, entity canonicalisation & relationship precision

**Status:** Accepted

## Context

The pipeline had seven precision layers (ADR-0004, ADR-0009, ADR-0011) but **no
way to measure their effect**. The eval harness (`tests/eval_pipeline.py`) scored
only *recall* (NER / ATE) on ~10 hand-written fixtures. Two questions could not be
answered from data:

1. **Hallucination** — of what the pipeline actually emits, how much is *not*
   supported by the source text?
2. Whether any given change (a model swap, a new filter) helps or hurts.

Every proposed improvement (an NLI-entailment stage, a domain embedding model) was
therefore a guess. We needed a measurement keystone before building anything.

## Decision

### 1. Grounding / hallucination-rate benchmark (measurement)

A third benchmark mode, `eval_pipeline.py -b grounding`, measures how much emitted
output is groundable in the source. It is **offline** and reuses the pipeline's own
grounding primitive (`stage3b._name_in_text`) so the number matches what the
hallucination filter enforces.

- **Inputs**: `--from-db` (real processed reports in `cti_stix.db`), `--dataset`
  (exported output JSON), or built-in fixtures with planted hallucinations.
- **Metrics**: entity grounding rate; relationship *claim* grounding graded
  best-first as `cosentence > window(±N) > evidence-quote > proximity > endpoints
  > none`. `--rel-window`, `--rel-proximity`, `--alias-aware` tune the tiers.
- **Segmentation**: relationships are split into **named-entity** vs
  **IoC/technical** populations — one global number blends two very different
  regimes and misleads.

### 2. Entity canonicalisation (`pipeline/aliases.py`)

An offline alias index built from the shipped `gazetteer.json` + `mitre_index.json`:
`mitre_id_for`, `canonical_name`, `alias_surface_forms`, `technique_id_for`,
`technique_name_for`. Unknown names pass through unchanged (safe to apply blindly).

`stage4_stix_mapping.py` uses it so actor/malware/tool SDOs are keyed by their
**canonical** name — `APT34` and `OilRig` (MITRE group G0049) collapse into one
node instead of two — and every alias surface form is registered so a relationship
naming any alias resolves to the merged node.

### 3. Relationship precision guard (`stage4`)

Observable-SCO ↔ attack-pattern edges (e.g. `domain communicates-with T1071.001`)
are a type error the LLM occasionally emits. Rather than downgrade them to a noisy
`related-to`, Stage 4 drops them (`_is_spurious_observable_ttp_edge`).

## Consequences

Measured on a 4-report corpus (2 in-DB + 2 processed offline, 151 relationships):

- **Entity hallucination ≈ 0** (name filter robust; alias-aware resolves the last
  residual surface-form mismatches).
- **Named-entity relationship hallucination ≈ 11 %** — the real, tractable target.
- **IoC/technical relationships** stay ~0.53 groundable even with proximity + the
  precision guard: their support is structural (tables) and dispersed. This is a
  **metric-visibility** limit, not a to-fix hallucination number.
- The 2-report baseline (9 %) proved **non-representative** — relationship support
  is strongly bimodal (narrative ~0.91 vs IoC-heavy ~0.47). Always read the
  segments, never the global blend.

The benchmark redirected the roadmap by evidence, away from a lower-value
NLI-entailment stage toward canonicalisation and metric segmentation. Every future
extraction-quality change is now validated before/after with one command:

```bash
python tests/eval_pipeline.py -b grounding --from-db all \
    --rel-window 1 --alias-aware --rel-proximity 200
```

## Notes

- No new dependencies; `aliases.py` reuses `pipeline/data/gazetteer.json` and
  `mitre_index.json` already built by `scripts/build_indexes.py`. Install steps
  are unchanged.
- Extends the extraction-quality line (ADR-0004) and the TTP-precision work
  (ADR-0011). Superseded by nothing.
