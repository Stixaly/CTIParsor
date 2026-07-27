# ADR-0012: STIX Graph Completion (edge enrichment)

**Status:** Accepted
**Date:** 2026-07-27
**Deciders:** maintainer

## Context

Relationships reach the bundle through a single, deliberately strict path: the
Stage 3 LLM emits an edge only when it finds an **explicit** statement, and Stage
3d/3f then **delete** any edge whose supporting sentence cannot be quoted (Stage
3d cut relationship hallucination 27%→8%; ADR-0009). That gate is why precision
is high — and it is also why the graph is **sparse**:

- Two objects that clearly belong together but were never described in a single
  sentence get no edge.
- Aliasing fragments the graph: "APT29", "Cozy Bear", and "the group" become
  separate nodes, so every verified edge attached to one alias is invisible to
  the others. The [grounding baseline](../../memory) notes the residual ~12.5%
  relationship error is *mostly coreference/alias, not invented facts* — the same
  root cause as the sparsity.

Loosening the extraction gate to add edges would directly cost accuracy. The CTI
KG literature (CTINexus, arXiv:2410.21060; edge-propagation link prediction,
ScienceDirect S0020025523013555) converges on a different answer: **add a
graph-completion layer *after* the precision-gated extraction**, so the base
graph is untouched and every new edge is independently justified.

Approaches weighed:

| Option | Verdict |
|---|---|
| Naive co-occurrence / same-sentence linking | **Rejected** — high recall, wrecks precision. |
| KGE / GNN link prediction (TransE, RotatE, edge-propagation) | **Rejected for now** — needs a large annotated training graph and yields probabilistic edges hard to hold at our precision bar; CTINexus rejected GNN link prediction for the same reason. |
| Deterministic ontology inference + alias merge + LLM long-distance (CTINexus-style) | **Chosen** — append-only, spec-guarded, and each edge carries provenance. |

## Decision

Add **Stage 4b** (`pipeline/stage4b_graph_completion.py`), run inside
`build_stix_bundle` immediately before the Report SDO is assembled — so new edges
land in `object_refs` and are provenance-stamped like every other object. Three
engines, in order:

| Step | Engine | Guarantee |
|---|---|---|
| **1** | **Alias merge** — collapse same-type SDOs (threat-actor / intrusion-set / malware / campaign / tool) whose normalised name or `aliases` denote the same object; rewire their edges onto one canonical node and drop the duplicates. Optional `fuzzy_alias` adds rapidfuzz name matching (ratio ≥ 93). An **IOC guard** (CVE / hash / IP regex) never merges look-alike-but-distinct observables (CVE-2023-23397 vs -23392). | Reconnects fragmented edges; the only destructive step, but SCO identity is untouched. |
| **1b** | **ATT&CK reference grounding** — `scripts/build_indexes.py --only relationships` distils the MITRE ATT&CK STIX bundles into `pipeline/data/attack_relationships.json` (~20 000 curated `G/S/T`-ID triples, 586 KB). At mapping time, report SDOs are resolved to ATT&CK IDs (techniques via their `mitre-attack` external reference; actors/malware/tools via the gazetteer's `mitre_id`), and any curated edge whose two endpoints both appear in the report is added — labelled `x_evidence_label="reported"` with the ATT&CK pair in `x_inference_rule` (e.g. `attack-reference:G0016>S0002`). Runs *before* transitive inference so curated edges can serve as premises. | Expert-maintained facts, not inferences — the highest-precision edge source available; no LLM, no network. |
| **2** | **Transitive inference** — compose two verified edges along a fixed table `(v1,v2)→v3` (e.g. `uses∘uses→uses`, `attributed-to∘attributed-to→attributed-to`, `uses∘exploits→targets`). Every candidate is guarded by `rel_is_suggested`; if the composed verb is not a *suggested* STIX 2.1 relationship for the actual (src-type → tgt-type) pair, it is **skipped, not downgraded**. | No invalid or speculative edge ships; premises are already verified. |
| **3** | **Long-distance prediction** (opt-in) — CTINexus Phase 3: DFS the remaining disconnected sub-graphs, pick each sub-graph's central node by degree centrality and the report's topic node (global max degree), and ask an **injected** LLM inferer (`stage4c_long_distance`) for the relation between them. The inferer requires the model to **quote the exact supporting sentence** — the same evidence bar as Stage 3d — so no quote ⟹ no edge; the quote is stored as `x_evidence_text`. Same `rel_is_suggested` guard. Off unless a callable is supplied, so Stage 4 stays network-free by default. | Bounded to O(components) edges, not O(n²); evidence-grounded (a supporting sentence is mandatory). |

Every inferred edge is tagged `x_evidence_label="inferred"` (weakest grade, per
ADR-0009), plus `x_inference_rule` (e.g. `transitive:uses+uses`) and
`x_inferred_from` (premise edge ids), so the review UI can display and reject
them. Confidence is discounted from the weaker premise (`min(conf) × 0.9`).

**User specifies vs. tool decides.** Completion honours the existing relationship
policy (ADR-0007 panel) via a new optional `completion` block:

```json
"completion": { "transitive": true, "alias": true, "reference": true,
                "long_distance": false, "fuzzy_alias": false,
                "semantic_alias": false, "max_new_edges": 200 }
```

`semantic_alias` (opt-in) extends the alias merge with CTINexus-style embedding
matching: same-type SDO names with cosine ≥ 0.6 (their tested optimum) under the
Stage 2c sentence-embedding model are merged, catching aliases with no character
overlap ("the Dukes" ↔ "APT29"). The IOC guard still applies, and the pass
silently no-ops when the model is unavailable (`SKIP_HEAVY_MODELS=1`).

`completion` is the "let the tool decide" switch (defaults: transitive + alias on,
long-distance off). A per-rule `"mode":"pin"` is "the analyst specifies the link"
and **always wins**: an inferred verb is passed through the same pin override as
Stage 4, so the tool never contradicts an explicit human decision.

## Consequences

- **Easier:** denser, more navigable graphs at **zero accuracy cost** for steps 1–2
  (deterministic, spec-guarded); disconnected sub-graphs shrink; the dominant
  coreference/alias error is retired by the merge step. Inferred edges are
  visually distinguishable and analyst-rejectable.
- **Harder / watch:** alias merge is the one destructive step — the IOC guard and
  same-type restriction bound its blast radius, but a wrong merge collapses two
  real actors, so `fuzzy_alias` defaults off. Long-distance depends on an external
  LLM and is opt-in; its graph-side logic (components, central-node selection) is
  unit-tested with a fake inferer. `max_new_edges` caps runaway fan-out on
  high-cardinality reports.
- **Wiring:** steps 1–2 run transparently inside `build_stix_bundle` (CLI + API).
  Step 3 is wired in the API worker: it builds the inferer via
  `stage4c_long_distance.default_long_distance_inferer(policy)`, which returns a
  callable bound to the Stage 3 LLM client only when `completion.long_distance` is
  set AND the provider is ready (else `None`), and passes it as
  `long_distance_infer=` to `build_stix_bundle`. The CLI leaves long-distance off
  (no policy DB) but still gets the deterministic steps 1–2.
- **Measurement:** `python tests/eval_pipeline.py -b rel` scores the completion
  layer at the edge level (per-engine judged precision, recall, F1) against gold
  accept/reject labels — built-in fixtures, or `--dataset gold.json` for
  human-annotated reports. This is the harness that turns the "no accuracy loss"
  design claim into a measured number (comparable to CTINexus's 0.91 relation-
  prediction precision).
- **Superseded/related:** builds on ADR-0009 (evidence labels, provenance) and
  ADR-0007 (policy panel). Does not touch the Stage 3 extraction gate.
