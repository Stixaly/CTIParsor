# ADR-0013: STIX Graph Completion (edge enrichment)

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
  the others. The grounding baseline (`tests/eval_pipeline.py -b grounding`)
  measures the residual relationship error at ~12.5%, and it is *mostly
  coreference/alias, not invented facts* — the same root cause as the sparsity.

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
| **1** | **Alias merge — fallback, default OFF.** ADR-0012 already canonicalises MITRE-known aliases in `pipeline/aliases.py` at SDO-*creation* time, so `APT34`/`OilRig` never split into two nodes — a strictly better fix than merging after the fact. This engine therefore only covers aliases **absent from the gazetteer** (novel or report-specific names), plus the opt-in `fuzzy_alias` (rapidfuzz ≥ 93) and `semantic_alias` (embedding cosine ≥ 0.6) matchers. An **IOC guard** (CVE / hash / IP regex) never merges look-alike-but-distinct observables (CVE-2023-23397 vs -23392). | Off by default because it is the only *destructive* engine and mostly redundant with ADR-0012; opt in when a corpus has many non-MITRE aliases. |
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
"completion": { "transitive": true, "reference": true, "alias": false,
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

## Status review (2026-09-02)

Three of the consequences above need qualifying against what runs:

- Alias merge is **off by default**, so "the dominant coreference/alias error
  is retired by the merge step" holds only through ADR-0012/0021
  canonicalisation at SDO creation, not through Stage 4b.
- `max_new_edges=200` is a single budget shared by reference grounding and
  transitive inference; ADR-0024 measured a bundle that hit it exactly.
- "Visually distinguishable" is not implemented: `frontend/src/pages/Graph.tsx`
  does not read `x_evidence_label` or `x_inference_rule`; only the Review page
  keys on the label (auto-promotion gate).

The default-policy and cap questions are taken up by ADR-0038.

## Amendment (2026-10-11): what the report does not state stays out of its Report

The October 2026 audit (B 8.4.2, 8.4.3) found that reference grounding is on
by default, labels MITRE's curated edges `reported` (the grade for what the
source states) and runs before the Report SDO is built, so its edges entered
the Report's `object_refs`: OpenCTI then files "APT29 uses Mimikatz" as
contained in this report when only MITRE says it. Transitive edges, composed
from two of the report's edges and not measured rule by rule, entered it the
same way.

- A reference edge is labelled `external-reference`, outside the
  EvidenceLabel scale, which grades what the report says.
- Reference and transitive edges ship in the bundle, as before, but not in
  the Report's `object_refs`; the ledger records each with
  `outside_report: true`. OpenCTI imports them as relationships between the
  objects, not as part of the report. The Graph page builds from the bundle
  and still shows them, with their provenance.
- Long-distance edges (step 3, opt-in) are read from the report's own text
  and stay in the Report.
- Measuring each transitive rule before it stays on by default waits for the
  in-house set's gold relationships.

## Amendment (2026-10-26): a rejected relationship stays rejected

The code audit of 2026-10-25 found that graph completion adds back a
relationship an analyst rejected. Finalize hands Stage 4 only the rows that
ship (`decisions.SHIPS`), and each engine skipped a triple only when it was
already one of the bundle's edges; a rejected row is not. So "A uses B" and
"B uses C", both accepted, composed the rejected "A uses C" back
(`transitive:uses+uses`), and reference grounding re-added a rejected edge that
MITRE also states. A row held for review (ADR-0082) shipped the same way, as an
inference, before anyone had decided it. Both engines are on by default.

Decided by the maintainer:

- **A rejection says the relationship is false for this report**, not only that
  its evidence is weak. No engine adds a rejected triple back: not transitive
  inference, not reference grounding, not long distance. MITRE stating it does
  not override the analyst, as an inferred verb does not override a pinned rule.
- **A held row blocks its triple until an analyst decides it.** Accepted, it
  ships as the row; rejected, the rule above applies. The bundle does not get
  ahead of the review.
- **How.** Finalize also reads the rows that do not ship, `decisions.WITHHELD`:
  rejected, or pending with a `held_reason`. It is written out because
  `NOT SHIPS` is NULL for a held row. Stage 4 resolves each of them as it
  resolves a row that ships (`_resolve_row`: the name and its aliases, the
  observable's Indicator, the policy pin, the fall back to `related-to`) and
  gives `complete_graph` the triples as `forbidden`. A pipeline run does the
  same with Stage 3d's `rel_review`. After an alias merge (step 1), a forbidden
  triple follows the absorbed node onto the one kept. A refused edge takes none
  of the `max_new_edges` budget.
- **The match is the triple, verb included**: rejecting "A uses C" does not
  forbid "A targets C". `related-to` and `duplicate-of` name no direction, so
  rejecting "A related-to C" also forbids "C related-to A", the direction the
  long-distance inferer may answer instead. A row whose endpoint resolves to no
  object (its entity was rejected too) forbids nothing, since no edge can reach
  that object.
- **The mapping ledger** gains `refused`, present only when not empty, so a
  build with no rejection keeps the ledger it had. One entry per triple and
  rule: the two ids, the verb, the `x_inference_rule` the edge would have
  carried, its premises for a transitive one, and the reason,
  `rejected_by_analyst` or `held_for_review`. After a baseline merge
  (ADR-0090) the ids follow the baseline objects that replaced them. An engine
  that reaches `max_new_edges` stops there, so `refused` lists only the
  candidates examined before the cap.

Not covered here:

- Other edges Stage 4 builds with no review row can recreate a rejected row's
  triple too: the actor × targeted country and sector product
  (`targeted_location`, inside the Report) and the policy-pinned edges, both
  read in the code. IoC associations were not checked. *The product and the
  pinned edges are covered by the next amendment; IoC associations are not.*
- A deleted row (`DELETE /relationships/{id}`, the Graph page's delete) leaves
  no trace, so completion may add its triple back. Only a rejection holds.
- The Graph page does not show `refused` yet.
- The alias merge, off by default, rewires the rows that ship: an accepted
  "apt-29 uses X" can land on a rejected "APT29 uses X". It adds no edge, so it
  is not refused.
- The measurement scripts that call `build_bundle` from stored rows
  (`scripts/baseline_round_trip.py`, `rebuild_bundle_provenance.py`,
  `measure_pin_allocation.py`) do not pass the refused rows yet, so on a job
  with a rejection they can differ from finalize.

Validation: `tests/test_stage4b_completion.py` (each engine, the held reason,
the budget, an undirected verb, the alias merge, rows resolved through
`build_stix_bundle`, through an observable's Indicator, a rejection over a hold,
a row that resolves to nothing), `tests/test_held_for_review.py` (finalize while
a claim is held, then once it is rejected; `SHIPS` and `WITHHELD` split every
row), `tests/test_orchestrator.py` (a run refuses Stage 3d's held claim) and
`tests/test_bundle_ledger.py` (`refused` after a baseline merge). Each fails
with its part of the change disabled, except the two that check what must not
change (a row that resolves to nothing, the split of the rows).

## Amendment (2026-10-26, continued): the targets product and pinned edges

The amendment above kept graph completion from building a rejected or held
row's triple, and left out two other Stage 4 builders that make edges with no
review row of their own. The actor × targeted country and sector product
(origin `targeted_location`, inside the Report) filtered rejected location and
identity *entities*, not rejected rows: a rejected "APT29 targets France" was
built again from the LLM's lists, and a held one shipped before anyone decided
it. A policy-pinned rule (ADR-0024, ADR-0026) materialised the triple of a
rejected row the same way, since it pins every pair of its two types.

Decided by the maintainer: the same rule, with the same triples.

- **One set of forbidden triples.** Stage 4 resolves the rows that do not ship
  once, before the targets product, adds the reverse of each triple whose verb
  names no direction (`related-to`, `duplicate-of`), and the product, the pin
  pass and `complete_graph` all read that set. It is built whether or not
  graph completion runs: `graph_completion=False` (an ablation, ADR-0059)
  turns Stage 4b off, not the analyst's decision.
- **A row that ships wins over a refused row with the same triple.** The job
  store can hold two rows with one triple (an analyst adds the edge again after
  rejecting it); the accepted one ships as a row anyway, and no row's decision
  outranks another's. Such a triple is taken out of the set, so neither the
  product nor a pinned rule refuses it, and the ledger does not list as
  refused an edge that ships.
- **The edge each builder would make.** The product compares the edge
  `_add_relationship` would build (the policy pin applied, the fall back to
  `related-to`), and the pin pass the key `_pin_edge_key` gives, after routing
  through an Indicator and after the evidence gate (ADR-0027). A refused pair
  takes none of the `max_pinned_edges` budget and is not one of the rule's
  candidates in `x_synthesis_stats.pin`, which keeps its shape; a pair the
  gate blocks is still counted `blocked`. A rule whose every pair is refused
  therefore drops out of `x_synthesis_stats.pin.rules`, as a rule that matched
  nothing does; the ledger lists its refusals.
- **A targeted country or sector is found by its list's key.** Stage 4 keys
  the objects it makes from the targeted lists `location:<name>` and
  `identity:<name>`, not by bare name (only an NER entity of the same name has
  one). When a bare name finds nothing, a row that does not ship is also looked
  up under those keys, so "France", named only by the LLM's targeted-country
  list, is the Location the product targets. The rows that ship are looked up
  the same way for the rule above; in the relationship loop they resolve as
  before.
- **The ledger.** Each refusal joins `refused`, which now names on every entry
  the `origin` the edge would have had: `targeted_location`, `policy_pin`, or
  `completion_reference` / `completion_transitive` / `completion_long_distance`
  for the engines' refusals of the amendment above. A pinned edge's entry
  carries its `rule` (the `x_policy_rule` it would have carried), the
  product's carries `actor` and `target` as the lists name them. One entry per
  triple, origin and rule. These refusals are recorded before Stage 4b's alias
  merge; their ids follow it as they follow a baseline merge, and two entries a
  merge makes one keep the first.

Not covered here:

- **IoC associations** (`ioc_associations` from the LLM's JSON, origin
  `ioc_association`, read in the code) build `indicator indicates malware`
  with no review row, the triple a rejected "185.220.101.5 indicates
  ZetaLoader" row resolves to. They run before the Indicators a refused row is
  routed through exist, so they need their own change.

A build with no rejection is unchanged: the forbidden set is empty and both
builders go on as before (`tests/test_stage4_reference.py` does not move).

Validation: `tests/test_stage4_refusals.py` (a rejected and a held row against
the product, with France from the list alone and from NER too, with graph
completion off, a country the list names twice, an accepted row with the same
triple, a policy that rewrites `targets`; against a pinned rule, the pin
budget and the synthesis stats, a verb the rule rewrites, an undirected verb),
`tests/test_pin_evidence.py` (the gate judges before the refusal),
`tests/test_held_for_review.py` (finalize: the product does not ship a held
claim, nor once rejected, and ships it once accepted) and
`tests/test_bundle_ledger.py` (one entry per triple, origin and rule; the
alias merge; `origin` on an engine's refusal). Each fails with its part of the
change disabled, except the one that checks what must not change (every pair
built when nothing is refused).
