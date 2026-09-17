# ADR-0038: Link density under policy — one default rule set, kept `gap` edges, per-node fan-out caps

**Status:** Proposed
**Date:** 2026-09-02
**Deciders:** maintainer
**Amends:** ADR-0013 (completion defaults and cap), ADR-0024 (cap rationale), ADR-0026/0027 (pin budget and gate). Depends on ADR-0009 (evidence labels) and ADR-0012/0021 (alias canonicalisation).

## Context

The question asked was "how do we get more links between objects, while respecting the relationship policy — and do the default policies need improving?". Before designing anything, every path an edge can take into a bundle was enumerated from the code, and a measurement instrument was built. The measurement itself is blocked on this host (see §3); the two defects that decide most of this ADR are facts of the code, not of a sample.

### 1. Where an edge can come from today

| # | Source | Gate | Label | Cap | Default |
|---|---|---|---|---|---|
| S1 | Stage 3 LLM relationship, Stage 3d quote-verified | explicit statement + verbatim quote; endpoints must resolve by **exact lowercase name** in Stage 4 (`name_to_stix`) | `observed`/`reported`/`assessed`/`inferred` | none | on |
| S2 | Stage 4 helpers: `indicator→indicates→malware` (from `ioc_associations`), `indicator→based-on→observed-data`, `actor→targets→location/identity` | LLM association / list membership | `reported`, `observed` | none | on |
| S3 | Policy **pin** rules (ADR-0024/26/27) | co-sentence window 3 (`pin_evidence`), fair-share budget | `assessed` | `max_pinned_edges=200` | **0 rules** in the factory default |
| S4 | Stage 4b ATT&CK reference grounding | both endpoints resolve to ATT&CK ids and a curated pair exists — `pipeline/data/attack_relationships.json` holds 20 015 pairs: 12 782 S→T, 4 598 G→T, 1 273 C→T, 1 159 G→S, 176 C→S `uses`, and 27 C `attributed-to` G | `reported` | shares `max_new_edges=200` with S5 | on |
| S5 | Stage 4b transitive inference (9 compositions in `_TRANSITIVE_RULES`) | both premises exist; composed verb suggested for the type pair | `inferred` | shares the 200 with S4 | on |
| S6 | Stage 4b long-distance LLM inference (one call per disconnected component) | model must quote one supporting sentence | `inferred` | same 200 | **off** |
| S7 | Stage 4b alias merge (rewires, adds no edge) | normalised-name equality; fuzzy/semantic opt-in | — | — | off |

Two entries in that table are not decisions anyone took; they are accidents of where the code lives.

**The factory default policy has no rules.** `api/routes/policy.py::_DEFAULT_POLICY` is `{"version": 1, "global": "enforce", "rules": []}`. `frontend/src/pages/Policy.tsx::DEFAULT_RULES` holds 27 rules (21 `pin`, 6 `auto`) and the page *displays* them whenever the server returns an empty list ("so the editor isn't presented blank on first visit") — but nothing seeds the database. Stage 4 reads `relationship_policy` (`api/worker.py`), so on any install where nobody has pressed Save it runs with zero pinned rules while the page shows a full model. Every pin figure in ADR-0026/0027 (18 426 candidates for a budget of 200; 344 orphan `course-of-action` objects) was taken with a saved policy. After the 2026-09-02 fresh clone the `relationship_policy` table is empty, so today's bundles carry S1, S2, S4 and S5 edges only. *What you see is not what runs.*

**`gap` relationships are requested, then deleted.** The Stage 3 prompt (`pipeline/stage3_llm.py`) instructs: "when you cannot find explicit support for a relationship, still emit it with `evidence_label` `gap` and `evidence_text` `""` — a missing answer expressed as gap is correct and useful". Stage 3d (`pipeline/stage3d_verify.py`, `ENABLE_STIX_VERIFICATION=true` in `.env`) then asks the model to quote a supporting sentence for **every** claim and discards the ones marked unverified — which is, by construction, every `gap` claim. ADR-0009 created the `gap` grade precisely so such edges could ship and wait for a reviewer ("only `observed` auto-promotes; `inferred`/`gap` always wait"), and `Review.tsx` still implements that gate. The pipeline pays for these edges twice (extraction, then verification) and throws them away.

Three smaller structural facts, all from the code:

- **`auto` rules are inert.** `_apply_policy` and `_materialise_pinned_edges` act on `mode == "pin"` only; an `auto` rule changes nothing. The six `auto` rules in the template are documentation ("declare the pair so an analyst sees it"), which is fine as long as nobody expects them to add edges.
- **The caps are global and shared.** `max_new_edges` is one counter for S4 *and* S5 (S4 runs first and can consume all of it); ADR-0024 measured a bundle that hit exactly 200. ADR-0024 itself rejected a fan-out cap for "picking a limit with no data behind it".
- **The Graph page cannot tell an inferred edge from a reported one.** `frontend/src/pages/Graph.tsx` reads neither `x_evidence_label` nor `x_inference_rule`; ADR-0013's "visually distinguishable and analyst-rejectable" holds only for the Review list.

### 2. The instrument

`scripts/measure_graph_links.py` (new, stdlib, read-only) reports per stored bundle: nodes, edges, extracted relationships (rows in `relationships`), isolated nodes, connected components and the largest component's share, edges by evidence label and by source tag (`attack-reference`, `transitive`, `long-distance`, `policy-pin`, none), isolated nodes by type, and — the number this ADR turns on — **co-mention candidates**: unlinked node pairs of linkable types (never SCO–SCO, never technique–technique, never identity/location/indicator/observed-data) that share at least one sentence of the report, plus how many currently isolated nodes such a pair would rescue. It is the pool a policy rule with the ADR-0027 gate can reach, before any verb is chosen.

Companion one-off (scratch, to be folded into the script if kept): the share of `relationships` rows whose `source_value`/`target_value` fail Stage 4's exact-name lookup — the S1 edges lost to endpoint resolution.

### 3. Measurement status — blocked on this host, procedure recorded

The thirteen bundles the earlier ADRs measured no longer exist: the working copy was re-cloned on 2026-09-02 and `jobs` is empty. Four report texts available locally without downloading anything were re-ingested through `POST /api/ingest/text` under the factory default policy:

| report | source | chars |
|---|---|---|
| SEO poisoning campaign … infostealer | vendor report recovered from the sibling project's DB (`../cti-to-stix/cti_stix.db`) | 27 783 |
| APT28 / APT29 / APT32 | STIXnet dataset (`../STIXnet-main.zip`), MITRE group descriptions | 2 710 / 1 488 / 1 744 |

Seven attempts, none produced a bundle:

| # | Setup | Outcome |
|---|---|---|
| 1 | API, 4 jobs at once, heavy models | worker of the 27 KB report SIGKILLed by the OOM killer at 10.3 GB RSS; the three others got SIGTERM — ADR-0036's 4.4 GB-per-job figure, confirmed |
| 2–3 | API, `WORKER_MAX_CONCURRENT=1`, with and without heavy models | WSL distro terminated (`Wsl/Service/E_UNEXPECTED`, journal "uncleanly shut down") within a minute of Stage 3 starting |
| 4–5 | API detached with `setsid`, single uvicorn worker, no further WSL commands issued | same termination, at "[Stage 3] chunk 1/1" |
| 6 | CLI `main.py`, Anthropic provider | same |
| 7 | CLI `main.py`, Ollama provider on a separate host (whose HTTP endpoint the same WSL distro had been calling for minutes without incident) | same, at "LLM chunk 1/1" |

The distro dies at the first Stage 3 LLM call whatever the provider, the entry point or the process model; host RAM was 16 GB free throughout. This is a WSL fault on the Windows workstation, not a pipeline defect, and it is outside this ADR's remit to fix. Attempt 2 also exposed a real defect worth its own fix: with `API_WORKERS=4` and reload off, every uvicorn worker runs the startup "requeue and start queued jobs" hook, so one queued job was spawned three times (three Stage 3 runs, duplicate `entities`/`relationships` rows).

**Procedure to produce the numbers (action item 0), on the Linux host:**

```bash
# baseline — factory default policy
scripts/measure_graph_links.py --db cti_stix.db --json links_default.json
# variant — the 27 rules the Policy page shows, everything else unchanged
PUT /api/relationship-policy  <policy_default_rules.json>     # rules from Policy.tsx, co-occurrence gate, window 3, fair share, budget 200
POST /api/jobs/{id}/finalize?quick=true   for every job      # Stages 4–5 only, no LLM call
scripts/measure_graph_links.py --db cti_stix.db --json links_rules.json
# hallucination by label on the same bundles (ADR-0024 Phase C)
tests/eval_pipeline.py -b grounding --from-bundle --rel-window 3 --alias-aware
```

The decision below is therefore taken on the structural findings; decisions 3 and 4 carry an explicit measurement gate and the tables in §3 are to be replaced by the two runs above before this ADR moves to Accepted.

## Options considered

| Option | What it does | Verdict |
|---|---|---|
| **A. Loosen the Stage 3 gate** (accept unquoted relationships) | more S1 edges | **Rejected.** ADR-0009/0013 measured the gate as the source of precision (27 % → 8 % hallucination). The label taxonomy already carries weak edges; the gate should not. |
| **B. Keep `gap` edges instead of deleting them** | Stage 3d verifies only claims that *claim* support (`observed`/`reported`/`assessed`); `gap` claims skip verification and ship as `gap` | **Adopted.** Zero extra LLM cost (fewer claims to verify). They never auto-promote (Review gate), so nothing ships as fact that is not. |
| **C. One default rule set, owned by the backend** | move the 27 rules into `_DEFAULT_POLICY`; `GET /api/relationship-policy` returns them when no row exists; the frontend stops carrying its own list | **Adopted.** Removes the display/run divergence; the evidence gate and fair-share budget already bound what those rules can add. |
| **D. Alias-aware endpoint resolution in Stage 4** | resolve `source_value`/`target_value` through `canonical_name(name, type)` and each SDO's `aliases` before giving up | **Adopted behind a measurement gate** — implement if the endpoint-loss share on the four reports is above 10 % of extracted relationships. |
| **E. Per-node fan-out cap instead of a global count** | `max_edges_per_node` (per source node, per source tag) replaces "first 200 then stop" as the anti-Cartesian control; the global caps stay as ceilings and scale with bundle size; S4 and S5 get separate budgets | **Adopted; defaults set from the run in §3.** ADR-0024 already rejected its own cap for having no data behind it; a shared 200 was hit on the first bundle it met. |
| **F. Long-distance inference on a local model** | bind S6 to a `COMPLETION_PROVIDER`/`COMPLETION_MODEL` pair (the ADR-0033 pattern), default on when a local provider answers | **Adopted.** O(components) calls per report; on a local GPU each call is free and private. Same quote bar as Stage 3d. |
| **G. Co-mention linking for every pair** (`related-to`) | one edge per co-sentence pair | **Rejected**, as in ADR-0013 — recall without a verb is noise. Its policy-declared, evidence-gated form *is* option C. |
| **H. KG embedding link prediction** (TransE/RotatE/GNN) | probabilistic edges | **Still rejected** (ADR-0013): no gold graph to train on, no way to hold the precision bar. Revisit when ≥ 50 reviewed bundles exist. |
| **I. Make `auto` rules materialise** | a third mode that emits evidence-gated edges | **Rejected.** The six `auto` rules are `course-of-action` pairs, which are unanchorable (0/344 locatable, ADR-0027); the real fix is upstream in what Stage 3 returns for mitigations. `auto` stays documentation and the README says so. |

## Decision

1. **The backend owns the default policy.** `api/routes/policy.py::_DEFAULT_POLICY` gains the 27 rules (moved verbatim from `Policy.tsx`, comments included), `max_pinned_edges`, `pin_budget_mode` and `pin_evidence` with today's defaults, and a `completion` block with the defaults of decisions 4–5. `GET /api/relationship-policy` returns it when no row exists. `Policy.tsx` drops `DEFAULT_RULES`; "Reset to defaults" fetches `GET /api/relationship-policy/default`. `run_config_json` already snapshots the policy, so a bundle built under the factory default stays distinguishable from one built under an edited copy.
2. **`gap` relationships are kept.** Stage 3d sends only claims labelled `observed`/`reported`/`assessed` for verification; `inferred` and `gap` claims bypass it and keep their label and empty `evidence_text`. Stage 4 already carries the label onto the edge. The Review auto-promotion gate is unchanged.
3. **Endpoint resolution becomes alias-aware** (gated on the §3 measurement): exact name → `canonical_name(value, expected_type)` → any SDO whose `aliases` contains the value, folded with Stage 4b's `_norm_name`. Every recovered edge carries `x_endpoint_resolution="alias"` so the effect stays measurable. Type-aware only — ADR-0021's "snake" case forbids name-only lookup.
4. **Fan-out is capped per node, not per bundle.** New policy key `max_edges_per_node`, applied independently by the pin materialiser, reference grounding, transitive inference and long-distance. `max_pinned_edges` and `max_new_edges` remain as ceilings, default `max(200, 2 × nodes)`; reference grounding and transitive inference get separate budgets. `x_synthesis_stats` reports per-node truncation. The default for `max_edges_per_node` is the 95th percentile of per-node candidate degree in the §3 run — not a number chosen here. Two rules from the external confrontation below: the `("uses", "exploits") → "targets"` composition becomes opt-in (`completion.transitive_targets`, default `false`) because it is the exact shape OpenCTI shipped and then retracted as a bug; and every policy edit is followed by `re_run_final_stages`, so no synthesised edge outlives the rule that produced it.
5. **Long-distance completion runs on a local model when one is configured.** `COMPLETION_PROVIDER` / `COMPLETION_MODEL` (default: the local Ollama, `qwen3.8`, via `/api/generate` with `think:false` — ADR-0033 measured that the OpenAI-compatible route ignores it) select the inferer; `completion.long_distance` defaults to `true`; `default_long_distance_inferer` still returns `None` when the provider is not reachable, so an offline install loses nothing.
6. **The Graph page renders the label.** `inferred`/`gap` edges dashed and dimmed, `assessed` (pins) dotted, with a legend and a per-label filter — the ADR-0013 promise that never shipped.

Alias merge (S7) stays off: ADR-0012/0021 handle the MITRE-known case at creation time, and the measured residual (ADR-0012: ~12.5 % relationship error, mostly coreference) is prose coreference, which decision 5 addresses with a quoted sentence rather than string similarity.

## Consequences

- **Easier:** a fresh install produces the graph the Policy page describes; the graph gains edges only through paths that carry a label and a provenance property, so every added edge is filterable and rejectable; caps stop truncating small reports to protect against large ones.
- **Harder / to watch:** more `gap`/`inferred` edges reach the reviewer — the Review page must stay fast with 2–3× more pending relationships; alias resolution can mis-wire an edge when two SDOs share an alias, hence type-aware only; a run's S6 edge set depends on whether the station was up (recorded in `run_config_json`).
- **Measurement:** `scripts/measure_graph_links.py` is the before/after instrument; `tests/eval_pipeline.py -b grounding --from-bundle` scores hallucination per label and must be re-run after decisions 2 and 3 on the same reports.
- **Superseded:** ADR-0013's "`long_distance` default off" and the shared `max_new_edges`; ADR-0024's fixed 200.

## Action items

0. [ ] On the Linux host: run the §3 procedure (baseline, 27-rule variant, grounding by label) and replace §3's attempt table with the numbers; set decision 4's defaults from them; confirm or drop decision 3.
1. [ ] Decision 1 — backend default policy + `GET /default`, frontend reset button (`api/routes/policy.py`, `Policy.tsx`; tests: factory GET returns 27 rules, PUT of `[]` is honoured, `run_config_json` snapshot unchanged).
2. [ ] Decision 2 — label-aware Stage 3d (`pipeline/stage3d_verify.py`; test: a `gap` claim survives with its label, a `reported` claim without quote is still removed — re-introduce the defect to prove the test bites).
3. [ ] Decision 3 — alias-aware resolution (`pipeline/stage4_stix_mapping.py`; test: "Cozy Bear" resolves to the APT29 SDO, "snake" resolves by type — ADR-0021 fixture).
4. [ ] Decision 4 — per-node caps, separate S4/S5 budgets, stats (`stage4_stix_mapping.py`, `stage4b_graph_completion.py`, `PolicySynthesis.tsx`).
5. [ ] Decision 5 — `COMPLETION_PROVIDER` (`stage4c_long_distance.py`, `.env.example`, `docs/deployment.md`).
6. [ ] Decision 6 — Graph page label rendering (`Graph.tsx`).
7. [ ] Separate fix, not this ADR: the startup job pickup runs once per uvicorn worker (`api/main.py::lifespan` → `start_queued_jobs`), and the concurrency counter is per process — claim jobs atomically and count running jobs from the database (ADR-0002/0036).
8. [ ] README "Relationship policy" section: document the factory default and the new keys; CHANGELOG entry.

## Confrontation with external practice (2026-09-02)

Checked against the tools and papers that solve the same problem, before this ADR moves to Accepted.

| Source | What they do | Bearing on this ADR |
|---|---|---|
| **OpenCTI rules engine** ([docs](https://docs.opencti.io/latest/administration/reasoning/), [inferences](https://docs.opencti.io/latest/usage/inferences/)) | 23 predefined inference rules (attribution propagation, usage-via-attribution, target propagation, location propagation …), **all disabled by default**; inferred edges drawn as "dotted lines of a different color" with a wand icon; deactivating a rule **deletes everything it created**. | Decision 6 (render the label) is exactly OpenCTI's practice — confirmed. The default-off stance differs from S4/S5 being on, but OpenCTI infers platform-wide across every source, while CTIParsor infers inside one report with `x_inference_rule` / `x_inferred_from` provenance and a cap. The reversibility rule is worth stating explicitly: a policy edit must be followed by `re_run_final_stages`, which already rebuilds Stages 4–5 from stored entities, so no inferred edge outlives the rule that made it. |
| **OpenCTI issue #174** ([link](https://github.com/OpenCTI-Platform/opencti/issues/174)) | `UsageTargetsRule` inferred "Incident uses Malware X + Malware X targets Org Y ⟹ Incident targets Org Y", filed as a bug and fixed in 1.1.1. | `_TRANSITIVE_RULES` contains the same shape: `("uses", "exploits") → "targets"` (actor uses malware, malware exploits CVE ⟹ actor targets CVE). `rel_is_suggested` lets it through because `threat-actor —targets→ vulnerability` is a suggested pair. **Amendment:** this composition is demoted to opt-in (`completion.transitive_targets: false`); `uses∘uses`, `attributed-to∘attributed-to` and the `variant-of` family stay on. |
| **GRID** (Huang et al., 2026, [arXiv 2605.16714](https://arxiv.org/pdf/2605.16714)) | "Text-provable truth": forbids external completion and "subject-changing chain deduction"; a **connectivity recheck removes unsupported isolated entities instead of hallucinating links**; reaches CTINexus-level F1 (68.5 % vs 68.7 %) at ~40 % of its token cost. | The opposite bias to this ADR, and deliberately so: GRID builds a graph for reasoning, CTIParsor builds a STIX bundle for a SOC, where an unlinked hash is still a detection. Isolated nodes stay. GRID's ban on chain deduction is the strongest external argument that S5 edges must never auto-promote and must stay capped low per node — which decisions 2 and 4 already require. Its hallucination taxonomy (relation / object / subject illusion) is a better rubric for the `-b grounding` harness than a single rate; noted for ADR-0024 Phase C. |
| **AZERG** (Kucsván et al., 2025, [arXiv 2507.16576](https://arxiv.org/abs/2507.16576)) | Relationship extraction as two tasks: T3 "is this pair related" constrained by the **STIX relationship matrix** (95.5 % F1), then T4 verb classification with explicit "not related" and **"not sure"** options (84.6 % F1); both require a passage where both entities co-occur; human verification after each task. | The co-mention candidate pool plus `rel_is_suggested` is T3 in the same shape. The "not sure" option is the `gap` label: they keep it as a class rather than dropping the pair — direct support for decision 2. Their T3/T4 split also argues for measuring endpoint resolution (decision 3) separately from verb choice. |
| **txt2stix** ([repo](https://github.com/muchdogesec/txt2stix), [guide](https://www.dogesec.com/blog/txt2stix_quickstart_guide/)) | `--relationship_mode standard` = every extraction linked to the Report only (hub-and-spoke); `ai` = "rich relationships" from the provider, no evidence gate documented. | CTIParsor's Report `object_refs` already gives the hub-and-spoke baseline for free; its `ai`-mode equivalent is Stage 3 *with* the ADR-0009 quote gate. Nothing to adopt; confirms the gate is the differentiator, not the density. |
| **ANCHOR / schema-agnostic KG** (Kim et al., 2026, [arXiv 2606.01208](https://arxiv.org/pdf/2606.01208)) | Confidence-thresholded typing that **defaults unverified items to a generic class** rather than dropping them; built for local LLMs because enterprise APIs "conflict with privacy constraints". | Same doctrine as the `related-to` downgrade and the `gap` label: keep, weaken, never invent. Supports decision 5 (completion on the local station). |
| **Admiralty codes in STIX** ([dogesec](https://www.dogesec.com/blog/representing_admiralty_codes_in_stix/)) | Argues against vendor `x_` properties for evidence grading; recommends marking-definitions plus an extension-definition so consumers can filter interoperably. | Out of scope here but real: `x_evidence_label`, `x_inference_rule`, `x_policy_rule` are exactly the pattern criticised. Candidate for a later ADR — an `extension-definition` carrying the ADR-0009 vocabulary, with `confidence` derived from it. |

**Net effect:** decisions 1, 2, 5 and 6 are confirmed by independent practice; decision 4 gains the `transitive_targets` opt-in and an explicit reversibility rule; option H (KG embedding link prediction) stays rejected — none of the 2025–2026 systems reviewed use it, all ground to text.
