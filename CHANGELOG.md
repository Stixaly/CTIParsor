# Changelog

All notable changes to CTIParsor are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/); this project is pre-1.0 so
sections group by theme rather than strict semver.

## [Unreleased]

### Added
- **STIX graph completion** (ADR-0012) — a Stage 4b/4c layer that enriches edges
  *after* the Stage 3d/3f precision gate instead of loosening it, so the base graph
  is untouched and every added edge is independently justified. Four engines, all
  guarded by `rel_is_suggested` (a composed verb that is not a *suggested* STIX 2.1
  relationship for the type pair is **skipped, not downgraded**):
  **(1)** alias merge — collapse same-object SDOs and rewire their edges onto one
  node, with an IOC guard that never merges look-alike CVEs/hashes/IPs (optional
  `fuzzy_alias` rapidfuzz and `semantic_alias` embedding matching at cosine ≥ 0.6);
  **(2)** ATT&CK reference grounding — `build_indexes.py --only relationships` distils
  the ATT&CK bundles into `pipeline/data/attack_relationships.json` (20 015 curated
  G/S/T triples); curated edges are added when both endpoints resolve to ATT&CK IDs
  and labelled `reported`, not `inferred`; **(3)** transitive inference over a fixed
  composition table; **(4)** Stage 4c long-distance prediction (opt-in) — connects
  disconnected sub-graphs via degree-centrality central/topic nodes, requiring the
  LLM to quote a supporting sentence (Stage 3d's evidence bar) stored as
  `x_evidence_text`. Inferred edges carry `x_inference_rule` + `x_inferred_from`
  (premise ids). New: `pipeline/stage4b_graph_completion.py`,
  `pipeline/stage4c_long_distance.py`, `tests/test_stage4b_completion.py`,
  `tests/test_stage4c_long_distance.py`.
- **Graph-completion benchmark** (`eval_pipeline.py --benchmark rel`) — edge-level
  per-engine precision/recall/F1 against gold accept/reject judgments, with built-in
  fixtures and a documented dataset format for human-annotated reports. Makes the
  "no accuracy loss" claim measurable rather than asserted.
- **TTP extraction precision** (ADR-0011) — four layers raising MITRE technique
  precision: **(A)** model-aware Stage 2c cosine thresholds (per-model defaults →
  embedding manifest → `TTP_HIGH_THRESHOLD`/`TTP_MEDIUM_THRESHOLD` env), one match
  per sentence with a `TTP_TOP2_MARGIN` gate, and Stage 3c no longer letting a
  *medium*-confidence semantic match override the LLM; **(B)** Stage 3f TTP
  self-verification (`ENABLE_TTP_VERIFICATION`) — a second LLM pass must quote the
  sentence describing each technique's use, semantic-corroborated TTPs skipped;
  **(C)** parent/sub-technique subsumption + a technique→tactic lookup feeding the
  3f prompt; **(D)** ATE benchmark `--stage full` (regex + semantic + LLM + Stage 3c
  normalize) and adversarial precision fixtures. New: `pipeline/stage3f_ttp_verify.py`,
  `tests/test_ttp_precision.py`.
- **Default Sigma corpora + cross-corpus dedup** (ADR-0010) — the committed registry
  now ships 8 public Sigma repos (SigmaHQ, DFIR-Report, tsale, P4T12ICK,
  RussianPanda95, linkedin, mthcht, Yamato hayabusa) with verified licenses,
  per-corpus `priority`, and `subdir` scoping. A global `dedupe_store` pass folds
  rules that share normalized detection logic into one canonical (by priority),
  losslessly (provenance kept as `also_in`), so a copied rule never inflates the
  coverage score. Registry columns: `detection_rules.dedup_key`, `is_canonical`.
- **Detection coverage matrix** (ADR-0008) — per-report ATT&CK techniques scored
  0–3 for *detection readiness* (not lab validation), in a tactic-column matrix at
  `/coverage/:jobId`.
- **Multi-corpus Sigma ingestion** (ADR-0006) — pluggable `RuleCorpusAdapter`,
  `SigmaAdapter`, a two-tier registry (committed public `detection_corpora.yaml` +
  gitignored private `detection_corpora.local.yaml`), a SQLite rule store, and a
  fork-safe corroboration score. Scripts: `sync_corpora.py`, `build_detection_index.py`.
- **In-app Settings panel** (ADR-0007 Slice 1) — list/add/remove corpora and rebuild
  the rule index from the UI (`/settings`).
- **Evidence labels** (ADR-0009) — every relationship carries `observed` / `reported`
  / `assessed` / `inferred` / `gap`, persisted, exposed on the API, emitted as
  `x_evidence_label` in STIX, and gating the review auto-accept.
- **Cross-model consensus** (ADR-0009, opt-in `ENABLE_CONSENSUS`) — re-runs
  relationship-bearing chunks through a second provider; agreement boosts confidence,
  single-model claims are downgraded.
- **STIX provenance & sharing markings** (ADR-0009) — every object stamped with a
  TLP (and optional PAP) marking and an authoring `Identity` (`created_by_ref`).
  Config: `STIX_TLP`, `STIX_AUTHOR_NAME`; per-job `tlp_level` / `pap_level`.
- **Docs** — `SECURITY.md`, `TESTING.md`, `CONTRIBUTING.md`, an ADR index, and ADRs
  0002–0011.

### Changed
- The relationship policy gained an optional `completion` block
  (`alias` / `reference` / `transitive` / `long_distance` / `fuzzy_alias` /
  `semantic_alias` / `max_new_edges`) — the "let the tool decide" switch for graph
  completion. A `"pin"` rule still always wins, so inference never contradicts an
  explicit analyst choice.
- `build_stix_bundle()` gained `long_distance_infer=`; the API worker supplies it
  via `stage4c_long_distance.default_long_distance_inferer(policy)`, which returns
  `None` unless the policy enables long-distance *and* the LLM provider is ready —
  keeping STIX mapping network-free by default.
- New API routes: `/api/jobs/{id}/coverage`, `/api/detection-corpora`,
  `/api/settings/corpora*`.
- DB schema: `relationships.evidence_label`, `jobs.tlp_level` / `pap_level`,
  and `detection_rules` / `rule_techniques` tables (auto-migrated).
- New dependency: `PyYAML`.

### Security
- Documented the security model (`SECURITY.md`): prompt-injection handling, the
  localhost/CORS posture, secrets/data-at-rest, and the deliberate deferral of the
  LLM-keys settings panel until its security work lands.

---

Earlier history predates this changelog; see `git log` and `docs/adr/`.
