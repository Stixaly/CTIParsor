# Changelog

All notable changes to CTIParsor are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/); this project is pre-1.0 so
sections group by theme rather than strict semver.

## [Unreleased]

### Changed
- **Unified ATT&CK entities under a single `ttp` type** — the extractors no longer
  emit separate `technique` / `tactic` / `procedure` types; all ATT&CK entities are
  now `ttp`, which maps to the STIX 2.1 `attack-pattern` SDO (the only spec object
  for this concept — "technique"/"tactic" are not STIX object types). The
  tactic/technique distinction is preserved losslessly in each entity's `mitre_id`
  (TA#### vs T####), which Stage 4 still uses for ATT&CK URL routing. The review's
  type picker now offers only "TTP" for ATT&CK. Legacy `technique`/`tactic`/
  `procedure` rows in existing databases still render and still map to
  attack-pattern (kept for backward compatibility). Bundle output is unchanged —
  it already emitted only `attack-pattern`.

### Fixed
- **Wrapped hashes now extracted** — MD5/SHA1/SHA256 values that a PDF wraps
  across 1, 2 or 3 lines inside a narrow IOC-table cell were silently dropped
  (the strict contiguous-hex regex couldn't span the newlines). Stage 2 now
  de-wraps hex blocks and accepts them when the joined length is exactly
  32/40/64, while a strict fallback keeps stacked full hashes intact and avoids
  inventing hashes from unrelated hex. Recovered 5 SHA-256 IOCs on the
  ShinyHunters/PeopleSoft report that previously extracted none.
- **Wrapped hashes now highlight & locate in the document** — because the stored
  hash is de-wrapped (contiguous) but the source still has it split across lines,
  the review couldn't find it verbatim ("not found in document text") and drew no
  highlight. `buildRanges` now matches hash values with whitespace tolerance, so
  the wrapped occurrence is highlighted and click-to-locate works across the Text,
  Source and PDF views.
- **Bare filenames now extracted** — path-less filenames with an executable /
  script / installer extension (`payload.exe`, `_fanout.sh`, `meshctrl.js`) are
  extracted as `file` entities. Previously only path-embedded filenames were
  captured; the extension allow-list keeps prose (`report.pdf`, `chart.png`) out.

### Added
- **STIX graph completion** (ADR-0013) — a Stage 4b/4c layer that enriches edges
  *after* the Stage 3d/3f precision gate instead of loosening it, so the base graph
  is untouched and every added edge is independently justified. Engines, all guarded
  by `rel_is_suggested` (a composed verb that is not a *suggested* STIX 2.1
  relationship for the type pair is **skipped, not downgraded**):
  **(1)** ATT&CK reference grounding — `build_indexes.py --only relationships` distils
  the ATT&CK bundles into `pipeline/data/attack_relationships.json` (20 015 curated
  G/S/T triples); curated edges are added when both endpoints resolve to ATT&CK IDs
  and labelled `reported`, not `inferred`; **(2)** transitive inference over a fixed
  composition table; **(3)** an alias-merge *fallback* (default **off** — ADR-0012's
  `pipeline/aliases.py` already canonicalises MITRE-known aliases at SDO-creation
  time, so this only covers names absent from the gazetteer, with opt-in
  `fuzzy_alias` / `semantic_alias` matchers); **(4)** Stage 4c long-distance
  prediction (opt-in) — connects disconnected sub-graphs via degree-centrality
  central/topic nodes, requiring the LLM to quote a supporting sentence (Stage 3d's
  evidence bar) stored as `x_evidence_text`. Inferred edges carry `x_inference_rule`
  + `x_inferred_from` (premise ids). New: `pipeline/stage4b_graph_completion.py`,
  `pipeline/stage4c_long_distance.py`, `tests/test_stage4b_completion.py`,
  `tests/test_stage4c_long_distance.py`.
- **Graph-completion benchmark** (`eval_pipeline.py --benchmark rel`) — edge-level
  per-engine precision/recall/F1 against gold accept/reject judgments, with built-in
  fixtures and a documented dataset format for human-annotated reports. Complements
  `-b grounding` (ADR-0012): grounding measures hallucination in *extracted* output,
  `rel` measures precision of *completion-added* edges.
- **Inline source view for all formats** — the Review page's *Source* tab now
  renders the original upload inline for every supported format, not just PDF:
  HTML/HTM in a fully-sandboxed iframe (scripts disabled), and TXT/MD as raw
  source text with the same entity highlights the Text view uses. DOCX keeps a
  download fallback (no browser-native rendering). New:
  `frontend/src/components/SourceViewer.tsx`, `frontend/src/components/sourceKind.ts`.
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
- **Stage 2d NER model → CyNER 2.0 (DeBERTa-v3)** — replaces the removed
  `aiforsec/cyner-xlm-roberta-base` with `PranavaKailash/CyNER-2.0-DeBERTa-v3-base`
  (public, F1 91.88%), re-enabled by default (`CYNER_ENABLED=true`). The new model
  exposes a dedicated `Threat_group` label distinct from `Organization`, so
  threat-actor detection no longer relies on the `_ORG_BLOCKLIST` heuristic (kept
  as a safety net). New dependency: `sentencepiece` (DeBERTa-v2 tokenizer). `setup.sh`
  gains a CyNER pre-download step and clears the stale `.cyner_model_unavailable`
  sentinel. New: `tests/test_stage2d_cyner.py` (mapping + parsing, no model download).
- The relationship policy gained an optional `completion` block
  (`transitive` / `reference` / `alias` / `long_distance` / `fuzzy_alias` /
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
