# Changelog

All notable changes to CTIParsor are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/); this project is pre-1.0 so
sections group by theme rather than strict semver.

## [Unreleased]

### Added
- **Filtered, multi-format rule export** (ADR-0020) — the export ZIPped every rule
  matching the report's techniques, and was written when the store held 11,396
  Sigma rules. At 86,183 rules across three formats it was broken three ways:
  a real report produced **10,372 rules / 224 MB** (another **18,196 / 268 MB**);
  **8,380 of those 10,372 were Suricata rules written with a `.yml` extension**,
  which no tool loads; and 1,290–1,642 rules carried licence `none`
  (all-rights-reserved) with no way to leave them out.
  Export now accepts `format`, `corpus`, `license` and `severity` — repeatable,
  combining with AND, applied to the technique-selected set so ADR-0008's coverage
  semantics are untouched. Files land as `rules/{format}/…` with the extension the
  format requires (`.yml` / `.rules` / `.yar`), and the archive drops `_sigma_`
  from its name. `MANIFEST.json` records both the filters requested and the
  per-axis counts **excluded**, so an export that omitted 1,642 rules is
  distinguishable from one where they never matched.
  A new `GET /jobs/{id}/detections/export/facets` reports each axis with rule
  counts and byte size, so the operator sees the volume and licence split *before*
  downloading — which is why no silent cap was added; truncating a detection
  package without saying so is worse than a large one.
  This makes ADR-0006's stance actionable: licence was always "carried, not
  enforced — the operator decides", but the operator had no mechanism to decide.
  Measured end-to-end: "Sigma only, redistributable licences, high severity"
  returns **324 rules / 0.30 MB**, with zero all-rights-reserved files.
  Known limitation, documented rather than hidden: facets take **12.4 s** because
  byte totals need `LENGTH(raw)` over 219 MB of overflow-page text. An earlier
  per-axis SQL version measured **43 s** — 2.4× worse, since each axis re-read the
  same bodies — and the fix (a `raw_bytes` column written at ingest) is scoped out.
  YARA still cannot be exported at all: selection is technique-based and YARA
  carries 0 techniques across all 16,314 canonical rules.

- **Suricata and YARA adapters — the formats now actually ingest** (completes
  ADR-0015 §1). ADR-0015 shipped the atom extractors, the store schema and the
  corpora registry, but never the `RuleCorpusAdapter` implementations, so
  `_ADAPTERS` held only Sigma and both formats reported `adapter unavailable`.
  `pipeline/detection/suricata.py` and `pipeline/detection/yara.py` close that.
  Measured on the real corpora: **86,183 rules ingested (75,127 canonical,
  363,166 atoms)** against 11,396 before — ET Open 51,799, Yara-Rules 12,258,
  signature-base 5,889, elastic-artifacts 2,877, rl-yara 1,240, tbg-hunting 682,
  inquest-yara 39. Severity is mapped from ET's own `signature_severity`
  distribution and `sid` is the native key (all 51,799 verified distinct).
  Four defects were found by reading the output rather than by tests:
  **(1)** the YARA rule regex required the opening brace on the `rule` line, but
  brace-on-next-line outnumbers it **7:1** (10,720 vs 1,492) — `peid.yar` alone
  holds 7,615 rules and yielded zero, and `inquest-yara` yielded zero entirely;
  **(2)** the Suricata `dedup_key` hashed only the option body, so the 854
  `ET TOR Known Tor Exit Node Traffic` rules — which differ *only* in their header
  address list — collapsed into one cluster, and ADR-0017 would have demoted 853
  of them, discarding thousands of exit-node addresses. The header is detection
  logic, and is now hashed with the options;
  **(3)** bracketed header address lists were skipped as "not a literal", which
  threw away precisely the C2 addresses the atom index exists to match — atoms
  rose 47,117 → 72,632 once unpacked;
  **(4)** `meta.id` was the YARA native key, but YARA has no uniqueness rule for
  it and signature-base reuses it across families (the eleven distinct
  `APT30_Sample_10..19` share one id, in 57 such groups) — they collided on
  `detection_rules.id` where `INSERT OR REPLACE` would have silently dropped them.
  YARA `private` rules are skipped: a private rule is a helper predicate that
  cannot fire alone, so counting it would overstate coverage.

- **Multi-format corpus management in Settings** (ADR-0019) — the panel was
  Sigma-only in three places at once: the API hardcoded
  `if body.adapter != "sigma"`, the heading read *"Detection Corpora (Sigma)"*,
  and the add form collected **name, git, license** and nothing else. That form
  could not express what the registry already supports, which blocked the corpora
  committed in ADR-0015: `subdir` (3 of the 5 YARA repos keep rules under
  `yara/`), `tarball` (ET Open is published only as a tarball, and is 70% of all
  Suricata rules), and `priority` (dedup authority).
  It also closes a trap of my own making: ADR-0015 committed seven corpora as
  `enabled: false`, and **there was no way to enable them** — `Remove` writes a
  *disable override*, with no route back short of hand-editing
  `detection_corpora.local.yaml`. `PATCH /api/settings/corpora/{name}` now
  toggles `enabled`, verified to round-trip through `load_corpora()` so the
  toggle actually changes what gets ingested.
  New `GET /api/settings/formats` reports each format with `available` derived
  from the adapter registry, so the UI never hardcodes a format list and lights
  up on its own when an adapter ships. **Configuring and ingesting are separate
  gates**: a repo may be configured for any of sigma/suricata/yara, while
  `available` reflects whether a parser is compiled in. Gating creation on the
  registry alone would have refused to create the very corpora the committed
  registry already holds. Corpora whose adapter is missing are badged
  `adapter unavailable` and the create response carries an explicit `warning`,
  so the operator learns at creation time rather than after a Rebuild returns
  zero rules.
  The table now groups by format with per-format repo and rule counts.
  Today that reads: **sigma available (8 repos, 11,396 rules), suricata and yara
  unavailable (2 and 5 repos, 0 rules)** — which is the truth, displayed.

### Changed
- **The detection-proposal ranking no longer collapses into one score** (ADR-0018).
  ADR-0014's technique term was a flat `TECH_EXACT = 0.30`, so a report's 34–48
  techniques tagged ~1,400 rules that all scored *identically*. **99.7% of
  proposals were tied**, and since `rank_rules` sorts by `(-score, corpus, title)`,
  everything past the handful of evidence-backed hits was ordered alphabetically —
  "7Zip Compressing Dump Files", "ADFS Database Named Pipe", "APT29".
  The term is now weighted by the technique's **IDF** — the same argument that
  already makes atom IDF work, applied to the axis it was never applied to. Being
  tagged `T1059` says little when 358 rules carry it; a technique carried by a
  handful says a lot. A `1/sqrt(n)` breadth damping then separates rules tagged
  with one technique from rules tagged with eight.

  | | Distinct scores | Largest tie |
  |---|---|---|
  | ShinyHunters | 6 → **284** | 1,469 → **107** |
  | GREYVIBE | 4 → **296** | 1,336 → **95** |

  The improvement is qualitative too: for a Linux PeopleSoft intrusion the list
  now surfaces `Chmod Targeting Sensitive Directories`, `Remove Immutable File
  Attribute` and `File or Folder Permissions Change` behind the MeshAgent hits.
  An earlier formula that ranked by rule *quality* (breadth × corpus authority)
  was simulated and rejected — it barely dented the tie and put `Screen Capture -
  macOS` and `Too Many Global Admins` at the top of a Linux report.
  Evidence-backed proposals still occupy the top of the list; latency is +1.7%.
  Absolute scores shift downward (technique-only hits now ~0.20–0.26 rather than
  0.300), so any saved threshold is stale.
  Requires the ADR-0017 dedup: a technique's document frequency is meaningless
  against a store that counts the same rule twice.

### Fixed
- **A redacted IoC placeholder could fail an entire ingestion job.** Stage 2 called
  `urlparse()` on report-derived text; since Python 3.11 `urlsplit` validates a
  bracketed netloc as an IPv6 literal via `ipaddress.ip_address()`, so any URL
  whose host is bracketed but not a valid address raises `ValueError`. A real
  Mandiant report contained `http://[actor-controlled-ip]/…` — a redaction
  placeholder — and the unguarded call killed the job at stage 2. The report was
  otherwise fully processable: after the fix it yields **83 entities and 35
  relationships**, where it previously produced nothing.
  Brackets are routine in this corpus (defanging, redaction), so the failure is
  recurring rather than exotic. Hostname extraction moves to `_url_host()`, which
  falls back to a lexical split and keeps a valid IPv6 literal intact — stripping
  brackets then splitting on `:` turned `[2001:db8::1]:8080` into `2001`.
  Found by ingesting a 15-report corpus of public vendor reporting; two reports
  were never going to surface it.
- **Cross-corpus dedup was folding 11 rules out of 11,396** (ADR-0017). ADR-0010
  clusters on `dedup_key`, a hash of the normalised detection logic, and the
  registry claimed hayabusa's converted SigmaHQ copies folded under sigmahq. They
  did not: hayabusa shared **exactly one** `dedup_key` with sigmahq, because its
  conversion injects a `Channel`/`EventID` selection, wraps the condition around
  it, and renames `Image` to `NewProcessName` for the Security-4688 variant. Same
  detection, different hash.
  Rules are now also clustered on **declared provenance** — the Sigma `related:`
  block — via union-find, so derivation chains collapse. 4,758 of hayabusa's
  4,759 rules declare a `related:` id present in sigmahq, so the signal is
  near-total where the hash was useless. Only `derived` and `renamed` fold:
  `similar` means same idea but *different* logic (SigmaHQ's own MeshAgent
  Windows and MacOS rules declare each other `similar`), and `obsolete` runs the
  other way.
  Canonical rules drop **11,385 → 6,349**, hayabusa **4,758 → 5**, and the top-20
  on both stored reports goes from four duplicate-title slots to zero.
  The canonical rule now also inherits the **union of its cluster's ATT&CK
  techniques** — added after validation showed the first version losing two
  techniques, because SigmaHQ's "Double Extension" derivatives carry `T1036.007`
  while the parent they derive from does not. With the union propagated, coverage
  rises 885 → 887 techniques instead of falling.
  This also corrects ADR-0014's IDF denominator, which had been computed against
  a store roughly 44% redundant — an error ADR-0015 would have carried into a
  7.5× larger store.
  The pre-existing dedup test passed throughout, because its fixture made the
  "converted" rule byte-identical to its source — a conversion that never occurs
  upstream. It now asserts the fixture's own limitation, and a second test models
  the real conversion and fails if provenance folding is removed.

### Added
- **Report-derived Sigma rule synthesis** (ADR-0016) — ADR-0014 ranks rules that
  already exist; on a real 41-observable intrusion it found **2** `direct`-tier
  proposals, meaning the campaign's hashes, binaries and C2 addresses were in no
  corpus rule at all. `pipeline/detection/synth_sigma.py` closes that gap: it
  turns a report's observables into draft Sigma, grouped **one rule per telemetry
  type** (`dns_query`, `proxy_url`, `network_connection`, `process_hash`,
  `process_image`, `file_event`, `registry_set`) rather than one rule per
  observable, so a 41-observable report yields 4 reviewable rules instead of 41.
  Deterministic throughout — UUIDv5 rule ids over `(job_id, kind)` and an explicit
  `date` — so re-running a report reproduces byte-identical rules.
  Observables are gated before they may key a rule: values already carried by a
  canonical corpus rule are skipped (ADR-0014 will propose that rule instead), and
  `domain` values must pass the ADR-0015 hostname test — which on a real report
  rejects `agent.ashx`, `exfil.tar.zst` and `psemhub.war`, three filenames that
  upstream extraction had labelled as domains.
  Three further defects were found only by reading the generated rules, not by
  the tests: the report's entire technique list was being stamped on every rule
  (a `file_event` rule tagged with 34 techniques, including an ICS one), so tags
  are now one well-founded tactic per kind and none where the tactic is not
  determinable; `/etc/hosts` was being rendered as the Windows pattern `\hosts`,
  so path separators are now derived from the value's shape rather than assumed;
  and `/usr/bin:/bin`, a `$PATH` fragment, was producing a file rule. Every rule
  carries `status: experimental`, the source report, and the observables behind
  it — nothing is written to the corpus store, which stays a record of *ingested*
  rules only.

- **Multi-format detection matching — atom extractors** (ADR-0015, in progress) —
  groundwork for ranking a report against Suricata and YARA corpora, not Sigma
  alone. The store has always been format-agnostic on paper (`format` column,
  `RuleCorpusAdapter` seam) and single-format in practice: **11 396 rules, 100 %
  `sigma`**. Landed so far:
  **(1)** `pipeline/detection/suricata_atoms.py` — parses Snort/Suricata syntax
  (sticky buffers *and* legacy content modifiers, which are disambiguated by
  position since the two vocabularies overlap), yielding `domain`/`url`/`ip`/
  `port`/`hash`/`strlit` atoms. Validated on ET Open 7.0.3: **51 799 active rules
  → 45 682 atoms at 12 700 rules/s**;
  **(2)** `pipeline/detection/yara_atoms.py` — brace-balanced rule splitter plus
  meta/strings parser. Metadata hashes are extracted first as the highest-value
  atoms a YARA rule carries (**8 932 distinct hashes** across the corpora), and
  hex/regex strings are deliberately *not* indexed — a report never carries a byte
  pattern as an observable. Validated on 10 668 rules from five corpora;
  **(3)** `pipeline/detection/tlds.py` — one shared "is this a hostname" test.
  An allowlist, not the generic shape used for IoC extraction: an atom index needs
  precision where extraction needs recall, and the generic shape admitted ActiveX
  ProgIDs (`aventail.epinstaller`) and `kernel32.dll` as domains. Because such
  values are rare they earn *high* IDF and score near 1.0 — the ADR-0014 failure
  mode of confident nonsense at the top of the list.
  Registry entries for seven new corpora (five YARA, two Suricata) are committed
  **disabled** pending the adapters, with every licence verified from the repo.
  `Neo23x0/signature-base` is DRL-1.1 — the same licence as SigmaHQ, not the
  CC BY-NC it is widely reported to be. `ptresearch/AttackDetection` is excluded:
  proprietary Positive Technologies EULA, sanctioned entity.

- **Observable-driven detection proposals** (ADR-0014) — the Review "Detections"
  tab ranked rules by ATT&CK tag alone, which on a real Linux/WebLogic intrusion
  proposed **2 688 rules**, its two largest buckets being 760 PowerShell rules and
  500 generic `T1059` rules. Nothing in the selection knew the report mentioned
  `meshagent64-azure-ops.exe`, `azurenetfiles.net`, `_fanout.sh` or `/etc/hosts`,
  or that the intrusion was not on Windows. Three parts:
  **(1)** each Sigma rule's `detection:` block is now reduced to normalized
  **atoms** — the literal values it looks for, keyed by field class (`image`,
  `cmdline`, `file`, `registry`, `hash`, `domain`, `ip`, `url`, `pipe`, `service`,
  `port`, `user`) — stored in a new `rule_atoms` table, alongside a `platform`
  column derived from `logsource` (`pipeline/detection/atoms.py`);
  **(2)** a report's entities are normalized into the same vocabulary, with URLs
  expanded to their host, executable paths to path *and* basename, and defanged
  IoCs refanged, plus an inferred report platform
  (`pipeline/detection/observables.py`);
  **(3)** rules are scored on IDF-weighted observable overlap + a technique term
  + a platform factor, and tiered `direct` / `behavioural` / `weak`
  (`pipeline/detection/relevance.py`). IDF is what makes it work without a
  stoplist: a match on `cmd.exe` scores ~0, a match on a campaign-specific binary
  scores ~1. Every proposal carries the evidence behind its rank — which
  observable matched which rule field — so the ranking is auditable.
  Scoring is deterministic and offline (no model, honouring ADR-0008's constraint
  on the detection artifact). New endpoint
  `GET /api/jobs/{id}/detections/proposals`; the unranked
  `GET /api/jobs/{id}/coverage/rules` is unchanged. Coverage's 0–3 readiness
  score (ADR-0008) is untouched — readiness and relevance are separate questions.
- **`scripts/build_rule_atoms.py`** — backfills the atom index from the stored
  rule bodies, so a store built before ADR-0014 gains observable ranking without
  re-cloning several gigabytes of Sigma corpora.
- **Untagged rules are reachable** — 1 049 of the 11 396 rules in the default
  corpora carry no `attack.tXXXX` tag and were invisible to a tag-keyed join.
  They now surface when one of their atoms matches a report observable.

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
- **Runaway TTP counts on reports with no explicit T-IDs** — a 12-page report
  produced 65 TTP rows in the review UI against 51 attack-patterns in its bundle.
  Four compounding defects, each fixed and pinned by tests
  (`tests/test_ttp_volume_controls.py`):
  **(1)** `_save_entities` persisted the Stage 2c row *and* the Stage 3c-normalized
  LLM row for the same technique, so the UI double-counted every technique both
  stages found — it now skips a raw TTP the normalized set already covers, making
  the UI count match the bundle; **(2)** the same path reintroduced a parent
  technique next to its sub-technique when the two came from different stages
  (`T1027` beside `T1027.004`) — parents of a present sub-technique are now
  subsumed across sources; **(3)** Stage 3f's "already corroborated, skip
  verification" exemption ignored confidence despite its docstring promising
  *high*-confidence — every medium semantic match (≥ 0.48, the nearest-but-wrong
  tier the Phase A margin gate suppresses) was waiving quote-verification for its
  LLM twin. On the sample report 13 of 16 corroborators sat below the 0.62
  cut-point, waving through techniques with zero textual support (`T0873`
  "Project File Infection" at 0.52, in a report containing no ICS content).
  Extracted as `stage3_llm.corroborated_ttp_ids()` and floored at the model's
  high threshold; **(4)** CAPEC is ~40% of the embedding corpus (615/1533) and
  shadowed the ATT&CK technique that belonged in the bundle — the semantic corpus
  is now ATT&CK-only by default (`TTP_SEMANTIC_DOMAINS`, set to `all` to restore
  CAPEC), which also makes the *correct* technique surface instead
  (`CAPEC-648 Collect Data from Screen Capture` → `T1113 Screen Capture`).
  `ENABLE_TTP_VERIFICATION` now defaults to `true` in `.env.example`.
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
