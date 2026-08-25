# Changelog

All notable changes to CTIParsor are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/); this project is pre-1.0 so
sections group by theme rather than strict semver.

## [Unreleased]

### Fixed
- **Stage 2c's evidence was being thrown away at the merge.** The semantic
  matcher *selects* a sentence from the report, so its evidence is verbatim by
  construction — measured **120/120 locatable**, against 109/280 for the LLM's
  written descriptions. But Stage 2c stored that sentence in `description`, and
  `normalize_ttps` then picked between the two by **length**:

  ```python
  if len(result_ttp.description) > len(existing.description):
      # the LLM's description replaces the semantic evidence sentence
  ```

  A quote and a summary compared by length in one field — the ADR-0028 defect
  one stage earlier. The two now live in separate fields and merge on separate
  rules: the description by length, the evidence by provenance.

  A second distinction the code did not make: the 0.62 cosine floor answers
  *"may this match create a technique?"* — it does **not** answer *"may it supply
  the sentence for a technique the LLM independently found?"* In that
  corroboration case two signals agree on the id and the LLM already vouched for
  it, so the semantic sentence is the better citation at any confidence.
  Restricting evidence to the high floor left the first fix inert (only 16 of
  120 matches clear 0.62): 38.9% → 39.3%. Lifting it for corroboration only:
  **38.9% → 43.9%** across the four reports, 43.6% → 50.4% on APT44 — **without
  re-running the LLM**. That is a floor, not a ceiling: it measures old stored
  TTPs that carry no `evidence_text` of their own.

  Agreement between the two extractors is large — 116 of 120 semantic techniques
  are also found by the LLM, which contributes 164 more — so the semantic stage
  is not a second opinion on *what* is present, it is a source of *evidence* for
  what the LLM already found.
- **Two response ceilings silently discarded whole LLM chunks.** Found on the
  first real call under the ADR-0028 contract, invisible to every unit test.
  `max_tokens` was hard-coded to 4096 at both provider call sites: the reply was
  cut mid-object at 14,812 characters and **TTPs, relationships and malware
  families were all lost**, not just the truncated tail. Raising it exposed the
  second guard — `_MAX_RESPONSE_LENGTH` at 16,000 characters, which *truncates
  the string*, so a complete and valid 23,324-character reply became invalid
  JSON. Now `_MAX_OUTPUT_TOKENS` (8192, `LLM_MAX_OUTPUT_TOKENS`) and 48,000
  characters, coupled in a comment: the character cap must stay above the token
  ceiling times ~4 or it silently undoes it.
- **344 orphan `course-of-action` objects.** Measured across the four stored
  bundles: 10.4% of every bundle — the third most numerous object type — and
  **not one carried a single relationship**. A STIX consumer received them as
  free-floating nodes. The default relationship model now declares the four
  `mitigates` pairs STIX 2.1 Appendix B allows, deliberately on **Auto**: a
  pinned rule is a Cartesian product and `course-of-action` is unanchorable
  (0/344 locatable), so the ADR-0027 gate cannot filter it — pinning would add
  12,768 candidate pairs on CERT Polska and 18,408 on APT44.

### Added
- **TTPs must quote, not describe** (ADR-0028) — what the pipeline read as
  evidence for a technique was a **`description`**, and the prompt asked for
  exactly that. `TTPExtracted` had no evidence field at all, while
  `RelationshipExtracted` twenty lines below already carried `evidence_text`
  ("verbatim quote from source text") and `evidence_label`, and the prompt's
  anti-fabrication rules applied only to relationships.

  Measured over every stored quote with the new locator — same model, same
  reports, same call: relationship quotes locate to a sentence **85.6%** of the
  time (215/277 exact, 22 partial), TTP descriptions **38.9%** (103/280 exact).
  **2.2× apart, from the contract alone.**

  Two hypotheses were tested and discarded first. PDF mangling: rejoining
  end-of-line hyphenation recovered **0** of the 166 failures, the alphanumeric
  skeleton 0.7%, fuzzy matching 3.9%. Invention: of those 166, **99.4% have at
  least half their distinctive tokens present in the report** and 24.7% have all
  of them — the model recomposes real facts, it does not fabricate them. One
  case in 166 falls below half.

  `TTPExtracted` now carries `evidence_text` + `evidence_label` under the same
  rules as relationships; `description` is kept and keeps its job. `entities`
  gains `evidence_text`, `evidence_label` and `evidence_start` (additive
  migration). A quote that cannot be located stores a NULL offset and demotes
  the grade one step — it never drops the technique.
- **`pipeline/evidence_span.py`** — locates a quote in the source text and
  returns a span in *original* coordinates, keeping an index map through
  normalisation of the substitutions PDF extraction introduces (curly quotes,
  en/em dashes, five space characters, five ligatures), with a longest-prefix
  and longest-suffix fallback worth 7.9 points over exact matching alone.
  Ligatures are handled apart from the character map because that map may only
  hold one-to-one substitutions — the offset invariant depends on it.
- **Evidence-gated pin materialisation** (ADR-0027) — a pinned rule now emits an
  edge only when the report links the two objects within three sentences. The
  gate applies **only to types whose identity actually appears in prose**,
  measured over the four stored bundles before any code was written: SCOs,
  `malware`, `tool` and `threat-actor` land at **91–100% verbatim**, while
  `attack-pattern` reaches only **24.3%** (16.8% by ATT&CK `external_id`) and
  `course-of-action` **0/344** — those come from ATT&CK mapping, not from the
  text, so pairs touching them are never gated. That exempts 47% of the
  candidate pool by design, and the ADR says so rather than glossing it.

  A second correction the measurement forced: an Indicator's `name`
  (`"Indicator: evil.com"`) never appears in prose — **0/136** — so its anchor is
  the literals parsed out of its `pattern`, which reach **131/136 (96.3%)**.

  Result over the four bundles: **18,426 → 10,278 candidate pairs, 8,148 blocked
  (44.2%)**, with build latency unchanged (399→310 ms, 457→472 ms) because one
  inverted sentence index is built per bundle instead of scanning the text per
  pair. On the edges actually shipped, `x_pin_evidence` goes from **100%
  `unchecked`** to **32.7% carrying a real textual anchor** (`cosentence` or
  `window:N`), the rest explicitly marked `unanchorable`. ShinyHunters stops
  saturating the ADR-0026 cap entirely — the first time on real data that the
  budget is no longer what decides which edges ship.

  `PinRuleStat.blocked` is reported **separately from `truncated`**: "the budget
  ran out" and "the report does not support this pair" are different verdicts.
  Controlled by `"pin_evidence": {"mode": "cooccurrence"|"cartesian", "window": 3}`;
  `"cartesian"` restores the previous behaviour exactly. The window of 3 is
  reused from ADR-0024 Phase C, the only proximity threshold in this project
  backed by a measurement.
- **Rejected, and recorded as such:** dropping the two `attack-pattern` pin rules
  would remove 8,679 candidate pairs for zero code, but Stage 4b only infers 49
  of the edges the pin rule materialises 200 of — so it would cost analysts the
  "which techniques does this malware use, which does this campaign use" view.
  Coverage of that question outweighs graph tidiness.
- **Per-rule budget for policy pins + `x_synthesis_stats`** (ADR-0026) — the
  `max_pinned_edges` cap ADR-0024 introduced turned out to truncate by the
  **rank of the rule in the policy array**. Measured over the four bundles in
  `cti_stix.db`: the cap was saturated **4 times out of 4** (exactly 200 pinned
  edges each, 800 of 2,023 relationships), and on GREYVIBE the 10th rule
  (`malware uses attack-pattern`, 13 × 39 = 507 candidate pairs) consumed the
  whole budget while the **13 rules after it emitted nothing, silently**.

  The budget is now split by **max-min fair share**: rules are served in
  ascending demand order, each taking at most an equal share of the remainder,
  so a small rule is always satisfied in full and its unspent share flows to the
  larger ones. Replaying all four jobs read-only, rules actually served go from
  **20 to 46** (+26). `pin_budget_mode: "sequential"` restores the old
  behaviour; `max_pinned_edges` and `pin_budget_mode` are now validated at the
  API boundary instead of being coerced silently in Stage 4.

  The Report SDO gains `x_synthesis_stats` — per-rule `candidates / emitted /
  truncated` for the pin pass, plus the `CompletionStats` Stage 4b had been
  **returning and having discarded** at the call site since ADR-0013. The worker
  reads it back off the Report for `emit_progress`, so the live channel consumes
  the same record that ships in the bundle.

  What the measurement also showed, and it is in the ADR: the candidate pool is
  **18,426 pairs for a budget of 200**. Fair share ends the starvation, but at
  ~14 edges per rule it distributes arbitrariness evenly rather than removing
  it — which is the evidence for gating pins on textual co-occurrence next.
- **`scripts/measure_pin_allocation.py`** — read-only harness that replays every
  stored job under both allocation modes and prints the per-rule table, read
  back off the rebuilt bundle's `x_synthesis_stats`.
- **Evidence gate in the Policy UI** — a panel above the rule list showing what
  the last run produced (edges emitted / candidate pairs / cut by budget /
  unevidenced, plus Stage 4b's completion counters), and a per-rule badge
  `emitted / candidates` with a fill bar that turns amber when the rule was
  truncated. A rule absent from the last run shows **nothing** rather than `0` —
  unmeasured and zero are not the same claim.

  The controls are the evidence gate (On/Off) and its window, offered as three
  named steps — Strict 1 / Normal 3 / Wide 10 — because a free number field
  invites typing 50 without realising that switches the gate off in practice.
  **`max_pinned_edges` is deliberately NOT exposed**: an analyst cannot know the
  right total before reading the report, and the number scales with report size
  rather than with anything they can judge. It stays in the policy as a safety
  ceiling. "How close must two things be in the text before I link them?" is
  answerable without knowing how big the report is; "how many edges in total?"
  is not.

  New `GET /api/relationship-policy/last-run` serves it from the newest bundle's
  `x_synthesis_stats`. It parses **exactly one** `bundle_json` by design: at
  ~475 KB–1.3 MB per bundle, scanning back until one carries the property would
  make latency depend on how many old bundles are stored. When the newest bundle
  predates ADR-0026 the answer is `available: false` — measured at **101 ms
  median** warm on the real database, of which **0.7 ms is the JSON parse**; the
  rest is reading the blob off the NTFS mount.

### Fixed
- **Saving the relationship policy wiped its `completion` block.** `PUT
  /api/relationship-policy` is a full replacement, and all four save paths in
  the Policy page sent only `{version, global, rules}` — so every edit silently
  dropped the Stage 4b configuration (ADR-0013) that `complete_graph` still
  reads. The stored policy had no `completion` key at all, despite the API
  documenting it. Saves now spread the last server response, so unknown
  top-level keys survive a round-trip.
- **`max_pinned_edges` was never validated.** It was accepted at any type and
  coerced silently inside Stage 4; it is now rejected at the API boundary
  alongside the new `pin_budget_mode`.

### Added
- **Evidence-keyed detection coverage** (ADR-0025) — coverage stops being indexed
  on ATT&CK techniques and becomes indexed on the report's own technical content.
  The measurement that forced it, over the two real reports in `cti_stix.db`
  (75,127 canonical rules): the technique key selects **25,493 rules of which 4
  match anything in the reports**, and **58 of the 64 cells scored ≥2 have no
  matching rule at all**. `T1071.003` scored 3 on 6,573 rules with zero evidence.

  New `GET /api/jobs/{id}/coverage/artifacts` returns one row per technical
  artifact — hash, IP, domain, URL, file, registry key, tool or malware identity —
  scored 3/2/1/0 on whether canonical rules actually hold that value and from how
  many independent corpora, tiered by **Pyramid of Pain** so a hash match and a
  tool-identity match are never averaged together. Every score above 0 names the
  rule and the field that matched. Measured result: **58 artifacts, 4 covered, 50
  uncovered** — sparse by construction, because a fresh campaign's indicators are
  not in public rule corpora, and the uncovered list is the point.

  ATT&CK is kept as an unscored **phase band** in kill-chain order, with two
  independent rows: what the report claims, and where the rules that actually
  matched an artifact sit. The second is sourced from the matching rule's own
  tags, never from the report's TTP extraction, so the gap between them is a real
  roadmap. On ShinyHunters the report spans 14 phases and detections reach 6.
- **`scripts/measure_ttp_vs_observable_coverage.py`** and
  **`scripts/validate_artifact_coverage.py`** — the before/after harness and the
  real-data validation behind ADR-0025.

### Fixed
- **Malware families scored below system utilities.** Validated against a CERT
  Polska energy-sector report (119 techniques, 22 hashes, 25 tools, 10 malware):
  `Ping` scored 2 and `netstat` 3, while `BlackEnergy` scored **1** despite 28
  dedicated YARA/Suricata rules named after it across three corpora. `tool`
  entities scored 2–3 in 12 of 18 cases; `malware` entities scored 0–1 in 8 of 10.

  Structural cause: a tool's binary name is an atom value inside a rule's
  detection block (exact match, 2–3), while a malware family name lives in the
  rule **title** — which was capped at 1. For a family, the rule named after it
  *is* the detection. Title evidence now corroborates, but only for `malware`
  entities, only on the title (a description mention stays weak), and carrying
  the rule's `native_key` so a forked rule still folds to one owner. Result:
  BlackEnergy 1→3, PrestigeRansomware 1→2, Impacket 2→3, while `Ping` stays 2.
- **One technical element was counted several times.** `nircmd.exe` counted twice
  (file + image) and `pastebin.com` three times (domain + file + image); 16 values
  duplicated on one report, and **13 of 28 "covered" rows were duplicate halves**.
  ADR-0014 had already drawn this lesson for ranking and it was never carried into
  coverage. Artifacts fold on the normalized value, with the score recomputed over
  the unioned evidence rather than taken as a max. 116→97 artifacts on CERT
  Polska, 38→29 on ShinyHunters.
- **`.com` was treated as an executable suffix on the file branch**, so
  `pastebin.com` and `curity.com` became `image` observables — DOS COM
  executables. Same carve-out as the domain guard: a `.com` value that is also a
  well-formed hostname is not an executable.
- **The ATT&CK phase columns were missing two tactics.** `mitre_index.json`
  renames `TA0005` to `stealth` (not `defense-evasion`) and adds `TA0112`
  `defense-impairment`, but the Coverage page hard-coded the classic fourteen —
  so **204 enterprise techniques were silently bucketed as "other"**. Both the
  page and `pipeline/detection/phases.py` now carry fifteen columns, locked by
  `test_every_enterprise_tactic_in_the_index_has_a_column`, which fails if a
  future ATT&CK version adds another.
- **The hostname gate ran on rules but not on reports.** `looks_like_domain`
  (ADR-0015) was applied when extracting atoms from Suricata/YARA rules and never
  when normalising a report, so `agent.ashx`, `exfil.tar.zst` and `psemhub.war`
  became `domain` observables — and a bogus domain is rare by construction, so its
  IDF is ~1.0 and it ranks first with maximum confidence. One real report drops
  from 41 to 38 observables with no genuine domain lost. `onion` joins `GTLDS`:
  on 1,399 domain-shaped Sigma atoms failing only the TLD test, Tor addresses were
  the sole real-domain category among filenames (`.exe` 382, `.zip` 163).
- **`store.rule_details` now returns `native_key`.** Corroboration folds a rule
  forked across corpora onto one owner; artifact scoring was re-deriving that key
  from the rule id, which matches the persisted column only by accident of how ids
  are built.
- **Grounding over the shipped bundle, split by evidence label** (ADR-0024
  Phase C) — `tests/eval_pipeline.py -b grounding --from-bundle all` reads
  `jobs.bundle_json` instead of the `relationships` table, which held only 65 of
  the 1,207 edges actually delivered. It prints a census of every edge by
  `x_evidence_label` and scores hallucination **only** over `observed`/`reported`:
  an `assessed` or `inferred` edge makes no claim about a sentence in the report,
  so measuring it against the text reports an assertion as a hallucination.
  What the split reveals: **endpoint grounding is 1.000 (38/38, zero dangling)** —
  every flagged edge has both entities present in the report, just never close
  enough together. Widening to `--rel-window 3 --alias-aware` takes hallucination
  from 0.500 to **0.211**, leaving 8 edges genuinely worth a human read.
- **`scripts/rebuild_bundle_provenance.py`** — replays a stored job in memory
  (strictly read-only, `mode=ro`) under an explicit relationship policy and counts
  the resulting edges by label. Rebuilding the GREYVIBE report under the two
  pinned rules its edge arithmetic implies: **1,140 edges with 914 unlabelled
  becomes 350 edges with 0 unlabelled**, the cap holds at 200, and the warning
  names the rule that hit it.
- **Run-configuration provenance** (ADR-0024 Phase B) — new `jobs.run_config_json`
  column, stamped by the worker immediately after the relationship policy is read,
  so the snapshot is the policy actually passed to `build_stix_bundle` rather than
  whatever the mutable `relationship_policy` row holds when someone later asks. It
  records the policy, the enabled stage list, the embedding model, the resolved
  TTP thresholds, `git rev-parse HEAD`, and an **allow-listed** set of `TTP_*` /
  `ENABLE_*` environment variables — never a scan of `os.environ`, which holds API
  keys. Without this a bundle cannot be explained: the 872 unlabelled edges in job
  `32b5475b` were produced by pinned rules the stored policy no longer contains.
- **`scripts/audit_edge_provenance.py`** — read-only, stdlib-only audit of what
  fraction of each stored bundle's edges carry provenance, broken down by
  `x_evidence_label` and by source-type -> target-type pair. Current baseline
  across both stored bundles: **1,207 edges, 245 labelled (20.3%), 962
  unlabelled**, and both report `run config: ABSENT`.
- **`custom=` on `_add_relationship`** — merges STIX custom properties and sets
  `allow_custom` only when properties are actually passed, so every existing edge
  stays byte-identical.
- **Retrieval recall @ k** (ADR-0023 Phase 2) — `tests/eval_pipeline.py -b ate
  --retrieval-recall 1,5,10,25` reports the fraction of gold techniques present in
  Stage 2c's top-k candidates *before* any confidence threshold, at both ATT&CK
  granularities. This is the ceiling on every downstream stage: a selector can
  only pick what retrieval proposed. On the ATE fixtures the retriever reaches
  **0.967 technique recall at k=25** while production runs at k=1 and scores F1
  0.550 — roughly 43 points of attainable recall discarded by never looking past
  rank 1. (n=10 hand-written fixtures; a hypothesis to re-measure on TRAM2 in
  Phase 3, not yet a result.)
- **Stage 2c sentence-gate instrumentation** — `sentence_gate_stats()` reports
  `sentences_total / kept_by_keyword / scored / dropped_by_keyword /
  dropped_by_cap` without loading a model, and the ATE benchmark prints the
  aggregate. Two measurement escape hatches: `TTP_KEYWORD_GATE=off` prices the
  keyword allow-list against a baseline, `TTP_UNWRAP_LINES=0` restores the old
  splitter. Both default to production behaviour and are read per call.
- **`semantic_topk_ids(text, k)`** — measurement-only top-k retrieval that
  deliberately ignores the confidence thresholds and the top-2 margin, so the
  ceiling can be measured independently of the gates applied under it.
- **`--gate-off` on `scripts/probe_ttp_recall_caps.py`** — runs the measurement
  twice and prints what the keyword gate costs in sentences of retrieval surface.
- **Dual-granularity ATE scoring** (ADR-0023 Phase 1) — the ATT&CK Technique
  Extraction benchmark now reports **technique-level** (all IDs truncated to their
  parent) and **sub-technique-level** (exact match only) scores side by side,
  macro-averaged per sample, following the protocols of Buchel et al. (SoK, 2025)
  and Zhang et al. (TTP-R1 / RCPO). Every run also prints
  `mean labels predicted` vs `gold` — the one-line diagnostic that separates
  over-prediction (frontier LLMs emit ~4.2 labels against a gold mean of 1.7) from
  the conservative under-prediction of token-level fine-tuned models.
- **`scripts/verify_ate_scorer.py`** — a mutation harness for the scorer. It
  re-implements the pre-ADR-0023 scorer verbatim and replays every case the
  regression tests assert on, requiring each defect case to diverge and each
  control case to agree; it separately replays a two-sample corpus to prove the
  micro-to-macro aggregation change is real (old micro F1 0.1667 vs new macro
  0.5000). A regression test that agrees with the old code is a test that locks
  nothing.
- **`scripts/probe_ttp_recall_caps.py`** — measures how many sentences Stage 2c
  discards before computing a single embedding. On the two real reports in
  `cti_stix.db`: the `_has_ttp_keyword` allow-list drops **400 of 477 sentences
  (83.9%)**, while `_MAX_CANDIDATES=200` drops **zero** — the keyword gate is the
  binding recall ceiling, the candidate cap is latent.
- **`make check-docs` — a documentation drift guard** (`scripts/check_doc_claims.py`)
  — recomputes every precise number the README asserts (gazetteer size, semantic
  corpus split, ATT&CK grounding pairs, all fuzzy thresholds, the ISO country
  table) from the actual JSON data files and module constants, and exits non-zero
  on any mismatch. Standard library only, read-only, degrades to SKIP when a data
  file is absent so it runs on a fresh clone. Every one of the 11 claims checked
  currently passes.
- **Granular multi-format detection selection on `/coverage/:jobId`** (ADR-0022) —
  the page now makes Sigma, Suricata and YARA distinct throughout, and lets an
  analyst select rules at every level (rule → technique → ATT&CK tactic → corpus
  → format) before exporting. A **format board** shows per-format selected counts,
  byte volume and a per-technique tick strip; matrix cells gained tri-state
  checkboxes and format ticks; a **drill-in strip** lists every rule of the
  focused technique in three always-present format columns (a format with no rule
  renders as a visible absence, not a missing lane); the **export panel** groups
  by tactic or by format/corpus, previews the actual ZIP contents, and warns on
  all-rights-reserved licences. Selection is modelled as an exclusion set, so
  "everything that matches the report" remains the default.
- **Rule-id export** — `POST /api/jobs/{id}/detections/export` with
  `{"rule_ids": [...]}` packages exactly the requested rules. The axis-filtered
  `GET` cannot express an arbitrary set, and ~10k ids cannot ride on a URL. Both
  routes share one ZIP builder, so layout, manifest and README cannot drift; ids
  are intersected with the report's linkable rules.
- **Detections tab reworked** (option 1b) — one ranked list with format as a
  column plus `All / Sigma / Suricata / YARA` filter chips carrying counts,
  instead of tier sections.
- **Per-format coverage breakdown** (ADR-0022) — `CoverageCell` now carries
  `by_format`, an entry per detection format (`sigma` / `suricata` / `yara`) with
  its own `rule_count` and `corpora`, and `CoverageRule` carries `format`. Every
  format key is always present, so a format with no rule renders as an explicit
  zero rather than a missing lane. The coverage *score* is unchanged and still
  computed across all formats combined — corroboration is a property of the
  technique, not of one tool's rule language. Per-format `corpora` reuses the
  same first-seen-corpus attribution as the score, so the panel can never claim
  more corroboration than the score does.

### Fixed
- **The six ordinary Stage 4 mapping edges shipped without provenance**
  (ADR-0024 Phase A2). Phase A labelled the policy-materialised edges, but the
  audit showed that was not the only unlabelled source: `indicates`, `based-on`
  and `targets` call `_add_relationship` too, and account for 48 of the 67 edges
  in the second stored bundle. `based-on` now carries `observed` — the Indicator
  restates an IoC regex actually found in the text — while `indicates` and
  `targets` carry `reported`, being model claims about the document. The grade is
  not bookkeeping: the review-UI auto-accept gate promotes only `observed`, so it
  decides what an analyst checks by hand.
- **Policy-materialised edges shipped with no provenance and no cap** (ADR-0024
  Phase A). Stage 4's pinned-rule materialisation is an intentional all-pairs
  feature — it expresses the analyst's link model — but unlike Stage 4b it stamped
  no `x_evidence_label` and had no ceiling, so on one real report it emitted **872
  of 1,140 edges** with nothing distinguishing a materialised assumption from an
  extracted fact. Pinned edges now carry `x_evidence_label="assessed"` and
  `x_policy_rule="<src> <verb> <tgt>"`, mirroring 4b's `x_inference_rule`, and
  obey a `max_pinned_edges` cap (default 200, matching 4b's `max_new_edges`) that
  logs a warning naming the rule when it truncates. `assessed` correctly fails the
  review-UI auto-accept gate, so these edges now queue for review — **the analyst
  workload this adds was always there, it was just invisible.**
- **`_split_sentences` fragmented PDF-extracted text** (ADR-0023 Phase 2). Its
  regex treated every newline as a sentence boundary, so each hard-wrapped PDF
  line became its own "sentence" — fragments like `"AI across state-aligned
  operations -"`. The obvious fix (protect runs of two-or-more newlines as
  paragraph breaks) does nothing, because the ingested corpus carries **237
  `\n\n` runs against 2 single `\n`**: every wrapped line arrives doubled, so
  that rule protects exactly the newlines that need joining. Deciding on content
  alone — join unless the previous segment ended in `.!?:;` or the next opens a
  list item — takes the corpus from 477 segments to 195, median length 68 to 155
  chars, and the share ending in sentence punctuation from **27% to 81%**.
  Measured consequence: the keyword gate's cost falls from 83.9% to 68.2%, so the
  earlier figure was partly measuring the splitter rather than the gate.
- **10 tests in `tests/eval_pipeline.py` had never run in CI.** The file holds the
  ADR-0011 Phase D adversarial precision tests plus the ATE benchmark tests, but
  its name does not match pytest's default `test_*.py` glob, so `pytest` collected
  it zero times — the suite went from 584 to 593 passing once `python_files` in
  `pytest.ini` named it explicitly. The file is also a documented CLI entry point
  (`python tests/eval_pipeline.py -b ate`), so it was named rather than renamed.
- **The ATE scorer was inflating both precision and recall** (ADR-0023 Phase 1).
  `_score_ate_sample` awarded 0.5 partial credit for a parent/sub-technique
  mismatch but excluded the prediction from the false-positive count, so half the
  prediction's mass left the accounting. Predicting `T1059.001` **and**
  `T1059.002` against a gold `T1059` scored precision 1.00 and recall 1.00.
  Partial credit is now removed entirely in favour of the two-granularity report,
  and `tp + fp == len(predictions)` is asserted as an invariant. Aggregation also
  moved from corpus-level micro-averaging — which let long, technique-dense
  reports dominate — to per-sample macro-averaging. **Any ATE number recorded
  before this change is not comparable to one recorded after it.**
- **Pipeline diagram corrected against the implementation** — the README's stage
  diagram drew Stage 3c (MITRE normalisation) between 3b and 3d, but
  `normalize_ttps()` runs once per document in `_merge_results()`, after every
  chunk is merged; the real per-chunk order is 3b → 3d → 3f → 3e. Stage 3e
  (cross-model consensus) was missing from the diagram entirely although it is
  configured in `.env.example` and listed in the file tree. Stage 2 no longer
  claims to extract mutexes (no pattern produces one — they are analyst-entered
  only, now footnoted in the STIX object table alongside user-account and
  network-traffic). Stage 2c's "margin gate" line implied two active filters when
  `top_k=1` is the operative one and `TTP_TOP2_MARGIN` guards a 2nd match that
  the default configuration never requests (ADR-0011 Phase A). Stage 4 now shows
  the real `Indicator → based-on → ObservedData → SCO` chain and the TLP/PAP +
  `created_by_ref` stamping that Stage 4b's note already referenced. Added a
  scope note: the diagram describes the API worker, not the thinner
  `python main.py` CLI.
- **File-tree drift in the README** — `pipeline/detection/` was missing eight
  modules (the whole Suricata/YARA multi-format layer from ADR-0015, plus
  `dedup.py`, `synth_sigma.py`, `tlds.py`, `sync.py`); `api/routes/` was missing
  `policy.py`; `models/` was missing `config.py`; and `tests/` listed 3 of 31
  modules with no indication it was a sample (571 tests, mapped in TESTING.md).
- **Stale counts** — `stage2b_gazetteer.py` still documented a 1,792-name
  gazetteer (actual: 1,827 variants / 1,114 unique) and a ~194 KB index (~275 KB).
  ADR-0002 was marked *Proposed* despite `WORKER_MAX_CONCURRENT` shipping;
  ADR-0012's status line did not use the same bold form as every other ADR.
- **Undocumented Ollama fallback** — the README and `.env.example` both set
  `OLLAMA_MODEL=mistral`, but leaving it unset falls back to `llama3.2`. Stated
  explicitly rather than leaving the two defaults to disagree silently.
- **`/api/jobs/{id}/coverage/rules` was unusable on real reports** (ADR-0022) —
  the endpoint the Detection Coverage page selects over did not complete: on a
  34-technique report (9,777 canonical rules) a 600 s measurement finished 3 of
  34 techniques, extrapolating to **~2.4 hours**. Two instances of one planner
  pathology in `rules_for_technique`, both already documented elsewhere in the
  same module: the `is_canonical` JOIN predicate made SQLite enter through
  `idx_detection_canon` (~43k of 86k rows) at **4.11 s per technique — even for a
  technique with zero rules** — and the per-rule `also_in` sub-query repeated the
  same scan at **871-1,227 ms per rule**. The first is now an `EXISTS`, the second
  one batched sweep pinned to `idx_detection_dedup`. Measured after: T1190's 6,404
  rules in **1.99 s**, T1082 235.66 s → **0.123 s**, a zero-rule technique
  4.11 s → **0.000 s**. Verified key-by-key against the original query on live
  rules with folded duplicates: 0 mismatches.
- **The Detection Coverage page could not be scrolled** (ADR-0022) — `body` and
  `#root` are `height:100vh; overflow:hidden` so the Review page can own its
  internal scroll panes, which means a full-screen route gets no page scrollbar
  at any window size. The coverage page is ~1,680px tall, so everything below the
  fold — including the whole export panel — was unreachable even on a 1920×1080
  display. It now scrolls itself (`flex:1; min-height:0; overflow-y:auto`), the
  same pattern Policy and Dashboard use, and the page is responsive: the archive
  preview stacks under the selection table at 1180px, and the format board and
  drill-in columns fold 3 → 2 → 1 at 1000px and 720px. Those declarations moved
  from inline styles into `index.css`, since inline styles silently override
  media queries.
- **Three more per-element query patterns in the same area** (ADR-0022) —
  `rules_for_job` called `rules_for_technique` once per technique (34 EXISTS
  joins + 34 `also_in` sweeps, **26.34 s → 5.44 s** as one flat sweep); the
  rule-id export loaded all 10,372 rule bodies (219 MB) to package 45
  (**14.83 s → 4.08 s** via a `body_ids` restriction); and `_load_rules` scanned
  all 86,180 store rows to enrich ~10k (**4.83 s → ~0.3 s** batched by id).
- **Rule body sizes moved to a `rule_bytes` side table** (ADR-0022) — the
  selection UI needs a per-rule byte count, and both obvious placements are slow:
  `LENGTH(raw)` per query costs 8.78 s for 10,372 rules, and a `raw_bytes` column
  on `detection_rules` costs **8.19 s** — no better, because `ALTER TABLE`
  appends it after `raw`, so SQLite still walks each record past a multi-kilobyte
  body. From its own table the same read is ~0.1 s. Written on ingest; existing
  stores are filled by `scripts/backfill_rule_bytes.py` (86,180 rows in 23 s).
- **Alias canonicalisation conflated groups with malware** (ADR-0021) — the
  gazetteer index was built with `name2id[name] = mid`, assuming a surface form
  identifies one MITRE object. It does not: **23 of the 1,814 surface forms carry
  two ids**, and for **18 of them the two objects have different canonical
  names**. `snake` resolved to the Turla *group* G0010 over the Uroburos
  *malware* S0022; `sofacy` and `sednit` to APT28 over CORESHELL/JHUHUGIT;
  `uac-0056` merged two distinct ATT&CK groups (G1031 and G1003).
  The rename was the visible half. The damaging half was in
  `stage4_stix_mapping._register_named`, which registered *every alias of the
  winning id* in `name_to_stix` — so a report describing the Snake malware
  registered `turla`, `secret blizzard`, `krypton`, `group 88` and
  `belugasturgeon` pointing at the **malware** node, and every later
  relationship naming "Turla" attached to the wrong object. Node counts looked
  correct throughout, which is why this was invisible.
  Lookups now take the STIX type the caller is about to create — which both
  production call sites already knew — and use the gazetteer's own `entity_type`
  to break ties. An unambiguous form still resolves whatever the type says, so
  the 1,791 unaffected forms behave exactly as before; a form the type cannot
  narrow resolves to nothing and passes through unchanged rather than being
  guessed. `stage4b_graph_completion` dropped its own last-write-wins copy of the
  index and now shares this one, so a malware node can no longer inherit a
  group's curated ATT&CK edges.
- **YARA and Suricata escape decoding corrupted Windows paths** — both parsers
  unescaped with a chain of `str.replace` that collapsed `\\` to `\` *first* and
  then re-read that backslash as the start of the next escape. The literal
  `"C:\\Windows\\notepad.exe"` decoded to `C:\Windows` + NEWLINE + `otepad.exe`.
  Measured over the real corpora: **349 atoms changed across 138 files**, and the
  mangled values failed the file-extension test and fell through to the
  unmatchable `strlit` class — **232 `file` and 7 `registry` atoms were missing
  from the index entirely**, while 41 truncated fragments sat in it matching
  nothing. `M:\\sc\\p\\testbuild.pdb` produced *no atoms at all*; it now yields
  two, including the PDB basename. Both parsers now decode in one left-to-right
  pass, and undefined escapes (`\x41`) are preserved verbatim as before.
- **A valid-looking relationship policy could fail every job** — `PUT
  /api/relationship-policy` checked that `rules` was a list but never checked its
  items, so `{"rules": ["oops"]}` was accepted and stored, then raised
  `AttributeError` in `build_stix_bundle` and `complete_graph` for every
  subsequent job until the policy was edited by hand. This also defeated Stage
  4b's own contract: it wraps all four completion engines in `try/except` because
  "completion must never break the bundle", but `_pol_index` ran *before* the
  first guard. The endpoint now validates each rule is an object, and both
  index builders skip non-dict entries.
- **The proposals endpoint counted 363k rows to answer a yes/no** —
  `atom_index_size` ran `SELECT COUNT(*) FROM rule_atoms` on every request purely
  to test `> 0`, costing **0.54 s** of each response. Replaced by
  `atom_index_built`, a `SELECT 1 … LIMIT 1` at 0.5 ms. Measured end-to-end on
  real reports: 4.30 s → 3.20 s and 13.95 s → 12.22 s, with identical results.

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
