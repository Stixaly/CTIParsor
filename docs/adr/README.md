# Architecture Decision Records

Each ADR records one significant decision: its context, the options weighed, the
choice, and the consequences. They're append-only — supersede rather than rewrite.

| # | Title | Status |
|---|---|---|
| [0002](0002-concurrent-report-ingestion.md) | Concurrent report ingestion | Accepted |
| [0004](0004-extraction-quality-enhancements.md) | Extraction quality enhancements (embeddings, GLiNER, doc-context, self-verify) | Accepted (retroactive) |
| [0005](0005-ioc-extraction-defang-robustness.md) | IoC extraction & defang robustness | Accepted (retroactive) |
| [0006](0006-multi-corpus-detection-ingestion.md) | Multi-corpus detection-rule ingestion | Accepted |
| [0007](0007-in-app-configuration-panel.md) | In-app configuration panel (keys + corpora) | Proposed |
| [0008](0008-detection-coverage-matrix.md) | Per-report detection-coverage matrix | Accepted |
| [0009](0009-stix-trust-and-provenance.md) | STIX trust & provenance (evidence labels, consensus, markings) | Accepted |
| [0010](0010-default-sigma-corpora-and-dedup.md) | Default multi-repo Sigma corpora + cross-corpus deduplication | Accepted |
| [0011](0011-ttp-extraction-precision.md) | TTP extraction precision (thresholds, margin gate, TTP self-verify, subsumption) | Accepted |
| [0012](0012-hallucination-measurement-and-canonicalization.md) | Hallucination measurement, entity canonicalisation & relationship precision | Accepted |
| [0013](0013-graph-completion.md) | STIX graph completion (alias fallback, ATT&CK grounding, transitive, long-distance) | Accepted |
| [0014](0014-observable-driven-detection-proposals.md) | Observable-driven detection proposals (rule atom index, IDF relevance, platform) | Accepted |
| [0015](0015-multi-format-detection-matching.md) | Multi-format detection matching (Suricata + YARA adapters, per-format IDF) | Proposed |
| [0016](0016-report-derived-sigma-synthesis.md) | Report-derived Sigma rule synthesis (gated templates, deterministic ids) | Proposed |
| [0017](0017-provenance-based-rule-dedup.md) | Provenance-based rule dedup (`related:` folding, technique union) | Proposed |
| [0018](0018-technique-idf-ranking.md) | Technique-IDF ranking (breaks the ~1,400-rule score plateau) | Proposed |
| [0019](0019-multi-format-corpus-management.md) | Multi-format corpus management (format discovery, enable/disable, subdir/tarball) | Proposed |
| [0020](0020-filtered-multi-format-export.md) | Filtered multi-format export (facets, per-format extensions, licence gating) | Proposed |
| [0021](0021-type-aware-alias-resolution.md) | Type-aware alias resolution (a surface form can denote two MITRE objects) | Proposed |
| [0022](0022-per-format-coverage-breakdown.md) | Per-format coverage breakdown, granular multi-format selection + rule-id export (`/coverage/rules`: ~2.4 h → 5.4 s) | Proposed |
| [0023](0023-ttp-extraction-measurement-and-retrieval.md) | TTP extraction: fix the ruler, then retrieve-then-validate (dual-granularity scoring, procedure corpus, BM25+dense candidates) | Proposed |
| [0024](0024-edge-synthesis-provenance-and-run-config.md) | Edge-synthesis provenance & run config (label + cap policy-materialised edges, `jobs.run_config_json`, grounding by evidence label) | Proposed |
| [0025](0025-evidence-keyed-detection-coverage.md) | Evidence-keyed detection coverage — artifacts score, TTPs locate (Pyramid-of-Pain tiers, unscored tactic phase band; 58 of 64 cells scored ≥2 had no matching rule) | Proposed |
| [0026](0026-pin-budget-allocation-and-synthesis-stats.md) | Per-rule budget for policy pins + `x_synthesis_stats` (max-min fair share replaces rank-order starvation: 20 → 46 rules served across 4 bundles; 18,426 candidates for a budget of 200) | Proposed |
| [0027](0027-evidence-gated-pin-materialisation.md) | Evidence-gated pin materialisation, anchorable types only (SCOs/malware/tool 91–100% verbatim; `attack-pattern` 24.3%, `indicator` 0% by name but 96.3% by pattern value — 47% of candidates fail open by design) | Proposed |
| [0028](0028-ttp-evidence-contract.md) | TTPs must quote, not describe — `TTPExtracted` gains `evidence_text`/`evidence_label` (relationship quotes locate at 79.4%, TTP descriptions at 36.8%, same call; 99.4% of failures are paraphrase, not invention) | Proposed |
| [0029](0029-pasted-text-and-captured-url-ingestion.md) | Pasted text and captured URLs as ingestion sources — Chromium renders the archive, the DOM text is what gets ingested (the PDF keeps 99.6% of characters but only 72.2% of observables: 9 of 12 hashes lost to a wrapped table column; JS off is both the security and the functional default — Unit 42 serves 0 chars to a JS-enabled headless browser) | Proposed |
| [0030](0030-evidence-gated-coverage-and-corroboration-scoring.md) | Evidence-gated coverage + corroboration scored on discriminating values (the tag join proposes 86 453 rules across 7 reports, 908 of them — 1.05 % — hold anything the report contains; `strlit`/`pipe` were indexed and unreachable, hiding all 16 314 YARA rules; df keeps `certutil` at 15 and strips `api.telegram.org` at 60, so it cuts the wrong way) | Proposed |
| [0031](0031-brand-evidence-from-campaign-domains.md) | Brand evidence mined from campaign domains + an FTS5 rule-text index (UNC6671's 79 domains were all freshly registered, so the gate served 0 — while 32 Okta rules sat in the store and `okta` appeared in 7 of those domains; recurrence across domains is the anti-noise filter, and FTS5 makes the lookup 0.4 ms instead of 4.1 s) | Proposed |
| [0032](0032-figure-derived-evidence.md) | Figures are evidence, and they enter through `report_text` (141 figures in 200 pages and 56.9% of images are icons a free geometric filter kills; one FortiGate screenshot carries three techniques the text layer never states, one Ukrainian lure page carries a payload filename; the design question is the coordinate system, not the model — injection costs one side table, a separate evidence space costs six gates; whole-page input is not the slow option but the broken one — both ADR-0029 tall-sheet captures returned empty after 90 s) | Proposed |
| [0033](0033-provider-agnostic-vision-calls.md) | One vision call, three providers — capability-gated, schema-constrained (amends 0032 §3: reusing `LLM_PROVIDER` is wrong because the Stage-3 defaults have no vision — `OLLAMA_MODEL=llama3.2` is not even pulled — and a text model handed an image invents rather than raising; Ollama's OpenAI route takes `image_url`, so Mistral and Ollama are one code path; `json_object` invented the key `first_2_text_lines` where `json_schema` returned `lines`, which deletes the repair code at `stage3_llm.py:673`) | Proposed |
| [0034](0034-negated-selections-are-not-atoms.md) | A negated Sigma selection is not an atom (the index held what rules EXCLUDE: 14,037 atoms across 1,742 rules came only from a negated block — `svchost.exe` in 80 rules, `explorer.exe` in 75, `msmpeng.exe` in 62 — so a report naming `explorer.exe` pulled in the rules written to ignore it; the `filter*` naming convention is not usable, 10 rules use one positively and 72 negate a selection not named that way, so the `condition` is parsed instead; over-exclusion is the deliberate bias — it costs an atom where under-exclusion invents one) | Accepted |
| [0035](0035-bundle-staleness-is-a-first-class-signal.md) | A stored bundle carries the pipeline that built it, and must say so (the self-edge fix shipped 2026-08-28 and all 13 stored bundles predate it, so 6 self-loops still ride in two delivered artefacts; `run_config_json.git_rev` already records which commit built each bundle and nothing reads it, while `re_run_final_stages` already rebuilds Stages 4–5 from accepted entities at zero LLM cost — the missing piece is a hand-kept list of output-affecting revisions, because comparing to HEAD marks every frontend commit as invalidating and so never returns to green) | Accepted |

**Numbering notes**
- `0001` and `0003` are unused gaps (early informal decisions never filed).
- `0004` and `0005` were referenced in code (`ADR-004 P*`, `ADR-005`) before being
  filed; documented retroactively to match the implementation.
- The coverage matrix is **0008** — earlier drafts (and ADR-0006/0007) called it
  "ADR-0005"; that number belongs to IoC/defang robustness. References were repointed.

## Dependency sketch

```
0004 extraction quality ─┐
0005 IoC/defang ─────────┤→ better structured intel
0009 trust & provenance ─┘        │
   ▲   measured & extended by     │
   └── 0012 hallucination metric  │
       + canonicalisation         │
          ▲   corrected by        │
          └── 0021 type-aware alias resolution — 23 gazetteer surface
              forms denote two MITRE objects ("snake" = Turla G0010 AND
              Uroburos S0022); resolving them type-blind renamed the SDO
              after the wrong one and mis-wired relationship endpoints
                                         ▼
          ▲            0008 coverage matrix ◄── consumes techniques
          │               ▲   its SCORING superseded by
          │               ├── 0025 evidence-keyed coverage: the technique key
          │               │   selected 25,493 rules across two reports of which
          │               │   4 matched anything in them, and 58 of 64 cells
          │               │   scored >=2 had no matching rule at all.  The
          │               │   artifact becomes the scored unit (Pyramid-of-Pain
          │               │   tiers) and ATT&CK keeps only the phase band, which
          │               │   is sourced from the MATCHING RULE's tags, never
          │               │   from the report's own TTP extraction.  Generalises
          │               │   0014 from ranking to scoring, and carries 0015's
          │               │   hostname gate across to the report side — an
          │               │   asymmetry that had made `agent.ashx` a domain
          │               │      ▲   shipped to the analyst, and repaired, by
          │               │      └── 0030 evidence-gated coverage: 0025 was built
          │               │          and the frontend never called it, so the
          │               │          panel still served the tag join — 86,453
          │               │          rules across 7 reports, 908 (1.05%) holding
          │               │          anything the report contains.  Gates the
          │               │          panel on evidence, and fixes two holes 0025
          │               │          did not see: `strlit`/`pipe` were indexed
          │               │          yet in no MATCHABLE set, so all 16,314
          │               │          canonical YARA rules (none of which carry an
          │               │          ATT&CK tag) were unreachable except by hash;
          │               │          and 0025's df vocabulary cut keeps `certutil`
          │               │          (15) while stripping `api.telegram.org` (60).
          │               │          Corroboration is therefore counted over
          │               │          DISCRIMINATING values, from a static table —
          │               │          not over df, and not over adversary control,
          │               │          which would have stripped Telegram too
          │               │             ▲   its false-negative mode fixed by
          │               │             └── 0031 brand evidence: 0030 validated
          │               │                 the top of the KEPT list and never
          │               │                 looked at what it DROPPED.  On a
          │               │                 campaign whose 79 domains are all
          │               │                 freshly registered no rule holds any
          │               │                 value, so the panel served 0 — while
          │               │                 32 Okta rules sat in the store and
          │               │                 `okta` appeared in 7 of those domains.
          │               │                 A rule whose TITLE names what the
          │               │                 report targets is now admitted, in a
          │               │                 weaker tier that never corroborates.
          │               │                 Brands are mined from the campaign's
          │               │                 own domains by recurrence — no
          │               │                 gazetteer, because recurrence IS the
          │               │                 noise filter.  Adds an FTS5 index:
          │               │                 0.4 ms per lookup against 4.1 s, and
          │               │                 its tokenizer supplies the
          │               │                 word-boundary semantics that plain
          │               │                 containment could not (`reat` matched
          │               │                 52,775 rules)
          │               ▲   implemented by
 canonical names         └── 0006 multi-corpus rules ── managed by ── 0007 settings panel
 feed node identity          ▲   extended by
          │                  ├── 0010 default corpora + dedup
          │                  │      └── 0017 fixed by: dedup_key alone folded 11
          │                  │          of 11,396 rules; `related:` folds 5,036
          │                  │          and corrects 0014's IDF denominator
          │                  └── 0014 observable-driven proposals ◄── consumes IoCs (0005)
          │                         ▲   plateau broken by
          │                         ├── 0018 technique-IDF ranking ── needs 0017:
          │                         │      a technique's document frequency is
          │                         │      meaningless if rules are counted twice
          │                         ▲   generalised to N formats by
          │                         ├── 0015 multi-format matching (suricata + yara)
          │                         │       └── scopes IDF per format so 0014's
          │                         │           Sigma scores survive a 7.5× store
          │                         └── 0016 sigma synthesis — fills the gap 0014
          │                                 leaves (reuses its observables + IDF,
          │                                 and 0015's hostname gate)
          │                  └── 0020 filtered multi-format export ── made granular by
          │                         └── 0022 per-format coverage + rule-id export:
          │                             0008's cells gain a per-format split, and
          │                             the drill-down that feeds it went from
          │                             ~2.4 h to 5.4 s (same planner pathology as
          │                             0014's atom_hits, three more times over)
          └── 0013 graph completion (denser edges, same precision gate)
                 ▲   its discipline applied to the OTHER edge source by
                 └── 0024 edge-synthesis provenance: 4b labels and caps every
                     edge it adds (200 max); the policy-pin all-pairs
                     materialisation at stage4:769 does neither, and produced
                     872 of 1,140 shipped edges on one report with no
                     x_evidence_label at all.  Adds jobs.run_config_json --
                     the stored policy is now `rules: []`, so that bundle
                     cannot be reproduced.  Blocks 0023 Phase 3: a baseline
                     with no run config is not attributable
                        ▲   its cap shown to be the wrong lever by
                        └── 0026 per-rule budget: the cap truncated by the RANK
                            of a rule in the policy array -- saturated 4 times
                            out of 4, and on one report the 10th rule took all
                            200 while the 13 after it emitted nothing.  Max-min
                            fair share: 20 -> 46 rules served.  Adds
                            x_synthesis_stats, which also rescues the
                            CompletionStats 0013 had been returning and having
                            discarded at the call site
                               ▲   is the instrument for
                               └── 0027 evidence-gated materialisation: a pin
                                   emits only where the report links the two
                                   objects (18,426 -> 10,278 pairs).  Applied
                                   PER TYPE because it must be -- attack-pattern
                                   is 24.3% verbatim and course-of-action 0/344,
                                   so 47% of the pool fails open by design
                                      ▲   its exemption is lifted by
                                      └── 0028 TTPs must quote, not describe:
                                          `description` was read as evidence and
                                          locates 38.9%, against 85.6% for the
                                          quotes 0009's contract already asks of
                                          relationships.  Not hallucination --
                                          99.4% of failures are paraphrase of
                                          real content.  Gives a technique an
                                          offset, which is what 0027 needs to
                                          gate the attack-pattern rules at all

0011 TTP precision (thresholds, margin gate, 3f verify, subsumption)
   ▲   measured — and partly corrected — by
   └── 0023 fix the ruler, then retrieve-then-validate: the ATE scorer
       leaked partial credit (a parent + two subs scored P=R=1.00), and
       0011 Phase A specified `top_k=1` *with* a 2nd-match margin gate —
       two clauses that cannot both hold, so TTP_TOP2_MARGIN never fired.
       Reverses 0004 P1-A's SecureBERT-Plus pick for the unlabeled
       similarity setting (ATT&CK-BERT wins there; CTI-pretrained
       encoders do not consistently beat generic ones)

0029 ingestion entry points (paste, URL capture)
   stands alone: it adds ways IN, and converges on the file-on-disk
   contract every later ADR already assumes.  Nothing downstream of
   Stage 1 can tell an uploaded file from a pasted excerpt or a
   rendered page -- which is why it depends on none of the above and
   none of the above changes.  Its own finding is about the library,
   not the pipeline: Playwright defaults chromium_sandbox to False and
   appends --no-sandbox itself, so the careful arg list read correct
   while the sandbox was off
```
