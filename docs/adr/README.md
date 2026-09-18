# Architecture Decision Records

Each ADR records one significant decision: its context, the options weighed, the
choice, and the consequences. They're append-only — supersede rather than rewrite.

| # | Title | Status |
|---|---|---|
| [0002](0002-concurrent-report-ingestion.md) | Concurrent report ingestion | Accepted |
| [0004](0004-extraction-quality-enhancements.md) | Extraction quality enhancements (embeddings, GLiNER, doc-context, self-verify) | Accepted (retroactive) |
| [0005](0005-ioc-extraction-defang-robustness.md) | IoC extraction & defang robustness | Accepted (retroactive) |
| [0006](0006-multi-corpus-detection-ingestion.md) | Multi-corpus detection-rule ingestion | Accepted |
| [0007](0007-in-app-configuration-panel.md) | In-app configuration panel (keys + corpora) | Accepted (slice 1 done) |
| [0008](0008-detection-coverage-matrix.md) | Per-report detection-coverage matrix | Accepted |
| [0009](0009-stix-trust-and-provenance.md) | STIX trust & provenance (evidence labels, consensus, markings) | Accepted |
| [0010](0010-default-sigma-corpora-and-dedup.md) | Default multi-repo Sigma corpora + cross-corpus deduplication | Accepted |
| [0011](0011-ttp-extraction-precision.md) | TTP extraction precision (thresholds, margin gate, TTP self-verify, subsumption) | Accepted |
| [0012](0012-hallucination-measurement-and-canonicalization.md) | Hallucination measurement, entity canonicalisation & relationship precision | Accepted |
| [0013](0013-graph-completion.md) | STIX graph completion (alias fallback, ATT&CK grounding, transitive, long-distance) | Accepted |
| [0014](0014-observable-driven-detection-proposals.md) | Observable-driven detection proposals (rule atom index, IDF relevance, platform) | Accepted |
| [0015](0015-multi-format-detection-matching.md) | Multi-format detection matching (Suricata + YARA adapters, per-format IDF) | Accepted |
| [0016](0016-report-derived-sigma-synthesis.md) | Report-derived Sigma rule synthesis (gated templates, deterministic ids) | Accepted |
| [0017](0017-provenance-based-rule-dedup.md) | Provenance-based rule dedup (`related:` folding, technique union) | Accepted |
| [0018](0018-technique-idf-ranking.md) | Technique-IDF ranking (breaks the ~1,400-rule score plateau) | Accepted |
| [0019](0019-multi-format-corpus-management.md) | Multi-format corpus management (format discovery, enable/disable, subdir/tarball) | Accepted |
| [0020](0020-filtered-multi-format-export.md) | Filtered multi-format export (facets, per-format extensions, licence gating) | Accepted |
| [0021](0021-type-aware-alias-resolution.md) | Type-aware alias resolution (a surface form can denote two MITRE objects) | Accepted |
| [0022](0022-per-format-coverage-breakdown.md) | Per-format coverage breakdown, granular multi-format selection + rule-id export (`/coverage/rules`: ~2.4 h → 5.4 s) | Accepted |
| [0023](0023-ttp-extraction-measurement-and-retrieval.md) | TTP extraction: fix the ruler, then retrieve-then-validate (dual-granularity scoring, procedure corpus, BM25+dense candidates) | Accepted in part |
| [0024](0024-edge-synthesis-provenance-and-run-config.md) | Edge-synthesis provenance & run config (label + cap policy-materialised edges, `jobs.run_config_json`, grounding by evidence label) | Accepted |
| [0025](0025-evidence-keyed-detection-coverage.md) | Evidence-keyed detection coverage — artifacts score, TTPs locate (Pyramid-of-Pain tiers, unscored tactic phase band; 58 of 64 cells scored ≥2 had no matching rule) | Accepted |
| [0026](0026-pin-budget-allocation-and-synthesis-stats.md) | Per-rule budget for policy pins + `x_synthesis_stats` (max-min fair share replaces rank-order starvation: 20 → 46 rules served across 4 bundles; 18,426 candidates for a budget of 200) | Accepted |
| [0027](0027-evidence-gated-pin-materialisation.md) | Evidence-gated pin materialisation, anchorable types only (SCOs/malware/tool 91–100% verbatim; `attack-pattern` 24.3%, `indicator` 0% by name but 96.3% by pattern value — 47% of candidates fail open by design) | Accepted |
| [0028](0028-ttp-evidence-contract.md) | TTPs must quote, not describe — `TTPExtracted` gains `evidence_text`/`evidence_label` (relationship quotes locate at 79.4%, TTP descriptions at 36.8%, same call; 99.4% of failures are paraphrase, not invention) | Accepted |
| [0029](0029-pasted-text-and-captured-url-ingestion.md) | Pasted text and captured URLs as ingestion sources — Chromium renders the archive, the DOM text is what gets ingested (the PDF keeps 99.6% of characters but only 72.2% of observables: 9 of 12 hashes lost to a wrapped table column; JS off is both the security and the functional default — Unit 42 serves 0 chars to a JS-enabled headless browser) | Accepted |
| [0030](0030-evidence-gated-coverage-and-corroboration-scoring.md) | Evidence-gated coverage + corroboration scored on discriminating values (the tag join proposes 86 453 rules across 7 reports, 908 of them — 1.05 % — hold anything the report contains; `strlit`/`pipe` were indexed and unreachable, hiding all 16 314 YARA rules; df keeps `certutil` at 15 and strips `api.telegram.org` at 60, so it cuts the wrong way) | Accepted |
| [0031](0031-brand-evidence-from-campaign-domains.md) | Brand evidence mined from campaign domains + an FTS5 rule-text index (UNC6671's 79 domains were all freshly registered, so the gate served 0 — while 32 Okta rules sat in the store and `okta` appeared in 7 of those domains; recurrence across domains is the anti-noise filter, and FTS5 makes the lookup 0.4 ms instead of 4.1 s) | Accepted |
| [0032](0032-figure-derived-evidence.md) | Figures are evidence, and they enter through `report_text` (141 figures in 200 pages and 56.9% of images are icons a free geometric filter kills; one FortiGate screenshot carries three techniques the text layer never states, one Ukrainian lure page carries a payload filename; the design question is the coordinate system, not the model — injection costs one side table, a separate evidence space costs six gates; whole-page input is not the slow option but the broken one — both ADR-0029 tall-sheet captures returned empty after 90 s) | Accepted |
| [0033](0033-provider-agnostic-vision-calls.md) | One vision call, three providers — capability-gated, schema-constrained (amends 0032 §3: reusing `LLM_PROVIDER` is wrong because the Stage-3 defaults have no vision — `OLLAMA_MODEL=llama3.2` is not even pulled — and a text model handed an image invents rather than raising; Ollama's OpenAI route takes `image_url`, so Mistral and Ollama are one code path; `json_object` invented the key `first_2_text_lines` where `json_schema` returned `lines`, which deletes the repair code at `stage3_llm.py:673`) | Accepted |
| [0034](0034-negated-selections-are-not-atoms.md) | A negated Sigma selection is not an atom (the index held what rules EXCLUDE: 14,037 atoms across 1,742 rules came only from a negated block — `svchost.exe` in 80 rules, `explorer.exe` in 75, `msmpeng.exe` in 62 — so a report naming `explorer.exe` pulled in the rules written to ignore it; the `filter*` naming convention is not usable, 10 rules use one positively and 72 negate a selection not named that way, so the `condition` is parsed instead; over-exclusion is the deliberate bias — it costs an atom where under-exclusion invents one) | Accepted |
| [0035](0035-bundle-staleness-is-a-first-class-signal.md) | A stored bundle carries the pipeline that built it, and must say so (the self-edge fix shipped 2026-08-28 and all 13 stored bundles predate it, so 6 self-loops still ride in two delivered artefacts; `run_config_json.git_rev` already records which commit built each bundle and nothing reads it, while `re_run_final_stages` already rebuilds Stages 4–5 from accepted entities at zero LLM cost — the missing piece is a hand-kept list of output-affecting revisions, because comparing to HEAD marks every frontend commit as invalidating and so never returns to green) | Accepted |
| [0036](0036-architecture-service-multi-utilisateur.md) | A layered rewrite is not what makes this multi-user (the reviewed proposal's diagnosis holds — `_run_pipeline` is 678 lines, SQL sits in 10 route files of 10, config is read 82 times — but it credits the boolean index with a 5 078 ms win that was 4 624 ms of filesystem, and the deployed Linux instance already answers coverage in 23 ms; `fork` is unavailable because Torch's OpenMP pool deadlocks after it, which rules out ARQ, RQ and default-prefork Celery; `INSERT OR IGNORE` is inert on `entities` because the PK is a fresh uuid4 and no UNIQUE exists; the pool is not a new decision but ADR-0002 accepted 2026-06-07 with all five action items still unticked; ordered by impact per unit of effort, so the few-line queue fix ships before the multi-week auth project) | Proposed |
| [0037](0037-scaling-to-30-40-users.md) | Scaling to 30–40 concurrent users — measure the stack before rewriting it (a Rust + PostgreSQL + Elasticsearch rewrite targets the <1 ms slice of a 5 078 ms response; `mv` to native storage delivers the bulk of it for free, and the real ceiling is 4.4 GB of model RSS per job with a 133 s cold start, identical in every language; its Measurement 2 has since been invalidated — see 0036) | Superseded in part by 0036 |
| [0038](0038-link-density-under-policy.md) | Link density under policy — the factory policy has no rules while the Policy page shows 27 (nothing seeds the DB, so Stage 4 pins nothing on a fresh install); `gap` relationships are requested from the LLM and then deleted by Stage 3d; caps are one shared counter that ADR-0024 saw hit at exactly 200; decision: backend-owned default rule set, kept `gap` edges, alias-aware endpoint resolution behind a measurement gate, per-node fan-out caps, long-distance completion on the local model; the before/after run is recorded as a procedure because the WSL distro dies at the first Stage 3 LLM call on this workstation (7 attempts, both providers) | Proposed |
| [0039](0039-per-stage-observability.md) | Per-stage observability — 18 stage modules, 6 report anything, and the ones that change the data most report least (3d deletes every unquotable relationship, 4b adds up to 200 edges, neither emits an event); 209 `logger` call sites carry no job id because the worker subprocess never sets the `request_id` ContextVar, so every pipeline line reads `[none]`; the traceback is computed then discarded in favour of `str(exc)`; a SIGKILLed job does not say which stage it died in (7 manual greps on 2026-09-02); the progress bar is `(stage / 5) * 100`, which hardcodes the count, weights a millisecond stage like a 4-minute one, and yields `NaN` for stage `"1f"`. Decision: a typed `job_stages` table written through one `stage_span` context manager that also sets the log context, times the stage, emits the event and attributes the exception | Proposed |
| [0040](0040-offline-installation-bundle.md) | Offline (air-gapped) installation bundle — `setup.sh` reaches 12 network sources (452 `.deb`, 167 wheels / 3.1 GB, 2.6 GB of models, 684 MB of corpora, Chromium, Node, an LLM); one self-contained ~13 GB bundle built by `scripts/package_offline.sh` on a twin of the target, installed by `setup.sh --offline=<dir>` through env vars (`PIP_NO_INDEX`, `HF_HUB_OFFLINE`) and pre-staged files so each step's own "already present" branch fires; checksums verified before touching the host; Python/distro coupling accepted and enforced | Proposed |
| [0041](0041-observables-route-through-indicators.md) | Observables route through their Indicator, never straight to a threat SDO — two paths still wire a raw SCO directly to malware/threat-actor/etc: the LLM relationships loop (only observable↔attack-pattern was guarded) and the policy pin engine (the *larger* source per ADR-0024, 872/1,140 edges on one report); measured 12/29 and 2/45 raw-SCO edges on stored bundles, mostly observable-to-observable (`file↔ipv4-addr`, out of scope — no single STIX answer exists for it); redirects the observable side to its Indicator only when the other endpoint is a real SDO, opt-in via a `sco_id_to_indicator` parameter so the pin engine's own budget/gating unit tests are untouched; also closes a silent gap where `NETWORK_TRAFFIC` observables never got an Indicator at all | Accepted |
| [0043](0043-self-contained-bundle-embeds-source-pdf.md) | The STIX bundle embeds the source document (`payload_bin`) — the `Artifact` object `stage4_stix_mapping.py` has always tried to build (hash + MIME type only, no bytes, "to keep the bundle compact") has never actually existed: STIX 2.1 requires exactly one of `payload_bin`/`url`, so `stix2.Artifact(hashes=...)` alone raises `MutuallyExclusivePropertiesError` and the surrounding `except Exception: artifact_obj = None` has silently swallowed it on every job ever processed, found only by checking a real bundle instead of the docstring's claim; fix embeds the source file as base64 `payload_bin` (measured ≈347 KB added for a 260 KB PDF), making the bundle self-contained | Accepted |
| [0048](0048-queue-status-endpoint.md) | A queue-status endpoint, not a metrics exporter — closes a blind spot named while documenting 0046: no purpose-built way to see backlog or worker liveness beyond `docker compose logs`. `GET /api/queue/status`, no new dependency, no auth (same posture as every other GET route); real `GROUP BY` counts (not an invented status vocabulary), oldest-queued age, and the lease made visible per worker (`heartbeat` freshness against `WORKER_LEASE_TIMEOUT_S`); rejected a Prometheus exporter as the first metrics dependency this codebase would carry, for a question one endpoint answers; validated against the live compose stack — a worker row appeared 1.1 s after upload and vanished the moment the report reached `for_review` | Accepted |
| [0047](0047-publish-image-to-ghcr.md) | Publish the image to GHCR; tag by commit and `latest` — closes the other blind spot named alongside 0048: CI builds the image and stops (`push: false`), so a second host's only path to it was rebuilding from source. GHCR over Docker Hub (already on GitHub, zero new secret — the `GITHUB_TOKEN` the workflow already has); a second job, gated on the smoke test passing and on `main` only, `packages: write` scoped to that job alone; tags `sha-<full sha>` (pins) and `latest` (tracks main); named what it can't automate — a GHCR package is private by default regardless of repo visibility, one manual click required after the first push; verified the pull-then-up mechanic against the real compose file: a pre-existing local tag skipped the build entirely, 6.4 s to running containers | Accepted |
| [0049](0049-redos-guard-actually-wired-in.md) | The ReDoS guard becomes real: `google-re2`, and actually called — two bugs, not one, found while chasing a routine build warning: the pinned `re2` package doesn't build past Python 3.12, and `_compile_pattern`, the function that was ever supposed to route Stage 2's 19 patterns through it, was never called by any of them; switched to `google-re2` (wheels, no libre2-dev/libre2-9 — confirmed by `ldd` that it statically bundles RE2) and wired every pattern through it, mapping `re.IGNORECASE`/`MULTILINE`/`DOTALL` onto RE2's inline `(?ims)` prefix syntax; 7 of the 19 sub-patterns use lookaround RE2's syntax can't parse at all (`(?<!...)`, `(?!...)`) and fall back to stdlib `re` regardless — verified inside the built container that those 7 have no nested unbounded quantifier, so they were never exploitable by backtracking either way; identical `extract_entities()`/`refang()` output re2 vs. stdlib fallback on 9 real ingested reports (501 entities, 0 mismatches) | Accepted |
| [0050](0050-cyner-generic-language-filter.md) | CyNER's Malware/Threat_group labels get a generic-language filter — a user-reported real report produced far more `malware`/`threat_actor` entities than made sense; the labels fire on any span discussing malware/threat-actor activity, not only on named entities, so `extract_cyner_entities` was accepting pure category vocabulary (`malware`, `ransomware family`, `cyber espionage`), comma-joined lists of several real names as one entity, sentence-boundary/OCR garbage, and mistagged countries; added list splitting, a ~150-word enumerated generic-token stoplist (any fragment with zero non-generic tokens is dropped), and two small denylists folded into the same check so one denylisted word cannot veto an otherwise distinct name; measured on the real job, replaying its actual captured CyNER output through the fix: 255 -> 162 raw entities (-36.5%), malware -26.4%, threat_actor -67.7%, every removed entity manually verified as noise | Accepted |
| [0051](0051-calibrated-ner-thresholds.md) | NER confidence cutoffs calibrated from analyst decisions, per source and entity type — each stage applied one constant to every label (GLiNER 0.40 across six, CyNER 0.70 across two) while the store already held a labelled sample of P(correct \| score) in `entities.confidence` + `accepted`; an isotonic (PAV) fit per pair proposes the lowest score whose calibrated accept rate reaches a target precision, applied only on `--apply` / `"apply": true` into a `model_thresholds` row the stages read per type; three guards reported rather than resolved — too few decisions, no band reaching the target (a content problem, ADR-0050), and a clean band only at or above the review UI's auto-accept tier where an accept is the model's verdict echoed back; a proposal never goes below a score analysts have seen; GLiNER has one threshold for all labels, so the model is asked at the lowest and each type post-filtered | Accepted |
| [0046](0046-worker-container.md) | The worker is a container of its own; the `jobs` table is the queue — `CTIPARSOR_ROLE` (`all` keeps the single-process host install, `api` only enqueues, `worker` runs `python -m api.queue_loop`); the existing conditional-UPDATE claim was already atomic on both engines, what was missing for several workers was a lease (`worker_id`, `heartbeat_at`, requeue after `WORKER_LEASE_TIMEOUT_S`) since the old `requeue_orphans` reset every `processing` row; same image, `command: worker`, scalable with `--scale worker=N`; every compose service now carries measured CPU/memory limits (worker 4.4 GB per report + 1 GB); no broker, `FOR UPDATE SKIP LOCKED` deferred as an optimisation; validated: 1206/1214 tests green on SQLite/PostgreSQL, a report processed by the worker container while the API spawned nothing | Accepted |
| [0045](0045-postgresql-for-the-job-store.md) | PostgreSQL for the job store, SQLite kept for the rule corpus — the maintainer brought ADR-0037's Option C forward without waiting for authentication; measured: 213 SQL sites but only 7 SQLite-only statements on the per-job tables, every row read by name, no `%`/`LIKE` in that SQL, so a 165-line adapter (`?`→`%s`, a `sqlite3.Row`-like tuple, a wrapper whose `with` never closes) replaces an ORM; `DATABASE_URL` unset = today's single file, set = eight tables move; the FTS5 corpus cannot move (`MATCH`, `INDEXED BY`) and stays; the coverage code is the one place both stores meet and gains a `jobs_conn` parameter; a migration script copies an existing store in one transaction, ids preserved, sequence realigned; the compose stack gains a non-root, capability-less, read-only `postgres:17-alpine` on the internal network; validated: 1206 tests green on PostgreSQL, 1198 on SQLite, 47 rows migrated inside the container, a report processed through the API to a 53-object bundle | Accepted |
| [0044](0044-container-images.md) | Container images: one hardened application image, not a database tier — the requested "PostgreSQL + app" split has nothing to hold on the DB side (SQLite is opened in-process, ADR-0037 defers PostgreSQL until authentication) and a separate worker needs a broker ADR-0002/0036 rejected; one 3-stage image (4.48 GB, 3 min 24 s cold build), two volumes (`cti-state` precious, `cti-cache` rebuildable), compose profiles `bootstrap` / `ollama` / `proxy`; runs as uid 1001 on a read-only root with every capability dropped — the Chromium sandbox stays ON through a seccomp profile that had to allow `chroot` unconditionally (Playwright's stock profile gates it on `CAP_SYS_CHROOT`; measured `Check failed: sys_chroot("/proc/self/fdinfo/")`); found `libmagic1` missing from slim images and the optional `re2` pin unbuildable on Python 3.12 | Accepted |
| [0042](0042-embedded-yara-rules-as-indicators.md) | Embedded detection rules (YARA, Suricata, Snort, Sigma) become Indicator SDOs — CTI reports routinely publish a literal rule inline (verified: 4 complete YARA rules in one real Google TIG report), and none of it survived past ingestion; STIX 2.1's `Indicator.pattern_type` already models all four natively, so the work is extraction — reuses `yara_atoms.split_rules` and `suricata_atoms.rule_header`/`parse_options` (ADR-0015's own corpus parsers, validated at ~20,000-rule scale) unchanged; Sigma gets a new grow-then-shrink YAML boundary heuristic since it has no self-delimiting rule-end marker, fail-closed (must parse as valid title+detection YAML) and unvalidated against any real report, unlike the other two; auto-links to an already-extracted malware/tool by name substring (`x_evidence_label: "observed"`) — measured wrong on the first check (raw Stage-3 output) and right on the second (the DB-merged entity list `build_stix_bundle` actually sees, where CyNER had already found all 4 names) | Accepted |

**Numbering notes**
- `0001` and `0003` are unused gaps (early informal decisions never filed).
- `0004` and `0005` were referenced in code (`ADR-004 P*`, `ADR-005`) before being
  filed; documented retroactively to match the implementation.
- The coverage matrix is **0008** — earlier drafts (and ADR-0006/0007) called it
  "ADR-0005"; that number belongs to IoC/defang robustness. References were repointed.
- The scaling study was drafted as "ADR-0013" and filed as **0037**: `0013` belongs
  to STIX graph completion. Its draft also claimed ADR-0012 had never been filed —
  it had; `0012` is hallucination measurement. Both were corrected before filing.

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

0002 concurrent ingestion (persistent worker pool, queue, no broker)
   ▲   re-affirmed, re-measured and re-sequenced by
   └── 0036: 0002 was accepted 2026-06-07 and none of its five action
       items shipped -- `run_pipeline_async` still spawns one process per
       upload.  0036 keeps its verdict (pool yes, Redis no), corrects its
       memory estimate (~1 GB/worker -> 4.4 GB, GLiNER-dominated), adds
       the `fork` constraint it left implicit, and puts the queue-full
       data-loss fix ahead of the pool instead of inside it

0037 scaling study (measure the stack before rewriting it)
   ▲   sequenced by
   └── 0036 multi-user service architecture: keeps 0037's measurements and
       its verdicts on Rust/Elasticsearch, re-orders its action list by
       impact per unit of effort, and adds what 0037 left implicit -- the
       `fork` constraint that rules out ARQ/RQ/default-Celery, the inert
       `INSERT OR IGNORE` that any retry would turn into duplicate
       entities, and the fact that half of 0037's 715x is already banked
       by the move to native storage.  Neither touches the pipeline: they
       are about how the service is run, not what it extracts

0013 graph completion (reference grounding, transitive, long-distance)
   ▲   defaults and cap re-decided by
   └── 0038 link density under policy: the factory policy has NO rules
       while the Policy page displays 27 (nothing seeds the DB), `gap`
       relationships are asked for and then deleted by Stage 3d, and one
       shared 200-edge counter serves both 4b engines.  Backend-owned
       default rule set, `gap` edges kept under their label, alias-aware
       endpoint resolution behind a measurement gate, per-node fan-out
       caps, long-distance completion on the local model.  Also amends
       0024 (fixed cap) and 0026/0027 (budget, gate); the before/after
       run is a recorded procedure until it can be executed on the
       Linux host

0002 worker subprocess model + 0024 run_config (what a run was CONFIGURED with)
   ▲   completed by
   └── 0039 per-stage observability: 0024 records the configuration of a run
       and nothing records its EXECUTION.  18 stage modules, 6 report; the
       stages that delete and add the most data (3b, 3d, 3f, 4b) report
       nothing, although 3d and 4b already compute the numbers and throw
       them away.  A `job_stages` table written through one `stage_span`
       context manager, which also sets the job id on the log context that
       209 call sites currently render as `[none]`, and names the stage a
       SIGKILLed job died in.  Supplies the per-stage timings 0036 Phase 0
       and 0037 had to obtain with throwaway scripts, and the dropped-edge
       count 0038 decision 2 changes on purpose

0009 trust & provenance (observable → ObservedData → Indicator chain)
   ▲   its LLM-relationship and pin-engine edges disciplined by
0024 edge-synthesis provenance + 0027 evidence-gated pin materialisation
   ▲   both are sources of a raw SCO reaching a threat SDO directly
   └── 0041 observables route through their Indicator: the pin engine is
       the LARGER of the two sources (872/1,140 edges on one report, per
       0024), not the smaller one — only observable↔attack-pattern was ever
       guarded (0012).  Scoped to observable↔non-observable-SDO pairs only:
       12/29 and 2/45 raw-SCO edges measured on stored bundles turned out to
       be mostly observable-to-observable (`file↔ipv4-addr`), which has no
       single correct STIX answer and stays out of scope.  Opt-in via a
       `sco_id_to_indicator` parameter so 0027's own budget/gating unit
       tests, built on bare fakes with no Indicator behind them, are
       untouched.  Also closes a silent gap where NETWORK_TRAFFIC
       observables never got an Indicator at all

0015 multi-format detection matching (names the gap: reports carry
detection rules inline, nothing extracts them — never built)
   ▲   built by
   └── 0042 embedded detection rules become Indicator SDOs: STIX 2.1's
       `pattern_type` (yara/suricata/snort/sigma) already models this, so
       the work is extraction — reuses 0015's own `yara_atoms.split_rules`
       and `suricata_atoms.rule_header`/`parse_options` unchanged (both
       validated at ~20,000-rule corpus scale); Sigma alone needs new
       logic, a grow-then-shrink YAML boundary heuristic, because YAML has
       no self-delimiting rule end the way YARA's braces or Suricata's
       one-line format do.  Verified against a real report with 4 embedded
       YARA rules; Sigma has no real counter-example and stays fail-closed.
       Auto-links to an already-extracted malware/tool by name substring —
       wrong on the first check (raw Stage-3 output), right on the second
       (the DB-merged entity list 0002/1359's `re_run_final_stages`
       actually builds, where CyNER had already found all 4 names the LLM
       had not)

0040 offline bundle (its Option C, "a container image", set aside)
0002 in-process worker pool, no broker ──┐
0037 SQLite stays, PostgreSQL deferred ──┤  the seams a container split would need
0029 Chromium sandbox forced on ─────────┘  do not exist in the code
   ▲   packaged, not re-architected, by
   └── 0044 container images: ONE hardened application image (4.48 GB,
       3 min 24 s cold build), two volumes (state to back up, cache to
       rebuild), compose profiles bootstrap / ollama / proxy — the proxy
       profile is deployment.md option C in container form.  The requested
       "PostgreSQL + app" and "app / worker / Chromium / database" splits
       were each checked against the code: the database is a file opened
       in-process, the worker is spawned from inside the API, Chromium is
       launched in-process — so a database container would serve nothing
       and a worker container needs the broker 0002/0036 rejected.  Runs as
       uid 1001 on a read-only root with every capability dropped; the
       0029 sandbox stays ON through a seccomp profile that additionally
       had to allow `chroot` (Playwright's stock profile gates it on
       CAP_SYS_CHROOT, and the zygote chroots inside its own userns).
       Found on the way: `libmagic1` absent from slim images, and the
       optional `re2` pin unbuildable on Python 3.12 — nobody has had the
       ReDoS guard for a while.  A dedicated Chromium container (Playwright
       remote mode) is named as the next hardening step
          ▲   its "no database tier" decision reversed by the maintainer in
          └── 0045 PostgreSQL for the job store: 0037's Option C brought
              forward without authentication.  Two stores behind one switch —
              DATABASE_URL unset keeps today's single SQLite file, set moves
              the eight per-job tables — because the per-job SQL was already
              portable (7 SQLite-only upserts, rewritten to ON CONFLICT for
              both engines) while the FTS5 rule corpus of 0031 is not and
              stays put, as 0037 said.  No ORM (0036's verdict holds): a
              165-line adapter translates `?` placeholders and gives psycopg
              rows sqlite3.Row's access pattern.  The coverage code of 0008 /
              0025 / 0030 is the one place both stores meet and takes a
              `jobs_conn`; the compose stack of 0044 gains a hardened
              postgres service and the operator gains a one-shot migration
              script that keeps progress-event ids (the SSE resume point)
                 ▲   is what lets a second writer exist without corrupting a
                 │   job, which is exactly what
                 └── 0046 needs: the worker becomes a container of its own.
                     The claim (`UPDATE … WHERE status='queued'`) was already
                     atomic on both engines; a lease (`worker_id`,
                     `heartbeat_at`) is the piece PostgreSQL made safe to add,
                     because SQLite's single-writer file could not have
                     hosted a second process claiming jobs without risking
                     the same row twice.  `CTIPARSOR_ROLE` (`all` / `api` /
                     `worker`) is the switch; `all` is the exact behaviour a
                     host install had before roles existed.  No broker
                     (0002/0036's verdict holds): the `jobs` table is the
                     queue.  Every compose service of 0044 now carries a
                     measured CPU/memory limit
                        ▲   named two blind spots, closed by
                        ├── 0048 queue-status endpoint: nothing made the
                        │   lease visible to an operator except log-watching
                        │   or counting rows by hand.  One read-only
                        │   endpoint, no Prometheus (this codebase's first
                        │   metrics dependency would answer a question one
                        │   endpoint already does); validated live — a
                        │   worker row appeared 1.1s after upload, vanished
                        │   the moment the report reached for_review
                        └── 0047 publish the image to GHCR: 0044's CI builds
                            and stops (push: false); a second host's only
                            path to the image was rebuilding from source.
                            GHCR, not Docker Hub — already on GitHub, zero
                            new secret.  Verified the actual mechanic a
                            "pull instead of build" workflow depends on: a
                            pre-existing local tag made `up` skip the build
                            entirely, not assumed

0044 found the re2 pin unbuildable on Python 3.12 (noted, not fixed)
   ▲   turned out to be two bugs, fixed by
   └── 0049 the ReDoS guard becomes real: the package AND the fact that
       `_compile_pattern` — the function SECURITY-relevant docs credited
       with linear-time matching — was never called by any of Stage 2's
       19 patterns, all of which bypassed it via bare `re.compile()`.
       Switched to `google-re2` (wheels, no libre2-dev/libre2-9 -- `ldd`
       confirmed it statically bundles RE2) and wired every pattern
       through `_compile_pattern`, mapping the three `re` flags this
       codebase uses onto RE2's inline `(?ims)` prefix syntax.  7 of the
       19 sub-patterns use lookaround RE2 cannot parse at all and fall
       back to stdlib `re` regardless of the flag mapping -- checking
       that, rather than assuming the flag fix covered everything, found
       none of the 7 has a nested unbounded quantifier, so backtracking
       blowup was never reachable on them either way (stress-tested
       against adversarial input up to 16k chars, <11 ms).  Validated
       identical extract_entities()/refang() output re2 vs. stdlib
       fallback on all 9 real ingested reports in cti_stix.db
```
