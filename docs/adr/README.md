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
| [0013](0013-graph-completion.md) | STIX graph completion (alias fallback, ATT&CK grounding, transitive, long-distance). Amended 2026-10-11: MITRE's edges are graded `external-reference`, and they and the transitive ones ship outside the Report's `object_refs` (audit B 8.4.2) | Accepted |
| [0014](0014-observable-driven-detection-proposals.md) | Observable-driven detection proposals (rule atom index, IDF relevance, platform) | Accepted |
| [0015](0015-multi-format-detection-matching.md) | Multi-format detection matching (Suricata + YARA adapters, per-format IDF) | Accepted |
| [0016](0016-report-derived-sigma-synthesis.md) | Report-derived Sigma rule synthesis (gated templates, deterministic ids) | Accepted |
| [0017](0017-provenance-based-rule-dedup.md) | Provenance-based rule dedup (`related:` folding, technique union) | Accepted |
| [0018](0018-technique-idf-ranking.md) | Technique-IDF ranking (breaks the ~1,400-rule score plateau) | Accepted |
| [0019](0019-multi-format-corpus-management.md) | Multi-format corpus management (format discovery, enable/disable, subdir/tarball) | Accepted |
| [0020](0020-filtered-multi-format-export.md) | Filtered multi-format export (facets, per-format extensions, licence gating) | Accepted |
| [0021](0021-type-aware-alias-resolution.md) | Type-aware alias resolution (a surface form can denote two MITRE objects) | Accepted |
| [0022](0022-per-format-coverage-breakdown.md) | Per-format coverage breakdown, granular multi-format selection + rule-id export (`/coverage/rules`: ~2.4 h → 5.4 s) | Accepted |
| [0023](0023-ttp-extraction-measurement-and-retrieval.md) | TTP extraction: fix the ruler, then retrieve-then-validate (dual-granularity scoring, procedure corpus, BM25+dense candidates) | Accepted in part (Phases 4–6: ADR-0072) |
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
| [0035](0035-bundle-staleness-is-a-first-class-signal.md) | A stored bundle carries the pipeline that built it, and must say so (the self-edge fix shipped 2026-08-28 and all 13 stored bundles predate it, so 6 self-loops still ride in two delivered artefacts; `run_config_json.git_rev` already records which commit built each bundle and nothing reads it, while `re_run_final_stages` already rebuilds Stages 4–5 from accepted entities at zero LLM cost — the missing piece is a hand-kept list of output-affecting revisions, because comparing to HEAD marks every frontend commit as invalidating and so never returns to green). Amended 2026-10-17: a bundle built at the fix's own commit is not stale for it (`merge-base --is-ancestor` is true for a commit and itself; audit Q05). Amended again 2026-10-17 (ADR-0086): a Stage 4/5 fix is judged on the build's revision, so a finalize clears it; a fix in Stages 1–3 still needs a new run | Accepted |
| [0036](0036-architecture-service-multi-utilisateur.md) | A layered rewrite is not what makes this multi-user (the reviewed proposal's diagnosis holds — `_run_pipeline` is 678 lines, SQL sits in 10 route files of 10, config is read 82 times — but it credits the boolean index with a 5 078 ms win that was 4 624 ms of filesystem, and the deployed Linux instance already answers coverage in 23 ms; `fork` is unavailable because Torch's OpenMP pool deadlocks after it, which rules out ARQ, RQ and default-prefork Celery; `INSERT OR IGNORE` is inert on `entities` because the PK is a fresh uuid4 and no UNIQUE exists; the pool is not a new decision but ADR-0002 accepted 2026-06-07 with all five action items still unticked; ordered by impact per unit of effort, so the few-line queue fix ships before the multi-week auth project) | Proposed |
| [0037](0037-scaling-to-30-40-users.md) | Scaling to 30–40 concurrent users — measure the stack before rewriting it (a Rust + PostgreSQL + Elasticsearch rewrite targets the <1 ms slice of a 5 078 ms response; `mv` to native storage delivers the bulk of it for free, and the real ceiling is 4.4 GB of model RSS per job with a 133 s cold start, identical in every language; its Measurement 2 has since been invalidated — see 0036) | Superseded in part by 0036 |
| [0038](0038-link-density-under-policy.md) | Link density under policy — the factory policy has no rules while the Policy page shows 27 (nothing seeds the DB, so Stage 4 pins nothing on a fresh install); `gap` relationships are requested from the LLM and then deleted by Stage 3d; caps are one shared counter that ADR-0024 saw hit at exactly 200; decision: backend-owned default rule set, kept `gap` edges, alias-aware endpoint resolution behind a measurement gate, per-node fan-out caps, long-distance completion on the local model; the before/after run is recorded as a procedure because the WSL distro dies at the first Stage 3 LLM call on this workstation (7 attempts, both providers) | Proposed |
| [0039](0039-per-stage-observability.md) | Per-stage observability — 18 stage modules, 6 report anything, and the ones that change the data most report least (3d deletes every unquotable relationship, 4b adds up to 200 edges, neither emits an event); 209 `logger` call sites carry no job id because the worker subprocess never sets the `request_id` ContextVar, so every pipeline line reads `[none]`; the traceback is computed then discarded in favour of `str(exc)`; a SIGKILLed job does not say which stage it died in (7 manual greps on 2026-09-02); the progress bar is `(stage / 5) * 100`, which hardcodes the count, weights a millisecond stage like a 4-minute one, and yields `NaN` for stage `"1f"`. Decision: a typed `job_stages` table written through one `stage_span` context manager that also sets the log context, times the stage, emits the event and attributes the exception | Proposed |
| [0040](0040-offline-installation-bundle.md) | Offline (air-gapped) installation bundle — `setup.sh` reaches 12 network sources (452 `.deb`, 167 wheels / 3.1 GB, 2.6 GB of models, 684 MB of corpora, Chromium, Node, an LLM); one self-contained ~13 GB bundle built by `scripts/package_offline.sh` on a twin of the target, installed by `setup.sh --offline=<dir>` through env vars (`PIP_NO_INDEX`, `HF_HUB_OFFLINE`) and pre-staged files so each step's own "already present" branch fires; checksums verified before touching the host; Python/distro coupling accepted and enforced | Proposed |
| [0041](0041-observables-route-through-indicators.md) | Observables route through their Indicator, never straight to a threat SDO — two paths still wire a raw SCO directly to malware/threat-actor/etc: the LLM relationships loop (only observable↔attack-pattern was guarded) and the policy pin engine (the *larger* source per ADR-0024, 872/1,140 edges on one report); measured 12/29 and 2/45 raw-SCO edges on stored bundles, mostly observable-to-observable (`file↔ipv4-addr`, out of scope — no single STIX answer exists for it); redirects the observable side to its Indicator only when the other endpoint is a real SDO, opt-in via a `sco_id_to_indicator` parameter so the pin engine's own budget/gating unit tests are untouched; also closes a silent gap where `NETWORK_TRAFFIC` observables never got an Indicator at all | Accepted |
| [0043](0043-self-contained-bundle-embeds-source-pdf.md) | The STIX bundle embeds the source document (`payload_bin`) — the `Artifact` object `stage4_stix_mapping.py` has always tried to build (hash + MIME type only, no bytes, "to keep the bundle compact") has never actually existed: STIX 2.1 requires exactly one of `payload_bin`/`url`, so `stix2.Artifact(hashes=...)` alone raises `MutuallyExclusivePropertiesError` and the surrounding `except Exception: artifact_obj = None` has silently swallowed it on every job ever processed, found only by checking a real bundle instead of the docstring's claim; fix embeds the source file as base64 `payload_bin` (measured ≈347 KB added for a 260 KB PDF), making the bundle self-contained | Accepted |
| [0048](0048-queue-status-endpoint.md) | A queue-status endpoint, not a metrics exporter — closes a blind spot named while documenting 0046: no purpose-built way to see backlog or worker liveness beyond `docker compose logs`. `GET /api/queue/status`, no new dependency, no auth (same posture as every other GET route); real `GROUP BY` counts (not an invented status vocabulary), oldest-queued age, and the lease made visible per worker (`heartbeat` freshness against `WORKER_LEASE_TIMEOUT_S`); rejected a Prometheus exporter as the first metrics dependency this codebase would carry, for a question one endpoint answers; validated against the live compose stack — a worker row appeared 1.1 s after upload and vanished the moment the report reached `for_review` | Accepted |
| [0047](0047-publish-image-to-ghcr.md) | Publish the image to GHCR; tag by commit and `latest` — closes the other blind spot named alongside 0048: CI builds the image and stops (`push: false`), so a second host's only path to it was rebuilding from source. GHCR over Docker Hub (already on GitHub, zero new secret — the `GITHUB_TOKEN` the workflow already has); a second job, gated on the smoke test passing and on `main` only, `packages: write` scoped to that job alone; tags `sha-<full sha>` (pins) and `latest` (tracks main); named what it can't automate — a GHCR package is private by default regardless of repo visibility, one manual click required after the first push; verified the pull-then-up mechanic against the real compose file: a pre-existing local tag skipped the build entirely, 6.4 s to running containers. Amended 2026-10-17 (ADR-0085): the inert `type=semver` lines are gone; a release tag gives the image its `X.Y.Z` and `X.Y` names | Accepted |
| [0049](0049-redos-guard-actually-wired-in.md) | The ReDoS guard becomes real: `google-re2`, and actually called — two bugs, not one, found while chasing a routine build warning: the pinned `re2` package doesn't build past Python 3.12, and `_compile_pattern`, the function that was ever supposed to route Stage 2's 19 patterns through it, was never called by any of them; switched to `google-re2` (wheels, no libre2-dev/libre2-9 — confirmed by `ldd` that it statically bundles RE2) and wired every pattern through it, mapping `re.IGNORECASE`/`MULTILINE`/`DOTALL` onto RE2's inline `(?ims)` prefix syntax; 7 of the 19 sub-patterns use lookaround RE2's syntax can't parse at all (`(?<!...)`, `(?!...)`) and fall back to stdlib `re` regardless — verified inside the built container that those 7 have no nested unbounded quantifier, so they were never exploitable by backtracking either way; identical `extract_entities()`/`refang()` output re2 vs. stdlib fallback on 9 real ingested reports (501 entities, 0 mismatches). Amended 2026-10-11: IPv4, hash blocks, the half-bracket defang and the SHA-1/MD5 labels run on RE2 with their guards in code (same output on AnnoCTR's 400 texts); the domain, bare-filename and Unix-path patterns and three sentence splitters stay on `re`, pinned by `tests/test_re2_fallbacks.py` and timed on adversarial input. Amended 2026-10-18: RE2's `\s` is ASCII, `re`'s is Unicode, so no-break and thin spaces split production from local runs; of 72 module-level `\s` patterns, 21 now say `PY_WHITESPACE` or use `str.split()`, 51 keep `\s` with a reason, pinned by `tests/test_unicode_whitespace.py` | Accepted |
| [0050](0050-cyner-generic-language-filter.md) | CyNER's Malware/Threat_group labels get a generic-language filter — a user-reported real report produced far more `malware`/`threat_actor` entities than made sense; the labels fire on any span discussing malware/threat-actor activity, not only on named entities, so `extract_cyner_entities` was accepting pure category vocabulary (`malware`, `ransomware family`, `cyber espionage`), comma-joined lists of several real names as one entity, sentence-boundary/OCR garbage, and mistagged countries; added list splitting, a ~150-word enumerated generic-token stoplist (any fragment with zero non-generic tokens is dropped), and two small denylists folded into the same check so one denylisted word cannot veto an otherwise distinct name; measured on the real job, replaying its actual captured CyNER output through the fix: 255 -> 162 raw entities (-36.5%), malware -26.4%, threat_actor -67.7%, every removed entity manually verified as noise. Amended 2026-10-18 (ADR-0088): for `Threat_group`, a second filter drops what ADR-0050's stoplist left (87 of the 97 threat-actor false positives on AnnoCTR dev were CyNER's); `Malware` is unchanged | Accepted |
| [0051](0051-calibrated-ner-thresholds.md) | NER confidence cutoffs calibrated from analyst decisions, per source and entity type — each stage applied one constant to every label (GLiNER 0.40 across six, CyNER 0.70 across two) while the store already held a labelled sample of P(correct \| score) in `entities.confidence` + `accepted`; an isotonic (PAV) fit per pair proposes the lowest score whose calibrated accept rate reaches a target precision, applied only on `--apply` / `"apply": true` into a `model_thresholds` row the stages read per type; three guards reported rather than resolved — too few decisions, no band reaching the target (a content problem, ADR-0050), and a clean band only at or above the review UI's auto-accept tier where an accept is the model's verdict echoed back; a proposal never goes below a score analysts have seen; GLiNER has one threshold for all labels, so the model is asked at the lowest and each type post-filtered. Amended 2026-10-17: observations with the same score are pooled into one weighted point before the fit, so the proposed cutoff no longer depends on the order the rows come back in (audit Q02) | Accepted |
| [0052](0052-analyst-grown-deny-and-promote-lists.md) | Deny and promote lists grown from analyst decisions — ADR-0050's hand-kept lists in `stage2d_cyner.py` are the right mechanism with the wrong feed: the review UI already records the same judgement in `entities.accepted`; an `entity_overrides` table of `deny` rows (exact whole value per type, dropped at the output of the gazetteer, CyNER, GLiNER and the LLM name lists) and `promote` rows (merged into the Stage 2b gazetteer at 0.92, same automaton, same word boundary) grown as *candidates* by two rules (rejected/accepted ≥ 3 times in ≥ 2 reports in ≥ 80 % of reviews; promote only for gazetteer types, unknown to it, ≥ 4 chars, not generic vocabulary) and applied only once a person activates them — a wrong deny is a false negative in every report after, a wrong promote a 0.92 false positive the UI auto-accepts, so the same gate for both | Accepted |
| [0053](0053-postgresql-only-sqlite-removed.md) | PostgreSQL only: the detection-rule corpus moves off SQLite, and SQLite is removed entirely — reverses part of 0037/0045's "the FTS5 corpus cannot move" on the strength of what those ADRs' own reasoning actually required: every `MATCH` call site is a quoted-phrase lookup (brand tokens, CVE ids), not free-text ranking, so `to_tsvector('simple', ...)` + `phraseto_tsquery` gives the same word-boundary, non-substring semantics FTS5 was chosen for; the one `INDEXED BY` planner hint (`_also_in_map`, ADR-0022) defeated a SQLite-specific no-`ANALYZE` planner quirk PostgreSQL's cost-based planner doesn't share, so it is dropped, not translated; `DATABASE_URL` becomes mandatory everywhere (API, worker, test suite — `main.py`'s batch CLI is untouched, it reads neither store); `rule_text` becomes a plain table with a `GENERATED ALWAYS AS` `tsvector` column instead of an FTS5 virtual one; six upserts rewritten to `ON CONFLICT`, matching the treatment 0045 already gave the job store; a new `migrate_rules_to_postgres.py` sibling to `migrate_jobs_to_postgres.py`; ~20 peripheral audit/measure scripts that bypassed `api.db` converted, catching a few already-latent bugs (`instr()` with no PostgreSQL equivalent, `rowid`-based ordering, a `.cursor()` call that skipped placeholder translation) along the way; validated: 1377 tests green against a live PostgreSQL server, 0 failed, including new coverage for the exact cases most at risk — the `reat`-inside-`threat`/`great` non-substring regression ADR-0031 was written to fix, and a hyphenated CVE id, both previously untested because a bare fixture table without a real `rule_text` made the existing brand/CVE tests pass vacuously | Accepted |
| [0046](0046-worker-container.md) | The worker is a container of its own; the `jobs` table is the queue — `CTIPARSOR_ROLE` (`all` keeps the single-process host install, `api` only enqueues, `worker` runs `python -m api.queue_loop`); the existing conditional-UPDATE claim was already atomic on both engines, what was missing for several workers was a lease (`worker_id`, `heartbeat_at`, requeue after `WORKER_LEASE_TIMEOUT_S`) since the old `requeue_orphans` reset every `processing` row; same image, `command: worker`, scalable with `--scale worker=N`; every compose service now carries measured CPU/memory limits (worker 4.4 GB per report + 1 GB); no broker, `FOR UPDATE SKIP LOCKED` deferred as an optimisation; validated: 1206/1214 tests green on SQLite/PostgreSQL, a report processed by the worker container while the API spawned nothing | Accepted |
| [0045](0045-postgresql-for-the-job-store.md) | PostgreSQL for the job store, SQLite kept for the rule corpus — the maintainer brought ADR-0037's Option C forward without waiting for authentication; measured: 213 SQL sites but only 7 SQLite-only statements on the per-job tables, every row read by name, no `%`/`LIKE` in that SQL, so a 165-line adapter (`?`→`%s`, a `sqlite3.Row`-like tuple, a wrapper whose `with` never closes) replaces an ORM; `DATABASE_URL` unset = today's single file, set = eight tables move; the FTS5 corpus cannot move (`MATCH`, `INDEXED BY`) and stays; the coverage code is the one place both stores meet and gains a `jobs_conn` parameter; a migration script copies an existing store in one transaction, ids preserved, sequence realigned; the compose stack gains a non-root, capability-less, read-only `postgres:17-alpine` on the internal network; validated: 1206 tests green on PostgreSQL, 1198 on SQLite, 47 rows migrated inside the container, a report processed through the API to a 53-object bundle | Accepted |
| [0044](0044-container-images.md) | Container images: one hardened application image, not a database tier — the requested "PostgreSQL + app" split has nothing to hold on the DB side (SQLite is opened in-process, ADR-0037 defers PostgreSQL until authentication) and a separate worker needs a broker ADR-0002/0036 rejected; one 3-stage image (4.48 GB, 3 min 24 s cold build), two volumes (`cti-state` precious, `cti-cache` rebuildable), compose profiles `bootstrap` / `ollama` / `proxy`; runs as uid 1001 on a read-only root with every capability dropped — the Chromium sandbox stays ON through a seccomp profile that had to allow `chroot` unconditionally (Playwright's stock profile gates it on `CAP_SYS_CHROOT`; measured `Check failed: sys_chroot("/proc/self/fdinfo/")`); found `libmagic1` missing from slim images and the optional `re2` pin unbuildable on Python 3.12 | Accepted |
| [0042](0042-embedded-yara-rules-as-indicators.md) | Embedded detection rules (YARA, Suricata, Snort, Sigma) become Indicator SDOs — CTI reports routinely publish a literal rule inline (verified: 4 complete YARA rules in one real Google TIG report), and none of it survived past ingestion; STIX 2.1's `Indicator.pattern_type` already models all four natively, so the work is extraction — reuses `yara_atoms.split_rules` and `suricata_atoms.rule_header`/`parse_options` (ADR-0015's own corpus parsers, validated at ~20,000-rule scale) unchanged; Sigma gets a new grow-then-shrink YAML boundary heuristic since it has no self-delimiting rule-end marker, fail-closed (must parse as valid title+detection YAML) and unvalidated against any real report, unlike the other two; auto-links to an already-extracted malware/tool by name substring (`x_evidence_label: "observed"`) — measured wrong on the first check (raw Stage-3 output) and right on the second (the DB-merged entity list `build_stix_bundle` actually sees, where CyNER had already found all 4 names) | Accepted |
| [0062](0062-observables-keep-their-listed-relationships.md) | An observable keeps the relationships STIX 2.1 defines for it (amends 0041) — 0041 routed every observable opposite an SDO through its Indicator *before* the verb check, so `malware communicates-with domain-name`, `malware drops file`, `infrastructure consists-of <SCO>` shipped as `related-to` an Indicator (the ledger showed the seeded Industroyer2 row rewritten twice; on 7 re-extracted real reports, 3 of 150 extracted rows and, under the Policy page's template, 304 of 1,245 pinned edges); now routed only when the verb is not *listed* for the direct pair — listed, not "suggested", since `related-to` is always suggested and would undo 0041's own case — judged on the verb after the direct pair's policy pin, in the semantic loop and the pin engine alike; the reverse direction is not flipped | Accepted |
| [0063](0063-relationship-dates-keep-what-the-source-said.md) | A relationship date keeps what the source said — the prompt allows `2021`/`2023-03` and `dates.py` pads them to a 1st, so "active in 2021" as start = stop is dropped whole by the `stop <= start` guard; the date has no quote of its own and 3d overwrites the one it shared; captured URLs, pasted text and HTML reach Stage 3 with no anchor although the page's `datePublished` was in the browser, while the anchor PDFs get is their print time; the reload path drops `2023-03` silently (`fromisoformat`). Decision: `TemporalAssertion` records (role, verbatim `time_text`, unpadded EDTF value, precision, anchor with its source) in a side table; the model names and places, the code locates, normalises, resolves relative dates and computes the status (`verified`/`ambiguous`/`unresolved`/`conflict`); merge takes the union, counting one occurrence once; export `faithful` by default (native bounds only for verified instants), `day` projection as a labelled option, everything else in `x_temporal_assertions`, each decision in the ledger; AnnoCTR's unused TimeML layer (1 129 in-text dates, 61.6 % year or month) picks the normaliser on train+dev. Implemented 2026-09-29: on 7 re-extracted real reports 26 % of relationships were dated, 43 % of the bounds on a 1st ("April and June 2026" → `2026-04-01 → 2026-06-01`), only 57 % with their year in the relationship's quote; rules-only normaliser 99.2 % right when it reads on AnnoCTR test (87.9 % read); a `times_json` column, context-placed occurrences and ledger `times` beside `changes` replace the side table, chunk offsets and `changes` entries the proposal named | Accepted (Phases 0–3) |
| [0064](0064-whole-document-relation-steps-read-the-whole-document.md) | The whole-document relation steps read the whole document (amends 0057). Found by comparing with Stixify/txt2stix, which makes one relations-only call over the whole text. The three steps meant to see past a chunk read only a prefix: the 0057 document pass was cut to 32 000 chars by `_call_llm`, losing its entity list and answer format past ~30 000; Stage 3d (and 3f) sent `text[:3_500]`, so it removed document-level claims supported later and never saw the tail of long reports' chunks; 4c read 6 000 chars. Now: a per-call limit that cuts the report text, never the instructions; 3d/3f get the whole text, 3d in batches of 40 with a document mode (a second sentence may only say who the subject is, never a chain); 4c sends the passages naming either entity. Measured on 7 reports, one series of calls, blind-judged sample of 125: chunks only 195 relations at 0.81 strict precision; document pass only (txt2stix's organisation, run with CTIParsor's prompt, entities and 3d — not txt2stix itself) 309 at 0.51, the same ≈157 correct but mostly different ones; both 434 at 0.58 with ≈253 correct (+60 %). The old 3d kept 71 of 336 document relations, the new one 309. The document pass stays opt-in: at ~15 tokens/s its answer on a 37 000-char report outgrows the shipped `LLM_TIMEOUT`/`LLM_MAX_OUTPUT_TOKENS` | Accepted (document pass stays opt-in) |
| [0065](0065-review-what-nobody-decided-and-ioc-indicates-technique.md) | Review shows what nobody decided; an IoC indicates a technique through its Indicator (amends 0012). An analyst could not make an IoC → technique link ship: the form offered all 35 verbs, and Stage 4 dropped every observable ↔ attack-pattern edge before the 0041/0062 Indicator routing. Reproduced: an accepted `link.ps1 indicates Group Policy Modification` was dropped, although STIX lists `indicator indicates attack-pattern`. Now `indicates` is routed through the Indicator (turned around if written backwards); other verbs stay dropped; the form offers only `indicates` and searches ATT&CK ids. The pipeline stores every relationship accepted as `default` (0058), so the rail's "pending" read 0 on all 7 real reports while 150 rows shipped. "To review" now counts what no analyst decided; rows sharing a target are grouped and decided in one click (`POST /relationships/bulk`, journaled `human_bulk`). Edges with no review row (IoC → malware associations, targeted locations, completion, pins) are listed, not changed | Accepted |
| [0066](0066-stix-ids-are-opencti-standard-ids.md) | STIX ids are OpenCTI's standard ids. The validator's {103} "not UUIDv4" warning hid a MUST NOT: domain objects were UUIDv5 under the namespace STIX reserves for observables, from a key only CTIParsor computed. The maintainer asked to do what OpenCTI does; OpenCTI (platform `generateStixId`, pycti `generate_id`) uses the same namespace with canonical JSON of a few normalised properties per type. `pipeline/stix_ids.py` reproduces pycti exactly (15/15 ids identical, run from the OpenCTI source), so a bundle lands on the technique, sector, country and built-in PAP marking OpenCTI already holds; incidents keep a name-only id (pycti hashes the build time); relationships and the Report stay random UUIDv4. The {103} and {302} warnings stay by design, as on OpenCTI's own exports; every SDO, indicator and marking id changes once | Accepted |
| [0067](0067-quoted-yara-rules-ship-only-if-they-compile.md) | A YARA rule quoted in a report ships only if it compiles. OpenCTI checks a YARA Indicator with `yara.compile()` (yara-python 4.5.4) and refuses it, then every edge to it: the INDUSTROYER.V2 PDF lost 2 rules and 14 edges because the print layout cut a `meta` string. Stage 4 rejoins a cut `meta` string, adds an `import` the report declares outside the rule, compiles with the same yara-python, and leaves out what still fails, with the compiler's message in the ledger; a cut `strings:` text string is never guessed. Without yara-python the rule ships as `unverified` | Accepted |
| [0068](0068-an-indicator-does-not-inherit-its-malwares-techniques.md) | An Indicator does not inherit its malware's techniques. Stage 4b composed indicator indicates malware + malware uses technique into indicator indicates technique: 12 of the 29 edges of the INDUSTROYER.V2 bundle, 91 edges across the stored bundles (uses+uses: 5). A YARA rule or a hash detects the malware, not each technique it uses. The composition is removed for every Indicator; indicates+variant-of stays, and an analyst or report can still state IoC indicates technique (ADR-0065) | Accepted |
| [0069](0069-the-ui-the-policy-and-stage5-say-what-ships.md) | The UI, the policy and Stage 5 say what ships (review of 2026-10-02, points 1, 2, 5, 7, 9). One rule for "ships as written", verb_ships_as_written in Stage 4 and shippedVerbs in the frontend, both held to a generated 33x33 matrix; duplicate-of/derived-from only for a same-type pair. The policy API refuses unknown types or verbs, a second rule for a pair, and a pinned verb that would ship as related-to. Stage 5 returns validated / unverified / invalid with the warnings, from schemas pinned to one commit. NETWORK_TRAFFIC becomes a real network-traffic to its destination instead of Software. Not done: av-analysis-of (CSD only; OpenCTI uses analysis-of), custom verbs (OpenCTI refuses them). Amended 2026-10-10: the JSON schemas ship with the repository and the image installs them at build time; Stage 5 downloads nothing, and bundles are validated in full | Accepted |
| [0070](0070-quoted-sigma-suricata-snort-rules-ship-only-if-opencti-parses-them.md) | Quoted Sigma, Suricata and Snort rules ship only if OpenCTI parses them (pysigma 1.5.0, parsuricata 0.4.1, OpenCTI's own Snort parser copied unmodified). Measured on 2,000 ET Open and 1,000 SigmaHQ rules quoted through a PDF-like layout: the 20 truncated Suricata rules still extracted and 14 of 110 Sigma rules are refused; OpenCTI's Snort parser refuses 1,833 of 2,000 ET rules (http/dns/tls), which ADR-0042 typed snort whenever the word preceded them. A refused rule is left out with the parser's message; a net rule only the other dialect's parser accepts is retyped | Accepted |
| [0071](0071-ci-blocks-on-every-deterministic-check.md) | CI blocks on every deterministic check, and `make ci` runs the same (review of 2026-10-02). Tests write under `tmp_path` (`api/paths.py`); `eval_pipeline.py`, the OpenCTI parser tests and the re2 guard run in the fast job, where a missing test dependency fails; branch coverage floors 87 % total, 92 % STIX, 91 % persistence; one ruff/mypy scope in `pyproject.toml` (scripts/ had a NameError), mypy `check_untyped_defs`; ESLint with the hooks rules; a `dev` image stage with the CI tools. Making the parser tests block found parsuricata failing to import in the image (lark 1.x from jsonschema 4.25 overwrote lark-parser): every Suricata rule shipped unverified; jsonschema is held below 4.25 | Accepted |
| [0072](0072-ttp-retrieve-then-select.md) | TTPs: retrieve candidates from ATT&CK procedures, ship only what a selector can quote (ADR-0023 Phases 4–6). A versioned corpus of 697 full descriptions + 16,653 procedure examples, names neutralised; BM25 ⊕ dense fused per technique; on AnnoCTR dev parent recall per passage at k=5 goes from 0.33 (today's 300-character descriptions, dense, keyword gate) to 0.77 (both corpora, RRF, no gate), 0.95 at k=25. `TTP_MODE=select`: 2c emits candidates only, 3f selects among them and the LLM's proposals with a quote checked by code, a failed call ships nothing. 48 MITRE examples cite AnnoCTR reports (28 test) and are excluded from evaluations. Default since its dev run: technique F1 0.465 → 0.607 against the 2c-off configuration (docs/eval/baseline-2026-10.md). Amended 2026-10-19: a selection answer cut off at the token limit keeps its complete choices, each checked as before (docs/eval/selection-cut-off-2026-10.md). Amended 2026-10-20: the selection call has its own output ceiling (`TTP_SELECT_MAX_OUTPUT_TOKENS`, 4,096 on vLLM with thinking off) and the stage report counts the answers the provider stopped there, while a prompt that bounds `reason` was measured and not adopted (docs/eval/selection-loop-2026-10.md). Noted 2026-10-24: a narrower prompt asking only for the answer once was measured and not adopted (docs/eval/selection-once-2026-10.md) | Accepted (select mode is the default) |
| [0073](0073-tlp-fail-closed-and-amber-strict-as-opencti-defines-it.md) | A TLP marking is never guessed: `TLP:AMBER`, `amber+strict` and `white` normalise, anything else raises at API, worker and CLI start; the default is AMBER (was CLEAR); AMBER+STRICT ships as OpenCTI exports it (`definition_type: "TLP"`, OpenCTI's extension and static id) because stix2 refuses any `tlp` marking outside the four spec objects — two SHOULD warnings accepted by choice | Accepted |
| [0074](0074-report-text-is-delimited-data-not-redacted.md) | Report text reaches every LLM call between `<<<REPORT n>>>` / `<<<END REPORT n>>>` markers the system prompt names (spotlighting; `n` is a hash of the text, so prompts stay reproducible at temperature 0). The sanitiser deletes nothing the report says: no more tag stripping or `[REDACTED]` (it erased a T1480 description and `<iframe src>` IoCs, and missed synonyms and other languages); invisible characters are removed and chat-template markup defused (the `im_end` marker written in a report became the real end-of-turn token on vLLM), both counted | Accepted |
| [0075](0075-verifiable-supply-chain.md) | A verifiable supply chain: the Dockerfile's base images pinned by digest like compose's; Dependabot for actions, images and npm (not the uv-compiled Python lock); a blocking `dependency-audit` job (pip-audit on the lock as written, npm audit on production packages) that `publish-image` needs, accepted vulnerabilities listed in SECURITY.md (diskcache, unreachable); CodeQL; the GHCR image gets a CycloneDX SBOM and signed provenance and SBOM attestations. Hashes in the lock: ADR-0080. Amended 2026-10-17 (ADR-0085): a release promotes the attested image by digest, and its files carry an SLSA provenance | Accepted |
| [0076](0076-postgresql-18-on-a-new-volume.md) | PostgreSQL 18 (Dependabot #98): the 18 image refuses the old `/var/lib/postgresql/data` mount and cannot open a 17 cluster, so compose mounts a new volume, `pg-data-18`, at `/var/lib/postgresql` (re-mounting `pg-data` would start an empty cluster beside the 17 files, silently); `scripts/upgrade_postgres_17_to_18.sh` moves the data by `pg_dump`/`pg_restore` with a per-table row-count check, refuses to overwrite, leaves `pg-data` as the way back; CI tests 18 | Accepted |
| [0077](0077-versioned-database-migrations.md) | The database knows its version: `schema_migrations` and a history of one module per version since the first PostgreSQL job store (9 rebuilt from git), each with its statements, an optional data step and its own verification; the API, every worker and `bootstrap` bring the database up to date at start under an advisory lock, one transaction per version, recognising the version of a database created before the history; a newer database or an edited migration stops the start. Engine majors (part B): the 18 image already refuses to start beside another major's cluster (checked; no entrypoint of ours); the state volume records each database's cluster and an empty database on a new cluster where data existed stops the start; `make db-upgrade` moves any major by dump, restore and row counts, in both volume layouts; CI migrates a database written by the PR's base commit | Accepted |
| [0078](0078-repository-security-settings-and-workflow-hardening.md) | Repository security beyond ADR-0075: every action pinned to a full SHA (Dependabot updates it), read-only tokens by default and no persisted checkout credentials; CodeQL also analyses the workflows; Grype scans the image's OS packages into Code scanning (fixable CVEs, not blocking); dependency review fails a PR adding a high-severity vulnerability; a weekly CI run; OpenSSF Scorecard (badge, not in Code scanning). Settings by the maintainer: Dependabot alerts (security updates off for the uv lock), private vulnerability reporting, a `main` ruleset (PRs, green checks, no force-push, CodeQL high gate), then required SHA pinning. Amended 2026-10-10: the Scorecard checks still below 10 and why (Code-Review and Contributors by construction; the ruleset and the Best Practices badge are maintainer actions); a GitHub Release scores 0 on Signed-Releases without signed or provenance assets; the ruleset and private vulnerability reporting are still off; the four fuzz jobs are required checks too. Amended again 2026-10-10: the settings as applied (ruleset active with 13 required checks and a CodeQL medium-or-higher gate; Dependabot security updates kept on; Grype not gating; two rules that would have blocked every PR removed). Amended 2026-10-17 (ADR-0085): a Release now attaches the `*.intoto.jsonl` Signed-Releases looks for | Accepted |
| [0079](0079-python-3-14.md) | Python 3.14 for the image, CI and the lock (3.12 got seven CVE fixes only on newer branches; 3.14.8 clears five, the other two are 3.15-only and unreachable); onnxruntime 1.20.1 → 1.30.0 (no 3.14 wheel); yara-python compiled from source with `libssl-dev` (no 3.14 wheel, and without OpenSSL the build silently drops `hash` and PE signatures; a test now asserts them); Debian 12 kept, trixie to revisit | Accepted |
| [0080](0080-hash-locked-installs.md) | Every `pip install` checks hashes (`--require-hashes`): four locks from `make lock` (image from PyPI, torch's CPU build from the PyTorch index alone, CI's fast-test set at the image's versions, pip-audit); torch installed first with `--no-deps`, everything else from PyPI only, because the PyTorch index re-hosts markupsafe, jinja2 and colorama with other bytes (the first hashed build caught pip taking its markupsafe); PyPI pins get PyPI's published hashes (`scripts/lock_pypi_hashes.py`); no unhashed pip upgrade. Amended: diskcache not shipped; the uv `make lock` runs gets a fifth hashed lock. Amended 2026-10-10: the files move to `requirements/` and the six lists become four (`requirements.txt` the light runtime, `requirements-full.txt` the image; no hand-kept CI list), the locks unchanged | Accepted |
| [0081](0081-fuzzing-the-attacker-facing-parsers.md) | Atheris fuzzing of the code that reads attacker-controlled input: report text (refang, extraction), dates, the rule gates (Sigma, Suricata, Snort, YARA with libyara, STIX literals) and the prompt enclosure (each marker once, report only cut, question intact); 60 s a target per PR, 10 min weekly, failing input uploaded; a seed test keeps the targets alive in the ordinary suite; not ClusterFuzzLite (its Python trails 3.14) | Accepted |
| [0082](0082-what-the-model-could-not-decide-waits-for-an-analyst.md) | What the model could not decide waits for an analyst (amends 0058, 0065, 0072). Stage 3d kept every claim it did not explicitly refute — failed call, unreadable or silent answer, missing verdict, a quote not in the text — and they shipped as verified; select mode's `ttp_review` reached only the evaluation record. Both are now stored pending with a `held_reason` (migration v0010), out of the bundle until an analyst accepts them on their own card: auto-accept, type, group and selection accepts skip them, a `human_bulk` accept is refused. One predicate, `decisions.SHIPS`, for finalize, coverage and rule relevance. Quotes are checked word for word, Markdown aside (179/181 dev quotes; the rest are not quotes) | Accepted |
| [0083](0083-a-hashless-file-keeps-its-path-in-name.md) | A file named without a hash keeps its path in `name`, as OpenCTI identifies it. STIX 2.1 would split the path into a Directory (`parent_directory_ref`, an id-contributing property), but OpenCTI identifies a hashless StixFile by `name` alone (`identifier.js`: `(!) extensions, parent_directory_ref`): the split would merge the `svchost.exe` dropped in `C:\Users\Public` with the legitimate one. The behaviour CTIParsor already had is recorded as a choice (audit B 8.1.12); its ids equal OpenCTI's standard ids, measured. A strict STIX export profile would split | Accepted |
| [0084](0084-a-bundle-stage-5-refuses-is-not-served.md) | A bundle Stage 5 refuses is not served, and never completes a job (amends 0069; audit of 2026-10-17, Q01). `validate_and_export` returned `validated`, `unverified` or `invalid`, and nothing read it: the initial run stored the bundle unread, finalize dropped the return value and marked the job `completed`, `GET /bundle` served whatever was stored, and only the file on disk got an `_invalid` suffix. Migration v0011 stores the verdict (`jobs.bundle_validation`) and the first 20 errors (`bundle_validation_errors`) in the same `UPDATE` as the bundle; `NULL` is unknown and served as before, with no backfill. An invalid bundle leaves the status alone (a `completed` job goes back to `for_review`); `GET /bundle` answers 409 with the errors, and a 200 carries `X-Bundle-Validation`; finalize, and `PATCH` to `completed`, answer 409. Rejected: keeping the old valid bundle with the candidate stored apart (more columns and a "bundle older than your edits" state), and 422 (FastAPI's request-validation code, with a list `detail`). Concurrent finalization is not addressed here; ADR-0086 orders it | Accepted |
| [0085](0085-releases-promote-the-image-main-built.md) | Releases promote the image main built, and sign the files they add (amends 0047, 0075, 0078). There was no version: FastAPI and `frontend/package.json` both said `1.0.0`, backed by nothing; no tag, no Release; ADR-0047's two `type=semver` lines never ran, because `ci.yml` never runs on a tag. A release is now a tag `vX.Y.Z` on a commit of `main` whose CI passed. `release.yml` rebuilds nothing: it gives the image main's CI attested for that commit the names `X.Y.Z` and `X.Y` from its digest (same digest, verified), signs an SLSA provenance of the source archive and the image's SBOM, and publishes the Release (draft, files, public). The version has one source, `pipeline.__version__` (`0.0.0` until the first release), and `scripts/release.py` checks the tag against it, `frontend/package*.json` and the CHANGELOG, writes the notes (a list of entries when the section exceeds 100 000 characters: `[Unreleased]` was 244 547 before this change's own entry) and prepares the release pull request. A pull request that touches the machinery, and a weekly run, get a dry run, nothing published. The checks catch mistakes, not a person who can push a tag: only the tag ruleset stops that. Rejected: a rebuild on the tag, slsa-github-generator (needs a tag reference; actions are SHA-pinned), release-please, the version in `pyproject.toml`, PyPI, pre-releases. Maintainer settings, recommended: a `v*` tag ruleset and immutable releases. Not done: `check_migration_from.py` from the last release tag. Amended 2026-10-24: v0.1.0 as published on 2026-10-17 (tag on 4bdfa8f; its files and image verify with the pinned commands; `0.1.0`, `0.1` and `sha-4bdfa8f…` name one digest); immutability turned on after it, so v0.1.0 is not immutable; no tag ruleset yet; Signed-Releases 10 | Accepted (v0.1.0 released; tag ruleset not set) |
| [0086](0086-a-bundle-names-its-build-and-a-slower-build-does-not-overwrite-it.md) | A bundle names the build that made it, and a slower build does not overwrite a newer one (amends 0059 and 0035; audit of 2026-10-17, lot L1). A finalize rebuilt Stages 4–5 with the current policy, data and code but recorded nothing: `run_config_json` still described the run, so a rebuild never cleared a Stage 4 staleness, and overrides were recorded as counts. It also read its rows, released the lock for the mapping and wrote unconditionally, so a slow finalize could publish over a newer one (reproduced by a test first). Migration v12: `jobs.review_revision`, bumped by a row-level trigger on `entities` and `relationships` in the transaction of each write; `bundle_review_revision`, the revision the stored bundle was read at; `bundle_build_json`, its build record (kind, time, `git_rev`, policy, allow-listed env, manifest). A finalize reads one `REPEATABLE READ READ ONLY` snapshot and publishes bundle, ledger, verdict, record and revision in one conditional `UPDATE` (`WHERE bundle_review_revision IS NULL OR bundle_review_revision <= R`); a refused build returns the stored bundle, a full finalize completes the job with it unless its verdict is invalid (then 409 with the stored errors). `entity_overrides` gains a content fingerprint. `BUNDLE_AFFECTING` gains a scope: `mapping` fixes are judged on the build (a finalize clears them), `extraction` fixes on the run and the build (only a new run does). Rejected: explicit bumps in each write path, `max(review_decisions.id)`, a hash of the rows, holding `_lock` through the mapping, retrying a refused finalize. Cost: 5,000 entity `INSERT`s took 0.66 s with the trigger, 0.16 s without (2026-10-17; 0.78 s and 0.21 s when remeasured on 2026-10-18). Policy, data and code changes are not decisions and do not bump the revision. Amended 2026-10-18: only a build that publishes writes the export file (a refused build overwrote the newer build's file, and a finalize ending after `_delete_job` recreated the deleted one; Stage 5 is split into `validate_bundle`, `export_path` and `export_bundle`, and the file is written inside the transaction of the publishing `UPDATE`); the trigger stays per row (a statement trigger with transition tables took 1.03 s against 0.78 s for 5,000 `executemany` inserts, 0.21 s with no trigger); the store audit checks that no `bundle_review_revision` exceeds its job's `review_revision` | Accepted |
| [0087](0087-an-attack-release-is-a-track-a-run-selects.md) | An ATT&CK release is a track a run selects (audit of 2026-10-17: add a v20 track without replacing the experimental snapshots, which would mix the system's evolution with the change of taxonomy). ATT&CK v20.0 came out on 2026-10-13 and no shipped file said which release it came from: the retrieval corpus's manifest read `attack_version: null`, and `scripts/download_attack.py` without an option now fetches 20.0 from the mitre/cti master, which would have changed the evaluation's gold mapping while the pipeline's index stayed on 19.2. Each shipped file was rebuilt from the official v19.2 assets and compared: the index, the revoked table, the retrieval corpus and both embedding sets match 19.2; the gazetteer (14 name variants short) and the curated relationships (237 pairs short, 1 extra) predate it; the 615 CAPEC entries come from a bundle whose version was not recorded. `pipeline/data/` stays the default track, named 19.2 by a new `attack_manifest.json`; a track `pipeline/data/attack/<X.Y>/` (v20.0 ships, 39.9 MB) is selected per process by `ATTACK_RELEASE`, and an unknown value stops the run instead of falling back (ADR-0073's rule for TLP). The run manifest gains an `attack` block and hashes the files actually loaded, and the Stage 3 checkpoint carries the release. `download_attack.py --release` and `build_attack_release.py` fetch and build a track from assets checked against the sha256 GitHub publishes. The evaluation maps the gold against one release (`--attack-release`), and `attack-diff` and `release-effect` split a score change into taxonomy and system. The default does not change: that asks for ADR-0060's paired comparison on dev. Rejected: replacing the shipped files, moving the default track into a directory, the mitre/cti master bundle, a fallback for an unknown value, a track nobody commits. Amended 2026-10-19: the interface reads the selected track's index from `GET /api/attack/index` (release in `X-Attack-Release`, ETag the file's sha256), and the static `frontend/public/mitre_index.json` is removed (written by no script; 39 tactics instead of 41, domains spelled `enterprise`); the Coverage column check runs on every committed track | Accepted |
| [0088](0088-cyner-actors-and-spacy-places-must-look-like-names.md) | A CyNER threat actor and a spaCy place must look like a name (amends 0050; audit of 2026-10-17, entity precision). On AnnoCTR dev most false positives came from two models: CyNER gave 87 of the 97 threat-actor ones ("cybercriminals", "underground forums", "Chinese threat actors", "Iran"), spaCy's `GPE` label gave most location ones ("C&C", "XSS", "GitHub") and returned "the United States" with its article, which Stage 4's ISO table does not know. `pipeline/ner_precision.py`, switch `NER_PRECISION_FILTERS` (default true; `false` restores the old output, identical on 70/70 train and 16/16 dev documents when replayed). CyNER `Threat_group` only: a fragment is dropped when it has no capital letter and no digit in a text written with capitals, is a country, or has only category words, software names, nationalities or countries (ADR-0050's 141 words, 178 more read in the train false positives); words that form real names (agent, crew, circles, miner) stay out. spaCy locations: put on one line, "the" and a trailing apostrophe dropped, then kept only if they can be a place (no "C&C", acronym of 5 letters or fewer, camel case, category word). Both run before the case-insensitive dedup, so a capitalised spelling outlives a lowercase one. Designed on train, criteria G1–G6 fixed before any dev figure (ADR-0060), then a real dev run with the LLM against a baseline of the same commit, test split not read: threat-actor precision 0.134 → 0.326 (+19.2 [+11.4, +30.9], recall 0.938 unchanged, 15 TP / 97 FP → 15 / 31), location precision 0.406 → 0.526 (+12.0 [+5.1, +18.9], recall 0.402 → 0.412, 39 / 57 → 40 / 36), malware and identity unchanged. Rejected, each under the +5-point gate on its own: the same rule for CyNER's malware (+2.6), reducing "Ryuk ransomware" to "Ryuk" and splitting on brackets (+1.2 actors, +3.0 malware), dropping spaCy's PRODUCT → malware (+3.5); all four leads together gave +13.2 on malware offline, but that was read after the measurement and would have to be registered as one lead and measured on unread data. Also left out: spaCy's label majority, a link-host test for places, a country list as the only place test, a higher CyNER threshold (ADR-0050: no cutoff separates them). The commit is added to `BUNDLE_AFFECTING` with scope `extraction` by a follow-up commit. Known losses: a lowercase-only name in a cased report, "Iranian Cyber Army", "Pakistan Cyber Army"; vendor names that look like towns remain places | Accepted |
| [0089](0089-the-malware-lead-measured-once-on-test.md) | The malware lead, registered as one lead and measured once on test (amends 0088). ADR-0088 left malware precision at 0.205 on dev because each of three malware leads stayed under its +5-point gate alone, and their joint +13.2 was read after the fact. Registered as one lead behind `NER_PRECISION_MALWARE` (ADR-0088's ordinary-language rule for CyNER's malware; a name with its category around it reduced to the name, brackets split, the higher confidence kept; spaCy's PRODUCT no longer malware), frozen at `ccb9edf` with criteria M0–M5 fixed before two real runs on the AnnoCTR test split (chosen by the maintainer over in-house annotation and a post-hoc dev decision; docs/eval/ner-malware-2026-10.md). Result, 34 of 34 reports: malware precision 0.194 → 0.389 (+19.5 [+14.5, +24.9], 3 gold gained, none lost), threat actors +5.0, but locations −4.2 precision and −4.5 recall (M4b fails): the LLM, given other CyNER names, listed countries where it had listed the nationality adjectives AnnoCTR annotates in one report; Stage 2 offline changes no location. Not adopted, code removed, not measured on test again. The baseline gives ADR-0088's first test figures (threat actors 0.259, locations 0.505). Harness kept: `scripts/measure_ner_precision.py` | Rejected |
| [0061](0061-bundle-view-and-mapping-ledger.md) | The Graph page drew the review rows, never the bundle — on the stored bundles 80–100 % of the edges had no row behind them, rows were rewritten (verb → `related-to`, observable → its Indicator) or dropped with no trace; Stage 4 now writes a mapping ledger beside the bundle (what each row became, was merged into, or why it was dropped; why each object and edge exists), served at `/bundle/ledger`; the graph defaults to a bundle view with links coloured by origin, dropped rows as ghosts and a Differences panel; Graph-page edits rebuild the bundle; `indicator based-on` now targets the SCO directly and ObservedData is gone | Accepted |
| [0060](0060-evaluation-protocol.md) | Evaluation protocol: AnnoCTR (120 reports with the cyber layer, official temporal split, per-document annotated-layer registry, ATT&CK ids mapped on both sides through `revoked-by`) plus an in-house set annotated from the original files (IoCs, relationships, negative cases); parent-level TTP F1 as primary score, paired bootstrap between configurations, decision rule fixed before test; the first runs found every Stage 3 call 404ing on a mis-set model name while Stage 3 reported success, so Stage 3 now counts provider failures and is `failed` when all fail; `LLM_TEMPERATURE`/`LLM_SEED` added | Accepted |
| [0059](0059-one-pipeline-for-every-entry-point.md) | The API worker, the CLI and the ATE `full` benchmark ran three different stage sequences (the CLI skipped every NER stage, the benchmark sent the whole text as one chunk and silently dropped the LLM); `pipeline/orchestrator.py` is now the one sequence, with hooks for what differs (job store, progress, lease, crash-resume) and a per-stage report (ran / skipped / failed and why); `--stage full` refuses a run without the LLM unless `--allow-degraded`; the Stage 3 checkpoint resumes only on a matching fingerprint (text, model, prompts), not a matching chunk count; run config gains a reproducibility manifest. Amended 2026-10-17: the manifest also records the output-shaping settings, the remaining data files, the validators' packages and the per-provider model names, and a test fails when a file of `pipeline/data/` is not fingerprinted (audit Q04). Amended again 2026-10-17 (ADR-0086): a finalize records its build (`jobs.bundle_build_json`) and publishes only if no newer build is stored | Accepted in part |
| [0058](0058-decision-provenance.md) | Records who decided every accept/reject (`decision_origin`: human, human_bulk, auto_policy, default, propagated, legacy) plus an insert-only `review_decisions` journal; auto-accept moves from the review page — which wrote accepted=true through the analyst PATCH just by opening a report — to the worker; a 10 % control sample stays pending so analyst verdicts measure auto-accept; calibration reads only one-at-a-time human decisions and promotion only human accepts (the LLM name lists, stored at 0.9, were all auto-accepted and counted toward promotion). Amended 2026-10-17: the lexicon rescan that wrote `propagated` is removed (it could never insert a row); the value stays for older rows (audit Q03) | Accepted |
| [0057](0057-document-level-relation-extraction.md) | Adds one extra opt-in Stage 3 LLM call per report (`ENABLE_DOCUMENT_LEVEL_RELATIONS`) that reads the WHOLE document (not a ~3000-char chunk) and the full known-entity list to find relationships whose two supporting facts sit in different chunks — relations only, not a re-run of entity discovery (measured worse full-document); needs no new merge logic, its output is just another per-chunk-shaped result appended before the existing dedup pass; a first prompt draft ambiguously read as "don't relate to IOC/TTP entities" and silently found only 12 relationships instead of 88 on the same report — caught by testing against a real report before shipping, documented as a worked example of exactly this kind of silent-failure risk | Accepted |
| [0056](0056-domain-file-tld-exclusion-sync.md) | Fixes the largest single pattern ADR-0055's real-corpus measurement surfaced: 137 cases (of 12 reports) where the regex IoC layer typed the same string both `domain` and `file` — 126 were bare ".com" strings (a real domain TLD but also a legacy DOS executable extension in the bare-filename allow-list) and 11 were extensions (.msi/.pl/.sys/.cmd/.app) present in the filename allow-list but missing from the domain pattern's independently-hand-typed exclusion list; removes "com" from the filename allow-list (a full-path ".com" file is still caught, unaffected) and derives the domain exclusion list from the filename list so the two cannot drift apart again; re-measured on the same corpus: 137 → 0 | Accepted |
| [0055](0055-stage2-precision-and-alias-list-fixes.md) | Three Stage-2 precision fixes found via a real-corpus mix-vs-LLM comparison: a new regex-only alias-list extractor (`stage2g`) catches "X (aka Y, Z)" constructs none of the dictionary/model stages split; a CyNER repeated-token collapse fixes verbatim duplicated-word artifacts ("COLDWELL COLDWELL Dropper"); a cross-source `resolve_type_conflicts()` pass reconciles disagreements like the gazetteer's `tool` vs. CyNER's `malware` for the same name (CyNER has no dedicated Tool label) — investigated adding missing gazetteer entries first, found all the suspected-missing names were already present and correctly typed, so the real defect was the unreconciled disagreement, not coverage | Accepted |
| [0054](0054-full-docker-installation.md) | Full-Docker installation: `setup.sh` becomes environment prep only — Docker is now the only supported way to install, develop and run CTIParsor, dev loop and air-gap included, not just deployment; `setup.sh` drops from 1298 lines to ~250 (checks Docker, writes `.env` + `CTI_DB_PASSWORD` + `.secrets/db_password`, prints next commands, builds/starts nothing itself); two new `profiles: [dev]` compose services, `dev` (bind-mounts the repo live over `/app`, replacing the image's `tests/`-excluding `COPY` — edits need no rebuild) and `frontend-dev` (Vite HMR via a bind-mounted `node:24` container); re-examines ADR-0037's WSL `/mnt/` bind-mount warning and finds it doesn't recur — that measurement was SQLite random access (gone, ADR-0053) and Torch/HF `.so` reads from `/opt/venv` (stays baked in the image, never bind-mounted); the ADR-0040 air-gap bundle is redesigned around `docker save`/`load` plus a `pg_dump`-based database export instead of a wheel/deb/model bundle, cutting its staging logic from a dozen host-install functions to two generic mechanisms; `scripts/check_offline_bundle_docker.sh` reuses the existing `docker_smoke.sh` for the "does the restored stack work" half after confirming by reading it that it never itself calls `bootstrap` | Accepted |

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
           ▲   amended by (surfaced by 0061's mapping ledger)
           └── 0062 an observable keeps the relationships STIX defines for
               it: routing ran before the verb check, so `malware
               communicates-with domain-name` shipped as `related-to` an
               Indicator.  Routed now only when the verb is not *listed*
               for the direct pair (`related-to` is valid anywhere, so it
               still routes), judged on the verb after the direct pair's
               policy pin — which restores the pin contract for SDO>SCO
               rules, unreachable for extracted rows since 0041

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
