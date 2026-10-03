# Extraction pipeline

Every stage a report goes through, in execution order, what each one guards
against, and which of them need a network connection. The overview table is in
the [README](../README.md#how-it-works); this page is the detail.

- [Stages](#stages)
- [Extraction quality layers](#extraction-quality-layers)
- [MITRE ATT&CK data](#mitre-attck-data)
- [Offline support](#offline-support)

## Stages

```
┌──────────────────────────────────────────────────────────────────────┐
│  Stage 1 — INGESTION                                    (offline ✅)  │
│  PDF / DOCX / HTML / TXT / MD → normalised text + chunks            │
│  • Text PDF    : markitdown (structure-preserving) → pdfplumber      │
│  • Scanned PDF : auto-detected → OCR via Tesseract / pdf2image       │
│  • Defanging   : hxxps://, [.], (.), [at], [@] → live form          │
│  • Chunking    : paragraph-aware + 400-char sliding-window overlap   │
│  • Adaptive    : larger chunks for large docs (3 000–5 000 chars)    │
└─────────────────────────────┬────────────────────────────────────────┘
                              │
┌─────────────────────────────▼────────────────────────────────────────┐
│  Stage 1f — FIGURE READING                       (opt-in — ADR-0032) │
│  PDF-only · off by default (VISION_PROVIDER=none)                    │
│  • Triage    : geometry discards 56.9% of images before any model    │
│  • Crops     : 150 DPI crops, not pages (977 tokens vs 2 191/page)   │
│  • Injection : transcription enters report_text in ⟦…⟧ sentinels     │
│  • Relations : attack-chain / network-diagram arrows → src -> dst    │
│  • Safety    : an unreadable figure is skipped, never costs the run  │
│  Enable: VISION_PROVIDER=anthropic|ollama|mistral|vllm in .env       │
└─────────────────────────────┬────────────────────────────────────────┘
                              │
┌─────────────────────────────▼────────────────────────────────────────┐
│  Stage 2 — REGEX IOC EXTRACTION                         (offline ✅)  │
│  IPv4/v6, domains, URLs, emails, MAC, ASN, file paths + filenames   │
│  Registry keys, MD5/SHA-1/SHA-256 (incl. line-wrapped hashes)        │
│  CVE IDs, raw MITRE ATT&CK IDs (T1234 / T1234.001) → ttp            │
└─────────────────────────────┬────────────────────────────────────────┘
                              │
┌─────────────────────────────▼────────────────────────────────────────┐
│  Stage 2b — GAZETTEER NER                               (offline ✅)  │
│  Aho-Corasick scan over 1 827 name variants (1 114 unique malware   │
│  families, offensive tools and APT groups — ATT&CK Ent + Mob + ICS) │
│  • Longest-match-wins, word-boundary checked                        │
│  • Confidence: 0.92 canonical / 0.88 alias                          │
└─────────────────────────────┬────────────────────────────────────────┘
                              │
┌─────────────────────────────▼────────────────────────────────────────┐
│  Stage 2c — SEMANTIC TTP DETECTION                      (offline ✅)  │
│  Sentence-transformer cosine-similarity against the pre-embedded    │
│  MITRE technique descriptions (local .npy cache)                    │
│  • Default model: all-MiniLM-L6-v2 (80 MB)                         │
│  • Upgrade: ehsanaghaei/SecureBERT-Plus (+8-12% F1 on CTI text)     │
│  • Model-aware tiers: ≥ high wins over LLM / medium = candidate     │
│    (MiniLM 0.62 / 0.48; resolved per-model — ADR-0011 Phase A)      │
│  • 1 match/sentence (top_k=1); TTP_TOP2_MARGIN guards any 2nd match  │
│  • ATT&CK-only by default (918 of 1 533): CAPEC shadows the real    │
│    technique, so it is excluded — TTP_SEMANTIC_DOMAINS=all restores │
│  • TTP_MODE=select (ADR-0072): retrieves ranked candidates only —   │
│    ATT&CK descriptions + procedures, BM25 ⊕ dense; never a TTP      │
└─────────────────────────────┬────────────────────────────────────────┘
                              │
┌─────────────────────────────▼────────────────────────────────────────┐
│  Stage 2d — CyNER 2.0                       (offline once cached)   │
│  DeBERTa-v3 fine-tuned on cybersecurity NER (F1 91.88%)             │
│  Detects: Malware, Threat_group (threat-actor groups)               │
│  Model: PranavaKailash/CyNER-2.0-DeBERTa-v3-base (CYNER_ENABLED)    │
└─────────────────────────────┬────────────────────────────────────────┘
                              │
┌─────────────────────────────▼────────────────────────────────────────┐
│  Stage 2e — GLiNER ZERO-SHOT NER                       (offline ✅)  │
│  Zero-shot NER with natural-language label descriptions              │
│  Detects entity types the gazetteer and CyNER cannot:               │
│    targeted sectors, campaign names, attack infrastructure,          │
│    novel actors & malware not yet in MITRE ATT&CK                   │
│  Default model: urchade/gliner_large-v2.1 (~800 MB)                 │
│  Configurable via GLINER_MODEL in .env                              │
└─────────────────────────────┬────────────────────────────────────────┘
                              │
┌─────────────────────────────▼────────────────────────────────────────┐
│  Stage 3 — LLM ENRICHMENT              (requires API key)            │
│  Input : chunk + pre-detected IoCs + gazetteer/NER context          │
│  Output: threat actors, malware families, tools, TTPs,              │
│          relationships (+ evidence quote), IoC→malware links,       │
│          targeted sectors/countries, course of action               │
│  • Parallel processing (configurable via LLM_PARALLELISM)           │
│  • Crash-resume: checkpoint saved every N chunks                     │
│  • Providers: Anthropic Claude | Mistral AI | Ollama                │
└─────────────────────────────┬────────────────────────────────────────┘
                              │
┌─────────────────────────────▼────────────────────────────────────────┐
│  Stage 3b — HALLUCINATION FILTER                        (offline ✅)  │
│  Verifies each LLM-returned name against source chunk text           │
│  via fuzzy sliding-window matching (rapidfuzz):                     │
│  • ≤ 5 chars (FIN7, APT1)   : 92% similarity threshold             │
│  • 6–9 chars (LummaC2)      : 80% similarity threshold             │
│  • ≥ 10 chars (Cobalt Strike): 75% similarity threshold            │
│  Campaign names: word-level fallback to avoid over-filtering        │
│  Names already confirmed by NER or doc context skip the fuzzy scan   │
└─────────────────────────────┬────────────────────────────────────────┘
                              │
┌─────────────────────────────▼────────────────────────────────────────┐
│  Stage 3d — RELATIONSHIP SELF-VERIFICATION              (optional)   │
│  Second LLM call: "quote the exact sentence supporting this claim"  │
│  Unsupported relationships are removed.                             │
│  Effect: hallucination rate 27% → 8% (aCTIon paper, NEC Labs 2023) │
│  Cost: ~1.4× total LLM calls (only chunks with ≥ 1 relationship)   │
│  Enable: ENABLE_STIX_VERIFICATION=true in .env                      │
└─────────────────────────────┬────────────────────────────────────────┘
                              │
┌─────────────────────────────▼────────────────────────────────────────┐
│  Stage 3f — TTP SELF-VERIFICATION                       (optional)   │
│  TTP analogue of 3d: second LLM call quotes the sentence describing │
│  each technique's USE (with its expected ATT&CK tactic); unsupported │
│  techniques are dropped. Semantic-corroborated TTPs are trusted and │
│  skipped, so cost tracks 3d (~1.4× calls — ADR-0011 Phase B).       │
│  Enable: ENABLE_TTP_VERIFICATION=true in .env                       │
│  TTP_MODE=select (ADR-0072): selects among the retrieved candidates │
│  and the LLM's own picks, exact quote checked by code; a failed     │
│  call ships nothing (candidates go to review)                       │
└─────────────────────────────┬────────────────────────────────────────┘
                              │
┌─────────────────────────────▼────────────────────────────────────────┐
│  Stage 3e — CROSS-MODEL CONSENSUS                       (optional)   │
│  Re-runs every relationship-bearing chunk through a SECOND provider  │
│  and treats agreement as a trust signal — a model is a poor judge of │
│  its own hallucination; two different models disagreeing is signal.  │
│  • Agreed by both   : confidence +0.10                               │
│  • Primary only     : confidence −0.20, "observed" → "reported"      │
│  Enable: ENABLE_CONSENSUS=true + CONSENSUS_PROVIDER (≠ LLM_PROVIDER) │
└─────────────────────────────┬────────────────────────────────────────┘
                              │
┌─────────────────────────────▼────────────────────────────────────────┐
│  Stage 3c — MITRE ATT&CK NORMALISATION                 (offline ✅)  │
│  Runs ONCE per document, after every chunk is merged — not per chunk │
│  Fuzzy-matches extracted TTPs against the full ATT&CK corpus         │
│  (Enterprise + Mobile + ICS + CAPEC, compact local JSON index)       │
│  • Score ≥ 85 : canonical name + correct MITRE ID                    │
│  • Score 70–84: keep LLM phrasing, override ID                       │
│  • Score < 70 : pass through unchanged                               │
│  + Merge precision (ADR-0011): only HIGH-confidence semantic wins    │
│    over the LLM; parent technique dropped when a sub-technique fires │
└─────────────────────────────┬────────────────────────────────────────┘
                              │
┌─────────────────────────────▼────────────────────────────────────────┐
│  Stage 4 — STIX 2.1 MAPPING                            (offline ✅)  │
│  IoC → SCO  (IPv4Address, DomainName, File, URL, Email, MACAddr…)  │
│  Malware / Actor / Tool / TTP / CVE / Campaign / Infra → SDO        │
│  Location → SDO (targeted country, ISO 3166-1 lookup, 80+ nations)  │
│  Identity → SDO (targeted sector, identity_class=class)             │
│  CourseOfAction → SDO (recommended remediations)                    │
│  All accepted IoCs → Indicator → based-on → SCO   (ADR-0061)        │
│  IoC linked to malware → indicates SRO                              │
│  Threat actor → targets → Location / Identity SROs                 │
│  Semantic relations → Relationship SRO (deduplicated, spec-valid)    │
│  Every object: TLP/PAP marking + created_by_ref → authoring Identity │
└─────────────────────────────┬────────────────────────────────────────┘
                              │
┌─────────────────────────────▼────────────────────────────────────────┐
│  Stage 4b — GRAPH COMPLETION                (offline ✅ — ADR-0013)   │
│  Enriches edges AFTER the precision gate, never loosening it.        │
│  Runs before the Report SDO, so new edges are wrapped + stamped.     │
│  1. Alias merge     : OFF by default — aliases.py (ADR-0012) already │
│    (fallback)         canonicalises MITRE aliases at SDO creation.   │
│                       Fallback for non-gazetteer names only.         │
│  1b. ATT&CK grounding: add MITRE-curated edges (20 015 G/S/T pairs)  │
│                       when both endpoints resolve to ATT&CK IDs      │
│                       → x_evidence_label="reported" (expert fact)    │
│  2. Transitive infer : compose two verified edges via a fixed table  │
│                       (uses∘uses→uses …); a composed verb that is    │
│                       not spec-*suggested* is SKIPPED, not emitted   │
│  Every inferred edge: x_evidence_label="inferred" + x_inference_rule │
│  + x_inferred_from (premise ids). Pinned policy rules always win.    │
└─────────────────────────────┬────────────────────────────────────────┘
                              │
┌─────────────────────────────▼────────────────────────────────────────┐
│  Stage 4c — LONG-DISTANCE PREDICTION                    (optional)   │
│  Connects still-disconnected sub-graphs (CTINexus Phase 3):          │
│  DFS components → central node per component (degree centrality) →   │
│  topic node (global max degree) → ask the LLM for the relation.      │
│  Same evidence bar as 3d: the model must QUOTE the supporting        │
│  sentence (stored as x_evidence_text) — no quote ⟹ no edge.          │
│  Off unless policy completion.long_distance=true AND provider ready  │
│  (so Stage 4 stays network-free by default).                         │
└─────────────────────────────┬────────────────────────────────────────┘
                              │
┌─────────────────────────────▼────────────────────────────────────────┐
│  Stage 5 — VALIDATION & EXPORT                         (offline ✅)  │
│  stix2 library validates every object at construction time           │
│  stix2-validator JSON-schema check (when schemas installed)          │
│  Valid bundle → output/{report}_bundle.json                         │
│  Invalid bundle → output/{report}_bundle_invalid.json (for debug)   │
└──────────────────────────────────────────────────────────────────────┘

On Finalize (web UI):
  + Report Lexicon Re-scan: accepted named entities used as a per-report
    domain lexicon to find additional occurrences missed by NER/LLM.
    Source tagged "report_lexicon". Zero ML cost, pure string matching.
```

**The API worker, the `main.py` CLI and the `--stage full` benchmark run the
same sequence of stages** (`pipeline/orchestrator.py`, ADR-0059); they differ
only in what happens around it (job store, progress events, crash-resume).
Every run records which stages ran, were skipped (disabled, model missing, no
LLM provider) or failed — the CLI prints it, the worker stores it in the job's
run config (`stage_report`). The lexicon re-scan runs on Finalize, so it stays
web-only.

Stage order note: 3b, 3d, 3f and 3e run **per chunk**; 3c runs **once per
document**, after every chunk has been merged. The boxes are drawn in that
execution order.

## Extraction quality layers

### 0. What a figure read returns (Stage 1f)

The model is constrained by a JSON schema and returns four fields.

| Field | What it is | Where it goes |
|---|---|---|
| `figure_kind` | One of eight predefined categories | Determines the block header and controls whether arrows are rendered |
| `verbatim_text` | Text lines transcribed directly from the image | Injected into `report_text`, making it visible to Stage 2 regex and all subsequent stages as if it were body text |
| `edges` | `src → dst → label` triples extracted from diagrams | Rendered as `src -> dst` lines within the block, applicable only to `attack-chain` and `network-diagram` types |
| `iocs` | Values identified by the model as indicators | **Not injected** — see the note below |

The `figure_kind` field accepts one of eight values: `network-diagram`, `attack-chain`, `screenshot`, `code-listing`, `table`, `chart`, `logo`, and `none`. Three of these values—`logo`, `none`, and `unread` (which the pipeline assigns when reading fails)—result in an empty block. The figure retains its ordinal number regardless of the kind assigned; otherwise, numbering would shift based on model decisions, causing a `⟦figure 7⟧` reference to point to different images across runs.

**What the model is told besides the image**

The crop does not travel alone. Each read carries the text in a band around the figure and the head of the report, which MM-AttacKG's ablation (arXiv:2506.16968, Table 3) measures at roughly **7 points of entity F1** — 0.7716 with both context sources, 0.7022 with neither — for no extra call.

The context block opens with an explicit prohibition: this text is not in the image and must never appear in `verbatim_text`, `iocs` or `edges`. Without it the model transcribes the surrounding prose as though it had read it off the page, pushing report text back into `report_text` a second time inside a figure block.

**Why `iocs` is not injected**

Measured over two production runs — 26 figures carrying content — **63 of 64** listed IoCs were already in the transcription, so injecting the list buys almost no recall. The one that was not is a phishing URL the model transcribed twice and garbled differently each time, so injecting it would have added a domain that does not exist (ADR-0032, amendment of 2026-08-30). The reason not to inject it is what the exception would cost: an IoC present in the `iocs` list but absent from `verbatim_text` is a model assertion not grounded in its own transcription. Injecting such values would introduce data into the bundle that no stage can verify—precisely the class of hallucination that Stage 3b and Stage 3d are designed to prevent. Consequently, image-derived IoCs reach the pipeline through a single path: the model transcribes them into `verbatim_text`, which is injected into `report_text` before Stage 2 executes, allowing regex patterns to extract them exactly as they would from document body text.

| Limit | Value | What happens at it |
|---|---|---|
| Context sent with each crop | 1200 chars around the figure, 600 of the report head | A band of ±250 pt, not the whole page: on a web capture one page holds 18 371 characters and 18 figures, so page-level text would hand each of them the same navigation menu |
| Figures read per PDF | 40 | Additional candidates are dropped, logged as a warning, with no indication in the bundle |
| Arrows rendered per figure | 24 | Further edges from the same figure are not rendered |
| Crop render resolution | 150 DPI | Only crops are processed, never whole pages |

### 1. Multi-layer NER (Stages 2b–2e)

Each NER stage adds a different capability:

| Stage | Method | Entities found |
|---|---|---|
| 2 | Regex | IoCs (IPs, hashes, domains, CVEs, paths…) |
| 2b | Aho-Corasick gazetteer | Known malware/tools/APT groups |
| 2c | Semantic embeddings | MITRE techniques by meaning, not name |
| 2d | CyNER 2.0 (DeBERTa-v3) | Cybersecurity NER — malware & threat-actor groups |
| 2e | GLiNER zero-shot | Sectors, campaigns, infrastructure, novel actors |

### 2. Sliding-window chunk overlap (Stage 1)

```
Chunk N:   [...──────── entity ─────]
Chunk N+1:       [──── entity ─────────...]
                ↑ 400-char overlap
```

Named entities at chunk boundaries appear in both adjacent chunks. De-duplicated at merge. Estimated: +5–12% recall on long documents.

### 3. Hallucination filter (Stage 3b)

After every LLM call, each returned name is fuzzy-matched against the source chunk text. Names below the length-adjusted threshold are dropped and logged.

| Name length | Strategy | Threshold |
|---|---|---|
| ≤ 5 chars | Exact + fuzzy | 92% |
| 6–9 chars | Exact + fuzzy | 80% |
| ≥ 10 chars | Exact + fuzzy | 75% |
| Campaign names | Word-level keyword fallback | — |

### 4. MITRE normalisation (Stage 3c)

Fuzzy-matched against the full ATT&CK corpus. Eliminates ~40% of wrong or invented MITRE IDs. Merge precision (ADR-0011): only a **high-confidence** semantic match overrides the LLM — a medium-confidence one is kept only when the LLM is silent and never wins the dedup. When a sub-technique (`T1059.001`) is present, its parent (`T1059`) is dropped as redundant.

### 5. Relationship self-verification (Stage 3d)

Second LLM call per chunk quotes the exact supporting sentence for every relationship. Unsupported relationships are dropped. Reduces hallucination rate from ~27% to ~8% (aCTIon paper benchmark).

### 6. TTP self-verification (Stage 3f)

The TTP analogue of Stage 3d (ADR-0011 Phase B). For each LLM-extracted technique, a second LLM call must quote the sentence describing that technique being *used* — annotated with the technique's expected ATT&CK tactic so a behaviour-vs-tactic mismatch is also rejected. Enable with `ENABLE_TTP_VERIFICATION` (recommended on — without it TTPs pass no evidence gate while relationships pass two).

Only a **high-confidence** semantic match (cosine ≥ the model's high cut-point) waives the check. That floor matters: a *medium* match (≥ 0.48) is precisely the nearest-but-wrong tier the Phase A margin gate exists to suppress, so letting it grant a bypass would hand the weakest signal in the pipeline veto power over the strongest check. On a real 12-page report, 13 of 16 corroborators sat below the cut-point and were waving through techniques with no textual support at all.

### 6b. Why TTP counts stay bounded

A report with no explicit T-IDs is where technique counts run away, because every entry is inferred. Four controls keep the number honest:

| Control | Effect |
|---|---|
| Stage 3f verification | drops techniques with no supporting sentence |
| High-confidence corroboration floor | stops weak semantic matches waiving 3f |
| Cross-source dedup at persistence | one row per technique, not one per source — the review UI matches the bundle |
| Parent/sub subsumption across sources | `T1027` dropped when `T1027.004` is present, even when the two came from different stages |
| ATT&CK-only semantic corpus | removes CAPEC near-duplicates of the technique that belongs in the bundle |

### 7. Report lexicon re-scan (Finalize)

On **Finalize**, accepted named entities form a per-report domain lexicon. The full text is re-scanned with word-boundary string matching to find additional occurrences that NER or the LLM missed. New occurrences are inserted with `source="report_lexicon"` and `accepted=True`.

### 8. Entity canonicalisation & relationship precision (Stage 4, ADR-0012)

`pipeline/aliases.py` builds an offline MITRE alias index from `gazetteer.json` +
`mitre_index.json` (no new dependencies). Stage 4 uses it to:

- **Merge aliases** — `APT34` and `OilRig` (MITRE group G0049) collapse into one
  `threat-actor` SDO instead of two, and a relationship naming *any* alias resolves
  to the merged node.
- **Drop spurious edges** — an observable ↔ attack-pattern relationship
  (e.g. `domain communicates-with T1071.001`) is a type error; it is dropped, not
  emitted as a noisy `related-to`.
- **Route observables through their indicator** — any other relationship
  touching a raw observable (LLM-extracted or policy-pinned) is re-anchored on
  that observable's `indicator` rather than the SCO itself (ADR-0041), unless
  STIX 2.1 defines the verb for the observable itself: `malware
  communicates-with domain-name`, `malware drops file` or `infrastructure
  consists-of ipv4-addr` stay on the observable, since through the indicator
  they could only ship as `related-to` (ADR-0062). Scoped to observable↔SDO
  pairs only — observable↔observable facts (`file related-to ipv4-addr`) are
  left as-is, since the spec's real answer for those is embedded ref
  properties, not a relationship object.

Measured effect on a 4-report corpus: named-entity relationship hallucination
≈ 11 % (the tractable target), entity hallucination ≈ 0. See
[ADR-0012](adr/0012-hallucination-measurement-and-canonicalization.md) /
[ADR-0041](adr/0041-observables-route-through-indicators.md) /
[ADR-0062](adr/0062-observables-keep-their-listed-relationships.md).

## MITRE ATT&CK data

Stages 2b, 2c, 3c, and 4b use pre-built local indexes in `pipeline/data/`.

### Build the indexes

```bash
# pipeline/data/*.json/*.npy ship pre-built and committed to git — this is only
# needed to rebuild them after a MITRE ATT&CK release update.
docker compose run --rm dev python scripts/build_indexes.py

# Or build only specific indexes
docker compose run --rm dev python scripts/build_indexes.py --only mitre         # mitre_index.json
docker compose run --rm dev python scripts/build_indexes.py --only gazetteer     # gazetteer.json
docker compose run --rm dev python scripts/build_indexes.py --only embeddings    # mitre_embeddings.npy
docker compose run --rm dev python scripts/build_indexes.py --only relationships # attack_relationships.json
```

The script auto-discovers bundle files in `data/`, `~/Downloads/`, and `~/Documents/`. Accepts `--enterprise`, `--mobile`, `--ics`, `--capec` flags for explicit paths.

| File | Stage | Size |
|---|---|---|
| `pipeline/data/mitre_index.json` | 3c normalisation | ~430 KB |
| `pipeline/data/gazetteer.json` | 2b gazetteer NER | ~194 KB |
| `pipeline/data/attack_relationships.json` | 4b ATT&CK grounding | ~586 KB |
| `pipeline/data/mitre_embeddings.npy` | 2c semantic TTP | ~2.3 MB |
| `pipeline/data/mitre_embeddings_meta.json` | 2c semantic TTP | ~60 KB |
| `pipeline/data/mitre_embeddings_manifest.json` | 2c cache validity + thresholds | ~1 KB |

These files are not gitignored — commit them to your repo to avoid a per-clone rebuild.

> The **manifest** records the model the cache was built with (so Stage 2c can detect a stale cache after `TTP_EMBEDDING_MODEL` changes) and the calibrated `thresholds` (`high`/`medium`) for that model — written by `build_indexes.py --only embeddings` (ADR-0011 Phase A).

## Offline support

| Component | Offline |
|---|---|
| Stages 1, 2, 4, 5 | ✅ fully offline |
| Stage 4b — graph completion (alias, grounding, transitive) | ✅ fully offline (grounding needs `build_indexes.py --only relationships`) |
| Stage 4c — long-distance prediction (opt-in) | ❌ requires an LLM provider |
| Stage 2b — gazetteer NER | ✅ after `build_indexes.py` |
| Stage 2c — semantic TTP | ✅ after `build_indexes.py` + model download |
| Stage 2e — GLiNER | ✅ after first model download (~800 MB cached) |
| Stage 3b — hallucination filter | ✅ fully offline (rapidfuzz) |
| Stage 3c — MITRE normalisation + merge precision | ✅ after `build_indexes.py` |
| Stage 3f — TTP self-verification (opt-in) | ❌ requires an LLM provider |
| Stage 3 — Anthropic / Mistral | ❌ requires internet |
| Stage 3 — Ollama | ✅ if instance is local |
| OCR (Tesseract) | ✅ local binary |
| Web UI (frontend assets) | ✅ served from local dist/ |
| Detection coverage (Sigma) | ✅ after `sync_corpora` (one-time clone) + `build_detection_index` |
