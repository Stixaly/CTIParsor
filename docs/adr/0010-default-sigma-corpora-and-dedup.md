# ADR-0010: Default Multi-Repo Sigma Corpora + Cross-Corpus Deduplication

**Status:** Accepted (documented alongside implementation)
**Date:** 2026-06-19
**Deciders:** maintainer

> Ships 8 public Sigma repos in the committed registry (was 1) and adds a global
> dedup pass so a rule copied across corpora counts once. Builds directly on
> ADR-0006 (multi-corpus ingestion), ADR-0007 (config panel), ADR-0008 (coverage).

## Context

`detection_corpora.yaml` shipped a single corpus (`sigmahq`). We want a fresh
clone to reproduce broad coverage from 8 public Sigma repositories. The ingestion
machinery already supports many corpora (registry → `sync_corpora` → `SigmaAdapter`
→ store), but three forces complicate "just add them":

1. **The repos are heterogeneous.** `SigmaHQ`, `DFIR-Report`, `P4T12ICK`,
   `RussianPanda95`, `tsale`, `linkedin` are clean Sigma. `mthcht` is large and
   auto-generated; `Yamato hayabusa-rules` is a Sigma-derived dialect that
   **embeds a converted copy of SigmaHQ** under `sigma/`. Licenses differ
   (DRL-1.1, GPL-3.0, BSD-2-Clause, and two with **no LICENSE file**).
2. **`DetectionRule.content_hash` claimed "cross-corpus dedup" but nothing
   implemented it.** The store keyed every row on `corpus:native_key`, so the same
   rule from two corpora produced two rows. With 8 overlapping repos that
   double-counts heavily — exactly where hayabusa↔sigmahq lands.
3. **Dedup must not destroy the corroboration signal.** Coverage scores a
   technique **3** when ≥2 *independent* corpora cover it (ADR-0006). Folding true
   copies must not collapse genuinely-independent rules that merely share a
   technique.

## Decision

### 1. Ship all 8 repos, enabled, in the committed registry

Each entry gains `priority` (dedup precedence, lower = more authoritative) and,
for the two large repos, `subdir` to scope the clone to its rule subtree
(`mthcht/sigma_rules`, `hayabusa/sigma`). Licenses were **verified from each repo
on 2026-06-19** and stamped:

| Corpus | License | priority | subdir |
|---|---|---|---|
| sigmahq | DRL-1.1 | 10 | — |
| dfir-report | GPL-3.0 | 20 | — |
| tsale | GPL-3.0 | 30 | — |
| p4t12ick | GPL-3.0 | 40 | — |
| russianpanda | **none** (no LICENSE upstream) | 50 | — |
| linkedin | BSD-2-Clause | 60 | — |
| mthcht | **none** (no LICENSE upstream) | 90 | sigma_rules |
| hayabusa | DRL-1.1 | 95 | sigma |

`license: none` = all-rights-reserved upstream. License is **carried to drill-down,
not auto-enforced** — ingesting for *coverage* is low-risk; exporting those `raw`
bodies is the operator's call. (A future ADR may gate export on
`license ∈ {none, proprietary}`.)

### 2. Deduplicate on *normalized detection logic*, not raw bytes

The dedup axis is `dedup_key = sha256(normalized(logsource) + normalized(detection))`,
computed by `SigmaAdapter`. Normalization lowercases scalars/keys and sorts lists,
so formatting-, ordering-, case-, and metadata-only differences (title, author,
id, references) hash identically — but two rules with different detection logic do
not. This is the semantically correct definition of "duplicate" for coverage: two
rules corroborate a technique only if they would match different events. Rules with
no usable detection logic fall back to their `content_hash` so they never pool.

### 3. A global post-rebuild election, not per-corpus

`replace_corpus_rules` writes one corpus at a time and can't see cross-corpus
duplicates, so dedup is a separate **global** pass (`dedupe_store`) that runs at the
end of `rebuild_store` (and therefore after the settings-panel "rebuild" too). It
clusters all rows by `dedup_key`, elects one **canonical** per cluster by
`(priority, corpus, id)`, and sets `is_canonical` (1/0). **Lossless** — every row,
its `raw`, and its provenance stay; only the flag changes. Coverage and drill-down
read `is_canonical = 1`; drill-down adds `also_in` so a folded copy is still
credited to its corpus.

## Options Considered (dedup)

### Option A — Query-time collapse on `content_hash`
No schema change; collapse in each read query.
**Rejected:** catches byte-identical only — misses hayabusa's reformatted SigmaHQ
conversions (the dominant overlap) and forks that touch metadata; smears dedup
logic across every query.

### Option B — Ingest-time dedup (store canonical only)
Skip a duplicate at insert.
**Rejected:** lossy (drops the fact corpus B also had it → violates provenance) and
fights the per-corpus rebuild model — a single-corpus rebuild can't make a globally
correct skip decision.

### Option C — Normalized `dedup_key` + `is_canonical` flag, global pass — **chosen**
Lossless, true counts available (`WHERE is_canonical=1`), catches near-dups, fits
the existing per-corpus rebuild (dedup is a final global step), and keeps the
corroboration signal intact (independent logic ⇒ distinct key ⇒ both canonical).
Cost: two nullable columns, a precedence model, and per-format normalization rules.

## Consequences

**Easier:** Coverage counts stop double-counting; a fresh clone reproduces a rich,
deduped corpus set; new Sigma repos are a one-line registry add.
**Harder / revisit:** A larger `sync_corpora` (two big repos) — clones are still
gitignored and out-of-band. Per-corpus rebuilds re-run the global dedup (cheap, one
pass). Normalization rules need upkeep as Sigma evolves.
**Watch:** `russianpanda` and `mthcht` ship rule bodies with **no redistribution
grant** — visible as `license: none` at every drill-down; do not export their `raw`
without clearing terms. Five corpora are GPL-3.0 — copyleft attaches only if a
bundle *redistributes* those rule bodies, not to coverage metadata.

## Implementation

- `detection_corpora.yaml` — 8 entries with `priority`/`subdir`/verified licenses.
- `models/detection.py` — `DetectionRule.dedup_key`.
- `pipeline/detection/sigma.py` — `_dedup_key` / `_canonicalize`.
- `pipeline/detection/dedup.py` — `dedupe_store(conn, priority)` (new).
- `pipeline/detection/builder.py` — builds the priority map, runs dedup after rebuild.
- `pipeline/detection/registry.py` — `corpus_root()` (subdir scoping).
- `pipeline/detection/store.py` — persist `dedup_key`/`is_canonical`; coverage &
  drill-down read canonical-only; `also_in` provenance; `canonical` in counts.
- `api/db.py` — additive migration (`dedup_key`, `is_canonical`, two indexes).
- `tests/test_detection_dedup.py` — adapter key, election, provenance, subdir, and a
  hayabusa-vs-sigmahq overlap fixture asserting a duplicate corpus does not inflate
  the score while an independent rule still corroborates to 3.
