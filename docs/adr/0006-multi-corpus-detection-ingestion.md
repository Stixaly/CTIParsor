# ADR-0006: Multi-Corpus Detection-Rule Ingestion for Coverage

**Status:** Accepted
**Date:** 2026-06-19
**Deciders:** maintainer
**Relates:** elaborates ADR-0008 (the coverage matrix consumes this data)

> **Current privacy model: Revision 3 (mixed public + private, two-tier registry).**
> See the Revision History at the end — it supersedes the all-private framing in
> the "Private-repo access" / "Privacy boundary" bullets below.

## Context

The coverage matrix (ADR-0008) needs real detection rules behind a persisted
`coverage_score`. The corpuses come from **more than one source** and the
formats/licenses/privacy differ, so the ingestion layer must be pluggable rather
than Sigma-specific.

**Confirmed scope (Rev 1):** all corpuses are **Sigma format**, spread across
**multiple private git repos**.

CTIParsor invariants: offline at runtime, deterministic (no LLM in scoring),
additive (a new corpus = minimal work), reuse of existing patterns
(build-index scripts, SQLite + migrations, stage modules).

## Decision

An **adapter-per-format** architecture normalizes every corpus into a common
`DetectionRule`, persisted in SQLite and indexed by ATT&CK technique. A coverage
stage joins a report's extracted techniques against the store to compute and
persist a `coverage_score`; the frontend matrix reads it via an API.

```
RuleCorpusAdapter.parse(local_clone) ──► DetectionRule (normalized, technique-tagged, license-stamped)
                                              │
                              detection_rules table  ──► technique→rule index
                                              │
        Stage 6: extracted techniques ⋈ index ──► coverage table ──► /coverage API ──► CoverageMatrix
```

Scoped decisions for this revision:

- **Adapters:** only `SigmaAdapter` is implemented; `RuleCorpusAdapter` (ABC)
  remains the seam for future formats. One adapter serves *all* Sigma repos.
- **Private-repo access (Option A):** the registry (`detection_corpora.yaml`)
  points at **local clones**; an ambient-auth sync helper (`scripts/sync_corpora.py`)
  `git pull`s them using the operator's existing git auth (SSH agent /
  `credential.helper`). **Credentials never enter CTIParsor.**
- **Privacy boundary:** anything derived from private rules lives in **SQLite
  only** — never committed, never shipped to `frontend/public/`. The matrix reads
  scores/titles via the API; raw rule bodies only on explicit, license-aware drill-down.

## Options Considered

### Option A — Adapter registry → normalized DB rule store (chosen)
| Dimension | Assessment |
|---|---|
| Complexity | Medium |
| Extensibility | Adding a corpus = 1 config line (Sigma adapter reused) |
| Offline / Determinism | ✅ / ✅ |
| Private/large corpuses | ✅ DB-backed, SQL drill-down, local clones |

### Option B — pySigma as a universal IR
Rejected as the universal layer: pySigma converts *from* Sigma *to* backends; it
can't ingest arbitrary non-Sigma formats. Reused only *inside* a future converter.

### Option C — Per-corpus committed JSON indexes, frontend-joined
Rejected: can't host a **private** corpus (commit/ship leakage), no SQL drill-down.

### Private-repo access sub-options
- **A (chosen):** local clones + ambient-auth sync. No secrets in CTIParsor.
- **B:** CTIParsor clones with configured tokens — more attack surface; rejected
  unless unattended CI ingestion is needed (then read-only deploy keys).
- **C:** git submodules — commits private repo URLs/refs into CTIParsor; rejected.

## Coverage score (NOT lab-validated)

| Score | Meaning |
|---|---|
| 3 | rules from **≥2 corpora** (corroborated) |
| 2 | rule from **1 corpus** |
| 1 | **telemetry-mapped only** (ATT&CK data source, no rule) — ADR-0008 fallback |
| 0 | technique extracted, no coverage |

Cross-corpus corroboration mirrors the cross-model consensus signal already in
the pipeline. Dedup identical rules by `content_hash`; if repos are forks of a
shared base, key corroboration on the Sigma rule `id` to avoid inflating scores.

## Consequences

- **Easier:** add corpuses (incl. private); drill from a cell into actual rules;
  Sigma export; the matrix gains real teeth.
- **Harder / revisit:** licensing is first-class (per-corpus `license`, honored on
  export/UI); the normalized schema versions as new formats expose new fields.
- **Watch:** untagged rules score 0 despite existing; `.gitignore` the clones +
  the SQLite DB; keep the "readiness ≠ validation" banner.

## Action Items

**Foundation (done in this change)**
1. [x] `DetectionRule` model + `Severity` (`models/detection.py`).
2. [x] `RuleCorpusAdapter` ABC (`pipeline/detection/base.py`) + `SigmaAdapter`
       (`pipeline/detection/sigma.py`) + registry (`pipeline/detection/registry.py`).
3. [x] `detection_corpora.yaml.example`; `.gitignore` clones + private registry.

**Next**
4. [ ] `scripts/sync_corpora.py` (ambient git auth) + `scripts/build_detection_index.py`
       (parse local clones → upsert `detection_rules` table).
5. [ ] `detection_rules` + `coverage` tables (db migrations); `Stage 6 — coverage`
       computes + persists the 0–3 score.
6. [ ] `GET /api/jobs/{id}/coverage` (+ license-aware rule drill-down); wire the
       `useCoverage` hook + `CoverageMatrix` view (ADR-0008).

## Open Question
Are the repos **independent** rule sets (cross-repo overlap = genuine
corroboration) or **forks/mirrors** of a shared base? Resolved in the
implementation: the corroboration policy deduplicates logical rules by Sigma
`id` across corpora, so forks never inflate the score — no answer required.

---

## Revision History

**Rev 1 (private):** assumed all corpuses private — registry gitignored, derived
data DB-only, ambient-auth sync.

**Rev 2 (public):** corrected to all-public — registry committed for
reproducibility; clones gitignored for size, not secrecy.

**Rev 3 (mixed — current):** corpuses are a **mix** of public and private, so
privacy is **per-corpus**, handled by a **two-tier registry**:

| File | Tracked | Holds |
|---|---|---|
| `detection_corpora.yaml` | committed | public corpuses (reproducible: clone → sync → build) |
| `detection_corpora.local.yaml` | gitignored | private corpuses + local overrides |

`load_corpora` merges the local overlay over the committed file (override by
`name`, append new). All clones stay gitignored (`/corpora/`). Sync uses ambient
git auth — public needs none, private uses the SSH agent. `license` and the
`private` flag stay per-corpus.

**Forward rule:** any *exported or committed* artifact (e.g. a static frontend
index) must filter to `private: false` corpuses. The live local API serving
private rule titles to the local UI is fine — nothing leaves the machine.
