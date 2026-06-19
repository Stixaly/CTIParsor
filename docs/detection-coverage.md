# Detection Coverage — How-To

A practical walkthrough for setting up Sigma corpora and reading the coverage
matrix. For the design rationale see [ADR-0006](adr/0006-multi-corpus-detection-ingestion.md),
[ADR-0007](adr/0007-in-app-configuration-panel.md), [ADR-0008](adr/0008-detection-coverage-matrix.md).

> **Readiness, not validation.** Coverage tells you whether a detection *exists*
> (and from how many independent corpora) for each extracted technique — not that a
> rule was tested against live telemetry.

## 1. Configure corpora

Two registry files:

| File | Tracked | Holds |
|---|---|---|
| `detection_corpora.yaml` | committed | public corpora (ships with SigmaHQ) |
| `detection_corpora.local.yaml` | gitignored | private corpora + local overrides |

The local overlay is merged over the committed file: an entry with an existing
`name` overrides it (e.g. `enabled: false` to disable SigmaHQ); a new `name` is
appended.

**From the UI:** open **Settings** → add a repo (name + git URL + license). It's
written to the local overlay.

**By hand (private repos):**
```bash
cp detection_corpora.local.yaml.example detection_corpora.local.yaml
# edit: add your private Sigma repo entries
```

## 2. Fetch the clones

```bash
python scripts/sync_corpora.py
```
Clones/pulls each repo with a `git:` remote using your **ambient git auth** —
public repos need none; private repos use your SSH agent / credential helper.
Clones land under `./corpora/` (gitignored). No credentials are stored.

## 3. Build the rule store

```bash
python scripts/build_detection_index.py
```
Parses every enabled corpus's local clone into the `detection_rules` /
`rule_techniques` tables in `cti_stix.db`. Re-runnable and idempotent. The
**Rebuild index** button on the Settings page does the same from already-cloned repos.

## 4. Read the matrix

Open `/coverage/:jobId` for any processed report. Techniques are laid out in
ATT&CK-tactic columns and coloured by score:

| Score | Meaning | Action |
|---|---|---|
| 3 — Corroborated | rules in ≥ 2 corpora | high confidence |
| 2 — Covered | rule in 1 corpus | corroborate before relying on it |
| 1 — Telemetry only | data-source mapped, no rule | write a detection |
| 0 — No coverage | extracted, no rule | gap — prioritise |

Hover a cell for the rule count and contributing corpora.

## Scoring details (fork-safe corroboration)

Logical rules are identified by their **Sigma `id`** (or content hash) across
corpora and attributed to the first corpus they're seen in. So a rule **mirrored**
in two repos collapses to one corpus (score 2), while two **independent** rules for
a technique corroborate it (score 3). Forks/mirrors never inflate the score.

`license` travels with every rule; honor it before exporting or sharing rules.

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `[build] skipped (no clone)` | run `sync_corpora.py` first; check the corpus `path` |
| corpus shows `0` rules | rules untagged with `attack.tXXXX`, or pointed at a non-rules dir |
| private repo won't clone | ensure your SSH agent has the key; `git clone` it manually to confirm access |
| a technique reads 0 despite a known rule | the rule lacks an `attack.tXXXX` tag — coverage keys on ATT&CK tags |
| score never reaches 1 ("telemetry only") | the ATT&CK data-source enrichment (ADR-0008 Phase 1) isn't built yet — scores are rule-based (0/2/3) until then |
