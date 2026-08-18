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
`rule_techniques` / `rule_atoms` tables in `cti_stix.db`. Re-runnable and
idempotent. The **Rebuild index** button on the Settings page does the same from
already-cloned repos.

If your store was built before ADR-0014, add the atom index in place — no
re-clone needed, it re-derives everything from the stored rule bodies:

```bash
python scripts/build_rule_atoms.py
```

## 4. Read the matrix

Open `/coverage/:jobId` for any processed report.

At the top, the **format board** carries one card per rule language — Sigma
(`.yml`, SIEM), Suricata (`.rules`, IDS) and YARA (`.yar`, scanner) — each showing
how many of its rules are selected, their byte volume, and a tick per technique
in the report. All three cards are always shown: a format with no rule for this
report is a visible absence, not a missing lane.

Below it, techniques are laid out in ATT&CK-tactic columns and coloured by score:

| Score | Meaning | Action |
|---|---|---|
| 3 — Corroborated | rules in ≥ 2 corpora | high confidence |
| 2 — Covered | rule in 1 corpus | corroborate before relying on it |
| 1 — Telemetry only | data-source mapped, no rule | write a detection |
| 0 — No coverage | extracted, no rule | gap — prioritise |

Each cell carries three thin ticks on its right — one per format — filled when
that format has a selected rule for the technique, faint when it has rules but
none are selected, and hollow when it has none. Hovering gives the score and the
per-format split (`Corroborated · Sigma 6 · Suricata 9`).

Clicking a cell's **body** drills into it; the strip underneath then lists every
rule covering that technique, in three format columns, with its corpus, severity,
licence and (where the Detections ranking found one) the observable it matched.

## Scoring details (fork-safe corroboration)

Logical rules are identified by their **Sigma `id`** (or content hash) across
corpora and attributed to the first corpus they're seen in. So a rule **mirrored**
in two repos collapses to one corpus (score 2), while two **independent** rules for
a technique corroborate it (score 3). Forks/mirrors never inflate the score.

`license` travels with every rule; honor it before exporting or sharing rules.

## 5. Select and export rules

Every checkbox on the page drives one selection, and it rolls up: rule →
technique → ATT&CK tactic → corpus → format. A scope shows `✓` when all of it is
selected, a dash when only part is, and empty when none is. Clicking a format
card toggles that whole format; clicking a tactic column header toggles every
rule under it.

Everything matching the report starts selected — the same default the plain
export has always had — so the workflow is *deselect what you don't want*. The
export panel at the bottom shows the consequences live: per-format counts, total
size, a licence warning when any selected rule is all-rights-reserved, and a
preview of the actual ZIP layout. Group the table **by ATT&CK tactic** to answer
"what covers this attack step", or **by format · corpus** to answer "what am I
about to deploy where". The grouping never changes the selection.

`Download ZIP` sends the full set through `GET /detections/export` when nothing
is excluded, and POSTs the exact rule ids otherwise. Either way the archive is
identical in shape:

```
<report>_detection_rules.zip
├─ rules/sigma/     · N × .yml
├─ rules/suricata/  · N × .rules
├─ rules/yara/      · N × .yar
├─ MANIFEST.json    · licence + source per rule, and what was excluded
└─ README.txt       · formats present, excluded counts
```

Each rule keeps the extension its tool requires, and `MANIFEST.json` records the
excluded count — an export that silently dropped rules would otherwise look
identical to one where they never matched.

Your selection is remembered per report in `localStorage`.

## 6. Read the proposals

The coverage matrix tells you *whether* a rule exists. The Review **Detections**
tab tells you *which rules to read first* — a different question, answered from
the report's own technical content (ADR-0014).

Each rule's `detection:` block is indexed into normalized **atoms** (the literal
values it looks for) and each report's IoCs, file paths, registry keys, tool
names and CVEs are normalized into the same vocabulary. Proposals are ranked on
that overlap, weighted by how rare each value is across the whole corpus, then
adjusted for platform:

| Tier | Meaning | Read it because |
|---|---|---|
| **Matched this report** | a rule field matches an extracted observable | it names your artifact — start here |
| **Behavioural** | ATT&CK technique match, platform-compatible | it covers the behaviour, not your specific IoC |
| **Off-platform** | technique match, but the rule targets another OS | usually noise; kept for mixed intrusions |

Each proposal shows *why* it ranked: `Image ≡ meshagent64-v2.exe` (exact) or
`cmdline ⊃ sshpass` (substring). Rules carrying **no ATT&CK tag** are reachable
here even though the coverage matrix cannot see them.

The list is one ranked table with **format as a column**, not one section per
tool — the top of the list is the top of the list whichever tool the rule belongs
to. The `All / Sigma / Suricata / YARA` chips filter it and carry live counts.
Because this path keys on observables rather than ATT&CK tags, it reaches rules
the coverage matrix structurally cannot: on a report whose matrix shows **0**
YARA rules, the Detections tab can still rank YARA candidates.

Ranking is deterministic and offline — no model is involved (ADR-0008).

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `[build] skipped (no clone)` | run `sync_corpora.py` first; check the corpus `path` |
| corpus shows `0` rules | rules untagged with `attack.tXXXX`, or pointed at a non-rules dir |
| private repo won't clone | ensure your SSH agent has the key; `git clone` it manually to confirm access |
| a technique reads 0 despite a known rule | the rule lacks an `attack.tXXXX` tag — coverage keys on ATT&CK tags (the Detections tab still finds it via its atoms) |
| Detections warns the atom index is empty | run `python scripts/build_rule_atoms.py`; until then rules can only be ranked by technique |
| no proposal is tiered "Matched this report" | the report has few IoCs, or its observables appear in no rule — the behavioural tier is then the real answer |
| every YARA lane reads 0 | YARA rules carry no `attack.tXXXX` tags, so a technique-keyed join cannot reach them (ADR-0020). The board, ticks and drill-in show this as an honest absence; the Detections tab still finds YARA via observables |
| sizes all show `0 B` | the `rule_bytes` side table is empty on a store built before ADR-0022 — run `python -m scripts.backfill_rule_bytes` (no corpus re-clone needed) |
| the coverage page seems cut off | it scrolls itself; if it does not, the page's own scroll container is missing — `body`/`#root` are `overflow:hidden` by design so the Review page can own its panes |
| score never reaches 1 ("telemetry only") | the ATT&CK data-source enrichment (ADR-0008 Phase 1) isn't built yet — scores are rule-based (0/2/3) until then |
