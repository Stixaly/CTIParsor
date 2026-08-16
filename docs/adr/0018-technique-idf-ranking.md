# ADR-0018 — Technique-IDF ranking (breaking the score plateau)

**Status:** Proposed
**Date:** 2026-08-16
**Extends:** [0014](0014-observable-driven-detection-proposals.md) (relevance scoring)
**Depends on:** [0017](0017-provenance-based-rule-dedup.md) — the technique document frequency is meaningless against a store that counts the same rule twice

## Context

ADR-0014 scores a rule as `observable evidence + technique term`, where the
technique term is a **flat constant**: `TECH_EXACT = 0.30`, `TECH_PARENT = 0.18`.

A CTI report carries 34–48 techniques, which tags ~1,400 canonical rules. Every
one of them receives an identical 0.30. Measured on the two stored reports:

| Report | Candidates | direct | behavioural | Distinct scores |
|---|---|---|---|---|
| ShinyHunters | 2,693 | 8 | 2,685 | 6 |
| GREYVIBE | 3,010 | 2 | 3,008 | 4 |

**99.7% of proposals are tied.** `rank_rules` sorts by `(-score, corpus, title)`,
so once past the handful of evidence-backed hits the analyst is reading an
alphabetical list — "7Zip Compressing Dump Files", "ADFS Database Named Pipe",
"APT29". The ordering carries no information.

ADR-0017 made this more visible rather than less: with 5,036 duplicates folded,
the plateau is no longer masked by repeated titles.

## Options considered

**A — Rank the plateau by rule quality: breadth × corpus authority.** A rule
tagged with one technique is more specific than one tagged with eight; SigmaHQ
outranks auto-generated corpora. **Simulated, then rejected.** It reduced the
largest tie only from 1,469 to 313, and — the reason it was dropped — it ranks by
*quality*, not by *relevance*. Its top of list for a Linux PeopleSoft intrusion
was `Screen Capture - macOS`, `Too Many Global Admins`, `PIM Alert Setting Changes
To Disabled`: narrow, authoritative, and unrelated to the incident.

**B — IDF-weight the technique, then damp by rule breadth.** The information in
"this rule is tagged T1059" depends on how many rules carry T1059. **Chosen.**

**C — Learn weights from analyst accept/reject.** Rejected for now: 145 of 146
entities in the store are `accepted=1`, so there is no negative signal to learn
from, and it would end ADR-0014's determinism guarantee.

## Decision

### 1. The technique term becomes IDF-weighted

```
tech_component = TECH_EXACT × technique_idf(t) × breadth(rule)
```

`technique_idf` reuses ADR-0014's existing `idf()` verbatim, with the document
frequency being **the number of canonical rules carrying that technique**. This is
the same argument that made atom IDF work, applied to the axis it was never
applied to: a match on `cmd.exe` scores ~0 because thousands of rules contain it,
and by exactly the same logic a match on T1059 (358 rules) should not score what
T1222.002 (a handful) scores.

Measured spread on the real store — this is what the flat constant was throwing
away:

| Technique | Canonical rules | idf |
|---|---|---|
| T1059 | 358 | 0.330 |
| T1105 | 339 | 0.334 |
| T1078 | 257 | 0.366 |
| T1082 | 133 | 0.441 |
| T1102 | 87 | 0.489 |
| T1036.007 | 1 | ~0.92 |

### 2. Breadth damping

`breadth(rule) = 1 / sqrt(n_techniques_on_rule)`

A rule tagged with eight techniques is diffuse; one tagged with a single technique
is about that technique. Correlated with IDF but not redundant — simulated, IDF
alone leaves a 200-rule tie, IDF × breadth leaves 107.

### 3. `TECH_PARENT` becomes a ratio, not a second constant

The parent→sub roll-up (a rule on T1059 covers a report's T1059.004) keeps its
relative discount as `TECH_PARENT / TECH_EXACT = 0.6`, applied on top of the
weighted term rather than replacing it.

### 4. The cap is preserved by construction

`idf()` is normalised to 0..1, so the technique term can never exceed
`TECH_EXACT`. The rarest possible technique yields ≈ 0.28. ADR-0014's constraint —
that the technique term stays below the weight of one strong observable match —
therefore still holds without a second clamp.

### 5. Still deterministic and offline

No model, no network, no randomness. The same store and the same accepted entities
produce the same ranking, which ADR-0008 requires of the detection artifact.

## Consequences

**Easier**

- The list becomes readable past rank 10. Largest tie **1,469 → 107**; distinct
  scores **1 → 224**.
- Relevance improves qualitatively, not just statistically. On the ShinyHunters
  Linux intrusion the weighted term surfaces `Remove Immutable File Attribute`,
  `Chmod Targeting Sensitive Directories`, `File or Folder Permissions Change`
  (T1222.002) and the PetitPotam forced-authentication family (T1187) — rules an
  analyst would connect to the incident.
- No new tunable: the weight comes from the corpus, so it tracks the store as
  corpora are added.

**Harder**

- **The technique term now depends on dedup being correct.** Against the
  pre-ADR-0017 store, hayabusa's 4,758 unfolded copies would have inflated the
  document frequency of every technique they carry. This ADR is not safe to land
  without 0017.
- A technique carried by exactly one rule scores near the ceiling. That is right
  when the rule is genuinely specific, and wrong when the technique is rare only
  because it is *mis-tagged* — which the store does contain (`CAPEC-175`, ICS
  `T0866` on enterprise reports). Those are extraction defects that this change
  makes more visible.
- Scores shift downward overall (0.300 → ~0.20–0.26 for technique-only hits).
  Any saved threshold or screenshot referring to absolute values is stale.

## Validation

Run against the deduped store (ADR-0017 applied). **All four pass.**

**1. Plateau broken**

| Report | Distinct scores | Largest tie |
|---|---|---|
| ShinyHunters | 6 → **284** | 1,469 → **107** |
| GREYVIBE | 4 → **296** | 1,336 → **95** |

**2. Direct-tier hits stay on top** — on both reports the evidence-backed
proposals occupy ranks 0..n-1 and the first technique-only proposal appears
exactly at rank n. No inversion.

**3. Relevance** — the ShinyHunters top 10 now reads as the incident does:
MeshCentral/MeshAgent (the RAT actually used), `/etc/hosts` modification, then
`Chmod Targeting Sensitive Directories`, `Remove Immutable File Attribute`,
`File or Folder Permissions Change` (T1222.002) and `Suspicious Access to
Sensitive File Extensions`. Compare the rejected Option A, whose top of list for
the same report was `Screen Capture - macOS` and `Too Many Global Admins`.

**4. Latency** — 5,527 ms median for both jobs at `limit=200`, against a 5,435 ms
baseline: **+1.7%** for two added queries.

Worth recording: halving the canonical rule count (ADR-0017: 11,385 → 6,349) did
**not** reduce latency. The hot path is therefore not the rule count, and the
~2.7 s per job spent before ADR-0015 grows the store 7.5× is unexplained and
un-optimised. That is a separate investigation, not a blocker here.

### One boundary case the tests forced

`idf()` returns exactly 0 when a technique is carried by every canonical rule.
That is correct information theory and wrong behaviour here: unlike an atom match,
where a hit on `cmd.exe` genuinely carries no information, a technique match always
means the rule addresses something the report describes. On a 2-rule fixture the
term collapsed to zero and flattened the entire ranking.

`TECH_IDF_FLOOR = 0.15` puts a floor under the multiplier. It never binds on the
real store — the commonest report technique, T1059 at 358 of 6,349 rules, scores
0.330 — so it is purely a guard for small or freshly-seeded stores.
