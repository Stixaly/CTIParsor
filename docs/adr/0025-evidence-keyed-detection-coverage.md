# ADR-0025: Evidence-Keyed Detection Coverage (artifacts score, TTPs locate)

**Status:** Proposed
**Date:** 2026-08-22
**Deciders:** maintainer
**Relates:** supersedes the scoring model of ADR-0008 (coverage matrix); generalises
ADR-0014 (observable-driven proposals) from ranking to scoring; consumes ADR-0018's
technique IDF only as a display signal; constrained by ADR-0023 (TTP extraction quality)

## Context

ADR-0008 defined a coverage cell as an **ATT&CK technique**, scored 0–3 by how many
independent corpora hold a rule *tagged* with that technique. ADR-0014 then showed
that the same tag join was a poor way to *rank* rules, and replaced it with
observable evidence — but explicitly left coverage scoring alone: "readiness and
relevance are different questions and stay separate views."

Measured on the two real reports in `cti_stix.db` (75 127 canonical rules across
Sigma / Suricata / YARA, 363 166 atoms) with
`scripts/measure_ttp_vs_observable_coverage.py`:

| | GREYVIBE | ShinyHunters |
|---|---|---|
| Report techniques | 48 | 34 |
| Rules selected by technique | **15 121** (20.1% of the store) | **10 372** (13.8%) |
| Report artifacts with any rule hit | **1** of 20 | **3** of 31 |
| Rules selected by technique with zero evidence | 15 120 | 10 370 |
| Cells scored ≥ 2 with **no** evidence-backed rule | **33** of 36 | **25** of 28 |

Aggregated: of **25 493** rules the technique path selects, **4** are backed by any
technical element of the reports — a 100.0% no-evidence rate to one decimal. Of the
**64** cells claiming a coverage score of 2 or 3, **58 have no rule that matches
anything in the report**.

The cells are not marginal. `T1071.003` scores 3 on **6 573** rules with zero
evidence; `T1566.003` and `T1566.004` pull 1 608 rules each; `T1190` pulls 6 404.
A score of 3 currently reads "corroborated by two or more corpora" while meaning
only "two corpora have rules carrying this tag" — a statement about ATT&CK's tag
distribution, not about the report.

Two independent causes, and both must be addressed:

1. **A technique tag is not a detection claim.** It is a taxonomy label attached to
   both sides of a join. The join succeeds whenever the label exists on both sides,
   which for common techniques is nearly always. `rank_rules` shows the same
   pathology in its tiering — direct=16 vs behavioural=15 105 on GREYVIBE: 99.9% of
   proposals carry no evidence.
2. **The report's technique set is itself noisy.** 11 of GREYVIBE's 48 techniques
   are off the enterprise matrix (8 mobile — `T1417`, `T1418`, `T1430`, `T1636.002`,
   `T1636.003`, `T1660`; 1 ICS — `T0873`) and 2 are not techniques at all
   (`CAPEC-175`, and `TA0042`, which is a *tactic* id). ShinyHunters carries
   `T0866`, `T0882`, `T1404`. Each of these fabricates a coverage cell.

There is also a measured asymmetry feeding the evidence path itself:
`looks_like_domain` (ADR-0015) is applied when extracting atoms from **rules**
(`suricata_atoms.py`, `yara_atoms.py`, `synth_sigma.py`) and never when normalising
**reports**. `agent.ashx`, `exfil.tar.zst` and `psemhub.war` therefore become
`domain` observables. A bogus domain is rare by construction, so its IDF is ~1.0 —
the ADR-0014 failure mode of confident nonsense at the top of the list.

## Decision

**Coverage is scored on what a report gives you to match on — its technical
elements. ATT&CK stops carrying the score and becomes the axis that says where in
the kill chain the intrusion sits.**

Three parts.

### 1. The artifact is the unit of coverage

A coverage row is an **artifact**, keyed on `(artifact_class, normalized_value)` —
never on the display string. Display is not unique: `/etc/hosts` yields two
observables (the full path and the basename `hosts`) that share one display, which
is why it appears twice in the measurement output above.

Score, redefined against evidence:

| Score | Meaning |
|---|---|
| 3 | exact atom match in rules from ≥ 2 independent corpora |
| 2 | exact atom match in rules from exactly 1 corpus |
| 1 | weak match only — guarded substring, or the value appears in a rule title/description |
| 0 | no rule holds this value |

The corroboration rule of ADR-0008 is kept verbatim: a rule is attributed to the
first corpus its `native_key` is seen in, so a rule forked across repositories
collapses to one corpus and cannot inflate a score.

### 2. Artifacts are tiered by Pyramid of Pain

A hash match and a tool-name match are not the same detection claim, and averaging
them hides the difference. Each artifact class carries its pyramid tier:

| Tier | Pyramid level | Artifact classes |
|---|---|---|
| 1 | trivial | `hash` |
| 2 | easy | `ip`, `domain`, `url`, `cve` |
| 3 | annoying | `file`, `image`, `registry`, `user`, `port` |
| 4 | challenging | `name` (tool / malware identity) |

Coverage is reported **per tier**, never as one number. "1 of 5 hashes, 0 of 6
tools" is actionable; "8% covered" is not.

This also explains the failure being corrected here. TTPs are the pyramid's top
level, where matching is semantic rather than literal — which is exactly why a
string join on technique ids cannot support a coverage claim.

### 3. TTPs become the phase band, and are never derived into it

The ATT&CK matrix stays, in kill-chain order, carrying **no score**. It shows two
independent rows:

- **Report phases** — tactics of the techniques the report exhibits. Off-matrix and
  non-technique ids (`T0873`, `T1417`, `CAPEC-175`, `TA0042`) are listed separately
  as extraction noise rather than silently placed in a column.
- **Covered phases** — tactics carried by the rules that actually matched an
  artifact. Sourced from the *rule's* own ATT&CK tags, which are a
  detection-engineering fact, not from the report's extracted TTPs.

Neither row is computed from the other. The gap between them is the detection
roadmap, and it is honest precisely because the two sides are independent.

**The band has fifteen columns, not fourteen.** Building it surfaced a defect in
the existing matrix: `frontend/src/pages/Coverage.tsx` hard-codes the classic
fourteen enterprise tactics including `defense-evasion`, but the shipped
`mitre_index.json` renamed `TA0005` to **`stealth`** and added **`TA0112`
defense-impairment**. 148 techniques carry `stealth` and 56 carry
`defense-impairment`, so **204 enterprise techniques have been silently bucketed
as "other"** in the matrix. Copying that list into the backend reproduced the bug
exactly — `T1027.004`, `T1036`, `T1140` and `T1620` all landed off-matrix on the
real reports.

The column list is therefore locked against the index rather than against a
hand-copied list: `test_every_enterprise_tactic_in_the_index_has_a_column` fails
if any enterprise tactic in `mitre_index.json` has no column, so the next ATT&CK
version cannot reintroduce this quietly.

Measured after the fix, the off-matrix bucket contains exactly the extraction
noise it should: GREYVIBE 11 of 48 (8 mobile, 1 ICS, `CAPEC-175`, and `TA0042` —
a tactic id in a technique field), ShinyHunters 3 of 34 (2 ICS, 1 mobile).

### Denominator hygiene

An artifact-keyed denominator is only meaningful if noise stays out of it. Four
guards, each traceable to a measured value:

- **Report-side hostname guard** (implemented). `looks_like_domain` is applied to
  every `domain` observable, from the `domain`, `url` and `email` branches alike.
  Because that helper accepts any two-letter final label as a ccTLD, values ending
  in an executable/script suffix are additionally rejected — `meshctrl.js` passes
  the helper and is a JavaScript file.

  The suffix set is `EXECUTABLE_SUFFIXES` **minus `.com`**. `.com` is both a DOS
  executable suffix and the most common TLD in existence; including it rejected
  every `.com` domain, which two pre-existing relevance tests caught immediately.

  Measured before/after on the real reports: ShinyHunters goes from 41 to 38
  observables — `agent.ashx`, `exfil.tar.zst` and `psemhub.war` removed,
  `azurenetfiles.net` kept; GREYVIBE keeps `frontforce.org` and loses nothing.

  Erring toward rejection was checked rather than assumed. Sigma atoms are not
  passed through `looks_like_domain`, so they are an unbiased sample of what the
  gate would drop: of 2 454 domain-shaped Sigma `domain` atoms, 1 399 fail only
  the TLD test, and they are filenames almost without exception — `.exe` 382,
  `.zip` 163, `.ps1` 152, `.sln` 95, `.git` 65, `.csproj` 57. The single genuine
  domain category was `.onion` (3), so `onion` was added to `GTLDS`.
- **Vocabulary floor.** An artifact whose atom document frequency reaches
  `max(20, 0.0005 × canonical_rules)` — 37 on the live store — is corpus
  vocabulary rather than an indicator, and leaves the denominator while staying
  visible and flagged.

  The threshold is set from measurement, not judgement: `powershell.exe` 241,
  `cmd.exe` 190, `rundll32.exe` 143, `wscript.exe` 101, `svchost.exe` 91,
  `regsvr32.exe` 91, `mshta.exe` 87, `explorer.exe` 72, `curl` 43 and `net.exe` 43
  must not count as covered artifacts; `wget` 27, `python` 17, `mimikatz` 7,
  `psexec` 5, `cobaltstrike` 5, `anydesk` 4 and `/etc/hosts` 3 must. The threshold
  sits in that gap.

  It guards a case these two reports do not contain: across all 60 of their
  matchable values the maximum df is 3, and 56 have df 0. In particular the
  basename `hosts` derived from `/etc/hosts` matches nothing at all, so the floor
  is a safety valve for reports that name LOLBins, not a fix for observed noise.
  Because flagged artifacts stay visible, the exact threshold is not load-bearing.
- **Pseudo-filesystems and non-indicator addresses** stay excluded at the observable
  stage, as ADR-0014 established.
- **CVEs** carry no atom class and are matched against rule title and description
  only; they score, but can never reach 3 by atom corroboration.

### Scope

Coverage, the Detections panel and the export share one evidence key. The export
currently selects via `job_technique_ids`, so a report ships thousands of
technique-matched rules with no evidence behind them; after this change what is
shown, what is scored and what is exported are the same set.

## Options Considered

| Option | Coverage signal | Verdict |
|---|---|---|
| **A — keep ADR-0008's technique cells, re-score on evidence** | technique tag, gated by an evidence check | Rejected — keeps the UI intact and the smallest diff, but 58 of 64 cells go to 0 and the uncovered-artifact backlog, which is the useful output, has nowhere to live |
| **B — artifact rows + unscored tactic phase band** | exact/weak atom match, tiered by Pyramid of Pain | **Chosen** — the score becomes a claim that can be verified in one click, and the matrix keeps the job it is actually good at |
| **C — artifact coverage as an additional view** | both, side by side | Rejected — ships two competing definitions of "coverage", the confusion ADR-0008 set out to avoid |
| **D — fix TTP extraction first, keep technique scoring** | cleaner technique tags | Rejected as a *substitute*, kept as complementary (ADR-0023). Removing all 14 off-matrix ids still leaves 15 121 → ~13 000 rules on GREYVIBE with 1 evidence-backed. Extraction noise inflates the problem; it does not cause it |
| **E — embed artifacts and rules, rank by similarity** | vector similarity | Rejected for ADR-0014's reason — an IoC match is exact by nature, and embeddings blur exactly the distinction that matters |

## Consequences

- **Easier:** a coverage claim is now auditable — every score above 0 names the rule
  and the field that matched. The score-0 list is a ready-made detection-engineering
  backlog. Untagged rules (1 049 in Sigma alone) become scoreable, since evidence
  does not need a tag.
- **Coverage gets much sparser, and that is the intended result.** On these two
  reports it falls from "35 and 27 cells at score 3" to 3 and 1 artifacts with any
  match. A fresh campaign's indicators are, by construction, absent from public rule
  corpora. The view must therefore lead with the uncovered list and per-tier
  fractions, or it reads as a broken feature rather than a true one.
- **Harder / revisit:** reports with no IoCs at all. GREYVIBE carries 19 names and
  one domain — no hash, no IP. Its coverage rests entirely on tier 4, where matching
  is weakest, and the phase band carries most of the analyst value. If such reports
  are common, tier 4 matching (name → rule title/description) needs its own
  precision measurement before it can be trusted.
- **ADR-0008's 0–3 scale is retained in shape but re-based.** Same numbers, different
  denominator: the readiness/validation banner still applies, and "score 3" now means
  two corpora hold *this value*, not this tag.
- **`score_techniques` and its tests survive as the phase-band rule counter**, no
  longer as a coverage score. The ~30 tests keyed on technique cells must be re-read
  rather than mechanically repointed: several assert that a tag join produces a
  score, which is the behaviour being removed.
- **Cost profile is favourable.** `compute_for_job` measures 1.5–2.0 s and
  `rank_rules` 5.1–6.7 s today, both dominated by materialising 10–15 k
  technique-matched rules. Evidence selection touches 1–3 rules per report through
  `idx_rule_atoms_value`, so the new path should be far cheaper — to be confirmed,
  not assumed, and reported here once measured.

## Measured result

Run on the two real reports via `scripts/validate_artifact_coverage.py`:

| | Artifacts | Covered (≥2) | Weak (1) | Uncovered (0) |
|---|---|---|---|---|
| GREYVIBE | 20 | 1 | 2 | 17 |
| ShinyHunters | 38 | 3 | 2 | 33 |
| **Total** | **58** | **4** | **4** | **50** |

By Pyramid tier: trivial 1 of 5 (20.0%), easy 0 of 9 (0.0%), annoying 1 of 13
(7.7%), challenging 2 of 31 (6.5%).

Against the old view, which scored **62 of 64** technique cells at 2 or 3. The
covered artifacts are now individually checkable: one SHA-256 in `mthcht`, the
`meshagent` tool identity in `mthcht`, `TrickBot` in `mthcht`, and `/etc/hosts`
via a `sigmahq` cmdline. The uncovered list — five sequential C2 IPs,
`azurenetfiles.net`, four of five hashes, `CVE-2026-35273` — is the detection
backlog, and it is the artifact this change exists to produce.

`coverage_for_job` measures **3.8–3.9 s**, against `compute_for_job` at 1.5–2.0 s
and `rank_rules` at 5.1–6.7 s. Essentially all of it is the title sweep: a
`LIKE '%needle%'` over title/description costs ~3.6 s regardless of the needle,
because no index applies. Twenty needles as twenty queries would be 72 s; one
streaming sweep over all 75 127 canonical rules is 3.6 s once. That is the whole
reason `_title_evidence` is written as a single cursor.

## Validation on a third report (CERT Polska, energy sector)

The first two reports were IoC-poor. A 2025 CERT Polska incident report — 119
techniques, 25 tools, 23 files, 22 hashes, 13 IPs, 10 malware names, 7 URLs, 5
domains — exercised the paths they could not, and broke two of them.

**One technical element was counted several times.** `observables_from_entities`
emits several observables per element by design (ADR-0014): an executable gives
`file` *and* `image`; a value the extractor typed as both a `domain` and a `file`
entity gives `domain` + `file` + `image`. Coverage counted each as its own
artifact — 16 values twice, some three times, and **13 of the 28 "covered" rows
were duplicate halves**.

ADR-0014 had already drawn this lesson for *ranking* ("One source entity scores
once") and it was never carried across to *coverage*. Artifacts are now folded on
the normalized value: one row per element, representative class = strongest
Pyramid tier (ties broken alphabetically), evidence unioned and deduplicated, and
the score **recomputed** over the union rather than taken as the max — folding
`file` in corpus A with `image` in corpus B correctly yields 3.

| | before | after |
|---|---|---|
| CERT Polska | 116 artifacts / 28 covered | **97 / 21** |
| ShinyHunters | 38 / 3 | **29 / 3** |
| GREYVIBE | 20 / 1 | 20 / 1 (no duplicates) |

**`.com` struck twice.** Having already been excluded from the domain guard for
being the commonest TLD, it was still in the executable-suffix test on the `file`
branch — so `pastebin.com` and `curity.com` were emitted as `image`, i.e. as DOS
COM executables. `_is_executable_name` now applies the mirror carve-out: a `.com`
value that is also a well-formed hostname is not an executable.

### Malware identity was scored below system utilities

The same report exposed the scoring model as inverted at tier 4:

| Artifact | What it is | Rules | Score before |
|---|---|---|---|
| `Ping` | system utility | 347 | 2 |
| `netstat` | system utility | 16 | 3 |
| `BlackEnergy` | named APT family | 28, across 3 corpora | **1** |
| `PrestigeRansomware` | ransomware family | 1 | **1** |

Across the report, `tool` entities scored 2–3 in 12 of 18 cases while `malware`
entities scored 0–1 in 8 of 10 — the reverse of what an analyst expects.

The cause is structural, not a threshold. A tool's binary name (`ping`,
`certutil`) is an **atom value** inside a rule's detection block, so it matches
exactly and scores 2–3. A malware family name lives in the rule **title** — YARA
rules are literally named after families, ET signatures too — and title evidence
was capped at 1. Checked against the corpus: all 28 BlackEnergy matches are YARA
and Suricata rules named `BlackEnergy_BE_2`, `BlackEnergy_VBS_Agent`,
`BlackEnergyDDoSBotCrypter`. That is dedicated family coverage, not a mention.

**Decision: for a malware identity, a rule named after the family corroborates
like an atom match**, because in these corpora that is how family coverage is
expressed. Three constraints keep it honest:

- Only `malware` entities. A `tool` gets no title corroboration — its binary name
  is already reachable as an atom, and enabling it would score LOLBins on generic
  titles. `test_tool_name_gets_no_title_corroboration` locks this.
- Only the **title**. A description mention ("similar to BlackEnergy") is weaker
  and still scores 1; `_title_evidence` now distinguishes the two fields.
- Title evidence carries the rule's `native_key`, so a family named by a rule
  forked across two corpora still folds to one owner. Without it every weak
  evidence shared an empty key and corroboration silently collapsed to one corpus.

Measured after: `BlackEnergy` 1→3, `PrestigeRansomware` 1→2, `Impacket` 2→3,
`Rubeus` 2→3, while `Ping` stays 2 and `netstat` stays 3.

### What the report actually says

After folding, CERT Polska reads:

| Tier | Artifacts | Covered |
|---|---|---|
| 1 trivial (hashes) | 22 | **0** |
| 2 easy (IP / domain / URL / CVE) | 27 | 2 |
| 3 annoying (files, registry) | 20 | 5 |
| 4 challenging (tool / malware identity) | 28 | 18 |

Across all three reports — 146 artifacts — the Pyramid shape is the result worth
reading: **tier 1 3.7% covered, tier 2 5.6%, tier 3 21.4%, tier 4 38.2%**. Public
rule corpora encode families and tooling well and this week's indicators not at
all, which is exactly what they are for.

**Not one of the campaign's 22 hashes is covered by any rule in the 75 127-rule
store**, and the two tier-2 hits are `github.com` and `pastebin.com` — legitimate
services present in rules that detect exfiltration *behaviour*, not this
intrusion. Real network-indicator coverage is zero. That is the finding the view
exists to deliver, and the technique-keyed matrix reported the same report as
broadly covered.

## Known limitations

- **`/etc/hosts` scores 2.** Its df is 3, well under the vocabulary floor, and a
  `sigmahq` rule genuinely names it in a cmdline — so the score is literally true
  and still not what an analyst means by coverage. ADR-0014 deliberately keeps
  `/etc/hosts` as an observable (an explicit test asserts it), so this is left
  as-is rather than silently reversed. The tier label ("annoying") is currently
  the only thing telling the reader it is not a campaign identity.
- **Extraction noise reaches the denominator.** `JavaScript-based loader` and
  `Python SimpleHTTP` are typed as tools and become tier-4 artifacts. They cannot
  be scored and inflate the uncovered count.
- **Generic words extracted as malware names now over-score.** Enabling title
  corroboration promotes `Solar` (56 rules — actually SolarWinds, SolarMarker and
  SolarPhantom, three unrelated things sharing a prefix) and `Wiper` (38 rules —
  a category word) to 3. Neither is a family. This is deliberately *not*
  compensated for in scoring: the defect is that extraction emits them at all, and
  a word list bolted onto the scorer would hide it rather than fix it. `Ping`,
  `route`, `Expand`, `Slack` and `Microsoft Edge` are the same defect on the tool
  side. Tracked separately.
- **The title sweep is now the whole cost.** `coverage_for_job` measures
  5.5–7.0 s, up from 3.8 s: the sweep additionally reads `native_key` and tests
  title and description separately. Still one streaming pass over the canonical
  rules; if this becomes the binding constraint the answer is an index on rule
  titles, not more queries.
- **Tier 4 dominates IoC-poor reports.** GREYVIBE is 19 of 20 artifacts at tier 4,
  where the only mechanism is usually a title match. Spot-checked on the three
  names that matched: `Elise` 12 rules, `XMRig` 31, `TrickBot` 72, and every one
  is genuinely about that family — no substring accidents. That is reassuring
  rather than conclusive: all three are distinctive strings, and a family whose
  name is an ordinary word would behave differently.
- **A title-only match reports its corpora separately.** `Elise` scores 1 with
  `corpora: []`, because `corpora` is the set that drives the score and only
  exact atom evidence may drive it. On an IoC-poor report that read as no
  coverage at all, while four corpora carry twelve rules named after it — so
  `evidence_corpora` is reported alongside, spanning all evidence. It informs;
  it must never score, because a rule *named after* a family is not a rule
  holding a value in a detection field.

## Implementation

Landed: `pipeline/detection/artifacts.py` (artifact scoring, Pyramid tiers,
vocabulary floor, title sweep), `pipeline/detection/phases.py` (the two-row band),
the report-side hostname guard in `pipeline/detection/observables.py`, `onion` in
`pipeline/detection/tlds.py`, and `native_key` on `store.rule_details` — added
because `_owner_corpora` was re-deriving the key from the rule id, which agrees
with the persisted column only by accident of how ids are built.

API: `GET /api/jobs/{job_id}/coverage/artifacts`, backed by
`artifacts.coverage_with_phases`, which composes the artifact rows and the phase
band from **one** scoring pass — `_summarize` is factored out of
`coverage_for_job` for exactly that reason, since scoring twice would double the
3.8 s title sweep.

Only artifacts that are unexcluded **and** score ≥ 1 contribute rules to the
band. Vocabulary and unmatchable values are precisely the generic ones, and
letting them place phases would light up the kill chain from noise.

Harnesses: `scripts/measure_ttp_vs_observable_coverage.py` (the before/after that
opens this ADR) and `scripts/validate_artifact_coverage.py`.

The fifteen-column correction is applied to `frontend/src/pages/Coverage.tsx`.

Still to land: the artifact view itself in the Coverage page, and moving the
export off `job_technique_ids`.

### A test that locked nothing

`test_artifact_route_is_not_shadowed_by_the_technique_route` was written to prove
route ordering mattered — the spec asserted `/coverage/artifacts` would be
captured by `/coverage/{technique_id}/rules` unless declared first. Moving the
route below it left all five tests passing: the second template carries a
trailing `/rules` segment, so the two templates cannot compete at any ordering.
The premise was wrong and the test verified nothing. It is now a payload contract
test, which is what the frontend actually depends on.
