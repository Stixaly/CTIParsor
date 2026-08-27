# ADR-0030: Evidence-gated coverage, and corroboration scored on adversary-controlled values

Status: Proposed
Date: 2026-08-27
Supersedes the *selection* rule of ADR-0008 / ADR-0022; extends ADR-0025.

## Context

ADR-0025 established that the artifact, not the ATT&CK technique, is the unit of
coverage — and it was implemented: `GET /api/jobs/{id}/coverage/artifacts` works
today and answers in 4.7 s. **The frontend never calls it.** `Coverage.tsx` and
`client.ts` consume `/coverage/rules`, the unchanged technique-tag join. So the
decision was made, built, and never reached the analyst.

Measured across all seven reports in `cti_stix.db` (`scripts/measure_relevance.py`):

| report | observables | tag-joined rules | with evidence | ≥ 2 observables |
|---|---|---|---|---|
| aeternum blockchain C2 | 101 | 17 463 | 120 | 1 |
| distinct-clusters (Russia) | 71 | 12 280 | 3 | 0 |
| industroyer-v2 | 6 | 1 722 | 0 | 0 |
| GREYVIBE | 20 | 14 675 | 1 | 0 |
| ShinyHunters PeopleSoft | 37 | 10 398 | 3 | 1 |
| apt44 / Sandworm | 138 | 22 779 | 335 | 24 |
| CERT Polska energy | 122 | 7 136 | 446 | 148 |
| **total** | **495** | **86 453** | **908** | **174** |

**1.05 % of what the panel proposes is backed by anything the report contains.**
On `distinct-clusters` it is 3 rules in 12 280 — a ratio of 1 : 4 093.

Three defects sit behind that number.

### The evidence surface has a hole

`MATCHABLE` in `pipeline/detection/relevance.py` maps each report observable class
to the rule-side atom classes it may match. Two indexed atom classes appear in no
value set at all, so nothing can ever reach them:

| atom class | atoms indexed | holds | reachable |
|---|---|---|---|
| `strlit` | 53 517 (32 642 YARA + 20 875 Suricata) | every YARA string, every Suricata `content:` | never |
| `pipe` | 14 468 (Sigma) | named pipes | never |

Compounding it: **0 of the 16 314 canonical YARA rules carry an ATT&CK tag.** YARA
is invisible to the technique join by construction, and its only evidence path is
`strlit`. It is therefore reachable *solely* through an exact hash match — which is
why every report in the table above reports zero YARA rules in its coverage panel.

### Document frequency cannot tell a LOLBin from a campaign identity

ADR-0025 excludes "corpus vocabulary" at `df ≥ max(20, 0.0005 × rules)` = **37** on
the live store. Measured against that threshold:

| kept (df < 37) | df | | stripped (df ≥ 37) | df |
|---|---|---|---|---|
| `certutil` | 15 | | `api.telegram.org` | 60 |
| `schtasks` | 16 | | `powershell.exe` | 241 |
| `systeminfo` | 14 | | `cmd.exe` | 190 |
| `ping` | 10 | | `rundll32.exe` | 143 |
| `netstat` | 9 | | `curl` | 43 |
| `tasklist` | 7 | | | |

The threshold keeps six system binaries and throws away a genuine C2 hostname. It
cuts the wrong way because df measures rarity **in the rule corpus**, and that is
simply not the property being asked about. `certutil` is rare among rules and
present on every Windows host; `api.telegram.org` is common among rules precisely
*because* it is a real and recurring C2 channel.

This is not a tuning problem. No value of the threshold separates these two lists.

### Naive corroboration ranks the noisiest rules first

174 rules already match ≥ 2 distinct observables, so corroboration is measurable
today. But sorting by that count, unweighted, produces this on CERT Polska:

```
5  sigmahq  Windows Suspicious Child Process from Node.js   :: Ping, PowerShell, certutil
4  sigmahq  Potentially Suspicious Execution From Parent    :: PowerShell, certutil, cmd.exe
4  sigmahq  Mint Sandstorm - AsperaFaspex Suspicious Proc   :: Tasklist, certutil, powershell.exe
4  sigmahq  Potential Data Exfiltration Via CommandLine     :: Tasklist, cmd.exe, netstat
```

Every corroborating value is a system binary. On apt44, fourteen separate rules tie
at n=2 on the identical pair `powershell.exe + schtasks.exe`. Meanwhile the genuinely
informative hits sit at n=1 — `api.telegram.org`, `Mimikatz`, `METASPLOIT` — and would
be ranked *below* the noise.

Corroboration is the right idea and the raw count is the wrong statistic.

## Decision

### 1. The coverage panel serves evidence-backed rules only

`/coverage/rules` gains an evidence gate and becomes the panel's sole source of
truth. A rule appears if and only if it holds at least one value the report
contains. The technique-tag join is **not** deleted — the ZIP export and the
detection-engineering backlog both legitimately want "every rule tagged with this
report's techniques" — but it stops being the thing the panel counts and shows.

The panel will be near-empty on a fresh campaign. **That is the correct answer and
it ships that way**, per ADR-0025's own consequence: a new campaign's indicators are
by construction absent from public corpora. The UI leads with the uncovered count so
this reads as a true finding, not a broken feature.

### 2. `strlit` and `pipe` become matchable

```python
"hash":     {"hash", "strlit"},
"ip":       {"ip", "url", "cmdline", "strlit"},
"domain":   {"domain", "url", "cmdline", "strlit"},
"url":      {"url", "cmdline", "strlit"},
"file":     {"file", "image", "cmdline", "strlit"},
"image":    {"image", "file", "cmdline", "strlit"},
"registry": {"registry", "strlit"},
"name":     {"image", "file", "service", "cmdline", "strlit", "pipe"},
```

Measured effect on evidence-backed rules across the seven reports:

| format | before | after |
|---|---|---|
| yara | 32 | **73** |
| suricata | 71 | **117** |
| sigma | 467 | 468 |

It buys recall almost entirely in single-evidence rules (174 → 177 at n ≥ 2), so it
adds reach without adding corroboration noise.

### 3. Corroboration counts discriminating values only

A third axis, which neither df nor the Pyramid tier supplies: **does this value
distinguish this report from every other intrusion report?**

- `discriminating` — narrows the field: hashes, C2 domains/IPs/URLs, campaign
  filenames, malware family names, mutexes, named pipes, abused-service endpoints.
- `ubiquitous` — present in the overwhelming majority of intrusion reports and
  therefore carrying no ranking signal: LOLBins and OS binaries, shell and
  interpreter names, standard system paths.

Only `discriminating` values corroborate, **and only they admit**. A `ubiquitous`
value is still shown as supporting evidence on a rule that earned its place — it
is true that the rule looks for `certutil` — but it contributes zero to the
corroboration count and cannot, on its own, put a rule in front of an analyst.

The admission half of that rule was missed in the first implementation and cost
more than the scoring half would have, because admission is what reaches the
export. Measured on the Cisco SD-WAN report: **60 rules served, 50 of them
justified by nothing but `/bin/bash` (39 rules), `/etc/passwd` (10) and
`/etc/shadow` (3)**, while the proposals panel beside it reported 14 direct hits.
A user downloaded the ZIP and asked why it held 58 Sigma rules. Corrected in
`_admits`; the same predicate now gates the panel and the export.

The first draft of this decision used *adversary-controlled* vs *system-provided*,
borrowed from [Summiting the Pyramid](https://ctid.mitre.org/projects/summiting-the-pyramid/).
It was discarded on inspection: `api.telegram.org` is controlled by Telegram, not by
the adversary, and would have been classified `system` and stripped — yet it is
precisely the kind of evidence this ranking exists to surface, because only a subset
of campaigns run C2 over Telegram. Control and discrimination correlate but are not
the same property, and the one this feature needs is discrimination. STP remains the
right frame for scoring *rule robustness*, which is a separate axis (see Options).

Classification is a static table (`pipeline/detection/control.py`), seeded from
LOLBAS and the OS binary sets, applied **after** normalisation and **before**
scoring. It is deliberately a table and not a heuristic: ADR-0025 already found that
a word list bolted onto a scorer hides extraction defects, so this table classifies
by identity, never by shape, and every entry is auditable.

Honest limitation stated up front: with seven reports in the store there is no way
to *measure* ubiquity, so the table encodes a judgement. Once the corpus is large
enough, report-side document frequency should replace it, and the table becomes the
bootstrap rather than the mechanism.

### 4. The composite score

For a rule *r* against a report:

```
corroboration(r) = Σ over distinct discriminating observables o matched:
                       CLASS_WEIGHT[o.class] × idf(matched_value)
                       × (PARTIAL_FACTOR if the match was a substring)
score(r)         = (1 − exp(−(corroboration(r) + technique_term(r))))
                   × platform_factor(r)                                # 0..1
```

Every factor already exists in `relevance.py` — `CLASS_WEIGHT`, `idf`,
`PARTIAL_FACTOR`, `platform_factor`, and the ADR-0018 `technique_term` capped at
`TECH_EXACT` = 0.30. Nothing new is invented, and in particular the Pyramid tier is
**not** used in the formula: `CLASS_WEIGHT` already encodes evidential strength for
relevance (hash 1.00 → port 0.25), which is the question here. The tier answers a
different one — how painful the indicator is for the adversary to change — and stays
where ADR-0025 put it, in the artifact view.

What changes is the *combination*. Noisy-OR over a hard cap of `MAX_SCORING_MATCHES`
= 4 is replaced by a sum inside a saturating exponential, so a third and a fourth
genuine observable keep moving the score instead of hitting the cap:

| discriminating matches (domain, idf ≈ 0.9) | old noisy-OR | new |
|---|---|---|
| 1 | 0.77 | 0.53 |
| 2 | 0.94 | 0.78 |
| 3 | 0.99 | 0.90 |
| 4 | 0.997 | 0.95 |

The new curve is lower everywhere and, unlike the old one, still has headroom at 4.
A technique-only rule reaches 1 − exp(−0.30) = 0.26 and can never pass a single
discriminating match. `ubiquitous` values are summed into a separate `support`
figure that is reported and never scored.

Sort key becomes `(-discriminating_match_count, -score)`: a rule holding three
campaign values outranks any rule holding one, and the composite score breaks ties
within a count. Rules with zero discriminating evidence sort last regardless of score.

## Options considered

| Option | Verdict |
|---|---|
| Raise the df vocabulary threshold | Rejected — measured: no threshold separates `certutil` (15) from `api.telegram.org` (60). The axis is wrong, not the cut. |
| Keep noisy-OR, raise `MAX_SCORING_MATCHES` | Rejected — saturation still lets one hash outrank three corroborating domains, and it does nothing about LOLBin corroboration. |
| Derive discrimination from the Pyramid tier | Rejected — the tier is assigned per observable *class*. `certutil` and `Mimikatz` are both class `name`, tier 4. The tier cannot see the distinction. |
| Classify by adversary control instead (STP framing) | Rejected on inspection — `api.telegram.org` is Telegram-controlled and would be stripped, though it is exactly the evidence worth surfacing. See Decision 3. |
| Ingest Summiting the Pyramid scored analytics | Deferred — STP scores rule robustness, an orthogonal quality axis, and ships one CSV covering a fraction of the corpora. Useful as a later tiebreaker; it does not answer relevance. |
| Delete the technique join entirely | Rejected — the export and the backlog view need it. It is demoted, not removed. |

## Consequences

- **The panel gets much smaller and much truer.** 12 280 → 3 on `distinct-clusters`.
  The uncovered list becomes the deliverable: it is a detection-engineering backlog
  with the report's own artifacts as its items.
- **YARA becomes reachable at all** for the first time — 73 evidence-backed rules
  across seven reports, up from 32, on a corpus of 16 314 that carries no ATT&CK tag.
- **Easier:** every rule shown names the value and the field that matched. A coverage
  claim is auditable end to end.
- **Harder:** the discrimination table needs maintenance. A LOLBin missing from it
  silently corroborates. Mitigated by making the table data, testable, and printed by
  the measurement harness.
- **Extraction noise is now load-bearing.** ADR-0025 noted `Solar` and `Wiper` typed
  as malware; under corroboration scoring such a name now *adds* to a count rather
  than merely appearing. The table classifies category words as `ubiquitous` as a
  stopgap; the real fix stays upstream in extraction.
- **`score_techniques` keeps its ADR-0022 role** as the phase-band rule counter and
  the export selector. Its tests are unaffected.

## Measured result

`scripts/check_evidence_gate.py` on the live store, all seven reports:

| report | tag join | gated | untagged | ≥2 evidence | ms tag → gated |
|---|---|---|---|---|---|
| aeternum blockchain C2 | 17 463 | 138 | 102 | 0 | 7 683 → 2 919 |
| distinct-clusters | 12 280 | 3 | 3 | 0 | 5 286 → 2 072 |
| industroyer-v2 | 1 722 | 0 | 0 | 0 | 1 161 → 714 |
| GREYVIBE | 14 675 | 1 | 0 | 0 | 6 524 → 2 470 |
| ShinyHunters | 10 398 | 3 | 1 | 2 | 4 540 → 1 613 |
| apt44 / Sandworm | 22 779 | 356 | 154 | 17 | 10 740 → 4 942 |
| CERT Polska | 7 136 | 510 | 266 | 7 | 5 684 → 3 575 |
| **total** | **86 453** | **1 011** | **526** | **26** | **41 618 → 18 305** |

- **86 453 → 1 011 rules**, and the panel is 2.3× faster because it stops
  materialising rules it was going to show without justification.
- **526 rules become visible that no view could previously reach** — over half the
  gated set. These carry no ATT&CK tag and arrive purely through `strlit`.
- **`≥2 evidence` fell from 174 to 26** once discrimination was applied. That drop is
  the control table working: the 174 included fourteen apt44 rules tied on
  `powershell.exe + schtasks.exe`. What survives is `SMOKELOADER + TrickBot`,
  `rsocx + rsocx.exe`, `pastebin.com + github.com/b23r0/` — real corroboration.

### Top of the new ranking, aeternum (blockchain/Telegram C2)

```
 1  ev=2  0.544  sigma  Simple keyword detection rule for Xworm   XWorm=image | XWorm RAT~cmdline
 2  ev=1  0.550  sigma  Microsoft Binary Github Communication     github.com/lencod/=domain
 3  ev=1  0.545  sigma  Telegram Bot API Request                  api.telegram.org=domain
 7  ev=1  0.535  suri   ET INFO Observed Smart Chain Domain (DNS) api.zan.top/polygon-amoy=domain
 8  ev=1  0.535  suri   ET INFO Observed Smart Chain Domain (DNS) endpoints.omniatech.io=domain
```

Every entry is about this report: a RAT the report names, its GitHub C2 path, its
Telegram channel, and the blockchain RPC endpoints the title is about. Before this
change the same report's top entry was `gmail.com` matching ET "Google Talk"
signatures, reached because an attacker's mail address had been reduced to its
free-mail domain.

### Defects the validation exposed

- **`netstat` was missing from the control table** and was silently corroborating.
  Caught by `test_the_values_document_frequency_kept_are_now_stripped`, which failed
  before the entry was added and passes after — the ADR-0025 step-8bis check.
- **The first implementation of the `(untagged)` group could never fill**, because
  the gate had already merged every evidence-backed id into `all_ids`. It is now
  computed against the rules actually placed in a technique group. Without this,
  YARA would have stayed invisible — the exact defect being fixed.
- **`_evidence_for_job` created an empty entry for every rule `atom_hits` touched**,
  so rules whose only hit failed the matchable filter would have passed the gate
  with no evidence. The entry is now created only when a hit survives.

### Test state

849 passed, 2 skipped. Two pre-existing tests asserted the tag join's output and now
pass `evidence_only=False` — they test the roll-up and the query count, which both
survive; a third asserted the exact key list of a rule dict and gained the two new
keys.

## Still open

- **`rsocx` and `rsocx.exe` count as two.** Dedup is on the report's display string,
  so one identity spelled two ways corroborates twice. Under-counted risk is nil,
  over-counting is real; needs identity folding, not a scorer patch.
- **mthcht ships near-duplicate rules that dedup does not fold** — ten identical
  "Simple keyword detection rule for Antivirus Si…" entries share the apt44 top.
  Unrelated to this ADR, visible because the list is finally short enough to read.
- **The discrimination table encodes judgement, not measurement.** Seven reports
  cannot estimate ubiquity. Replace with report-side document frequency once the
  corpus supports it; the table is the bootstrap.
