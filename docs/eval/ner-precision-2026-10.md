# Entity precision: CyNER and spaCy filters on AnnoCTR train + dev — October 2026

The audit of 2026-10-17 named entity precision as the main quality defect of
the shipped bundle; on AnnoCTR dev most false positives came from CyNER
(threat actors, malware) and spaCy (locations, malware). Four filters were
designed on train and measured on dev against criteria fixed beforehand.
Two are adopted, on by default (`NER_PRECISION_FILTERS`, ADR-0088): CyNER's
threat actors written as ordinary language are dropped (precision 0.134 →
0.326, nothing lost) and spaCy's locations must look like a place name
(0.406 → 0.526, one gold entity gained). The two malware filters and the
name normalisation each stayed under the +5-point gate on their own, and
malware precision is unchanged (0.205).

## Adoption criteria (fixed before any dev measurement)

Written on 2026-10-18, before any figure with a filter was computed on dev.
They are not changed after the measurement.

Each lead below is judged on its own, on the types it acts on, then the
retained leads together.

| # | Criterion | Applies to |
|---|---|---|
| G1 | Strict precision of the type gains at least +5 points on dev, and the lower bound of the 95% paired-bootstrap interval is above 0 | each type a lead acts on |
| G2 | At most one gold entity of the type is lost on dev (a strict true positive becomes a false negative, net). That is 6.3 points for threat actors (16 gold), 2.6 for malware (39), 1.0 for locations (97). Every lost entity is listed and read | same |
| G3 | Strict F1 of the type does not go down on dev | same |
| G4 | No other type's strict precision or recall drops by more than 1 point on dev | the other scored types |
| G5 | On train, where the lead was designed, it loses at most 2% of the type's true positives | sanity check, train |
| G6 | The retained combination, run for real on dev with the LLM, against a baseline run of the same commit with the switch off, meets G1–G4 for each type | the decision |

One amendment, also before any dev figure: G4 first read "moves by more than
1 point". On train, removing a CyNER row lets a spaCy location through the
type-conflict resolution (`pipeline.base.resolve_type_conflicts`), which
raises location recall. Such a gain is not what G4 guards against, so G4 now
reads "drops".

The offline simulation (G1–G5) only chooses what goes to the real run. The
real run (G6) decides, because the LLM sees CyNER's names in its prompt and
drops its own names that CyNER already found. Removing a CyNER row can
therefore bring back an LLM row, or change what the LLM extracts.

Bootstrap: documents resampled with replacement, 10,000 resamples, seed 13,
2.5th and 97.5th percentiles (`evaluation.metrics.paired_bootstrap`).
Matching: `evaluation.metrics.score_entities`, strict (one-to-one, exact pairs
first, a partial pair counts as a false positive and a false negative).

The test split is not read.

## Setup

- Commit `1ef9638` (main after PR #171), run from a detached worktree.
  `ENTITY_OVERRIDES_ENABLED=0` and `THRESHOLD_CALIBRATION_ENABLED=false`, so
  no analyst row changes what the models return.
- **Train** (70 documents with the cybersecurity layer): Stages 1, 2, 2b, 2d,
  2e, 2g, with Stage 2c and Stage 3 off (`--disable 2c,3 --allow-degraded`).
  No LLM, so the train figures are those of the extractors alone.
- **Dev** (16 documents): the full `evaluation run` configuration (Stages
  1–3 with 3d and 3f, `TTP_MODE=select`, `LLM_TEMPERATURE=0 LLM_SEED=13`,
  `VLLM_MODEL=Inferact/Qwen3.8-27B-NVFP4`).
- Both runs record what the models returned: CyNER's predictions as the
  HuggingFace pipeline gave them, and every spaCy entity of every chunk with
  its label and sentence. The simulation re-runs Stage 2 on these records
  with the code of the branch: spaCy and CyNER are replaced by stubs that
  return the recorded output, everything else (the regex extractors, the
  filters, the merge in `pipeline/orchestrator.py`, the type conflicts) runs.
  With the switch off, the simulation gives back the run's Stage 2 entities
  exactly, document by document (70/70 on train), or it stops. On dev the
  LLM's names are added as the run recorded them.
- The record is taken before the stages deduplicate: CyNER and spaCy keep the
  first spelling of a name (case-insensitive), and a filter that drops
  "blackwater" from a URL must let a later "BlackWater" through. A simulation
  on the saved entity rows alone would count it as lost.

## The four leads, as designed on train

As measured. What the dev measurement retained (A for threat actors, and D)
is in `pipeline/ner_precision.py`, applied when `NER_PRECISION_FILTERS` is
true; A for malware, B and C are described here and are not in the code
(see "Decision").

- **A. CyNER, ordinary language.** A fragment is dropped when it has no
  capital letter and no digit ("cybercriminals", "underground forums",
  "banking trojan"), or when every word of 3+ letters is a category word:
  ADR-0050's list plus 178 words read in the train false positives
  (criminals, underground, forum, botnet, keylogger, affiliates, bad, same,
  multiple…) and Stage 2's list of software names (Linux, Windows, JSON;
  PowerShell, Mac, VBS, VBA, Excel and Office added).
  For actors, nationalities and countries count as category words too
  ("Chinese threat actors", "Iran", "United States", "Hong Kong"). A fragment
  with no letter, or a CVE id, is dropped: the bracket split of B can leave one
  ("Emotet (4.2)"). Words that form real names stay out of the list:
  "miner" (Miner Dropper), "agent" (X-Agent), "crew" (Shell Crew), "circles"
  (Circles); "Agent", "Crew" and "Miner" alone are dropped. The
  capital-letter test is skipped for a text with fewer than 0.5% capital
  letters (a chat log, a lowercased OCR), where case says nothing; the
  share is counted on words made only of letters, so an appendix of
  hashes or URLs does not count, and every train and dev report has more
  than 1.6%.
- **B. CyNER, a name with its category around it.** Fragments are also split
  on brackets ("Winnti Group (APT41"). A leading run of category words ending
  with a category noun is dropped ("hacking group TA505", "multipurpose trojan
  QBot"), and so is a trailing category word that never ends a name
  ("Ryuk ransomware", "TA575 campaign", "TrickBot banking trojan"), as long
  as what remains has a letter and a word that is not a category or software
  word ("Group 123" and "Linux backdoor" stay whole, and A then judges them).
  The leading nouns are per type: an actor keeps "Backdoor" in "Backdoor
  Diplomacy". "RAT", "loader", "stealer", "dropper" and "kit" are not
  stripped: Hallaj Pro RAT, Smoke Loader, Miner Dropper and RIG Exploit Kit
  are names. The shortened value then merges with the same name found by
  CyNER elsewhere in the report, keeping the higher confidence, or by another
  stage.
- **C. spaCy, malware.** spaCy's PRODUCT label no longer proposes malware.
- **D. spaCy, locations.** The value is put on one line ("Saudi\nArabia"
  from a wrapped line), a trailing apostrophe and a leading "the" are
  dropped ("the United States"
  is scored as a partial match, and Stage 4's ISO country table does not
  know it). A country or a known abbreviation (U.S., USA, PRC…) is kept;
  two-letter values stay dropped by Stage 2's length rule, as before ("US",
  and now "the US"). Anything else is kept only if it can be a place name:
  letters (accented ones too: São Paulo), spaces, periods, hyphens and
  apostrophes only; a capital first letter; not an all-capital acronym of
  five letters or fewer (XSS, SCADA, IRGC); no camel case (GitHub, DocuSign;
  McLean and MacKenzie are allowed); not made only of category or software
  words (Payload, Exploit, Linux).

Two rounds of code review before the dev measurement changed the design in
the ways listed above (a remainder must have a letter, fragments with no
letter, CVE ids, platform words, multi-word countries, per-type leading
nouns, the higher confidence on a merge, whitespace, the trailing
apostrophe, the two-letter rule, the lowercase-text exception, four words
out of the list and three that are dropped alone) and removed a
possessive strip that turned "St. John's" into "St. John". The train
figures below are those of the reviewed code.

Three ideas were tried and left out. A country list alone (keep a spaCy
place only if Stage 4's ISO table knows it) lost 21 train true positives,
the cities and states (Oldsmar, Jeddah, Texas). spaCy's own labels (keep a place only if
spaCy calls the same string a place at least as often as anything else in
the chunk) removed nothing and lost two places. Dropping a place whose name
is the host of a link in the chunk (proofpoint.com) removed 6 false
positives and lost Doha.

### Train figures (no LLM)

Strict matching; P and R before → after, true positives lost.

| Lead | Threat actor P | R | Malware P | R | Location P | R | Lost (train TP) |
|---|---|---|---|---|---|---|---|
| none | 0.132 | 0.851 | 0.213 | 0.869 | 0.440 | 0.401 | — |
| A | 0.320 | 0.851 | 0.261 | 0.858 | 0.443 | 0.406 | malware 2 of 153 (1.3%) |
| B | 0.148 | 0.878 | 0.244 | 0.886 | 0.443 | 0.401 | none |
| C | — | — | 0.243 | 0.864 | — | — | malware 1 of 153 (0.7%) |
| D | — | — | — | — | 0.599 | 0.440 | location 1 of 143 (0.7%) |
| A+B | 0.409 | 0.878 | 0.312 | 0.886 | 0.446 | 0.406 | none |
| A+B+C+D | 0.409 | 0.878 | 0.378 | 0.881 | 0.607 | 0.445 | malware 1, location 1 |
| A on actors, D (what ships) | 0.320 | 0.851 | 0.213 | 0.869 | 0.602 | 0.445 | location 1 |

Gold on train: 74 threat actors, 176 malware, 357 locations. Counts at the
baseline: threat actors 63 TP / 413 FP, malware 153 / 565, locations 143 /
182. With all four leads: 65 / 94, 155 / 255, 159 / 103.

What is lost, read in context:

- A, malware: "BlackWater" twice, both times found only in a URL slug
  (`quointelligence.eu/2020/08/blackwater-malware-leveraging-…`). With B the
  report's "BlackWater Malware" is reduced to "BlackWater" and one of the two
  comes back.
- C, malware: "Taurus" in the Golden Chickens report, found by spaCy alone
  (CyNER read "Taurus Builder Kit", "Taurus Building Kit" and "Taurus
  building kits", which B does not shorten: "kit" can end a name).
- D, location: "The United States", annotated with its capital "The"; the
  report's other mentions become exact matches (15 partial matches turn into
  true positives).

G5 holds for every lead.

What A+B+C+D leaves is mostly real names that AnnoCTR does not annotate in
that report (Fancy Bear, APT10, Sofacy, Lazarus, Winnti; DarkSide, LockBit,
Nefilim) and gazetteer matches outside this work ("elise" 15 times, see
[gazetteer-policy-2026-10.md](gazetteer-policy-2026-10.md)). Among places,
vendor names are what remains (Proofpoint 15 times, Gecko, Citrix, Cisco):
nothing in their spelling tells them from a town.

## Dev, offline simulation

The baseline run (`ner-dev-base-1ef9638`) re-run through the simulation with
each lead, its LLM names added unchanged. With the switch off, the
simulation gives back the run's Stage 2 entities on 16/16 documents, with
the branch's code: the branch changes nothing while the switch is off.

Dev gold: 16 threat actors, 39 malware, 97 locations. Baseline (strict):
threat actors 15 TP / 97 FP (P 0.134, R 0.938), malware 34 / 132 (0.205,
0.872), locations 39 / 57 (0.406, 0.402), with the LLM.

Differences in points, 95% paired-bootstrap interval in brackets.

| Lead | Type | Precision | Δ precision | Recall | Lost / gained | G1 | G2 | G3 | G4 |
|---|---|---|---|---|---|---|---|---|---|
| A | threat actor | 0.134 → 0.319 | +18.5 [+10.4, +31.1] | 0.938 → 0.938 | 0 / 0 | pass | pass | pass | pass |
| A | malware | 0.205 → 0.231 | +2.6 [+1.5, +4.0] | 0.872 → 0.872 | 0 / 0 | **fail** | pass | pass | pass |
| B | threat actor | 0.134 → 0.146 | +1.2 [+0.4, +2.4] | 0.938 → 0.938 | 0 / 0 | **fail** | pass | pass | pass |
| B | malware | 0.205 → 0.234 | +3.0 [+1.2, +5.7] | 0.872 → 0.872 | 0 / 0 | **fail** | pass | pass | pass |
| C | malware | 0.205 → 0.239 | +3.5 [+1.8, +5.1] | 0.872 → 0.872 | 0 / 0 | **fail** | pass | pass | pass |
| D | location | 0.406 → 0.526 | +12.0 [+4.7, +19.4] | 0.402 → 0.412 | 0 / 1 | pass | pass | pass | pass |

F1: A actors 0.234 → 0.476, A malware 0.332 → 0.366, B actors → 0.252,
B malware → 0.370, C malware → 0.376, D locations 0.404 → 0.462. B and C
also raise location precision by 0.4 points: one spaCy location now loses
a type conflict ("Kaseya", against CyNER's "Kaseya ransomware" shortened by
B; "NetWire", against the gazetteer's malware once C removes spaCy's).
D's gained entity is "Kingdom of Saudi Arabia", which spaCy gave as "the
Kingdom of Saudi Arabia" (once with a non-breaking space).

No lead loses a gold entity on dev. A for malware, B and C each remove only
false positives (19, 9 + 21 and 24 of them), but none reaches the +5 points
G1 asks of a lead on its own. Together, the four leads would raise malware
precision by 13.2 points [+9.1, +18.6] with nothing lost; that figure is
read after the fact and decides nothing (see "Decision").

Retained by the rule: **A for threat actors, and D**. Together, offline:
threat actors 0.134 → 0.319 (15 TP / 32 FP), locations 0.406 → 0.526
(40 / 36), the other types unchanged. The module as trimmed to these two
gives the same figures as the two leads written out, on train and dev.

## Dev, real run (G6)

The trimmed module run for real on dev with the LLM, switch on
(`ner-dev-cand-1ef9638p`: commit `1ef9638` plus this change's five source
files, same settings as the baseline), against the baseline
(`ner-dev-base-1ef9638`, `1ef9638`, which behaves as the switch off: the
simulation above reproduces it with the branch's code). The candidate run
stopped after 12 documents when the session was interrupted and was resumed
for the last 4: `evaluation run` skips the documents already written, and
each document is run on its own with fixed sampling.

Scored by `evaluation compare` (10,000 resamples), strict:

| Type | Precision | Δ precision | Recall | Δ recall | F1 | Lost / gained |
|---|---|---|---|---|---|---|
| threat actor | 0.134 → 0.326 | +19.2 [+11.4, +30.9] | 0.938 → 0.938 | 0 | 0.234 → 0.484 | 0 / 0 |
| location | 0.406 → 0.526 | +12.0 [+5.1, +18.9] | 0.402 → 0.412 | +1.0 [0, +3.1] | 0.404 → 0.462 | 0 / 1 |
| malware | 0.205 → 0.205 | 0 | 0.872 → 0.872 | 0 | 0.332 → 0.332 | 0 / 0 |
| tool | 0.344 → 0.355 | +1.1 [0, +3.9] | 0.733 → 0.733 | 0 | 0.468 → 0.478 | 0 / 0 |
| identity | 0.345 → 0.345 | 0 | 0.377 → 0.377 | 0 | 0.360 → 0.360 | 0 / 0 |

Counts: threat actors 15 TP / 97 FP → 15 / 31 (CyNER's false positives
87 → 22), locations 39 / 57 → 40 / 36 (false positives proposed by spaCy
alone 44 → 23). The location gained is the same as offline ("Kingdom of
Saudi Arabia").

The LLM sees fewer CyNER names in its prompt, and its answers change: one
threat-actor false positive and one tool false positive fewer than the
offline simulation predicted, nothing lost. Of the 69 threat-actor
predictions that went, none was in the gold; three LLM names appeared that
the baseline did not have (Sandworm, Shathak, "Ministry of State Security of
China"), real names that AnnoCTR does not annotate in those reports. CyNER
never found them in either run: the LLM named them itself once the list of
CyNER names in its prompt was shorter. Techniques, for information
(not a gate): F1 +0.024 [−0.016, +0.080], precision +0.006, recall +0.047,
inside run-to-run noise; the LLM gave 175 relationships against 172.

| Gate | Threat actor (A) | Location (D) |
|---|---|---|
| G1 precision ≥ +5 points, interval above 0 | pass (+19.2, low +11.4) | pass (+12.0, low +5.1) |
| G2 at most one gold entity lost | pass (0) | pass (0, one gained) |
| G3 F1 not down | pass | pass |
| G4 no other type drops by more than 1 point | pass | pass |
| G5 train loss ≤ 2% | pass (0) | pass (1 of 143) |

The filters cost a few microseconds per name; the two
runs' durations differ by the LLM server's latency, not by this change.

## Decision

- **Adopted, on by default** (`NER_PRECISION_FILTERS`, true unless set to
  false): lead A for CyNER's threat actors, lead D for spaCy's locations.
- **Not adopted**: A for malware (+2.6 points), B (+1.2 actors, +3.0
  malware), C (+3.5 malware). Each loses nothing on dev, and each is under
  the +5 points G1 asks of a lead on its own. Their joint effect on malware
  (+13.2 points [+9.1, +18.6] offline) was seen only after the measurement;
  it would have to be registered as one lead and measured on data this
  study has not read: dev has been read, and test is kept for frozen
  configurations (ADR-0060).
- Malware precision on dev therefore stays at 0.205: 93 of its 132 false
  positives come from CyNER and 23 from spaCy (October 18 breakdown).

What the bundle gets: fewer Threat Actors named after ordinary language,
and Locations that now ship because Stage 4 finds them in its ISO table
("the United States" becomes "United States"). Stage 4 already dropped the
other non-country places, so D changes the analyst's entity list more than
the bundle.

Not covered: the test split; reports written in lower case (the
capital-letter test is skipped below 0.5% capitals, measured on no such
report); names written only in lowercase in a cased report (rule A drops
them for actors: on train it lost none of the 63 true positives).
