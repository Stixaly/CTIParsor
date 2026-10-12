# The gazetteer's ordinary-word policy on AnnoCTR train + dev — October 2026

[The ordinary-word review](../gazetteer-ordinary-words.md), measured in two
steps. Step 1: its CASE decisions, its CONTEXT decisions with no construction
recognised (every occurrence `unresolved`), and the 23 forms that name two
ATT&CK objects. Step 2: the naming constructions that resolve a CONTEXT or
ambiguous occurrence (`pipeline/gazetteer_context.py`). Stage 2b alone, run on
the same documents with no policy and with the policy applied; the comparison
and the gates are the document's ("Proposed acceptance gates before
activation").

```
python scripts/measure_gazetteer_policy.py [--only CASE CONTEXT AMBIGUOUS] --json out.json
```

## Setup

- Policy version `b2ab83cf9d78` (SHA-256 prefix of the reviewed document) in
  step 1; `b2ab83cf9d78+a64a02640d29` in step 2 (the construction rules,
  `pipeline/data/gazetteer_context_rules.json`). 151 reviewed forms + 20
  ambiguous forms without a review = 171 judged forms.
- AnnoCTR train + dev, the 86 documents with the cybersecurity layer. The test
  split is not read. 47 documents are *affected*: a raw, case-insensitive match
  of a judged form under the matcher's boundary rule, fixed before either run.
- Scored on distinct (document, entity type, ATT&CK ID) triples, the gold's ID
  read from AnnoCTR's link to attack.mitre.org. 891 gold rows link outside
  ATT&CK (entities the gazetteer cannot produce) and are not scored. Every
  gold mention was located in its text.
- Paired bootstrap over documents, 10,000 resamples, seed 13, 2.5th/97.5th
  percentiles. Analyst overrides off.
- Aho-Corasick and the regex fallback: identical output and identical
  withheld occurrences on every document, with and without the policy, in
  both steps.
- `--only` withholds by reason: CASE = `case_mismatch`; CONTEXT =
  `missing_context`, `conflicting_sense`, `embedded`; AMBIGUOUS =
  `ambiguous_identity`, `other_identity`.

## Step 1: CONTEXT withheld whatever the sentence says

Differences are apply − off, in points of precision or recall.

| Withheld | Emitted | Precision, all 86 docs | Recall, all 86 docs | Precision, 47 affected docs |
|---|---|---|---|---|
| nothing (production) | 324 | 0.543 | 0.859 | 0.487 |
| everything | 257 | +13.4 [10.1, 17.5] | −1.0 [−2.5, 0] | +18.1 [13.9, 23.7] |
| CASE + ambiguous | 310 | +2.5 [1.2, 4.0] | 0 | +3.1 [1.5, 5.0] |
| CASE | 320 | +0.7 [0.2, 1.5] | 0 | +0.8 [0.2, 1.8] |
| ambiguous | 314 | +1.7 [0.7, 3.0] | 0 | +2.2 [0.8, 3.7] |
| CONTEXT | 271 | +9.9 [7.1, 13.3] | −1.0 [−2.5, 0] | +13.0 [9.5, 17.5] |

Per type, withholding everything: malware precision 0.555 → 0.712 (recall
unchanged, 0.867), threat actor 0.722 → 0.825 (unchanged, 0.853), tool
0.250 → 0.289 with recall 0.812 → 0.688 — 16 gold tool triples, two lost.

The removed identities, by form (document level): `page` 19, `play` 6,
`ping` 4 (two of them in the gold), `route` 4, `chromium`, `empire`,
`expand`, `photo` 3 each, `electrum` 2 (and 1 with `iridium`), `equation`,
`exodus`, `joker`, `circles` 2 each, and one each for `anchor`, `carbanak`,
`chaos`, `cuba`, `epic`, `havoc`, `mercury`, `scorpion`, `sednit`, `sofacy`,
`spicyomelette` — 67 in all, 65 of them not in the gold.
At mention level, 76 occurrences of `page` were withheld, none annotated.

The two lost are both `ping` named in prose: once beside curl as the
connectivity check of a reconnaissance script, once as `ping.exe` in a list
of the Windows tools an actor used (train, Proofpoint 2021-07-28; dev, Lab52
2020-05-14).

## Step 2: the naming constructions

An occurrence of a CONTEXT form, or of a form naming two ATT&CK objects, is
resolved when its sentence (a list item, table row or heading being its own
unit) names the object: an attached ATT&CK ID (`Machete (S0409)`), an
explicit alias of another name of the same object, itself identified
(`Elise malware, also known as Page`), a typed apposition with the nouns the
form's rule allows (`Cuba ransomware`, `the ping utility`; none for `play`,
`snake`, `page`), or, for `ping`, `route` and `expand`, a command line or an
executable (`ping -n 1 localhost`, `expand.exe`). An occurrence inside a URL
or a file name, or inside a conflicting sense the rule names (`Google
Play`, `Joker's Stash`, `Equation Editor`), is excluded. Every example in the
document's acceptance table and its protected cases passes, on both paths
(`tests/test_gazetteer_context.py`).

| Withheld | Emitted | Precision, all 86 docs | Recall, all 86 docs | Precision, 47 affected docs |
|---|---|---|---|---|
| nothing (production) | 324 | 0.543 | 0.859 | 0.487 |
| everything | 260 | +13.0 [9.8, 16.9] | −0.5 [−1.7, 0] | +17.6 [13.6, 22.7] |
| CASE + ambiguous | 311 | +2.3 [1.0, 3.8] | 0 | +2.8 [1.3, 4.7] |
| ambiguous | 315 | +1.6 [0.5, 2.8] | 0 | +1.9 [0.7, 3.4] |
| CONTEXT | 273 | +9.8 [7.1, 13.2] | −0.5 [−1.7, 0] | +12.9 [9.5, 17.2] |

The constructions bring back `ping.exe` (gold), a `ping` command line and
the Empire post-exploitation framework (both read as correct, neither
annotated as their ATT&CK object by AnnoCTR). On the 366 AnnoCTR texts outside the
test split (the general-only ones included, read without gold) they
resolve 9 occurrences — 4 executables, 2 command lines, 2 typed appositions,
1 alias (`APT28 (also known as Sofacy)`, which also excludes Sofacy's other
identity) — and each one, read in context, is the object it is mapped to.

One valid mention is still lost: `ping` in "using ping and curl", a
construction the document does not list. Tool recall goes from 0.812 to 0.750:
one triple of 16.

## Gates

| Gate | Step 1, everything | Step 2, everything | Step 2, CASE + ambiguous |
|---|---|---|---|
| Both paths agree | pass | pass | pass |
| Acceptance examples and protected cases (synthetic) | — | pass | pass |
| Precision on affected documents ≥ +5 points, CI low > 0 | pass | pass | **fail** (+2.8) |
| Recall over all documents ≥ −1 point, CI low ≥ −2 points | **fail** (CI low −2.5) | pass | pass |
| No type loses more than 2 points of P or R | **fail** (tool R −12.5) | **fail** (tool R −6.25) | pass |
| No lost valid mention | **fail** (2) | **fail** (1) | pass |
| Five documents per class per form | inconclusive | inconclusive | inconclusive |

The coverage gate needs adjudicated negatives; an occurrence AnnoCTR does
not annotate is not one. No observed form has five documents on both sides.
The output-and-provenance gate is met by construction for matcher output (no
entity from an unresolved occurrence) and does not arise yet: nothing is
persisted from the policy in shadow mode.

## Reading

- The CONTEXT forms carry most of the gain. Step 2 halves their loss and
  resolves nothing wrongly in 366 texts, but resolves little: AnnoCTR
  rarely writes these names in a construction.
- What blocks the whole policy is one sentence ("using ping and curl") and
  the 16 gold tool triples that make it 6 points. A construction for it
  (a command named beside another tool, as the object of "using") is a change
  to the document's rules, not to the code: the maintainer's call.
- CASE and the ambiguous forms lose nothing but stay under the +5-point gate.
- Production stays in shadow mode: no subset passes every gate. The stage
  report's `policy_*` counts give, on real reports, the volume the policy
  would withhold; the coverage gate needs contexts adjudicated by a person.
