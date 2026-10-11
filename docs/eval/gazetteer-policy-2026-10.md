# The gazetteer's ordinary-word policy on AnnoCTR train + dev — October 2026

Step 1 of [the ordinary-word review](../gazetteer-ordinary-words.md): its
CASE decisions, its CONTEXT decisions with no construction recognised yet
(every occurrence `unresolved`), and the 23 forms that name two ATT&CK
objects. Stage 2b alone, run on the same documents with no policy and with
the policy applied; the comparison and the gates are the document's
("Proposed acceptance gates before activation").

```
python scripts/measure_gazetteer_policy.py [--only CASE CONTEXT AMBIGUOUS] --json out.json
```

## Setup

- Policy version `b2ab83cf9d78` (SHA-256 prefix of the reviewed document), 151
  reviewed forms + 20 ambiguous forms without a review = 171 judged forms.
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
  withheld occurrences on every document, with and without the policy.

## Results

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
connectivity check of a reconnaissance script, once as `ping.exe` in a list of the Windows
tools an actor used (train, Proofpoint 2021-07-28; dev, Lab52 2020-05-14).
That is the construction step 2 must recognise for command forms.

## Gates

| Gate | Everything | CASE + ambiguous |
|---|---|---|
| Both paths agree | pass | pass |
| Precision on affected documents ≥ +5 points, CI low > 0 | pass | **fail** (+3.1) |
| Recall over all documents ≥ −1 point, CI low ≥ −2 points | **fail** (CI low −2.5) | pass |
| No type loses more than 2 points of P or R | **fail** (tool recall −12.5) | pass |
| No lost valid mention | **fail** (2, `ping`) | pass |
| Five documents per class per form | inconclusive | inconclusive |

The coverage gate needs adjudicated negatives; an occurrence AnnoCTR does
not annotate is not one. No observed form has five documents on both sides.

## Reading

- The CONTEXT forms carry most of the gain, and their only loss is the
  command form the document already expects a recogniser for (step 2).
- CASE and the ambiguous forms are safe on this corpus — nothing lost — but
  rare in it: 4 and 10 identities removed. Their gain is real but small.
- Production stays in shadow mode: no subset passes every gate. The stage
  report's `policy_*` counts give, on real reports, the volume the policy
  would withhold.
