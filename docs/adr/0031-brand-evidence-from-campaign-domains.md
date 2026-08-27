# ADR-0031: Brand evidence from campaign domains, and a full-text rule index

Status: Proposed
Date: 2026-08-27
Extends ADR-0030. Depends on ADR-0025's weak-evidence distinction.

## Context

ADR-0030 gated the coverage panel on evidence: a rule appears only if it holds a
value the report contains. On the UNC6671 vishing/AiTM report the panel returned
**0 rules of 3,786 tag-joined**.

That zero is literally true. The report's technical content is 79 freshly
registered phishing domains (`passkeyhelpdesk.com`, `oktaenroll.com`,
`addssopasskey.com`, …) and 11 IPs. Checked against the whole atom index —
363,166 rows, canonical and non-canonical alike — **not one of the report's 98
distinct values appears anywhere**. No public rule contains this campaign's
infrastructure, because the campaign registered it.

But the store is not empty of relevant rules:

| keyword in title/description | rules in store | reachable by this report's ATT&CK tags | served after the gate |
|---|---|---|---|
| `okta` | 32 | 3 — incl. **`Okta FastPass Phishing Detection`** | **0** |
| `aitm` | 18 | 1 — `ET PHISHING Generic AiTM Fingerprint Exfil` | **0** |
| `evilginx` | 16 | 2 | **0** |

Six rules that are *about this report* were in the 3,786 and the gate discarded
every one. This is a false-negative mode ADR-0030 did not measure: its validation
read the top of the **kept** list and never looked at what was **dropped**. A rule
can be about a report's subject while sharing no literal value with it — and on a
campaign whose infrastructure is entirely new, that is the only kind of rule left.

The mechanism that should have caught it exists. `_text_matches` searches rule
titles for `name`-class observables. It failed for two independent reasons:

- **`okta` is never extracted.** It is a legitimate SaaS product, not malware, so
  the extractor emits no entity for it — even though "okta" appears in 7 of the
  campaign's domains: `idokta.com`, `keyokta.com`, `oktaenroll.com`,
  `oktaportalsso.com`, `passkeyokta.com`, `myoktasso.com`, `addoktapasskey.com`.
- **Containment is the wrong test for multiword names.** The report yields
  `aitm panel`; the rule is titled `Generic AiTM Fingerprint Exfil`. `"aitm panel"
  in "…generic aitm fingerprint exfil…"` is False.

### A second, unrelated defect the report exposed

The report produced **175 observables for 98 distinct values**. Every one of its
78 `file`/`image` observables was domain-shaped, and 77 duplicated a `domain`
observable already present:

| report | observables | file/image | domain-shaped | exact duplicate of a domain |
|---|---|---|---|---|
| UNC6671 | 175 | 78 | 78 | 77 |
| distinct-clusters | 71 | 15 | 15 | 15 |
| apt44 | 138 | 21 | 1 | 1 |

ADR-0025 put a hostname gate on the *domain* side, so `agent.ashx` cannot become a
domain. The mirror gate was missing: nothing stopped a domain becoming a filename.
The cost is not only a wrong count — `file` reaches `{file, image, cmdline,
strlit}` and admits substring matching, which is how `file: gmail.com` came to
match an lsassy rule on the distinct-clusters report.

## Decision

### 1. Title evidence admits a rule, in its own weaker tier

A rule whose **title or description names something the report is about** is
admitted to the panel, carried in `matches` with `kind: "title"` and
`discriminating: false`. It never contributes to corroboration and never lifts
`evidence_count`; it sorts below every rule with literal-value evidence.

This is ADR-0025's own distinction, promoted from "reported but unscored" to
"admits, but in its own tier" — because on an IoC-fresh report it is the
difference between six relevant rules and none.

### 2. Brand tokens are mined from the campaign's own domains

No dictionary, no gazetteer: **a substring that recurs across several of the
report's domains is a campaign theme**; a one-off domain contributes nothing.
Recurrence *is* the noise filter, which is what makes this safe without a
maintained product list.

```
label      = registrable name minus TLD, dots and hyphens   ("oktaenroll.com" → "oktaenroll")
candidates = substrings of length 4..14 occurring in ≥ 3 distinct domains
maximal    = drop s when a longer t exists with s ⊂ t and df(t) ≥ df(s)
brand      = maximal token that is not a stopword and names 1..50 canonical rules
```

Measured across five real reports:

| report | domains | tokens kept |
|---|---|---|
| UNC6671 | 79 | **`okta`** (7 domains → 31 rules) |
| distinct-clusters | 31 | **`ms365`** (3 → 8) |
| aeternum | 25 | **`polygon`** (13 → 22) |
| apt44 | 5 | — |
| CERT Polska | — | — |

The random domain `sqfepjvmrd.xyz` yields nothing at any threshold, which is the
property the design rests on.

Three filters do the real work, and each was forced by a measurement:

- **Word boundaries, not containment.** As substrings, `reat` matched **52,775**
  rules (inside "c*reat*ed", "th*reat*"), `pass` 1,221, `port` 1,598.
- **A rule-count cap of 50.** Real identities sit below it (okta 31, polygon 22,
  ms365 8, tenderly 4); generic words sit above (port 160, create 155, secure 124,
  keys 98, portal 96, gateway 81, share 77, public 75, connect 64, enable 58).
- **A stopword list of domain-construction vocabulary** (`passkey`, `login`,
  `activate`, `portal`, `setup`, …). A campaign registering `activatepasskey.com`,
  `enablepasskey.com` and `setpasskey.com` makes `passkey` recur 60 times; it
  names a concept, never a product.

### 3. Rule text gets an FTS5 index

Looking a token up by scanning `detection_rules` for title and description costs
**4.1 s per token**, and the first implementation needed two such sweeps —
8.1 s + 4.7 s on one report, against a panel that answers in 2.9 s. `SELECT …
LIKE '%okta%'` is no faster (4.1 s): the cost is reading the description column
across 75,127 rows, not the comparison.

A virtual table `rule_text USING fts5(rule_id UNINDEXED, body)` answers the same
question in **0.4 ms** — roughly 10,000×. It builds in 5.2 s offline and costs
38 MB.

FTS5 also *is* the word-boundary semantics the match needs, so the regex goes
away rather than being reimplemented. `MATCH okta` returns exactly the 31 rules
the boundary regex found.

The index is built by `scripts/build_rule_text.py` and is **optional**: while the
table is absent or empty, brand evidence is simply not produced, exactly as
proposals degrade while the atom index is unbuilt. No corpus re-clone.

### 4. A hostname typed as a file is re-routed to `domain`

In the `file` branch of `observables_from_entities`, a value with no path
separator that passes `_is_report_domain` is added as a `domain` observable
instead of as `file` + `image`.

**Re-routed, not dropped.** `add` deduplicates on `(class, value)`, so when a
`domain` entity already produced it this is a no-op; when the extractor typed it
*only* as a file, the observable survives in the class it belongs to rather than
being lost. A value carrying a path separator is always kept as a file — a path is
a file, whatever its last segment looks like.

Measured: UNC6671 175 → **97** observables with zero duplicates, distinct-clusters
71 → 56, while genuine files are untouched (apt44 21 → 20, CERT Polska 40 → 40,
aeternum 26 → 26).

## Options considered

| Option | Verdict |
|---|---|
| Leave the zero as the honest answer | Rejected — true of the *values*, false of the *store*. Six rules named after the report's subject existed and were dropped. |
| A maintained gazetteer of SaaS/IdP/EDR products | Rejected as the primary mechanism — it only ever knows the brands someone remembered to add, and this campaign's tell (`okta` inside coined domains) needs no list. Still the right fallback if domain mining proves thin across more reports. |
| Token-match the names already extracted | Insufficient alone — recovers AiTM and Evilginx, but not Okta, which is extracted under no form at all. Worth adding later; it is not what unblocks this report. |
| Segment domains with an English wordlist | Rejected — needs a dictionary, and still cannot split coined brand names. Recurrence achieves the same separation using the report itself as the corpus. |
| Let title evidence corroborate like atom evidence | Rejected — ADR-0025 measured why a rule *named after* a family is not a rule *holding* its value. |
| Scan `detection_rules` per lookup | Rejected on measurement: 4.1 s per token, 12.8 s per report. |

## Consequences

- **The IoC-fresh report stops being a dead end.** UNC6671 goes from 0 rules to
  the Okta set, every one about the technique the report describes.
- **A new failure mode to watch:** a brand token that is a real product name but
  wrong for the report (a domain coined around `citrix` when the campaign only
  impersonates it). Brand evidence is deliberately the weakest tier and never
  corroborates, which bounds the damage to list position.
- **`rule_text` must be rebuilt when corpora change**, like the atom index. A
  stale index under-reports; it cannot over-report, since every hit is re-checked
  against the live `detection_rules` row.
- **Easier next:** `artifacts.py` still pays a 5.5–7 s title sweep for the same
  question and can be repointed at `rule_text`.
- **The observable count drops sharply on domain-heavy reports** (175 → 97). Any
  figure quoted from before this change is not comparable.

## Measured result

`scripts/build_rule_text.py`: 75,127 rules indexed in 26.9 s, +22 MB on disk.
Brand lookup per report, end to end: **47 ms** on UNC6671, 8 ms on aeternum, 4 ms
on distinct-clusters — against 12.8 s for the two-sweep version it replaces.

`scripts/check_evidence_gate.py` over all eight reports:

| report | tag join | gated before ADR-0031 | gated now | brand token |
|---|---|---|---|---|
| **UNC6671** | 3 786 | **0** | **31** | `okta` (7 domains) |
| aeternum | 17 463 | 138 | **160** | `polygon` (13) |
| distinct-clusters | 12 280 | 3 | **11** | `ms365` (3) |
| industroyer-v2 | 1 722 | 0 | 0 | — |
| GREYVIBE | 14 675 | 1 | 1 | — |
| ShinyHunters | 10 398 | 3 | 3 | — |
| apt44 | 22 779 | 356 | 356 | — |
| CERT Polska | 7 136 | 510 | 508 | — |
| **total** | **90 239** | 1 011 | **1 070** | |

Validation points, in order:

1. Latency total 50.5 s → 22.4 s for the gated pass; the brand lookup adds ~144 ms
   to the largest report.
2. **UNC6671 serves `Okta FastPass Phishing Detection`**, alongside 25 further
   Okta rules and 6 Scattered Spider signatures — `ET MALWARE DNS Query to
   Scattered Spider Domain`, `Okta 2023 Breach Indicator Of Compromise`,
   `Okta Session Impersonation Granted From Untrusted Domain`. Scattered Spider is
   the vishing/AiTM cluster this report is about.
3. **`ev2+` stayed at 26 across all reports** — brand evidence corroborated
   nowhere, which is the invariant.
4. **apt44 and CERT Polska produced no brand tokens.** Their domains are not
   themed, so the noise floor holds; CERT Polska lost 2 rules, from the file→domain
   re-route removing bogus observables rather than from anything brand-related.

### Defects the validation exposed

- **`_label` did not strip dots**, so `api.zan.top` yielded the "themes" `api.`,
  `rpc.` and `net.` on the aeternum report. Fixed; aeternum now yields `polygon`
  alone.
- **Substring matching was unusable** and was caught before shipping: `reat`
  matched 52,775 rules. FTS5's tokenizer replaced the boundary regex entirely.
- **The build script filled a 2.3 GB WAL and had to be killed.** `get_conn()` is in
  autocommit, so every batch committed separately, and with the API server holding
  readers SQLite could never auto-checkpoint. The rebuild now runs in one
  `BEGIN IMMEDIATE` transaction and ends with `wal_checkpoint(TRUNCATE)`: 26.9 s,
  WAL back to 0. `PRAGMA quick_check` confirmed no damage from the interrupted run.
- **`brand_tokens` must not query when nothing survives filtering** — an
  early return added, since a sweep for zero tokens is pure waste.

### Extended after the fact: CVE ids, and the basename hole

Two gaps the Cisco SD-WAN report exposed once the panel was tight enough to read:

- **A CVE reached no evidence path at all.** `MATCHABLE` has no `cve` key, so a
  rule naming the vulnerability a report is *about* was invisible. `cve_evidence`
  answers it through the same FTS index, with none of the guards a mined token
  needs — a CVE id is specific by construction. Measured: `cve-2021-44228` names
  120 rules, `cve-2024-3400` names 10. This report's three 2026 zero-days name
  **none**, the public corpora not having caught up, so its honest answer stays 0.
- **A file's basename escaped the ubiquity check.** `observables_from_entities`
  emits both the path and its basename, so `/etc/shadow` arrived twice — once
  classified ubiquitous, once as bare `shadow`, which was neither a binary nor a
  path and so read as discriminating. `shadow` and `auth.log` were the sole
  justification for all 10 rules the report served after the admission fix.
  `UBIQUITOUS_SYSTEM_FILES` closes it, tested against both the basename and its
  extension-stripped stem.

## Still open

- **`Okta FastPass Phishing Detection` and `New Okta User Created` rank equally.**
  Brand evidence carries no strength signal, so within the tier the order is
  arbitrary. Ranking by how specific the rule is to the brand would need the STP
  robustness axis ADR-0030 deferred.
- **A brand can be right about the product and wrong about the report** — a
  campaign impersonating Citrix would surface Citrix rules whether or not Citrix
  was breached. The tier separation bounds this to list position, but it is real.
- **Only domains feed brand mining.** URLs, email addresses and rule titles could
  too; measure before extending.
