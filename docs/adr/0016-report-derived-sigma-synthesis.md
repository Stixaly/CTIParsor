# ADR-0016 — Report-derived Sigma rule synthesis

**Status:** Proposed
**Date:** 2026-08-16
**Builds on:** [0014](0014-observable-driven-detection-proposals.md) (observables, atom index, IDF),
[0015](0015-multi-format-detection-matching.md) (shared hostname test)

## Context

ADR-0014 answers *"which existing rule should I read first?"*. It cannot answer
*"nobody has written a rule for this yet — give me one."* On the two reports in
the store, that gap is measurable:

| Report | Observables | `direct`-tier proposals |
|---|---|---|
| ShinyHunters / Oracle PeopleSoft | 41 | **2** |
| GREYVIBE | 20 | **8** |

Two direct hits on a 41-observable intrusion means the campaign's hashes,
binaries and C2 addresses are, for the most part, in no corpus rule at all. That
is the normal state for a fresh report and exactly what synthesis is for.

### What the reports actually offer a generator

Measured with `observables_from_entities` on both stored jobs:

| Report | platform | domain | ip | hash | image | file | name | cve |
|---|---|---|---|---|---|---|---|---|
| ShinyHunters | `multi` | 4 | 6 | 5 | 5 | 8 | 12 | 1 |
| GREYVIBE | `""` | 1 | 0 | 0 | 0 | 0 | 19 | 0 |

Two things follow directly.

**GREYVIBE would yield one rule.** A behaviour-heavy report whose observables are
19 tool *names* and a single domain has almost nothing a Sigma `detection:` block
can key on — a name is not a field value. Synthesis is worth building, but it is
not a universal answer, and the UI must not imply it is.

**The observable stream is not clean enough to template directly.** The
ShinyHunters `domain` observables are:

    azurenetfiles.net    agent.ashx    exfil.tar.zst    psemhub.war

Three of four are filenames that upstream extraction labelled `domain`. Emitting
a `dns_query` rule for `agent.ashx` would discredit the whole feature. The
hostname test introduced in ADR-0015 for the Suricata/YARA atom extractors
already separates them correctly (verified on these exact values), so synthesis
reuses it rather than inventing a second notion of "domain".

## Options considered

**A — One rule per observable.** Verdict: **rejected.** 41 observables would
become 41 rules for one report; nobody reviews that, and it buries the two or
three that matter.

**B — One rule containing every observable.** Verdict: **rejected.** Sigma
`logsource:` is per-telemetry-type; a hash, a DNS name and a registry key cannot
share one `detection:` block without becoming meaningless.

**C — One rule per (logsource category × observable family), gated.**
Verdict: **chosen.** Mirrors how a detection engineer actually splits work, and
caps output at seven rules per report regardless of observable count.

## Decision

### 1. Synthesis is complementary to matching, never redundant

An observable already carried as an atom by a canonical corpus rule is
**excluded** from synthesis: ADR-0014 will already propose that rule, and
shipping a generated near-duplicate alongside it is noise. Concretely, the caller
resolves the observable values against `rule_atoms` and passes the hits in as
`exclude_values`. Synthesis therefore covers precisely the gap matching leaves.

### 2. Grouping is fixed, and so is the field for each group

Seven rule kinds, one per telemetry type. This table is normative:

| kind | from classes | `logsource.category` | field |
|---|---|---|---|
| `dns_query` | `domain` | `dns_query` | `QueryName` |
| `proxy_url` | `url` | `proxy` | `c-uri` |
| `network_connection` | `ip` | `network_connection` | `DestinationIp` |
| `process_hash` | `hash` | `process_creation` | `Hashes\|contains` |
| `process_image` | `image` | `process_creation` | `Image\|endswith` |
| `file_event` | `file` (non-executable) | `file_event` | `TargetFilename\|endswith` |
| `registry_set` | `registry` | `registry_set` | `TargetObject\|contains` |

`name`, `user`, `port` and `cve` produce **no** rule. A tool name is not a field
value; a bare port is not a detection. They are used in the title and description
only.

### 3. Gates applied, in order, before a value may enter a rule

1. **Class gate** — the class must appear in the table above.
2. **Already-covered gate** — §1.
3. **Hostname gate** — `domain` values must satisfy
   `pipeline.detection.tlds.looks_like_domain`. Rejects `agent.ashx`,
   `exfil.tar.zst`, `psemhub.war`; keeps `azurenetfiles.net`.
4. **Shape gates, per class** — valid IPv4 only (no IPv6: `DestinationIp` handles
   it poorly and reports rarely carry it); a digest length that maps to a real
   algorithm; executables excluded from `file_event` because `observables.py`
   already emits them as `image`.
5. **Specificity gate** *(added after validation, see below)* — a bare basename
   must carry an extension or reach 8 characters, and a value with a colon
   outside a drive prefix is not a path at all.

The **IDF boilerplate gate** originally specified here was **not built**. It needs
the rule-atom index, and keeping the generator a pure function (no DB handle) is
worth more than the gate: the already-covered gate subsumes most of it, since a
boilerplate value like `cmd.exe` is by definition carried by many corpus rules and
is therefore excluded anyway. The specificity gate covers the residue. If a
generic value still slips through in practice, the IDF gate belongs in the
DB-side caller, not here.

### 3b. What real-data validation changed

The first working version passed every assertion in §Validation and was still not
shippable. Three defects only visible by reading the output:

- **34 ATT&CK tags on every rule.** The report's whole technique inventory was
  stamped on each rule, so a `file_event` rule carried `attack.t0866` (an ICS
  technique) and `attack.t1110.003` (password spraying). An observable does not
  record which technique it served. Replaced by `TACTIC_BY_KIND`: one
  well-founded tactic for the network and process kinds, and **no `tags:` block
  at all** for `file_event`/`registry_set`, where the tactic genuinely is not
  determinable. The report's techniques stay on `DraftRule.techniques` and in the
  description — recorded, not asserted.
- **`/etc/hosts` rendered as `\hosts`.** `observables.py` normalises every path to
  forward slashes, so the separator must be re-derived, not assumed. Paths are now
  emitted POSIX-style when rooted at `/`, Windows-style behind a drive prefix, and
  — for a bare basename on an undecided platform — in **both** forms, which costs
  nothing because the field is already a YAML list.
- **`/usr/bin:/bin` became a file rule.** A `$PATH` fragment. The drive-letter
  exemption has to be anchored: the substring test `":/" in value` matches this
  string happily.

### 4. Output is a draft, and says so

Every generated rule carries `status: experimental`, an `author` naming
CTIParsor and the job, a `references:` entry pointing at the source report, and a
`description` listing the observables that produced it. Rules are returned for
review and export; nothing is written to the corpus store, which stays a record
of *ingested* rules only.

### 5. Deterministic, like the rest of the detection stack

Same constraint as ADR-0014: no model, no network, no randomness. Rule `id` is a
**UUIDv5** over `(job_id, kind)`, so re-running a report reproduces byte-identical
rules instead of churning fresh UUIDs. `date` is an explicit parameter rather
than `today()`, for the same reason — otherwise output changes at midnight and no
test can pin it.

## Consequences

**Easier**

- The gap ADR-0014 leaves is now fillable in one click, on the same observables,
  with the same vocabulary.
- The gates are all reused code — no new notion of domain, no new stoplist.

**Harder**

- Rules are only as good as extraction. A misclassified observable that survives
  the gates becomes a bad rule with CTIParsor's name on it, which is why
  `status: experimental` and the provenance block are not optional.
- Behaviour-only reports get little or nothing (GREYVIBE: one rule). The feature
  must degrade visibly rather than emit something plausible and empty.
- Generated Sigma is *valid* but not *tuned*: no `filter:` clauses, no
  environment baselining. It is a starting point for an engineer, and the
  `falsepositives:` field says `Unknown` honestly rather than guessing.

**Deferred:** Suricata and YARA synthesis reuse this shape (gates, grouping,
provenance) with their own field tables — a follow-up once this is validated.

## Validation

1. Every generated rule parses as YAML and carries the Sigma-required keys
   (`title`, `id`, `status`, `logsource`, `detection`, `condition`, `level`).
2. On the ShinyHunters report, no rule contains `agent.ashx`, `exfil.tar.zst` or
   `psemhub.war`.
3. On GREYVIBE, output is one rule or none — never a padded set.
4. Re-running a job twice produces identical bytes.
