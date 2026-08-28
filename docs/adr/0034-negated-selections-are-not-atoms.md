# ADR-0034: A negated Sigma selection is not an atom

**Status:** Accepted
**Date:** 2026-08-28
**Deciders:** maintainer

## Context

### The index held what rules exclude, as if they looked for it

`rule_atoms` is contracted (ADR-0014) to hold *"the literal values a rule looks
for"*. `extract_atoms` built it by walking the whole `detection:` block, skipping
only `condition` and `timeframe`.

But a Sigma rule keeps its **exclusions in that same block**. Only the
`condition` says which selections are positive and which are subtracted:

```yaml
detection:
  selection:
    Image|endswith: '\rundll32.exe'
  filter_teams:
    Image|endswith: '\teams.exe'
  condition: selection and not filter_teams
```

Walking the block indexed `teams.exe` as something this rule looks for. It is
the opposite: the rule exists to ignore Teams.

Measured over 4 000 canonical Sigma rules, `scripts/audit_store_invariants.py`
and a differential run of the extractor:

| | |
|---|---|
| rules carrying a `filter*` selection | 787 |
| — of those, rules whose atoms came **only** from a negated block | **649** |
| atoms that exist solely because a negated block was walked | **5 530** |

Over the full store (11 393 Sigma rules), `scripts/measure_negated_atoms.py`:

| | before | after |
|---|---|---|
| atoms | 562 198 | 548 161 |
| | | **−14 037 (−2.5 %)** |
| rules changed | | **1 742 (15.3 %)** |

The removed values are not a random 2.5 %. They are the exclusion vocabulary of
Windows detection engineering:

| count | value |
|---|---|
| 112 | `c:/windows/system32/` |
| 100 | `c:/windows/syswow64/` |
| 88 | `c:/program files/` |
| 80 | `svchost.exe` |
| 79 | `msiexec.exe` |
| 75 | `explorer.exe` |
| 62 | `msmpeng.exe` (Windows Defender) |
| 43 | `teams.exe` |
| 41 | `chrome.exe` |

By class: 9 398 `image`, 2 025 `cmdline`, 1 078 `registry`, 615 `ip`, 532 `file`.

A report mentioning `explorer.exe` was pulling in 75 rules whose sole reason to
name it is to *not* fire on it — and pulling them in through the `image` class,
which ADR-0030 weights near the top. The 938-test suite was green throughout:
nothing asserted this.

### Naming is not a usable signal

The obvious cheap fix — skip selections named `filter*` — was measured against
the corpus before being rejected:

| | |
|---|---|
| rules with a `filter*` selection | 2 002 |
| — where a `filter*` selection is used **positively** | **10** |
| rules negating a selection **not** named `filter*` | **72** |

A name-only rule would wrongly drop the content of 10 rules
(`condition: selection and filter`) and miss 72 whose exclusions are called
`legitimate_process_path`, `falsepositives`, `exclude_tlds`, `computer_acct`,
`z_flag_unset`, `keywords_filter`. Both errors are silent.

Condition shapes across the same 11 393 rules:

| shape | count |
|---|---|
| no negation | 9 343 |
| `not <n> of <pattern>` | 1 511 |
| `not <name>` | 532 |
| `not ( … )` | 9 |

Every `condition` in the store is a string; none is the list Sigma also permits.

### How much of that reaches an analyst

The atom count overstates the user-visible damage, and saying so is part of the
decision. `scripts/`-side probe over all 12 stored jobs, 200 proposals each,
counting proposals whose every non-title match is a value the rule excludes:

| | |
|---|---|
| proposals served | 2 400 |
| resting **only** on excluded values | **7 (0.3 %)** |

IDF is why. `svchost.exe` sits in 80 rules and `explorer.exe` in 75, so their
inverse document frequency is near zero and they cannot lift a rule into the
served set on their own. What survives is the *specific* exclusion:

| score | rule | matched only on |
|---|---|---|
| 0.539 | Network Connection Initiated From Process Located In Potential… | `github.com` |
| 0.476 | Potential Privilege Escalation To LOCAL SYSTEM | `psexec` |
| 0.470 | Notepad++ Updater DNS Query to Uncommon Domains | `github.com` |
| 0.435 | PowerShell Core DLL Loaded By Non PowerShell Process | `powershell.exe` |
| 0.422 | Suspicious Dropbox API Usage | `dropbox` |
| 0.210 | ADSI-Cache File Creation By Uncommon Tool | `wmiprvse.exe` |

Read the third row: *Notepad++ Updater DNS Query to **Uncommon** Domains*
excludes `github.com` because that is where the updater is *supposed* to go. A
report mentioning GitHub surfaced the rule that fires when Notepad++ talks to
anywhere else. The proposal is not merely unsupported — it is inverted, and it
scores 0.470 while reading as legitimate evidence.

So this is a small, sharp precision fix, not a large one. It is worth making
because the failure is silent, inverted, and indistinguishable from a real hit
in the panel — not because it moves a headline number.

## Options

**A — Skip selections named `filter*`.** One line, no parser. Rejected on the
measurement above: wrong for 10 rules, blind to 72.

**B — Parse the condition.** A ~60-line tokeniser over the three negation shapes.
Costs a parser that must be kept honest against real conditions. Chosen.

**C — Keep the atoms, discount them at match time.** Rejected: it spreads
condition semantics into `relevance.py`, `coverage.py` and every future consumer,
and it leaves a store whose documented contract is false.

**D — Full Sigma condition evaluation.** Rejected as disproportionate. Nothing
downstream needs the boolean structure — only the set of subtracted selections.

## Decision

`extract_atoms` resolves the negated selection names from the `condition` and
drops those keys before walking the block.

`_negated_selections(detection)` tokenises the condition (digits are their own
token, so `not 1 of filter_*` reads as three operands) and handles exactly the
three shapes the corpus contains: `not <name>`, `not <quantifier> of <pattern>`,
and `not ( … )`. `_expand_selector` resolves an operand against the block's real
keys — `them` to all of them, a `*` pattern by wildcard, a bare name only if it
actually names a selection.

Exclusion is applied at the **top level only**: negation names a top-level
selection, never a nested field. Dropping the keys before `_collect` keeps the
walk itself unaware of condition semantics.

## Consequences

- The index loses 14 037 atoms and 1 742 rules change shape. This is a
  **precision** gain, not a recall loss: every removed value was one the rule
  subtracts.
- A rule whose condition is wholly negated (`condition: not selection`,
  one rule in the store) now contributes **no** atoms. Correct, and it means a
  rule can legitimately have zero atoms — consumers already tolerate that, since
  rules with no usable detection logic always could.
- **Accepted imprecision.** A double negation inside a group,
  `not (a and not b)`, marks `b` negated although De Morgan makes it positive.
  Nine rules use `not (` at all and none of them nests this way. Over-excluding
  costs an atom; under-excluding invents one, so the parser is deliberately
  biased that way.
- **The store must be rebuilt** for this to take effect. The change is in the
  extractor, not in the data; `rule_atoms` keeps the 14 037 stale rows until
  `scripts/build_rule_atoms.py` (or a full index rebuild) re-derives them.
- The parser is a new thing that can rot. `scripts/measure_negated_atoms.py`
  re-measures the before/after on the live store, and
  `tests/test_sigma_negation.py` pins all three shapes plus the two cases the
  naming heuristic got wrong.

## What this does not fix

`_normalize` still emits command-line fragments under `image`/`file` when a
generated corpus puts them there (`' 2>nul'`, `' a: the meterpreter stage is a
large shellcode'`). Those are positive content — badly typed, but not negated —
and out of scope here. The whitespace half of that defect is fixed separately:
the basename was not re-stripped after the path split, which left 49 atoms that
could never match a report observable.
