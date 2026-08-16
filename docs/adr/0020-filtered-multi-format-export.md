# ADR-0020 — Filtered, multi-format detection export

**Status:** Proposed
**Date:** 2026-08-16
**Extends:** [0006](0006-multi-corpus-detection-ingestion.md) (licence travels with the export), [0008](0008-detection-coverage-matrix.md) (coverage semantics)
**Caused by:** [0015](0015-multi-format-detection-matching.md) — the store is no longer Sigma-only

## Context

`GET /jobs/{id}/detections/export` ZIPs every canonical rule linkable to the
report's techniques. It was written when the store held 11,396 Sigma rules. It
now holds 86,183 across three formats, and the endpoint is broken in three ways
at once.

Measured on the current store:

| Report | Rules exported | Raw size |
|---|---|---|
| ShinyHunters / PeopleSoft | **10,372** | **224 MB** |
| CrowdStrike WARP PANDA | **18,196** | **268 MB** |

**1. The volume makes it unusable.** A quarter-gigabyte ZIP of 18,000 files is
not a deliverable an analyst hands to a SOC.

**2. Every non-Sigma rule is written with the wrong extension.** The endpoint
hardcodes `.yml`, the archive is named `_sigma_rules.zip`, and the README says
"Sigma detection rules". Of the ShinyHunters export, **8,380 of 10,372 rules are
Suricata** — emitted as `.yml`, which no tool will load.

**3. Restricted licences cannot be excluded.** The breakdown:

| Licence | ShinyHunters | WARP PANDA |
|---|---|---|
| BSD-3-Clause (ET Open) | 8,380 | 15,702 |
| **`none` — all rights reserved** | **1,290** | **1,642** |
| DRL-1.1 | 699 | 846 |
| GPL-3.0 / BSD-2-Clause | 3 | 6 |

ADR-0006 decided licence is *carried, not enforced* — "the operator decides what
to export". But the operator currently has **no mechanism to decide**: the README
says "respect each license before redistributing" while the ZIP hands over 1,642
all-rights-reserved rules with no way to leave them out.

### A finding this exposes

**No YARA rule can ever be exported today.** The export selects by ATT&CK
technique, and YARA carries **0 techniques** across all 16,314 canonical rules
(measured). So a format the user just enabled is structurally unreachable through
this path.

## Options considered

**A — Cap the export at N rules.** Verdict: **rejected.** Silent truncation of a
detection package is worse than a large one; the analyst cannot tell what is
missing.

**B — Always split by format into separate downloads.** Verdict: **rejected.**
Doesn't address licence or volume, and forces three downloads where one filtered
archive is wanted.

**C — Filter on the axes the data actually has, and tell the operator the size
before they commit.** Verdict: **chosen.**

## Decision

### 1. Four filters, all optional, all repeatable

`format`, `corpus`, `license`, `severity` — each accepting repeated query
parameters. Omitting an axis means "no constraint on it", so the current
behaviour is unchanged for existing callers.

Filters are applied to the technique-selected set, never widening it: this stays
a *coverage* export, and ADR-0008's semantics are untouched.

### 2. A facets endpoint, so the UI never guesses

`GET /jobs/{id}/detections/export/facets` returns, for the report's selected
rules, the available value of each axis with its **rule count and byte size**:

```json
{"total": 10372, "bytes": 229911552,
 "format":   [{"value": "suricata", "rules": 8380, "bytes": 201326592}, …],
 "license":  [{"value": "none",     "rules": 1290, "bytes":  12582912}, …],
 "severity": [...], "corpus": [...]}
```

This is what makes §1 usable: the operator sees *"18,196 rules / 268 MB"* and
narrows **before** downloading, rather than discovering it afterwards. It is also
why no cap is needed — the size is disclosed, not silently imposed.

### 3. Correct extension and layout per format

| format | extension |
|---|---|
| sigma | `.yml` |
| suricata | `.rules` |
| yara | `.yar` |

Archive layout becomes `rules/{format}/{corpus}__{title}.{ext}`, so a mixed
export unpacks into per-format directories a tool can be pointed at directly.
The archive name drops `_sigma_`.

### 4. The manifest records what was filtered out

`MANIFEST.json` gains `filters` (what was requested) and `excluded` (counts per
axis). An export that silently omitted 1,642 rules would be indistinguishable
from one where they never matched; recording it keeps the artifact self-describing.

The README's licence section lists only the licences actually present in *this*
archive, so it stops warning about licences the operator already excluded.

## Consequences

**Easier**

- A SOC-ready export: "Sigma only, exclude all-rights-reserved, high severity"
  is one request instead of unpacking 268 MB and sorting by hand.
- Licence compliance becomes actionable rather than advisory, without CTIParsor
  enforcing a policy — ADR-0006's stance is preserved, the operator just gains
  the control it assumed they had.
- Non-Sigma rules land with loadable filenames.

**Harder**

- Four axes multiply the states to test; the facets endpoint and the export must
  agree, or the UI shows counts that don't match the download.

- **Facets are slow, and remain so: ~12.4 s (ShinyHunters) / 15.5 s (WARP PANDA).**
  The byte totals require `LENGTH(raw)` over every selected rule, and `raw` is a
  large TEXT column in overflow pages — 219–262 MB of disk reads per call, on an
  endpoint that fires when the panel opens.

  Two attempts, both measured, because the first was wrong:

  | Implementation | ShinyHunters |
  |---|---|
  | Load bodies into Python (first cut) | 17.6 s |
  | Aggregate per axis in SQL | **43 s** — 2.4× *worse* |
  | Single pass, aggregate in Python | **12.4 s** |

  Per-axis SQL looked tidier and lost badly: each of the four axes re-ran
  `SUM(LENGTH(raw))`, so SQLite read the same 219 MB four times. What matters is
  reading the length **once per rule**, not where the `GROUP BY` happens.

  12.4 s is still poor for a panel. The real fix is a `raw_bytes INTEGER` column
  written at ingest, so facets never touch `raw` at all — a schema change plus a
  backfill, deliberately out of scope here and noted rather than hidden.

**Not addressed:** YARA remains unreachable, because selection is technique-based
and YARA is untagged. Fixing that means exporting from the ADR-0014 *proposal*
set (which reaches rules by observable match) rather than from techniques — a
different artifact with different semantics, and its own ADR.

## Validation

1. Filters compose: `format=sigma&license=DRL-1.1` returns exactly the rules
   matching both, and the count equals the facets prediction.
2. Every file in the archive carries the extension its format dictates.
3. `MANIFEST.json` `excluded` counts plus the included count equal the unfiltered
   total.
4. An export excluding `license=none` contains **zero** rules from `mthcht`.
5. Unfiltered behaviour is byte-comparable to today's, aside from layout and
   extension.
