# ADR-0070: Quoted Sigma, Suricata and Snort rules ship only if OpenCTI parses them

**Status:** Accepted
**Date:** 2026-10-02
**Deciders:** maintainer
**Amends:** ADR-0042 (embedded detection rules), ADR-0067 (the same gate for YARA)

## Context

ADR-0067 gated quoted YARA rules on `yara.compile`, because OpenCTI refuses an
Indicator its parser rejects, and every edge to it then fails. OpenCTI checks
the other formats Stage 4 quotes the same way
(`opencti-graphql/src/python/runtime/check_indicator.py`, any exception means
a refusal):

- Sigma with `SigmaCollection.from_yaml` (pysigma 1.5.0);
- Suricata with `parsuricata.parse_rules` (0.4.1);
- Snort with OpenCTI's own `snort_parser.Parser`, which is not on PyPI.

### Measured

No report behind the bundles in `output/` quotes a Sigma, Suricata or Snort
rule, so the measurement uses the detection corpora. 2,000 ET Open lines and
1,000 SigmaHQ files were quoted in prose, extracted with Stage 4's own finders
(`_find_embedded_net_rules`, `_find_embedded_sigma_rules`), and checked with
OpenCTI's parsers at OpenCTI's versions. The run was repeated after a PDF-like
layout: lines longer than 90 characters are wrapped at a space, the
continuation starts at column 0, and every line is followed by a blank line,
which is what the INDUSTROYER.V2 PDF did (ADR-0067).

| | clean text | PDF layout |
|---|---|---|
| Suricata extracted / accepted by parsuricata | 2,000 / 2,000 | 20 / **0** |
| same lines, accepted by OpenCTI's Snort parser | **167** / 2,000 | 0 / 20 |
| Sigma extracted / accepted by pysigma | 1,000 / 1,000 | 110 / **96** |

Two failures that would reach OpenCTI:

1. **A rule cut by the layout.** Every wrapped ET rule that the line finder
   still matched was truncated: its first line happened to contain a `)`.
   OpenCTI refuses all 20. 14 Sigma rules lost their `condition` to the
   finder's shrink and are refused.
2. **The Snort/Suricata label.** ADR-0042 types a rule `snort` when that word
   appears in the 200 characters before it, because the two dialects share
   one syntax. OpenCTI's Snort parser refuses Suricata's application-layer
   protocols (`http` 879, `dns` 516, `tls` 369 of the refusals). A report
   that introduces "Snort and Suricata signatures" therefore ships Suricata
   rules as `snort`, and OpenCTI refuses them.

The layout also costs recall: 1,980 of 2,000 wrapped rules are not found at
all. That is a separate problem. Joining the lines back would guess what each
break stood for inside `content:` strings, and ADR-0067 declined that guess
for YARA `strings:`.

## Decision

`pipeline/detection/pattern_check.py` runs OpenCTI's parser for each quoted
rule before Stage 4 creates its Indicator.

- **Refused**: the Indicator is not built. The ledger records it in `removed`
  with reason `rule_does_not_parse`, the rule's name and the parser's message,
  and the Graph page lists it under "Removed".
- **Dialect**: a net rule that its typed parser refuses and the other parser
  accepts is shipped with the other type. The ledger records `retyped_from`,
  and the node panel says why. Only the parsers decide, never the wording
  around the rule.
- **Unverified**: without the parser installed, the rule ships as
  `pattern_check: "unverified"`, never as accepted, with one warning per
  process.
- **Length bound**: OpenCTI's Snort parser is quadratic on a line with no
  `;)` (0.14 s at 32,000 characters). A net rule longer than 16,384
  characters is refused without parsing.
- **Dependencies**: `pysigma` (1.5.0 in the lock, OpenCTI's pin; it brings
  jinja2, jq, diskcache and pyparsing) and `parsuricata` (0.4.1, with
  lark-parser). OpenCTI's Snort parser is copied unmodified into
  `pipeline/detection/opencti_snort/`. It is Apache-2.0, like this project;
  the header records the source, and mypy skips it.

## Consequences

- With the parsers installed, a bundle carries no Sigma, Suricata or Snort
  Indicator that OpenCTI's check refuses.
- A report's "Snort" wording no longer decides the dialect on its own.
- The copied Snort parser must be refreshed from OpenCTI when OpenCTI changes
  it. Its source path is in its header.
- The recall loss on wrapped net rules remains. Fixing it needs a decision on
  how to join a cut `content:` string.
