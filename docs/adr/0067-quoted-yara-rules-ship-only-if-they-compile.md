# ADR-0067: A YARA rule quoted in a report ships only if it compiles

**Status:** Accepted
**Date:** 2026-10-02
**Deciders:** maintainer
**Amends:** ADR-0042 (embedded detection rules become Indicators)
**Relates to:** ADR-0061 (the mapping ledger), ADR-0066 (OpenCTI is the
interop target), ADR-0013 (transitive completion)

## Context

The bundle for the Mandiant post "INDUSTROYER.V2: Old Malware Learns New
Tricks" (a Google Cloud blog page printed to PDF, pre-prod job `29fdabdd`) was
imported into OpenCTI. The worker logged:

- twice: `indicator of type yara is not correctly formatted` (HTTP 400,
  `incorrect_indicator_format`);
- 14 times: `element(s) not found` (HTTP 404) for the two Indicator ids above.

OpenCTI checks each Indicator with a parser for its `pattern_type`
(`opencti-graphql/src/python/runtime/check_indicator.py`). For YARA, the check
is `yara.compile(source=pattern)` with yara-python 4.5.4, and any exception
means a refusal. Once the Indicator is refused, every relationship that points
at it fails. Here that was 2 `indicates malware` edges (ADR-0042's title match)
and 12 `indicates attack-pattern` edges, which Stage 4b inferred through
`indicates + uses` (ADR-0013).

Compiled with the same yara-python, both rules fail at
`line 10: syntax error, unexpected end of file`. The cause is the PDF, not the
extraction. The printed page wraps the long `description` line of each rule's
`meta` block, so the quoted string is cut in two:

```
        description = "Searching for executables containing
bytecode associated with the INDUSTROYER.V2 malware family."
```

YARA does not allow a line break inside a string literal. The rule Mandiant
published compiles. The rule the report quotes does not. The same layout also
wraps the hex string and the condition, but YARA allows whitespace there. The
extracted text has a blank line after every line, which is also harmless.

ADR-0042 shipped `pattern=rule.body` without checking it. A rule a layout broke
therefore costs an analyst the Indicator, every edge to it, and an import log
full of errors that do not name the cause.

## Decision

Before Stage 4 creates a YARA Indicator, it calls
`pipeline/detection/yara_check.prepare_embedded_rule`.

1. **Repair what the layout broke, and only what cannot compile as it is.**
   - In the `meta:` section, a string left open at the end of a line is
     joined with the next non-blank lines, with one space, until it closes. It
     stops after 3 lines, at a section header, and at the rule's closing brace.
     If the string still does not close, the lines stay as they were. A meta
     value does not change what the rule matches.
   - A text string cut under `strings:` is left alone. Whether the break stood
     for a space or for nothing changes what the rule matches, and the text
     cannot say which.
   - An `import "module"` that the report declares outside the rule
     (`YaraRule.imports`) is added when the rule uses `module.`. An import
     the report does not declare is never added.

   Both repairs do nothing to a rule that already compiles on its own.
2. **Compile with yara-python, as OpenCTI does.** `yara-python>=4.5.4,<5` is
   now a requirement, pinned at 4.5.4 in the lock, the version OpenCTI pins.
   Any exception means `does_not_compile`.
3. **A rule that does not compile is left out.** No Indicator, so no edge to
   it. The ledger records it in `removed` with reason
   `rule_does_not_compile`, the rule's name and the compiler's message. The
   Graph page lists it under "Removed".
4. **A repaired rule says so.** Its ledger origin carries `rejoined_lines`
   and/or `added_imports`, and the node panel explains each repair.
5. **Without yara-python, the status is `unverified`, never `compiles`.** The
   rule still ships, and the ledger records `pattern_check: "unverified"`.
   One warning per process is logged, and the node panel says that OpenCTI may
   refuse the rule. PyPI has wheels only up to CPython 3.13. The image and CI
   run 3.12. A 3.14 venv needs `python3.14-dev` to build the package.

On the job above, both rules compile after one rejoined line each. Their
Indicators and all 14 edges become importable.

## Options considered

| Option | Verdict |
|---|---|
| **A — ship the quoted text, as before** | Rejected: OpenCTI refuses the Indicator and every edge to it |
| **B — drop any rule that does not compile, no repair** | Rejected: it loses the two rules of this report for a cosmetic break in a comment-like field |
| **C — join every unclosed string, `strings:` included** | Rejected: for a text string, a space or nothing at the break are two different detections, and neither can be proven |
| **D — a hand-written YARA syntax check** | Rejected: it would drift from the parser OpenCTI uses, and the check must be the one that decides the import |
| **E — repair `meta` and imports, compile with yara-python, leave out the rest** (chosen) | Matches OpenCTI's check, keeps what the layout broke cosmetically, and names what it leaves out |

## Consequences

**Easier:**
- A bundle never carries a YARA Indicator that OpenCTI's own check refuses,
  when yara-python is installed.
- Rules from reports printed to PDF survive the most common wrap.

**Harder / revisit:**
- A new native dependency (a 2.3 MB wheel, no transitive dependencies). The
  offline bundle needs its wheel, so regenerate it from the lock.
- Sigma, Snort and Suricata Indicators carry the same risk. OpenCTI checks
  them with pysigma, its own Snort parser, and parsuricata. They are not gated
  yet.
- Of the 14 edges, 12 were `indicates attack-pattern` inferences from
  `indicates + uses`. Saying that a byte-pattern rule "indicates" every
  technique its malware uses is a stretch. That is ADR-0013's rule to
  revisit, not this ADR's.
