# ADR-0081: Fuzzing the code that reads attacker-controlled input

**Status:** Accepted
**Date:** 2026-10-04
**Deciders:** maintainer
**Amends:** ADR-0078 (repository security)
**Amended by:** ADR-0078's amendment of 2026-10-10. The four fuzz jobs are
required checks on `main`, and a failure's input joins the seed corpus with
its fix.

## Context

CTIParsor's input is written by the people it reports on:

- the report text;
- the rules quoted in it (YARA, Sigma, Suricata, Snort), checked before
  OpenCTI sees them (ADR-0067, ADR-0070);
- the dates in it (ADR-0063);
- the text it puts in front of an LLM, which the prompt enclosure must keep
  from closing its block (ADR-0074).

The test suite covers these with the inputs someone thought of. The bugs
found lately came from inputs nobody thought of: ten regexes quadratic or
worse under backtracking `re`, one of them 110 s on a line of tabs, found by
CodeQL. OpenSSF Scorecard scored Fuzzing 0.

## Decision

1. **Four Atheris targets in `fuzz/`.** Atheris is Google's coverage-guided
   fuzzer for Python, built on libFuzzer; 3.1.0 has a CPython 3.14 wheel.

   | Target | Exercises | Invariant |
   |---|---|---|
   | `fuzz_report_text` | `refang`, `extract_entities` | no exception; every entity has a value |
   | `fuzz_dates` | `normalize` (every role, with and without an anchor), `locate`, `header_candidates` | no exception |
   | `fuzz_rule_gates` | the Sigma, Suricata and Snort gates, YARA (`prepare_embedded_rule` compiles with libyara, `split_rules`), STIX pattern literals | a gate answers a status and never raises; each literal is a slice of the input |
   | `fuzz_spotlight` | `fit_report` | each marker exactly once, in order; the report between them only cut, never altered; the question after it intact |

   Beyond each invariant, libFuzzer fails a target on three more things:
   - a native crash (libyara);
   - an input slower than `-timeout=10`, the ReDoS class;
   - memory past `-rss_limit_mb=2048`, a YAML alias bomb through pySigma.
2. **A `Fuzzing` workflow.** It runs the four targets in parallel, from
   copies of the committed seeds (`fuzz/corpus/`): 60 s each on every pull
   request and push to `main`, 10 minutes in the weekly run. The input that
   failed is uploaded as an artifact. Dependencies come from
   `requirements-ci.lock.txt`, by hash (ADR-0080). Atheris is pinned in
   `requirements-dev.txt`, for Linux x86_64 only, the one platform it
   publishes wheels for.
3. **`tests/test_fuzz_targets.py`** runs every target over its seeds in the
   ordinary suite, so a target that stops importing, or whose invariant a
   seed breaks, fails between fuzzing runs.

### Not chosen
- **ClusterFuzzLite** (OSS-Fuzz's runner). Its Python images trail CPython,
  and this code targets 3.14. It would add a builder image to pin and a
  Dockerfile to maintain, for the same libFuzzer engine.
- **Hypothesis** (property-based testing). It is useful, but generates from
  strategies rather than following coverage, and Scorecard does not count it
  for Python.

## Consequences

- **Easier:** inputs nobody wrote a test for are tried on every PR and
  weekly, and a slow input is a failure, not a silent ReDoS. Scorecard
  Fuzzing goes from 0 to 10 (it looks for `import atheris`).
- **Harder:**
  - four more CI jobs of about two minutes each on every pull request;
  - a failure needs its artifact to reproduce: run the target on the
    uploaded file, `python fuzz/fuzz_<target>.py <file>`.
- **Limits:**
  - `-timeout=10` with inputs of at most 16 KB catches catastrophic slowness,
    such as the cubic YARA rule header (110 s on 8,000 tabs). A merely
    quadratic regex stays under it at that size; `tests/test_linear_regexes.py`
    and re2 in the image cover those.
  - `fit_report` has almost no branches, so coverage guidance adds little
    there: `fuzz_spotlight` is a high-volume random test of its invariant.
- **Verified (2026-10-04).** 120 s per target, in a clean Python 3.14
  container with the CI lock installed by hash, found no crash, no broken
  invariant, no input over 10 s and no memory blow-up:

  | Target | Inputs | Coverage (edges) | Peak memory |
  |---|---|---|---|
  | `report_text` | 486,872 | 349 | 81 MB |
  | `dates` | 196,156 | 218 | 61 MB |
  | `rule_gates` | 383,041 | 1,171 | 154 MB |
  | `spotlight` | 23.5 million | — | 45 MB |

  The seed test passes, 5 cases.
- **To revisit:**
  - keeping the corpus the fuzzer grows between runs, with a cache, for
    longer runs;
  - more targets: the STIX bundle validation, the PDF and HTML ingestion.
