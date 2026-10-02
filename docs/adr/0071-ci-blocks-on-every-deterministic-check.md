# ADR-0071: CI blocks on every deterministic check, and `make ci` runs the same

**Status:** Accepted
**Date:** 2026-10-03
**Deciders:** maintainer
**Amends:** ADR-0054 (the `dev` service), ADR-0070 (its parsuricata dependency)

## Context

An outside review of the development practices (2026-10-02) listed six
problems. Each was checked against the tree before acting:

1. **Tests wrote into the checkout.** Finalizing a job writes its bundle to
   `output/`, and the persistence tests did so into the repository's own
   `output/`: the review saw three fail with `PermissionError` where it was
   read-only, and a run here left five `report_job-*_bundle.json` files behind.
2. **Deterministic tests did not block.** `tests/eval_pipeline.py` (10 tests,
   collected by `pytest.ini`) was excluded by `--ignore` in both CI jobs since
   before `pytest.ini` started collecting it. The fast job installed neither the
   OpenCTI pattern parsers (ADR-0067, ADR-0070) nor google-re2 (ADR-0049), so
   their tests skipped; they ran only in `model-tests`, which may fail and which
   the publish job does not wait for.
3. **The `dev` image lacked the CI tools.** No ruff, mypy or pytest-cov, and no
   Node, while CONTRIBUTING ran `ruff` and `npx tsc` in it.
4. **Coverage was reported, never enforced**, and measured lines only.
5. **No frontend lint; two Python lint scopes.** CI's ruff command left
   `scripts/` out, where nine errors had piled up, one of them a `NameError`
   (`measure_graph_links.py` called `compile_pattern` without importing it).
6. **TESTING.md was stale**: "no behavioural frontend tests" with 141 Vitest
   tests passing, a coverage gate that did not exist, and `make test` /
   `make docker-test` presented as equivalent while selecting different tests.

### What making the parser tests block found

Installed the way the image's builder installs them (one
`pip install -r requirements.lock.txt`, Python 3.12, pip 26.2.1), parsuricata
**does not import**. It needs `lark.InlineTransformer`, from lark-parser 0.12;
the lock also carried lark 1.3.1, brought by rfc3987-syntax, which jsonschema
4.25 added to the `format-nongpl` extra that stix2-validator requires. Both
distributions write the same `lark` package and the last one installed wins:
lark 1.3.1. `check_pattern()` catches the `ImportError` and returns
`unverified`, so every quoted Suricata rule shipped unchecked: ADR-0070's
Suricata gate was off in an image built from that lock, and nothing failed,
because CI never installed parsuricata.

## Decision

- **Files stay in `tmp_path`.** `api/paths.py` names the uploads and output
  directories, read on every call from `CTIPARSOR_UPLOADS_DIR` /
  `CTIPARSOR_OUTPUT_DIR` (default: the repository's `uploads/` and `output/`).
  An autouse fixture points both at each test's `tmp_path`; a session hook lists
  any file a run still adds to the checkout, and fails the run under CI.
- **A missing test dependency fails in CI.** The fast job installs the three
  pattern parsers, google-re2 and numpy, and sets
  `CTIPARSOR_REQUIRE_TEST_DEPS=1`: a test skipped by `pytest.importorskip`
  then fails. `eval_pipeline.py` runs in both jobs.
- **jsonschema < 4.25.** It removes lark 1.x and rfc3987-syntax from the lock
  (4.26.0 → 4.24.1, nothing else moves), which is OpenCTI's own environment:
  its platform installs parsuricata with lark-parser only. rfc3987-syntax
  checks only the `iri` format, which no STIX 2.1 schema uses; `uri`, `email`
  and `idn-hostname` are still checked. The smoke test now imports the three
  parsers in the built image.
- **Coverage floors, with branches.** `branch = true` over `pipeline/`, `api/`
  and `models/` (the copied Snort parser omitted). Floors at what the fast job
  measured, rounded down: 87 % total (`fail_under`, measured 88.0 %), 92 % for
  STIX mapping and validation and 91 % for persistence
  (`scripts/check_coverage.py`, measured 92.7 % and 91.8 %). They stop a
  slide; they are not targets.
- **One scope per tool, in `pyproject.toml`.** CI runs `ruff check .` and
  `mypy`. mypy additionally gets `check_untyped_defs`, `warn_redundant_casts`,
  `strict_equality` and `extra_checks`, which the tree passes after three
  small typing fixes (`check_untyped_defs` found `pipeline()` called with the
  task alias `"ner"`, which transformers' overloads do not list; it is now
  `"token-classification"`, what `"ner"` resolves to).
- **Frontend lint.** ESLint with typescript-eslint, `rules-of-hooks` and
  `exhaustive-deps` as errors, and the formatting the code already has. Not
  Prettier: it re-wraps 73 of the 82 files and undoes the aligned columns. Not
  the React Compiler rules of the hooks preset: 36 findings in code that works
  as written. `npm run check` = lint, tsc, Vitest, CI's three steps.
- **A `dev` image stage.** `FROM runtime AS dev` adds `requirements-dev.txt`;
  the Dockerfile ends on `FROM runtime`, so a build without `--target` (compose's
  `app`/`worker`, CI's publish job) never carries the dev tools. The `dev`
  service builds it and keeps the tools' caches and coverage data in its `/tmp`.
  `frontend-dev` keeps `node_modules` in a named volume: its root-run `npm ci`
  had left a root-owned tree in `frontend/node_modules`.
- **`make ci`** runs `lint`, `typecheck`, `coverage` and `frontend-check`, the
  pull-request jobs; `make docker-test` is an alias of `make test`.

## Consequences

- The publish job now waits for every deterministic test, the coverage floors
  and the frontend lint. `model-tests` stays a non-gate: it needs downloads and
  a live key.
- A new optional import in a test should use `pytest.importorskip`, and the
  package should be added to the fast job, or CI fails.
- jsonschema is held at 4.24.x until parsuricata or OpenCTI moves to lark 1.x.
  Lifting the bound needs the smoke test's parser import to stay green.
- An air-gapped install has the `app` image but not `dev`: its first
  `make test` needs the network once.
- Still open: Stage 5's schema-backed test skips in the fast job (the STIX
  schemas are fetched at run time); mypy's next steps measured at
  `warn_return_any` 28 errors, `warn_unreachable` 27,
  `disallow_incomplete_defs` 140; no browser end-to-end test yet.
