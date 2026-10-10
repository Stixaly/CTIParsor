# OpenSSF Best Practices: the self-assessment

CTIParsor's answers to the [OpenSSF Best Practices](https://www.bestpractices.dev)
"passing" criteria (67, as listed in the badge's `criteria.yml` on
2026-10-10), with the evidence for each. The badge is a self-assessment: the
maintainer enters these answers on bestpractices.dev, and Scorecard's
CII-Best-Practices check reads the result (ADR-0078, "In progress" 2/10,
"passing" 5/10).

**To enter them:** sign in to bestpractices.dev with GitHub, *Get your
badge now*, give `https://github.com/Stixaly/CTIParsor`. The form fills some
answers itself; check each against this page, paste the justification, save.
Re-read this page at each release and when a criterion changes.

`main/` below stands for `https://github.com/Stixaly/CTIParsor/blob/main/`.

## What still stands between "in progress" and "passing"

Four MUST criteria need **the first versioned release** (the plan's v0.x
Release, ADR-0078's amendment on Signed-Releases):

- `version_unique`, `release_notes`: a `v0.1.0` tag, a GitHub Release whose
  notes summarise the CHANGELOG, and SLSA provenance among its assets.
- The publish job (`.github/workflows/ci.yml`, `publish-image`) runs only on
  pushes to `main` and the workflow is not triggered by tags, so its
  `type=semver` image tags never apply today. The release work changes that.

Two answers are the maintainer's own statement, not evidence in the
repository: `know_secure_design` and `know_common_errors`. The
justifications below list what the repository shows.

Everything else is **Met** or **N/A** as of 2026-10-10.

## Basics

| Criterion | Answer | Justification |
|---|---|---|
| description_good | Met | The README opens with what CTIParsor does: it turns unstructured CTI reports into validated STIX 2.1 bundles, with the evidence behind every claim. `main/README.md` |
| interact | Met | README: *Quick start* (obtain), *Feedback and contributing* (bug reports and feature requests in GitHub Issues, vulnerabilities via SECURITY.md, contributions via CONTRIBUTING.md). |
| contribution | Met | `main/CONTRIBUTING.md#how-a-change-gets-in`: fork, branch, one pull request per change, required checks, review. |
| contribution_requirements | Met | `main/CONTRIBUTING.md`: the green-build checklist (ruff, mypy, coverage floors, frontend checks), *Conventions* (tests with each change, ADRs, line length). |
| floss_license | Met | Apache-2.0. |
| floss_license_osi | Met | Apache-2.0 is OSI-approved. |
| license_location | Met | `main/LICENSE`; per-file licences in `main/REUSE.toml`, texts in `LICENSES/`. |
| documentation_basics | Met | README, and `docs/` (pipeline, configuration, web UI, deployment, Docker). |
| documentation_interface | Met | REST API: `docs/api.md`; output: `docs/stix-output.md`; configuration: `docs/configuration.md`; CLI: README *Usage*. |
| sites_https | Met | github.com and ghcr.io, HTTPS only. |
| discussion | Met | GitHub Issues and pull requests: searchable, addressable by URL, open to anyone with a GitHub account. |
| english | Met | Documentation, code and issues in English (one review note, `docs/stix-relationships-review.md`, is in French). |
| maintained | Met | Changes merged weekly; `CHANGELOG.md`. |

## Change control

| Criterion | Answer | Justification |
|---|---|---|
| repo_public | Met | `https://github.com/Stixaly/CTIParsor` |
| repo_track | Met | git: every change has its author, date and pull request. |
| repo_interim | Met | Every change lands on `main` through a pull request, between releases. |
| repo_distributed | Met | git. |
| version_unique | **Unmet until v0.1.0** | Each published image already carries a unique `sha-<commit>` tag (GHCR), but there is no versioned release yet. After the release: "SemVer tags (`vX.Y.Z`), GitHub Releases." |
| version_semver | Unmet until v0.1.0 | Then: SemVer. |
| version_tags | Unmet until v0.1.0 | Then: each release is a git tag `vX.Y.Z`. |
| release_notes | **Unmet until v0.1.0** | `CHANGELOG.md` (Keep a Changelog) groups every change; the Release notes will summarise it per version. |
| release_notes_vulns | N/A | No publicly known vulnerability in CTIParsor itself has had a CVE. Then: the CHANGELOG's *Security* sections name each fix. |

## Reporting

| Criterion | Answer | Justification |
|---|---|---|
| report_process | Met | `https://github.com/Stixaly/CTIParsor/issues`, described in README *Feedback and contributing*. |
| report_tracker | Met | GitHub Issues. |
| report_responses | Met | Every bug report in the last 12 months was handled (so far filed by the maintainer, e.g. #57). |
| enhancement_responses | Met | No enhancement request has been left unanswered (none from outside contributors so far). |
| report_archive | Met | `https://github.com/Stixaly/CTIParsor/issues?q=is%3Aissue` |
| vulnerability_report_process | Met | `main/SECURITY.md#reporting-a-vulnerability` |
| vulnerability_report_private | Met | GitHub private vulnerability reporting is on: `https://github.com/Stixaly/CTIParsor/security/advisories/new`. |
| vulnerability_report_response | N/A | No vulnerability report received in the last 6 months. SECURITY.md commits to a first answer within 14 days. |

## Quality

| Criterion | Answer | Justification |
|---|---|---|
| build | Met | `Dockerfile` (multi-stage: UI build, venv, runtime), `docker compose build` / `make docker-build`; CI builds and smoke-tests the image on every pull request. |
| build_common_tools | Met | Docker, pip, npm/Vite, make. |
| build_floss_tools | Met | All FLOSS: Docker Engine, Python, Node.js, uv. |
| test | Met | pytest (~2,400 tests) and Vitest; how to run them: `main/CONTRIBUTING.md` (green-build checklist), `main/TESTING.md`, `.github/workflows/ci.yml`. |
| test_invocation | Met | `pytest`, `npm test`, `make test` / `make ci`. |
| test_most | Met | Branch coverage, CI floor 87% total plus per-area floors (`pyproject.toml`, `scripts/check_coverage.py`). |
| test_continuous_integration | Met | GitHub Actions on every pull request and push, weekly too. |
| test_policy | Met | `main/CONTRIBUTING.md`: a change comes with its tests; new behaviour with a test that fails without it. |
| tests_are_added | Met | E.g. PR #132 adds a test reproducing the Stage 2e defect it fixes; PR #128 tests each Stage 2 extraction fix. |
| tests_documented_added | Met | `main/CONTRIBUTING.md#how-a-change-gets-in`. |
| warnings | Met | ruff (pycodestyle, pyflakes, isort, bandit `S`, bugbear `B`), mypy, ESLint, TypeScript `strict`. |
| warnings_fixed | Met | CI blocks on every one (ADR-0071); `main` is at zero. |
| warnings_strict | Met | ruff with the security and bugbear rule sets, TypeScript `strict`; mypy flags tightened step by step (`pyproject.toml` records the next ones and their counts). |

## Security

| Criterion | Answer | Justification |
|---|---|---|
| know_secure_design | Met (maintainer) | The maintainer's statement. Evidence: `SECURITY.md`'s threat model per surface; least privilege in the containers (ADR-0044: non-root, read-only, no capabilities, seccomp); fail-closed TLP handling (ADR-0073); report text treated as delimited data (ADR-0074); a verifiable supply chain (ADR-0075, ADR-0080). |
| know_common_errors | Met (maintainer) | The maintainer's statement. Evidence of each error class and its counter: prompt injection (ADR-0074), ReDoS (google-re2, ADR-0049), SSRF in URL capture (validated URLs, egress proxy), path traversal in tar extraction (`_safe_members`), XML attacks (defusedxml), option injection into git (commit ids only), CodeQL and ruff `S` on every change. |
| crypto_published | Met | TLS through nginx/OpenSSL; proxy passwords as bcrypt (or SHA-512-crypt); no custom cryptography. |
| crypto_call | Met | OpenSSL (nginx), Python's hashlib; nothing re-implemented. |
| crypto_floss | Met | OpenSSL, nginx, Python: FLOSS. |
| crypto_keylength | Met | The documented certificate is RSA 4096; TLS 1.2+ only, ECDHE with AEAD ciphers (`docker/nginx/default.conf`), configurable there. |
| crypto_working | Met | No MD4/MD5/DES/RC4 in any security mechanism: the docs no longer suggest APR1 (MD5) password entries, TLS 1.2 is ECDHE+AEAD only. MD5 and SHA-1 appear only as indicator types read from reports. |
| crypto_weaknesses | Met | No SHA-1 or CBC suite in TLS. STIX ids are UUIDv5 as STIX 2.1 specifies: identifiers, not a security mechanism. |
| crypto_pfs | Met | TLS 1.2 limited to ECDHE suites; TLS 1.3 is forward-secret by design. Checked with `openssl s_client` on 2026-10-10: RSA key exchange and CBC suites refused. |
| crypto_password_storage | Met | The application stores no passwords (no user accounts: SECURITY.md). The optional proxy's `htpasswd` is written by the operator; the docs give bcrypt, cost 12 (`htpasswd -nBC 12`). |
| crypto_random | Met | The only secret CTIParsor generates, the database password, comes from `openssl rand -hex 24` (`setup.sh`, fallback `/dev/urandom`). The application generates no keys or nonces. |
| delivery_mitm | Met | GitHub and GHCR over HTTPS; images pinned by digest, the published image with Sigstore-signed provenance; every pip install checks hashes (ADR-0080). |
| delivery_unsigned | Met | No hash is fetched over HTTP: the lock files carry them, in the repository. |
| vulnerabilities_fixed_60_days | Met | 0 open Dependabot and code-scanning alerts. The accepted ones in `SECURITY.md` are not exploitable in CTIParsor, each with its reason and review date. |
| vulnerabilities_critical_fixed | Met | Dependency and image vulnerabilities are fixed in days (CHANGELOG *Security*); CI audits weekly. |
| no_leaked_credentials | Met | Secret scanning with push protection is on, 0 alerts; `.env` and `.secrets/` are gitignored. |

## Analysis

| Criterion | Answer | Justification |
|---|---|---|
| static_analysis | Met | CodeQL (`security-extended`) on Python, TypeScript and the workflows on every pull request, push and weekly; ruff with bandit rules; mypy. A CodeQL alert of medium severity or higher that a pull request adds blocks its merge (ADR-0078). |
| static_analysis_common_vulnerabilities | Met | CodeQL `security-extended`, ruff `S`. |
| static_analysis_fixed | Met | 0 open code-scanning alerts. |
| static_analysis_often | Met | Every pull request and push. |
| dynamic_analysis | Met | Atheris fuzzes the attacker-facing parsers on every pull request (four targets, ADR-0081); the container smoke test runs the stack end to end. |
| dynamic_analysis_unsafe | N/A | Python and TypeScript, memory-safe languages. |
| dynamic_analysis_enable_assertions | Met | The fuzz targets assert invariants; the tests run with assertions on. |
| dynamic_analysis_fixed | Met | A fuzzer failure blocks the merge (required check); the input joins `fuzz/corpus/` and the fast tests replay it. |
