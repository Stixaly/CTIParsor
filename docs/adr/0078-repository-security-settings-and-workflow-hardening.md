# ADR-0078: Repository security: pinned actions, image and workflow scanning, settings

**Status:** Accepted — workflows implemented; repository settings applied by the maintainer
**Date:** 2026-10-04
**Deciders:** maintainer
**Amends:** ADR-0075 (a verifiable supply chain)

## Context

ADR-0075 pinned the images, audited the locks and switched CodeQL on. A
review of the repository on 2026-10-04 (files and settings, through the API)
found what it left open:

- **Actions were referenced by tag** (`actions/checkout@v7`). A tag can be
  moved to other code: that is how `tj-actions/changed-files` leaked CI secrets
  in March 2025. Anchore had in fact stopped moving its major tags in March
  2026: `anchore/sbom-action@v0` ran a release six months old.
- **No check saw the image's operating-system packages.** `pip-audit` and
  `npm audit` stop at the lock files; Debian under `python:3.12-slim`,
  Chromium and its libraries were not scanned.
- **Vulnerabilities were found only on push.** A CVE published on a pinned
  version reached nobody until someone pushed.
- **A pull request could add a vulnerable dependency** that only the next
  full audit would catch.
- **The workflows themselves were not analysed**, although GitHub lists
  `actions` among the repository's languages. Every checkout also left the job's token
  in `.git/config` for later steps to read.
- **Settings:**
  - Dependabot alerts were off.
  - Private vulnerability reporting was off, although SECURITY.md told
    reporters to "open a private security advisory".
  - `main` had no protection: a ruleset existed, disabled and targeting no
    branch.
  - Any action could run, unpinned.

## Decision

### In the repository (this change)

1. **Every action is pinned to a full commit SHA**, with its version as a
   comment (`@<sha> # v7.0.1`). The existing Dependabot `github-actions`
   entry updates SHA and comment together. `dependabot.yml` is unchanged
   (maintainer's rule: Dependabot is never restricted).
2. **Least-privilege tokens.** `permissions: contents: read` sits at the top
   of `ci.yml` and `codeql.yml`; a job asks for more by name (`publish-image`,
   `container-image`). Every checkout sets `persist-credentials: false`: no
   job pushes, so none needs the token in `.git/config`.
3. **CodeQL also analyses the workflows** (`actions` in the matrix): script
   injection, over-broad permissions, untrusted checkouts.
4. **Image scan.** After the build, `container-image` runs **Grype** (Anchore,
   already trusted for the SBOM) on the image. The vulnerabilities **with a
   fix** go to Code scanning (category `container-image`). It does not fail
   the build: a base image always carries some CVEs, and those with a fix are
   the ones a rebuild or a base-image bump removes.
5. **Dependency review on pull requests.** `actions/dependency-review-action`
   fails a PR that adds or changes a dependency with a known vulnerability of
   high severity or worse, in any manifest the dependency graph reads. It
   needs the dependency graph, which turning on Dependabot alerts enables.
6. **Weekly CI run** (Monday, `schedule`): `pip-audit`, `npm audit` and the
   image scan meet the vulnerabilities published since the last push. Model
   tests and publishing stay push-only.
7. **OpenSSF Scorecard**, weekly and on push. It scores branch protection,
   pinning, token permissions, dangerous workflows and signed releases, and
   publishes to scorecard.dev (README badge). Its results are **not** uploaded
   to Code scanning: Code-Review, Fuzzing and CII-Best-Practices score a
   one-maintainer project low by construction, and would sit there as alerts
   nobody can close.

### In the repository settings (maintainer)

Settings are not files. These are applied by hand (Settings → Advanced Security, Rules, Actions):

8. **Dependabot alerts on**, which also enables the dependency graph.
   **Dependabot security updates stay off:** for Python they would bump a
   single pin in the uv-compiled lock, the inconsistency ADR-0075 avoided.
   `make update-deps` re-resolves instead.
9. **Private vulnerability reporting on**, so that SECURITY.md's "open a
   private security advisory" works for someone outside the repository.
10. **A ruleset on the default branch.** The existing "basic rules" ruleset is
    completed and enabled:
    - deletion and force-push blocked;
    - changes through a pull request, with 0 approvals required (one
      maintainer);
    - required checks: the four CI jobs that run on every PR (fast tests,
      dependency audit, frontend, container image) and CodeQL for Python and
      for TypeScript;
    - "require code scanning results": CodeQL, security alerts high or
      higher;
    - bypass for admins **in pull requests only**: an emergency merge when a
      check is broken, never a direct push.
11. **Once this change is on `main`: require actions pinned to a full SHA**
    (Settings → Actions → General). Turned on earlier, it would make every
    workflow on `main`, still on tags, fail.

## Options considered

- **Trivy instead of Grype.** Equivalent coverage. Grype comes from the vendor
  of the SBOM action already in use, so one supplier instead of two.
- **Image scan as a blocking gate.** It would fail the build on CVEs that
  have no fix yet, or that are fixed only in the next base-image release.
  Reporting the fixable ones to Code scanning keeps them visible without
  that noise. Revisit once the first runs show the baseline.
- **zizmor for the workflows.** It is more thorough than CodeQL's `actions`
  queries, but it would be one more tool, and CodeQL already runs.
- **StepSecurity harden-runner** (egress policy on runners). It is useful
  against a compromised dependency calling home during CI, but it adds a
  third-party agent to every job. Not now.
- **A Dependabot `cooldown`** (wait N days after a release, against freshly
  compromised npm packages). Not added: Dependabot is never restricted.

## Consequences

- **Easier:**
  - every action is a fixed, reviewable SHA, updated by Dependabot;
  - the image's OS packages, newly published CVEs and the workflows
    themselves are all watched;
  - a vulnerable dependency cannot ride in on a PR;
  - `main` only changes through green pull requests;
  - outside reporters have a private channel.
- **Harder:**
  - Code scanning gains a second source (Grype), whose first run may report a
    batch of fixable OS-package CVEs;
  - a direct push to `main` is refused.
- **To revisit:** making the image scan blocking for critical CVEs with a fix
  once the baseline is clean; adding "Dependency review" and "CodeQL
  (actions)" to the required checks once they have run on `main`.

## Action items

1. [x] Pin every action by SHA; top-level read-only `permissions`;
       `persist-credentials: false` on every checkout.
2. [x] CodeQL `actions`; Grype image scan to Code scanning; dependency review
       on PRs; weekly CI; Scorecard with README badge.
3. [x] SECURITY.md: reporting through private advisories, the new checks.
4. [ ] Maintainer: Dependabot alerts, private vulnerability reporting, the
       `main` ruleset (items 8–10).
5. [ ] Maintainer, after merge: require SHA-pinned actions (item 11); add
       "Dependency review (what this PR adds)" and "CodeQL (actions)" to the
       required checks.

## Amendment (2026-10-10) — Scorecard after ADR-0080 and ADR-0081

Item 7 named Code-Review, Fuzzing and CII-Best-Practices as the checks a
one-maintainer project scores low by construction. Fuzzing now scores 10
(ADR-0081), and CII-Best-Practices does not belong in the list. The checks
below 10 on 2026-10-10, and why:

| Check | Why it is below 10 | What raises it |
|---|---|---|
| Code-Review | Each change needs an approval from someone other than its author. | A second human reviewer, nothing else: by construction. |
| Contributors | It counts the companies and organizations of contributors with at least 5 commits. Only one is found. | Outside contributors: by construction. |
| Branch-Protection | Item 10's "basic rules" ruleset exists but is **disabled** (API, 2026-10-10). | Enabling it: deletion and force-push blocked give 3/10, about 4/10 with a required pull request and "require branches to be up to date". The next tier needs required approvals, which would block the only maintainer. |
| CII-Best-Practices | No OpenSSF Best Practices badge. | Maintainer: register the project at bestpractices.dev. "In progress" gives 2/10, "passing" 5/10. |

Pinned-Dependencies and Vulnerabilities reach 10 with ADR-0080's item 7 and
the `osv-scanner.toml` files (SECURITY.md, "Accepted vulnerabilities").
Each entry there expires at its review date, and the check drops back until
the review. `docs/dependencies.md`'s quarterly routine includes that review.

**Signed-Releases is not scored, as long as the repository publishes no
GitHub Release.** A Release changes that. Scorecard looks at the assets of
the last five Releases only, not at the GHCR image's attestations. A Release
without a provenance file (`*.intoto.jsonl`, 10/10) or a signature (`*.sig`,
`*.asc`, `*.minisig`, `*.sign`, `*.sigstore`, `*.sigstore.json`, 8/10) among
its assets scores 0. That costs about half a point of the overall score. A
Release, if there is ever one, attaches SLSA provenance for its assets.

**The fuzzers are required checks too (decided 2026-10-10).** Item 10's
list of required checks predates ADR-0081. The ruleset also requires:

- `Fuzz (report_text)`
- `Fuzz (dates)`
- `Fuzz (rule_gates)`
- `Fuzz (spotlight)`

No change reaches `main` while a fuzzer fails on it. This goes further than
ADR-0071, which blocks on deterministic checks. Sixty seconds of mutation
can find a defect that the pull request did not introduce. Such a failure
is still a bug to fix before the merge:

1. Reproduce it from the uploaded artifact:
   `python fuzz/fuzz_<target>.py <file>`.
2. Fix it.
3. Add the input to `fuzz/corpus/<target>/`.

From then on, `tests/test_fuzz_targets.py` replays that input in the fast
tests, so an exception or a broken invariant fails them. A merely slow input
fails only the fuzz run. The Fuzzing workflow runs on every pull request,
with no path filter, so these checks always report.

**Settings observed through the API on 2026-10-10.** Private vulnerability
reporting (item 9) is **off**, so SECURITY.md's "open a security advisory"
link does not work for a reporter outside the repository. The `main`
ruleset (item 10) is **disabled**. Action item 4 stays open, and now
includes the four fuzz checks. Items 8 (Dependabot alerts) and 11 (actions
pinned by SHA) cannot be read without administrator access. The maintainer
checks them in Settings.
