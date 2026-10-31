# ADR-0085: Releases promote the image main built, and sign the files they add

**Status:** Accepted — workflow implemented; v0.1.0 released 2026-10-17; release immutability enabled after it; v0.2.0 released 2026-10-29, the first immutable Release; tag ruleset still to be applied by the maintainer (2026-10-30)
**Date:** 2026-10-17
**Deciders:** maintainer
**Amends:** ADR-0047 (version tags), ADR-0075 (a verifiable supply chain), ADR-0078 (Signed-Releases)
**Relates to:** ADR-0035 (a bundle records the commit that built it), ADR-0054
(Docker is the only supported way to run CTIParsor), ADR-0077 (§7, the previous
release in CI)

## Context

CTIParsor has no version. Measured on 2026-10-17 (the repository's files, and
its settings through the API, read-only):

- **No tag and no GitHub Release exist.**
- **The numbers that exist back nothing.** FastAPI's `version` (in the OpenAPI
  schema) and `frontend/package.json` both said `1.0.0`.
- **ADR-0047's semver tags never applied.** It added two `type=semver` lines to
  the `docker/metadata-action` of `publish-image`, "ready if versioning
  starts". `ci.yml` never runs on a tag, so they were inert.
- **The image main publishes is verifiable.** The `latest` image on GHCR
  carries SLSA provenance v1 and a CycloneDX SBOM attestation.
  `gh attestation verify` passed for the image of commit 88bd1d7, signer
  `ci.yml@refs/heads/main`. The GHCR package is public (an anonymous pull
  works). The published images are OCI image indexes.
- **No rule covers tags.** The ruleset "basic rules" targets the default branch
  only: anyone with write access can create, move or delete a `v*` tag.
- **Immutable releases are off.** There are no environments.
- **The Actions settings need no change.** Every action is allowed and SHA
  pinning is required (ADR-0078, item 11). The default `GITHUB_TOKEN` is
  read-only, but a job may still ask for `contents: write`, `packages: write`,
  `id-token: write` and `attestations: write`.
- **Private vulnerability reporting, Dependabot alerts, and secret scanning
  with push protection are on**, as SECURITY.md says.

Four things wait for a first release:

- Four OpenSSF Best Practices criteria: `version_unique`, `version_semver`,
  `version_tags` and `release_notes` (`docs/openssf-best-practices.md`).
- Scorecard's Signed-Releases check. ADR-0078's amendment says it is not scored
  while there is no Release, and that a Release whose assets hold no
  `*.intoto.jsonl` file or signature scores 0.
- ADR-0077 §7, which says "There are no release tags".
- The CHANGELOG. `[Unreleased]` holds everything since the project began: 244 547
  characters (246 KB) in 86 entries on 2026-10-17, before this change's own
  entry. GitHub refuses a release body above 125 000 characters.

## Decision

1. **A release is a tag `vX.Y.Z` on a commit of `main` whose CI passed.** The
   maintainer pushes it by hand, after merging a release pull request that
   `scripts/release.py prepare X.Y.Z` prepared: it moves `[Unreleased]` under
   `## [X.Y.Z] - date` and sets the version everywhere. The procedure is
   `docs/releasing.md`.

2. **The release promotes the image main built; it rebuilds nothing.** Main's CI
   (`ci.yml`, `publish-image`) already built, tested and attested the image of
   every commit, under `sha-<commit>`. The release gives that image the name
   `X.Y.Z`, and `X.Y` when the tag is the highest `vX.Y.*`, with
   `docker buildx imagetools create` from its digest.
   That is a carbon copy: the digest is unchanged, and the workflow verifies
   it, so the provenance and the SBOM attestation signed on `main` are the
   release's.

3. **One source for the version.** `__version__` in `pipeline/__init__.py`,
   `"0.0.0"` until the first release.
   - FastAPI's `version` reads it.
   - `frontend/package.json` and `frontend/package-lock.json` mirror it (the
     lock states it twice).
   - `tests/test_release.py` fails if they disagree, or if the CHANGELOG's
     first `##` heading is not `## [Unreleased]`.
   - Between two releases `main` carries the last release's number. Builds are
     told apart by `git_rev`, which every bundle records and the image stamps
     (`CTIPARSOR_GIT_REV`).

4. **`scripts/release.py`** (standard library only, Python 3.12+), six
   subcommands:
   - `version [--next major|minor|patch]`;
   - `check vX.Y.Z`: the tag against `__version__`, `frontend/package.json` and
     `frontend/package-lock.json`, and a non-empty `## [X.Y.Z] - YYYY-MM-DD`
     section of the CHANGELOG; every mismatch is reported;
   - `notes X.Y.Z [--image REF]`: the CHANGELOG section, then "Container image"
     and "Files" paragraphs with the verify commands. Those commands pin the
     signer workflow and the source ref (`--signer-workflow`, `--source-ref`):
     with `-R` alone, an attestation signed by any workflow of the repository
     would pass. A section longer than
     100 000 characters is replaced by its opening paragraph and the list of its
     `####` entry titles under their `###` groups, with a link to CHANGELOG.md at
     the tag. That is the case for 0.1.0 as `[Unreleased]` stands;
   - `unreleased`: prints what `[Unreleased]` holds, which is what the next
     release would ship; nothing if it is empty, exit 1 if the section does not
     exist;
   - `prepare X.Y.Z [--date]`: refuses a version not above the current one, or an
     empty `[Unreleased]`;
   - `predicate`: extracts a predicate from `gh attestation verify --format json`.

5. **`scripts/release_files.sh <tag> <commit>`** finds the image
   `ghcr.io/stixaly/ctiparsor:sha-<commit>` and verifies its provenance and its
   SBOM attestation with `gh attestation verify --signer-workflow
   Stixaly/CTIParsor/.github/workflows/ci.yml --source-ref refs/heads/main
   --source-digest <commit>`. An image pushed by hand under that tag fails. It
   writes:
   - `release/dist/ctiparsor-X.Y.Z.tar.gz` (`git archive`);
   - `release/dist/ctiparsor-X.Y.Z-image.cdx.json`, the SBOM as attested when
     main built the image, taken from the verified attestation, not regenerated;
   - `release/dist/SHA256SUMS`;
   - `release/notes.md`.

6. **`release.yml`, job `publish`, on a push of a tag `v*`**, in this order:
   - runs `release.py check` on the tag, then checks the tagged commit is on
     `main`. It comes first, so that a wrong version file fails before the
     wait;
   - requires that no Release exists for the tag, draft or published. If one
     does, it fails and says how to fix it: a draft left by a failed run is
     deleted by hand (`gh release delete vX.Y.Z --yes`, which keeps the tag)
     and the run is re-run; a published Release means releasing the next patch
     version. Nothing deletes a draft automatically: on GitHub, deleting the tag
     of a published Release turns it back into a draft, and an automatic delete
     would have removed it;
   - waits up to an hour for main's CI (`ci.yml`, push event) on that commit and
     requires it to have passed. It retries after a transient API error. If
     five checks, a minute apart, find no CI run it fails: the wrong commit was
     tagged, and the release pull request's merge commit is the one to tag;
   - sets up buildx and logs in to GHCR, before the files: anonymous reads work
     only while the package is public;
   - runs `scripts/release_files.sh`;
   - gives the image its version names (decision 2). `X.Y.Z` is refused if it
     already names another digest: a version never moves to another image.
     `X.Y` is moved only if the tag is the highest `vX.Y.*`. Then both names are
     checked against the digest;
   - signs an SLSA provenance of the files with `actions/attest`, taking the
     subjects from `SHA256SUMS`;
   - creates the GitHub Release as a draft, uploads the files and
     `ctiparsor-X.Y.Z.intoto.jsonl` (the Sigstore bundle of that provenance),
     then publishes it. "Latest" is set only if the tag is the highest tag of
     strict SemVer form (`v0.1.0-rc.1` or `vfoo` do not count).

7. **`release.yml`, job `dry-run`, on a pull request that changes `release.yml`,
   `scripts/release.py` or `scripts/release_files.sh`, and every Monday
   (`schedule`):**
   - the weekly run catches what the paths filter cannot see: a change to
     `ci.yml`, to `gh`, or to the registry;
   - the token is read-only (`contents: read`, `actions: read`,
     `attestations: read`);
   - it prepares the next minor version on the runner only. When `[Unreleased]`
     is empty (right after a release, or on a Dependabot bump of `release.yml`)
     it first adds a placeholder line on the runner, because `prepare` refuses
     an empty section;
   - it runs `scripts/release_files.sh` against main's last commit whose CI
     passed, and checks the sums;
   - it puts the notes in the job summary;
   - it publishes, tags and attests nothing.

8. **SemVer before 1.0.** The minor version goes up for new behaviour or for
   anything an operator must act on: the API, the bundle output, the
   configuration, a database migration. The patch version is for fixes only.

9. **`latest` keeps its meaning: current `main`** (ADR-0047). A released image is
   pinned by `X.Y.Z`, or better by digest: a workflow with `packages: write` can
   push a registry tag name again, so the Release notes give the digest.

10. **Two repository settings, recommended and not required.** The maintainer
    applies them by hand and reads them back through the API; the clicks are in
    `docs/releasing.md`.
    - **A tag ruleset** `release tags` on `v*`: restrict creations, updates and
      deletions, and block force pushes, with the repository admin role as the
      only bypass. Only the repository admin can then create, move or delete a
      release tag, through the bypass.
    - **Release immutability**: once a Release is published, its files cannot
      change and its tag can be neither moved nor deleted, and GitHub adds a
      release attestation. The workflow already publishes draft, then files,
      then public, which immutability requires.

## Options rejected

- **Rebuilding the image on the tag.** It would produce a digest different from
  the one CI tested, with a second provenance, and repeat the image build.
- **`slsa-framework/slsa-github-generator`.** Its reusable workflow must be
  referenced by a tag for its verification to work, and the repository requires
  every action to be pinned to a full SHA (ADR-0078, item 11). `actions/attest`
  is already used in `ci.yml`, and `gh` verifies what it signs.
- **release-please or semantic-release.** They derive the version and the notes
  from Conventional Commits. Commits here are prose, and the CHANGELOG is
  written by hand, with its measurements.
- **The version in `pyproject.toml` `[project]`.** A `[project]` table belongs to
  the packaging work ADR-0075 deferred, and its `requires-python` would change
  the target version ruff infers. **A `VERSION` file** was also rejected: it
  would have to be copied into the image and read at runtime, while the module
  already ships with the code.
- **An sdist, a wheel, PyPI.** Docker is the only supported way to run CTIParsor
  (ADR-0054). **A separate frontend file:** the UI is built into the image
  (`docs/deployment.md`).
- **Pre-releases (`-rc.N`).** Not for now: `release.py check` refuses them. The
  pull-request dry run is the rehearsal.
- **A GitHub environment with a required reviewer.** The maintainer already
  pushes the tag, so a second click adds no independent check. It can be added
  later.

## Consequences

- **Easier:**
  - a version names one commit, one image digest and one set of files that
    verify against each other;
  - an operator pins `ghcr.io/stixaly/ctiparsor:X.Y.Z`, or the digest the
    notes give, instead of a `sha-` tag found by hand;
  - a change to the release machinery is rehearsed in its own pull request.
- **Harder:**
  - a release takes a pull request before the tag, because the version and the
    CHANGELOG section are files;
  - tagging a commit main's CI did not run on fails the workflow and costs a
    deleted tag;
  - the image's new names are pushed before the Release is public, so a run
    that fails after that step leaves them on GHCR, and once the provenance
    step has run, its attestation is in GitHub's attestation store and in
    Sigstore's public transparency log;
  - once the version names are on the image, `X.Y.Z` names that image for good:
    a run that failed after that step cannot be redone with another commit under
    the same version, and the next patch version is released instead;
  - until the tag ruleset exists, anyone with write access can create, move or
    delete a `v*` tag. With immutable releases off, the tag and the files of a
    published Release can still be changed.
- **What the checks are worth.** The workflow refuses a commit that is not on
  `main`, one whose CI did not pass, a tree whose version files and CHANGELOG do
  not state the tag's version, and an image whose attestations do not verify.
  They catch mistakes, not a person. A tag run uses `release.yml` and
  `release_files.sh` as they are on the tagged commit: someone who can push a
  tag can edit them on a branch, tag that commit, and skip every check. Only the
  tag ruleset stops that.
- **Not validated yet.** The `publish` job has not run: there is no tag. The
  dry run rehearses the checks, the image lookup and its attestations, the files
  and the notes. It cannot rehearse the version names on the image, the
  provenance of the files or the Release itself; the first release is their
  first test. v0.1.0 passed it (see the amendment below).
- **Waiting on the first release:**
  - the four OpenSSF criteria stay unmet until v0.1.0 is published, and are met
    once it is;
  - Scorecard's Signed-Releases check starts scoring at the first Release.
    ADR-0078's amendment says a `*.intoto.jsonl` asset is what it looks for. No
    score is predicted here.

  Both came with v0.1.0 (see the amendment below).
- **To revisit:** pre-releases, a protected environment, and the follow-up
  below.

## Action items

1. [x] `.github/workflows/release.yml`, `scripts/release.py`,
       `scripts/release_files.sh`, `tests/test_release.py`; the version in
       `pipeline/__init__.py` (FastAPI and `frontend/package*.json` follow it,
       from `1.0.0` to `0.0.0`); the two inert `type=semver` lines removed from
       `ci.yml`; `docs/releasing.md`.
2. [ ] Maintainer: the tag ruleset `release tags` (decision 10). Read back with
       `gh api repos/Stixaly/CTIParsor/rulesets`. Still open on 2026-10-30: the
       only ruleset is "basic rules", which targets the branch.
3. [x] Maintainer: enable release immutability (decision 10). Read back with
       `gh api repos/Stixaly/CTIParsor/immutable-releases`: `"enabled": true`
       on 2026-10-24. It was enabled after v0.1.0 was published, so v0.1.0 is
       not immutable (`isImmutable` is false). The setting applies to the
       Releases published after it.
4. [x] Cut v0.1.0: a pull request from `release.py prepare 0.1.0`, then the
       maintainer's tag. Once the Release is published, change every statement
       that says none exists:
       - `SECURITY.md`, the "Releases" bullet;
       - `docs/docker.md`, the paragraph on `X.Y.Z` names;
       - `docs/releasing.md`, "What a release is" and, once the two settings are
         applied, the dated paragraph of its settings section;
       - `docs/openssf-best-practices.md`, the paragraph under "What still stands
         between…" and the four rows; then enter the answers on bestpractices.dev;
       - this ADR's status line and action items.

       Done: PR #170, then the tag `v0.1.0` on its merge commit 4bdfa8f; the
       Release was published on 2026-10-17. The statements were changed on
       2026-10-24. Entering the answers on bestpractices.dev is item 6.
5. [x] Follow-up, not done here: with release tags, `scripts/check_migration_from.py`
       could also start from the last release tag. ADR-0077 §7 takes the pull
       request's base commit because "there are no release tags".

       Done on 2026-10-31 by ADR-0094 item 2: CI runs it from the highest tag
       `vX.Y.Z` on origin (fetched at depth 1) on every push to main, every pull
       request and every weekly run, and from the base commit on a pull request.
6. [ ] Maintainer: enter the answers of `docs/openssf-best-practices.md` on
       bestpractices.dev. Not done on 2026-10-24: Scorecard's
       CII-Best-Practices check is 0 ("no effort to earn an OpenSSF best
       practices badge detected").

## Amendment (2026-10-24) — v0.1.0 as published

Read back on 2026-10-23 and 2026-10-24, read-only: the API, `gh attestation
verify`, the registry and Scorecard's public results.

- **The Release.** "CTIParsor 0.1.0", published on 2026-10-17 at 15:06:52Z
  and marked Latest: <https://github.com/Stixaly/CTIParsor/releases/tag/v0.1.0>.
  Its tag `v0.1.0` is annotated and names 4bdfa8f, the merge commit of PR #170.
  The `publish` job ran once and passed.
- **Its files.** `ctiparsor-0.1.0.tar.gz`, `ctiparsor-0.1.0-image.cdx.json`,
  `SHA256SUMS` and `ctiparsor-0.1.0.intoto.jsonl`. `sha256sum -c SHA256SUMS`
  passes.
- **The verify commands of the notes pass**, with the signer workflow and the
  source ref pinned:
  - the archive and the SBOM: `release.yml`, `refs/tags/v0.1.0`;
  - the image: `ci.yml`, `refs/heads/main`, commit 4bdfa8f.

  Verifying the archive as signed by `ci.yml` fails, as it should.
- **The SBOM.** The attached file is the attested predicate, unchanged:
  CycloneDX 1.7, 7 202 components.
- **The image.** On GHCR, `0.1.0`, `0.1` and
  `sha-4bdfa8f9b2b3916486b87019a40148d5d15d9239` name the same digest,
  `sha256:80aca36a7cf3fbf9319ee828f8d4811bf90e56d94120a99776ba8df4cc71a773`.
  Nothing was rebuilt (decision 2).

  The three steps the dry run cannot rehearse therefore worked on their first
  run: the version names on the image, the provenance of the files, and the
  Release.
- **The settings.** Release immutability is on, but it was turned on after
  v0.1.0 was published. That Release is not immutable: its files can still be
  changed, and GitHub added no release attestation to it. No ruleset covers
  tags (item 2). Until one does, anyone with write access can create, move or
  delete a `v*` tag, `v0.1.0` included.
- **Scorecard.** Signed-Releases scores 10 on 2026-10-23 and 2026-10-24: "1 out
  of the last 1 releases have a total of 1 signed artifacts". That artifact is
  `ctiparsor-0.1.0.intoto.jsonl`, the only signature or provenance file among
  the assets.

## Amendment (2026-10-30) — v0.2.0, the first immutable Release

Read back on 2026-10-30, read-only, as for v0.1.0. Scorecard was not read again.

- **The Release.** "CTIParsor 0.2.0", published on 2026-10-29 at 23:00:04Z
  and marked Latest: <https://github.com/Stixaly/CTIParsor/releases/tag/v0.2.0>.
  Its tag `v0.2.0` is annotated and names ce59cfb, the merge commit of PR #223,
  whose `ci.yml` push run had passed. The `publish` job ran once and passed.
- **Its notes.** The CHANGELOG section is 111 KB, so the notes are its opening
  paragraphs (a summary and upgrade notes from 0.1.0) and its entry titles,
  6.6 KB (decision 4).
- **Its files.** `ctiparsor-0.2.0.tar.gz`, `ctiparsor-0.2.0-image.cdx.json`,
  `SHA256SUMS` and `ctiparsor-0.2.0.intoto.jsonl`. `sha256sum -c SHA256SUMS`
  passes. The archive and the SBOM pass `gh attestation verify` with
  `release.yml` and `refs/tags/v0.2.0`; the archive fails with `ci.yml`, as it
  should. The SBOM is CycloneDX 1.7, 7 200 components.
- **The image.** On GHCR, `0.2.0`, `0.2` and
  `sha-ce59cfb7025daf46fcb661b71c1ac7cd23f3f16b` name the same digest,
  `sha256:f7ea0d3f9d44692b8b08ed31dae5b1738ab19a88bc1cce856d7a297320c95526`,
  which passes `gh attestation verify` with `ci.yml` and `refs/heads/main`.
  Nothing was rebuilt.
- **Immutability.** `isImmutable` is true, and `gh release verify v0.2.0` finds
  GitHub's release attestation of the four files. Its files cannot change and
  its tag can be neither moved nor deleted. No ruleset covers tags yet
  (item 2): anyone with write access can still create a `v*` tag, or move or
  delete `v0.1.0`.
