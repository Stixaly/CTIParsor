# Releasing CTIParsor

The maintainer's procedure for cutting a release, and what a user checks. The
decision and the options rejected are in
[ADR-0085](adr/0085-releases-promote-the-image-main-built.md).

- [What a release is](#what-a-release-is)
- [The image main's CI publishes](#the-image-mains-ci-publishes)
- [Versioning](#versioning)
- [Where the version lives](#where-the-version-lives)
- [Cutting a release](#cutting-a-release)
- [What the Release contains](#what-the-release-contains)
- [Verifying a release](#verifying-a-release)
- [When the workflow fails](#when-the-workflow-fails)
- [The dry run](#the-dry-run)
- [What the workflow's checks are worth](#what-the-workflows-checks-are-worth)
- [One-time repository settings](#one-time-repository-settings)

## What a release is

A tag `vX.Y.Z` on a commit of `main` whose CI passed. Pushing the tag starts
`.github/workflows/release.yml`, which publishes a GitHub Release.

**Nothing is rebuilt.** Main's CI (`ci.yml`) built the image of that commit
once, scanned and smoke-tested that build, then pushed it unchanged and
attested it as `ghcr.io/stixaly/ctiparsor:sha-<commit>` (see
[below](#the-image-mains-ci-publishes)). The release workflow gives that same
image the name `X.Y.Z`, and `X.Y` when the tag is the highest of its minor line. The digest does not change, so the build
provenance and the SBOM attestation that main's CI signed stay valid.

`latest` keeps meaning current `main` (ADR-0047). Pin a released image by
`X.Y.Z`, or better by digest: a workflow with `packages: write` can push a
registry tag name again. The Release notes give the digest.

The first release, [0.1.0](https://github.com/Stixaly/CTIParsor/releases/tag/v0.1.0),
was published on 2026-10-17. Its tag `v0.1.0` is annotated
and names commit 4bdfa8f, the merge of the release pull request (#170). On GHCR,
`0.1.0`, `0.1` and `sha-4bdfa8f…` name one digest,
`sha256:80aca36a7cf3fbf9319ee828f8d4811bf90e56d94120a99776ba8df4cc71a773`. Its
archive and SBOM pass `sha256sum -c SHA256SUMS`, and the archive, the SBOM and the
image pass the commands of [Verifying a release](#verifying-a-release) (checked
2026-10-23). It is not an immutable Release: immutability was turned on after
it was published (see [One-time repository settings](#one-time-repository-settings)).

The latest, [0.2.0](https://github.com/Stixaly/CTIParsor/releases/tag/v0.2.0),
was published on 2026-10-29 and is marked Latest. Its tag `v0.2.0` is annotated
and names commit ce59cfb, the merge of the release pull request (#223). On GHCR,
`0.2.0`, `0.2` and `sha-ce59cfb…` name one digest,
`sha256:f7ea0d3f9d44692b8b08ed31dae5b1738ab19a88bc1cce856d7a297320c95526`. The
same checks pass (2026-10-30). It is the first immutable Release: `gh release
view v0.2.0 --json isImmutable` gives `true`, and `gh release verify v0.2.0`
finds GitHub's release attestation.

## The image main's CI publishes

Since 2026-11-01 ([ADR-0047](adr/0047-publish-image-to-ghcr.md), amended),
each commit's image is built once, and the image GHCR serves is the image CI
tested:

Both jobs run on `ubuntu-26.04`: its Docker keeps images in the containerd
image store, which loads and pushes an image index whole. They fail if the
store is another one (Docker 28's classic store cannot load the archive).

1. Job `container-image` builds the image into an OCI archive: an image index
   holding the linux/amd64 image and BuildKit's SLSA provenance of it. The step
   "Load the archive as ctiparsor:ci" runs `docker load`, logs the archive's
   index digest and the loaded image's ID, and fails unless they are the same.
   The Grype scan, the smoke test and the air-gap check then run that image. On
   a push to `main`, the archive leaves the job as a workflow artifact
   (`ctiparsor-image`, kept one day) once every step has passed.
2. Job `publish-image` builds nothing. It loads the archive, checks that it is
   the image `container-image` tested, and pushes it as `sha-<commit>` with
   `docker push`, which sends the index, its attestation manifest and every
   blob unchanged. It fails unless GHCR then serves the digest
   `container-image` reported. The SBOM and the two attestations are bound to
   that digest.
3. Last, `publish-image` names that digest `latest`, only if the commit is
   still main's head (`gh api repos/…/commits/main`). A run that finishes after
   a newer push, or a re-run of an old one, leaves `latest` where it is, with a
   notice; its `sha-<commit>` image is published and attested all the same.

If `publish-image` fails after its push, `sha-<commit>` may already be on
GHCR, without attestations: `release.yml` refuses such an image, and `latest`
has not moved.

To check a commit of `main` by hand (read-only), compare three digests: the
one `container-image` tested, the one `publish-image` read back, and the one
GHCR serves for `sha-<commit>`. They must be the same.

```bash
sha=<full commit of main>
run=$(gh run list -R Stixaly/CTIParsor -w ci.yml -b main -e push -c "$sha" \
  --json databaseId -q '.[0].databaseId')
job() {
  gh run view "$run" -R Stixaly/CTIParsor --json jobs \
    -q ".jobs[] | select(.name == \"$1\") | .databaseId"
}
gh run view -R Stixaly/CTIParsor --job "$(job 'Container image (build + smoke)')" --log \
  | grep -oE "image index: sha256:[0-9a-f]{64}"
gh run view -R Stixaly/CTIParsor --job "$(job 'Publish image to GHCR')" --log \
  | grep -oE '(sha-[0-9a-f]{40}|latest) -> sha256:[0-9a-f]{64}'
docker buildx imagetools inspect "ghcr.io/stixaly/ctiparsor:sha-$sha" \
  --format '{{json .Manifest}}' | python3 -c 'import json, sys; print(json.load(sys.stdin)["digest"])'
```

`latest` names the same digest, unless the log of `publish-image` shows the
notice that main had moved on, until the next push to `main` moves it. The
image then passes `gh attestation verify` as in
[Verifying a release](#verifying-a-release), with `--source-digest "$sha"`.

## Versioning

[Semantic Versioning](https://semver.org/), from 0.1.0. Before 1.0:

- **The minor version goes up** for new behaviour, or for anything an operator
  must act on: the API, the bundle output, the configuration, a database
  migration.
- **The patch version is for fixes only.**

A tag is `vX.Y.Z`. The files carry `X.Y.Z`, without the `v`. There are no
pre-releases: `scripts/release.py check` refuses a tag such as `v0.1.0-rc.1`.
The dry run (below) is the rehearsal.

What changes from 1.0 is in [support-policy.md](support-policy.md) (ADR-0094,
proposed): the stable surfaces, what counts as a breaking change and needs a
major version, how a deprecation is announced, and which version line gets
fixes.

## Where the version lives

One source, `__version__` in `pipeline/__init__.py`. It was `"0.0.0"` until the
first release, 0.1.0.

| Place | What it holds |
|---|---|
| `pipeline/__init__.py` | `__version__ = "X.Y.Z"`, the source. FastAPI's `version` (in the OpenAPI schema) reads it. |
| `frontend/package.json` | `version`, the same number. |
| `frontend/package-lock.json` | `version` and `packages[""].version`, the same number. |
| `CHANGELOG.md` | The section `## [X.Y.Z] - YYYY-MM-DD`, which is the Release's notes. |
| The git tag | `vX.Y.Z`. |
| The image | `ghcr.io/stixaly/ctiparsor:X.Y.Z` and `:X.Y`. |

`tests/test_release.py` fails if the first three disagree, or if the first `##`
heading of the CHANGELOG is not `## [Unreleased]`.

Between two releases `main` carries the last release's number. Builds are told
apart by `git_rev`, which every bundle records and the image stamps
(`CTIPARSOR_GIT_REV`).

## Cutting a release

`scripts/release.py` uses the Python standard library only (Python 3.12 or
newer, nothing to install). Its exit code is `0` when done, `1` when it refuses
(the reasons are on stderr and nothing was written), `2` for a usage error.

| Command | What it does |
|---|---|
| `release.py version [--next major\|minor\|patch]` | Prints the current version, or the one after that bump. |
| `release.py check vX.Y.Z` | Compares the tag with `__version__`, `frontend/package.json` and `frontend/package-lock.json`, and looks for a non-empty `## [X.Y.Z] - YYYY-MM-DD` section in the CHANGELOG. Reports every mismatch. Prints `X.Y.Z` when all agree. |
| `release.py notes X.Y.Z [--image REF] [--repo OWNER/NAME] [--max-chars N]` | Prints the Release notes: the CHANGELOG section, then "Container image" and "Files" paragraphs when `--image` is given. `--repo` is the repository the links and commands name (default `Stixaly/CTIParsor`). `--max-chars` is the length past which the section is listed by entry (default 100 000). |
| `release.py unreleased` | Prints what `[Unreleased]` holds, which is what the next release would ship; nothing when it is empty. Exit code `1` if the CHANGELOG has no `[Unreleased]` section. |
| `release.py prepare X.Y.Z [--date YYYY-MM-DD]` | Inserts `## [X.Y.Z] - date` under an emptied `## [Unreleased]`, and sets the version in the three places. Refuses a version not above the current one, an empty `[Unreleased]`, or a section that already exists. The date defaults to today. |
| `release.py predicate FILE --type URI` | Extracts one predicate from `gh attestation verify --format json` output. The workflow uses it for the SBOM. |

**Steps**, for 0.1.0:

1. **Branch off `main`.** Be sure `[Unreleased]` holds what the release ships:
   `release.py unreleased` prints it, and `prepare` refuses an empty one.

   ```bash
   git fetch origin
   git switch -c release-0.1.0 origin/main
   python3 scripts/release.py unreleased | head
   ```

2. **Prepare it.**

   ```bash
   python3 scripts/release.py prepare 0.1.0
   ```

   It prints the four files it wrote: `CHANGELOG.md`, `pipeline/__init__.py`,
   `frontend/package.json` and `frontend/package-lock.json`.

3. **Review.** Read the diff and the new CHANGELOG section. You may add a short
   summary paragraph at the top of the section. Then check the tree, and read
   the notes as the Release will show them:

   ```bash
   git diff
   python3 scripts/release.py check v0.1.0     # prints 0.1.0
   python3 scripts/release.py notes 0.1.0
   ```

   GitHub refuses a release body above 125 000 characters. When the section is
   longer than 100 000 characters, `notes` keeps the paragraph that opens the
   section, then lists the section's `####` entry titles under their `###`
   groups, each group once, with a link to CHANGELOG.md at the tag. Older
   entries that are plain bullets, with no `####` title, are only in the
   CHANGELOG. A short summary paragraph at the top of the section is therefore
   worth writing, as 0.1.0's section has.

4. **Open the pull request "Release 0.1.0"** and merge it once the required
   checks pass.

   ```bash
   git add CHANGELOG.md pipeline/__init__.py frontend/package.json frontend/package-lock.json
   git commit -m "Release 0.1.0"
   git push -u origin release-0.1.0
   gh pr create --title "Release 0.1.0" --body "Moves [Unreleased] under 0.1.0 and sets the version (ADR-0085)."
   ```

   From 1.0, before the tag: once main's CI has published the image of the
   merge commit, run the OpenCTI import of the candidate on it (ADR-0094
   item 8, TESTING.md, *OpenCTI import (A4)*), and post its report on the
   release pull request. It must exit 0 (a WARN does not fail it; read it). It
   takes about two minutes, refuses to start OpenCTI with less than 8 GB of
   memory available, uses about 6 GB at its peak, and needs the pycti venv
   TESTING.md creates once.

   ```bash
   bash scripts/check_opencti_candidate.sh --image ghcr.io/stixaly/ctiparsor:sha-<merge commit>
   gh pr comment <release pull request> --body-file output/opencti-candidate/<UTC time>/report.md
   ```

   The Release cannot carry the report: the workflow uploads its own files,
   and an immutable Release takes no file once published. The row "Import into
   OpenCTI" of [support-policy.md](support-policy.md) names the date and the
   digest of the last run: update them in the next pull request.

   Then the clean install on the same image (ADR-0094 item 9, TESTING.md,
   *Clean install from the published image*): the last release installed as
   the README writes it, then upgraded to the candidate as docs/upgrading.md
   writes it, with a report, a restart and a restore. It must exit 0; post its
   report on the release pull request too. It downloads the models and the
   corpora (3.3 GB), takes about 20 minutes, and refuses to start with less
   than 6 GB of memory available or 20 GB free for Docker.

   ```bash
   bash scripts/check_clean_install.sh --candidate ghcr.io/stixaly/ctiparsor:sha-<merge commit>
   gh pr comment <release pull request> --body-file output/clean-install/<UTC time>/report.md
   ```

   The row "Install with Docker Compose" of
   [support-policy.md](support-policy.md) names the date and the digests of
   the last run: update them in the next pull request.

5. **Tag the merge commit.** Check that `origin/main` is the release merge
   before tagging.

   ```bash
   git fetch origin
   git log -1 origin/main
   git tag -a v0.1.0 -m "CTIParsor 0.1.0" origin/main
   git push origin v0.1.0
   ```

   If another pull request merged after the release, tag the release's merge
   commit by its hash instead of `origin/main`. The workflow accepts any commit
   of `main`, as long as its CI ran and passed.

6. **Watch the Release workflow.**

   ```bash
   gh run list --workflow release.yml --limit 1
   gh run watch <run-id>
   ```

   The `publish` job does this, in order (the "job steps" below):

   1. Runs `release.py check` on the tag, then checks that the tagged commit is
      on `main`. It comes first, so that a wrong version file fails before the
      wait.
   2. Checks that no Release exists for the tag, draft or published. If one
      does, it fails and says how to fix it (see *When the workflow fails*).
   3. Waits for main's CI (`ci.yml`, push event) on that commit, up to an
      hour, and requires it to have passed. It retries after a transient API
      error. If five checks, a minute apart, find no CI run, it fails: the wrong
      commit was tagged. That CI migrates a database written by the last
      release (fast-tests, `scripts/check_migration_from.py`): a commit whose
      migrations lose or change what the last release stored is not released.
      When that step fails, its log names each table, row and column. Fix the
      migration in a pull request, or declare a deliberate rewrite in
      `EXPECTED_CHANGES` (in the script), then tag the commit that passes (see
      *When the workflow fails*).
   4. Sets up buildx and logs in to GHCR. This comes before the files: reading
      the image anonymously works only while the package is public.
   5. Runs `scripts/release_files.sh`. It checks the tag again, finds the image
      `sha-<commit>`, verifies its provenance and SBOM attestations, and writes
      the files and the notes.
   6. Gives the image its version names, from its digest. `X.Y.Z` is refused if
      it already names another digest: a version never moves to another image.
      `X.Y` is moved only if the tag is the highest `vX.Y.*`. Then it checks that
      each name resolves to the digest.
   7. Signs an SLSA provenance of the files with `actions/attest`.
   8. Creates the Release as a draft, uploads the files, then publishes it.
      "Latest" is set only if the tag is the highest tag of strict SemVer form
      (`vX.Y.Z`): a stray `v0.1.0-rc.1` or `vfoo` does not count.

7. **After every release,** in the next pull request: the first line of the
   README's `INSTALL_FILES` block names the new release and its digest, and
   the first line of `UPGRADE_COMMANDS` in docs/upgrading.md moves from the
   previous release to it; docs/docker.md's paragraph on the latest release
   gives the same digest. `tests/test_check_clean_install.py` holds the three
   together, and the next clean install starts from that release.

8. **After the first release,** the statements that said none had been
   published had to change. For 0.1.0 that was done on 2026-10-24:

   - `SECURITY.md`: the "Releases" bullet of *Supply chain*, and *Supported
     versions*;
   - `docs/docker.md`: the paragraph on `X.Y.Z` names (*Pulling a pre-built
     image*);
   - `docs/releasing.md`: *What a release is*, and the dated paragraph of
     *One-time repository settings*;
   - `docs/openssf-best-practices.md`: the paragraph under *What still stands
     between…* and the four rows `version_unique`, `version_semver`,
     `version_tags`, `release_notes`;
   - ADR-0085: the status line, the action items and an amendment.

   Entering the answers on bestpractices.dev is left to the maintainer
   (ADR-0085, action item 6).

## What the Release contains

| File | What it is |
|---|---|
| `ctiparsor-X.Y.Z.tar.gz` | `git archive` of the tagged commit, with the prefix `ctiparsor-X.Y.Z/`. |
| `ctiparsor-X.Y.Z-image.cdx.json` | The image's CycloneDX SBOM, as attested when main's CI built the image. It is taken from the verified attestation, not regenerated. |
| `SHA256SUMS` | The sha256 of the two files above. |
| `ctiparsor-X.Y.Z.intoto.jsonl` | The Sigstore bundle of the SLSA provenance of the two files in `SHA256SUMS`, signed by the release workflow run. |

The notes are the CHANGELOG section (or the list of its entries, see step 3),
followed by a "Container image" paragraph that names the image by digest and a
"Files" paragraph; both give the verify commands of the next section.

There is no sdist, no wheel and no PyPI package: Docker is the only supported
way to run CTIParsor (ADR-0054). The web UI is built into the image
([deployment.md](deployment.md)), so it has no file of its own.

## Verifying a release

```bash
# The image. The digest is in the Release notes.
gh attestation verify oci://ghcr.io/stixaly/ctiparsor@sha256:<digest> -R Stixaly/CTIParsor \
  --signer-workflow Stixaly/CTIParsor/.github/workflows/ci.yml --source-ref refs/heads/main

# The files, from the Release page.
sha256sum -c SHA256SUMS
gh attestation verify ctiparsor-X.Y.Z.tar.gz -R Stixaly/CTIParsor \
  --signer-workflow Stixaly/CTIParsor/.github/workflows/release.yml --source-ref refs/tags/vX.Y.Z
```

The first command checks the build provenance that `ci.yml` signed on `main` for
the image. The last one checks the provenance that the release workflow signed
for the archive.

`--signer-workflow` and `--source-ref` are not optional extras. Without
`--signer-workflow`, an attestation signed by any workflow of the repository
would pass.

## When the workflow fails

What is public depends on how far the run got (the job steps are listed in
step 6 of *Cutting a release*):

- Before job step 6, nothing.
- From job step 6, the image's new names `X.Y.Z` (and `X.Y`).
- From job step 7, the provenance of the files, in GitHub's attestation store
  and in Sigstore's public transparency log.
- In job step 8, a draft Release. Only people with write access see it, until
  the last command publishes it.

Pick the case that fits:

- **A Release already exists for the tag** (job step 2 fails, and says so).
  - A draft left by a failed run: delete it by hand, which keeps the tag, then
    re-run the failed run.

    ```bash
    gh release delete vX.Y.Z --yes
    ```

    Nothing deletes a draft automatically. Deleting the tag of a published
    Release turns that Release back into a draft on GitHub, and an automatic
    delete would have removed it.
  - A published Release: never reuse its version, even if you can delete the
    tag. Release the next patch version.
- **The cause is in the tree or in the tag** (a wrong version in a file, no
  CHANGELOG section, a commit that is not on `main`, a commit main's CI did not
  run on or did not pass): fix the tree through a pull request if it needs one,
  delete the tag, and tag the right commit.

  ```bash
  git push --delete origin vX.Y.Z
  git tag -d vX.Y.Z
  ```

  Once the tag ruleset exists, deleting a tag needs the admin bypass (below).
  If the run had reached job step 6, `X.Y.Z` already names that commit's image,
  and job step 6 refuses a different commit under the same version: release the
  next patch version instead.
- **The cause is not in the repository** (a runner or registry outage):
  re-run the failed run from the Actions tab. It repeats every step on the same
  commit. If the failed run had got as far as creating the draft, job step 2
  fails until you delete the draft as above.

## The dry run

The job `dry-run` of `release.yml` (named "Release dry run (notes and files,
nothing published)") runs:

- on a pull request that changes `.github/workflows/release.yml`,
  `scripts/release.py` or `scripts/release_files.sh`;
- **every Monday** (`schedule`). That catches what the paths filter cannot see:
  a change to `ci.yml`, to `gh`, or to the registry.

It:

1. has a read-only token (`contents: read`, `actions: read` and
   `attestations: read`);
2. prepares the next minor version on the runner only (`release.py version
   --next minor`, then `prepare`). When `[Unreleased]` is empty, as it is right
   after a release or on a Dependabot bump of `release.yml`, it first adds a
   placeholder line on the runner, because `prepare` refuses an empty section;
3. finds main's last commit whose CI passed, and runs
   `scripts/release_files.sh` against it, which verifies that commit's image and
   attestations;
4. checks `SHA256SUMS` with `sha256sum -c`;
5. puts the notes in the job summary.

It publishes, tags and attests nothing. It cannot rehearse the version names on
the image, the provenance of the files or the Release itself; only a tag run
does. The tag runs for 0.1.0 and 0.2.0 each ran once and passed.

## What the workflow's checks are worth

A tag run uses `release.yml` and `scripts/release_files.sh` as they are on the
tagged commit. Someone who can push a tag can edit both on a branch, tag that
commit, and skip every check: the commit on `main`, the CI that passed, the
attestation verification.

So the checks catch mistakes. Only the tag ruleset (below) stops a person. The
header of `release.yml` says the same.

## One-time repository settings

Two settings are recommended and not required: the release workflow runs
without them. The repository's Actions settings already allow it, since a job
may ask for `contents: write`, `packages: write`, `id-token: write` and
`attestations: write`.

On 2026-10-17, read through the API, neither was set. On 2026-10-24, read again
on 2026-10-30:

- **Immutable releases are on** (`"enabled": true`). They were turned on after
  0.1.0 was published, so that Release is not immutable: `gh release view
  v0.1.0 --json isImmutable` gives `false`, and `gh release verify v0.1.0`
  finds no release attestation. 0.2.0, the first Release published after,
  is immutable, and `gh release verify v0.2.0` passes.
- **No ruleset covers tags.** The only ruleset, "basic rules", targets the
  branch.

Settings are the maintainer's clicks. Read each one back afterwards and record
the result (ADR-0085, action items 2 and 3).

**1. A tag ruleset.** Without it, anyone with write access can create, move or
delete a `v*` tag.

1. Settings → Rules → Rulesets → New ruleset → New tag ruleset.
2. Name: `release tags`. Enforcement status: **Active**.
3. Bypass list → Add bypass → **Repository admin**, "Always allow".
4. Target tags → Add target → Include by pattern → `v*`.
5. Rules: **Restrict creations**, **Restrict updates**, **Restrict
   deletions**, **Block force pushes**.
6. Create.

Effect: only the repository admin can create, move or delete a `v*` tag,
through the bypass. Read back with:

```bash
gh api repos/Stixaly/CTIParsor/rulesets
```

**2. Immutable releases.** Settings → General → section "Releases" → **Enable
release immutability**.

Effect: once a Release is published, its files cannot be changed and its tag
cannot be moved or deleted, and GitHub adds a release attestation. The workflow
already publishes draft, then files, then public, which immutability requires.
Read back with:

```bash
gh api repos/Stixaly/CTIParsor/immutable-releases
```
