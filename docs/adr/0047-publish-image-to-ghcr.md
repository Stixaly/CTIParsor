# ADR-0047 — Publish the image to GHCR; tag by commit and `latest`

**Status:** Accepted (implemented 2026-09-16)
**Date:** 2026-09-16
**Amended by:** [0085](0085-releases-promote-the-image-main-built.md) (2026-10-17). The
two `type=semver` lines of the tag list below are gone from `ci.yml`: that
workflow never runs on a tag, so they never applied. The version names
`X.Y.Z` and `X.Y` come from `release.yml`, which gives the image main published
for the tagged commit those names, with the same digest.
**Amended by:** the change of 2026-11-01 ([below](#amendment-2026-11-01--publish-image-pushes-the-build-container-image-tested)).
`publish-image` builds nothing: it pushes, byte for byte, the OCI archive
`container-image` built, scanned and smoke-tested, and fails unless GHCR holds
the digest `container-image` reported. The option rejected below, "reuse the
`container-image` job's own build", is now the decision.
**Relates to:** [0044](0044-container-images.md) (the image this publishes), [0040](0040-offline-installation-bundle.md)
(a separate, unrelated build path — see its 2026-09-16 status review)

## Context

ADR-0044's CI job builds the image and smoke-tests it with `push: false`.
Nothing after that: no registry, no tag beyond the dev-local `ctiparsor:local`
`compose.yaml` defaults to. A second machine's only path to the image is
`git clone && docker compose build` — every host repeats the ~3.5-minute
build and the ~450 MB of layer downloads (`python:3.12-slim-bookworm`,
`node:24-bookworm-slim`, apt packages, Playwright's Chromium) that a shared
image would only pay once.

## Decision

**GHCR (`ghcr.io`), not Docker Hub.** The repository already lives on
GitHub; GHCR authenticates with the workflow's own `GITHUB_TOKEN` — no new
account, no new secret to store or rotate, the same trust boundary as the
code. This is the same reasoning this project has used to reject every other
optional piece of infrastructure (Redis, an ORM, a broker): don't add a
dependency a simpler option already covers.

**A second job, gated on the smoke test, only on `main`.**

```yaml
container-image:            # unchanged: builds, smoke-tests, push: false
  ...
publish-image:
  needs: container-image
  if: github.event_name == 'push' && github.ref == 'refs/heads/main'
  permissions:
    contents: read
    packages: write          # scoped to this job only, not the workflow
  steps:
    - checkout, setup-buildx
    - login to ghcr.io with the workflow's own GITHUB_TOKEN
    - docker/metadata-action → tags: sha-<full sha>, latest, and (semver(+minor+major)
      when triggered by a v*.*.* tag — inert today, ready if versioning starts)
    - docker/build-push-action, push: true, cache: type=gha (reuses the
      smoke-test job's build cache, so this is not a second full build)
```

Runs only after `container-image` passes, so nothing broken is ever
published, and only on a push to `main` — a pull request, including from a
fork, never gets `packages: write` (a fork's workflow run does not receive
repository secrets or elevated `GITHUB_TOKEN` permissions regardless; the
`if` is defense in depth, not the only control).

**Tags:** the immutable `sha-<full sha>` for pinning (mirrors the
`CTIPARSOR_GIT_REV` provenance the image already stamps into every bundle it
produces) and `latest` for "give me current main". No `v*` tags are cut by
this project today; the metadata action's semver extraction is included so
adopting them later needs no workflow change.

**One manual step this cannot automate:** a GHCR package is private by
default regardless of the repository's own visibility, and there is no safe,
narrowly-scoped API call from inside the workflow to flip that — it needs a
human in the package's own GitHub settings, once, after the first push.
Documented as a one-time step in `docs/docker.md`, not hidden.

**Out of scope:** multi-arch (`linux/arm64`) builds — the image is built and
smoke-tested on `amd64` only today; publishing a manifest for an
architecture nothing here has run would be a claim this project cannot back.
A frontend or dashboard surface for any of this is likewise out of scope —
this ADR is the delivery pipeline, not a UI.

## Options considered

- **Docker Hub** — rejected: a second account and a second secret
  (`DOCKERHUB_TOKEN`) for no capability GHCR lacks, given the repo is
  already on GitHub.
- **Publish on every PR, not just `main`** — rejected: a PR build is
  unreviewed by definition; publishing it would let anyone opening a PR grow
  the registry (and, if a public package, publish content of their choosing)
  before a maintainer looks at it.
- **Reuse the `container-image` job's own build for the push** (skip the
  second job) — rejected: it would need `packages: write` on a job that also
  builds and smoke-tests untrusted PR code, widening the permission's blast
  radius for no real saving — `cache-from: type=gha` already makes the
  second build cheap.
- **Tag only `latest`** — rejected: an operator who pulled `latest` last
  week and pulls it again today gets a different image under the same name,
  silently. `sha-<sha>` is what `docker compose pull` with `CTI_IMAGE` pinned
  actually reproduces.

## Consequences

- `docs/docker.md` gains a "pull instead of build" path:
  `CTI_IMAGE=ghcr.io/stixaly/ctiparsor:latest` (or a `sha-` tag) in `.env`,
  then `docker compose pull app worker bootstrap && docker compose up -d`.
  Compose only builds a service when its `image:` tag is not already present
  locally, so a prior `pull` is what makes `up` skip the build — verified
  against this repo's own `compose.yaml`, not assumed.
- What becomes harder: two things can now drift — the image `docker compose
  build` produces locally and the one GHCR serves — if a host pulls without
  also pulling a matching `.env`/`compose.yaml`. The `sha-` tag exists
  precisely so a host can pin to what it tested.
- Not done here: multi-arch builds, image signing (cosign), a formal
  version/release process — each is a further decision, not implied by this
  one.

## Validation record (2026-09-16)

`.github/workflows/ci.yml` parses as valid YAML with the new job present:
`needs: container-image`, `if: github.event_name == 'push' && github.ref ==
'refs/heads/main'`, `permissions: {contents: read, packages: write}` scoped
to this job alone. The push step itself only runs on GitHub's own runners
against `main` and cannot be executed from this workstation — verified
everything reachable locally instead:

- **`docker compose pull` on a service that also declares `build:`** works
  as documented — attempted against a real (nonexistent) GHCR tag, it
  printed `denied` and a hint to run `docker compose build`, not an error
  about the conflicting keys.
- **The pull-then-up mechanic** — the actual claim this ADR rests on: built
  the image locally, retagged it under a GHCR-shaped name, pointed
  `CTI_IMAGE` at that tag, and ran `docker compose up -d app`. Total wall
  time 6.4 s including the PostgreSQL healthcheck wait; the log shows
  containers going straight from `Created` to `Starting`, no `Building`
  step at any point — confirming `up` only builds when the tag is absent
  locally, as documented.

## Amendment (2026-11-01) — publish-image pushes the build container-image tested

**What was wrong.** `publish-image` built the image a second time, with a
cache `container-image` never wrote. That second build was the one pushed,
attested (ADR-0075) and promoted by a release (ADR-0085); the scan and the
smoke test had run the first.

**Decision.** One build per commit, in `container-image`, into an OCI archive:
an image index holding the linux/amd64 image and BuildKit's SLSA v1
provenance, stated in the workflow, with the labels `publish-image` gave.
`docker load` takes the archive into the containerd image store whole, and
the step fails unless the loaded image's ID is the archive's index digest.
The scan, the smoke test and the air-gap check run that image. On a push to
`main` the archive goes to `publish-image` as a workflow artifact. That job
builds nothing: it loads the archive, pushes it as `sha-<full sha>` with
`docker push`, which sends the index, its attestation manifest and every blob
unchanged, and fails unless GHCR returns the digest `container-image`
reported. After the SBOM and the two attestations, it names that digest
`latest`, only if the commit is still main's head.

**Consequences.**

- Both jobs run on `ubuntu-26.04`, whose Docker 29 uses the containerd image
  store, and fail if the store is another one: the classic store of Docker 28
  cannot load an OCI archive. No third-party container runs in either job.
- `latest` no longer moves back when an older run, or a re-run, publishes
  after a newer commit; that commit's `sha-` image is still pushed and attested.
- The option rejected above, "reuse the `container-image` job's own build", is
  now the decision, without its drawback: the archive is handed over as an
  artifact, so `container-image` keeps no `packages: write`.
- `release.yml` is unchanged. It still finds `sha-<commit>`, verifies the
  attestations and names that digest.
- Until the first push to `main` after the merge, GHCR's answer to the push
  and the artifact's round trip are unproven; `docs/releasing.md` ("The image
  main's CI publishes") gives the commands that compare the digests.
