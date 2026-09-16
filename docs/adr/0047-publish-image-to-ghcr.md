# ADR-0047 — Publish the image to GHCR; tag by commit and `latest`

**Status:** Accepted (implemented 2026-09-16)
**Date:** 2026-09-16
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
