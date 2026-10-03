# ADR-0075: A verifiable supply chain — pinned inputs, a blocking audit, CodeQL, an attested image

**Status:** Accepted (in part — see "Not done yet")
**Date:** 2026-10-03
**Deciders:** maintainer
**Amends:** ADR-0047 (the GHCR image), ADR-0071 (CI blocks on every deterministic check)

## Context

The October 2026 audits found the project hard to adopt for a CERT or a CSIRT
that has to answer for what it runs (synthesis § 10.5, implementation report
B12.c):

- the Dockerfile's base images were tags (`python:3.12-slim-bookworm`,
  `node:24-bookworm-slim`); compose's were pinned by digest in lot 0 (D11);
- `make audit` scanned the **ranges** of `requirements*.txt`, not the versions
  the image installs, and never failed (`npm audit … || true`); CI did not run
  it at all;
- no static security analysis, no SBOM, nothing a consumer could check about
  where an image came from;
- nothing updated pinned versions or digests, so pinning meant freezing.

Since 11 September 2026 an integrator that ships CTIParsor inside a product is
a manufacturer under the Cyber Resilience Act and needs an SBOM and a way to
track vulnerabilities; the project itself has no such obligation while no
entity carries it (B12.e covers that statement).

Measured on 2026-10-03: `pip-audit` on `requirements.lock.txt` finds one
known vulnerability, diskcache 5.6.3 (PYSEC-2026-2447: pickle deserialisation
from a cache directory an attacker can write), with no fixed release; torch's
`+cpu` build is not on PyPI and cannot be looked up. `npm audit --omit=dev`
finds none in the UI's production packages.

## Decision

1. **Base images by digest.** The Dockerfile's `FROM` lines carry the same
   digests as compose.yaml (node) or the tag's current index digest (python).
2. **Dependabot** proposes updates for GitHub Actions, the Dockerfile and
   compose images, and the UI's npm packages. **Not for Python**: the lock is
   `uv pip compile` output, which Dependabot neither regenerates (its uv
   support reads `uv.lock`) nor treats as pip-compile output; it would bump
   one pin and leave the rest of the resolution stale. `make update-deps`
   re-resolves; the audit below says when to.
3. **A blocking `dependency-audit` CI job**: `pip-audit` on the lock as
   written (`--no-deps --disable-pip`, nothing installed) and `npm audit
   --omit=dev --audit-level=high`. `publish-image` needs it. `make audit` runs
   the same two commands locally.
4. **Accepted vulnerabilities are listed in SECURITY.md** with the reason and
   a review date, and ignored by id in CI and `make audit`, nowhere else.
   diskcache is the first: CTIParsor never imports `sigma.data.mitre_attack`,
   the only pySigma module that uses it, and the Sigma gate parses a rule with
   ATT&CK tags without loading diskcache (checked); exploitation also needs
   write access to `~/.cache/pysigma` in the container.
5. **CodeQL** (`security-extended`, Python and TypeScript) on every push, pull
   request and weekly. Findings go to the Security tab; the job fails only if
   the analysis cannot run.
6. **The published image is verifiable.** After the push, `publish-image`
   generates a CycloneDX SBOM of the image by digest (syft through
   `anchore/sbom-action`) and two Sigstore-signed attestations bound to that
   digest with `actions/attest`: SLSA build provenance and the SBOM, both
   pushed to GHCR. `gh attestation verify oci://ghcr.io/stixaly/ctiparsor@<digest>
   -R Stixaly/CTIParsor` checks them. Attestations are free on a public
   repository; no artifact storage record, which exists for
   organisation-owned repositories only.

## Options rejected

- **Dependabot on `requirements.lock.txt` anyway.** A pin bumped outside the
  resolver can conflict with another package's range and is only caught when
  the image build fails; the lock's guarantee is that it was resolved whole.
- **Moving to `uv.lock` / a `[project]` table now.** The right direction
  (B12.d gives `pyproject.toml` a `[project]`), but it changes how the image
  and CI install; it goes with the packaging work, not this one.
- **Failing CI on CodeQL findings.** The first scan of a 46 000-line Python
  tree will report findings that need triage; blocking would push towards
  dismissing them in bulk.
- **cosign-signed images instead of GitHub attestations.** Same Sigstore
  machinery; `actions/attest` needs no key management and `gh` verifies it.

## Not done yet

- **Hashes in the lock** (`uv pip compile --generate-hashes`) and
  `pip install --require-hashes` in the image, with the PyTorch index limited
  to torch (`--index-strategy unsafe-best-match` today lets any package
  resolve from it). Needs a full image build to verify; scheduled after the
  2026-10-03 evaluation runs, which share the machine.
- ruff's full `S` (bandit) set and `BLE001` (blind except, ~215 sites);
  S110/S112 are enforced since lot 0's D10 extension.

## Consequences

- An image is published only if the lock has no known, unaccepted
  vulnerability; accepting one is a SECURITY.md edit in review, with a reason.
- Each published image can be traced to the workflow run and commit that
  built it, and its components listed, without trusting the registry.
- Weekly Dependabot PRs for actions, images and npm; Python stays on
  `make update-deps`.
