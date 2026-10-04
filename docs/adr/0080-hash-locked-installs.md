# ADR-0080: Every pip install checks hashes, and the PyTorch index serves torch alone

**Status:** Accepted
**Date:** 2026-10-04
**Deciders:** maintainer
**Amends:** ADR-0075 (supply chain: "hashes in the lock are not done yet")

## Context

`requirements.lock.txt` pinned versions, not files. pip installed whatever
file the index served for that version, and the lock named two indexes:
PyPI, and the PyTorch CPU index for torch's `+cpu` build. ADR-0075 left
hashes for later, for a reason recorded in `docs/dependencies.md`: the
PyTorch index re-hosts common packages under PyPI's file names, so pip may
take the mirror's file.

OpenSSF Scorecard (ADR-0078) scored Pinned-Dependencies 6/10: 0 of 9 `pip
install` commands pinned by hash, in the Dockerfile and in CI. Two of the CI
installs named packages on the command line, and one installed `pip-audit`
unpinned.

The first hashed build confirmed the risk. **pip downloaded markupsafe 3.0.3
from the PyTorch index**, whose file differs from PyPI's (another sha256).
The image had been shipping whichever copy pip found.

## Decision

1. **Four hashed locks, from one script** (`make lock` → `scripts/lock.sh`):

   | Lock | Contents | Source |
   |---|---|---|
   | `requirements.lock.txt` | the image | PyPI only; names no index |
   | `requirements-torch.lock.txt` | torch's `+cpu` build alone | PyTorch index |
   | `requirements-ci.lock.txt` | `requirements-ci.txt` (the API, the light pipeline dependencies, the dev tools), resolved under the image's versions | PyPI |
   | `requirements-audit.lock.txt` | pip-audit | PyPI |

2. **The two indexes are never mixed at install time.** torch is installed
   first, alone, `--no-deps --index-url <PyTorch>`; then the image lock from
   PyPI, where torch is already satisfied. This applies to the image and to
   the model-tests job.
3. **PyPI pins carry PyPI's hashes.** The resolution still needs both indexes
   to pick the `+cpu` build. With them, uv recorded the PyTorch copies'
   hashes for markupsafe, colorama and jinja2, and none of PyPI's Linux wheel
   for markupsafe. `scripts/lock_pypi_hashes.py` rewrites every PyPI pin with
   the sha256 PyPI publishes for that release; torch keeps its own.
4. **Everywhere: `pip install --require-hashes -r <lock>`.** That covers the
   image builder, the `dev` image, the fast tests, the model tests and the
   audit. CI's three installs become one. The image no longer upgrades pip
   first: the pip Python 3.14.8 bundles (26.2.1) is current, and the upgrade
   was the one download without a hash.
5. The audit job also audits CI's tools and the scanner itself: the three
   locks.

## Consequences

- **Easier:** a tampered, re-uploaded or mirrored file fails the build
  instead of shipping. The PyTorch index can no longer supply anything but
  torch. Scorecard's pipCommand count goes from 0/9 to all.
- **Harder:**
  - `make lock` takes a few seconds more, because it queries PyPI's JSON API
    for every pin;
  - a dependency added to a test now goes in `requirements-ci.txt`, then
    `make lock`;
  - the locks are long, about 3,400 lines for the image's.
- **Verified (2026-10-04):**
  - every PyPI pin's hashes cover PyPI's files for the image: 159/159, CI
    110/110, audit 28/28, and no foreign hash;
  - the image builds: torch from the PyTorch index, everything else from
    PyPI, and nothing else from the PyTorch index;
  - `pip check` is clean;
  - a clean container installs the CI lock by hash, builds yara-python and
    `cpe` from source under hash mode, and runs the suite.
