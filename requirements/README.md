# Python requirements

Four lists you edit, five locks `make lock` writes (ADR-0080). Every install
uses a lock, by hash: `pip install --require-hashes`.

| File | What it is | Installed by |
|---|---|---|
| `requirements.txt` | The light runtime: the pipeline without its ML models, and the API | CI, with the dev tools |
| `requirements-full.txt` | `-r requirements.txt`, then ML models, OCR, `openai`, spaCy, Playwright | the image |
| `requirements-dev.txt` | Test, lint, type-check and fuzzing tools, pinned; `httpx` | CI and the `dev` image |
| `requirements-audit.txt` | pip-audit, pinned | the dependency-audit job, `make audit` |
| `requirements.lock.txt` | `requirements-full.txt`, resolved, every file's sha256 from PyPI | the image |
| `requirements-torch.lock.txt` | torch's CPU build, from the PyTorch index | the image, first |
| `requirements-ci.lock.txt` | `requirements.txt` + `requirements-dev.txt`, at the image's versions | CI, the `dev` image |
| `requirements-audit.lock.txt` | pip-audit and its dependencies | the dependency-audit job |
| `requirements-uv.lock.txt` | the uv that `make lock` runs | `make lock` |
| `osv-scanner.toml` | The vulnerabilities SECURITY.md accepts, for Scorecard's scan of these files | OSV-Scanner |

**Adding a package:** to `requirements.txt` when the fast tests need it, to
`requirements-full.txt` when only the image does, as a range; a test or lint
tool goes to `requirements-dev.txt`, pinned. Then `make lock`, and commit
every lock it rewrote.

**A floor is read as a version.** Scorecard's scanner may take
`package>=X` for an install of X. Keep each floor at or above the release
that fixes the package's last known vulnerability;
`python3 scripts/check_requirement_floors.py` checks every floor against OSV.

**The names keep "requirements".** OSV-Scanner reads a `.txt` file only when
its name contains `requirements`, and it reads the `osv-scanner.toml` next to
a file, not a parent's: a file renamed `dev.txt`, or moved away from
`osv-scanner.toml`, would leave Scorecard's scan without a word.

[docs/dependencies.md](../docs/dependencies.md) has what each package is for
and the maintenance routine.
