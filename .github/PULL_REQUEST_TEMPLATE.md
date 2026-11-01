## What and why

<!-- What this changes, and the problem it solves. -->

Closes #

<!-- The issue it answers. CONTRIBUTING.md asks for one first for anything larger than a fix. -->

## Checks run

Which checks, and when: [CONTRIBUTING.md](https://github.com/Stixaly/CTIParsor/blob/main/CONTRIBUTING.md#tests-lint-types--the-green-build-checklist).
The test strategy: [TESTING.md](https://github.com/Stixaly/CTIParsor/blob/main/TESTING.md).
Delete a line that does not apply to this change.

- [ ] `make ci`
- [ ] New behaviour comes with a test that fails without it
- [ ] The checks `make ci` does not run, for what I touched (CONTRIBUTING.md lists them; `make docker-smoke` for the Dockerfile, `compose.yaml` and `docker/`)

## Records

- [ ] A CHANGELOG entry under `## [Unreleased]`; the version left alone
- [ ] The documentation the change touches; a new ADR in `docs/adr/`, and its index, when a decision changes
- [ ] A stable surface changed (API schema, `main.py` arguments, container commands, `.env.example`, Compose layout, STIX custom properties or ids): `make contract` run and `contract/` committed. A breaking change needs `make contract ACCEPT_BREAKING=1` and a CHANGELOG entry
- [ ] Stage 4 or 5 now emits different objects for the same input: the commit is listed in `BUNDLE_AFFECTING` (`pipeline/bundle_revisions.py`)
- [ ] No secret and no report text I may not share, in the diff, the fixtures or this description
