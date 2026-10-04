# ADR-0076: PostgreSQL 18, on a new volume, moved by dump and restore

**Status:** Accepted
**Date:** 2026-10-04
**Deciders:** maintainer
**Amends:** ADR-0045 (PostgreSQL for the job store), ADR-0054 (full-Docker installation)

## Context

Dependabot proposed `postgres:17-alpine` → `postgres:18-alpine` (PR #98) and
the container smoke test failed: the database never became healthy. Run
locally on a fresh volume mounted where compose mounted it, the 18 image says
why and exits — in 18+ it keeps its cluster under
`/var/lib/postgresql/18/docker`, declares `/var/lib/postgresql` as its volume,
and refuses a mount at the old `/var/lib/postgresql/data`. Independently of
the path, a PostgreSQL 17 data directory cannot be opened by 18: a major
version needs `pg_upgrade` (both versions' binaries) or a dump and restore.

The maintainer's policy is to follow upstream releases rather than pin old
majors (2026-10-04): the change has to be made, not declined.

## Decision

1. **`postgres:18-alpine`** (digest pinned, as every compose image), with
   the hardening unchanged: uid 70, read-only root, tmpfs socket and `/tmp`,
   no capabilities, scram for local and host connections. Checked locally:
   18.6 starts and answers healthy under exactly those flags.
2. **A new volume, `pg-data-18`, mounted at `/var/lib/postgresql`.**
   Re-mounting `pg-data` at the new path would make 18 create an empty
   cluster in `pg-data/18/docker` next to the 17 files: an existing install
   would come up with no reports and no visible error. A new name keeps the
   17 cluster out of reach of the 18 server. `pg-data` is no longer declared,
   so `docker compose down -v` does not delete it.
3. **`scripts/upgrade_postgres_17_to_18.sh` moves the data**: a throwaway
   `postgres:17-alpine` (the previous digest) on `pg-data`, `pg_dump -Fc`
   into `./backups/` (gitignored), the 18 service on `pg-data-18`,
   `pg_restore`, then the row count of every table compared between the two;
   any difference stops it. It refuses to restore over an 18 database that
   already has tables unless `FORCE=1`, and refuses to run with app or
   worker up. Passwords are read inside the containers from the mounted
   secret, never passed on this host's command line.
4. **CI tests PostgreSQL 18** (the service image of the two test jobs).

## Options rejected

- **`pg_upgrade --link` in place.** Needs both versions' binaries in one
  container (the image's own guidance is a single mount at
  `/var/lib/postgresql` so `--link` works *next time*); third-party images
  that automate it (pgautoupgrade) would put an unaudited image in charge of
  the only copy of the data.
- **Keep 17.** Supported upstream until November 2029, but declines the
  maintainer's policy and leaves the layout change for later.
- **Reuse `pg-data` at the new path.** The silent empty-database failure
  above.

## Consequences

- An existing stack must run the script **before** `docker compose up`
  (docs/upgrading.md §7); if it starts first, the app sits on an empty 18
  database until the script is run with `FORCE=1`. The 17 volume stays until
  the operator deletes it, which is also the way back.
- Verified on 2026-10-04: the preview database (7 reports, 17 tables) moved
  from a 17 cluster under the old layout to 18 with identical row counts; a
  second run refused to overwrite; the full test suite passes on 18.
- Future majors (19+) can use `pg_upgrade --link`, the volume now being the
  image's recommended single mount.
