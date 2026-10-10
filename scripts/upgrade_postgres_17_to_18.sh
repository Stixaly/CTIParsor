#!/usr/bin/env bash
# PostgreSQL 17 -> 18 (ADR-0076) is one case of `make db-upgrade`, which moves
# the job store to whatever major compose.yaml names (scripts/db_upgrade.sh,
# ADR-0077 part B).  Kept so the docs and habits that name this script still
# work; same environment (COMPOSE_PROJECT_NAME, OLD_VOLUME, FORCE=1, ...).
exec bash "$(dirname "$0")/db_upgrade.sh" "$@"
