#!/usr/bin/env bash
# Move the job and rule stores from PostgreSQL 17 to PostgreSQL 18.
#
# Until 2026-10 the stack ran postgres:17 with its cluster in the `pg-data`
# volume.  PostgreSQL 18's image keeps its cluster under /var/lib/postgresql/18
# and refuses the old mount, so compose.yaml now gives it a new volume,
# `pg-data-18`.  This script copies the database across with pg_dump /
# pg_restore (the documented backup format, docs/docker.md):
#
#   1. starts a throwaway postgres:17 container on the OLD volume and dumps
#      the database to backups/; the instance is stopped cleanly afterwards,
#      its data is not changed and the volume is never deleted;
#   2. starts the new `postgres` service (18) on `pg-data-18`;
#   3. refuses to restore into a database that already has tables, unless
#      FORCE=1;
#   4. restores, then compares the row count of every table with the old one.
#
# Usage, from the repository root, with app and worker stopped:
#   scripts/upgrade_postgres_17_to_18.sh
# Environment: COMPOSE_PROJECT_NAME (default: ctiparsor, compose.yaml's name),
#   OLD_VOLUME (default: <project>_pg-data), CTI_DB_USER / CTI_DB_NAME
#   (default: ctiparsor), BACKUP_DIR (default: ./backups), FORCE=1.
#
# The password is the one in .secrets/db_password (make docker-up writes it
# from CTI_DB_PASSWORD): the 17 cluster must accept it, so do not change
# CTI_DB_PASSWORD before migrating.
set -euo pipefail
cd "$(dirname "$0")/.."

PROJECT="${COMPOSE_PROJECT_NAME:-ctiparsor}"
OLD_VOLUME="${OLD_VOLUME:-${PROJECT}_pg-data}"
DB_USER="${CTI_DB_USER:-ctiparsor}"
DB_NAME="${CTI_DB_NAME:-ctiparsor}"
BACKUP_DIR="${BACKUP_DIR:-./backups}"
SECRET=".secrets/db_password"
# The image the stack ran before this change, same digest.
PG17_IMAGE="postgres:17-alpine@sha256:b0f9560a2de083e2cc7382e75f808c7381a32852a7ec49117deedb300e552b24"
EXPORTER="${PROJECT}-pg17-export"
COMPOSE="docker compose -p ${PROJECT}"

log()  { printf '[upgrade-pg] %s\n' "$*"; }
die()  { printf '[upgrade-pg] ERROR: %s\n' "$*" >&2; exit 1; }

# psql/pg_dump inside a container, the password read there from the mounted
# secret so it never appears on this host's command line.
in_pg() {  # in_pg <container-or-"compose"> <command...>
    local where="$1"; shift
    if [ "$where" = compose ]; then
        $COMPOSE exec -T postgres sh -c 'PGPASSWORD="$(cat /run/secrets/db_password)" exec "$@"' sh "$@"
    else
        docker exec -i "$where" sh -c 'PGPASSWORD="$(cat /run/secrets/db_password)" exec "$@"' sh "$@"
    fi
}

row_counts() {  # row_counts <where> -> "table count" lines, sorted
    in_pg "$1" psql -U "$DB_USER" -d "$DB_NAME" -v ON_ERROR_STOP=1 -tAF ' ' -c \
        "SELECT format('SELECT %L, count(*) FROM %I.%I;', tablename, schemaname, tablename)
           FROM pg_tables WHERE schemaname = 'public' ORDER BY tablename" \
      | in_pg "$1" psql -U "$DB_USER" -d "$DB_NAME" -v ON_ERROR_STOP=1 -tAF ' ' \
      | sort
}

wait_ready() {  # wait_ready <where>
    for _ in $(seq 1 60); do
        if in_pg "$1" pg_isready -U "$DB_USER" -d "$DB_NAME" >/dev/null 2>&1; then return 0; fi
        sleep 2
    done
    return 1
}

cleanup() {  # a clean shutdown, so the 17 cluster needs no crash recovery later
    docker stop -t 60 "$EXPORTER" >/dev/null 2>&1 || true
    docker rm "$EXPORTER" >/dev/null 2>&1 || true
}
trap cleanup EXIT

[ -f "$SECRET" ] || die "$SECRET is missing: run 'make docker-up' once, or write CTI_DB_PASSWORD to it"
docker volume inspect "$OLD_VOLUME" >/dev/null 2>&1 \
    || die "no volume $OLD_VOLUME: nothing to migrate (a fresh install needs no migration)"
if [ -n "$($COMPOSE ps -q app worker 2>/dev/null)" ]; then
    die "app or worker is running: stop them first ($COMPOSE stop app worker)"
fi

# ── 1. dump the 17 cluster ────────────────────────────────────────────────────
mkdir -p "$BACKUP_DIR"
DUMP="$BACKUP_DIR/${DB_NAME}-pg17-$(date +%Y%m%d-%H%M%S).dump"
log "starting PostgreSQL 17 on $OLD_VOLUME for the dump"
cleanup
docker run -d --name "$EXPORTER" --user 70:70 \
    -e POSTGRES_USER="$DB_USER" -e POSTGRES_DB="$DB_NAME" \
    -e POSTGRES_PASSWORD_FILE=/run/secrets/db_password \
    -v "$OLD_VOLUME":/var/lib/postgresql/data \
    -v "$PWD/$SECRET":/run/secrets/db_password:ro \
    "$PG17_IMAGE" >/dev/null
wait_ready "$EXPORTER" || { docker logs --tail 30 "$EXPORTER" >&2; die "PostgreSQL 17 did not start on $OLD_VOLUME"; }
OLD_COUNTS="$(row_counts "$EXPORTER")"
[ -n "$OLD_COUNTS" ] || die "no table in $DB_NAME on $OLD_VOLUME: nothing to migrate"
log "dumping $DB_NAME ($(printf '%s\n' "$OLD_COUNTS" | wc -l) tables) -> $DUMP"
in_pg "$EXPORTER" pg_dump -U "$DB_USER" -d "$DB_NAME" -Fc > "$DUMP"
[ -s "$DUMP" ] || die "the dump is empty"
cleanup

# ── 2. the 18 service ─────────────────────────────────────────────────────────
log "starting the postgres service (18) on ${PROJECT}_pg-data-18"
$COMPOSE up -d postgres >/dev/null
wait_ready compose || { $COMPOSE logs --tail 30 postgres >&2; die "PostgreSQL 18 did not become ready"; }

# ── 3. never restore over data ────────────────────────────────────────────────
EXISTING="$(in_pg compose psql -U "$DB_USER" -d "$DB_NAME" -tAc \
    "SELECT count(*) FROM pg_tables WHERE schemaname = 'public'")"
if [ "$EXISTING" != "0" ] && [ "${FORCE:-0}" != "1" ]; then
    die "the 18 database already has $EXISTING tables (the app started on it?). The dump is kept at $DUMP; rerun with FORCE=1 to replace those tables"
fi

# ── 4. restore and compare ────────────────────────────────────────────────────
log "restoring into PostgreSQL 18"
in_pg compose pg_restore -U "$DB_USER" -d "$DB_NAME" --clean --if-exists --exit-on-error < "$DUMP"
NEW_COUNTS="$(row_counts compose)"
if [ "$OLD_COUNTS" != "$NEW_COUNTS" ]; then
    diff <(printf '%s\n' "$OLD_COUNTS") <(printf '%s\n' "$NEW_COUNTS") >&2 || true
    die "row counts differ between 17 and 18 (above); the dump is kept at $DUMP"
fi
log "all $(printf '%s\n' "$NEW_COUNTS" | wc -l) tables restored with the same row counts"
log "next: '$COMPOSE up -d' (or make docker-up). The 17 volume $OLD_VOLUME is untouched;"
log "delete it with 'docker volume rm $OLD_VOLUME' once the app shows your reports."
