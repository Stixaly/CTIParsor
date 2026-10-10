#!/usr/bin/env bash
# Move the job and rule stores to the PostgreSQL major compose.yaml names
# (ADR-0077 part B, 10; generalises ADR-0076's 17 -> 18 script).
#
# Run it after changing the postgres image in compose.yaml to a new major, or
# when docker/postgres/guard.sh refused to start the service.  It:
#
#   1. finds the cluster to move: a <major>/docker cluster of another major in
#      the stack's volume (`<project>_pg-data-18`, mounted at /var/lib/postgresql
#      — PostgreSQL 18 on keeps one directory per major there), or else the
#      pre-18 volume `<project>_pg-data` (17 kept its cluster at its root);
#   2. stops whatever still runs on that cluster, then dumps it with a
#      throwaway server of ITS major: the cluster is stopped cleanly, never
#      changed, never deleted;
#   3. creates the new major's cluster in the stack's volume with a throwaway
#      server of the compose image, refuses to restore over tables unless
#      FORCE=1, restores, and compares every table's row count;
#   4. leaves the stack stopped: `docker compose up -d` then starts on the new
#      cluster, and the app's start applies the schema history (api.migrate).
#
# Usage, from the repository root, app and worker stopped:
#   make db-upgrade            (or: scripts/db_upgrade.sh)
# Environment: COMPOSE_PROJECT_NAME (default ctiparsor), OLD_VOLUME (the pre-18
#   volume, default <project>_pg-data), CTI_DB_USER / CTI_DB_NAME (default
#   ctiparsor), BACKUP_DIR (default ./backups), FORCE=1,
#   SOURCE_IMAGE (the old major's image, for a major this script has no
#   pinned image for).
#
# The password is .secrets/db_password: the old cluster must accept it, so do
# not change CTI_DB_PASSWORD before migrating.
set -euo pipefail
cd "$(dirname "$0")/.."

PROJECT="${COMPOSE_PROJECT_NAME:-ctiparsor}"
VOLUME="${PROJECT}_pg-data-18"          # compose.yaml's `pg-data-18`, every major from 18 on
LEGACY_VOLUME="${OLD_VOLUME:-${PROJECT}_pg-data}"   # PostgreSQL 17's (ADR-0076)
DB_USER="${CTI_DB_USER:-ctiparsor}"
DB_NAME="${CTI_DB_NAME:-ctiparsor}"
BACKUP_DIR="${BACKUP_DIR:-./backups}"
SECRET=".secrets/db_password"
COMPOSE="docker compose -p ${PROJECT}"
EXPORTER="${PROJECT}-pg-upgrade-export"
IMPORTER="${PROJECT}-pg-upgrade-import"

# The images the stack has run, pinned as compose.yaml pinned them.  A major
# missing here is dumped with SOURCE_IMAGE.
pinned_image() {
    case "$1" in
        17) echo "postgres:17-alpine@sha256:b0f9560a2de083e2cc7382e75f808c7381a32852a7ec49117deedb300e552b24" ;;
        18) echo "postgres:18-alpine@sha256:77f585114c32fbca283dc835b0596f4e52b51b4c6662d7810b2f4084f60a1873" ;;
        *)  echo "" ;;
    esac
}

log()  { printf '[db-upgrade] %s\n' "$*"; }
die()  { printf '[db-upgrade] ERROR: %s\n' "$*" >&2; exit 1; }

# psql/pg_dump inside a container, the password read there from the mounted
# secret so it never appears on this host's command line.
in_pg() {  # in_pg <container> <command...>
    local where="$1"; shift
    docker exec -i "$where" sh -c 'PGPASSWORD="$(cat /run/secrets/db_password)" exec "$@"' sh "$@"
}

row_counts() {  # row_counts <container> -> "table count" lines, sorted
    in_pg "$1" psql -U "$DB_USER" -d "$DB_NAME" -v ON_ERROR_STOP=1 -tAF ' ' -c \
        "SELECT format('SELECT %L, count(*) FROM %I.%I;', tablename, schemaname, tablename)
           FROM pg_tables WHERE schemaname = 'public' ORDER BY tablename" \
      | in_pg "$1" psql -U "$DB_USER" -d "$DB_NAME" -v ON_ERROR_STOP=1 -tAF ' ' \
      | sort
}

wait_ready() {  # wait_ready <container>
    for _ in $(seq 1 90); do
        if in_pg "$1" pg_isready -U "$DB_USER" -d "$DB_NAME" >/dev/null 2>&1; then return 0; fi
        [ "$(docker inspect -f '{{.State.Running}}' "$1" 2>/dev/null)" = true ] || return 1
        sleep 2
    done
    return 1
}

stop_throwaway() {  # a clean shutdown, so neither cluster needs crash recovery later
    for c in "$EXPORTER" "$IMPORTER"; do
        docker stop -t 60 "$c" >/dev/null 2>&1 || true
        # -v: the image's own anonymous VOLUME, unused here (the data is on /pgvol)
        docker rm -v "$c" >/dev/null 2>&1 || true
    done
}
trap stop_throwaway EXIT

# The volume is mounted at /pgvol, not where the image keeps its data: from 18
# on, the image refuses to start on its default PGDATA while another major's
# cluster sits in the same volume (docker-library/postgres#1259) — which is
# exactly the state of a volume mid-move.  The directories inside the volume
# are the ones the compose service uses: <major>/docker.
pg_server() {  # pg_server <name> <image> <volume>:<mount> <PGDATA>
    docker run -d --name "$1" --user 70:70 \
        -e POSTGRES_USER="$DB_USER" -e POSTGRES_DB="$DB_NAME" \
        -e POSTGRES_PASSWORD_FILE=/run/secrets/db_password \
        -e POSTGRES_INITDB_ARGS="--auth-host=scram-sha-256 --auth-local=scram-sha-256" \
        -e PGDATA="$4" \
        -v "$3" -v "$PWD/$SECRET":/run/secrets/db_password:ro \
        "$2" >/dev/null
}

[ -f "$SECRET" ] || die "$SECRET is missing: run 'make docker-up' once, or write CTI_DB_PASSWORD to it"
if [ -n "$($COMPOSE ps -q app worker 2>/dev/null)" ]; then
    die "app or worker is running: stop them first ($COMPOSE stop app worker)"
fi

# ── 1. what to move, and where to ─────────────────────────────────────────────
TARGET_IMAGE="$(sed -n 's/^ *image: *\(postgres:[^ ]*\).*/\1/p' compose.yaml | head -1)"
[ -n "$TARGET_IMAGE" ] || die "no postgres image in compose.yaml"
TARGET="$(docker run --rm --entrypoint sh "$TARGET_IMAGE" -c 'echo "$PG_MAJOR"')"
case "$TARGET" in ''|*[!0-9]*) die "cannot read PG_MAJOR from $TARGET_IMAGE" ;; esac

majors_in() {  # majors_in <volume> -> one major per line, from <major>/docker/PG_VERSION
    docker run --rm -v "$1":/v --entrypoint sh "$TARGET_IMAGE" -c \
        'for f in /v/*/docker/PG_VERSION; do [ -s "$f" ] && cat "$f"; done; true'
}

SOURCE="" SRC_VOLUME="" SRC_MOUNT="" SRC_PGDATA=""
if docker volume inspect "$VOLUME" >/dev/null 2>&1; then
    OTHERS="$(majors_in "$VOLUME" | grep -vx "$TARGET" | sort -n | tr '\n' ' ' | sed 's/ $//')"
    case "$OTHERS" in
        "") ;;
        *" "*) die "$VOLUME holds clusters of PostgreSQL $OTHERS besides $TARGET: move one by hand" ;;
        *) SOURCE="$OTHERS" SRC_VOLUME="$VOLUME" SRC_MOUNT="/pgvol"
           SRC_PGDATA="/pgvol/$OTHERS/docker" ;;
    esac
    if [ -z "$SOURCE" ] && majors_in "$VOLUME" | grep -qx "$TARGET"; then
        log "$VOLUME already holds PostgreSQL $TARGET's cluster and no other major"
    fi
fi
if [ -z "$SOURCE" ] && docker volume inspect "$LEGACY_VOLUME" >/dev/null 2>&1; then
    SOURCE="$(docker run --rm -v "$LEGACY_VOLUME":/v --entrypoint sh "$TARGET_IMAGE" -c \
        '[ -s /v/PG_VERSION ] && cat /v/PG_VERSION; true')"
    if [ -n "$SOURCE" ]; then
        SRC_VOLUME="$LEGACY_VOLUME" SRC_MOUNT="/var/lib/postgresql/data" SRC_PGDATA="/var/lib/postgresql/data"
    fi
fi
[ -n "$SOURCE" ] || { log "no cluster of another PostgreSQL major to move: nothing to do"; exit 0; }
[ "$SOURCE" != "$TARGET" ] || die "the cluster in $SRC_VOLUME is already PostgreSQL $TARGET"
SOURCE_IMAGE="${SOURCE_IMAGE:-$(pinned_image "$SOURCE")}"
[ -n "$SOURCE_IMAGE" ] || die "no pinned image for PostgreSQL $SOURCE: set SOURCE_IMAGE=postgres:$SOURCE-alpine@sha256:<digest>"
log "moving PostgreSQL $SOURCE ($SRC_VOLUME) to PostgreSQL $TARGET ($VOLUME)"

# ── 2. stop what runs on the old cluster, dump it ─────────────────────────────
# Two servers on one data directory corrupt it, and in a container both are
# PID 1, so each takes the other's postmaster.pid for a stale one.
RUNNING="$(docker ps -q --filter "volume=$SRC_VOLUME")"
if [ -n "$RUNNING" ]; then
    log "stopping $(docker ps --filter "volume=$SRC_VOLUME" --format '{{.Names}}' | tr '\n' ' ')(they run on $SRC_VOLUME)"
    # shellcheck disable=SC2086  # one id per word
    docker stop -t 60 $RUNNING >/dev/null
fi
mkdir -p "$BACKUP_DIR"
DUMP="$BACKUP_DIR/${DB_NAME}-pg${SOURCE}-$(date +%Y%m%d-%H%M%S).dump"
stop_throwaway
pg_server "$EXPORTER" "$SOURCE_IMAGE" "$SRC_VOLUME:$SRC_MOUNT" "$SRC_PGDATA"
wait_ready "$EXPORTER" || { docker logs --tail 30 "$EXPORTER" >&2; die "PostgreSQL $SOURCE did not start on $SRC_VOLUME"; }
OLD_COUNTS="$(row_counts "$EXPORTER")"
[ -n "$OLD_COUNTS" ] || die "no table in $DB_NAME on $SRC_VOLUME: nothing to move"
log "dumping $DB_NAME ($(printf '%s\n' "$OLD_COUNTS" | wc -l) tables) -> $DUMP"
in_pg "$EXPORTER" pg_dump -U "$DB_USER" -d "$DB_NAME" -Fc > "$DUMP"
[ -s "$DUMP" ] || die "the dump is empty"
stop_throwaway

# ── 3. the new cluster, restored and compared ─────────────────────────────────
if ! docker volume inspect "$VOLUME" >/dev/null 2>&1; then
    # With compose's labels, so `docker compose up` adopts it without a warning.
    docker volume create --label "com.docker.compose.project=$PROJECT" \
        --label "com.docker.compose.volume=pg-data-18" "$VOLUME" >/dev/null
fi
log "creating PostgreSQL $TARGET's cluster in $VOLUME"
# Mounted away from the image's own data path, a new volume is root's: give
# its root and the major's directory to the postgres user (uid 70, as compose
# runs it), which a volume mounted at /var/lib/postgresql inherits from the image.
docker run --rm -v "$VOLUME":/pgvol --entrypoint sh "$TARGET_IMAGE" -c \
    "mkdir -p /pgvol/$TARGET && chown 70:70 /pgvol /pgvol/$TARGET"
pg_server "$IMPORTER" "$TARGET_IMAGE" "$VOLUME:/pgvol" "/pgvol/$TARGET/docker"
wait_ready "$IMPORTER" || { docker logs --tail 30 "$IMPORTER" >&2; die "PostgreSQL $TARGET did not start"; }
EXISTING="$(in_pg "$IMPORTER" psql -U "$DB_USER" -d "$DB_NAME" -tAc \
    "SELECT count(*) FROM pg_tables WHERE schemaname = 'public'")"
if [ "$EXISTING" != "0" ] && [ "${FORCE:-0}" != "1" ]; then
    die "PostgreSQL $TARGET's database already has $EXISTING tables. Either this move was done before \
(start the stack and check your reports, then delete the $SOURCE cluster), or the app started on an \
empty $TARGET database before the move: rerun with FORCE=1 to replace its tables with the dump kept at $DUMP"
fi
log "restoring into PostgreSQL $TARGET"
in_pg "$IMPORTER" pg_restore -U "$DB_USER" -d "$DB_NAME" --clean --if-exists --exit-on-error < "$DUMP"
NEW_COUNTS="$(row_counts "$IMPORTER")"
if [ "$OLD_COUNTS" != "$NEW_COUNTS" ]; then
    diff <(printf '%s\n' "$OLD_COUNTS") <(printf '%s\n' "$NEW_COUNTS") >&2 || true
    die "row counts differ between $SOURCE and $TARGET (above); the dump is kept at $DUMP"
fi
stop_throwaway
log "all $(printf '%s\n' "$NEW_COUNTS" | wc -l) tables restored with the same row counts"
log "next: '$COMPOSE up -d' (or make docker-up): the app's start applies the schema history."
log "The PostgreSQL $SOURCE cluster in $SRC_VOLUME is untouched; once the app shows your reports,"
if [ "$SRC_VOLUME" = "$VOLUME" ]; then
    log "delete it with: docker run --rm -v $VOLUME:/v --entrypoint rm $TARGET_IMAGE -rf /v/$SOURCE"
else
    log "delete it with: docker volume rm $SRC_VOLUME"
fi
