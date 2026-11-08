#!/bin/sh
# Scheduled backup of the CTIParsor stack: the commands of docs/docker.md,
# "Data and backups", run once a day (ADR-0097 item 19).
#
# It runs as the `backup` service of compose.yaml. That service mounts cti-state
# read-only, the target directory at /backups and the status volume at
# /backup-status. Nothing here stops app or worker: see docs/docker.md.
#
# Environment (all optional):
#   BACKUP_TIME         HH:MM, UTC, the daily run time (default 02:30)
#   BACKUP_KEEP         backup pairs kept, newest first (default 7)
#   BACKUP_RUN_NOW      1: back up once now and exit (0 on success, 1 on failure)
#   BACKUP_DIR          target directory (default /backups)
#   BACKUP_TARGET_CONFIGURED  the BACKUP_TARGET of .env; empty = refuse to run
#   BACKUP_STATUS_FILE  status file the app reads (default /backup-status/status.json)
#   STATE_DIR           the cti-state volume (default /app/state)
#   DB_PASSWORD_FILE    the database password secret (default /run/secrets/db_password)
#   PG_HOST, PG_PORT    the database (default postgres, 5432)
#   CTI_DB_USER, CTI_DB_NAME  the role and the database (default ctiparsor)
#
# A backup is two files with the same stamp, in UTC:
#   ctiparsor-YYYY-MM-DD-HHMMSS.dump   pg_dump, custom format
#   cti-state-YYYY-MM-DD-HHMMSS.tgz    tar of cti-state
# Both are written under a temporary name, checked, then renamed. A failed run
# deletes none of the older backups. The status file is written after each run.
set -eu

BACKUP_TIME=${BACKUP_TIME:-02:30}
BACKUP_KEEP=${BACKUP_KEEP:-7}
BACKUP_RUN_NOW=${BACKUP_RUN_NOW:-0}
BACKUP_DIR=${BACKUP_DIR:-/backups}
# Set from BACKUP_TARGET in compose.yaml. Empty means no target was configured.
BACKUP_TARGET_CONFIGURED=${BACKUP_TARGET_CONFIGURED:-}
BACKUP_STATUS_FILE=${BACKUP_STATUS_FILE:-/backup-status/status.json}
STATE_DIR=${STATE_DIR:-/app/state}
DB_PASSWORD_FILE=${DB_PASSWORD_FILE:-/run/secrets/db_password}
PG_HOST=${PG_HOST:-postgres}
PG_PORT=${PG_PORT:-5432}
CTI_DB_USER=${CTI_DB_USER:-ctiparsor}
CTI_DB_NAME=${CTI_DB_NAME:-ctiparsor}

# Backups hold every report at its TLP: readable by the backup user only.
umask 077

WORK=""
ERR_FILE=""
TMP_DUMP=""
TMP_ARCHIVE=""
DUMP_NAME=""
ARCHIVE_NAME=""
FAILURE=""

die() {
    echo "backup: $*" >&2
    exit 2
}

# A JSON string, or null when the value is empty.
json_str() {
    if [ -z "$1" ]; then
        printf 'null'
    else
        printf '"%s"' "$(printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g' | tr -d '\001-\037')"
    fi
}

# write_status OK LAST_ATTEMPT LAST_SUCCESS FILE ERROR
# Written to a temporary name in the same directory, then renamed, so the app
# never reads half a file. Readable by every user: the app runs as another uid.
write_status() {
    tmp="$BACKUP_STATUS_FILE.tmp"
    (
        umask 022
        {
            printf '{"last_attempt": %s, ' "$(json_str "$2")"
            printf '"last_success": %s, ' "$(json_str "$3")"
            printf '"ok": %s, ' "$1"
            printf '"error": %s, ' "$(json_str "$5")"
            printf '"file": %s}\n' "$(json_str "$4")"
        } > "$tmp"
    ) && mv -f "$tmp" "$BACKUP_STATUS_FILE"
}

# The last successful backup time already in the status file, or nothing.
previous_success() {
    [ -r "$BACKUP_STATUS_FILE" ] || return 0
    sed -n 's/.*"last_success": "\([^"]*\)".*/\1/p' "$BACKUP_STATUS_FILE" | head -n 1
}

# step LABEL COMMAND [ARGS...]: run one step; on failure keep its last stderr line.
# The steps below are functions: each command in them ends with `|| return 1`,
# because set -e does not stop a function that runs in an `if` condition.
step() {
    label=$1
    shift
    if "$@" 2> "$ERR_FILE"; then
        return 0
    fi
    last=$(tail -n 1 "$ERR_FILE" 2> /dev/null || true)
    FAILURE="$label failed${last:+: $last}"
    return 1
}

read_password() {
    PGPASSWORD=$(cat "$DB_PASSWORD_FILE") || return 1
    [ -n "$PGPASSWORD" ] || { echo "the password file is empty" >&2; return 1; }
    export PGPASSWORD
}

dump_database() {
    pg_dump -h "$PG_HOST" -p "$PG_PORT" -U "$CTI_DB_USER" -d "$CTI_DB_NAME" -Fc > "$TMP_DUMP" || return 1
}

archive_state() {
    tar czf "$TMP_ARCHIVE" -C "$STATE_DIR" . || return 1
}

# The dump must list tables with data, as docs/docker.md's check does.
check_dump() {
    pg_restore -l "$TMP_DUMP" > "$WORK/toc.dump" || return 1
    tables=$(grep -c 'TABLE DATA' "$WORK/toc.dump" || true)
    if [ "$tables" -eq 0 ]; then
        echo "the dump lists no table data" >&2
        return 1
    fi
}

# The archive must read back. Zero uploads is a valid state, so no count is required.
check_archive() {
    tar tzf "$TMP_ARCHIVE" > "$WORK/toc.tgz" || return 1
    [ -s "$WORK/toc.tgz" ] || { echo "the archive lists no entries" >&2; return 1; }
}

publish() {
    mv "$TMP_DUMP" "$BACKUP_DIR/$DUMP_NAME" || return 1
    mv "$TMP_ARCHIVE" "$BACKUP_DIR/$ARCHIVE_NAME" || return 1
}

# Keep the newest BACKUP_KEEP pairs. Names sort by time, so reverse order is newest first.
keep_newest() {
    ls -1 "$BACKUP_DIR" | grep '^ctiparsor-.*\.dump$' | sort -r > "$WORK/pairs" || true
    n=0
    while IFS= read -r name; do
        n=$((n + 1))
        if [ "$n" -gt "$BACKUP_KEEP" ]; then
            stamp=${name#ctiparsor-}
            stamp=${stamp%.dump}
            rm -f "$BACKUP_DIR/$name" "$BACKUP_DIR/cti-state-$stamp.tgz"
        fi
    done < "$WORK/pairs"
}

run_backup() {
    attempt=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    previous=$(previous_success)
    stamp=$(date -u +%Y-%m-%d-%H%M%S)
    DUMP_NAME="ctiparsor-$stamp.dump"
    ARCHIVE_NAME="cti-state-$stamp.tgz"
    TMP_DUMP="$BACKUP_DIR/.$DUMP_NAME.part"
    TMP_ARCHIVE="$BACKUP_DIR/.$ARCHIVE_NAME.part"
    FAILURE=""

    if step "reading the database password" read_password \
        && step "pg_dump" dump_database \
        && step "archiving $STATE_DIR" archive_state \
        && step "checking the dump" check_dump \
        && step "checking the archive" check_archive \
        && step "publishing the backup" publish; then
        keep_newest || echo "backup: could not delete the old backups" >&2
        write_status true "$attempt" "$attempt" "$DUMP_NAME" "" \
            || echo "backup: could not write the status file" >&2
        echo "backup: $DUMP_NAME and $ARCHIVE_NAME written"
        return 0
    fi

    rm -f "$TMP_DUMP" "$TMP_ARCHIVE"
    echo "backup: failed: $FAILURE" >&2
    write_status false "$attempt" "$previous" "" "$FAILURE" \
        || echo "backup: could not write the status file" >&2
    return 1
}

cleanup() {
    [ -z "$TMP_DUMP" ] || rm -f "$TMP_DUMP"
    [ -z "$TMP_ARCHIVE" ] || rm -f "$TMP_ARCHIVE"
    [ -z "$WORK" ] || rm -rf "$WORK"
}

main() {
    case $BACKUP_TIME in
        [01][0-9]:[0-5][0-9] | 2[0-3]:[0-5][0-9]) ;;
        *) die "BACKUP_TIME must be HH:MM, UTC (got '$BACKUP_TIME')" ;;
    esac
    case $BACKUP_KEEP in
        '' | *[!0-9]*) die "BACKUP_KEEP must be a whole number (got '$BACKUP_KEEP')" ;;
    esac
    [ "$BACKUP_KEEP" -ge 1 ] || die "BACKUP_KEEP must be at least 1"
    if [ -z "$BACKUP_TARGET_CONFIGURED" ]; then
        # Without a target, /backups would be a directory on the host running
        # Compose: refuse, record the refusal, back nothing up.
        msg="BACKUP_TARGET is not set: backups would stay on this host"
        echo "backup: $msg" >&2
        write_status false "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$(previous_success)" "" "$msg" \
            || echo "backup: could not write the status file" >&2
        exit 1
    fi
    [ -d "$BACKUP_DIR" ] || die "BACKUP_DIR $BACKUP_DIR is not a directory"

    WORK=$(mktemp -d "${TMPDIR:-/tmp}/ctibackup.XXXXXX")
    ERR_FILE="$WORK/stderr"
    trap cleanup EXIT
    trap 'cleanup; exit 143' TERM INT

    if [ "$BACKUP_RUN_NOW" = 1 ]; then
        if run_backup; then
            exit 0
        fi
        exit 1
    fi

    echo "backup: every day at $BACKUP_TIME UTC, keeping the newest $BACKUP_KEEP"
    last_day=""
    while :; do
        today=$(date -u +%Y-%m-%d)
        if [ "$(date -u +%H:%M)" = "$BACKUP_TIME" ] && [ "$today" != "$last_day" ]; then
            last_day=$today
            run_backup || true
        fi
        # Backgrounded and waited for, so that TERM is handled at once.
        sleep 20 &
        wait $! || true
    done
}

main "$@"
