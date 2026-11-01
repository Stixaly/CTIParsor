#!/usr/bin/env bash
# The backup and restore commands of docs/docker.md ("Data and backups"), run
# as written there, on a running stack (ADR-0094 item 3).
#
# scripts/docker_smoke.sh --backup-restore calls it on its own stack (CI's
# container-image job).  It writes a report into that stack (its rows, a
# decision, its uploaded file, an exported bundle, a private corpus overlay),
# takes a backup with the docs' commands and checks it with theirs, restores it
# into a second project, `<project>-restored`, whose volumes are empty, by the
# docs' restore steps, starts it, and checks:
#   - GET /api/health answers ok;
#   - every table: the same row count and the same checksum of its rows, but
#     worker_heartbeats, which lists the workers running now (each rewrites
#     its row every WORKER_HEARTBEAT_S, and the restored stack's adds its own):
#     compared by name only;
#   - every file of cti-state but db-identity.json, byte for byte, and the
#     uploaded one through GET /api/jobs/{id}/source;
#   - the report through GET /api/jobs/{id};
#   - db-identity.json: the restored database recorded on its new cluster.
# The restore's pg_restore must exit 0 and print nothing, as the docs require.
# The second project (`down -v`) and the backup files are removed at the end;
# the stack it started from is left running, its app and worker started again
# if the check stopped after `docker compose stop app worker`.
#
# Usage: bash scripts/check_backup_restore_docker.sh
# Environment: COMPOSE_PROJECT_NAME (the running stack: ctiparsor-smoke, the
#              default and the only one it runs on; any other exits 2),
#              DOCKER_BIN (default: docker), CTI_BIND / CTI_PORT (the running
#              stack's; the restored one listens on CTI_PORT + 1),
#              SMOKE_HEALTH_TIMEOUT (seconds, default 180).
# Exit 0 when everything came back, 1 otherwise, 2 on another project.

set -u
set -o pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'
FAILS=0
pass() { echo -e "${GREEN}PASS${NC}  $1"; }
fail() { echo -e "${RED}FAIL${NC}  $1"; FAILS=$((FAILS + 1)); }
info() { echo -e "${BLUE}INFO${NC}  $1"; }

REPO=$(cd "$(dirname "$0")/.." && pwd)
umask 077          # the files this check writes hold every report; the docs' commands set their own umask
DOCKER_BIN="${DOCKER_BIN:-docker}"
SOURCE="${COMPOSE_PROJECT_NAME:-ctiparsor-smoke}"
TARGET="$SOURCE-restored"
# The smoke's stack only: the check writes a test report into it, stops its app
# and worker, and removes `<project>-restored` with its volumes at the end.  An
# operator's shell may name the install, or a restored one (docs/docker.md).
if [ "$SOURCE" != ctiparsor-smoke ]; then
    echo "ERROR: this check runs only on the smoke's project, ctiparsor-smoke," \
         "and COMPOSE_PROJECT_NAME is $SOURCE." >&2
    exit 2
fi
BIND="${CTI_BIND:-127.0.0.1}"
PORT="${CTI_PORT:-8000}"
RESTORED_PORT=$((PORT + 1))
TIMEOUT="${SMOKE_HEALTH_TIMEOUT:-180}"
JOB="7d3c1b2a-5e4f-4a6b-9c8d-0e1f2a3b4c5d"
SAMPLE="$REPO/tests/fixtures/sample_report.txt"

# The docs' commands run in a directory of their own, where the backup files
# land; Compose still reads compose.yaml, .env and .secrets/ from the checkout.
WORK=$(mktemp -d)
export COMPOSE_FILE="$REPO/compose.yaml"
if [ "$DOCKER_BIN" != docker ]; then
    docker() { "$DOCKER_BIN" "$@"; }
fi

# The commands of docs/docker.md, "Data and backups", character for character:
# tests/test_check_backup_restore.py fails when the two differ.  YYYY-MM-DD
# stands for the date of the backup.
read -r -d '' BACKUP_COMMANDS <<'COMMANDS'
day=$(date +%F)
docker compose stop app worker
(umask 077; docker compose exec -T postgres sh -c 'PGPASSWORD="$(cat /run/secrets/db_password)" exec "$@"' sh pg_dump -U ctiparsor -d ctiparsor -Fc > ctiparsor-$day.dump)
(umask 077; docker compose run --rm --no-deps -T --entrypoint tar app czf - -C /app/state . > cti-state-$day.tgz)
docker compose start app worker
COMMANDS
read -r -d '' CHECK_COMMANDS <<'COMMANDS'
docker compose exec -T postgres pg_restore -l < ctiparsor-YYYY-MM-DD.dump | grep -c 'TABLE DATA'
tar tzf cti-state-YYYY-MM-DD.tgz | grep -c '^./uploads/.'
COMMANDS
read -r -d '' RESTORE_COMMANDS <<'COMMANDS'
docker compose up -d --wait postgres
docker compose exec -T postgres sh -c 'PGPASSWORD="$(cat /run/secrets/db_password)" exec "$@"' sh pg_restore -U ctiparsor -d ctiparsor --single-transaction < ctiparsor-YYYY-MM-DD.dump
docker compose run --rm --no-deps -T --entrypoint tar app xzf - --keep-old-files -C /app/state < cti-state-YYYY-MM-DD.tgz
docker compose up -d
COMMANDS

in_project() {     # in_project <project> <compose arguments...>
    COMPOSE_PROJECT_NAME="$1" docker compose "${@:2}"
}

in_app() {         # in_app <project> <command...>: in its app container, stdin left alone
    in_project "$1" exec -T app "${@:2}"
}

psql_in() {        # psql_in <project>: SQL on stdin, rows on stdout
    in_project "$1" exec -T postgres sh -c \
        'PGPASSWORD="$(cat /run/secrets/db_password)" exec psql -X -q -At -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d "$POSTGRES_DB"'
}

run_docs() {       # run_docs <project> <date> <commands>: the lines as written, in $WORK
    # One shell for the block, as an operator's: `day=` holds for the lines
    # after it.  The lines come in on fd 3: `docker compose
    # exec` reads its stdin, which is /dev/null unless the line redirects it.
    # Each line's stderr is shown; on the restore's pg_restore line, anything
    # there fails it (the docs: it must exit 0 and print nothing).
    (
        cd "$WORK" || exit 1
        export COMPOSE_PROJECT_NAME="$1"
        while IFS= read -r line <&3; do
            line=${line//YYYY-MM-DD/$2}
            info "[$1] \$ $line"
            if ! eval "$line" < /dev/null 2> "$WORK/.stderr"; then
                cat "$WORK/.stderr" >&2
                fail "[$1] $line"
                exit 1
            fi
            cat "$WORK/.stderr" >&2
            if [[ "$line" == *" pg_restore -U "* ]] && [ -s "$WORK/.stderr" ]; then
                fail "[$1] $line (exited 0, but printed the lines above)"
                exit 1
            fi
        done 3<<< "$3"
    )
}

# Every table of the database: its name, its row count, the md5 of its rows.
# worker_heartbeats by its name only: the running workers, not data (ADR-0094
# item 7).
FINGERPRINT_SQL="SELECT c.relname || CASE WHEN c.relname = 'worker_heartbeats' THEN ' (running workers)'
       ELSE ' ' || (xpath('/row/n/text()', q))[1]::text || ' ' || (xpath('/row/m/text()', q))[1]::text END
FROM pg_class c JOIN pg_namespace s ON s.oid = c.relnamespace,
     query_to_xml(format('SELECT count(*) AS n, md5(coalesce(string_agg(t::text, %L ORDER BY t::text), %L)) AS m '
                         'FROM %I t', '|', '', c.relname), false, true, '') AS q
WHERE s.nspname = current_schema() AND c.relkind = 'r' ORDER BY c.relname;"

# Every file of cti-state but db-identity.json, which each start rewrites.
FILES_COMMAND='cd /app/state && find . -type f ! -path ./db-identity.json -exec sha256sum {} + | sort -k 2'

# The restore's project must be empty before anything is written, and before
# the cleanup below may run `down -v` on it: a project left from another run is
# never removed by this one.  Captured, not piped into `grep -q` (which, under
# pipefail, can read an early exit for "empty"); a listing that fails stops it.
if ! TARGET_CONTAINERS=$(in_project "$TARGET" ps -aq) \
        || ! TARGET_VOLUMES=$(docker volume ls -q --filter "label=com.docker.compose.project=$TARGET"); then
    fail "cannot list the containers and volumes of project $TARGET"
    rm -rf "$WORK"
    exit 1
fi
if [ -n "$TARGET_CONTAINERS$TARGET_VOLUMES" ]; then
    fail "project $TARGET is not empty (it has containers or volumes: docker compose -p $TARGET down -v)"
    rm -rf "$WORK"
    exit 1
fi

SOURCE_STOPPED=false
cleanup() {
    if [ "$SOURCE_STOPPED" = true ]; then      # `start` leaves running containers alone
        info "Starting $SOURCE's app and worker again..."
        in_project "$SOURCE" start app worker >/dev/null 2>&1
    fi
    info "Removing the restored project and the backup files..."
    in_project "$TARGET" down -v --remove-orphans >/dev/null 2>&1
    rm -rf "$WORK"
}
trap cleanup EXIT

# ── 1. A report in the running stack ──────────────────────────────────────────
info "Writing a report into $SOURCE: its rows, a decision, its files..."
if psql_in "$SOURCE" <<SQL \
    && in_app "$SOURCE" sh -c "cat > /app/state/uploads/$JOB.txt" < "$SAMPLE" \
    && printf '{"type": "bundle", "id": "bundle--%s", "objects": []}\n' "$JOB" \
        | in_app "$SOURCE" sh -c "cat > /app/state/output/sample_report_${JOB}_bundle.json" \
    && printf 'corpora: []\n' | in_app "$SOURCE" sh -c 'cat > /app/state/detection_corpora.local.yaml'
INSERT INTO jobs (id, original_filename, status, report_text, created_at, updated_at)
VALUES ('$JOB', 'sample_report.txt', 'for_review', 'Frost Spider operates the Nightbell backdoor.',
        '2026-10-31T10:00:00+00:00', '2026-10-31T10:05:00+00:00');
INSERT INTO entities (id, job_id, value, entity_type, accepted, decision_origin, decided_at)
VALUES ('$JOB-e1', '$JOB', 'Nightbell', 'malware', 1, 'human', '2026-10-31T10:04:00+00:00'),
       ('$JOB-e2', '$JOB', 'Frost Spider', 'threat_actor', NULL, NULL, NULL);
INSERT INTO relationships (id, job_id, source_value, relationship_type, target_value, accepted)
VALUES ('$JOB-r1', '$JOB', 'Frost Spider', 'uses', 'Nightbell', 1);
INSERT INTO review_decisions (job_id, target_kind, target_id, accepted, origin, created_at)
VALUES ('$JOB', 'entity', '$JOB-e1', 1, 'human', '2026-10-31T10:04:00+00:00');
INSERT INTO progress_events (job_id, event_type, data, created_at)
VALUES ('$JOB', 'done', '{"status": "for_review"}', '2026-10-31T10:05:00+00:00');
SQL
then
    pass "a report written into the running stack: rows, a decision, three files"
else
    fail "a report written into the running stack"
    exit 1
fi

# ── 2. The backup, as docs/docker.md takes and checks it ──────────────────────
SOURCE_STOPPED=true
if run_docs "$SOURCE" "" "$BACKUP_COMMANDS"; then
    SOURCE_STOPPED=false        # its last line started them again
    pass "backup taken with the docs' commands"
else
    exit 1
fi
DUMP=$(cd "$WORK" && ls ctiparsor-*.dump)
DAY=${DUMP#ctiparsor-}
DAY=${DAY%.dump}
SOURCE_PRINT=$(psql_in "$SOURCE" <<< "$FINGERPRINT_SQL")
SOURCE_FILES=$(in_app "$SOURCE" sh -c "$FILES_COMMAND" < /dev/null)
SOURCE_IDENTITY=$(in_app "$SOURCE" cat /app/state/db-identity.json < /dev/null)
TABLES=$(printf '%s\n' "$SOURCE_PRINT" | grep -c .)
UPLOADS=$(in_app "$SOURCE" sh -c 'find /app/state/uploads -mindepth 1 | wc -l' < /dev/null | tr -d ' ')
info "backup of $DAY: $(wc -c < "$WORK/$DUMP") bytes of dump, $(wc -c < "$WORK/cti-state-$DAY.tgz") bytes of archive"
LISTED=$(run_docs "$SOURCE" "$DAY" "$CHECK_COMMANDS")
printf '%s\n' "$LISTED"
COUNTS=$(printf '%s\n' "$LISTED" | grep -E '^[0-9]+$' | paste -sd ' ')
if [ "$COUNTS" = "$TABLES $UPLOADS" ]; then
    pass "the backup checked with the docs' commands: the data of $TABLES tables, $UPLOADS entry(ies) under uploads/"
else
    fail "the backup checked with the docs' commands (expected $TABLES tables and $UPLOADS entries, got: $COUNTS)"
fi

# ── 3. The restore into an empty project, as docs/docker.md orders it ─────────
export CTI_PORT="$RESTORED_PORT"
if run_docs "$TARGET" "$DAY" "$RESTORE_COMMANDS"; then
    pass "restored into the empty project $TARGET with the docs' commands"
else
    in_project "$TARGET" logs --tail 40
    exit 1
fi

BASE="http://$BIND:$RESTORED_PORT"
start=$(date +%s)
until curl -fsS "$BASE/api/health" 2>/dev/null | grep -q '"ok"'; do
    if [ $(($(date +%s) - start)) -ge "$TIMEOUT" ]; then
        fail "GET /api/health on the restored stack (no answer after ${TIMEOUT}s)"
        in_project "$TARGET" logs --tail 60 app
        exit 1
    fi
    sleep 3
done
pass "GET /api/health on the restored stack"

# ── 4. Everything came back ───────────────────────────────────────────────────
TARGET_PRINT=$(psql_in "$TARGET" <<< "$FINGERPRINT_SQL")
if [ -n "$SOURCE_PRINT" ] && [ "$SOURCE_PRINT" = "$TARGET_PRINT" ]; then
    pass "every table: the same rows ($TABLES tables, row counts and checksums)"
else
    fail "every table: the same rows"
    diff <(printf '%s\n' "$SOURCE_PRINT") <(printf '%s\n' "$TARGET_PRINT")
fi

TARGET_FILES=$(in_app "$TARGET" sh -c "$FILES_COMMAND" < /dev/null)
WANT=$(sha256sum < "$SAMPLE" | cut -d' ' -f1)
SERVED=$(curl -fsS "$BASE/api/jobs/$JOB/source" | sha256sum | cut -d' ' -f1)
if [ -n "$SOURCE_FILES" ] && [ "$SOURCE_FILES" = "$TARGET_FILES" ] && [ "$SERVED" = "$WANT" ]; then
    pass "every file of cti-state, byte for byte ($(printf '%s\n' "$SOURCE_FILES" | grep -c .)), the upload served by GET /api/jobs/{id}/source"
else
    fail "every file of cti-state, byte for byte (served: $SERVED, want $WANT)"
    diff <(printf '%s\n' "$SOURCE_FILES") <(printf '%s\n' "$TARGET_FILES")
fi

SEEN=$(curl -fsS "$BASE/api/jobs/$JOB" | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d.get("status"), d.get("entity_count"), d.get("relationship_count"))' 2>/dev/null)
if [ "$SEEN" = "for_review 2 1" ]; then
    pass "the report through GET /api/jobs/{id}: for_review, 2 entities, 1 relationship"
else
    fail "the report through GET /api/jobs/{id} (got: $SEEN)"
fi

# The restored database answers at the same address, on another cluster: the
# first of app and worker to start accepts it, since it holds tables, and
# records the new cluster.
TARGET_IDENTITY=$(in_app "$TARGET" cat /app/state/db-identity.json < /dev/null)
IDENTITY=$(python3 -c '
import json, sys
before, after = json.loads(sys.argv[1]), json.loads(sys.argv[2])
moved = [a for a in after if a in before and after[a]["system_identifier"] != before[a]["system_identifier"]
         and after[a]["schema_version"] == before[a]["schema_version"]]
print("moved" if sorted(after) == sorted(before) and len(moved) == len(after) == 1 else "unexpected")
' "$SOURCE_IDENTITY" "$TARGET_IDENTITY" 2>/dev/null)
# The logs are read whole first: `grep -q` stops at the first match, and under
# pipefail the writer it leaves behind would fail the pipeline.
LOGS=$(in_project "$TARGET" logs app worker 2>&1)
if [ "$IDENTITY" = "moved" ] && grep -q "is now on cluster" <<< "$LOGS"; then
    pass "db-identity.json records the restored database on its new cluster"
else
    fail "db-identity.json records the restored database on its new cluster (before: $SOURCE_IDENTITY; after: $TARGET_IDENTITY)"
fi

echo ""
if [ "$FAILS" -gt 0 ]; then
    echo -e "${RED}Backup and restore: $FAILS failure(s)${NC}"
    exit 1
fi
echo -e "${GREEN}Backup and restore: 0 failure(s)${NC}"
exit 0
