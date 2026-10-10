#!/usr/bin/env bash
# `make db-upgrade` moves a database to the PostgreSQL major compose.yaml names,
# in both layouts it meets (ADR-0077 part B, 10), and the stack then starts on it:
#   A. PostgreSQL 17 in the pre-18 volume (`pg-data`, cluster at its root);
#   B. PostgreSQL 17 in the stack's volume (`pg-data-18`, 17/docker) — the
#      layout a future 18 -> 19 upgrade meets.  The image itself refuses to
#      start 18 beside it (docker-library/postgres#1259): checked first; once
#      the move made 18's cluster, the service starts.
# Each scenario runs under its own throwaway compose project, never `ctiparsor`.
# Usage: scripts/check_db_upgrade.sh   (needs docker and .secrets/db_password)
set -euo pipefail
cd "$(dirname "$0")/.."

PG17="postgres:17-alpine@sha256:b0f9560a2de083e2cc7382e75f808c7381a32852a7ec49117deedb300e552b24"
SECRET="$PWD/.secrets/db_password"
[ -f "$SECRET" ] || { echo "needs .secrets/db_password" >&2; exit 2; }
fail=0
projects=()
# The dumps db_upgrade.sh writes stay out of the checkout's backups/.
export BACKUP_DIR
BACKUP_DIR="$(mktemp -d)"

cleanup() {
    for p in "${projects[@]}"; do
        docker rm -f "$p-seed" >/dev/null 2>&1 || true
        docker compose -p "$p" down -v >/dev/null 2>&1 || true
        docker volume rm -f "${p}_pg-data" "${p}_pg-data-18" >/dev/null 2>&1 || true
    done
    rm -rf "$BACKUP_DIR"
}
trap cleanup EXIT

check() {  # check <name> <expected> <got>
    if [ "$2" = "$3" ]; then echo "ok   $1"; else echo "FAIL $1: expected '$2', got '$3'"; fail=1; fi
}

psql_in() {  # psql_in <container> <sql>
    docker exec -i "$1" sh -c 'PGPASSWORD="$(cat /run/secrets/db_password)" psql -U ctiparsor -d ctiparsor -tAc "$1"' sh "$2"
}

seed() {  # seed <project> <volume> <mount> <PGDATA>: a PostgreSQL 17 database with rows
    docker volume create "$2" >/dev/null
    docker run -d --name "$1-seed" --user 70:70 \
        -e POSTGRES_USER=ctiparsor -e POSTGRES_DB=ctiparsor -e POSTGRES_PASSWORD_FILE=/run/secrets/db_password \
        -e PGDATA="$4" -v "$2:$3" -v "$SECRET":/run/secrets/db_password:ro "$PG17" >/dev/null
    for _ in $(seq 1 60); do psql_in "$1-seed" "SELECT 1" >/dev/null 2>&1 && break; sleep 1; done
    psql_in "$1-seed" "CREATE TABLE jobs (id text primary key); INSERT INTO jobs SELECT 'j'||g FROM generate_series(1,3) g;
                       CREATE TABLE entities (id int); INSERT INTO entities SELECT g FROM generate_series(1,5) g;" >/dev/null
    docker stop -t 30 "$1-seed" >/dev/null && docker rm "$1-seed" >/dev/null
}

service_up() {  # service_up <project> -> healthy | exited <code> | timeout
    docker compose -p "$1" up -d postgres >/dev/null 2>&1 || true
    for _ in $(seq 1 60); do
        s="$(docker inspect -f '{{.State.Status}} {{.State.ExitCode}} {{if .State.Health}}{{.State.Health.Status}}{{end}}' "$1-postgres-1" 2>/dev/null || echo missing)"
        case "$s" in
            *" healthy") echo healthy; return ;;
            exited*|restarting*) echo "refused"; return ;;
        esac
        sleep 2
    done
    echo timeout
}

counts() {  # counts <project>
    psql_in "$1-postgres-1" "SELECT (SELECT count(*) FROM jobs)||'/'||(SELECT count(*) FROM entities)"
}

# ── A. the pre-18 volume ──────────────────────────────────────────────────────
A="cti-dbup-a-$$"; projects+=("$A")
seed "$A" "${A}_pg-data" /var/lib/postgresql/data /var/lib/postgresql/data
COMPOSE_PROJECT_NAME="$A" bash scripts/db_upgrade.sh
check "A: the service starts on the moved cluster" healthy "$(service_up "$A")"
check "A: every row came across" "3/5" "$(counts "$A")"
check "A: the 17 volume is left in place" "${A}_pg-data" "$(docker volume ls -q --filter "name=${A}_pg-data$")"

# ── B. another major in the stack's own volume ───────────────────────────────
B="cti-dbup-b-$$"; projects+=("$B")
docker volume create --label "com.docker.compose.project=$B" --label "com.docker.compose.volume=pg-data-18" \
    "${B}_pg-data-18" >/dev/null
seed "$B" "${B}_pg-data-18" /var/lib/postgresql /var/lib/postgresql/17/docker
check "B: the image refuses 18 beside the 17 cluster" refused "$(service_up "$B")"
# Captured first: with pipefail, `logs | grep -q` fails when grep stops reading early.
logs="$(docker compose -p "$B" logs postgres 2>&1 || true)"
case "$logs" in
    *"there appears to be PostgreSQL data in"*) echo "ok   B: and says where the old data is" ;;
    *) echo "FAIL B: no refusal in the logs"; fail=1 ;;
esac
docker compose -p "$B" rm -sf postgres >/dev/null 2>&1
COMPOSE_PROJECT_NAME="$B" bash scripts/db_upgrade.sh
check "B: the service starts once the 18 cluster exists" healthy "$(service_up "$B")"
check "B: every row came across" "3/5" "$(counts "$B")"
docker compose -p "$B" stop postgres >/dev/null 2>&1
again="$(COMPOSE_PROJECT_NAME="$B" bash scripts/db_upgrade.sh 2>&1 || echo "exit=$?")"
case "$again" in
    *"already has"*"exit=1"*) echo "ok   B: a second run restores nothing over the moved data" ;;
    *) echo "FAIL B: second run: $again"; fail=1 ;;
esac
check "B: the moved rows are intact" healthy "$(service_up "$B")"
check "B: still every row" "3/5" "$(counts "$B")"

exit "$fail"
