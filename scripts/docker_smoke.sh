#!/usr/bin/env bash
# CTIParsor Docker smoke test
#
# Verifies:
#   - compose file validity
#   - image build (unless --no-build)
#   - container startup and health
#   - API health endpoint
#   - web UI served (React build present)
#   - runs as non-root (uid 1001)
#   - root filesystem is read-only
#   - state and cache volumes are writable
#   - symlinks resolve into the volumes
#   - Python imports (magic, playwright, sentence_transformers, transformers, gliner, stix2validator, fastapi)
#   - google-re2 availability (warn if missing; ADR-0049)
#   - Chromium present
#   - Chromium launches sandboxed (proves seccomp profile grants user namespaces)
#   - optionally: sample report processed end-to-end (--job)
#   - no traceback in logs
#
# Usage: bash scripts/docker_smoke.sh [--no-build] [--job] [--keep] [--clean]
#   --no-build  reuse the existing image instead of building it
#   --job       upload tests/fixtures/sample_report.txt and wait for the job to finish
#   --keep      leave the stack running afterwards
#   --clean     `docker compose down -v` afterwards (DELETES the volumes)
# Environment: DOCKER_BIN (default: docker), CTI_BIND / CTI_PORT (as in compose.yaml),
#              SMOKE_JOB_TIMEOUT (seconds, default 1800), SMOKE_HEALTH_TIMEOUT (default 180)

set -u

# ── Colors ────────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m'

FAILS=0

pass() {
    echo -e "${GREEN}PASS${NC}  $1"
}

fail() {
    echo -e "${RED}FAIL${NC}  $1"
    FAILS=$((FAILS + 1))
}

warn() {
    echo -e "${YELLOW}WARN${NC}  $1"
}

info() {
    echo -e "${BLUE}INFO${NC}  $1"
}

# ── Argument parsing ──────────────────────────────────────────────────────────
NO_BUILD=false
DO_JOB=false
KEEP=false
CLEAN=false

for arg in "$@"; do
    case "$arg" in
        --no-build) NO_BUILD=true ;;
        --job)      DO_JOB=true ;;
        --keep)     KEEP=true ;;
        --clean)    CLEAN=true ;;
        *)          echo "Unknown option: $arg"; exit 2 ;;
    esac
done

# ── Prerequisites ─────────────────────────────────────────────────────────────
command -v curl >/dev/null 2>&1 || { echo "ERROR: curl is required on the host"; exit 1; }
command -v python3 >/dev/null 2>&1 || { echo "ERROR: python3 is required on the host"; exit 1; }

# compose.yaml bind-mounts .secrets/db_password into every service at
# /run/secrets/db_password (see its top-of-file comment) so CTI_DB_PASSWORD
# never appears in `docker inspect`/`docker compose config` output. This
# script drives `docker compose` directly rather than through the Makefile
# (whose `docker-up`/`docker-bootstrap` targets do this via a file
# prerequisite), so it materializes the same file itself.
CTI_ENV_FILE="${CTI_ENV_FILE:-.env}"
mkdir -p .secrets
case "$CTI_ENV_FILE" in
    /*) . "$CTI_ENV_FILE" ;;
    *)  . "./$CTI_ENV_FILE" ;;
esac
: "${CTI_DB_PASSWORD:?Set CTI_DB_PASSWORD in $CTI_ENV_FILE (e.g. openssl rand -hex 24)}"
printf '%s' "$CTI_DB_PASSWORD" > .secrets/db_password
# World-readable, not owner-only: app/worker read it as uid 1001 and postgres
# as uid 70, none of which is the host user that just created the file.
chmod 644 .secrets/db_password

# ── Variables ─────────────────────────────────────────────────────────────────
DOCKER_BIN="${DOCKER_BIN:-docker}"
COMPOSE="$DOCKER_BIN compose"
BIND="${CTI_BIND:-127.0.0.1}"
PORT="${CTI_PORT:-8000}"
BASE="http://$BIND:$PORT"
SMOKE_HEALTH_TIMEOUT="${SMOKE_HEALTH_TIMEOUT:-180}"
SMOKE_JOB_TIMEOUT="${SMOKE_JOB_TIMEOUT:-1800}"

# Move to repo root
cd "$(dirname "$0")/.."

# ── Helpers ───────────────────────────────────────────────────────────────────
in_app() {
    $COMPOSE exec -T app "$@"
}

wait_healthy() {
    local start=$(date +%s)
    local timeout=$SMOKE_HEALTH_TIMEOUT
    local id
    while true; do
        id=$($COMPOSE ps -q app 2>/dev/null)
        if [ -n "$id" ]; then
            local status
            status=$($DOCKER_BIN inspect --format '{{.State.Health.Status}}' "$id" 2>/dev/null || echo "unknown")
            if [ "$status" = "healthy" ]; then
                local elapsed=$(( $(date +%s) - start ))
                info "Container healthy after ${elapsed}s"
                return 0
            fi
        fi
        local now=$(date +%s)
        if [ $((now - start)) -ge $timeout ]; then
            info "Timed out waiting for healthy status after ${timeout}s"
            return 1
        fi
        sleep 3
    done
}

# ── Step 1: compose file valid ────────────────────────────────────────────────
info "Checking compose file validity..."
if $COMPOSE config -q; then
    pass "compose file valid"
else
    fail "compose file valid"
fi

# ── Step 2: image built ───────────────────────────────────────────────────────
if [ "$NO_BUILD" = false ]; then
    info "Building image..."
    if $COMPOSE build app; then
        pass "image built"
    else
        fail "image built"
        echo "Aborting: cannot test without a built image."
        exit 1
    fi
else
    info "Skipping build (--no-build)"
    pass "image built (skipped)"
fi

# ── Step 3: container healthy ─────────────────────────────────────────────────
info "Starting containers (api, worker and their database)..."
$COMPOSE up -d app worker
if wait_healthy; then
    pass "container healthy"
else
    fail "container healthy"
    info "Dumping last 80 lines of logs..."
    $COMPOSE logs --tail 80 app
    # Go directly to teardown
    if [ "$CLEAN" = true ]; then
        $COMPOSE down -v
    elif [ "$KEEP" = false ]; then
        $COMPOSE down
    fi
    echo "Smoke test: $FAILS failure(s)"
    exit 1
fi

# ── Step 4: GET /api/health ───────────────────────────────────────────────────
info "Checking /api/health..."
HEALTH_RESP=$(curl -fsS "$BASE/api/health" 2>/dev/null)
if echo "$HEALTH_RESP" | grep -q '"ok"'; then
    pass "GET /api/health"
else
    fail "GET /api/health"
fi

# ── Step 5: web UI served ─────────────────────────────────────────────────────
info "Checking web UI..."
UI_RESP=$(curl -fsS "$BASE/" 2>/dev/null)
if echo "$UI_RESP" | grep -q '<div id="root">'; then
    pass "web UI served"
else
    fail "web UI served"
fi

# ── Step 6: runs as uid 1001 ──────────────────────────────────────────────────
info "Checking user ID..."
UID_OUT=$(in_app id -u 2>/dev/null)
if [ "$UID_OUT" = "1001" ]; then
    pass "runs as uid 1001"
else
    fail "runs as uid 1001 (got: $UID_OUT)"
fi

# ── Step 7: root filesystem read-only ─────────────────────────────────────────
info "Checking root filesystem is read-only..."
FS_OUT=$(in_app sh -c 'touch /app/.smoke-probe 2>/dev/null && echo WRITABLE || echo READONLY' 2>/dev/null)
if [ "$FS_OUT" = "READONLY" ]; then
    pass "root filesystem read-only"
else
    fail "root filesystem read-only (got: $FS_OUT)"
fi

# ── Step 8: state and cache volumes writable ──────────────────────────────────
info "Checking volume writability..."
if in_app sh -c 'touch /app/state/.probe /app/cache/.probe && rm /app/state/.probe /app/cache/.probe' 2>/dev/null; then
    pass "state and cache volumes writable"
else
    fail "state and cache volumes writable"
fi

# ── Step 9: symlinks resolve into the volumes ─────────────────────────────────
info "Checking symlinks..."
UPLOADS_LINK=$(in_app readlink /app/uploads 2>/dev/null)
CORPORA_LINK=$(in_app readlink /app/corpora 2>/dev/null)
if [ "$UPLOADS_LINK" = "/app/state/uploads" ] && [ "$CORPORA_LINK" = "/app/cache/corpora" ]; then
    pass "symlinks resolve into the volumes"
else
    fail "symlinks resolve into the volumes (uploads: $UPLOADS_LINK, corpora: $CORPORA_LINK)"
fi

# ── Step 9b: job store on PostgreSQL (ADR-0045) ───────────────────────────────
# `backend()` answers from DATABASE_URL, and the round trip proves the app can
# actually reach the postgres service with the password compose handed it.
info "Checking the job store backend..."
BACKEND_OUT=$(in_app python -c "from api.db import backend, get_conn; print(backend(), get_conn().execute('SELECT 1').fetchone()[0])" 2>/dev/null)
if [ "$BACKEND_OUT" = "postgresql 1" ]; then
    pass "job store is PostgreSQL and answers"
else
    fail "job store is PostgreSQL and answers (got: $BACKEND_OUT)"
fi

# ── Step 9c: the worker container is up and owns the queue (ADR-0046) ────────
info "Checking the worker container..."
WORKER_ID=$($COMPOSE ps -q worker 2>/dev/null)
WORKER_STATE=$($DOCKER_BIN inspect --format '{{.State.Health.Status}}' "$WORKER_ID" 2>/dev/null || echo "missing")
for _ in $(seq 1 20); do
    [ "$WORKER_STATE" = "healthy" ] && break
    sleep 3
    WORKER_STATE=$($DOCKER_BIN inspect --format '{{.State.Health.Status}}' "$WORKER_ID" 2>/dev/null || echo "missing")
done
if [ "$WORKER_STATE" = "healthy" ]; then
    pass "worker container healthy"
else
    fail "worker container healthy (got: $WORKER_STATE)"
fi
API_ROLE=$(in_app python -c "from api import queue_loop; print(queue_loop.role())" 2>/dev/null)
if [ "$API_ROLE" = "api" ]; then
    pass "API runs with role api (never loads a model)"
else
    fail "API runs with role api (got: $API_ROLE)"
fi

# ── Step 9d: queue-status endpoint answers (ADR-0048) ─────────────────────────
info "Checking GET /api/queue/status..."
QUEUE_ROLE=$(curl -fsS "$BASE/api/queue/status" 2>/dev/null | python3 -c 'import json,sys; print(json.load(sys.stdin).get("role"))' 2>/dev/null)
if [ "$QUEUE_ROLE" = "api" ]; then
    pass "queue status endpoint answers (role: $QUEUE_ROLE)"
else
    fail "queue status endpoint answers (got role: $QUEUE_ROLE)"
fi

# ── Step 10: python imports ───────────────────────────────────────────────────
info "Checking Python imports..."
if in_app python -c "import magic, playwright, sentence_transformers, transformers, gliner, stix2validator, fastapi" 2>/dev/null; then
    pass "python imports"
else
    fail "python imports"
fi

# ── Step 11: google-re2 available (ADR-0049) ──────────────────────────────────
info "Checking re2..."
if in_app python -c "import re2" 2>/dev/null; then
    pass "re2 available — most Stage 2 regexes run in guaranteed linear time"
else
    warn "re2 not available (Stage 2 falls back to the stdlib re module)"
fi

# ── Step 12: chromium present ─────────────────────────────────────────────────
info "Checking Chromium presence..."
if in_app python -c "from pipeline.web_capture import check_chromium_installed as c; import sys; h = c(); print(h or 'chromium present'); sys.exit(1 if h else 0)" 2>/dev/null; then
    pass "chromium present"
else
    fail "chromium present"
fi

# ── Step 13: chromium launches sandboxed ──────────────────────────────────────
# This is the check that proves the seccomp profile grants user namespaces;
# without it Chromium dies at launch with "No usable sandbox".
info "Checking Chromium sandbox launch..."
if in_app python -c "
from playwright.sync_api import sync_playwright
with sync_playwright() as p:
    b = p.chromium.launch(headless=True, chromium_sandbox=True)
    print('chromium', b.version)
    b.close()
" 2>/dev/null; then
    pass "chromium launches sandboxed"
else
    fail "chromium launches sandboxed"
fi

# ── Step 14: sample report processed (optional) ───────────────────────────────
if [ "$DO_JOB" = true ]; then
    info "Uploading sample report..."
    UPLOAD_RESP=$(curl -fsS -F "file=@tests/fixtures/sample_report.txt" "$BASE/api/upload" 2>/dev/null)
    if [ -z "$UPLOAD_RESP" ]; then
        fail "sample report processed (upload failed)"
    else
        JOB_ID=$(echo "$UPLOAD_RESP" | python3 -c 'import json,sys; print(json.load(sys.stdin)["job_id"])' 2>/dev/null)
        if [ -z "$JOB_ID" ]; then
            fail "sample report processed (no job_id in response)"
        else
            info "Job ID: $JOB_ID — waiting for completion (timeout: ${SMOKE_JOB_TIMEOUT}s)..."
            JOB_START=$(date +%s)
            FINAL_STATUS=""
            while true; do
                JOB_RESP=$(curl -fsS "$BASE/api/jobs/$JOB_ID" 2>/dev/null)
                STATUS=$(echo "$JOB_RESP" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("status",""))' 2>/dev/null)
                if [ -z "$STATUS" ] || ! echo "$STATUS" | grep -qE '^(uploaded|queued|processing)$'; then
                    FINAL_STATUS="$STATUS"
                    break
                fi
                NOW=$(date +%s)
                if [ $((NOW - JOB_START)) -ge $SMOKE_JOB_TIMEOUT ]; then
                    FINAL_STATUS="timeout"
                    break
                fi
                sleep 5
            done

            if [ -n "$FINAL_STATUS" ] && [ "$FINAL_STATUS" != "failed" ]; then
                pass "sample report processed (status: $FINAL_STATUS)"
                # The report must have run in the worker container, not in the API.
                if $COMPOSE logs worker 2>&1 | grep -q "Spawning isolated subprocess for job $JOB_ID"; then
                    pass "report was processed by the worker container"
                else
                    fail "report was processed by the worker container (no spawn line in its logs)"
                fi
                if $COMPOSE logs app 2>&1 | grep -q "Spawning isolated subprocess"; then
                    fail "API container spawned no pipeline process"
                else
                    pass "API container spawned no pipeline process"
                fi
                # Check bundle export
                COUNTS=$(echo "$JOB_RESP" | python3 -c "import json,sys; d=json.load(sys.stdin); print(str(d.get('entity_count')) + ' entities, ' + str(d.get('relationship_count')) + ' relationships')" 2>/dev/null)
                info "Job result: $COUNTS"
                # Parsed, not grepped: FastAPI serialises without spaces, a pretty-printer with them.
                BUNDLE_OBJECTS=$(curl -fsS "$BASE/api/jobs/$JOB_ID/bundle" 2>/dev/null \
                    | python3 -c 'import json,sys; d=json.load(sys.stdin); print(len(d["objects"]) if d.get("type") == "bundle" else "")' 2>/dev/null)
                if [ -n "$BUNDLE_OBJECTS" ]; then
                    pass "bundle exported ($BUNDLE_OBJECTS STIX objects)"
                else
                    fail "bundle exported"
                fi
            else
                fail "sample report processed (final status: $FINAL_STATUS)"
            fi
        fi
    fi
fi

# ── Step 15: no traceback in the logs ─────────────────────────────────────────
info "Checking logs for tracebacks..."
TRACEBACK_COUNT=$($COMPOSE logs app 2>&1 | grep -ci traceback || true)
if [ "$TRACEBACK_COUNT" -gt 0 ]; then
    warn "no traceback in the logs (found $TRACEBACK_COUNT)"
else
    pass "no traceback in the logs"
fi

# ── Step 16: Teardown ─────────────────────────────────────────────────────────
if [ "$KEEP" = true ]; then
    info "Keeping stack running (--keep)"
elif [ "$CLEAN" = true ]; then
    info "Tearing down with volume deletion (--clean)..."
    $COMPOSE down -v
else
    info "Tearing down stack..."
    $COMPOSE down
fi

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
if [ $FAILS -gt 0 ]; then
    echo -e "${RED}Smoke test: $FAILS failure(s)${NC}"
    exit 1
else
    echo -e "${GREEN}Smoke test: 0 failure(s)${NC}"
    exit 0
fi
