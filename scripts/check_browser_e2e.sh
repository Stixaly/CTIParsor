#!/usr/bin/env bash
# The browser journey (ADR-0094 item 4): Playwright drives the built interface
# against the real API, its worker and PostgreSQL, offline.
#
#   scripts/check_browser_e2e.sh [--no-build] [--docker] [--network-guard] [-- PLAYWRIGHT ARGS]
#
# 1. builds the interface (cd frontend && npm run build), unless --no-build;
# 2. creates a new database on the PostgreSQL server CTIPARSOR_TEST_DATABASE_URL
#    names, and throwaway state, uploads, output and home directories;
# 3. starts `python run_api.py` (role all: the API and its worker, which runs
#    each report in a subprocess) on 127.0.0.1:E2E_PORT with `env -i` and the
#    variables below only: no .env (PYTHON_DOTENV_DISABLED), no key, no model
#    (SKIP_HEAVY_MODELS), no LLM, vision or CVE stage (PIPELINE_DISABLED_STAGES:
#    every stage that loads a model, calls an LLM or reaches the network);
# 4. waits for GET /api/health (E2E_HEALTH_TIMEOUT seconds, default 180), then
#    seeds the report whose bundle the schemas refused (scripts/browser_e2e_db.py);
# 5. runs `npx playwright test` in frontend/ (frontend/playwright.config.ts,
#    frontend/e2e/) with E2E_BASE_URL, and any arguments given after --;
# 6. prints each report's stage report, and fails if a stage the profile turns
#    off ran;
# 7. with --network-guard, runs the API and everything it starts under a group
#    of its own (E2E_GUARD_GID, default 64999, which must be unused) and
#    counts with iptables/ip6tables every packet that group sends anywhere but
#    loopback: each is rejected, and the run fails unless the count is 0.  The
#    rule goes first in OUTPUT, before any ACCEPT the host's firewall has.  A
#    canary connection from that group is refused and counted first, so the
#    guard is shown to work.  Needs sudo without a password (CI) or root.
#    The browser runs as the calling user: its own traffic is not counted.
#    A DNS lookup sent to a resolver on loopback (127.0.0.53) is not counted:
#    the resolver, not the API, sends it on; a connection after it is.
#
# Run as root (the guard, locally), the script builds the interface and runs
# the API as the checkout's owner: nothing in the checkout is left to root, and
# the API cannot leave the guard's group.
#
# Stops the API, removes the iptables rules, drops the database and removes
# the directories whatever happens.  The API's log is copied to
# frontend/test-results/api.log.
#
# Options:
#   --no-build        use the existing frontend/dist
#   --docker          run Playwright in mcr.microsoft.com/playwright:v<version>-noble
#                     (the version of frontend/node_modules/@playwright/test),
#                     with --network host: no browser to install on this host
#   --network-guard   step 7
# Environment: CTIPARSOR_TEST_DATABASE_URL (required), PYTHON (default
#   .venv/bin/python, else python3), E2E_PORT (default 8765),
#   E2E_HEALTH_TIMEOUT, E2E_GUARD_GID, DOCKER_BIN (default docker).
# Needs frontend/node_modules (npm ci) and, without --docker, Playwright's
# Chromium (npx playwright install --with-deps chromium).
#
# Exit: Playwright's code when it fails; else 1 when the stage report or the
# guard fails; 0 when everything passed; 2 when the journey cannot run (a
# missing tool or variable, a port in use, the guard's chain left by a killed
# run, a build, database or API that would not start).

set -u
set -o pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FRONTEND="$ROOT/frontend"
PORT="${E2E_PORT:-8765}"
BASE_URL="http://127.0.0.1:$PORT"
HEALTH_TIMEOUT="${E2E_HEALTH_TIMEOUT:-180}"
GUARD_GID="${E2E_GUARD_GID:-64999}"
DOCKER_BIN="${DOCKER_BIN:-docker}"
CHAIN="CTIPARSOR_E2E_EGRESS"
# Every stage that loads a model (1f 2c 2d 2e), calls an LLM (3 3d 3f 3e 3doc
# 4c) or reaches the network (1f 2f), from pipeline/orchestrator.py's STAGES.
DISABLED_STAGES="1f,2c,2d,2e,3,3d,3f,3e,3doc,2f,4c"

BUILD=1
USE_DOCKER=0
GUARD=0
PW_ARGS=()
while [ $# -gt 0 ]; do
    case "$1" in
        --no-build) BUILD=0 ;;
        --docker) USE_DOCKER=1 ;;
        --network-guard) GUARD=1 ;;
        --) shift; PW_ARGS=("$@"); break ;;
        -h|--help) sed -n '2,/^$/p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "check_browser_e2e: unknown option $1 (see --help)" >&2; exit 2 ;;
    esac
    shift
done

say() { echo "== $*"; }
unusable() { echo "check_browser_e2e: $*" >&2; exit 2; }

if [ -z "${PYTHON:-}" ]; then
    if [ -x "$ROOT/.venv/bin/python" ]; then PYTHON="$ROOT/.venv/bin/python"; else PYTHON="$(command -v python3 || true)"; fi
fi
[ -n "$PYTHON" ] && "$PYTHON" -c 'import sys' 2>/dev/null || unusable "no Python: set PYTHON"
PYTHON="$(command -v "$PYTHON")"
[ -n "${CTIPARSOR_TEST_DATABASE_URL:-}" ] || unusable "CTIPARSOR_TEST_DATABASE_URL is not set"
command -v curl >/dev/null || unusable "curl is missing"
command -v npm >/dev/null || unusable "npm is missing"
[ -f "$FRONTEND/node_modules/@playwright/test/package.json" ] || unusable "frontend/node_modules has no @playwright/test: run npm ci in frontend/"
if (exec 3<>"/dev/tcp/127.0.0.1/$PORT") 2>/dev/null; then
    unusable "port $PORT is in use: set E2E_PORT"
fi
# Who the build and the API run as: the checkout's owner when root runs this
# script, else the caller.
OWNER_UG="$(stat -c %u:%g "$FRONTEND")"
if [ "$(id -u)" = 0 ]; then
    APP_UID="$(stat -c %u "$ROOT")"
    APP_GID="$(stat -c %g "$ROOT")"
else
    APP_UID="$(id -u)"
    APP_GID="$(id -g)"
fi
SUDO=()
if [ "$GUARD" = 1 ]; then
    [ "$(id -u)" = 0 ] || SUDO=(sudo -n)
    "${SUDO[@]}" true 2>/dev/null || unusable "--network-guard needs sudo without a password, or root"
    getent group "$GUARD_GID" >/dev/null && unusable "group $GUARD_GID exists: set E2E_GUARD_GID to an unused gid"
fi
if [ "$GUARD" = 1 ] || [ "$(id -u)" = 0 ]; then
    command -v setpriv >/dev/null || unusable "setpriv (util-linux) is missing: --network-guard and a run as root need it"
fi

# The commands that remove the guard's chain when a run that was killed left it.
leftover_chain() {
    local tool rule
    for tool in iptables ip6tables; do
        "${SUDO[@]}" "$tool" -w -n -L "$CHAIN" >/dev/null 2>&1 || continue
        "${SUDO[@]}" "$tool" -w -S OUTPUT | grep -- "-j $CHAIN\$" | while read -r rule; do
            echo "  sudo $tool -w ${rule/#-A /-D }"
        done
        echo "  sudo $tool -w -F $CHAIN"
        echo "  sudo $tool -w -X $CHAIN"
    done
}
if [ "$GUARD" = 1 ]; then
    left="$(leftover_chain)"
    if [ -n "$left" ]; then
        echo "check_browser_e2e: the chain $CHAIN already exists: another run is using it, or a run that was killed left it." >&2
        echo "If no other run is in progress, remove it with:" >&2
        echo "$left" >&2
        exit 2
    fi
fi

TMP="$(mktemp -d "${TMPDIR:-/tmp}/ctiparsor-e2e.XXXXXX")" || unusable "mktemp failed"
chmod 755 "$TMP"
DB_URL=""
API_PID=""
GUARD_SET=0

guard_rules() {   # $@: -I OUTPUT 1 (first in OUTPUT) or -D OUTPUT
    local tool
    for tool in iptables ip6tables; do
        "${SUDO[@]}" "$tool" -w "$@" -m owner --gid-owner "$GUARD_GID" -j "$CHAIN" 2>/dev/null || return 1
    done
}

# The API runs under sudo with the guard: only sudo may signal it then.
api_alive() { [ -n "$API_PID" ] && "${SUDO[@]}" kill -0 "$API_PID" 2>/dev/null; }

cleanup() {
    local code=$?
    if api_alive; then
        "${SUDO[@]}" kill -TERM "$API_PID" 2>/dev/null
        for _ in $(seq 1 30); do api_alive || break; sleep 0.5; done
        api_alive && "${SUDO[@]}" kill -KILL "$API_PID" 2>/dev/null
    fi
    if [ "$GUARD_SET" = 1 ]; then
        guard_rules -D OUTPUT
        for tool in iptables ip6tables; do
            "${SUDO[@]}" "$tool" -w -F "$CHAIN" 2>/dev/null
            "${SUDO[@]}" "$tool" -w -X "$CHAIN" 2>/dev/null
        done
    fi
    if [ -f "$TMP/api.log" ]; then
        mkdir -p "$FRONTEND/test-results" && cp "$TMP/api.log" "$FRONTEND/test-results/api.log"
    fi
    # Run as root (the guard, locally): what the run leaves belongs to the checkout's owner.
    if [ "$(id -u)" = 0 ]; then
        chown -R "$OWNER_UG" "$FRONTEND/test-results" "$FRONTEND/playwright-report" 2>/dev/null
    fi
    if [ -n "$DB_URL" ]; then
        "$PYTHON" "$ROOT/scripts/browser_e2e_db.py" drop "$DB_URL" || echo "check_browser_e2e: could not drop the database" >&2
    fi
    "${SUDO[@]}" rm -rf "$TMP"
    exit "$code"
}
trap cleanup EXIT
trap 'exit 130' INT TERM

if [ "$BUILD" = 1 ]; then
    say "building the interface"
    if [ "$(id -u)" = 0 ]; then
        # As the owner of frontend/, as `docker run -u` below: dist/ is theirs.
        mkdir -p "$TMP/build-home" && chown "$OWNER_UG" "$TMP/build-home"
        (cd "$FRONTEND" && setpriv --reuid="${OWNER_UG%:*}" --regid="${OWNER_UG#*:}" --clear-groups -- \
            env HOME="$TMP/build-home" npm run build) || unusable "npm run build failed"
    else
        (cd "$FRONTEND" && npm run build) || unusable "npm run build failed"
    fi
fi
[ -f "$FRONTEND/dist/index.html" ] || unusable "frontend/dist is missing: run without --no-build"

say "creating the database"
DB_URL="$("$PYTHON" "$ROOT/scripts/browser_e2e_db.py" create)" || unusable "no database"
mkdir -p "$TMP/state/uploads" "$TMP/state/output" "$TMP/home" "$TMP/tmp"
# Under root, the API's directories belong to the user it runs as.
if [ "$(id -u)" = 0 ]; then
    chown -R "$APP_UID:$APP_GID" "$TMP"
fi

# The API's whole environment: nothing else reaches it.
API_ENV=(
    "PATH=$(dirname "$PYTHON"):/usr/local/bin:/usr/bin:/bin"
    "HOME=$TMP/home" "TMPDIR=$TMP/tmp" "LANG=C.UTF-8" "PYTHONUNBUFFERED=1"
    "PYTHON_DOTENV_DISABLED=1"
    "DATABASE_URL=$DB_URL" "CTIPARSOR_ROLE=all" "WORKER_MAX_CONCURRENT=3"
    "CTIPARSOR_STATE_DIR=$TMP/state" "CTIPARSOR_UPLOADS_DIR=$TMP/state/uploads"
    "CTIPARSOR_OUTPUT_DIR=$TMP/state/output" "WORKER_ALIVE_FILE=$TMP/state/worker.alive"
    "API_HOST=127.0.0.1" "API_PORT=$PORT" "API_WORKERS=1" "API_RELOAD=0"
    "API_ALLOWED_HOSTS=127.0.0.1,localhost"
    "SKIP_HEAVY_MODELS=1" "PIPELINE_DISABLED_STAGES=$DISABLED_STAGES"
    "VISION_PROVIDER=none" "CVE_ENRICHMENT=false" "HF_HUB_OFFLINE=1" "TRANSFORMERS_OFFLINE=1"
    "STIX_ENRICHMENT_ENABLED=true" "REVIEW_CONTROL_SAMPLE_RATE=0"
)
# Who the API runs as: under the guard, its user with the guard's group only;
# under root, the checkout's owner; else the caller, as is.  setpriv and env
# exec what follows, so $! below is the API itself (or sudo, which relays).
APP_AS=()
if [ "$GUARD" = 1 ]; then
    APP_AS=("${SUDO[@]}" setpriv --reuid="$APP_UID" --regid="$GUARD_GID" --clear-groups --)
elif [ "$(id -u)" = 0 ]; then
    APP_AS=(setpriv --reuid="$APP_UID" --regid="$APP_GID" --clear-groups --)
fi
as_app() { "${APP_AS[@]}" env -i "${API_ENV[@]}" "$@"; }

if [ "$GUARD" = 1 ]; then
    say "network guard: group $GUARD_GID, every packet off loopback rejected and counted"
    for tool in iptables ip6tables; do
        "${SUDO[@]}" "$tool" -w -N "$CHAIN" || unusable "$tool cannot create a chain"
        GUARD_SET=1
        "${SUDO[@]}" "$tool" -w -A "$CHAIN" -o lo -j RETURN || unusable "$tool: rule refused"
        "${SUDO[@]}" "$tool" -w -A "$CHAIN" -j REJECT || unusable "$tool: rule refused"
    done
    guard_rules -I OUTPUT 1 || unusable "the owner match is not available (iptables -m owner)"
    # The canary: a connection from that group to TEST-NET-1 must be refused and counted.
    as_app "$PYTHON" -c 'import socket, sys
s = socket.socket()
s.settimeout(5)
try:
    s.connect(("192.0.2.1", 9))
except ConnectionRefusedError:
    sys.exit(0)
except OSError:
    sys.exit(3)
sys.exit(4)' || unusable "the guard did not refuse the canary connection"
    canary="$("${SUDO[@]}" iptables -w -n -v -x -L "$CHAIN" | awk '$3 == "REJECT" {print $1}')"
    [ "${canary:-0}" -ge 1 ] || unusable "the guard did not count the canary"
    "${SUDO[@]}" iptables -w -Z "$CHAIN" && "${SUDO[@]}" ip6tables -w -Z "$CHAIN" || unusable "cannot zero the counters"
    echo "canary refused and counted ($canary packet(s)); counters reset"
fi

say "starting the API on $BASE_URL"
cd "$ROOT" || unusable "cannot enter $ROOT"
# Not through as_app: $! must be the API itself (or sudo, which relays), not a subshell.
"${APP_AS[@]}" env -i "${API_ENV[@]}" "$PYTHON" run_api.py >"$TMP/api.log" 2>&1 &
API_PID=$!
deadline=$((SECONDS + HEALTH_TIMEOUT))
until curl -fsS -o /dev/null "$BASE_URL/api/health" 2>/dev/null; do
    if ! api_alive; then tail -n 60 "$TMP/api.log"; unusable "the API stopped"; fi
    if [ "$SECONDS" -ge "$deadline" ]; then tail -n 60 "$TMP/api.log"; unusable "no healthy API after $HEALTH_TIMEOUT s"; fi
    sleep 1
done
curl -fsS "$BASE_URL/" | grep -q '<div id="root">' || unusable "the API does not serve the built interface"

say "seeding the refused report"
as_app "$PYTHON" "$ROOT/scripts/browser_e2e_db.py" seed "$DB_URL" || unusable "seeding failed"

say "running Playwright"
if [ "$USE_DOCKER" = 1 ]; then
    version="$(node -p "require('$FRONTEND/node_modules/@playwright/test/package.json').version")" || unusable "no Playwright version"
    "$DOCKER_BIN" run --rm --network host --ipc host -u "$(stat -c %u:%g "$FRONTEND")" -e HOME=/tmp \
        -e NPM_CONFIG_UPDATE_NOTIFIER=false -e CI="${CI:-}" -e E2E_BASE_URL="$BASE_URL" \
        -v "$ROOT:/repo" -w /repo/frontend \
        "mcr.microsoft.com/playwright:v$version-noble" npx playwright test "${PW_ARGS[@]}"
    PW_CODE=$?
else
    (cd "$FRONTEND" && E2E_BASE_URL="$BASE_URL" npx playwright test "${PW_ARGS[@]}")
    PW_CODE=$?
fi
echo "Playwright exited $PW_CODE"

say "stage report"
as_app "$PYTHON" "$ROOT/scripts/browser_e2e_db.py" stages "$DB_URL"
STAGES_CODE=$?

GUARD_CODE=0
if [ "$GUARD" = 1 ]; then
    v4="$("${SUDO[@]}" iptables -w -n -v -x -L "$CHAIN" | awk '$3 == "REJECT" {print $1}')"
    v6="$("${SUDO[@]}" ip6tables -w -n -v -x -L "$CHAIN" | awk '$3 == "REJECT" {print $1}')"
    if [ "${v4:-x}" = 0 ] && [ "${v6:-x}" = 0 ]; then
        echo "network guard: 0 packets from the API and its worker left loopback"
    else
        echo "FAIL network guard: the API or its worker sent packets off loopback (IPv4 ${v4:-?}, IPv6 ${v6:-?}), all rejected"
        GUARD_CODE=1
    fi
fi

if [ "$PW_CODE" -ne 0 ]; then
    tail -n 60 "$TMP/api.log"
    exit "$PW_CODE"
fi
[ "$STAGES_CODE" -eq 0 ] && [ "$GUARD_CODE" -eq 0 ] || exit 1
say "browser journey passed"
exit 0
