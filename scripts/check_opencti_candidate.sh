#!/usr/bin/env bash
# The OpenCTI import of a candidate image (ADR-0094 item 8): the A4 recipe
# (scripts/opencti_import_check.py) on bundles the candidate itself produced,
# tied to its image digest and its commit.  Never in CI: it starts two stacks,
# one after the other, and OpenCTI takes about 4 GB of RAM (TESTING.md).
#
#   scripts/check_opencti_candidate.sh --image REF [--out DIR]
#   scripts/check_opencti_candidate.sh --bundles DIR [--out DIR]
#
# 1. resolves REF: `name@sha256:<digest>` is used as given (pulled when
#    absent), a tag is pulled and named by its registry digest; reads the
#    commit from the label org.opencontainers.image.revision;
# 2. starts the candidate's app, worker and database from compose.yaml in a
#    Compose project of its own, ctiparsor-opencti-candidate, with CTI_IMAGE
#    set to that digest, the browser journey's offline profile (no model, LLM,
#    vision, CVE or network stage) and a database password generated for the
#    run: the checkout's .env and .secrets/ are not read;
# 3. produces three bundles through its API (scripts/opencti_candidate_bundles.py),
#    reads the commit each job recorded (run_config's git_rev; a job with none
#    is read as `(none)` and fails step 0), then removes the project and its
#    volumes;
# 4. starts a throwaway OpenCTI, docker/opencti-test/compose.yaml in the
#    project ctiparsor-opencti-check, with secrets generated for the run
#    (docker/opencti-test/.env is not read), and waits for its health
#    endpoint and its API;
# 5. runs scripts/opencti_import_check.py in the pycti venv: the baseline,
#    the enriched, the rejected and the full bundle, each imported twice;
# 6. writes report.json and report.md (scripts/opencti_expectations.py) next
#    to the bundles, the run's record (run.json: the candidate, where the
#    bundles come from, the checkout's commit and whether tracked files are
#    modified, the sha256 of the check's scripts and fixtures) and the check's
#    results;
# 7. removes the OpenCTI project and its volumes, whatever happened.
#
# --bundles DIR skips steps 1 to 3: it imports the bundles a previous run
# wrote in DIR (DIR/bundles, DIR/candidate.json), copied into the new report,
# which says they were not produced by this run and names DIR and the run
# that made them.  The report goes to --out, by default
# output/opencti-candidate/<UTC time>/.
#
# Every `docker compose` call runs under `env -i` with PATH, HOME and the
# DOCKER_* variables only: Compose would otherwise let an exported CTI_IMAGE,
# CTI_ENV_FILE or OPENCTI_* win over the files this script writes.  Python
# runs with PYTHONDONTWRITEBYTECODE=1: run as root, it would leave root-owned
# bytecode in the checkout.
#
# The check creates a role, a group, a user and an API token in OpenCTI and
# never revokes them: the instance is deleted at the end.
#
# Environment: DOCKER_BIN (default docker), PYTHON (default python3),
#   PYCTI_VENV (default ~/.cache/ctiparsor-pycti-7.260930.0 of the checkout's
#   owner; created from requirements/requirements-opencti.lock.txt, see the
#   message when it is missing), CANDIDATE_PORT (default 8790),
#   CANDIDATE_TIMEOUT (seconds a report may take, default 600),
#   OPENCTI_READY_TIMEOUT (seconds, default 900), OPENCTI_MIN_AVAILABLE_MB
#   (memory free -m must show available before OpenCTI starts, default 8000).
# Run it as root when Docker needs root: what it writes goes to the checkout's owner.
#
# Exit 0 when every expectation holds, 1 when one fails, 2 when the check
# cannot run (a missing tool or venv, a port or project in use, an image with
# no digest or commit, a stack that would not start, a candidate that failed).

set -u
set -o pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DOCKER_BIN="${DOCKER_BIN:-docker}"
PYTHON="${PYTHON:-python3}"
CANDIDATE_PROJECT=ctiparsor-opencti-candidate
OPENCTI_PROJECT=ctiparsor-opencti-check
CANDIDATE_PORT="${CANDIDATE_PORT:-8790}"
CANDIDATE_TIMEOUT="${CANDIDATE_TIMEOUT:-600}"
OPENCTI_URL="http://127.0.0.1:4000"
OPENCTI_READY_TIMEOUT="${OPENCTI_READY_TIMEOUT:-900}"
OPENCTI_MIN_AVAILABLE_MB="${OPENCTI_MIN_AVAILABLE_MB:-8000}"
PYCTI_VERSION=7.260930.0
# The browser journey's offline profile (scripts/check_browser_e2e.sh).
DISABLED_STAGES="1f,2c,2d,2e,3,3d,3f,3e,3doc,2f,4c"
PROFILE="offline: PIPELINE_DISABLED_STAGES=$DISABLED_STAGES, SKIP_HEAVY_MODELS=1, CVE_ENRICHMENT=false, VISION_PROVIDER=none"
# Compose interpolates the caller's environment before --env-file: an exported
# CTI_IMAGE or CTI_ENV_FILE would replace the digest or the env file written
# below.  Every compose call gets PATH, HOME and Docker's own variables only.
CLEAN_ENV=(env -i "PATH=$PATH" "HOME=${HOME:-/root}")
for var in DOCKER_HOST DOCKER_CONTEXT DOCKER_CONFIG DOCKER_CERT_PATH DOCKER_TLS_VERIFY; do
    [ -n "${!var:-}" ] && CLEAN_ENV+=("$var=${!var}")
done
export PYTHONDONTWRITEBYTECODE=1

IMAGE=""
FROM=""
OUT=""
while [ $# -gt 0 ]; do
    case "$1" in
        --image) IMAGE="${2:-}"; shift ;;
        --bundles) FROM="${2:-}"; shift ;;
        --out) OUT="${2:-}"; shift ;;
        -h|--help) sed -n '2,/^$/p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "check_opencti_candidate: unknown option $1 (see --help)" >&2; exit 2 ;;
    esac
    shift
done

say() { echo "== $*"; }
unusable() { echo "check_opencti_candidate: $*" >&2; exit 2; }

{ [ -n "$IMAGE" ] && [ -z "$FROM" ]; } || { [ -z "$IMAGE" ] && [ -n "$FROM" ]; } \
    || unusable "give --image REF, or --bundles DIR (see --help)"
command -v "$DOCKER_BIN" >/dev/null || unusable "$DOCKER_BIN is missing"
"$DOCKER_BIN" compose version >/dev/null 2>&1 || unusable "docker compose (v2) is missing"
command -v curl >/dev/null || unusable "curl is missing"
"$PYTHON" -c 'import sys' 2>/dev/null || unusable "no Python: set PYTHON"
command -v free >/dev/null || unusable "free (procps) is missing"

# The checkout's owner: who the report belongs to, and whose home holds the pycti venv.
OWNER_UG="$(stat -c %u:%g "$ROOT")"
OWNER_HOME="$(getent passwd "${OWNER_UG%:*}" | cut -d: -f6)"
PYCTI_VENV="${PYCTI_VENV:-${OWNER_HOME:-$HOME}/.cache/ctiparsor-pycti-$PYCTI_VERSION}"
PYCTI_PY="$PYCTI_VENV/bin/python"
found="$("$PYCTI_PY" -c 'from importlib.metadata import version; print(version("pycti"))' 2>/dev/null)"
if [ "$found" != "$PYCTI_VERSION" ]; then
    echo "check_opencti_candidate: no pycti $PYCTI_VERSION in $PYCTI_VENV (found: ${found:-none}). Create it, as the checkout's owner:" >&2
    echo "  python3 -m venv $PYCTI_VENV" >&2
    echo "  $PYCTI_VENV/bin/pip install --require-hashes --no-deps -r requirements/requirements-opencti.lock.txt" >&2
    exit 2
fi

port_free() { ! (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null; }
port_free 4000 || unusable "port 4000 is in use (another OpenCTI?): docker/opencti-test/compose.yaml publishes it"
[ -n "$FROM" ] || port_free "$CANDIDATE_PORT" || unusable "port $CANDIDATE_PORT is in use: set CANDIDATE_PORT"
for project in "$CANDIDATE_PROJECT" "$OPENCTI_PROJECT"; do
    left="$("$DOCKER_BIN" ps -aq --filter "label=com.docker.compose.project=$project")$("$DOCKER_BIN" volume ls -q --filter "label=com.docker.compose.project=$project")"
    [ -z "$left" ] || unusable "the Compose project $project exists (a run in progress, or one that was killed). If none is running: $DOCKER_BIN compose -p $project down -v"
done

DEFAULT_OUT=0
[ -n "$OUT" ] || { OUT="$ROOT/output/opencti-candidate/$(date -u +%Y%m%dT%H%M%SZ)"; DEFAULT_OUT=1; }
[ -e "$OUT" ] && [ -n "$(ls -A "$OUT" 2>/dev/null)" ] && unusable "$OUT is not empty"
mkdir -p "$OUT/logs" || unusable "cannot create $OUT"
OUT="$(cd "$OUT" && pwd)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/ctiparsor-opencti.XXXXXX")" || unusable "mktemp failed"
chmod 755 "$TMP"
CANDIDATE=("${CLEAN_ENV[@]}" "$DOCKER_BIN" compose -p "$CANDIDATE_PROJECT" --env-file "$TMP/compose.env" -f "$ROOT/compose.yaml" -f "$TMP/override.yaml")
OPENCTI=("${CLEAN_ENV[@]}" "$DOCKER_BIN" compose -p "$OPENCTI_PROJECT" --env-file "$TMP/opencti.env" -f "$ROOT/docker/opencti-test/compose.yaml")
SAMPLER=""
CANDIDATE_UP=0
OPENCTI_UP=0

cleanup() {
    local code=$?
    trap '' INT TERM   # a second Ctrl-C must not cut the removal short
    [ -n "$SAMPLER" ] && kill "$SAMPLER" 2>/dev/null
    if [ "$CANDIDATE_UP" = 1 ]; then
        "${CANDIDATE[@]}" down -v --remove-orphans >>"$OUT/logs/teardown.log" 2>&1 \
            || echo "check_opencti_candidate: could not remove $CANDIDATE_PROJECT: $DOCKER_BIN compose -p $CANDIDATE_PROJECT down -v" >&2
    fi
    if [ "$OPENCTI_UP" = 1 ]; then
        "${OPENCTI[@]}" logs --no-color --tail 300 >"$OUT/logs/opencti.log" 2>&1
        "${OPENCTI[@]}" down -v --remove-orphans >>"$OUT/logs/teardown.log" 2>&1 \
            || echo "check_opencti_candidate: could not remove $OPENCTI_PROJECT: $DOCKER_BIN compose -p $OPENCTI_PROJECT down -v" >&2
    fi
    rm -rf "$TMP"
    if [ "$(id -u)" = 0 ]; then
        chown -R "$OWNER_UG" "$OUT" 2>/dev/null
        [ "$DEFAULT_OUT" = 1 ] && chown "$OWNER_UG" "$ROOT/output" "$ROOT/output/opencti-candidate" 2>/dev/null
    fi
    exit "$code"
}
trap cleanup EXIT
trap 'exit 130' INT TERM

secret() { head -c "$1" /dev/urandom | od -An -tx1 | tr -d ' \n'; }
BUNDLES_FROM=""
# The checkout that runs the check: its fixtures and expectations, not the candidate's code.
# Read-only git (no optional locks): run as root, it must not rewrite the index.
GIT=(git -c "safe.directory=$ROOT" -C "$ROOT")
CHECKOUT_COMMIT="$("${GIT[@]}" rev-parse HEAD 2>/dev/null)"
CHECKOUT_DIRTY=""
if [ -n "$CHECKOUT_COMMIT" ]; then
    if [ -n "$("${GIT[@]}" --no-optional-locks status --porcelain --untracked-files=no 2>/dev/null)" ]; then
        CHECKOUT_DIRTY=true
    else
        CHECKOUT_DIRTY=false
    fi
fi
CHECKOUT_FILES="$(cd "$ROOT" && sha256sum scripts/check_opencti_candidate.sh scripts/opencti_candidate_bundles.py \
    scripts/opencti_import_check.py scripts/opencti_expectations.py tests/fixtures/sample_report.txt \
    tests/fixtures/baselines/opencti_report.txt tests/fixtures/baselines/opencti_report.json \
    docker/opencti-test/compose.yaml compose.yaml 2>/dev/null)"
STARTED=$SECONDS
CANDIDATE_S=0

if [ -n "$IMAGE" ]; then
    say "resolving $IMAGE"
    repo="${IMAGE%@*}"
    case "${repo##*/}" in *:*) repo="${repo%:*}" ;; esac
    if [[ "$IMAGE" =~ ^[^@]+@sha256:[0-9a-f]{64}$ ]]; then
        # A digest is the candidate as given, never another digest of the same image.
        "$DOCKER_BIN" image inspect "$IMAGE" >/dev/null 2>&1 \
            || "$DOCKER_BIN" pull "$IMAGE" >"$OUT/logs/pull.log" 2>&1 || unusable "cannot pull $IMAGE (logs/pull.log)"
        DIGEST_REF="$IMAGE"
    elif [[ "$IMAGE" == *@* ]]; then
        unusable "$IMAGE: a digest reference is name@sha256:<64 hex digits>"
    else
        "$DOCKER_BIN" pull "$IMAGE" >"$OUT/logs/pull.log" 2>&1 || unusable "cannot pull $IMAGE (logs/pull.log)"
        DIGEST_REF="$("$DOCKER_BIN" image inspect --format '{{range .RepoDigests}}{{println .}}{{end}}' "$IMAGE" | grep -m1 "^$repo@sha256:")"
        [ -n "$DIGEST_REF" ] || unusable "$IMAGE has no registry digest for $repo: a local build cannot be the candidate"
    fi
    COMMIT="$("$DOCKER_BIN" image inspect --format '{{index .Config.Labels "org.opencontainers.image.revision"}}' "$DIGEST_REF")"
    [[ "$COMMIT" =~ ^[0-9a-f]{40}$ ]] || unusable "$DIGEST_REF has no commit in its label org.opencontainers.image.revision (found: '$COMMIT')"
    echo "candidate $DIGEST_REF, commit $COMMIT"

    say "starting the candidate ($CANDIDATE_PROJECT, 127.0.0.1:$CANDIDATE_PORT, offline)"
    t0=$SECONDS
    secret 24 >"$TMP/db_password" && chmod 644 "$TMP/db_password"
    cat >"$TMP/candidate.env" <<EOF
SKIP_HEAVY_MODELS=1
PIPELINE_DISABLED_STAGES=$DISABLED_STAGES
CVE_ENRICHMENT=false
VISION_PROVIDER=none
HF_HUB_OFFLINE=1
TRANSFORMERS_OFFLINE=1
REVIEW_CONTROL_SAMPLE_RATE=0
STIX_ENRICHMENT_ENABLED=true
EOF
    cat >"$TMP/compose.env" <<EOF
CTI_IMAGE=$DIGEST_REF
CTI_BIND=127.0.0.1
CTI_PORT=$CANDIDATE_PORT
CTI_ENV_FILE=$TMP/candidate.env
EOF
    # The password file replaces the checkout's .secrets/db_password: Compose
    # merges a service's volumes by their path in the container.
    cat >"$TMP/override.yaml" <<EOF
services:
  app:
    volumes: ["$TMP/db_password:/run/secrets/db_password:ro"]
  worker:
    volumes: ["$TMP/db_password:/run/secrets/db_password:ro"]
  postgres:
    volumes: ["$TMP/db_password:/run/secrets/db_password:ro"]
EOF
    # Compose never pulls the candidate (--pull never): it is local, by digest.  The
    # database and the proxy, pinned by digest in compose.yaml, are pulled if absent.
    "${CANDIDATE[@]}" pull --quiet --policy missing postgres capture-proxy >"$OUT/logs/candidate-pull.log" 2>&1 \
        || unusable "cannot pull the candidate's database and proxy images (logs/candidate-pull.log)"
    CANDIDATE_UP=1
    "${CANDIDATE[@]}" up -d --no-build --pull never app worker >"$OUT/logs/candidate-up.log" 2>&1 \
        || unusable "the candidate did not start (logs/candidate-up.log)"
    deadline=$((SECONDS + 300))
    until curl -fsS -o /dev/null "http://127.0.0.1:$CANDIDATE_PORT/api/health" 2>/dev/null; do
        [ "$SECONDS" -lt "$deadline" ] || { "${CANDIDATE[@]}" logs --no-color >"$OUT/logs/candidate.log" 2>&1; unusable "no healthy candidate API after 300 s (logs/candidate.log)"; }
        sleep 2
    done

    say "producing the bundles through its API"
    "$PYTHON" "$ROOT/scripts/opencti_candidate_bundles.py" --api "http://127.0.0.1:$CANDIDATE_PORT" \
        --out "$OUT/bundles" --timeout "$CANDIDATE_TIMEOUT" \
        || { "${CANDIDATE[@]}" logs --no-color >"$OUT/logs/candidate.log" 2>&1; unusable "the candidate did not produce the bundles (logs/candidate.log)"; }
    # The commit each job recorded; a job that recorded none reads (none), and step 0 fails on it.
    # shellcheck disable=SC2016  # expanded in the container, where the password file is
    REVS="$("${CANDIDATE[@]}" exec -T postgres sh -c 'PGPASSWORD="$(cat /run/secrets/db_password)" exec psql -v ON_ERROR_STOP=1 -U ctiparsor -d ctiparsor -tA' <<'SQL'
SELECT DISTINCT COALESCE(run_config_json::jsonb->>'git_rev', '(none)') FROM jobs;
SQL
)" || unusable "cannot read the jobs' git_rev from the candidate's database"
    "${CANDIDATE[@]}" logs --no-color >"$OUT/logs/candidate.log" 2>&1
    "${CANDIDATE[@]}" down -v --remove-orphans >"$OUT/logs/candidate-down.log" 2>&1 \
        || unusable "cannot remove $CANDIDATE_PROJECT (logs/candidate-down.log)"
    CANDIDATE_UP=0
    CANDIDATE_S=$((SECONDS - t0))
    IMAGE="$IMAGE" DIGEST_REF="$DIGEST_REF" COMMIT="$COMMIT" REVS="$REVS" PROFILE="$PROFILE" \
        "$PYTHON" -c 'import json, os, sys
json.dump({"image": os.environ["IMAGE"], "digest_ref": os.environ["DIGEST_REF"], "commit": os.environ["COMMIT"],
           "job_git_revs": sorted({r.strip() for r in os.environ["REVS"].split() if r.strip()}),
           "profile": os.environ["PROFILE"]}, open(sys.argv[1], "w"), indent=2)' "$OUT/candidate.json"
else
    [ -f "$FROM/candidate.json" ] && [ -f "$FROM/bundles/manifest.json" ] || unusable "$FROM has no candidate.json and bundles/manifest.json"
    cp -r "$FROM/bundles" "$FROM/candidate.json" "$OUT/" || unusable "cannot copy $FROM"
    BUNDLES_FROM="$(cd "$FROM" && pwd)"
fi
for name in full enriched rejected; do
    [ -f "$OUT/bundles/$name.json" ] || unusable "no $name.json in $OUT/bundles"
done

say "starting a throwaway OpenCTI ($OPENCTI_PROJECT, $OPENCTI_URL)"
available="$(free -m | awk '/^Mem:/ {print $7}')"
[ "${available:-0}" -ge "$OPENCTI_MIN_AVAILABLE_MB" ] \
    || unusable "$available MB available, $OPENCTI_MIN_AVAILABLE_MB needed before OpenCTI starts (OPENCTI_MIN_AVAILABLE_MB)"
BEFORE_MB="$(free -m | awk '/^Mem:/ {print $3}')"
TOTAL_MB="$(free -m | awk '/^Mem:/ {print $2}')"
umask 077
TOKEN="$(cat /proc/sys/kernel/random/uuid)"
HEALTH_KEY="$(cat /proc/sys/kernel/random/uuid)"
cat >"$TMP/opencti.env" <<EOF
OPENCTI_ADMIN_EMAIL=admin@opencti.test
OPENCTI_ADMIN_PASSWORD=$(secret 24)
OPENCTI_ADMIN_TOKEN=$TOKEN
OPENCTI_HEALTHCHECK_ACCESS_KEY=$HEALTH_KEY
OPENCTI_ENCRYPTION_KEY=$(head -c 32 /dev/urandom | base64)
MINIO_ROOT_USER=opencti
MINIO_ROOT_PASSWORD=$(secret 24)
RABBITMQ_DEFAULT_USER=opencti
RABBITMQ_DEFAULT_PASS=$(secret 24)
EOF
printf 'Authorization: Bearer %s\nContent-Type: application/json\n' "$TOKEN" >"$TMP/auth.headers"
umask 022
( while :; do free -m | awk '/^Mem:/ {print $3}'; sleep 5; done ) >"$TMP/memory.log" 2>/dev/null &
SAMPLER=$!
t0=$SECONDS
OPENCTI_UP=1
"${OPENCTI[@]}" up -d >"$OUT/logs/opencti-up.log" 2>&1 || unusable "OpenCTI did not start (logs/opencti-up.log)"
deadline=$((SECONDS + OPENCTI_READY_TIMEOUT))
until curl -fsS -o /dev/null "$OPENCTI_URL/health?health_access_key=$HEALTH_KEY" 2>/dev/null \
        && curl -fsS -H "@$TMP/auth.headers" -d '{"query":"{ about { version } }"}' "$OPENCTI_URL/graphql" 2>/dev/null | grep -q '"version"'; do
    [ "$SECONDS" -lt "$deadline" ] || unusable "OpenCTI not ready after $OPENCTI_READY_TIMEOUT s (logs/opencti.log)"
    sleep 5
done
OPENCTI_S=$((SECONDS - t0))
echo "ready after $OPENCTI_S s"

say "importing and reading back (pycti $PYCTI_VERSION)"
t0=$SECONDS
B="$OUT/bundles"
"$PYCTI_PY" "$ROOT/scripts/opencti_import_check.py" --url "$OPENCTI_URL" --env-file "$TMP/opencti.env" \
    --baseline "$ROOT/tests/fixtures/baselines/opencti_report.json" --enriched "$B/enriched.json" \
    --rejected "$B/rejected.json" --full "$B/full.json" --out "$OUT/opencti-check.json" >"$OUT/logs/check.txt" 2>&1
CHECK_CODE=$?
CHECK_S=$((SECONDS - t0))
cat "$OUT/logs/check.txt"
[ "$CHECK_CODE" -le 1 ] && [ -f "$OUT/opencti-check.json" ] || unusable "the check could not run (exit $CHECK_CODE)"
kill "$SAMPLER" 2>/dev/null
SAMPLER=""
PEAK_MB="$(sort -n "$TMP/memory.log" | tail -1)"

IMAGES="$("${OPENCTI[@]}" config --images 2>/dev/null | sort -u | while read -r image; do
    printf '%s=%s\n' "$image" "$("$DOCKER_BIN" image inspect --format '{{index .RepoDigests 0}}' "$image" 2>/dev/null)"
done)"
STARTED_S=$((SECONDS - STARTED)) CANDIDATE_S="$CANDIDATE_S" OPENCTI_S="$OPENCTI_S" CHECK_S="$CHECK_S" \
TOTAL_MB="$TOTAL_MB" BEFORE_MB="$BEFORE_MB" PEAK_MB="$PEAK_MB" IMAGES="$IMAGES" BUNDLES_FROM="$BUNDLES_FROM" \
CHECKOUT_COMMIT="$CHECKOUT_COMMIT" CHECKOUT_DIRTY="$CHECKOUT_DIRTY" CHECKOUT_FILES="$CHECKOUT_FILES" \
    "$PYTHON" -c 'import json, os, platform, sys, time
out = sys.argv[1]
env = os.environ
run = {
    "date": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    "candidate": json.load(open(out + "/candidate.json")),
    "bundles": json.load(open(out + "/bundles/manifest.json"))["bundles"],
    "opencti": {"images": dict(line.split("=", 1) for line in env["IMAGES"].splitlines() if "=" in line)},
    "durations_s": {"candidate": int(env["CANDIDATE_S"]), "opencti_start": int(env["OPENCTI_S"]),
                    "check": int(env["CHECK_S"]), "total": int(env["STARTED_S"])},
    "memory_mb": {"total": int(env["TOTAL_MB"]), "before_opencti": int(env["BEFORE_MB"]), "peak_used": int(env["PEAK_MB"])},
    "host": platform.platform(),
}
run["profile"] = run["candidate"].get("profile")
source = env["BUNDLES_FROM"]
run["bundles_from"] = {"dir": source or None, "earlier_run": None}
if source:
    try:
        prior = json.load(open(source + "/run.json"))
    except (OSError, ValueError):
        prior = {"candidate": run["candidate"]}
    earlier = prior.get("candidate") or {}
    run["bundles_from"]["earlier_run"] = {"date": prior.get("date"), "digest_ref": earlier.get("digest_ref"),
                                          "commit": earlier.get("commit")}
files = (line.split(None, 1) for line in env["CHECKOUT_FILES"].splitlines() if line.strip())
run["checkout"] = {"commit": env["CHECKOUT_COMMIT"] or None,
                   "dirty": {"true": True, "false": False}.get(env["CHECKOUT_DIRTY"]),
                   "files": {name.strip(): digest for digest, name in files}}
json.dump(run, open(out + "/run.json", "w"), indent=2)' "$OUT" || unusable "cannot write run.json"

say "report"
"$PYTHON" "$ROOT/scripts/opencti_expectations.py" report --run "$OUT/run.json" --check "$OUT/opencti-check.json" --out-dir "$OUT"