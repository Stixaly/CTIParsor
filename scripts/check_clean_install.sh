#!/usr/bin/env bash
# The clean install from the published image (ADR-0094 item 9), run as the
# public documentation writes it.  A release step, never in CI: it downloads
# two images and, in full, the models and corpora (TESTING.md).
#
#   scripts/check_clean_install.sh --candidate REF [--previous VERSION@sha256:DIGEST] [--quick] [--out DIR]
#   scripts/check_clean_install.sh --print-blocks
#
# The commands are the documentation's own, read when the check starts from
# the blocks marked `<!-- scripts/check_clean_install.sh: NAME -->` in
# README.md, docs/docker.md and docs/upgrading.md, and the three of
# docs/docker.md marked for scripts/check_backup_restore_docker.sh.  Each
# block runs in one shell, line after line, as a newcomer types it: `cd` and
# variables hold for the lines after, and the first line that fails stops it.
# The check changes three things only: the first line of a block that names a
# release (its values line) gets the run's versions and digests; the
# candidate's archive is downloaded from a local stand-in (file://) of the
# Releases page, `git archive` of the commit its image names, since a
# candidate has no Release yet; and with --quick, the bootstrap lines skip
# the downloads.  What the documentation leaves to the reader in prose is
# done here and named in the report: choosing no LLM provider in .env, moving
# between directories.
#
# The journey, in a new empty directory:
#  1. installs the previous release (by default the one the README names):
#     its archive from the Releases page, checked; setup.sh; its image by digest;
#     `pull`, `up -d`, `bootstrap`;
#  2. a first report through the API: tests/fixtures/sample_report.txt
#     uploaded, APT29 accepted, the review completed, the bundle downloaded and
#     its X-Bundle-Validation checked;
#  3. a second report started and, while it runs, the stack restarted
#     (`restart app worker`); the worker's drain is 5 s (WORKER_DRAIN_S, 60 by
#     default, which the report would outlast less often than not), so the
#     restart puts the report back in the queue and the next worker runs it:
#     each change of its status recorded; in full, the step fails unless the
#     report was `processing` at the restart, was put back in the queue, and
#     ends reviewable (--quick reports it as INFO); then `down` and `up -d`;
#     the first report, its status and its bundle still there;
#  4. the backup and its check, then the upgrade to the candidate: the
#     schema migrated, the first report and its bundle (sha256) unchanged,
#     a third report on the candidate;
#  5. the backup restored with the previous release into a second, empty
#     project: the first report and its bundle there, the third absent.
#
# Projects ctiparsor-clean-install and ctiparsor-clean-install-restored,
# ports CLEAN_INSTALL_PORT and the next one (default 8795, 8796).  The
# documented commands run under `env -i` with a new HOME, so neither the
# caller's environment nor its Docker login reaches them, and through a
# `docker` wrapper that lets through `docker compose` on the run's two
# projects (and `docker info`, `docker --version`, which setup.sh calls) and
# refuses all else: any `-p`, `down -v`, `volume rm`, `rm`, `prune`.  A new
# HOME selects Docker's default context, so the check refuses to start under
# any other context, or with DOCKER_HOST set: the documented commands and its
# own calls must reach the same daemon.  Everything the run created
# (containers, networks, volumes, the directory) is removed at the end, on
# success, failure or Ctrl-C; the pulled images stay.  It refuses to start
# while a project, or a directory of a killed run, is left.
#
# The report goes to --out, by default output/clean-install/<UTC time>/:
# report.json and report.md (both digests and commits, each step PASS/FAIL,
# each documented command with its exit status and duration, sizes, peak
# memory), the bundles and the logs.  --quick skips the model and corpus
# downloads and turns the model stages off: its report says it is not the
# gate.
#
# Environment: DOCKER_BIN (default docker), PYTHON (default python3),
#   CLEAN_INSTALL_PORT (default 8795), CLEAN_INSTALL_TIMEOUT (seconds a
#   report may take, default 900), CLEAN_INSTALL_MIN_AVAILABLE_MB (default
#   6000), CLEAN_INSTALL_MIN_DISK_GB (free space Docker needs, default 20).
# Run it as root when Docker needs root: what it writes goes to the checkout's owner.
#
# Exit 0 when every step passed, 1 when one failed, 2 when the check cannot
# run (a missing tool, a Docker context other than default, a port or project
# in use, a leftover, a candidate without digest or commit).

set -u
set -o pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DOCKER_BIN="${DOCKER_BIN:-docker}"
PYTHON="${PYTHON:-python3}"
PROJECT=ctiparsor-clean-install
RESTORED=ctiparsor-clean-install-restored
PORT="${CLEAN_INSTALL_PORT:-8795}"
RESTORED_PORT=$((PORT + 1))
TIMEOUT="${CLEAN_INSTALL_TIMEOUT:-900}"
MIN_AVAILABLE_MB="${CLEAN_INSTALL_MIN_AVAILABLE_MB:-6000}"
MIN_DISK_GB="${CLEAN_INSTALL_MIN_DISK_GB:-20}"
RELEASES=https://github.com/Stixaly/CTIParsor/releases/download/
IMAGE_NAME=ghcr.io/stixaly/ctiparsor
JOURNEY=("$PYTHON" "$ROOT/scripts/clean_install_journey.py")
TMP_PREFIX="${TMPDIR:-/tmp}/ctiparsor-clean-install."
export PYTHONDONTWRITEBYTECODE=1

CANDIDATE=""
PREVIOUS=""
QUICK=0
OUT=""
PRINT=0
while [ $# -gt 0 ]; do
    case "$1" in
        --candidate) CANDIDATE="${2:-}"; shift ;;
        --previous) PREVIOUS="${2:-}"; shift ;;
        --quick) QUICK=1 ;;
        --out) OUT="${2:-}"; shift ;;
        --print-blocks) PRINT=1 ;;
        --print-wrapper) PRINT=2 ;;
        -h|--help) sed -n '2,/^$/p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "check_clean_install: unknown option $1 (see --help)" >&2; exit 2 ;;
    esac
    shift
done

say() { echo "== $*"; }
unusable() { echo "check_clean_install: $*" >&2; exit 2; }
DOCKER_PATH="$(command -v "$DOCKER_BIN")"
wrapper_text() {   # the `docker` the documented commands find first on their PATH
    cat <<EOF
#!/usr/bin/env bash
# The rehearsal's docker: an allowlist.  "docker compose" on the run's two
# projects, and the two read-only calls setup.sh makes; anything else is refused.
allowed=" $PROJECT $RESTORED "
refuse() { echo "check_clean_install: refused: docker \$ARGS (\$1)" >&2; exit 97; }
ARGS="\$*"
if [ "\${1:-}" != compose ]; then
    [ \$# = 1 ] && case "\$1" in info|--version) exec "$DOCKER_PATH" "\$@" ;; esac
    refuse "only docker compose, docker info and docker --version are allowed"
fi
case "\$allowed" in *" \${COMPOSE_PROJECT_NAME:-(unset)} "*) ;; *) refuse "COMPOSE_PROJECT_NAME is \${COMPOSE_PROJECT_NAME:-unset}" ;; esac
for a in "\${@:2}"; do
    case "\$a" in -p*|--project-name*) refuse "names a project" ;; esac
done
i=2; sub=""
while [ \$i -le \$# ]; do
    a="\${!i}"
    case "\$a" in
        -f|--file|--env-file|--profile|--project-directory|--ansi|--progress|--parallel) i=\$((i + 1)) ;;
        -*) ;;
        *) sub="\$a"; break ;;
    esac
    i=\$((i + 1))
done
if [ "\$sub" = down ]; then
    for a in "\${@:i+1}"; do case "\$a" in -v|--volumes|--volumes=*|--rmi|--rmi=*) refuse "deletes volumes or images" ;; esac; done
fi
exec "$DOCKER_PATH" "\$@"
EOF
}

"$PYTHON" -c 'import sys' 2>/dev/null || unusable "no Python: set PYTHON"
if [ "$PRINT" = 1 ]; then
    exec "${JOURNEY[@]}" blocks --root "$ROOT"
elif [ "$PRINT" = 2 ]; then
    [ -n "$DOCKER_PATH" ] || unusable "$DOCKER_BIN is missing"
    wrapper_text
    exit 0
fi
BLOCKS_ERR="$("${JOURNEY[@]}" blocks --root "$ROOT" 2>&1 >/dev/null)" || unusable "the documentation's blocks: $BLOCKS_ERR"
block() { "${JOURNEY[@]}" block "$1" --root "$ROOT"; }

[ -n "$CANDIDATE" ] || unusable "give --candidate REF: the image to upgrade to (see --help)"
for tool in "$DOCKER_BIN" curl git tar sha256sum free df; do
    command -v "$tool" >/dev/null || unusable "$tool is missing"
done
"$DOCKER_BIN" compose version >/dev/null 2>&1 || unusable "docker compose (v2) is missing"
# The documented commands run with a new HOME, where Docker's config selects no
# context: they reach the default one.  This script's own calls must reach it too.
context="$("$DOCKER_BIN" context show 2>/dev/null)" || unusable "cannot read Docker's context (docker context show)"
[ "$context" = default ] || unusable "Docker's context is $context, the documented commands would reach another daemon: docker context use default"
[ -z "${DOCKER_HOST:-}" ] || unusable "DOCKER_HOST is set ($DOCKER_HOST): unset it; the check runs on the default context's daemon"

# The previous release: by default the one the README installs.
if [ -z "$PREVIOUS" ]; then
    read -r first < <(block INSTALL_FILES)
    PREVIOUS="$(sed -E 's/^version=(\S+) digest=(sha256:[0-9a-f]{64})$/\1@\2/' <<< "$first")"
fi
[[ "$PREVIOUS" =~ ^([0-9A-Za-z.+-]+)@(sha256:[0-9a-f]{64})$ ]] || unusable "--previous is VERSION@sha256:<64 hex digits> (got: $PREVIOUS)"
PREV_VERSION="${BASH_REMATCH[1]}"
PREV_DIGEST="${BASH_REMATCH[2]}"

port_free() { ! (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null; }
port_free "$PORT" || unusable "port $PORT is in use: set CLEAN_INSTALL_PORT"
port_free "$RESTORED_PORT" || unusable "port $RESTORED_PORT is in use: set CLEAN_INSTALL_PORT"
for project in "$PROJECT" "$RESTORED"; do
    left="$("$DOCKER_BIN" ps -aq --filter "label=com.docker.compose.project=$project")$("$DOCKER_BIN" volume ls -q --filter "label=com.docker.compose.project=$project")$("$DOCKER_BIN" network ls -q --filter "label=com.docker.compose.project=$project")"
    [ -z "$left" ] || unusable "the Compose project $project exists (a run in progress, or one that was killed). If none is running: $DOCKER_BIN compose -p $project down -v"
done
for dir in "$TMP_PREFIX"*; do
    [ -e "$dir" ] && unusable "$dir is left from an earlier run (in progress, or killed). If none is running: rm -rf $dir"
done
available="$(free -m | awk '/^Mem:/ {print $7}')"
[ "${available:-0}" -ge "$MIN_AVAILABLE_MB" ] || unusable "$available MB of memory available, $MIN_AVAILABLE_MB needed (CLEAN_INSTALL_MIN_AVAILABLE_MB)"
docker_root="$("$DOCKER_BIN" info --format '{{.DockerRootDir}}' 2>/dev/null)"
free_gb="$(df -Pk "${docker_root:-/}" 2>/dev/null | awk 'NR == 2 {print int($4 / 1048576)}')"
[ "${free_gb:-0}" -ge "$MIN_DISK_GB" ] || unusable "${free_gb:-?} GB free under ${docker_root:-/}, $MIN_DISK_GB needed (CLEAN_INSTALL_MIN_DISK_GB)"

OWNER_UG="$(stat -c %u:%g "$ROOT")"
GIT=(git -c "safe.directory=$ROOT" -C "$ROOT")
DEFAULT_OUT=0
[ -n "$OUT" ] || { OUT="$ROOT/output/clean-install/$(date -u +%Y%m%dT%H%M%SZ)"; DEFAULT_OUT=1; }
[ -e "$OUT" ] && [ -n "$(ls -A "$OUT" 2>/dev/null)" ] && unusable "$OUT is not empty"
mkdir -p "$OUT/logs" || unusable "cannot create $OUT"
OUT="$(cd "$OUT" && pwd)"
TMP="$(mktemp -d "${TMP_PREFIX}XXXXXX")" || unusable "mktemp failed"
chmod 755 "$TMP"
WORK="$TMP/newcomer"            # the newcomer's directory: what the docs download, nothing else
STANDIN="$TMP/releases"         # the candidate's stand-in of the Releases page
mkdir -p "$WORK" "$TMP/home" "$TMP/bin" "$STANDIN"
SAMPLER=""
FOLLOWER=""
CREATED=0
STEPS="$OUT/steps.tsv"
: >"$STEPS"
FAILS=0
BLOCK_N=0

# Compose interpolates the caller's environment before .env: an exported
# CTI_IMAGE or CTI_PORT would replace the files' values.  The documented
# commands and the check's own calls run with PATH, a new HOME and Docker's
# own variables only; the documented ones through the wrapper in $TMP/bin.
CLEAN_ENV=(env -i "PATH=$TMP/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" "HOME=$TMP/home"
           "LANG=C.UTF-8" "TERM=dumb")
for var in DOCKER_CONTEXT DOCKER_CERT_PATH DOCKER_TLS_VERIFY; do
    [ -n "${!var:-}" ] && CLEAN_ENV+=("$var=${!var}")
done
in_project() {  # in_project PROJECT DIR compose-arguments...: the check's own calls, not the docs'
    "${CLEAN_ENV[@]}" "$DOCKER_PATH" compose -p "$1" -f "$2/compose.yaml" --project-directory "$2" "${@:3}"
}
any_dir() { local dir; for dir in "$WORK"/ctiparsor-*/; do [ -f "$dir/compose.yaml" ] && { echo "${dir%/}"; return; }; done; }

remove_project() {     # every container, network and volume of the project, nothing else
    local project="$1" dir
    dir="$(any_dir)"
    [ -n "$dir" ] && in_project "$project" "$dir" down -v --remove-orphans >>"$OUT/logs/teardown.log" 2>&1
    "$DOCKER_BIN" ps -aq --filter "label=com.docker.compose.project=$project" | xargs -r "$DOCKER_BIN" rm -f >>"$OUT/logs/teardown.log" 2>&1
    "$DOCKER_BIN" volume ls -q --filter "label=com.docker.compose.project=$project" | xargs -r "$DOCKER_BIN" volume rm >>"$OUT/logs/teardown.log" 2>&1
    "$DOCKER_BIN" network ls -q --filter "label=com.docker.compose.project=$project" | xargs -r "$DOCKER_BIN" network rm >>"$OUT/logs/teardown.log" 2>&1
}

cleanup() {
    local code=$?
    trap '' INT TERM   # a second Ctrl-C must not cut the removal short
    [ -n "$SAMPLER" ] && kill "$SAMPLER" 2>/dev/null
    # report B's follower polls for up to $TIMEOUT s and writes into $OUT
    [ -n "$FOLLOWER" ] && kill "$FOLLOWER" 2>/dev/null && wait "$FOLLOWER" 2>/dev/null
    if [ "$CREATED" = 1 ]; then
        for project in "$PROJECT" "$RESTORED"; do
            [ -n "$(any_dir)" ] && in_project "$project" "$(any_dir)" logs --no-color --timestamps >"$OUT/logs/$project.log" 2>&1
            remove_project "$project"
            left="$("$DOCKER_BIN" ps -aq --filter "label=com.docker.compose.project=$project")$("$DOCKER_BIN" volume ls -q --filter "label=com.docker.compose.project=$project")"
            [ -z "$left" ] || echo "check_clean_install: could not remove $project: $DOCKER_BIN compose -p $project down -v" >&2
        done
    fi
    rm -rf "$TMP"
    if [ "$(id -u)" = 0 ]; then
        chown -R "$OWNER_UG" "$OUT" 2>/dev/null
        [ "$DEFAULT_OUT" = 1 ] && chown "$OWNER_UG" "$ROOT/output" "$ROOT/output/clean-install" 2>/dev/null
    fi
    exit "$code"
}
trap cleanup EXIT
trap 'exit 130' INT TERM

step() {     # step NAME PASS|FAIL|INFO SECONDS DETAIL
    printf '%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "${4//$'\t'/ }" >>"$STEPS"
    echo "$2  $1 (${3} s) ${4:+- $4}"
    [ "$2" = FAIL ] && FAILS=$((FAILS + 1))
    return 0
}
abort() {    # a step the rest cannot go on without
    step "$1" FAIL "${2:-0}" "$3"
    finish
}

# ── The documented commands, as a newcomer runs them ─────────────────────────
wrapper_text >"$TMP/bin/docker"
chmod 755 "$TMP/bin/docker"

# One shell per block; the directory and the umask it ends with carry over to
# the next, as in a newcomer's terminal.  Each line's output goes to the
# block's log, its exit status and duration to <log>.times; a pg_restore line
# that prints anything fails, as docs/docker.md requires.
cat >"$TMP/runner.sh" <<'EOF'
#!/usr/bin/env bash
# runner.sh <state file> <lines file> <log>
__state=$1 __lines=$2 __log=$3
. "$__state"
umask "$UMASK"
cd "$DIR" || exit 1
__rc=0
while IFS= read -r __line <&3; do
    printf '$ %s\n' "$__line" >>"$__log"
    __t0=$EPOCHREALTIME
    eval "$__line" </dev/null >>"$__log" 2>"$__log.err"
    __rc=$?
    __t1=$EPOCHREALTIME
    cat "$__log.err" >>"$__log"
    if [ "$__rc" = 0 ] && [[ "$__line" == *" pg_restore -U "* ]] && [ -s "$__log.err" ]; then
        __rc=125
        echo "(exit 0, but pg_restore printed the lines above: docs/docker.md requires nothing)" >>"$__log"
    fi
    printf '%s\t%.1f\t%s\n' "$__rc" "$(echo "$__t1 - $__t0" | awk '{print $1 - $3}')" "$__line" >>"$__log.times"
    [ "$__rc" = 0 ] || { echo "(exit $__rc)" >>"$__log"; break; }
done 3<"$__lines"
rm -f "$__log.err"
printf 'UMASK=%s\nDIR=%q\n' "$(umask)" "$PWD" >"$__state"
exit "$__rc"
EOF
# The newcomer's terminal: where it stands, its umask.
printf 'UMASK=%s\nDIR=%q\n' 0022 "$WORK" >"$TMP/shell.state"

run_block() {   # run_block NAME PROJECT PORT [sed expression]: the block as the docs write it, but its values line
    local name="$1" project="$2" port="$3" expr="${4:-}" t0=$SECONDS file log
    BLOCK_N=$((BLOCK_N + 1))
    file="$TMP/block-$BLOCK_N"
    log="$OUT/logs/$(printf '%02d' "$BLOCK_N")-$name.log"
    if [ -n "$expr" ]; then block "$name" | sed -E "$expr" >"$file"; else block "$name" >"$file"; fi
    CREATED=1
    "${CLEAN_ENV[@]}" "COMPOSE_PROJECT_NAME=$project" "CTI_PORT=$port" bash "$TMP/runner.sh" "$TMP/shell.state" "$file" "$log"
    local rc=$?
    mv "$log.times" "${log%.log}.times" 2>/dev/null
    LAST_BLOCK_S=$((SECONDS - t0))
    if [ "$rc" != 0 ]; then
        step "$name" FAIL "$LAST_BLOCK_S" "exit $rc on: $(tail -1 "${log%.log}.times" | cut -f3) (logs/$(basename "$log"))"
        return 1
    fi
    step "$name" PASS "$LAST_BLOCK_S" "$(wc -l <"$file") line(s) as documented (logs/$(basename "$log"))"
}
prose() {       # prose DIR: where the docs' prose says the next block runs
    printf 'UMASK=%s\nDIR=%q\n' "$(. "$TMP/shell.state"; echo "$UMASK")" "$1" >"$TMP/shell.state"
}
here() { (. "$TMP/shell.state"; echo "$DIR"); }

psql_in() {     # psql_in PROJECT DIR: SQL on stdin, rows on stdout
    # shellcheck disable=SC2016  # expanded in the container, where the password file is
    in_project "$1" "$2" exec -T postgres sh -c \
        'PGPASSWORD="$(cat /run/secrets/db_password)" exec psql -X -q -At -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d "$POSTGRES_DB"'
}
healthy() {     # healthy PORT: /api/health answers ok within 300 s
    local deadline=$((SECONDS + 300))
    until curl -fsS "http://127.0.0.1:$1/api/health" 2>/dev/null | grep -q '"ok"'; do
        [ "$SECONDS" -lt "$deadline" ] || return 1
        sleep 2
    done
}
stages() {      # stages PROJECT DIR JOB REQUIRED: the job's stage report judged as docker_smoke.sh does
    psql_in "$1" "$2" <<<"SELECT COALESCE(run_config_json::jsonb->'stage_report', 'null'::jsonb) FROM jobs WHERE id = '$3';" \
        | "$PYTHON" "$ROOT/scripts/smoke_stage_report.py" "$4"
}
schema_version() { psql_in "$1" "$2" <<<"SELECT max(version) FROM schema_migrations;"; }
volume_mb() {   # volume_mb PROJECT VOLUME: its size, read in a container of the project's own image
    in_project "$1" "$2" run --rm --no-deps -T -v "$1_$3:/v:ro" --entrypoint du app -sm /v 2>/dev/null | awk '{print $1}'
}

finish() {
    [ -n "$SAMPLER" ] && kill "$SAMPLER" 2>/dev/null && SAMPLER=""
    local peak per
    peak="$(sort -n "$TMP/memory.log" 2>/dev/null | tail -1)"
    per="$(awk -F'\t' '{split($2, a, " "); v = a[1]; u = a[1]; sub(/[0-9.]+/, "", u); sub(/[A-Za-z]+$/, "", v);
                       m = (u == "GiB") ? v * 1024 : (u == "MiB") ? v + 0 : (u == "KiB") ? v / 1024 : 0;
                       s = $1; sub(/-[0-9]+$/, "", s); if (m > max[s]) max[s] = m}
                       END {for (s in max) printf "%s=%d\n", s, max[s]}' "$TMP/stats.log" 2>/dev/null | sort)"
    MODE="$([ "$QUICK" = 1 ] && echo quick || echo full)" PREVIOUS="$PREVIOUS" PREV_COMMIT="${PREV_COMMIT:-}" \
    CANDIDATE="$CANDIDATE" DIGEST_REF="${DIGEST_REF:-}" COMMIT="${COMMIT:-}" NEW_VERSION="${NEW_VERSION:-}" \
    CHECKOUT_COMMIT="$("${GIT[@]}" rev-parse HEAD 2>/dev/null)" \
    CHECKOUT_DIRTY="$("${GIT[@]}" --no-optional-locks status --porcelain --untracked-files=no 2>/dev/null | grep -c .)" \
    TOTAL_MB="$(free -m | awk '/^Mem:/ {print $2}')" BEFORE_MB="${BEFORE_MB:-0}" PEAK_MB="${peak:-0}" PER="$per" \
    SIZES="$(cat "$TMP/sizes" 2>/dev/null)" DURATIONS="$(cat "$TMP/durations" 2>/dev/null)" TOTAL_S="$SECONDS" \
    CHECK_FILES="$(cd "$ROOT" && sha256sum scripts/check_clean_install.sh scripts/clean_install_journey.py \
        scripts/opencti_candidate_bundles.py scripts/smoke_stage_report.py tests/fixtures/sample_report.txt \
        README.md docs/docker.md docs/upgrading.md 2>/dev/null)" \
        "$PYTHON" -c 'import json, os, platform, sys, time
env = os.environ
def num(v):
    for kind in (int, float):
        try:
            return kind(v)
        except ValueError:
            pass
    return v
pairs = lambda text: {k: num(v) for k, _, v in (l.partition("=") for l in text.splitlines() if "=" in l)}
run = {"date": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "mode": env["MODE"],
       "previous": {"release": env["PREVIOUS"], "commit": env["PREV_COMMIT"] or None},
       "candidate": {"given": env["CANDIDATE"], "digest_ref": env["DIGEST_REF"] or None, "commit": env["COMMIT"] or None,
                     "version": env["NEW_VERSION"] or None},
       "checkout": {"commit": env["CHECKOUT_COMMIT"] or None, "modified_tracked_files": int(env["CHECKOUT_DIRTY"] or 0),
                    "files": {n.strip(): d for d, _, n in (l.partition(" ") for l in env["CHECK_FILES"].splitlines() if l)}},
       "sizes_mb": pairs(env["SIZES"]), "durations_s": {**pairs(env["DURATIONS"]), "total": int(env["TOTAL_S"])},
       "memory_mb": {"host_total": int(env["TOTAL_MB"]), "host_used_before": int(env["BEFORE_MB"]),
                     "host_used_peak": int(env["PEAK_MB"]), "container_peak": pairs(env["PER"])},
       "host": platform.platform()}
json.dump(run, open(sys.argv[1], "w"), indent=2)' "$OUT/run.json"
    "${JOURNEY[@]}" summary --out "$OUT" >/dev/null
    echo ""
    echo "report: $OUT/report.md"
    if [ "$FAILS" -gt 0 ]; then
        echo "Clean install: $FAILS step(s) failed"
        exit 1
    fi
    echo "Clean install: every step passed$([ "$QUICK" = 1 ] && echo ' (--quick: not the gate)')"
    exit 0
}
note() { echo "$1=$2" >>"$TMP/$3"; }

# ── 0. The candidate, and its stand-in on the Releases page ──────────────────
say "resolving the candidate $CANDIDATE"
t0=$SECONDS
repo="${CANDIDATE%@*}"
case "${repo##*/}" in *:*) repo="${repo%:*}" ;; esac
if [[ "$CANDIDATE" =~ ^[^@]+@sha256:[0-9a-f]{64}$ ]]; then
    "$DOCKER_BIN" image inspect "$CANDIDATE" >/dev/null 2>&1 \
        || "$DOCKER_BIN" pull "$CANDIDATE" >"$OUT/logs/candidate-pull.log" 2>&1 || unusable "cannot pull $CANDIDATE (logs/candidate-pull.log)"
    DIGEST_REF="$CANDIDATE"
elif [[ "$CANDIDATE" == *@* ]]; then
    unusable "$CANDIDATE: a digest reference is name@sha256:<64 hex digits>"
else
    "$DOCKER_BIN" pull "$CANDIDATE" >"$OUT/logs/candidate-pull.log" 2>&1 || unusable "cannot pull $CANDIDATE (logs/candidate-pull.log)"
    DIGEST_REF="$("$DOCKER_BIN" image inspect --format '{{range .RepoDigests}}{{println .}}{{end}}' "$CANDIDATE" | grep -m1 "^$repo@sha256:")"
    [ -n "$DIGEST_REF" ] || unusable "$CANDIDATE has no registry digest for $repo: a local build cannot be the candidate"
fi
[ "${DIGEST_REF%@*}" = "$IMAGE_NAME" ] || unusable "the candidate must be an image of $IMAGE_NAME, the name the documentation installs (got ${DIGEST_REF%@*})"
CAND_DIGEST="${DIGEST_REF#*@}"
COMMIT="$("$DOCKER_BIN" image inspect --format '{{index .Config.Labels "org.opencontainers.image.revision"}}' "$DIGEST_REF")"
[[ "$COMMIT" =~ ^[0-9a-f]{40}$ ]] || unusable "$DIGEST_REF has no commit in its label org.opencontainers.image.revision (found: '$COMMIT')"
"${GIT[@]}" cat-file -e "$COMMIT^{commit}" 2>/dev/null || unusable "the checkout does not have the candidate's commit $COMMIT: git fetch origin"
tree_version="$("${GIT[@]}" show "$COMMIT:pipeline/__init__.py" | sed -nE 's/^__version__ = "([^"]+)"$/\1/p')"
NEW_VERSION="${tree_version:-0.0.0}+g${COMMIT:0:7}"
mkdir -p "$STANDIN/v$NEW_VERSION"
"${GIT[@]}" archive --format=tar.gz --prefix="ctiparsor-$NEW_VERSION/" -o "$STANDIN/v$NEW_VERSION/ctiparsor-$NEW_VERSION.tar.gz" "$COMMIT" \
    || unusable "git archive $COMMIT failed"
(cd "$STANDIN/v$NEW_VERSION" && sha256sum -- "ctiparsor-$NEW_VERSION.tar.gz" >SHA256SUMS)
echo "candidate $DIGEST_REF, commit $COMMIT, files ctiparsor-$NEW_VERSION.tar.gz (git archive, file:// stand-in)"
step "candidate" PASS $((SECONDS - t0)) "$DIGEST_REF, commit $COMMIT"
PREV_PRESENT="$("$DOCKER_BIN" image inspect "$IMAGE_NAME@$PREV_DIGEST" >/dev/null 2>&1 && echo yes || echo no)"

# Memory, every 5 s: the host's, and each container of the two projects.
BEFORE_MB="$(free -m | awk '/^Mem:/ {print $3}')"
(
    while :; do
        free -m | awk '/^Mem:/ {print $3}' >>"$TMP/memory.log"
        "$DOCKER_BIN" stats --no-stream --format '{{.Name}}\t{{.MemUsage}}' 2>/dev/null \
            | grep -E "^($PROJECT|$RESTORED)-" >>"$TMP/stats.log"
        sleep 5
    done
) 2>/dev/null &
SAMPLER=$!

# ── 1. Install the previous release ──────────────────────────────────────────
say "installing $PREV_VERSION as the README does ($PROJECT, 127.0.0.1:$PORT)"
run_block INSTALL_FILES "$PROJECT" "$PORT" "1s/.*/version=$PREV_VERSION digest=$PREV_DIGEST/" || finish
OLD_DIR="$(here)"
[ "$OLD_DIR" = "$WORK/ctiparsor-$PREV_VERSION" ] && grep -q "^CTI_IMAGE=$IMAGE_NAME@$PREV_DIGEST\$" "$OLD_DIR/.env" \
    && [ -s "$OLD_DIR/.secrets/db_password" ] \
    && step "files and .env" PASS 0 "in ctiparsor-$PREV_VERSION: .env with CTI_IMAGE by digest, .secrets/db_password" \
    || abort "files and .env" 0 "after INSTALL_FILES: directory $OLD_DIR, CTI_IMAGE or .secrets/db_password missing"

# The prose between the blocks: "choose the LLM provider in .env".  This run
# chooses none: the key is emptied (0.2.0's .env.example ships a placeholder one,
# which turns Stage 3 on and fails it; the README says so); --quick also turns
# the model stages off.
# A 5 s drain: the restart below requeues the report in flight (step 3).
sed -i 's/^ANTHROPIC_API_KEY=.*/ANTHROPIC_API_KEY=/' "$OLD_DIR/.env"
echo "WORKER_DRAIN_S=5" >>"$OLD_DIR/.env"
if [ "$QUICK" = 1 ]; then
    cat >>"$OLD_DIR/.env" <<'EOF'
SKIP_HEAVY_MODELS=1
PIPELINE_DISABLED_STAGES=1f,2c,2d,2e,3,3d,3f,3e,3doc,2f,4c
CVE_ENRICHMENT=false
VISION_PROVIDER=none
HF_HUB_OFFLINE=1
TRANSFORMERS_OFFLINE=1
EOF
    # The service's command is replaced by what follows its name: `bootstrap` again, then the options.
    QUICK_BOOT='s/(--profile bootstrap run --rm bootstrap)$/\1 bootstrap --no-models --no-corpora/'
    REQUIRED=""
else
    QUICK_BOOT=""
    REQUIRED="2c 2d 2e"
fi
step ".env" INFO 0 "no LLM provider (ANTHROPIC_API_KEY empty: Stage 3 skipped); WORKER_DRAIN_S=5$([ "$QUICK" = 1 ] && echo '; --quick: model stages off')"

run_block INSTALL_START "$PROJECT" "$PORT" "$QUICK_BOOT" || finish
sed -n '/^\$ docker compose pull$/,/^\$ docker compose --profile bootstrap/p' "$OUT/logs/"*-INSTALL_START.log \
        | grep -qE ' Building|#[0-9]+ \[internal\]|build tag cannot' \
    && step "no build" FAIL 0 "Compose built or tried to build an image (logs)" \
    || step "no build" PASS 0 "the image came from the registry, by digest (already present before the run: $PREV_PRESENT)"
while IFS=$'\t' read -r code secs line; do
    case "$line" in
        "docker compose pull") note pull_previous "$secs" durations ;;
        "docker compose up -d") note up_previous "$secs" durations ;;
        *bootstrap*) note bootstrap_first "$secs" durations ;;
    esac
done <"$OUT/logs/$(printf '%02d' "$BLOCK_N")-INSTALL_START.times"
healthy "$PORT" && step "health" PASS 0 "GET /api/health ok on $PREV_VERSION" || abort "health" 0 "no healthy API on 127.0.0.1:$PORT after 300 s"
SCHEMA_BEFORE="$(schema_version "$PROJECT" "$OLD_DIR")"
PREV_COMMIT="$("$DOCKER_BIN" image inspect --format '{{index .Config.Labels "org.opencontainers.image.revision"}}' "$IMAGE_NAME@$PREV_DIGEST")"
note image_previous "$(( $("$DOCKER_BIN" image inspect --format '{{.Size}}' "$IMAGE_NAME@$PREV_DIGEST") / 1048576 ))" sizes
for volume in cti-cache cti-state; do
    note "$volume" "$(volume_mb "$PROJECT" "$OLD_DIR" "$volume")" sizes
done
note pg-data-18 "$(in_project "$PROJECT" "$OLD_DIR" exec -T postgres du -sm /var/lib/postgresql | awk '{print $1}')" sizes
# What bootstrap downloaded: every directory of the cache of 50 MB or more, three levels down.
in_project "$PROJECT" "$OLD_DIR" run --rm --no-deps -T --entrypoint du app -m --max-depth=3 /app/cache </dev/null 2>/dev/null \
    | awk '$1 >= 50 && $2 != "/app/cache"' | while read -r mb path; do note "cache:${path#/app/cache/}" "$mb" sizes; done

# ── 2. A first report, reviewed and exported ─────────────────────────────────
API="http://127.0.0.1:$PORT"
say "report A through the API"
t0=$SECONDS
if "${JOURNEY[@]}" report --api "$API" --out "$OUT" --name A --accept APT29:threat_actor --timeout "$TIMEOUT" >/dev/null; then
    A_JOB="$("$PYTHON" -c 'import json, sys; print(json.load(open(sys.argv[1]))["job_id"])' "$OUT/A.meta.json")"
    A_SHA="$("$PYTHON" -c 'import json, sys; print(json.load(open(sys.argv[1]))["sha256"])' "$OUT/A.meta.json")"
    A_STATUS="$("$PYTHON" -c 'import json, sys; print(json.load(open(sys.argv[1]))["status"])' "$OUT/A.meta.json")"
    A_VALID="$("$PYTHON" -c 'import json, sys; print(json.load(open(sys.argv[1]))["validation"])' "$OUT/A.meta.json")"
    note report_A $((SECONDS - t0)) durations
    [ "$A_VALID" = validated ] && step "report A" PASS $((SECONDS - t0)) "job $A_JOB, APT29 accepted, finalized, bundle $A_SHA, X-Bundle-Validation: $A_VALID" \
        || step "report A" FAIL $((SECONDS - t0)) "X-Bundle-Validation: $A_VALID, expected validated"
else
    abort "report A" $((SECONDS - t0)) "the first report did not go through (see the output above)"
fi
STAGES_A="$(stages "$PROJECT" "$OLD_DIR" "$A_JOB" "$REQUIRED")" \
    && step "stages A" PASS 0 "$(grep -c '^stage' <<<"$STAGES_A") stages, none failed${REQUIRED:+, $REQUIRED ran}" \
    || step "stages A" FAIL 0 "$(grep '^problem' <<<"$STAGES_A" | paste -sd ';')"
printf '%s\n' "$STAGES_A" >"$OUT/stages-A.txt"

# ── 3. Restart with a report in flight, then down and up ─────────────────────
say "restart with report B in flight"
B_JOB="$("${JOURNEY[@]}" upload --api "$API" --out "$OUT" --name B)" || abort "report B" 0 "upload refused"
deadline=$((SECONDS + 120))
until [ "$(curl -fsS "$API/api/jobs/$B_JOB" | "$PYTHON" -c 'import json, sys; print(json.load(sys.stdin)["status"])')" != queued ]; do
    [ "$SECONDS" -lt "$deadline" ] || break
    sleep 1
done
B_BEFORE="$(curl -fsS "$API/api/jobs/$B_JOB" | "$PYTHON" -c 'import json, sys; print(json.load(sys.stdin)["status"])')"
"${JOURNEY[@]}" follow --api "$API" --job "$B_JOB" --out "$OUT/B.meta.json" --timeout "$TIMEOUT" >/dev/null &
FOLLOWER=$!
run_block RESTART_COMMANDS "$PROJECT" "$PORT" && note restart "$LAST_BLOCK_S" durations
healthy "$PORT" || step "health after restart" FAIL 0 "no healthy API after 300 s"
wait "$FOLLOWER"
FOLLOWER=""
B_FINAL="$("$PYTHON" -c 'import json, sys; d = json.load(open(sys.argv[1])); print(d["final"], "after", d["seconds"], "s:", " -> ".join("%s@%ss" % (e["status"], e["at_s"]) for e in d["timeline"]))' "$OUT/B.meta.json")"
in_project "$PROJECT" "$OLD_DIR" logs --no-color --timestamps app worker >"$OUT/logs/restart-app-worker.log" 2>&1
# Was B put back in the queue?  `queued` after `processing` in its timeline, or
# the worker's line when the drain ran out (api/queue_loop.py).  Ending
# reviewable alone proves nothing: B may have finished before or during the drain.
B_HOW=""
"$PYTHON" -c 'import json, sys
seen = [e["status"] for e in json.load(open(sys.argv[1]))["timeline"]]
sys.exit(0 if "processing" in seen and "queued" in seen[seen.index("processing"):] else 1)' "$OUT/B.meta.json" 2>/dev/null \
    && B_HOW="queued after processing in its timeline"
grep -qE 'Drain timeout: [0-9]+ job\(s\) still running, requeued|Terminated and requeued [0-9]+ job' "$OUT/logs/restart-app-worker.log" \
    && B_HOW="${B_HOW:+$B_HOW; }the worker's drain timed out and requeued it (logs/restart-app-worker.log)"
case "$B_FINAL" in for_review*|reviewing*|completed*) B_READABLE=1 ;; *) B_READABLE=0 ;; esac
if [ -n "$B_HOW" ]; then B_DETAIL="requeued: $B_HOW"
else B_DETAIL="NOT requeued: B finished before or during the drain, so the restart did not put it back in the queue"
fi
B_DETAIL="status $B_BEFORE at the restart; $B_DETAIL; $B_FINAL"
if [ "$B_READABLE" = 1 ] && [ "$B_BEFORE" = processing ] && [ -n "$B_HOW" ]; then
    step "report B through restart" PASS 0 "$B_DETAIL"
elif [ "$B_READABLE" = 1 ] && [ "$QUICK" = 1 ]; then
    step "report B through restart" INFO 0 "$B_DETAIL (--quick: not the gate)"
else
    step "report B through restart" FAIL 0 "$B_DETAIL"
fi
run_block STOP_START_COMMANDS "$PROJECT" "$PORT" && note down_up "$LAST_BLOCK_S" durations
healthy "$PORT" || step "health after down/up" FAIL 0 "no healthy API after 300 s"
"${JOURNEY[@]}" bundle --api "$API" --job "$A_JOB" --out "$OUT/A-after-restart.meta.json" --expect-sha256 "$A_SHA" --expect-status "$A_STATUS" >/dev/null \
    && step "report A after restart" PASS 0 "status and bundle sha256 unchanged" \
    || step "report A after restart" FAIL 0 "$(cat "$OUT/A-after-restart.meta.json" 2>/dev/null)"

# ── 4. Backup, then the upgrade to the candidate ─────────────────────────────
say "backup and upgrade to $NEW_VERSION"
UMASK_BEFORE="$(. "$TMP/shell.state"; echo "$UMASK")"
prose "$OLD_DIR"            # "in the directory of the installed release"
run_block BACKUP_COMMANDS "$PROJECT" "$PORT" || finish
DUMP="$(cd "$OLD_DIR" && ls ctiparsor-*.dump 2>/dev/null | head -1)"
DAY="${DUMP#ctiparsor-}"; DAY="${DAY%.dump}"
[ -n "$DAY" ] || abort "backup files" 0 "no ctiparsor-<date>.dump in $OLD_DIR"
note backup_dump "$(( $(stat -c %s "$OLD_DIR/$DUMP") / 1048576 ))" sizes
run_block CHECK_COMMANDS "$PROJECT" "$PORT" "s/YYYY-MM-DD/$DAY/g" || finish
UMASK_AFTER="$(. "$TMP/shell.state"; echo "$UMASK")"
[ "$UMASK_AFTER" = "$UMASK_BEFORE" ] \
    && step "umask after the backup" PASS 0 "$UMASK_AFTER, as before it" \
    || step "umask after the backup" FAIL 0 "$UMASK_AFTER, was $UMASK_BEFORE: files unpacked next in that shell would be unreadable by the containers"
prose "$WORK"               # "from the directory that holds ctiparsor-$old"
run_block UPGRADE_COMMANDS "$PROJECT" "$PORT" \
    "1s/.*/old=$PREV_VERSION new=$NEW_VERSION digest=$CAND_DIGEST/; s#https://github\.com/Stixaly/CTIParsor/releases/download/#file://$STANDIN/#g; $QUICK_BOOT" || finish
NEW_DIR="$(here)"
while IFS=$'\t' read -r code secs line; do
    case "$line" in
        "docker compose pull") note pull_candidate "$secs" durations ;;
        "docker compose up -d") note up_candidate "$secs" durations ;;
        *bootstrap*) note bootstrap_upgrade "$secs" durations ;;
    esac
done <"$OUT/logs/$(printf '%02d' "$BLOCK_N")-UPGRADE_COMMANDS.times"
# As root, tar keeps the archive's modes, so this cannot see the 600 a stale umask
# gives a newcomer's unpacked files: "umask after the backup" is that check.
SQUID_MODE="$(stat -c %a "$NEW_DIR/docker/squid/squid.conf" 2>/dev/null)"
if [ -z "$SQUID_MODE" ]; then
    step "files of the new release" FAIL 0 "docker/squid/squid.conf is not in $NEW_DIR"
elif [ "$SQUID_MODE" = 600 ]; then
    step "files of the new release" FAIL 0 "docker/squid/squid.conf is 600: the capture proxy cannot read it"
else
    step "files of the new release" INFO 0 "docker/squid/squid.conf mode $SQUID_MODE; root keeps the archive's modes, the umask step is the check"
fi
healthy "$PORT" && step "health after upgrade" PASS 0 "GET /api/health ok on $NEW_VERSION" || abort "health after upgrade" 0 "no healthy API after 300 s"
RUNNING="$(in_project "$PROJECT" "$NEW_DIR" ps -q app | xargs -r "$DOCKER_BIN" inspect --format '{{.Image}}')"
WANT="$("$DOCKER_BIN" image inspect --format '{{.Id}}' "$DIGEST_REF")"
[ -n "$RUNNING" ] && [ "$RUNNING" = "$WANT" ] && step "image after upgrade" PASS 0 "app runs $DIGEST_REF" \
    || step "image after upgrade" FAIL 0 "app runs $RUNNING, the candidate is $WANT"
SCHEMA_AFTER="$(schema_version "$PROJECT" "$NEW_DIR")"
# Whichever process starts first on the new image migrates, under a lock the
# others wait for: app, worker, or the bootstrap the upgrade runs after them.
MIGRATED="$( { cat "$OUT/logs/"*-UPGRADE_COMMANDS.log; in_project "$PROJECT" "$NEW_DIR" logs app worker 2>&1; } \
    | grep -o '\[db\] schema version [0-9]* -> [0-9]*' | head -1)"
if ! [[ "$SCHEMA_BEFORE" =~ ^[0-9]+$ && "$SCHEMA_AFTER" =~ ^[0-9]+$ ]]; then
    step "migration" FAIL 0 "the schema version could not be read: before '${SCHEMA_BEFORE}', after '${SCHEMA_AFTER}'"
elif [ "$SCHEMA_AFTER" -gt "$SCHEMA_BEFORE" ] && [ -n "$MIGRATED" ]; then
    step "migration" PASS 0 "schema $SCHEMA_BEFORE -> $SCHEMA_AFTER ($MIGRATED)"
elif [ "$SCHEMA_AFTER" = "$SCHEMA_BEFORE" ]; then
    step "migration" INFO 0 "schema $SCHEMA_AFTER, nothing to migrate"
else
    step "migration" FAIL 0 "schema $SCHEMA_BEFORE -> $SCHEMA_AFTER, log: ${MIGRATED:-none}"
fi
"${JOURNEY[@]}" bundle --api "$API" --job "$A_JOB" --out "$OUT/A-after-upgrade.meta.json" --expect-sha256 "$A_SHA" --expect-status "$A_STATUS" >/dev/null \
    && step "report A after upgrade" PASS 0 "status and bundle sha256 unchanged" \
    || step "report A after upgrade" FAIL 0 "$(cat "$OUT/A-after-upgrade.meta.json" 2>/dev/null)"
for volume in cti-cache cti-state; do
    note "$volume-after-upgrade" "$(volume_mb "$PROJECT" "$NEW_DIR" "$volume")" sizes
done
note image_candidate "$(( $("$DOCKER_BIN" image inspect --format '{{.Size}}' "$DIGEST_REF") / 1048576 ))" sizes

say "report C on the candidate"
t0=$SECONDS
if "${JOURNEY[@]}" report --api "$API" --out "$OUT" --name C --accept APT29:threat_actor --timeout "$TIMEOUT" >/dev/null; then
    C_JOB="$("$PYTHON" -c 'import json, sys; print(json.load(open(sys.argv[1]))["job_id"])' "$OUT/C.meta.json")"
    C_VALID="$("$PYTHON" -c 'import json, sys; print(json.load(open(sys.argv[1]))["validation"])' "$OUT/C.meta.json")"
    note report_C $((SECONDS - t0)) durations
    [ "$C_VALID" = validated ] && step "report C" PASS $((SECONDS - t0)) "job $C_JOB, X-Bundle-Validation: $C_VALID" \
        || step "report C" FAIL $((SECONDS - t0)) "X-Bundle-Validation: $C_VALID, expected validated"
    STAGES_C="$(stages "$PROJECT" "$NEW_DIR" "$C_JOB" "$REQUIRED")" \
        && step "stages C" PASS 0 "$(grep -c '^stage' <<<"$STAGES_C") stages, none failed${REQUIRED:+, $REQUIRED ran}" \
        || step "stages C" FAIL 0 "$(grep '^problem' <<<"$STAGES_C" | paste -sd ';')"
    printf '%s\n' "$STAGES_C" >"$OUT/stages-C.txt"
else
    step "report C" FAIL $((SECONDS - t0)) "the report did not go through on the candidate"
fi

# ── 5. The backup restored with the previous release, into an empty project ──
say "restoring the backup with $PREV_VERSION ($RESTORED, 127.0.0.1:$RESTORED_PORT)"
prose "$OLD_DIR"            # "from the old directory": its compose.yaml, .env and the backup files
run_block RESTORE_COMMANDS "$RESTORED" "$RESTORED_PORT" "s/YYYY-MM-DD/$DAY/g" || finish
note restore "$LAST_BLOCK_S" durations
healthy "$RESTORED_PORT" && step "health restored" PASS 0 "GET /api/health ok on $PREV_VERSION, restored" \
    || abort "health restored" 0 "no healthy API on 127.0.0.1:$RESTORED_PORT after 300 s"
"${JOURNEY[@]}" bundle --api "http://127.0.0.1:$RESTORED_PORT" --job "$A_JOB" --out "$OUT/A-restored.meta.json" --expect-sha256 "$A_SHA" --expect-status "$A_STATUS" >/dev/null \
    && step "report A restored" PASS 0 "status and bundle sha256 as exported" \
    || step "report A restored" FAIL 0 "$(cat "$OUT/A-restored.meta.json" 2>/dev/null)"
RESTORED_SCHEMA="$(schema_version "$RESTORED" "$OLD_DIR")"
C_THERE="$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$RESTORED_PORT/api/jobs/${C_JOB:-none}")"
[[ "$RESTORED_SCHEMA" =~ ^[0-9]+$ ]] && [ "$RESTORED_SCHEMA" = "$SCHEMA_BEFORE" ] && [ "$C_THERE" = 404 ] \
    && step "restored as backed up" PASS 0 "schema $RESTORED_SCHEMA, report C (made after the backup) absent" \
    || step "restored as backed up" FAIL 0 "schema $RESTORED_SCHEMA (backup: $SCHEMA_BEFORE), report C: HTTP $C_THERE"

finish
