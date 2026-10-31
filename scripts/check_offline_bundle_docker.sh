#!/usr/bin/env bash
set -u

# =============================================================================
# scripts/check_offline_bundle_docker.sh — verify a Docker air-gap bundle
# actually works (ADR-0054, replaces the old scripts/check_offline_bundle.sh
# dry-run checker).
#
# The old checker stubbed sudo/dpkg and blackholed the network to PROVE no
# install step reached out. That machinery doesn't apply here: `docker load`
# and a named-volume restore are offline by construction, nothing to prove
# absent. What's worth checking instead is that the RESTORED STACK WORKS —
# so this script does the load+restore itself (the thin wrapper part, using
# scripts/offline_lib_docker.sh) and then hands off to the existing
# scripts/docker_smoke.sh for the "does it actually serve traffic correctly"
# half, which every other Docker verification path in this repo already uses.
#
# Usage: bash scripts/check_offline_bundle_docker.sh [DIR] [--job] [--teardown] [--allow-no-llm]
#   DIR              extracted bundle directory (default: offline)
#   --job            also run docker_smoke.sh's end-to-end sample-report check. It is what
#                    proves the LLM and the NLP models ran: the job's stage report must
#                    show the stages in SMOKE_REQUIRED_STAGES as run
#   --teardown       bring the stack down afterwards (default: left running,
#                    since a real air-gap install wants it running)
#   --allow-no-llm   accept a .env with no local LLM. Stage 3 is then not required by
#                    --job, which requires 2c 2d 2e instead (unless SMOKE_REQUIRED_STAGES
#                    is already set)
#
# Run this on the machine you actually intend to test isolation on — copy the
# bundle there and cut network access (firewall rule, or a NIC-less VM)
# before running it, exactly as before.
# =============================================================================

cd "$(dirname "$0")/.."
# shellcheck source=scripts/offline_lib_docker.sh
source scripts/offline_lib_docker.sh

# Pin the Compose project for the whole script (restore, smoke test, teardown):
# the volume names below are hard-coded as ctiparsor_* (compose.yaml's `name:`),
# so a caller's COMPOSE_PROJECT_NAME must not redirect them. Exported so
# docker_smoke.sh inherits it, instead of its own default ctiparsor-smoke, which
# would start an empty stack and never test the restored one. Sharing the
# project is safe: this script never passes --clean, the only way
# docker_smoke.sh runs `down -v`, and the smoke refuses it on any project but
# its own. SMOKE_ALLOW_PROJECT tells the smoke this project is meant.
export COMPOSE_PROJECT_NAME=ctiparsor
export SMOKE_ALLOW_PROJECT=ctiparsor

DIR="offline"
DO_JOB=false
TEARDOWN=false
ALLOW_NO_LLM=false
for arg in "$@"; do
    case "$arg" in
        --job) DO_JOB=true ;;
        --teardown) TEARDOWN=true ;;
        --allow-no-llm) ALLOW_NO_LLM=true ;;
        -h|--help)
            sed -n '4,/^# =====/p' "$0" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *) DIR="$arg" ;;
    esac
done
# --allow-no-llm: docker_smoke.sh then requires only the stages that need no LLM.
# A value the caller set is kept.
if [ "$ALLOW_NO_LLM" = true ] && [ -z "${SMOKE_REQUIRED_STAGES:-}" ]; then
    export SMOKE_REQUIRED_STAGES="2c 2d 2e"
fi

command -v docker >/dev/null 2>&1 || offline_die "docker not found on PATH"
docker compose version >/dev/null 2>&1 || offline_die "docker compose plugin not found"
command -v curl >/dev/null 2>&1 || offline_die "curl not found (needed by docker_smoke.sh)"
command -v python3 >/dev/null 2>&1 || offline_die "python3 not found (needed by docker_smoke.sh)"
[ -f .env ] || offline_die ".env missing — run 'bash setup.sh' once before checking a bundle"
[ -f .secrets/db_password ] || offline_die ".secrets/db_password missing — run 'bash setup.sh' once before checking a bundle"

# Stage 3 needs an LLM the air-gapped stack can reach. Without one the pipeline skips
# Stage 3 and still finishes, so the .env is checked here, before the stack starts.
check_llm_config() {
    local provider model base_url url_var="" url shown local_re='^https?://(localhost|127\.0\.0\.1)([:/]|$)'
    provider=$(offline_env_value LLM_PROVIDER)
    provider="${provider,,}"  # the code lowercases LLM_PROVIDER too
    if [ -n "${BUNDLE_OLLAMA_MODEL:-}" ]; then
        model=$(offline_env_value OLLAMA_MODEL)
        base_url=$(offline_env_value OLLAMA_BASE_URL)
        base_url="${base_url%/}"  # one trailing slash is not a different URL
        if [ "$provider" != ollama ] || [ "$model" != "$BUNDLE_OLLAMA_MODEL" ] || [ "$base_url" != "http://ollama:11434" ]; then
            offline_die "the bundle carries the Ollama model $BUNDLE_OLLAMA_MODEL, and .env does not use it. Set these lines in .env, then run the check again:
  LLM_PROVIDER=ollama
  OLLAMA_MODEL=$BUNDLE_OLLAMA_MODEL
  OLLAMA_BASE_URL=http://ollama:11434"
        fi
        echo "  ✔  .env: LLM_PROVIDER=ollama, OLLAMA_MODEL=$BUNDLE_OLLAMA_MODEL"
    elif [ "$provider" = ollama ] || [ "$provider" = vllm ] || [ "$provider" = lmstudio ]; then
        echo "  ✔  .env: LLM_PROVIDER=$provider (a local server, not part of the bundle)"
        case "$provider" in
            ollama) url_var=OLLAMA_BASE_URL ;;
            vllm) url_var=VLLM_BASE_URL ;;
            lmstudio) url_var=LMSTUDIO_BASE_URL ;;
        esac
        url=$(offline_env_value "$url_var")
        # Warned, not refused: inside a container, localhost is the container itself, so a
        # server on this host (or an empty URL) does not answer the app there.
        if [ -z "$url" ] || [[ "$url" =~ $local_re ]]; then
            echo "  ⚠  .env: $url_var=${url:-<empty>} does not name a server the containers can reach: localhost, in a container, is the container itself. Set $url_var to the server's address as the containers see it."
        fi
    elif [ "$ALLOW_NO_LLM" = true ]; then
        echo "  –  .env: no local LLM, accepted by --allow-no-llm (Stage 3 is not required)"
    else
        shown="${provider:-unset, which the code reads as anthropic}"
        offline_die "LLM_PROVIDER in .env is $shown. Stage 3 cannot reach a cloud provider on an air-gapped host, and the pipeline does not fail when it is skipped.
Set LLM_PROVIDER to ollama, vllm or lmstudio in .env, or rebuild the bundle with a local model: package_offline_docker.sh --with-llm
To check this bundle without an LLM anyway, run again with --allow-no-llm."
    fi
}

echo "=== [1/6] Validating bundle: $DIR ==="
offline_validate_bundle "$DIR"
# bundle.env is sourced now, so BUNDLE_OLLAMA_MODEL is known. `false`: this run did not
# create .env, so the LLM lines are only printed; an existing .env keeps its own settings.
offline_write_env_hints false
check_llm_config

echo "=== [2/6] Loading images (offline) ==="
offline_docker_load_images "$DIR"
# BUNDLE_IMAGES (bundle.env, set by offline_validate_bundle) is a space-separated
# list of references: splitting it into one argument per image is the point.
# shellcheck disable=SC2086
offline_write_compose_override $BUNDLE_IMAGES

echo "=== [3/6] Restoring cti-cache (offline) ==="
offline_docker_restore_volume "$DIR" ctiparsor_cti-cache cti-cache.tar.gz required
if [ -n "${BUNDLE_OLLAMA_MODEL:-}" ]; then
    offline_docker_restore_volume "$DIR" ctiparsor_ollama-models ollama-models.tar.gz required
fi

echo "=== [4/6] Restoring the database (offline) ==="
docker compose up -d postgres
offline_wait_postgres_healthy 90 \
    || offline_die "postgres did not become healthy — check 'docker compose logs postgres'"
offline_docker_restore_pg_dump "$DIR"

echo "=== [5/6] Starting the local LLM (offline) ==="
if [ -n "${BUNDLE_OLLAMA_MODEL:-}" ]; then
    docker compose --profile ollama up -d ollama || offline_die "ollama did not start — check 'docker compose logs ollama'"
    waited=0
    until docker compose --profile ollama exec -T ollama ollama list >/dev/null 2>&1; do
        [ "$waited" -lt 60 ] || offline_die "ollama did not answer within 60 s — check 'docker compose logs ollama'"
        sleep 2
        waited=$((waited + 2))
    done
    # `ollama list` prints NAME, ID, SIZE, MODIFIED; a model pulled as `mistral` shows as `mistral:latest`.
    installed=$(docker compose --profile ollama exec -T ollama ollama list 2>/dev/null | awk 'NR > 1 { print $1 }')
    read -ra models <<< "${BUNDLE_OLLAMA_MODELS:-$BUNDLE_OLLAMA_MODEL}"
    for model in "${models[@]}"; do
        grep -qxF -e "$model" -e "${model}:latest" <<< "$installed" \
            || offline_die "model $model is not in the ollama volume: the bundle's ollama-models archive does not carry it"
    done
    echo "  ✔  ollama answers, with: ${models[*]}"
else
    echo "  –  no local LLM in this bundle, nothing to start"
fi

echo "=== [6/6] Verifying the stack (docker_smoke.sh, no build, no network) ==="
SMOKE_ARGS=(--no-build --keep)
$DO_JOB && SMOKE_ARGS+=(--job)
bash scripts/docker_smoke.sh "${SMOKE_ARGS[@]}"
SMOKE_STATUS=$?

echo ""
echo "=== Extra check: detection-corpora rule count (not covered by docker_smoke.sh) ==="
BIND="${CTI_BIND:-127.0.0.1}"; PORT="${CTI_PORT:-8000}"
# Fetched, then parsed: never `curl | python3`, which reads as download-and-run.
CORPORA_JSON=$(curl -fsS "http://$BIND:$PORT/api/detection-corpora" 2>/dev/null)
RULE_COUNT=$(printf '%s' "$CORPORA_JSON" \
    | python3 -c 'import json,sys; d=json.load(sys.stdin); print(sum(c.get("rules", 0) for c in d.get("corpora", [])))' 2>/dev/null)
if [ -n "$RULE_COUNT" ] && [ "$RULE_COUNT" -gt 0 ] 2>/dev/null; then
    echo "  PASS  detection-corpora rule count: $RULE_COUNT"
else
    echo "  FAIL  detection-corpora rule count (got: '${RULE_COUNT:-empty}') — the pg_restore may not have carried the rule store"
    SMOKE_STATUS=1
fi

if [ "$TEARDOWN" = true ]; then
    echo "Tearing down (--teardown)..."
    docker compose down
fi

exit $SMOKE_STATUS
