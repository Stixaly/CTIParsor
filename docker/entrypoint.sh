#!/usr/bin/env bash
#
# CTIParsor container entrypoint.
#
#   serve                (default) start the API and the web UI on $API_PORT
#   worker               run the job-queue supervisor: claims queued reports and
#                        runs the pipeline (ADR-0046); pair it with an API started
#                        with CTIPARSOR_ROLE=api
#   bootstrap [options]  one-shot: DB schema, NLP model warm-up, corpus sync, rule store
#                        --no-models   skip the HuggingFace downloads
#                        --no-corpora  skip the corpus clone + rule store build
#   cli <args...>        run the batch pipeline (main.py) with the given arguments
#   check                report which pipeline stages are available
#   <anything else>      executed as-is (e.g. bash, python -c ...)

set -euo pipefail

STATE_DIR=/app/state
CACHE_DIR=/app/cache

ensure_dirs() {
    mkdir -p "$STATE_DIR/uploads" "$STATE_DIR/output" "$STATE_DIR/backups" \
             "$CACHE_DIR/hf" "$CACHE_DIR/corpora" "$HOME" /tmp/matplotlib /tmp/cache || true

    local d
    for d in "$STATE_DIR" "$CACHE_DIR"; do
        if [ ! -w "$d" ]; then
            cat >&2 <<EOF
ERROR: $d is not writable by uid $(id -u).
       Named volumes inherit the owner from the image automatically. For a bind
       mount, give the host directory to the container user first:
         sudo chown -R $(id -u):$(id -g) <host-dir>
EOF
            exit 1
        fi
    done
}

banner() {
    echo "CTIParsor container - uid $(id -u) - state=$STATE_DIR - cache=$CACHE_DIR - db=${CTIPARSOR_DB_PATH:-?} - rev=${CTIPARSOR_GIT_REV:-unknown}"
}

warn_env() {
    local provider="${LLM_PROVIDER:-anthropic}"
    local key="${ANTHROPIC_API_KEY:-}"
    if [ "$provider" = "anthropic" ] && { [ -z "$key" ] || [[ "$key" == *xxxx* ]]; }; then
        echo "WARNING: ANTHROPIC_API_KEY is unset or still the placeholder - Stage 3 (LLM enrichment) will fail on every report. Set it in .env." >&2
    fi

    local host="${API_HOST:-}"
    if [ -n "$host" ] && [ "$host" != "0.0.0.0" ]; then
        echo "WARNING: API_HOST=$host - inside a container only 0.0.0.0 is reachable through the published port." >&2
    fi
}

bootstrap() {
    local do_models=true
    local do_corpora=true

    while [ $# -gt 0 ]; do
        case "$1" in
            --no-models)  do_models=false ;;
            --no-corpora) do_corpora=false ;;
            *)
                echo "unknown option: $1" >&2
                exit 2
                ;;
        esac
        shift
    done

    ensure_dirs
    banner

    echo "[bootstrap] database schema"
    python -c "from api.db import init_db; init_db()"

    if [ "$do_models" = true ]; then
        echo "[bootstrap] NLP models -> $HF_HOME"
        python docker/warm_models.py || \
            echo "WARNING: some models did not download - they will be fetched on the first report instead" >&2
    fi

    if [ "$do_corpora" = true ]; then
        echo "[bootstrap] detection corpora -> $CACHE_DIR/corpora"
        python scripts/sync_corpora.py || \
            echo "WARNING: corpus sync incomplete - re-run 'bootstrap --no-models' or use Settings > Redownload" >&2

        echo "[bootstrap] detection-rule store"
        python scripts/build_detection_index.py
    fi

    echo "[bootstrap] stage report"
    python scripts/check_stages.py || true
}

cmd="${1:-serve}"
if [ $# -gt 0 ]; then shift; fi
case "$cmd" in
    serve)     ensure_dirs; banner; warn_env; exec python run_api.py ;;
    worker)    ensure_dirs; banner; export CTIPARSOR_ROLE=worker; exec python -m api.queue_loop "$@" ;;
    bootstrap) bootstrap "$@" ;;
    cli)       ensure_dirs; exec python main.py "$@" ;;
    check)     exec python scripts/check_stages.py ;;
    *)         exec "$cmd" "$@" ;;
esac
