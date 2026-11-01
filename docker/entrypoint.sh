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
#                        --strict      exit 1 if a model or a corpus is missing, and check
#                                      that the models load from the cache with no network
#   cli <args...>        run the batch pipeline (main.py) with the given arguments
#   check                report which pipeline stages are available
#   <anything else>      executed as-is (e.g. bash, python -c ...)

set -euo pipefail

STATE_DIR=/app/state
CACHE_DIR=/app/cache

# If the DB password is delivered as a Docker secret (compose.yaml's
# `secrets: db_password`, mounted read-only at /run/secrets/db_password)
# rather than a plain `environment:` value, load it now. libpq (and hence
# psycopg, which every command below eventually needs) has no equivalent of
# Postgres's own *_FILE convention -- it only reads PGPASSWORD from the
# environment or a .pgpass file. `export` alone covers this script's own exec
# chain (serve/worker/bootstrap/cli), but NOT a process attached later via
# `docker exec`/`docker compose exec` -- that gets a fresh shell built from
# the container's static image-level env, never this script's runtime
# `export`. ~/.pgpass is also written for exactly that case: libpq reads it
# for any process running as this user, entrypoint or not. Field-wildcarded
# (`*`) since this container only ever talks to the one postgres compose
# wires it to. A deployment that still sets PGPASSWORD directly via .env
# keeps working unchanged: this only overrides it when the secret file is
# present.
load_db_password_secret() {
    if [ -r /run/secrets/db_password ]; then
        PGPASSWORD="$(cat /run/secrets/db_password)"
        export PGPASSWORD
        if [ -n "${HOME:-}" ] && [ -d "$HOME" ]; then
            printf '*:*:*:*:%s\n' "$PGPASSWORD" > "$HOME/.pgpass"
            chmod 600 "$HOME/.pgpass"
        fi
    fi
}
load_db_password_secret

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
    # DATABASE_URL carries no password (PGPASSWORD delivers that separately,
    # see compose.yaml), so it is safe to print as-is.
    echo "CTIParsor container - uid $(id -u) - state=$STATE_DIR - cache=$CACHE_DIR - db=${DATABASE_URL:-UNSET} - rev=${CTIPARSOR_GIT_REV:-unknown}"
}

warn_env() {
    local provider="${LLM_PROVIDER:-anthropic}"
    local key="${ANTHROPIC_API_KEY:-}"
    if [ "$provider" = "anthropic" ] && [[ "$key" == *xxxx* ]]; then
        echo "WARNING: ANTHROPIC_API_KEY is still the placeholder - Stage 3 (LLM extraction) will fail on every report. Set a real key in .env, or leave it empty." >&2
    elif [ "$provider" = "anthropic" ] && [ -z "$key" ]; then
        echo "NOTE: no LLM provider is set (ANTHROPIC_API_KEY is empty) - Stage 3 (LLM extraction) is skipped. Set one in .env." >&2
    fi

    local host="${API_HOST:-}"
    if [ -n "$host" ] && [ "$host" != "0.0.0.0" ]; then
        echo "WARNING: API_HOST=$host - inside a container only 0.0.0.0 is reachable through the published port." >&2
    fi
}

bootstrap() {
    local do_models=true
    local do_corpora=true
    local strict=false

    while [ $# -gt 0 ]; do
        case "$1" in
            --no-models)  do_models=false ;;
            --no-corpora) do_corpora=false ;;
            --strict)     strict=true ;;
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
        if ! python docker/warm_models.py; then
            if [ "$strict" = true ]; then
                echo "ERROR: some models did not download - --strict refuses a bundle without them" >&2
                exit 1
            fi
            echo "WARNING: some models did not download - they will be fetched on the first report instead" >&2
        elif [ "$strict" = true ]; then
            # The air-gapped run has no network: HF_HUB_OFFLINE makes warm_models.py read
            # the cache and download nothing, so this proves the cache is complete.
            if ! HF_HUB_OFFLINE=1 TRANSFORMERS_OFFLINE=1 python docker/warm_models.py; then
                echo "ERROR: the models do not load from the cache without network access - the bundle would not work air-gapped" >&2
                exit 1
            fi
        fi
    fi

    if [ "$do_corpora" = true ]; then
        echo "[bootstrap] detection corpora -> $CACHE_DIR/corpora"
        if ! python scripts/sync_corpora.py; then
            if [ "$strict" = true ]; then
                echo "ERROR: corpus sync incomplete - --strict refuses a bundle without its corpora" >&2
                exit 1
            fi
            echo "WARNING: corpus sync incomplete - re-run 'bootstrap --no-models' or use Settings > Redownload" >&2
        fi

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
