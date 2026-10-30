#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# scripts/package_offline_docker.sh — build a Docker-based air-gap install
# bundle (ADR-0054, supersedes ADR-0040's scripts/package_offline.sh).
#
# Run on a CONNECTED machine with Docker, of the SAME CPU architecture as the
# target host — Docker images are architecture-specific, there is no
# cross-arch fallback the way there was for the old wheel bundle.
#
#   bash scripts/package_offline_docker.sh [--with-llm[=MODEL[,MODEL...]]] [--with-proxy] [--output DIR]
#
# Produces dist/cti-parsor-offline-docker-<rev>-<arch>.tar (+ .sha256).
# Install it on the target with the steps the script prints at the end: the
# bundle plus the source tree at this commit, then bash setup.sh --offline=<dir>
# =============================================================================

cd "$(dirname "$0")/.."
# shellcheck source=scripts/offline_lib_docker.sh
source scripts/offline_lib_docker.sh

WITH_LLM=false
WITH_PROXY=false
OLLAMA_MODEL="${OLLAMA_MODEL:-mistral}"
MODEL_ARG=""
MODEL_GIVEN=false
OUTPUT_DIR="dist"
STAGE_DIR="offline"

usage() {
    cat <<'EOF'
Usage: bash scripts/package_offline_docker.sh [options]

  --with-llm[=MODEL[,MODEL...]]
                        Also bundle local Ollama models (default: mistral, or
                        $OLLAMA_MODEL when set). The first is the text model;
                        the others are for Stage 1f (vision). Requires network
                        access to pull them during packaging.
  --with-proxy          Also bundle the proxy profile's TLS + password front
                        (its nginx image, docs/docker.md), so it runs air-gapped.
  --output DIR          Where to write the packed tarball (default: dist)
  -h, --help            Show this help
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        --with-llm) WITH_LLM=true; shift ;;
        --with-llm=*) WITH_LLM=true; MODEL_ARG="${1#*=}"; MODEL_GIVEN=true; shift ;;
        --with-proxy) WITH_PROXY=true; shift ;;
        --output) OUTPUT_DIR="${2:?--output needs a directory}"; shift 2 ;;
        --output=*) OUTPUT_DIR="${1#*=}"; shift ;;
        -h|--help) usage; exit 0 ;;
        *) offline_die "unknown argument: $1 (see --help)" ;;
    esac
done

# One comma-separated list; the first name is the text model. An empty name
# (`a,,b`, `,a`, `a,`, `--with-llm=`) is refused, not silently dropped. Names are
# limited to Ollama's characters: BUNDLE_OLLAMA_MODEL is sourced by setup.sh on
# the target, and a `;` or `$` in it would run as shell there.
OLLAMA_MODELS=()
if $WITH_LLM; then
    if [ "$MODEL_GIVEN" = true ]; then LLM_LIST="$MODEL_ARG"; else LLM_LIST="$OLLAMA_MODEL"; fi
    model_list_re='^[A-Za-z0-9._/:-]+(,[A-Za-z0-9._/:-]+)*$'
    [[ "$LLM_LIST" =~ $model_list_re ]] \
        || offline_die "--with-llm: '$LLM_LIST' is not a comma-separated list of model names (letters, digits and . _ / : - only; no empty name)"
    IFS=',' read -r -a OLLAMA_MODELS <<< "$LLM_LIST"
    echo "  models: ${OLLAMA_MODELS[*]} (the first is the text model)"
fi
if $WITH_PROXY; then
    echo "  proxy: bundled (--with-proxy)"
fi

command -v docker >/dev/null 2>&1 || offline_die "docker not found on PATH"
docker compose version >/dev/null 2>&1 || offline_die "docker compose plugin not found"
[ -f .secrets/db_password ] || offline_die ".secrets/db_password missing — run 'bash setup.sh' first"

GIT_REV=$(git rev-parse --short HEAD 2>/dev/null || echo unknown)
ARCH=$(uname -m)
BUILT_AT=$(date -u +%Y-%m-%dT%H:%M:%SZ)

rm -rf "$STAGE_DIR"
mkdir -p "$STAGE_DIR" "$OUTPUT_DIR"

echo "=== [1/8] Building the app image ==="
CTI_GIT_REV="$(git rev-parse HEAD 2>/dev/null || echo unknown)" docker compose build app

echo "=== [2/8] Pulling supporting images ==="
docker compose pull postgres capture-proxy
docker pull alpine:latest
if $WITH_LLM; then
    docker compose --profile ollama pull ollama
fi
if $WITH_PROXY; then
    docker compose --profile proxy pull proxy
fi

echo "=== [3/8] Saving images → images.tar.gz ==="
IMAGES_LIST=$(offline_bundle_images "$WITH_LLM" "$WITH_PROXY")
mapfile -t IMAGES <<< "$IMAGES_LIST"
echo "  images: ${IMAGES[*]}"
offline_docker_save_images "$STAGE_DIR/images.tar.gz" "${IMAGES[@]}"

echo "=== [4/8] Running bootstrap locally (populates cti-cache + the rule store) ==="
docker compose up -d postgres
offline_wait_postgres_healthy 90 \
    || offline_die "postgres did not become healthy — check 'docker compose logs postgres'"
docker compose --profile bootstrap run --rm bootstrap

echo "=== [5/8] Exporting cti-cache (NLP models + corpus clones) ==="
docker run --rm \
    -v "ctiparsor_cti-cache:/data:ro" \
    -v "$(pwd)/$STAGE_DIR:/backup" \
    alpine tar czf /backup/cti-cache.tar.gz -C /data .

echo "=== [6/8] Exporting the rule store + job store (pg_dump) ==="
offline_pg_exec pg_dump -Fc -U "${CTI_DB_USER:-ctiparsor}" -d "${CTI_DB_NAME:-ctiparsor}" \
    > "$STAGE_DIR/ctiparsor.dump"

if $WITH_LLM; then
    echo "=== [7/8] Pulling and exporting the Ollama models (${OLLAMA_MODELS[*]}) ==="
    docker compose --profile ollama up -d ollama
    for _ in $(seq 1 30); do
        docker compose exec -T ollama ollama list >/dev/null 2>&1 && break
        sleep 2
    done
    for model in "${OLLAMA_MODELS[@]}"; do
        docker compose exec -T ollama ollama pull "$model"
    done
    docker run --rm \
        -v "ctiparsor_ollama-models:/data:ro" \
        -v "$(pwd)/$STAGE_DIR:/backup" \
        alpine tar czf /backup/ollama-models.tar.gz -C /data .
else
    echo "=== [7/8] Skipping Ollama (pass --with-llm to include a local model) ==="
fi

echo "=== [8/8] Manifest, checksums, pack ==="
{
    echo "BUNDLE_ARCH=$ARCH"
    echo "BUNDLE_GIT_REV=$GIT_REV"
    echo "BUNDLE_BUILT_AT=$BUILT_AT"
    echo "BUNDLE_IMAGES=\"${IMAGES[*]}\""
    echo "BUNDLE_DB_USER=${CTI_DB_USER:-ctiparsor}"
    echo "BUNDLE_DB_NAME=${CTI_DB_NAME:-ctiparsor}"
    if $WITH_LLM; then
        # The first model is the text model (setup.sh wires it into .env);
        # BUNDLE_OLLAMA_MODELS lists all of them, for the vision hint.
        echo "BUNDLE_OLLAMA_MODEL=${OLLAMA_MODELS[0]}"
        echo "BUNDLE_OLLAMA_MODELS=\"${OLLAMA_MODELS[*]}\""
    fi
} > "$STAGE_DIR/bundle.env"

( cd "$STAGE_DIR" && find . -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 sha256sum > SHA256SUMS )
echo "  ✔  SHA256SUMS ($(wc -l < "$STAGE_DIR/SHA256SUMS" | tr -d ' ') files)"

TARBALL="$OUTPUT_DIR/cti-parsor-offline-docker-${GIT_REV}-${ARCH}.tar"
tar -cf "$TARBALL" -C "$(dirname "$STAGE_DIR")" "$(basename "$STAGE_DIR")"
# Recorded from inside the output directory, so the checksum names the bare file:
# `sha256sum -c <name>.sha256` then works in dist/ and after the transfer, where
# the .tar and the .sha256 sit side by side.
TARBALL_NAME="$(basename "$TARBALL")"
( cd "$OUTPUT_DIR" && sha256sum "$TARBALL_NAME" > "$TARBALL_NAME.sha256" )

echo ""
echo "  Bundle: $TARBALL ($(du -h "$TARBALL" | cut -f1))"
echo "  Verify in transit (run where the .tar and the .sha256 sit together):"
echo "      sha256sum -c $TARBALL_NAME.sha256"
echo ""
echo "  On this machine, archive the source tree at this commit ($GIT_REV):"
echo "      git archive --format=tar.gz -o ctiparsor-src.tar.gz HEAD"
echo "  Copy both files to the target, then install there:"
echo "      mkdir ctiparsor && tar xzf ctiparsor-src.tar.gz -C ctiparsor && cd ctiparsor"
echo "      tar xf ../$(basename "$TARBALL") && bash setup.sh --offline=$STAGE_DIR"
