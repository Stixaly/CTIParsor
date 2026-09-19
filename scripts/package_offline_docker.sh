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
#   bash scripts/package_offline_docker.sh [--with-llm[=MODEL]] [--output DIR]
#
# Produces dist/cti-parsor-offline-docker-<rev>-<arch>.tar (+ .sha256).
# Install it on the target with: bash setup.sh --offline=<extracted-dir>
# =============================================================================

cd "$(dirname "$0")/.."
# shellcheck source=scripts/offline_lib_docker.sh
source scripts/offline_lib_docker.sh

WITH_LLM=false
OLLAMA_MODEL="${OLLAMA_MODEL:-mistral}"
OUTPUT_DIR="dist"
STAGE_DIR="offline"

usage() {
    cat <<'EOF'
Usage: bash scripts/package_offline_docker.sh [options]

  --with-llm[=MODEL]   Also bundle a local Ollama model (default: mistral).
                        Requires network access to pull it during packaging.
  --output DIR          Where to write the packed tarball (default: dist)
  -h, --help             Show this help
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        --with-llm) WITH_LLM=true; shift ;;
        --with-llm=*) WITH_LLM=true; OLLAMA_MODEL="${1#*=}"; shift ;;
        --output) OUTPUT_DIR="${2:?--output needs a directory}"; shift 2 ;;
        --output=*) OUTPUT_DIR="${1#*=}"; shift ;;
        -h|--help) usage; exit 0 ;;
        *) offline_die "unknown argument: $1 (see --help)" ;;
    esac
done

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

echo "=== [3/8] Saving images → images.tar.gz ==="
mapfile -t IMAGES < <(docker compose config --images | sort -u)
IMAGES+=("alpine:latest")
if $WITH_LLM; then
    mapfile -t OLLAMA_IMAGES < <(docker compose config --images --profile ollama | sort -u)
    IMAGES+=("${OLLAMA_IMAGES[@]}")
fi
mapfile -t IMAGES < <(printf '%s\n' "${IMAGES[@]}" | sort -u)
echo "  images: ${IMAGES[*]}"
docker save "${IMAGES[@]}" | gzip > "$STAGE_DIR/images.tar.gz"

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
docker compose exec -T postgres \
    pg_dump -Fc -U "${CTI_DB_USER:-ctiparsor}" -d "${CTI_DB_NAME:-ctiparsor}" \
    > "$STAGE_DIR/ctiparsor.dump"

if $WITH_LLM; then
    echo "=== [7/8] Pulling and exporting the Ollama model ($OLLAMA_MODEL) ==="
    docker compose --profile ollama up -d ollama
    for _ in $(seq 1 30); do
        docker compose exec -T ollama ollama list >/dev/null 2>&1 && break
        sleep 2
    done
    docker compose exec -T ollama ollama pull "$OLLAMA_MODEL"
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
        echo "BUNDLE_OLLAMA_MODEL=$OLLAMA_MODEL"
    fi
} > "$STAGE_DIR/bundle.env"

( cd "$STAGE_DIR" && find . -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 sha256sum > SHA256SUMS )
echo "  ✔  SHA256SUMS ($(wc -l < "$STAGE_DIR/SHA256SUMS" | tr -d ' ') files)"

TARBALL="$OUTPUT_DIR/cti-parsor-offline-docker-${GIT_REV}-${ARCH}.tar"
tar -cf "$TARBALL" -C "$(dirname "$STAGE_DIR")" "$(basename "$STAGE_DIR")"
sha256sum "$TARBALL" > "$TARBALL.sha256"

echo ""
echo "  Bundle: $TARBALL ($(du -h "$TARBALL" | cut -f1))"
echo "  Verify in transit with:  sha256sum -c $(basename "$TARBALL").sha256"
echo "  Install on the target:   tar -xf $(basename "$TARBALL") && bash setup.sh --offline=$STAGE_DIR"
