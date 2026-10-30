#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# scripts/package_offline_corpora.sh — a corpora-only refresh bundle for an
# air-gapped install (companion of scripts/package_offline_docker.sh).
#
# Run on a CONNECTED machine with Docker. The full bundle carries the rule store
# inside a pg_dump of the whole database, so today the only way to get newer
# rules onto an air-gapped host is to replace every analyst report with them.
# This bundle carries only the corpus clones (the corpora/ directory of the
# cti-cache volume). The target rebuilds its rule store from them and leaves
# the job store alone: scripts/update_offline_corpora.sh.
#
#   bash scripts/package_offline_corpora.sh [--output DIR] [--no-sync]
#
# Produces dist/cti-parsor-offline-corpora-<rev>-<YYYYMMDD>.tar (+ .sha256).
#
# Notes:
#  - The sync and the target's rebuild run inside the app IMAGE, not this
#    checkout: the image has its own copy of detection_corpora.yaml and the
#    parsers (Dockerfile: COPY . /app/). Build the image from this revision
#    first (docker compose build app), or what ships is not what HEAD says.
#  - Private corpora: their registry entries live in detection_corpora.local.yaml,
#    which is gitignored and excluded from the image. The containers read it at
#    /app/detection_corpora.local.yaml, a link into the cti-state volume, so it
#    must be in cti-state on this host for the sync to fetch a private corpus.
#    The bundle does not carry it. The target's rebuild ingests only the corpora
#    its own image registry and its own overlay list.
#  - The bundle carries every clone in corpora/, private ones included, the same
#    as the full bundle does with cti-cache.
#  - No BUNDLE_ARCH: the clones are architecture-independent.
# =============================================================================

cd "$(dirname "$0")/.."
# shellcheck source=scripts/offline_lib_docker.sh
source scripts/offline_lib_docker.sh

OUTPUT_DIR="dist"
NO_SYNC=false
STAGE_NAME="offline-corpora"   # not offline/: that is the full bundle's stage

usage() {
    cat <<'EOF'
Usage: bash scripts/package_offline_corpora.sh [options]

  --no-sync            Ship the clones as they are. By default they are refreshed
                       first with sync_corpora.py, which needs network access.
  --output DIR         Where to write the packed tarball (default: dist)
  -h, --help           Show this help
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        --no-sync) NO_SYNC=true; shift ;;
        --output) OUTPUT_DIR="${2:?--output needs a directory}"; shift 2 ;;
        --output=*) OUTPUT_DIR="${1#*=}"; shift ;;
        -h|--help) usage; exit 0 ;;
        *) offline_die "unknown argument: $1 (see --help)" ;;
    esac
done

command -v docker >/dev/null 2>&1 || offline_die "docker not found on PATH"
docker compose version >/dev/null 2>&1 || offline_die "docker compose plugin not found"
[ -f .env ] || offline_die ".env missing — run 'bash setup.sh' first"
[ -f .secrets/db_password ] || offline_die ".secrets/db_password missing — run 'bash setup.sh' first"

GIT_REV=$(git rev-parse --short HEAD 2>/dev/null || echo unknown)
BUILT_AT=$(date -u +%Y-%m-%dT%H:%M:%SZ)
DAY=$(date -u +%Y%m%d)
TARBALL_NAME="cti-parsor-offline-corpora-${GIT_REV}-${DAY}.tar"
STAGE_DIR="$OUTPUT_DIR/$STAGE_NAME"
TARBALL="$OUTPUT_DIR/$TARBALL_NAME"

echo "=== [1/4] Refreshing the clones ==="
if [ "$NO_SYNC" = true ]; then
    echo "  –  --no-sync: shipping the clones as they are"
else
    sync_log=$(mktemp)
    trap 'rm -f "$sync_log"' EXIT
    docker compose --profile bootstrap run --rm bootstrap python scripts/sync_corpora.py 2>&1 \
        | tee "$sync_log" \
        || offline_die "sync_corpora.py failed — nothing was packaged"
    # sync_corpora.py exits 0 even when a clone fails. Each failure prints a line
    # that starts with "  ! " (its _run() and its tarball branch), so look for those.
    if grep -q '^  ! ' "$sync_log"; then
        offline_die "a corpus did not sync (the '!' lines above) — nothing was packaged. Fix it, or pass --no-sync to ship the clones as they are"
    fi
    echo "  ✔  every corpus synced"
fi

echo "=== [2/4] Exporting the corpora/ directory of cti-cache ==="
rm -rf "$STAGE_DIR"
mkdir -p "$STAGE_DIR"
docker run --rm -v "ctiparsor_cti-cache:/data:ro" alpine:latest test -d /data/corpora \
    || offline_die "cti-cache has no corpora/ directory — bootstrap this host first: docker compose --profile bootstrap run --rm bootstrap"
docker run --rm \
    -v "ctiparsor_cti-cache:/data:ro" \
    -v "$(cd "$STAGE_DIR" && pwd):/backup" \
    alpine:latest tar czf /backup/corpora.tar.gz -C /data corpora
echo "  ✔  corpora.tar.gz ($(du -h "$STAGE_DIR/corpora.tar.gz" | cut -f1))"

echo "=== [3/4] Manifest and checksums ==="
# The corpus names are the top-level directories in the archive itself, so the
# manifest describes what was really written, not what the registry says.
CORPORA=$(tar -tzf "$STAGE_DIR/corpora.tar.gz" | awk -F/ '$1 == "corpora" && $2 != "" { print $2 }' | sort -u | paste -sd' ' -) \
    || offline_die "could not list $STAGE_DIR/corpora.tar.gz"
[ -n "$CORPORA" ] || offline_die "corpora.tar.gz holds no corpus directories"
{
    echo "BUNDLE_KIND=corpora"
    echo "BUNDLE_GIT_REV=$GIT_REV"
    echo "BUNDLE_BUILT_AT=$BUILT_AT"
    echo "BUNDLE_CORPORA=\"$CORPORA\""
} > "$STAGE_DIR/bundle.env"
echo "  ✔  bundle.env (corpora: $CORPORA)"

( cd "$STAGE_DIR" && find . -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 sha256sum > SHA256SUMS )
echo "  ✔  SHA256SUMS ($(wc -l < "$STAGE_DIR/SHA256SUMS" | tr -d ' ') files)"

echo "=== [4/4] Packing ==="
tar -cf "$TARBALL" -C "$OUTPUT_DIR" "$STAGE_NAME"
( cd "$OUTPUT_DIR" && sha256sum "$TARBALL_NAME" > "$TARBALL_NAME.sha256" )
# The archive is the deliverable. Leaving the stage would keep a second copy of
# the clones, which is large.
rm -rf "$STAGE_DIR"

echo ""
echo "  Bundle: $TARBALL ($(du -h "$TARBALL" | cut -f1))"
echo "  Verify in transit with:  (cd $OUTPUT_DIR && sha256sum -c $TARBALL_NAME.sha256)"
echo ""
echo "  Copy it to the target. In that host's checkout, at git $GIT_REV (with the app image"
echo "  built from the same revision), unpack it and run the update:"
echo "      tar xf $TARBALL_NAME && bash scripts/update_offline_corpora.sh offline-corpora"
