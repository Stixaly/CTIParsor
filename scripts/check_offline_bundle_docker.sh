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
# Usage: bash scripts/check_offline_bundle_docker.sh [DIR] [--job] [--teardown]
#   DIR         extracted bundle directory (default: offline)
#   --job       also run docker_smoke.sh's end-to-end sample-report check
#   --teardown  bring the stack down afterwards (default: left running,
#               since a real air-gap install wants it running)
#
# Run this on the machine you actually intend to test isolation on — copy the
# bundle there and cut network access (firewall rule, or a NIC-less VM)
# before running it, exactly as before.
# =============================================================================

cd "$(dirname "$0")/.."
# shellcheck source=scripts/offline_lib_docker.sh
source scripts/offline_lib_docker.sh

DIR="offline"
DO_JOB=false
TEARDOWN=false
for arg in "$@"; do
    case "$arg" in
        --job) DO_JOB=true ;;
        --teardown) TEARDOWN=true ;;
        -h|--help)
            sed -n '3,25p' "$0" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *) DIR="$arg" ;;
    esac
done

command -v docker >/dev/null 2>&1 || offline_die "docker not found on PATH"
docker compose version >/dev/null 2>&1 || offline_die "docker compose plugin not found"
command -v curl >/dev/null 2>&1 || offline_die "curl not found (needed by docker_smoke.sh)"
command -v python3 >/dev/null 2>&1 || offline_die "python3 not found (needed by docker_smoke.sh)"
[ -f .env ] || offline_die ".env missing — run 'bash setup.sh' once before checking a bundle"
[ -f .secrets/db_password ] || offline_die ".secrets/db_password missing — run 'bash setup.sh' once before checking a bundle"

echo "=== [1/5] Validating bundle: $DIR ==="
offline_validate_bundle "$DIR"

echo "=== [2/5] Loading images (offline) ==="
offline_docker_load_images "$DIR"

echo "=== [3/5] Restoring cti-cache (offline) ==="
offline_docker_restore_volume "$DIR" ctiparsor_cti-cache cti-cache.tar.gz
if [ -n "${BUNDLE_OLLAMA_MODEL:-}" ]; then
    offline_docker_restore_volume "$DIR" ctiparsor_ollama-models ollama-models.tar.gz
fi

echo "=== [4/5] Restoring the database (offline) ==="
docker compose up -d postgres
offline_wait_postgres_healthy 90 \
    || offline_die "postgres did not become healthy — check 'docker compose logs postgres'"
offline_docker_restore_pg_dump "$DIR"

echo "=== [5/5] Verifying the stack (docker_smoke.sh, no build, no network) ==="
SMOKE_ARGS=(--no-build --keep)
$DO_JOB && SMOKE_ARGS+=(--job)
bash scripts/docker_smoke.sh "${SMOKE_ARGS[@]}"
SMOKE_STATUS=$?

echo ""
echo "=== Extra check: detection-corpora rule count (not covered by docker_smoke.sh) ==="
BIND="${CTI_BIND:-127.0.0.1}"; PORT="${CTI_PORT:-8000}"
RULE_COUNT=$(curl -fsS "http://$BIND:$PORT/api/detection-corpora" 2>/dev/null \
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
