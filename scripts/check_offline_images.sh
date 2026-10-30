#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# scripts/check_offline_images.sh — the image half of an air-gap bundle works
# with no registry (ADR-0054; runs in CI's container-image job).
#
# scripts/package_offline_docker.sh saves the stack's images into
# images.tar.gz; `setup.sh --offline` loads them back. Nothing exercised that
# round trip, so two bugs went unnoticed:
#   1. compose.yaml pins images as name:tag@sha256:…. `docker save` of such a
#      reference records no name, so after `docker load` the image is <none>
#      and Compose cannot find it offline. offline_docker_save_images saves
#      those images under their plain name:tag, which fixes the name. On the
#      classic image store (overlay2 without the containerd snapshotter, as on
#      GitHub's Ubuntu runners) `docker load` still never restores the registry
#      digest, so the pinned reference stays "No such image". There,
#      offline_write_compose_override writes a compose.override.yaml naming the
#      plain tags of those services.
#   2. `docker compose config --images --profile ollama` is not valid, and its
#      error was swallowed, so --with-llm bundles lacked the Ollama image.
#
# What this does, with the functions in scripts/offline_lib_docker.sh:
#   - lists the bundle's images (offline_bundle_images) and checks that the
#     --with-llm list carries the Ollama image (bug 2);
#   - checks that the --with-proxy list carries the nginxinc/ proxy image. It is
#     listed, not round-tripped (CI cost);
#   - requires the app image (CTI_IMAGE, default ctiparsor:local) to be built.
#     It is not round-tripped: it is a plain tag, which docker save and load
#     always carry, and it is several GB;
#   - pulls what is missing, saves the other images, removes them locally and
#     loads the archive back (offline_docker_save_images, offline_docker_load_images);
#   - writes compose.override.yaml if the image store needs one
#     (offline_write_compose_override);
#   - runs `docker image inspect` on every image `docker compose config --images`
#     names (default profile, override applied): the lookup Compose does with
#     pull_policy: missing (bug 1).
# Nothing is pulled after the save, so a PASS means the archive, plus the
# override where one was needed, brings every image back under a name Compose
# asks for.
#
# DESTRUCTIVE: it removes the stack's local images (not the app image) and
# loads them back from the archive. It refuses to run if a compose.override.yaml
# already exists, and removes the one it wrote on exit. Run it on a CI runner or
# another host where that is acceptable. It needs .env (compose.yaml's env_file).
#
# Usage: bash scripts/check_offline_images.sh --yes [-h|--help]
#   --yes       required: confirms that the local images are removed and reloaded
#   -h, --help  print this header
# =============================================================================

cd "$(dirname "$0")/.."
# shellcheck source=scripts/offline_lib_docker.sh
source scripts/offline_lib_docker.sh

APP_IMAGE="${CTI_IMAGE:-ctiparsor:local}"
CONFIRMED=false
FAILED=0
TMP=""
REMOVE_OVERRIDE=false

# Runs on every exit, the die paths included. The override is removed only when
# it was absent at the start of this run (checked below), so an operator's
# file is never touched.
cleanup() {
    if [ -n "$TMP" ]; then rm -rf "$TMP"; fi
    if [ "$REMOVE_OVERRIDE" = true ]; then rm -f compose.override.yaml; fi
}
trap cleanup EXIT

for arg in "$@"; do
    case "$arg" in
        --yes) CONFIRMED=true ;;
        -h|--help)
            sed -n '4,50p' "$0" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *) offline_die "unknown argument: $arg (see --help)" ;;
    esac
done
[ "$CONFIRMED" = true ] || offline_die "refusing to run without --yes: this removes local images and reloads them (see --help)"

command -v docker >/dev/null 2>&1 || offline_die "docker not found on PATH"
docker compose version >/dev/null 2>&1 || offline_die "docker compose plugin not found"
[ -f .env ] || offline_die ".env missing — copy .env.example to .env first (compose.yaml reads it as env_file)"
[ ! -e compose.override.yaml ] || offline_die "compose.override.yaml already exists: this check writes and removes that file, so it will not run beside your own override — move it aside first"
REMOVE_OVERRIDE=true

echo "=== [1/5] Image lists (the bundle, with and without --with-llm) ==="
IMAGES_LIST=$(offline_bundle_images false) || offline_die "offline_bundle_images false failed (see the compose error above)"
[ -n "$IMAGES_LIST" ] || offline_die "offline_bundle_images false listed no images"
mapfile -t IMAGES <<< "$IMAGES_LIST"
printf '  %s\n' "${IMAGES[@]}"

WITH_LLM_LIST=$(offline_bundle_images true) || offline_die "offline_bundle_images true failed (see the compose error above)"
if grep -q '^ollama/' <<< "$WITH_LLM_LIST"; then
    echo "  PASS  --with-llm list carries an ollama/ image"
else
    echo "  FAIL  --with-llm list carries no ollama/ image (bug 2: the ollama profile is not read)"
    FAILED=1
fi

WITH_PROXY_LIST=$(offline_bundle_images false true) || offline_die "offline_bundle_images false true failed (see the compose error above)"
if grep -q '^nginxinc/' <<< "$WITH_PROXY_LIST"; then
    echo "  PASS  --with-proxy list carries an nginxinc/ image"
else
    echo "  FAIL  --with-proxy list carries no nginxinc/ image (the proxy profile is not read)"
    FAILED=1
fi

echo "=== [2/5] Images on this host (the app image must be built; the others are pulled) ==="
docker image inspect "$APP_IMAGE" >/dev/null 2>&1 \
    || offline_die "$APP_IMAGE is not built on this host — build it first (docker compose build app)"
ROUND_TRIP=()
for ref in "${IMAGES[@]}"; do
    if [ "$ref" = "$APP_IMAGE" ]; then
        continue
    fi
    docker image inspect "$ref" >/dev/null 2>&1 || docker pull "$ref"
    ROUND_TRIP+=("$ref")
done
echo "  ✔  ${#ROUND_TRIP[@]} images present ($APP_IMAGE is built, not round-tripped)"

echo "=== [3/5] Saving the bundle's images, then removing them locally ==="
TMP=$(mktemp -d)
offline_docker_save_images "$TMP/images.tar.gz" "${ROUND_TRIP[@]}"
for ref in "${ROUND_TRIP[@]}"; do
    # "No such image" is expected for a name that was already untagged above.
    docker image rm -f "$ref" >/dev/null 2>&1 || true
    docker image rm -f "${ref%@*}" >/dev/null 2>&1 || true
done
# Nothing may be left, or the load below would prove nothing.
for ref in "${ROUND_TRIP[@]}"; do
    for name in "$ref" "${ref%@*}"; do
        if docker image inspect "$name" >/dev/null 2>&1; then
            offline_die "$name is still on this host after docker image rm — the load check would prove nothing"
        fi
    done
done
echo "  ✔  saved to images.tar.gz and removed locally"

echo "=== [4/5] Loading the archive back (no registry, no pull), then the compose override ==="
offline_docker_load_images "$TMP"
offline_write_compose_override "${ROUND_TRIP[@]}"

echo "=== [5/5] Resolving what Compose asks for, as with pull_policy: missing ==="
if [ -f compose.override.yaml ]; then
    echo "  →  compose.override.yaml written (classic image store: the pinned digests did not resolve after load):"
    sed 's/^/       /' compose.override.yaml
else
    echo "  →  no compose.override.yaml: every pinned reference resolved after load (containerd image store)"
fi
RESOLVED_LIST=$(docker compose config --images | sort -u) || offline_die "docker compose config --images failed"
[ -n "$RESOLVED_LIST" ] || offline_die "docker compose config --images listed no images"
mapfile -t RESOLVED <<< "$RESOLVED_LIST"
for ref in "${RESOLVED[@]}"; do
    if docker image inspect "$ref" >/dev/null 2>&1; then
        echo "  PASS  $ref"
    else
        echo "  FAIL  $ref"
        FAILED=1
    fi
done

if [ "$FAILED" -ne 0 ]; then
    echo ""
    echo "Air-gap image check FAILED (see the FAIL lines above)." >&2
    exit 1
fi
echo ""
echo "Air-gap image check passed: every image Compose asks for resolves after save and load, with no pull."
