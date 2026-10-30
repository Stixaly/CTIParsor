#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# scripts/update_offline_corpora.sh — refresh the detection-rule corpora on an
# air-gapped install from a corpora bundle (built by package_offline_corpora.sh).
#
#   bash scripts/update_offline_corpora.sh [DIR]     DIR defaults to offline-corpora
#
# What it does: verifies the bundle, replaces the corpora/ directory of the
# ctiparsor_cti-cache volume with the bundle's clones, then rebuilds the rule
# store from them (build_detection_index.py reads the clones and writes the
# detection tables; no network).
#
# What it does NOT touch: the job store (reports and everything else in the job
# tables), cti-state (uploads and outputs), the rest of cti-cache (hf/, the NLP
# models), or the source tree. The rebuild writes only the detection tables and
# the dedup pass over them. One caveat: build_detection_index.py calls init_db()
# first, which applies pending schema migrations to either store when the image
# is newer than the database. That is what every bootstrap does, and on a host
# whose image and database came from the same bundle there are none to apply.
#
# It never needs the network: the rebuild reads the clones on disk, and the swap
# runs in an alpine container started with --network none.
#
# DIR is relative to the repo root, like setup.sh --offline=DIR. A full bundle
# (package_offline_docker.sh) is refused: it goes to setup.sh --offline instead.
# =============================================================================

cd "$(dirname "$0")/.."
# shellcheck source=scripts/offline_lib_docker.sh
source scripts/offline_lib_docker.sh

VOLUME="ctiparsor_cti-cache"   # compose.yaml: `name: ctiparsor` + volume cti-cache
IMAGE="alpine:latest"          # in every full bundle, so present with no pull

usage() {
    cat <<'EOF'
Usage: bash scripts/update_offline_corpora.sh [DIR]

  DIR          The directory holding the unpacked corpora bundle, relative to the
               repo root (default: offline-corpora).
  -h, --help   Show this help.
EOF
}

case "${1:-}" in
    -h|--help) usage; exit 0 ;;
    -*) offline_die "unknown option: $1 (see --help)" ;;
esac
[ "$#" -le 1 ] || offline_die "one bundle directory at most (see --help)"
DIR_ARG="${1:-offline-corpora}"

echo "=== [1/4] Verifying the bundle ==="
# offline_validate_bundle reads BUNDLE_ARCH under `set -u` once bundle.env is
# sourced. A corpora bundle has no arch line (the clones are architecture-
# independent), so define it empty first. The arch check runs only when a bundle
# actually carries one.
BUNDLE_ARCH=""
offline_validate_bundle "$DIR_ARG"
[ "${BUNDLE_KIND:-}" = corpora ] \
    || offline_die "$DIR_ARG is not a corpora bundle (BUNDLE_KIND=${BUNDLE_KIND:-unset}). A full bundle goes to: bash setup.sh --offline=$DIR_ARG"
echo "  →  corpora in the bundle: ${BUNDLE_CORPORA:-none recorded}"
echo "  ⚠  built from git ${BUNDLE_GIT_REV:-unknown}. The rebuild runs the app image loaded on this host,"
echo "     not this checkout (its parsers and detection_corpora.yaml come from that image), so the"
echo "     image should come from the same revision. Nothing here checks it."
DIR=$(cd "$DIR_ARG" && pwd)
ARCHIVE="$DIR/corpora.tar.gz"

echo "=== [2/4] Checking corpora.tar.gz ==="
[ -f "$ARCHIVE" ] || offline_die "$ARCHIVE missing from the bundle"
offline_check_tar_safe "$ARCHIVE" -z
# offline_check_tar_safe drops the status of its `tar -t` (stderr goes to
# /dev/null), so a truncated or corrupt archive passes it. Listing the archive
# here, with the status kept, fails closed on that case.
members=$(tar -tzf "$ARCHIVE") || offline_die "cannot read $ARCHIVE as a gzip tar (truncated or corrupt)"
outside=$(printf '%s\n' "$members" | grep -v -E '^corpora(/|$)' || true)
if [ -n "$outside" ]; then
    offline_die "members outside corpora/ — refusing to extract:
$outside"
fi
grep -q -E '^corpora/' <<< "$members" || offline_die "$ARCHIVE has no corpora/ directory"
echo "  ✔  every member is under corpora/"

[ -f .secrets/db_password ] || offline_die ".secrets/db_password missing — the rebuild needs it (setup.sh creates it)"
command -v docker >/dev/null 2>&1 || offline_die "docker not found on PATH"
docker compose version >/dev/null 2>&1 || offline_die "docker compose plugin not found"
docker volume inspect "$VOLUME" >/dev/null 2>&1 \
    || offline_die "volume $VOLUME does not exist — this host has not been set up yet (setup.sh --offline, or bootstrap)"

echo "=== [3/4] Replacing corpora/ in $VOLUME (hf/ is not touched) ==="
# One throwaway container, no network, running this script under busybox sh.
# Order matters: the live corpora/ is not touched until the whole archive has
# unpacked, so an extraction error leaves the old corpora in place. Everything
# after the unpack is a rename inside the volume. The only moment corpora/ is
# absent is the gap between the two renames, so run this with the queue idle
# (see step 4).
# The archive's top level is corpora/, so it unpacks under corpora.incoming and
# that directory is renamed to corpora.new. The clones must keep the owners the
# archive carries (uid 1001, the app user), because the app has to be able to git
# pull into them. Root extraction is expected to keep owners, and the check
# below refuses the swap if it did not. The owner to match is the cache root's:
# the Dockerfile chowns /app/cache to that uid, and docker/entrypoint.sh
# ensure_dirs needs it writable.
SWAP='set -eu
cd /data
# Leftovers from a run that died. A corpora.old with no corpora/ is the live
# tree that was being swapped out, so it goes back. Otherwise it is stale.
if [ -e corpora.old ]; then
    if [ -e corpora ]; then rm -rf corpora.old; else mv corpora.old corpora; fi
fi
rm -rf corpora.incoming corpora.new
trap "rm -rf /data/corpora.incoming /data/corpora.new" EXIT
mkdir corpora.incoming
tar -xzf /backup/corpora.tar.gz -C corpora.incoming
mv corpora.incoming/corpora corpora.new
rm -rf corpora.incoming
if [ "$(stat -c %u:%g corpora.new)" != "$(stat -c %u:%g .)" ]; then
    echo "extracted corpora/ is owned by $(stat -c %u:%g corpora.new), the cache root by $(stat -c %u:%g .) - not swapping in" >&2
    exit 1
fi
had_old=false
if [ -e corpora ]; then mv corpora corpora.old; had_old=true; fi
if ! mv corpora.new corpora; then
    if [ "$had_old" = true ]; then mv corpora.old corpora; fi
    exit 1
fi
rm -rf corpora.old || echo "  note: could not remove corpora.old" >&2
'
docker run --rm --network none \
    -v "$VOLUME:/data" \
    -v "$DIR:/backup:ro" \
    "$IMAGE" sh -c "$SWAP" \
    || offline_die "could not replace corpora/ (see above). The rule store was not rebuilt."
echo "  ✔  corpora/ replaced"

echo "=== [4/4] Rebuilding the rule store from the new clones ==="
# Whether the running app or worker needs a restart. No: nothing keeps rule rows
# in process memory, so the next request and the next report read the new store.
# Checked by reading the code:
#  - The rule-store functions (pipeline/detection/store.py, coverage.py,
#    artifacts.py, relevance.py) run their SQL when they are called, on the
#    connection from api/db.py (get_rule_conn and get_conn are the same per-thread
#    connection). That connection is autocommit, not a snapshot, so each read sees
#    the rows committed so far.
#  - The lru_caches under pipeline/detection/ hold ATT&CK metadata
#    (phases._technique_index, built from mitre_db), not rule rows. The other
#    lru_caches the search turned up (pipeline/ttp_retrieval.py,
#    pipeline/attack_data.py, api/db_backend.py) hold TTP corpora, release
#    metadata, file hashes and SQL text. coverage.py's _widened_matchable is
#    rebuilt per call on purpose ("rather than cached at module level").
# So this script prints no restart instruction. The rebuild is not atomic for
# readers, though: rebuild_store commits statement by statement (autocommit), so a
# report running during it can read a corpus that is half replaced. Run it while
# the queue is idle.
echo "  ⚠  the rebuild commits one statement at a time: run it while no report is running"
docker compose --profile bootstrap run --rm bootstrap python scripts/build_detection_index.py \
    || offline_die "rule-store rebuild failed. The corpora on the volume are the new ones, and the rule store may be partly rebuilt. Run again: docker compose --profile bootstrap run --rm bootstrap python scripts/build_detection_index.py"

echo ""
echo "  ✔  corpora updated: ${BUNDLE_CORPORA:-}"
echo "  ✔  rule store rebuilt from them (per-corpus rule counts are in the table above)"
