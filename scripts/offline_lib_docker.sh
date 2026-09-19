#!/usr/bin/env bash
# =============================================================================
# Shared functions for the Docker-based air-gap install (ADR-0054, supersedes
# ADR-0040's venv-based mechanism -- see docs/adr/0054-*.md for why).
#
# Sourced by setup.sh (install side) and scripts/package_offline_docker.sh
# (build side). Function definitions only -- nothing executes at source time.
#
# What changed from the old offline_lib.sh: a dozen staging functions
# (offline_stage_models/browsers/data/corpora/frontend, offline_install_debs/
# spacy_model/ollama) collapse into two generic mechanisms -- `docker load`
# for the image (which already contains Python/Node deps, Chromium, the
# built frontend, and the committed MITRE data files) and a tar-based named-
# volume restore for the two things `bootstrap` populates at runtime
# (cti-cache: HF models + corpus clones; the rule/job store: a pg_dump, not
# a raw pg-data tar -- see package_offline_docker.sh for why). The
# checksum-before-sourcing-config ordering and the zip-slip tar guard carry
# over unchanged; they were never venv-specific.
# =============================================================================

offline_die() {
    echo "  ✖  $*" >&2
    exit 1
}

# Zip-Slip guard: reject a tar whose members would write outside the
# extraction target (an absolute path, or a `..` path segment) before ever
# extracting it. Same check as pipeline/security.py::is_contained. Extra args
# are forwarded to `tar -t` (e.g. --use-compress-program for non-gzip).
offline_check_tar_safe() {
    local tar_path="$1"; shift
    local bad
    bad=$(tar -tf "$tar_path" "$@" 2>/dev/null | grep -E '^(/|.*\.\./)' || true)
    if [ -n "$bad" ]; then
        offline_die "unsafe path(s) in $tar_path — refusing to extract:
$bad"
    fi
}

# Verifies bundle.env + SHA256SUMS exist and every checksum matches BEFORE
# sourcing bundle.env -- deliberate ordering: nothing bundle-supplied runs as
# shell (or is trusted for anything) until its integrity is proven. Sets
# BUNDLE_* variables as a side effect (sourced into the caller's shell).
offline_validate_bundle() {
    local dir="$1"
    [ -f "$dir/bundle.env" ]   || offline_die "not a bundle: $dir/bundle.env missing"
    [ -f "$dir/SHA256SUMS" ]   || offline_die "not a bundle: $dir/SHA256SUMS missing"

    echo "  → verifying checksums…"
    ( cd "$dir" && sha256sum --quiet -c SHA256SUMS ) \
        || offline_die "checksum verification failed — the bundle is corrupt or tampered"
    echo "  ✔  checksums OK"

    # shellcheck disable=SC1091
    source "$dir/bundle.env"

    local host_arch
    host_arch=$(uname -m)
    if [ "${OFFLINE_FORCE:-}" != "1" ] && [ -n "${BUNDLE_ARCH:-}" ] && [ "$BUNDLE_ARCH" != "$host_arch" ]; then
        offline_die "architecture mismatch: bundle is $BUNDLE_ARCH, this host is $host_arch (set OFFLINE_FORCE=1 to override, at your own risk — Docker images are architecture-specific)"
    fi
    echo "  ✔  bundle built $BUNDLE_BUILT_AT from git $BUNDLE_GIT_REV ($BUNDLE_ARCH)"
}

# `docker load` every image tarball in the bundle. Multiple images (app,
# postgres, optionally ollama) are saved into ONE tar by `docker save img1
# img2 ... | gzip`, so one `docker load` restores all of them.
offline_docker_load_images() {
    local dir="$1"
    [ -f "$dir/images.tar.gz" ] || offline_die "$dir/images.tar.gz missing"
    echo "  → docker load < images.tar.gz (this can take a few minutes)…"
    gunzip -c "$dir/images.tar.gz" | docker load
    echo "  ✔  images loaded"
}

# Restores a named volume from a tar built by `docker run ... tar czf`
# (see package_offline_docker.sh::export_volume). Creates the volume if it
# doesn't already exist. `alpine` is loaded as part of images.tar.gz too
# (package_offline_docker.sh includes it) so this needs no network either.
offline_docker_restore_volume() {
    local dir="$1" volume_name="$2" archive_name="$3"
    local archive="$dir/$archive_name"
    [ -f "$archive" ] || { echo "  –  $archive_name not in bundle — skipping $volume_name"; return 0; }

    offline_check_tar_safe "$archive" -z

    docker volume inspect "$volume_name" >/dev/null 2>&1 || docker volume create "$volume_name" >/dev/null
    echo "  → restoring $volume_name from $archive_name…"
    docker run --rm \
        -v "${volume_name}:/data" \
        -v "$(cd "$dir" && pwd):/backup:ro" \
        alpine tar xzf "/backup/$archive_name" -C /data
    echo "  ✔  $volume_name restored"
}

# Restores the job store + rule store from a pg_dump (custom format, -Fc) --
# not a raw pg-data volume tar. Binary Postgres data directories are not
# reliably portable even between two instances of the exact same version;
# pg_dump/pg_restore is the mechanism this repo already documents and tests
# for backup/restore (docs/docker.md, ADR-0045/ADR-0053). Requires `postgres`
# already up and healthy -- the caller's job (see setup.sh).
offline_docker_restore_pg_dump() {
    local dir="$1" compose_project_user="${CTI_DB_USER:-ctiparsor}" compose_project_db="${CTI_DB_NAME:-ctiparsor}"
    local dump="$dir/ctiparsor.dump"
    [ -f "$dump" ] || offline_die "$dir/ctiparsor.dump missing"
    echo "  → pg_restore (job store + rule store, ADR-0053)…"
    docker compose exec -T postgres pg_restore -U "$compose_project_user" -d "$compose_project_db" --clean --if-exists < "$dump"
    echo "  ✔  database restored"
}

# Waits for the `postgres` compose service to report healthy. Uses `docker
# inspect` rather than `docker compose ps --format '{{.Health}}'` -- the
# former is what scripts/docker_smoke.sh already relies on and is known to
# work across compose versions; the latter's Go-template field support for
# health status varies. Caller must have already run `docker compose up -d
# postgres`.
offline_wait_postgres_healthy() {
    local timeout="${1:-90}" waited=0 id status
    while [ "$waited" -lt "$timeout" ]; do
        id=$(docker compose ps -q postgres 2>/dev/null)
        if [ -n "$id" ]; then
            status=$(docker inspect --format '{{.State.Health.Status}}' "$id" 2>/dev/null || echo "")
            [ "$status" = "healthy" ] && return 0
        fi
        sleep 2
        waited=$((waited + 2))
    done
    return 1
}

# Sets or appends a KEY=VALUE line in a file, in place.
_offline_set_key() {
    local file="$1" key="$2" value="$3"
    if grep -qE "^${key}=" "$file" 2>/dev/null; then
        sed -i "s#^${key}=.*#${key}=${value}#" "$file"
    else
        printf '%s=%s\n' "$key" "$value" >> "$file"
    fi
}

# If the bundle carries an Ollama model, point .env at it -- same fields the
# old offline_lib.sh set, minus everything HF/pip-offline related (no pip or
# HF Hub call happens on the host at all any more, so HF_HUB_OFFLINE /
# TRANSFORMERS_OFFLINE have nothing left to affect).
offline_write_env_hints() {
    local env_created="$1"
    [ -f .env ] || offline_die ".env should already exist by this point — internal error"
    if [ "$env_created" = true ] && [ -n "${BUNDLE_OLLAMA_MODEL:-}" ]; then
        _offline_set_key .env LLM_PROVIDER ollama
        _offline_set_key .env OLLAMA_MODEL "$BUNDLE_OLLAMA_MODEL"
        echo "  ✔  .env pointed at the bundled Ollama model: $BUNDLE_OLLAMA_MODEL"
    fi
}

offline_summary() {
    echo ""
    echo "  Air-gap install staged. Next:"
    echo "     docker compose up -d postgres   # wait for it to report healthy"
    echo "     (this script already restored the databases into it)"
    echo "     docker compose up -d            # app + worker"
    if [ -n "${BUNDLE_OLLAMA_MODEL:-}" ]; then
        echo "     docker compose --profile ollama up -d ollama"
    fi
    echo ""
    echo "  No 'docker compose --profile bootstrap run --rm bootstrap' needed —"
    echo "  the rule store and NLP model cache are already restored from the bundle."
}
