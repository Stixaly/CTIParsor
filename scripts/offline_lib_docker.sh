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

# Prints every image the bundle carries, one per line, sorted and de-duplicated:
# the default-profile services (app, worker, postgres, capture-proxy), the
# alpine image the volume tar steps run (not a compose service, so added by
# hand), and -- when WITH_LLM is true -- the ollama service. A failing compose
# command is fatal: the caller reads this through $(...), and a process
# substitution would hide the error, so the bundle would silently ship without
# the Ollama image (`docker compose config --images --profile ollama` is not
# valid -- --profile is a global flag and must come before the subcommand).
offline_bundle_images() {
    local with_llm="$1" default_images llm_images=""
    default_images=$(docker compose config --images) \
        || offline_die "docker compose config --images failed"
    if [ "$with_llm" = true ]; then
        llm_images=$(docker compose --profile ollama config --images) \
            || offline_die "docker compose --profile ollama config --images failed"
    fi
    printf '%s\n%s\n%s\n' "$default_images" "$llm_images" "alpine:latest" \
        | grep -v '^$' | sort -u
}

# Saves OUT_GZ (`docker save | gzip`) holding the given REFs. A digest-pinned
# reference (name:tag@sha256:...) is saved under its plain name:tag instead:
# measured on Docker 29.9.2, `docker save` of a digest reference records NO
# name in the archive, so after `docker load` the image is <none>:<none>,
# `docker image inspect 'name:tag@sha256:...'` says "No such image", and
# `docker compose up` tries to pull it -- which fails on an air-gapped host.
# `docker tag` gives the same image (same digest) the plain name. On the
# containerd image store (Docker Engine 29's default for new installs, Docker
# Desktop) Compose's pinned reference then resolves to it after `docker load`.
# On the classic store (overlay2: hosts installed before Engine 29 and upgraded,
# GitHub's ubuntu runners) `docker load` never restores a registry digest, so the
# pinned reference still does not resolve there -- offline_write_compose_override
# handles that case. REFs without a digest are saved as given.
offline_docker_save_images() {
    local out_gz="$1" ref name last names=()
    shift
    [ "$#" -gt 0 ] || offline_die "offline_docker_save_images: no images given"
    for ref in "$@"; do
        if [[ "$ref" == *@sha256:* ]]; then
            name="${ref%@*}"
            # `name@sha256:...` has no tag, so there is no plain name to save the
            # image under -- it would come back nameless, as described above.
            last="${name##*/}"
            [[ "$last" == *:* ]] \
                || offline_die "$ref is pinned by digest but has no tag, so it cannot be saved with a name — add the tag (name:tag@sha256:...)"
            docker tag "$ref" "$name" || offline_die "docker tag $ref $name failed"
            names+=("$name")
        else
            names+=("$ref")
        fi
    done
    echo "  → docker save ${names[*]} | gzip (this can take a few minutes)…"
    # Subshell with pipefail, so a failing `docker save` is not masked by gzip's
    # success. The caller's options are not relied on: setup.sh has only `set -e`.
    ( set -o pipefail; docker save "${names[@]}" | gzip > "$out_gz" ) \
        || offline_die "docker save failed (see above) — $out_gz is incomplete"
    echo "  ✔  images saved"
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

# Classic image store fix (measured on Docker 29.9.2). On the classic store
# (overlay2 -- hosts installed before Engine 29 and upgraded, GitHub's ubuntu
# runners) `docker load` never restores a registry digest: the plain tag is
# there, but `docker image inspect 'name:tag@sha256:...'` still says "No such
# image", so `docker compose up` would try to pull and fail on an air-gapped
# host. Fix: a compose.override.yaml next to compose.yaml, which Compose reads
# on every plain `docker compose` run in that directory, names the plain tag of
# each affected service. Measured: with it `docker compose up --no-start --pull
# never postgres capture-proxy` creates both containers; without it the same
# command fails with "No such image: ubuntu/squid:6.6-24.04_edge@sha256:...".
# The services come from an awk over compose.yaml, one `service ref` per
# digest-pinned `image:` line, because `docker compose config --images SERVICE`
# cannot map a service to its own image (it lists the dependencies too). A
# service is considered only if its pinned reference is one of the REFs: the
# image references the bundle carries (BUNDLE_IMAGES from bundle.env, in the
# form `docker compose config --images` prints). A plain tag of the same name
# on the host, pulled from elsewhere, does not make a service part of the
# bundle. The others (proxy, frontend-dev, ollama without --with-llm) are
# skipped and keep their pins. For a considered service: a pinned reference that
# already resolves (containerd store) needs nothing; otherwise its plain tag, if
# present, is what the bundle loaded, and it goes in the override. A
# compose.override.yaml this function did not write is never overwritten.
offline_write_compose_override() {
    local override="compose.override.yaml"
    local marker="# Written by setup.sh --offline (scripts/offline_lib_docker.sh) — the classic image store keeps no registry digest after docker load."
    local pairs svc ref bundle_ref in_bundle plain first body="" names="" needed=0

    [ "$#" -gt 0 ] || offline_die "offline_write_compose_override: no bundle image references given (a caller bug)"
    [ -f compose.yaml ] || offline_die "compose.yaml not found in $(pwd)"
    pairs=$(awk '/^services:/{s=1;next} /^[^ #]/{s=0} s&&/^  [A-Za-z0-9_.-]+:[ ]*$/{svc=$1;sub(/:$/,"",svc)} s&&/^    image:/&&/@sha256:/{print svc, $2}' compose.yaml) \
        || offline_die "could not read compose.yaml"
    [ -n "$pairs" ] || offline_die "compose.yaml has no digest-pinned services — nothing to check"

    while read -r svc ref; do
        in_bundle=false
        for bundle_ref in "$@"; do
            if [ "$bundle_ref" = "$ref" ]; then in_bundle=true; break; fi
        done
        [ "$in_bundle" = true ] || continue  # not in this bundle: keep its pin
        if docker image inspect "$ref" >/dev/null 2>&1; then
            continue  # containerd store: the pinned reference resolves as it is
        fi
        plain="${ref%@*}"
        if ! docker image inspect "$plain" >/dev/null 2>&1; then
            continue  # the bundle did not load this plain tag either
        fi
        body+="  ${svc}:"$'\n'"    image: ${plain}"$'\n'
        names+=" ${svc}"
        needed=$((needed + 1))
    done <<< "$pairs"

    if [ "$needed" -eq 0 ]; then
        echo "  ✔  pinned image references resolve as they are — no $override needed"
        if [ -f "$override" ] && [ "$(head -n 1 "$override")" = "$marker" ]; then
            echo "  ⚠  $override from an earlier run is still here; delete it to go back to the digest pins"
        fi
        return 0
    fi

    if [ -e "$override" ] && [ "$(head -n 1 "$override")" != "$marker" ]; then
        offline_die "$override exists and was not written by setup.sh — it is never overwritten.
Merge these lines into it yourself, then finish the restore by hand:
services:
$body"
    fi
    {
        printf '%s\n' "$marker"
        echo "# The images came out of the checksummed bundle. Delete this file to go back to"
        echo "# the digest pins once this host can pull them."
        echo "services:"
        printf '%s' "$body"
    } > "$override"
    echo "  ✔  wrote $override: plain tags for$names (classic image store)"
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

# Runs a command in the `postgres` service with PGPASSWORD taken from the secret
# mounted inside the container. compose.yaml sets POSTGRES_INITDB_ARGS to
# --auth-local=scram-sha-256, so even the local socket asks for a password:
# `docker compose exec -T postgres pg_dump ...` without one fails with
# "fe_sendauth: no password supplied" (measured). Same shape as db_upgrade.sh's
# in_pg. stdin and stdout pass straight through: `offline_pg_exec pg_dump ... >
# file`, or `offline_pg_exec pg_restore ... < dump`.
offline_pg_exec() {
    docker compose exec -T postgres \
        sh -c 'PGPASSWORD="$(cat /run/secrets/db_password)" exec "$@"' sh "$@"
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
    offline_pg_exec pg_restore -U "$compose_project_user" -d "$compose_project_db" --clean --if-exists < "$dump"
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
