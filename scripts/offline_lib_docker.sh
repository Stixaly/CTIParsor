#!/usr/bin/env bash
# =============================================================================
# Shared functions for the Docker-based air-gap install (ADR-0054, supersedes
# ADR-0040's venv-based mechanism -- see docs/adr/0054-*.md for why).
#
# Sourced by setup.sh (install side) and scripts/package_offline_docker.sh
# (build side). Definitions only (the functions and OFFLINE_RULE_STORE_TABLES) --
# nothing executes at source time.
#
# What changed from the old offline_lib.sh: a dozen staging functions
# (offline_stage_models/browsers/data/corpora/frontend, offline_install_debs/
# spacy_model/ollama) collapse into two generic mechanisms -- `docker load`
# for the image (which already contains Python/Node deps, Chromium, the
# built frontend, and the committed MITRE data files) and a tar-based named-
# volume restore for the two things `bootstrap` populates at runtime
# (cti-cache: HF models + corpus clones; the rule store: a pg_dump of the schema
# and the rules, not a raw pg-data tar -- see package_offline_docker.sh for why). The
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
    local listing bad
    # Tar's exit status is kept: a truncated or corrupt archive must fail here,
    # not pass because its readable prefix happens to hold no unsafe name.
    listing=$(tar -tf "$tar_path" "$@" 2>/dev/null) \
        || offline_die "cannot read $tar_path as a tar (truncated or corrupt) — refusing to extract"
    bad=$(grep -E '^(/|.*\.\./)' <<< "$listing" || true)
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
    # Every BUNDLE_* field is optional here: a bundle may carry no BUNDLE_ARCH (the
    # corpora bundle does not, on purpose), and a set -u caller must not die on it.
    local arch_note=""
    if [ -n "${BUNDLE_ARCH:-}" ]; then arch_note=" ($BUNDLE_ARCH)"; fi
    echo "  ✔  bundle built ${BUNDLE_BUILT_AT:-(time not recorded)} from git ${BUNDLE_GIT_REV:-(revision not recorded)}${arch_note}"
}

# Prints every image the bundle carries, one per line, sorted and de-duplicated:
# the default-profile services (app, worker, postgres, capture-proxy), the
# alpine image the volume tar steps run (not a compose service, so added by
# hand), -- when WITH_LLM is true -- the ollama service, and -- when WITH_PROXY
# (second argument, default false) is true -- the proxy profile's nginx image.
# A failing compose command is fatal: the caller reads this through $(...), and
# a process substitution would hide the error, so the bundle would silently ship
# without the Ollama image (`docker compose config --images --profile ollama` is
# not valid -- --profile is a global flag and must come before the subcommand).
offline_bundle_images() {
    local with_llm="$1" with_proxy="${2:-false}" default_images llm_images="" proxy_images=""
    default_images=$(docker compose config --images) \
        || offline_die "docker compose config --images failed"
    if [ "$with_llm" = true ]; then
        llm_images=$(docker compose --profile ollama config --images) \
            || offline_die "docker compose --profile ollama config --images failed"
    fi
    if [ "$with_proxy" = true ]; then
        proxy_images=$(docker compose --profile proxy config --images) \
            || offline_die "docker compose --profile proxy config --images failed"
    fi
    printf '%s\n%s\n%s\n%s\n' "$default_images" "$llm_images" "$proxy_images" "alpine:latest" \
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
    # Subshell with pipefail, as in offline_docker_save_images: a corrupt archive
    # (gunzip) is not masked by the success of docker load.
    ( set -o pipefail; gunzip -c "$dir/images.tar.gz" | docker load ) \
        || offline_die "docker load failed (see above) — $dir/images.tar.gz is corrupt or incomplete"
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
# An archive missing from the bundle is skipped, unless the fourth argument is
# `required`: the caller needs that volume, so an incomplete bundle stops here.
offline_docker_restore_volume() {
    local dir="$1" volume_name="$2" archive_name="$3" required="${4:-}"
    local archive="$dir/$archive_name"
    if [ ! -f "$archive" ]; then
        if [ "$required" = required ]; then
            offline_die "$archive is missing from the bundle"
        fi
        echo "  –  $archive_name not in bundle — skipping $volume_name"
        return 0
    fi

    offline_check_tar_safe "$archive" -z

    docker volume inspect "$volume_name" >/dev/null 2>&1 || docker volume create "$volume_name" >/dev/null
    echo "  → restoring $volume_name from $archive_name…"
    docker run --rm \
        -v "${volume_name}:/data" \
        -v "$(cd "$dir" && pwd):/backup:ro" \
        alpine tar xzf "/backup/$archive_name" -C /data \
        || offline_die "restoring $volume_name from $archive_name failed (see above)"
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

# The tables of the rule store: those the migrations with store="rules" create
# (api/migrations/v0005_rule_store.py). The bundle carries their data, and that of
# schema_migrations, and nothing else: the rest of the database is the job store,
# the reports. Keep this line equal to those tables;
# tests/test_offline_bundle_rule_tables.py fails otherwise.
OFFLINE_RULE_STORE_TABLES="detection_rules rule_atoms rule_bytes rule_related rule_techniques rule_text"

# Restores the schema + rule store from a pg_dump (custom format, -Fc) --
# not a raw pg-data volume tar. The dump carries no reports: the packager exports
# the data of the rule store and of schema_migrations only. Binary Postgres data
# directories are not reliably portable even between two instances of the exact
# same version; pg_dump/pg_restore is the mechanism this repo already documents and
# tests for backup/restore (docs/docker.md, ADR-0045/ADR-0053). Requires `postgres`
# already up and healthy -- the caller's job (see setup.sh).
#
# --clean drops and recreates every table of the dump, so a target that already
# holds data outside the rule store and schema_migrations (the reports) would lose
# it: the restore is refused then, unless the caller sets OFFLINE_FORCE_RESTORE=1.
offline_docker_restore_pg_dump() {
    local dir="$1" compose_project_user="${CTI_DB_USER:-ctiparsor}" compose_project_db="${CTI_DB_NAME:-ctiparsor}"
    local dump="$dir/ctiparsor.dump" holding="" listed=""
    [ -f "$dump" ] || offline_die "$dir/ctiparsor.dump missing"
    # The tables outside the rule store and schema_migrations that hold rows. The query
    # goes on stdin: psql substitutes :'keep' there, not in a -c string.
    holding=$(offline_pg_exec psql -U "$compose_project_user" -d "$compose_project_db" -tA -v keep="$OFFLINE_RULE_STORE_TABLES schema_migrations" <<'SQL'
SELECT table_name FROM information_schema.tables
WHERE table_schema = 'public' AND table_type = 'BASE TABLE'
  AND table_name <> ALL (string_to_array(:'keep', ' '))
  AND (xpath('/row/c/text()',
             query_to_xml(format('SELECT count(*) AS c FROM %I.%I', table_schema, table_name),
                          false, true, '')))[1]::text::bigint > 0
ORDER BY 1;
SQL
    ) || offline_die "cannot query $compose_project_db before the restore"
    if [ -n "$holding" ]; then
        listed="${holding//$'\n'/, }"
        if [ "${OFFLINE_FORCE_RESTORE:-}" != "1" ]; then
            offline_die "$compose_project_db already holds data in: $listed. The restore would erase it: pg_restore --clean drops and recreates every table.
  To refresh only the rules of an existing installation, use scripts/update_offline_corpora.sh with a corpora bundle.
  To restore over that data anyway: set OFFLINE_FORCE_RESTORE=1 and run again."
        fi
        echo "  ⚠  OFFLINE_FORCE_RESTORE=1: restoring over the data of: $listed"
    fi
    echo "  → pg_restore (schema + rule store; the bundle carries no reports)…"
    offline_pg_exec pg_restore -U "$compose_project_user" -d "$compose_project_db" --clean --if-exists < "$dump" \
        || offline_die "pg_restore failed (see above) — $dump was not restored"
    echo "  ✔  database restored"
}

# Prints a --exclude-table-data=public.<table> option for each table that is not
# in KEEP: a pg_dump then leaves out the data of those tables, but keeps their
# schema. Reads the table names on stdin, one per line (blank lines are ignored):
#   tables=$(offline_pg_exec psql ... -tAc "SELECT tablename FROM pg_tables WHERE schemaname='public'")
#   printf '%s\n' "$tables" | offline_exclude_data_args detection_rules schema_migrations
offline_exclude_data_args() {
    local keep=" $* " table
    while IFS= read -r table || [ -n "$table" ]; do
        [ -n "$table" ] || continue
        if [[ "$keep" != *" $table "* ]]; then
            echo "--exclude-table-data=public.$table"
        fi
    done
}

# The check behind the packager's "no reports in the bundle" claim. Reads the
# table of contents of a dump (`pg_restore -l`, on stdin) and refuses it when it
# cannot prove that the dump holds no report:
#   - an empty or unreadable listing, or one without the data of the rule store
#     (`TABLE DATA public detection_rules`), proves nothing;
#   - a `TABLE DATA` entry outside the public schema, or for a table that is not in
#     KEEP, is fatal, and the die names it as schema.table;
#   - a large object (BLOBS, BLOB, LARGE OBJECT) is fatal: the dump is --no-blobs.
# `SEQUENCE SET` entries are let through: they hold the counter of a sequence (the
# last id of a serial column), not rows. The ✔ line comes last, once all of it holds.
# A data entry of the TOC looks like:
#   3456; 0 16390 TABLE DATA public detection_rules ctiparsor
offline_check_dump_data() {
    local keep=" $* " toc data_entries schema table bad="" blobs=""
    toc=$(cat)
    data_entries=$(awk '$4 == "TABLE" && $5 == "DATA" { print $6, $7 }' <<< "$toc")
    grep -qxF "public detection_rules" <<< "$data_entries" \
        || offline_die "the table of contents is empty or unreadable, or the rule store is not in it (no TABLE DATA public detection_rules entry)"
    while read -r schema table; do
        [ -n "$table" ] || continue
        if [ "$schema" != public ] || [[ "$keep" != *" $table "* ]]; then
            bad+=" $schema.$table"
        fi
    done <<< "$data_entries"
    if [ -n "$bad" ]; then
        offline_die "the dump holds the data of:$bad — only the rule store and schema_migrations may be in the bundle, never reports"
    fi
    blobs=$(awk '$4 == "BLOBS" || $4 == "BLOB" || ($4 == "LARGE" && $5 == "OBJECT")' <<< "$toc")
    if [ -n "$blobs" ]; then
        offline_die "the dump holds large objects, which the bundle never carries:
$blobs"
    fi
    echo "  ✔  dump holds no report data (schema + rule store only)"
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

# Sets KEY=VALUE only when no KEY= line is present (an empty `KEY=` counts as
# present). Returns 1 and leaves the file alone when the key is there, so a
# value the operator chose -- or one .env.example ships -- is never overwritten.
_offline_set_key_if_absent() {
    local file="$1" key="$2" value="$3"
    if grep -qE "^${key}=" "$file" 2>/dev/null; then
        return 1
    fi
    printf '%s=%s\n' "$key" "$value" >> "$file"
}

# The host's CPU count, for the Ollama container's cpu limit: nproc, else getconf.
# Prints nothing when neither gives a number, so the caller skips the cap. Always
# returns 0: a failing command substitution would abort a set -e caller.
_offline_host_cpus() {
    local n
    n=$(nproc 2>/dev/null || getconf _NPROCESSORS_ONLN 2>/dev/null || true)
    if [[ "$n" =~ ^[0-9]+$ ]]; then
        echo "$n"
    fi
}

# The effective value of KEY in FILE (.env by default), as compose reads it: the
# text after the first `=` of the last `KEY=` line, without a trailing CR. A value
# between one pair of matching quotes gives what is inside them; a bare value loses
# an inline comment (a `#` after a space or tab) and its trailing blanks. Prints
# nothing, and returns 0, when the key is absent: callers run under `set -e`.
offline_env_value() {
    local key="$1" file="${2:-.env}" line value
    local double_re='^"([^"]*)"' single_re="^'([^']*)'"
    line=$(grep -E "^${key}=" "$file" 2>/dev/null | tail -n 1) || true
    value="${line#*=}"
    value="${value%$'\r'}"
    if [[ "$value" =~ $double_re || "$value" =~ $single_re ]]; then
        value="${BASH_REMATCH[1]}"
    else
        value="${value%%[[:blank:]]#*}"
        value="${value%"${value##*[![:blank:]]}"}"
    fi
    printf '%s' "$value"
}

# Writes the air-gap settings into .env (setup.sh --offline, after the restore).
#
# HF_HUB_OFFLINE and TRANSFORMERS_OFFLINE are always set, when absent: the worker
# container loads its HuggingFace models (all-MiniLM-L6-v2 in stage2c, gliner in
# stage2e) from the cti-cache volume on every report, and a Hub lookup there would
# fail or stall on an air-gapped host. (ADR-0040's bundle set them; ADR-0054's
# rewrite dropped them on the claim that nothing on the host calls the Hub -- but
# the calls happen in the worker container.)
#
# The bundled Ollama model is wired up only in a .env this run created from
# .env.example. An operator's own .env keeps its LLM settings: the lines to set
# are printed instead. The values are starting points for a CPU or single-GPU
# Ollama: one request at a time (LLM_PARALLELISM=1 -- the vision section of
# .env.example measured one in flight better than four on one GPU), a 600 s call
# timeout (LLM_TIMEOUT=120 is sized for the hosted APIs), and a 3-hour job timeout
# (WORKER_JOB_TIMEOUT). Tune them for the hardware. OLLAMA_BASE_URL names the
# compose service: inside a container, localhost is the container itself.
offline_write_env_hints() {
    local env_created="$1"
    local model="${BUNDLE_OLLAMA_MODEL:-}"
    local models="${BUNDLE_OLLAMA_MODELS:-$model}"
    local key pair value count host_cpus="" cap="" provider=""
    local bundled=()
    local llm_pairs=(
        "LLM_PROVIDER=ollama"
        "OLLAMA_MODEL=$model"
        "OLLAMA_BASE_URL=http://ollama:11434"
        "LLM_PARALLELISM=1"
        "LLM_TIMEOUT=600"
        "WORKER_JOB_TIMEOUT=10800"
    )
    [ -f .env ] || offline_die ".env should already exist by this point — internal error"

    for key in HF_HUB_OFFLINE TRANSFORMERS_OFFLINE; do
        if _offline_set_key_if_absent .env "$key" 1; then
            echo "  ✔  .env: $key=1"
        else
            echo "  –  .env: $key is already set, left as it is"
        fi
    done

    if [ -n "$model" ]; then
        # compose.yaml gives the ollama container cpus "${CTI_OLLAMA_CPUS:-8}", and
        # Docker refuses a cpu limit above the host's count ("range of CPUs is from
        # 0.01 to 4.00, as there are only 4 CPUs available"). Below the compose
        # default of 8, the cap becomes the host's CPU count. Silent if unknown.
        host_cpus=$(_offline_host_cpus)
        if [ -n "$host_cpus" ] && [ "$host_cpus" -lt 8 ]; then cap="$host_cpus"; fi
        if [ "$env_created" = true ]; then
            for pair in "${llm_pairs[@]}"; do
                key="${pair%%=*}"; value="${pair#*=}"
                _offline_set_key .env "$key" "$value"
                echo "  ✔  .env: $key=$value"
            done
            if [ -n "$cap" ]; then
                if _offline_set_key_if_absent .env CTI_OLLAMA_CPUS "$cap"; then
                    echo "  ✔  .env: CTI_OLLAMA_CPUS=$cap (this host has $cap CPUs; Docker refuses compose.yaml's default of 8 here)"
                else
                    echo "  –  .env: CTI_OLLAMA_CPUS is already set, left as it is"
                fi
            fi
        else
            echo "  →  .env already existed, so its LLM settings are unchanged. For the bundled model, set in .env:"
            for pair in "${llm_pairs[@]}"; do
                echo "       $pair"
            done
            if [ -n "$cap" ]; then
                echo "       CTI_OLLAMA_CPUS=$cap   # this host has $cap CPUs; Docker refuses compose.yaml's default of 8 here"
            fi
        fi
    else
        # No model in the bundle: the LLM is whatever LLM_PROVIDER names. A server on
        # this host (ollama, vllm, lmstudio) still answers offline; a hosted API (the
        # code's default, anthropic) does not, and Stage 3 calls it for every report.
        provider=$(offline_env_value LLM_PROVIDER)
        provider="${provider,,}"  # the code lowercases LLM_PROVIDER too
        provider="${provider:-anthropic}"
        case "$provider" in
            ollama|vllm|lmstudio) ;;
            *)
                echo "  ⚠  .env: LLM_PROVIDER=$provider needs the network: Stage 3 will not run on this air-gapped host."
                echo "     Point LLM_PROVIDER at a local server (ollama, vllm or lmstudio), or rebuild the bundle with --with-llm."
                ;;
        esac
    fi

    read -ra bundled <<< "$models" || true
    count=${#bundled[@]}
    if [ "$count" -gt 1 ]; then
        echo "  →  the bundle carries $count models: ${bundled[*]}"
        echo "     Stage 1f reads figures only with a vision model. Set in .env:"
        echo "       VISION_PROVIDER=ollama"
        echo "       VISION_MODEL=<one of those models that has the vision capability>"
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
    if [[ " ${BUNDLE_IMAGES:-} " == *" nginxinc/"* ]]; then
        echo "     # TLS + password front (docs/docker.md): create docker/nginx/certs/cti.crt,"
        echo "     # docker/nginx/certs/cti.key and docker/nginx/htpasswd first, then:"
        echo "     docker compose --profile proxy up -d       # https://<host>:8443"
    fi
    echo ""
    echo "  No 'docker compose --profile bootstrap run --rm bootstrap' needed —"
    echo "  the rule store and NLP model cache are already restored from the bundle."
}
