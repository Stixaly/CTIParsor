#!/usr/bin/env bash
# =============================================================================
# scripts/offline_lib.sh — functions setup.sh sources for `--offline=<dir>`
# (ADR-0040).  Definitions only: nothing runs at source time.
#
# Every function returns an explicit status because setup.sh runs under
# `set -e`; a bare failing command here would abort the whole install with a
# message that points at the wrong place.
# =============================================================================

offline_die() {
    err "$*"
    exit 1
}

offline_validate_bundle() {
    local DIR="$1"

    if [ ! -d "$DIR" ] || [ ! -f "$DIR/bundle.env" ] || [ ! -f "$DIR/SHA256SUMS" ]; then
        offline_die "not an offline bundle: $DIR (bundle.env or SHA256SUMS missing)"
    fi

    # shellcheck disable=SC1090
    . "$DIR/bundle.env" || offline_die "failed to source $DIR/bundle.env"

    local have
    have=$(python3 -c 'import sys;print(f"{sys.version_info.major}.{sys.version_info.minor}")' 2>/dev/null || echo none)
    if [ "$have" = none ]; then
        # No python3 yet — it ships in debs/ and is checked again after dpkg.
        warn "python3 not installed yet — the bundle provides $BUNDLE_PYTHON"
    elif [ "$have" != "$BUNDLE_PYTHON" ]; then
        offline_die "bundle was built for Python $BUNDLE_PYTHON, this host has $have — build the bundle on a twin of the target"
    fi

    local code
    code=$(. /etc/os-release 2>/dev/null && echo "${VERSION_CODENAME:-${ID:-unknown}}")
    if [ "$code" != "$BUNDLE_CODENAME" ]; then
        if [ "${OFFLINE_FORCE:-0}" = "1" ]; then
            warn "distribution mismatch: bundle=$BUNDLE_CODENAME, host=$code (OFFLINE_FORCE=1)"
        else
            offline_die "distribution mismatch: bundle=$BUNDLE_CODENAME, host=$code (set OFFLINE_FORCE=1 to override)"
        fi
    fi

    local arch
    arch=$(dpkg --print-architecture 2>/dev/null || uname -m)
    if [ "$arch" != "$BUNDLE_ARCH" ]; then
        offline_die "architecture mismatch: bundle=$BUNDLE_ARCH, host=$arch"
    fi

    info "Verifying checksums…"
    if ! ( cd "$DIR" && sha256sum --quiet -c SHA256SUMS ); then
        offline_die "checksum mismatch — the bundle is corrupt or was modified in transit"
    fi

    ok "bundle ${BUNDLE_GIT_REV} built ${BUNDLE_BUILT_AT} for Python ${BUNDLE_PYTHON} / ${BUNDLE_CODENAME} ${BUNDLE_ARCH}"
    if [ -n "${BUNDLE_OLLAMA_MODEL:-}" ]; then
        ok "local LLM: ${BUNDLE_OLLAMA_MODEL} (Ollama ${BUNDLE_OLLAMA_TAG:-?})"
    else
        warn "no local LLM in this bundle — Stage 3 needs LLM_PROVIDER to point at a reachable server"
    fi

    return 0
}

offline_export_env() {
    local DIR="$1"

    export PIP_NO_INDEX=1
    export PIP_FIND_LINKS="$DIR/wheels"
    export PIP_DISABLE_PIP_VERSION_CHECK=1
    export HF_HUB_OFFLINE=1
    export TRANSFORMERS_OFFLINE=1
    export HF_HUB_DISABLE_TELEMETRY=1

    info "pip → $DIR/wheels (no index); HuggingFace → offline"

    return 0
}

offline_install_debs() {
    local DIR="$1"
    local debs=()

    while IFS= read -r -d '' f; do
        debs+=("$f")
    done < <(find "$DIR/debs" -maxdepth 1 -name '*.deb' -print0 2>/dev/null || true)

    if [ ${#debs[@]} -eq 0 ]; then
        warn "no .deb in the bundle — system packages are assumed to be installed"
        return 0
    fi

    info "Installing ${#debs[@]} system packages with dpkg (sudo)…"

    if ! sudo dpkg -i --skip-same-version "$DIR"/debs/*.deb > "$DIR/dpkg-install.log" 2>&1; then
        warn "dpkg reported errors — running dpkg --configure -a"
    fi
    sudo dpkg --configure -a >> "$DIR/dpkg-install.log" 2>&1 || true

    if command -v python3 >/dev/null 2>&1 && python3 -c "import ensurepip" 2>/dev/null; then
        local have
        have=$(python3 -c 'import sys;print(f"{sys.version_info.major}.{sys.version_info.minor}")' 2>/dev/null || echo none)
        if [ "$have" != "${BUNDLE_PYTHON:-$have}" ]; then
            err "python3 is $have after dpkg, the wheelhouse was built for $BUNDLE_PYTHON"
            return 1
        fi
        ok "system packages installed (python3 $have)"
        return 0
    fi

    err "python3/ensurepip still missing after dpkg — see $DIR/dpkg-install.log"
    return 1
}

offline_stage_models() {
    local DIR="$1"

    if [ ! -d "$DIR/hf/hub" ]; then
        warn "no HuggingFace cache in the bundle"
        return 0
    fi

    local home="${HF_HOME:-$HOME/.cache/huggingface}"
    mkdir -p "$home/hub" || { err "failed to create $home/hub"; return 1; }
    if ! cp -a "$DIR/hf/hub/." "$home/hub/"; then
        err "failed to copy HuggingFace cache to $home/hub"
        return 1
    fi

    ok "HuggingFace cache staged → $home/hub (${BUNDLE_HF_MODELS:-?})"
    return 0
}

offline_stage_browsers() {
    local DIR="$1"

    if [ ! -d "$DIR/browsers" ]; then
        warn "no Playwright browsers in the bundle"
        return 0
    fi

    local dest="${PLAYWRIGHT_BROWSERS_PATH:-$HOME/.cache/ms-playwright}"
    mkdir -p "$dest" || { err "failed to create $dest"; return 1; }
    if ! cp -a "$DIR/browsers/." "$dest/"; then
        err "failed to copy browsers to $dest"
        return 1
    fi

    ok "Playwright browsers staged → $dest"
    return 0
}

offline_stage_data() {
    local DIR="$1"

    if [ ! -d "$DIR/data" ]; then
        warn "no data/ in the bundle"
        return 0
    fi

    mkdir -p data || { err "failed to create data/"; return 1; }
    local files=()
    while IFS= read -r -d '' f; do
        files+=("$f")
    done < <(find "$DIR/data" -maxdepth 1 -name '*.json' -print0 2>/dev/null || true)

    if [ ${#files[@]} -eq 0 ]; then
        warn "no .json files in $DIR/data"
        return 0
    fi

    local f
    for f in "${files[@]}"; do
        [ -e "data/$(basename "$f")" ] && continue
        cp "$f" data/ || { err "failed to copy $(basename "$f")"; return 1; }
    done
    ok "MITRE bundles staged → data/ (${#files[@]} files)"
    return 0
}

offline_stage_corpora() {
    local DIR="$1"

    if [ ! -f "$DIR/corpora.tar" ]; then
        warn "no corpora.tar in the bundle"
        return 0
    fi

    if [ -d corpora ]; then
        ok "corpora/ already present — kept (bundle copy not extracted)"
        return 0
    fi

    if ! tar -xf "$DIR/corpora.tar"; then
        err "failed to extract corpora.tar"
        return 1
    fi

    local n
    n=$(find corpora -mindepth 1 -maxdepth 1 -type d 2>/dev/null | wc -l)
    ok "corpora/ extracted (${n} entries)"
    return 0
}

offline_stage_frontend() {
    local DIR="$1"

    if [ -f "$DIR/frontend-dist.tar" ]; then
        mkdir -p frontend || { warn "failed to create frontend/"; return 1; }
        if ! tar -xf "$DIR/frontend-dist.tar" -C frontend; then
            warn "failed to extract frontend-dist.tar"
        fi
    fi

    if [ -f "$DIR/node_modules.tar" ] && [ ! -d frontend/node_modules ]; then
        if ! tar -xf "$DIR/node_modules.tar" -C frontend; then
            warn "failed to extract node_modules.tar"
        fi
    fi

    if [ -f frontend/dist/index.html ]; then
        ok "web UI staged from the bundle (frontend/dist)"
        return 0
    fi

    warn "no built web UI in the bundle — the API will serve a placeholder page"
    return 1
}

offline_install_spacy_model() {
    local model="${BUNDLE_SPACY_MODEL:-en_core_web_sm}"

    if pip install -q "$model"; then
        ok "spaCy model installed: $model"
        return 0
    fi

    warn "$model wheel not in the bundle — spaCy fallback unavailable"
    return 1
}

offline_install_ollama() {
    local DIR="$1"
    local asset="${BUNDLE_OLLAMA_ASSET:-}"

    if [ -z "$asset" ] || [ ! -f "$DIR/ollama/$asset" ]; then
        info "no Ollama runtime in this bundle — skipped"
        return 0
    fi

    if command -v ollama >/dev/null 2>&1; then
        ok "ollama already installed: $(ollama --version 2>/dev/null | head -1)"
    else
        if ! command -v unzstd >/dev/null 2>&1; then
            warn "zstd missing — install it from the bundle's debs, then: sudo tar --use-compress-program=unzstd -C /usr/local -xf $DIR/ollama/$asset"
            return 1
        fi
        info "Extracting Ollama to /usr/local (sudo)…"
        if ! sudo tar --use-compress-program=unzstd -C /usr/local -xf "$DIR/ollama/$asset"; then
            err "failed to extract Ollama runtime"
            return 1
        fi
        hash -r
    fi

    if [ -d "$DIR/ollama/models" ]; then
        mkdir -p "$HOME/.ollama/models" || { warn "failed to create ~/.ollama/models"; return 0; }
        if ! cp -a "$DIR/ollama/models/." "$HOME/.ollama/models/"; then
            warn "failed to copy Ollama models"
        else
            ok "model files staged → ~/.ollama/models (${BUNDLE_OLLAMA_MODEL:-?})"
        fi
    fi

    return 0
}

_offline_set_key() {
    local FILE="$1" KEY="$2" VALUE="$3"
    if grep -qE "^${KEY}=" "$FILE" 2>/dev/null; then
        sed -i "s|^${KEY}=.*|${KEY}=${VALUE}|" "$FILE"
    else
        printf '%s=%s\n' "$KEY" "$VALUE" >> "$FILE"
    fi
}

offline_write_env_hints() {
    local ENV_CREATED="$1"
    local file=".env"

    if [ ! -f "$file" ]; then
        touch "$file" || { err "failed to create .env"; return 1; }
    fi

    local keys=("HF_HUB_OFFLINE=1" "TRANSFORMERS_OFFLINE=1")
    local added_comment=false
    for kv in "${keys[@]}"; do
        local key="${kv%%=*}"
        local val="${kv#*=}"
        if grep -qE "^${key}=" "$file" 2>/dev/null; then
            sed -i "s|^${key}=.*|${key}=${val}|" "$file"
        else
            if [ "$added_comment" = false ]; then
                printf '\n# Added by setup.sh --offline (ADR-0040): models are read from the local cache, never fetched.\n' >> "$file"
                added_comment=true
            fi
            printf '%s=%s\n' "$key" "$val" >> "$file"
        fi
    done

    if [ "$ENV_CREATED" = "true" ] && [ -n "${BUNDLE_OLLAMA_MODEL:-}" ]; then
        _offline_set_key "$file" LLM_PROVIDER ollama
        _offline_set_key "$file" OLLAMA_MODEL "$BUNDLE_OLLAMA_MODEL"
        _offline_set_key "$file" OLLAMA_BASE_URL http://localhost:11434
        ok ".env → LLM_PROVIDER=ollama, OLLAMA_MODEL=$BUNDLE_OLLAMA_MODEL"
    elif [ -n "${BUNDLE_OLLAMA_MODEL:-}" ]; then
        info ".env kept as is — set LLM_PROVIDER=ollama and OLLAMA_MODEL=$BUNDLE_OLLAMA_MODEL to use the bundled model"
    fi

    return 0
}

offline_summary() {
    echo ""
    hdr "Offline install — next steps"

    if [ -n "${BUNDLE_OLLAMA_MODEL:-}" ]; then
        info "Start the local LLM:"
        echo "    ollama serve"
        info "Verify it responds:"
        echo "    ollama run ${BUNDLE_OLLAMA_MODEL} \"hello\""
        info "(or use the systemd unit described in docs/deployment.md)"
    fi

    info "HF_HUB_OFFLINE=1 is in .env — also export it in your shell before running python main.py:"
    echo "    export HF_HUB_OFFLINE=1 TRANSFORMERS_OFFLINE=1"

    info "Do NOT run scripts/sync_corpora.py without network — corpora date from the bundle."
    echo "    cat offline/bundle.env   # for the build date"

    return 0
}
