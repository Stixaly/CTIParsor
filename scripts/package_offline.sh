#!/usr/bin/env bash
# =============================================================================
# scripts/package_offline.sh — build a self-contained offline (air-gap)
# installation bundle (ADR-0040).
#
# Run on a CONNECTED machine that matches the target: same distribution
# release and same Python major.minor, because the wheelhouse is built for the
# interpreter that runs this script.  Everything lands in ./offline/ and is
# then packed with the source tree into dist/cti-parsor-offline-<rev>-<codename>-py<ver>.tar
#
# Usage:
#   bash scripts/package_offline.sh                 # everything, default model
#   bash scripts/package_offline.sh --llm-model mistral
#   bash scripts/package_offline.sh --no-llm --no-browsers
#   bash scripts/package_offline.sh --worktree      # snapshot the working tree, not HEAD
# =============================================================================
set -u

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'
CYAN='\033[0;36m';  BLUE='\033[0;34m';  NC='\033[0m'
ok()   { echo -e "  ${GREEN}✔${NC}  $*"; }
warn() { echo -e "  ${YELLOW}⚠${NC}  $*"; }
info() { echo -e "  ${CYAN}→${NC}  $*"; }
err()  { echo -e "  ${RED}✖${NC}  $*"; }
sep()  { echo -e "${BLUE}────────────────────────────────────────────────────${NC}"; }
hdr()  { echo ""; sep; echo -e "${CYAN}  $*${NC}"; sep; }

# =============================================================================
# Constants
# =============================================================================
PY=".venv/bin/python"
OUT="offline"
NODE_MAJOR=24                       # must match NODE_TARGET_MAJOR in setup.sh
NODESOURCE_BASE="https://deb.nodesource.com/node_${NODE_MAJOR}.x"
MITRE_BASE="https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master"
CAPEC_URL="https://raw.githubusercontent.com/mitre/cti/master/capec/2.1/stix-capec.json"
OLLAMA_API="https://api.github.com/repos/ollama/ollama/releases/latest"
SPACY_MODEL="en_core_web_sm"
HF_DEFAULT_MODELS="sentence-transformers/all-MiniLM-L6-v2 PranavaKailash/CyNER-2.0-DeBERTa-v3-base urchade/gliner_large-v2.1"

# Same packages as setup.sh [1/6] (_apt_install), plus what the offline steps
# need: python3.X-venv (ensurepip), libre2-dev (re2 wheel runtime), zstd
# (Ollama ships .tar.zst), and Chromium's runtime libraries so that
# `playwright install-deps chromium` has nothing left to fetch.
SYSTEM_PKGS="python3 python3-pip python3-venv python3-dev build-essential libxml2-dev libxslt1-dev tesseract-ocr poppler-utils curl wget git libre2-dev zstd"
CHROMIUM_PKGS="libasound2t64 libatk-bridge2.0-0t64 libatk1.0-0t64 libatspi2.0-0t64 libcairo2 libcups2t64 libdbus-1-3 libdrm2 libgbm1 libglib2.0-0t64 libnspr4 libnss3 libpango-1.0-0 libx11-6 libxcb1 libxcomposite1 libxdamage1 libxext6 libxfixes3 libxkbcommon0 libxrandr2 fonts-liberation fonts-noto-color-emoji"

# =============================================================================
# Globals
# =============================================================================
FAILED=""
NODE_DEB=""
HF_MODELS_USED=""
OLLAMA_ASSET=""
OLLAMA_TAG=""
LLM_MODEL_PACKED=""
OUT_ABS=""

# Options (defaults)
WITH_LLM=true
WITH_CORPORA=true
WITH_BROWSERS=true
WITH_FRONTEND=true
WITH_DEBS=true
DO_PACK=true
WORKTREE=false
LLM_MODEL=""

# =============================================================================
# Argument parsing
# =============================================================================
usage() {
    cat <<EOF
Usage: bash scripts/package_offline.sh [OPTIONS]

Options:
  --out DIR            Output directory (default: offline)
  --no-llm             Skip Ollama and LLM model collection
  --llm-model NAME     LLM model to pull (default: from .env or mistral)
  --no-corpora         Skip corpora collection
  --no-browsers        Skip Playwright browser collection
  --no-frontend        Skip frontend build and packing
  --no-debs            Skip system package collection
  --no-pack            Do not create the final tarball
  --worktree           Snapshot the working tree instead of HEAD
  -h, --help           Show this help
EOF
}

parse_args() {
    while [ $# -gt 0 ]; do
        case "$1" in
            --out)
                OUT="${2:?--out requires a directory}"
                shift 2
                ;;
            --no-llm)
                WITH_LLM=false
                shift
                ;;
            --llm-model)
                LLM_MODEL="${2:?--llm-model requires a name}"
                shift 2
                ;;
            --no-corpora)
                WITH_CORPORA=false
                shift
                ;;
            --no-browsers)
                WITH_BROWSERS=false
                shift
                ;;
            --no-frontend)
                WITH_FRONTEND=false
                shift
                ;;
            --no-debs)
                WITH_DEBS=false
                shift
                ;;
            --no-pack)
                DO_PACK=false
                shift
                ;;
            --worktree)
                WORKTREE=true
                shift
                ;;
            -h|--help)
                usage
                exit 0
                ;;
            *)
                err "Unknown option: $1"
                usage
                exit 2
                ;;
        esac
    done

    # Resolve LLM_MODEL from .env if not set
    if [ -z "$LLM_MODEL" ]; then
        if [ -f .env ]; then
            LLM_MODEL=$(grep -E '^OLLAMA_MODEL=' .env | tail -1 | cut -d= -f2-)
        fi
        [ -z "$LLM_MODEL" ] && LLM_MODEL="mistral"
    fi
}

# =============================================================================
# Preflight checks
# =============================================================================
preflight() {
    hdr "Preflight"

    if [ ! -x "$PY" ]; then
        err "run from the project root after setup.sh: $PY not found"
        exit 1
    fi

    local cmd
    for cmd in git curl tar sha256sum find; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            err "required command not found: $cmd"
            exit 1
        fi
    done

    if [ "$WITH_DEBS" = true ]; then
        for cmd in apt-cache apt-get dpkg; do
            if ! command -v "$cmd" >/dev/null 2>&1; then
                err "required command not found (WITH_DEBS): $cmd"
                exit 1
            fi
        done
    fi

    PY_MM=$($PY -c 'import sys;print(f"{sys.version_info.major}.{sys.version_info.minor}")')
    PY_MINOR="${PY_MM#*.}"
    CODENAME=$(. /etc/os-release && echo "${VERSION_CODENAME:-${ID}}")
    ARCH=$(dpkg --print-architecture 2>/dev/null || uname -m)
    GIT_REV=$(git rev-parse --short HEAD)
    BUILT_AT=$(date -u +%Y-%m-%dT%H:%M:%SZ)

    # Check system Python version
    local sys_py
    sys_py=$(python3 --version 2>/dev/null | awk '{print $2}' | cut -d. -f1,2)
    if [ -n "$sys_py" ] && [ "$sys_py" != "$PY_MM" ]; then
        warn "system Python ($sys_py) differs from venv Python ($PY_MM) — bundle targets venv Python"
    fi

    mkdir -p "$OUT"
    OUT_ABS=$(cd "$OUT" && pwd)   # env vars (HF_HOME, OLLAMA_MODELS…) need an absolute path

    info "Python: $PY_MM"
    info "Codename: $CODENAME"
    info "Arch: $ARCH"
    info "Git rev: $GIT_REV"
    info "LLM model: $LLM_MODEL"
    info "Options: llm=$WITH_LLM corpora=$WITH_CORPORA browsers=$WITH_BROWSERS frontend=$WITH_FRONTEND debs=$WITH_DEBS pack=$DO_PACK worktree=$WORKTREE"
}

# =============================================================================
# Collect Python wheels
# =============================================================================
collect_wheels() {
    hdr "Collecting Python wheels"

    # 1. Main requirements
    if ! $PY -m pip wheel --wheel-dir "$OUT/wheels" \
        -r requirements.txt \
        -r requirements-api.txt \
        "$(grep -E '^playwright' requirements-optional.txt || echo playwright)" \
        pip setuptools wheel; then
        err "pip wheel failed for main requirements"
        FAILED+=" wheels"
        return
    fi

    # 2. spaCy model
    local SPACY_MM
    SPACY_MM=$($PY -c 'import spacy;v=spacy.__version__.split(".");print(v[0]+"."+v[1])' 2>/dev/null)
    if [ -z "$SPACY_MM" ]; then
        warn "spacy not importable — skipping ${SPACY_MODEL}"
    else
        local spacy_url="https://github.com/explosion/spacy-models/releases/download/${SPACY_MODEL}-${SPACY_MM}.0/${SPACY_MODEL}-${SPACY_MM}.0-py3-none-any.whl"
        local spacy_file="$OUT/wheels/${SPACY_MODEL}-${SPACY_MM}.0-py3-none-any.whl"
        if [ -f "$spacy_file" ]; then
            ok "spaCy model wheel already present — kept"
        else
            if ! curl -fsSL --retry 3 -o "$spacy_file" "$spacy_url"; then
                warn "failed to download spaCy model wheel"
            fi
        fi
    fi

    # 3. re2 (best effort)
    if ! $PY -m pip wheel --wheel-dir "$OUT/wheels" \
        "$(grep -E '^re2' requirements-optional.txt || echo re2)" 2>/dev/null; then
        warn "re2 wheel not built (needs libre2-dev on this builder) — Stage 2 falls back to Python's re"
    fi

    # 4. Summary
    local count
    count=$(find "$OUT/wheels" -name '*.whl' 2>/dev/null | wc -l)
    local size
    size=$(du -sh "$OUT/wheels" 2>/dev/null | cut -f1)
    ok "$count wheels — $size"
}

# =============================================================================
# Collect system packages (.deb)
# =============================================================================
collect_debs() {
    hdr "Collecting system packages"

    local PKGS="$SYSTEM_PKGS python3.${PY_MINOR}-venv $CHROMIUM_PKGS"

    # Add Playwright dependencies
    local pw_deps
    pw_deps=$($PY -m playwright install-deps chromium --dry-run 2>/dev/null | grep -oE 'apt-get install[^&|;]*' | tr ' \\' '\n\n' | grep -vE '^(apt-get|install|-.*)?$')
    if [ -n "$pw_deps" ]; then
        PKGS="$PKGS $pw_deps"
    fi

    # Compute closure
    local CLOSURE
    CLOSURE=$(apt-cache depends --recurse --no-recommends --no-suggests --no-conflicts --no-breaks --no-replaces --no-enhances $PKGS 2>/dev/null | grep '^\w' | sort -u)
    if [ -z "$CLOSURE" ]; then
        err "apt-cache depends returned empty closure"
        FAILED+=" debs"
        return
    fi

    mkdir -p "$OUT/debs"

    local kept=0 downloaded=0 missing=0
    local MISSING=""
    local pkg
    for pkg in $CLOSURE; do
        if ls "$OUT/debs/${pkg}_"*.deb >/dev/null 2>&1; then
            kept=$((kept + 1))
        else
            if (cd "$OUT/debs" && apt-get download "$pkg" >/dev/null 2>&1); then
                downloaded=$((downloaded + 1))
            else
                missing=$((missing + 1))
                MISSING="$MISSING $pkg"
            fi
        fi
    done

    if [ $missing -gt 0 ]; then
        warn "$missing packages could not be downloaded (virtual or renamed):$MISSING"
        # Check critical packages
        if ! ls "$OUT/debs/python3_"*.deb >/dev/null 2>&1 || ! ls "$OUT/debs/python3-venv_"*.deb >/dev/null 2>&1; then
            err "critical packages (python3 or python3-venv) missing"
            FAILED+=" debs"
        fi
    fi

    # NodeSource
    local packages_file
    if packages_file=$(curl -fsSL "$NODESOURCE_BASE/dists/nodistro/main/binary-${ARCH}/Packages" 2>/dev/null); then
        local FILENAME
        FILENAME=$(echo "$packages_file" | awk '
            /^Package: nodejs/ { in_block=1; version="" }
            in_block && /^Version:/ { version=$2 }
            in_block && /^Filename:/ { print $2; in_block=0 }
            /^$/ { in_block=0 }
        ' | sort -V | tail -1)

        if [ -n "$FILENAME" ]; then
            local node_deb="$OUT/debs/$(basename "$FILENAME")"
            if [ -f "$node_deb" ]; then
                ok "Node.js .deb already present — kept"
                NODE_DEB=$(basename "$FILENAME")
            else
                if curl -fsSL -o "$node_deb" "$NODESOURCE_BASE/$FILENAME"; then
                    NODE_DEB=$(basename "$FILENAME")
                else
                    err "failed to download Node.js .deb"
                    FAILED+=" debs"
                fi
            fi
        else
            err "could not find Node.js package in NodeSource index"
            FAILED+=" debs"
        fi
    else
        err "failed to fetch NodeSource package index"
        FAILED+=" debs"
    fi

    local total
    total=$(find "$OUT/debs" -name '*.deb' 2>/dev/null | wc -l)
    local size
    size=$(du -sh "$OUT/debs" 2>/dev/null | cut -f1)
    ok "$total .deb files (kept $kept, downloaded $downloaded) — $size"
}

# =============================================================================
# Collect Hugging Face models
# =============================================================================
collect_models() {
    hdr "Collecting Hugging Face models"

    # Read model IDs from .env
    local TTP_EMBEDDING_MODEL CYNER_MODEL GLINER_MODEL
    TTP_EMBEDDING_MODEL=$(grep -E '^TTP_EMBEDDING_MODEL=' .env 2>/dev/null | tail -1 | cut -d= -f2-)
    CYNER_MODEL=$(grep -E '^CYNER_MODEL=' .env 2>/dev/null | tail -1 | cut -d= -f2-)
    GLINER_MODEL=$(grep -E '^GLINER_MODEL=' .env 2>/dev/null | tail -1 | cut -d= -f2-)

    # Apply defaults
    local defaults=($HF_DEFAULT_MODELS)
    [ -z "$TTP_EMBEDDING_MODEL" ] && TTP_EMBEDDING_MODEL="${defaults[0]}"
    [ -z "$CYNER_MODEL" ] && CYNER_MODEL="${defaults[1]}"
    [ -z "$GLINER_MODEL" ] && GLINER_MODEL="${defaults[2]}"
    # sentence-transformers resolves a bare name ("all-MiniLM-L6-v2") under its own
    # organisation; the Hub API does not, and answers 401 for the bare id.
    case "$TTP_EMBEDDING_MODEL" in
        */*) ;;
        *)   TTP_EMBEDDING_MODEL="sentence-transformers/${TTP_EMBEDDING_MODEL}" ;;
    esac

    HF_MODELS_USED="$TTP_EMBEDDING_MODEL $CYNER_MODEL $GLINER_MODEL"

    local enc_file="$OUT/hf/.encoders"
    if ! HF_HOME="$OUT_ABS/hf" HF_HUB_DISABLE_PROGRESS_BARS=1 HF_MODELS="$HF_MODELS_USED" HF_ENCODERS_OUT="$enc_file" $PY - <<'PYEOF'
import json, os, sys
from pathlib import Path
from huggingface_hub import snapshot_download
IGNORE = ["*.h5", "*.ot", "*.msgpack", "onnx/*", "openvino/*"]   # duplicate framework copies
# A GLiNER checkpoint carries its encoder's WEIGHTS but not its tokenizer: at
# load time it fetches `model_name` (microsoft/deberta-v3-large for the default)
# from the Hub, which is exactly what an air-gapped host cannot do.  Measured on
# 2026-09-09: the replayed install's GLiNER pre-load failed for that reason.
# Ship the encoder's tokenizer/config files (no weights) alongside.
TOKENIZER_ONLY = ["*.json", "*.model", "*.txt", "tokenizer*", "spm*", "vocab*", "merges*"]
encoders = []
for m in sys.argv[1:] if len(sys.argv) > 1 else os.environ["HF_MODELS"].split():
    path = snapshot_download(m, ignore_patterns=IGNORE)
    print(f"  {m} -> {path}", flush=True)
    cfg = Path(path) / "gliner_config.json"
    if cfg.exists():
        enc = json.loads(cfg.read_text(encoding="utf-8")).get("model_name")
        if enc and enc not in encoders:
            encoders.append(enc)
for enc in encoders:
    print(f"  {enc} (tokenizer only, GLiNER encoder) -> "
          f"{snapshot_download(enc, allow_patterns=TOKENIZER_ONLY)}", flush=True)
with open(os.environ["HF_ENCODERS_OUT"], "w", encoding="utf-8") as fh:
    fh.write(" ".join(encoders))
PYEOF
    then
        err "failed to download Hugging Face models"
        FAILED+=" models"
        return
    fi

    # Encoders fetched for GLiNER go into the manifest too, so the installer can list them.
    if [ -s "$enc_file" ]; then
        HF_MODELS_USED="$HF_MODELS_USED $(cat "$enc_file")"
    fi
    rm -f "$enc_file"
    local size
    size=$(du -sh "$OUT/hf" 2>/dev/null | cut -f1)
    ok "Hugging Face models — $size"
}

# =============================================================================
# Collect Playwright browsers
# =============================================================================
collect_browsers() {
    hdr "Collecting Playwright browsers"

    # Ensure playwright is installed
    if ! $PY -c "import playwright" 2>/dev/null; then
        if ! PIP_NO_INDEX=1 PIP_FIND_LINKS="$OUT/wheels" $PY -m pip install -q playwright; then
            warn "failed to install playwright from wheelhouse"
            return
        fi
    fi

    if ! PLAYWRIGHT_BROWSERS_PATH="$OUT_ABS/browsers" $PY -m playwright install chromium; then
        warn "failed to install Playwright Chromium"
        return
    fi

    local size
    size=$(du -sh "$OUT/browsers" 2>/dev/null | cut -f1)
    ok "Playwright browsers — $size"
}

# =============================================================================
# Collect MITRE ATT&CK data
# =============================================================================
collect_mitre() {
    hdr "Collecting MITRE ATT&CK data"

    mkdir -p "$OUT/data"

    local urls=(
        "$MITRE_BASE/enterprise-attack/enterprise-attack.json"
        "$MITRE_BASE/mobile-attack/mobile-attack.json"
        "$MITRE_BASE/ics-attack/ics-attack.json"
        "$CAPEC_URL"
    )
    local files=(
        "enterprise-attack.json"
        "mobile-attack.json"
        "ics-attack.json"
        "stix-capec.json"
    )

    local i
    for i in "${!urls[@]}"; do
        local url="${urls[$i]}"
        local dst="$OUT/data/${files[$i]}"

        # Skip if file exists and is > 1MB
        if [ -f "$dst" ]; then
            local size
            size=$(stat -c %s "$dst" 2>/dev/null || echo 0)
            if [ "$size" -gt 1048576 ]; then
                ok "${files[$i]} already present — kept"
                continue
            fi
        fi

        if curl -fsSL --retry 3 --retry-delay 2 -o "$dst.tmp" "$url" && mv "$dst.tmp" "$dst"; then
            ok "${files[$i]} downloaded"
        else
            rm -f "$dst.tmp"
            err "failed to download ${files[$i]}"
            FAILED+=" data"
        fi
    done

    local size
    size=$(du -sh "$OUT/data" 2>/dev/null | cut -f1)
    ok "MITRE data — $size"
}

# =============================================================================
# Collect corpora
# =============================================================================
collect_corpora() {
    hdr "Collecting corpora"

    if [ -f "$OUT/corpora.tar" ]; then
        ok "corpora.tar already present — kept"
        return
    fi

    if ! $PY scripts/sync_corpora.py; then
        warn "sync reported failures — packing the clones that are present"
    fi

    if [ ! -d corpora ]; then
        warn "corpora directory not found"
        return
    fi

    if ! tar -cf "$OUT/corpora.tar" corpora; then
        warn "failed to create corpora.tar"
        rm -f "$OUT/corpora.tar"
        return
    fi

    local size
    size=$(du -sh "$OUT/corpora.tar" 2>/dev/null | cut -f1)
    ok "corpora.tar — $size"
}

# =============================================================================
# Collect frontend
# =============================================================================
collect_frontend() {
    hdr "Collecting frontend"

    if command -v node >/dev/null 2>&1; then
        if ! (cd frontend && npm ci && npm run build); then
            warn "frontend build failed"
        fi
    else
        warn "node not found — packing frontend/dist and node_modules as they are"
    fi

    # Pack dist
    if [ -f frontend/dist/index.html ]; then
        if [ ! -f "$OUT/frontend-dist.tar" ]; then
            tar -cf "$OUT/frontend-dist.tar" -C frontend dist
        else
            ok "frontend-dist.tar already present — kept"
        fi
    else
        warn "frontend/dist missing — the UI will not be in the bundle"
    fi

    # Pack node_modules
    if [ -d frontend/node_modules ]; then
        if [ ! -f "$OUT/node_modules.tar" ]; then
            tar -cf "$OUT/node_modules.tar" -C frontend node_modules
        else
            ok "node_modules.tar already present — kept"
        fi
    fi

    local size
    size=$(du -ch "$OUT/frontend-dist.tar" "$OUT/node_modules.tar" 2>/dev/null | tail -1 | cut -f1)
    ok "frontend artifacts — ${size:-0}"
}

# =============================================================================
# Collect Ollama
# =============================================================================
collect_ollama() {
    hdr "Collecting Ollama"

    mkdir -p "$OUT/ollama"

    # Get latest tag
    local TAG
    TAG=$(curl -fsSL "$OLLAMA_API" 2>/dev/null | grep -m1 '"tag_name"' | cut -d'"' -f4)
    if [ -z "$TAG" ]; then
        warn "failed to get Ollama latest tag"
        return
    fi

    # Determine GOARCH
    local GOARCH
    case "$ARCH" in
        amd64|x86_64) GOARCH="amd64" ;;
        arm64|aarch64) GOARCH="arm64" ;;
        *) GOARCH="amd64" ;;
    esac

    local ASSET="ollama-linux-${GOARCH}.tar.zst"
    local URL="https://github.com/ollama/ollama/releases/download/${TAG}/${ASSET}"
    local DST="$OUT/ollama/${ASSET}"

    if [ -f "$DST" ]; then
        ok "Ollama asset already present — kept"
    else
        if ! curl -fsSL --retry 3 -o "$DST" "$URL"; then
            warn "failed to download Ollama asset"
            return
        fi
    fi

    OLLAMA_ASSET="$ASSET"
    OLLAMA_TAG="$TAG"

    # Check if model already pulled
    local model_base="${LLM_MODEL%%:*}"
    if [ -d "$OUT/ollama/models/manifests/registry.ollama.ai/library/${model_base}" ]; then
        ok "Ollama model already present — kept"
        LLM_MODEL_PACKED="$LLM_MODEL"
        return
    fi

    # Extract
    local RUNTIME="$OUT/ollama/runtime"
    mkdir -p "$RUNTIME"

    local extracted=false
    if command -v unzstd >/dev/null 2>&1; then
        if tar --use-compress-program=unzstd -xf "$DST" -C "$RUNTIME"; then
            extracted=true
        fi
    elif $PY -c "import compression.zstd" 2>/dev/null; then
        # Python >= 3.14 ships compression.zstd; stream it so 1.4 GB never sits in RAM.
        if $PY -c "
import sys, compression.zstd as z
d = z.ZstdDecompressor()
with open(sys.argv[1], 'rb') as f:
    while chunk := f.read(1 << 20):
        sys.stdout.buffer.write(d.decompress(chunk))
" "$DST" | tar -xf - -C "$RUNTIME"; then
            extracted=true
        fi
    fi

    if [ "$extracted" = false ]; then
        warn "zstd not available (apt install zstd) — the model was not pulled"
        return
    fi

    # Find binary
    local BIN
    BIN=$(find "$RUNTIME" -type f -name ollama -perm -u+x 2>/dev/null | head -1)
    if [ -z "$BIN" ]; then
        warn "Ollama binary not found in extracted archive"
        return
    fi

    # Start temporary server
    OLLAMA_MODELS="$OUT_ABS/ollama/models" OLLAMA_HOST=127.0.0.1:11435 "$BIN" serve > "$OUT/ollama/serve.log" 2>&1 &
    local SRV=$!

    # Wait for server
    local i
    for i in $(seq 1 60); do
        if curl -fs http://127.0.0.1:11435/api/tags >/dev/null 2>&1; then
            break
        fi
        sleep 1
    done

    if ! curl -fs http://127.0.0.1:11435/api/tags >/dev/null 2>&1; then
        warn "Ollama server did not start"
        kill "$SRV" 2>/dev/null
        wait "$SRV" 2>/dev/null
        return
    fi

    # Pull model
    if OLLAMA_HOST=127.0.0.1:11435 "$BIN" pull "$LLM_MODEL"; then
        ok "Ollama model pulled"
        LLM_MODEL_PACKED="$LLM_MODEL"
    else
        warn "failed to pull Ollama model"
    fi

    kill "$SRV" 2>/dev/null
    wait "$SRV" 2>/dev/null

    # Cleanup runtime
    rm -rf "$RUNTIME"

    local size
    size=$(du -sh "$OUT/ollama" 2>/dev/null | cut -f1)
    ok "Ollama — $size"
}

# =============================================================================
# Write manifest
# =============================================================================
write_manifest() {
    hdr "Writing manifest"

    # bundle.env
    cat > "$OUT/bundle.env" <<EOF
BUNDLE_PYTHON=$PY_MM
BUNDLE_CODENAME=$CODENAME
BUNDLE_ARCH=$ARCH
BUNDLE_GIT_REV=$GIT_REV
BUNDLE_BUILT_AT=$BUILT_AT
BUNDLE_NODE_DEB=${NODE_DEB:-}
BUNDLE_HF_MODELS="$HF_MODELS_USED"
BUNDLE_OLLAMA_ASSET=${OLLAMA_ASSET:-}
BUNDLE_OLLAMA_TAG=${OLLAMA_TAG:-}
BUNDLE_OLLAMA_MODEL=${LLM_MODEL_PACKED:-}
BUNDLE_SPACY_MODEL=$SPACY_MODEL
EOF

    # corpora.txt
    if ! $PY -c "from pipeline.detection.registry import merged_corpora; [print(c.get('name'), c.get('adapter'), c.get('license'), 'enabled' if c.get('enabled', True) else 'disabled') for c in merged_corpora('detection_corpora.yaml')]" > "$OUT/corpora.txt" 2>/dev/null; then
        warn "failed to generate corpora.txt"
    fi

    # SHA256SUMS
    (cd "$OUT" && find . -type f ! -name SHA256SUMS ! -path './ollama/runtime/*' ! -name '*.log' -print0 | sort -z | xargs -0 sha256sum > SHA256SUMS)
    local count
    count=$(wc -l < "$OUT/SHA256SUMS" 2>/dev/null || echo 0)
    ok "SHA256SUMS ($count files)"
}

# =============================================================================
# Pack final tarball
# =============================================================================
pack() {
    hdr "Packing final tarball"

    mkdir -p dist
    local TARBALL="dist/cti-parsor-offline-${GIT_REV}-${CODENAME}-py${PY_MM}.tar"

    # Source
    if [ "$WORKTREE" = true ]; then
        if ! git ls-files -co --exclude-standard -z | tar --null -T - --transform 's,^,cti-parsor/,' -cf "$TARBALL"; then
            err "failed to pack source (worktree)"
            return 1
        fi
    else
        if ! git archive --format=tar --prefix=cti-parsor/ -o "$TARBALL" HEAD; then
            err "failed to pack source (HEAD)"
            return 1
        fi
    fi

    # Bundle
    if ! tar -rf "$TARBALL" --transform "s,^${OUT}/,cti-parsor/offline/,;s,^${OUT}\$,cti-parsor/offline," --exclude="${OUT}/ollama/runtime" --exclude='*.log' "$OUT"; then
        err "failed to add bundle to tarball"
        return 1
    fi

    local size
    size=$(du -h "$TARBALL" | cut -f1)
    ok "$TARBALL ($size)"

    sha256sum "$TARBALL" > "$TARBALL.sha256"
}

# =============================================================================
# Summary
# =============================================================================
summary() {
    hdr "Summary"

    local items=("wheels" "debs" "hf" "browsers" "data" "corpora.tar" "frontend-dist.tar" "node_modules.tar" "ollama")
    local item
    for item in "${items[@]}"; do
        local path="$OUT/$item"
        if [ -e "$path" ]; then
            local size
            size=$(du -sh "$path" 2>/dev/null | cut -f1)
            ok "$item: present ($size)"
        else
            warn "$item: absent"
        fi
    done

    if [ -n "$FAILED" ]; then
        err "failed: $FAILED"
        exit 1
    fi

    ok "bundle complete"
    info "On the target machine: tar xf <tarball> && cd cti-parsor && bash setup.sh --offline=offline"
}

# =============================================================================
# Main
# =============================================================================
main() {
    parse_args "$@"
    preflight
    collect_wheels
    if [ "$WITH_DEBS" = true ]; then
        collect_debs
    else
        info "--no-debs: skipped"
    fi
    collect_models
    if [ "$WITH_BROWSERS" = true ]; then
        collect_browsers
    else
        info "--no-browsers: skipped"
    fi
    collect_mitre
    if [ "$WITH_CORPORA" = true ]; then
        collect_corpora
    else
        info "--no-corpora: skipped"
    fi
    if [ "$WITH_FRONTEND" = true ]; then
        collect_frontend
    else
        info "--no-frontend: skipped"
    fi
    if [ "$WITH_LLM" = true ]; then
        collect_ollama
    else
        info "--no-llm: skipped"
    fi
    write_manifest
    if [ "$DO_PACK" = true ]; then
        pack
    else
        info "--no-pack: skipped"
    fi
    summary
}

main "$@"
