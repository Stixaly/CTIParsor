#!/usr/bin/env bash
# =============================================================================
# cti-to-stix — Full Setup Script
# Supports: Ubuntu / Debian, AlmaLinux / RHEL / Fedora, WSL1, WSL2
#
# Usage:
#   bash setup.sh              # full setup (recommended for first install)
#   bash setup.sh --no-torch   # skip sentence-transformers / CyNER (faster, minimal)
#   bash setup.sh --no-mitre   # skip MITRE bundle download + index build
#   bash setup.sh --no-spacy   # skip optional spaCy model download
#   bash setup.sh --no-corpora # skip Sigma detection-corpora clone (~525 MB)
#   bash setup.sh --no-capture # skip Playwright + Chromium (disables URL ingestion)
# =============================================================================

set -e

# ── Colour helpers ──────────────────────────────────────────────────────────
GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'
CYAN='\033[0;36m';  BLUE='\033[0;34m';  MAGENTA='\033[0;35m'; NC='\033[0m'

ok()   { echo -e "  ${GREEN}✔${NC}  $*"; }
warn() { echo -e "  ${YELLOW}⚠${NC}  $*"; }
info() { echo -e "  ${CYAN}→${NC}  $*"; }
err()  { echo -e "  ${RED}✖${NC}  $*"; }
sep()  { echo -e "${BLUE}────────────────────────────────────────────────────${NC}"; }
hdr()  { sep; echo -e "${CYAN}  $*${NC}"; sep; }

# ── Flags ───────────────────────────────────────────────────────────────────
OPT_NO_TORCH=false
OPT_NO_MITRE=false
OPT_NO_SPACY=false
OPT_NO_CORPORA=false
OPT_NO_CAPTURE=false

for arg in "$@"; do
  case $arg in
    --no-torch)   OPT_NO_TORCH=true ;;
    --no-mitre)   OPT_NO_MITRE=true ;;
    --no-spacy)   OPT_NO_SPACY=true ;;
    --no-corpora) OPT_NO_CORPORA=true ;;
    --no-capture) OPT_NO_CAPTURE=true ;;
  esac
done

echo ""
sep
echo -e "${CYAN}   CTI → STIX Pipeline  —  Setup Script${NC}"
sep
echo ""

# ── Environment detection ───────────────────────────────────────────────────
IS_WSL=false; WSL_VERSION=""; DISTRO_NAME=""

if grep -qiE "microsoft|wsl" /proc/version 2>/dev/null || \
   grep -qiE "microsoft|wsl" /proc/sys/kernel/osrelease 2>/dev/null || \
   [ -n "${WSL_DISTRO_NAME:-}" ]; then
    IS_WSL=true
    if uname -r 2>/dev/null | grep -qi "WSL2\|wsl2" || [ -n "${WSL_DISTRO_NAME:-}" ]; then
        WSL_VERSION="WSL2"
    else
        WSL_VERSION="WSL1"
    fi
fi

[ -f /etc/os-release ] && DISTRO_NAME=$(. /etc/os-release && echo "${PRETTY_NAME:-$NAME}")

if [ "$IS_WSL" = true ]; then
    echo -e "  ${MAGENTA}🖥  ${WSL_VERSION}${NC}${DISTRO_NAME:+ — ${DISTRO_NAME}}"
    CURRENT_PATH=$(pwd)
    if echo "$CURRENT_PATH" | grep -q "^/mnt/"; then
        warn "Working from the Windows filesystem (${CURRENT_PATH})."
        echo "     Performance is slower on /mnt/. For best speed, copy to Linux FS:"
        echo -e "     ${CYAN}cp -r . ~/cti-to-stix && cd ~/cti-to-stix${NC}"
    else
        ok "Project on Linux filesystem — optimal performance."
    fi
    [ "$WSL_VERSION" = "WSL1" ] && warn "WSL1 detected — consider upgrading to WSL2."
else
    echo -e "  ${GREEN}🐧  Native Linux${NC}${DISTRO_NAME:+ — ${DISTRO_NAME}}"
fi
echo ""

# =============================================================================
# [1/6]  SYSTEM DEPENDENCIES
# =============================================================================
hdr "[1/6]  SYSTEM PACKAGES"

_apt_install() {
    info "apt-get update…"
    sudo apt-get update -q
    info "Installing system packages…"
    sudo apt-get install -y -q \
        python3 python3-pip python3-venv python3-dev \
        build-essential libxml2-dev libxslt1-dev \
        tesseract-ocr poppler-utils \
        curl wget git
}
_dnf_install() {
    info "Installing system packages (dnf)…"
    sudo dnf install -y -q \
        python3 python3-pip python3-devel \
        gcc gcc-c++ libxml2-devel libxslt-devel \
        tesseract poppler-utils \
        curl wget git
}
_yum_install() {
    info "Installing system packages (yum)…"
    sudo yum install -y -q \
        python3 python3-pip python3-devel \
        gcc gcc-c++ libxml2-devel libxslt-devel \
        tesseract poppler-utils \
        curl wget git
}

# `python3 -m venv --help` is NOT the right probe: the venv module lives in the
# stdlib, so the help text prints fine on a Debian/Ubuntu box that cannot create
# an environment.  What Debian packages separately, in python3.X-venv, is
# `ensurepip` — so that is what has to be tested.  Probing the help text meant
# _apt_install never ran on a fresh Ubuntu 26.04, and setup died two steps later
# with "ensurepip is not available".
if ! command -v python3 &>/dev/null || ! python3 -c "import ensurepip" &>/dev/null; then
    if   command -v apt-get &>/dev/null; then _apt_install
    elif command -v dnf     &>/dev/null; then _dnf_install
    elif command -v yum     &>/dev/null; then _yum_install
    else
        err "Unknown package manager. Install manually: python3 python3-pip python3-venv"
        exit 1
    fi
fi

ok "python3 $(python3 --version 2>&1)"

# The floor is 3.10: module-level annotations like `X | None` are evaluated at
# import time, so 3.9 raises TypeError before anything runs.  The ceiling is not
# enforced — a newer Python usually works — but CI pins 3.12, and a distro that
# ships ahead of the wheel ecosystem fails later, inside `pip install`, with an
# error that points at a package rather than at the interpreter.
PY_MINOR=$(python3 -c 'import sys; print(sys.version_info.minor)')
PY_TESTED=12
if [ "$PY_MINOR" -lt 10 ]; then
    err "Python 3.${PY_MINOR} is too old — this project needs 3.10 or newer."
    exit 1
elif [ "$PY_MINOR" -gt "$PY_TESTED" ]; then
    warn "Python 3.${PY_MINOR} is newer than the 3.${PY_TESTED} CI tests against."
    echo "       If pip fails to build a package below, that is the likely cause:"
    echo "       a dependency without a wheel for 3.${PY_MINOR} yet. Installing"
    echo -e "       ${CYAN}python3.${PY_TESTED}${NC} and re-running with it is the quickest way out."
fi

# ── Always ensure tesseract + poppler are installed ─────────────────────────
# These are optional tools used by pdf2image / pytesseract for scanned PDFs.
# They are checked separately so they get installed even when python3 already
# exists (which skips the full _apt_install above).
_install_if_missing_apt() {
    # $4 is the version flag: pdftoppm has no --version and reads it as a
    # filename, so the "installed" line printed
    #   poppler (pdftoppm) I/O Error: Couldn't open file '--version'
    local pkg="$1" bin="$2" label="$3" vflag="${4:---version}"
    if command -v "$bin" &>/dev/null; then
        local ver
        ver=$(${bin} "$vflag" 2>&1 | head -1)
        # Any probe can still surprise us on another distro; print the version
        # only when it looks like one.
        case "$ver" in
            *[Ee]rror*|*"No such file"*|"") ok "$label available" ;;
            *) ok "$label $ver" ;;
        esac
    else
        info "$label not found — attempting to install ${pkg}…"
        if sudo apt-get install -y -q "$pkg" 2>/dev/null; then
            ok "$label installed"
        else
            warn "$label install failed — you may need to run manually:"
            echo -e "       ${CYAN}sudo apt-get install -y ${pkg}${NC}"
        fi
    fi
}
_install_if_missing_dnf() {
    local pkg="$1" bin="$2" label="$3"
    command -v "$bin" &>/dev/null && return
    sudo dnf install -y -q "$pkg" 2>/dev/null || true
}

if command -v apt-get &>/dev/null; then
    _install_if_missing_apt "tesseract-ocr" "tesseract" "tesseract"
    _install_if_missing_apt "poppler-utils" "pdftoppm"  "poppler (pdftoppm)" "-v"
elif command -v dnf &>/dev/null; then
    command -v tesseract &>/dev/null || sudo dnf install -y -q tesseract 2>/dev/null || true
    command -v pdftoppm  &>/dev/null || sudo dnf install -y -q poppler-utils 2>/dev/null || true
    command -v tesseract &>/dev/null \
        && ok  "tesseract $(tesseract --version 2>&1 | head -1)" \
        || warn "tesseract not found — scanned PDF OCR will be disabled."
    command -v pdftoppm  &>/dev/null \
        && ok  "poppler (pdftoppm) available" \
        || warn "poppler not found — install 'poppler-utils' for PDF→image conversion."
else
    command -v tesseract &>/dev/null \
        && ok  "tesseract $(tesseract --version 2>&1 | head -1)" \
        || warn "tesseract not found — scanned PDF OCR will be disabled."
    command -v pdftoppm  &>/dev/null \
        && ok  "poppler (pdftoppm) available" \
        || warn "poppler not found — install 'poppler-utils' for PDF→image conversion."
fi

# =============================================================================
# [1b/6]  NODE.JS  (web UI frontend)
# =============================================================================
echo ""
hdr "[1b/6]  NODE.JS  (web UI)"

NODE_OK=false
if command -v node &>/dev/null; then
    NODE_VER=$(node --version 2>&1)
    NPM_VER=$(npm  --version 2>&1)
    NODE_MAJOR=$(echo "$NODE_VER" | sed 's/v\([0-9]*\).*/\1/')
    if [ "${NODE_MAJOR:-0}" -ge 18 ] 2>/dev/null; then
        ok "node ${NODE_VER}   npm v${NPM_VER}"
        NODE_OK=true
    else
        warn "node ${NODE_VER} is < 18 — frontend build may fail."
    fi
else
    warn "Node.js not found — web UI build unavailable."
    echo ""
    echo "  Install Node.js 20:"
    echo -e "    ${CYAN}curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -${NC}"
    echo -e "    ${CYAN}sudo apt-get install -y nodejs${NC}"
    echo ""
    echo "  Or use nvm (manages multiple versions):"
    echo -e "    ${CYAN}curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.7/install.sh | bash${NC}"
    echo -e "    ${CYAN}source ~/.bashrc && nvm install 20${NC}"
    [ "$IS_WSL" = true ] && warn "Install Node.js INSIDE ${WSL_VERSION}, not on Windows."
fi

# =============================================================================
# [2/6]  PYTHON VIRTUAL ENVIRONMENT
# =============================================================================
echo ""
hdr "[2/6]  PYTHON VIRTUAL ENVIRONMENT"

# A directory is not a virtualenv.  A run that dies at ensurepip leaves .venv/
# behind with an interpreter and no bin/activate; the next run then reports
# "reusing" and falls over at `source` with a message that looks nothing like
# the real cause.  Treat an incomplete tree as the debris it is.
if [ -d ".venv" ] && [ ! -f ".venv/bin/activate" ]; then
    warn ".venv exists but has no bin/activate — debris from a failed run."
    info "Removing it and starting over…"
    rm -rf .venv
fi

if [ ! -d ".venv" ]; then
    # Checked again here: step [1/6] only installs packages when it decides it
    # has to, and a --no-sudo run or a failed apt can still leave ensurepip
    # missing.  Naming the exact versioned package beats letting `venv` fail
    # with a message that guesses at the Python version.
    if ! python3 -c "import ensurepip" &>/dev/null; then
        PYVENV_PKG="python3.$(python3 -c 'import sys; print(sys.version_info.minor)')-venv"
        err "python3 cannot create a virtualenv — ensurepip is missing."
        echo   "       Debian and Ubuntu ship it in a separate package:"
        echo -e "         ${CYAN}sudo apt-get install -y ${PYVENV_PKG}${NC}"
        echo   "       Then run this script again."
        exit 1
    fi
    info "Creating .venv…"
    python3 -m venv .venv
    ok ".venv created"
else
    ok ".venv already exists — reusing"
fi

info "Activating .venv…"
# shellcheck disable=SC1091
source .venv/bin/activate
ok "Active: $(python --version)  ($(which python))"

# =============================================================================
# [3/6]  PYTHON PACKAGES
# =============================================================================
echo ""
hdr "[3/6]  PYTHON PACKAGES"

info "Upgrading pip…"
pip install --upgrade pip -q
echo ""

echo -e "  Packages in ${YELLOW}requirements.txt${NC}:"
echo "    pdfplumber, python-docx, beautifulsoup4, markitdown"
echo "    pdf2image, pytesseract, iocextract"
echo "    pydantic, stix2, stix2-validator, python-dotenv"
echo "    anthropic, openai, rapidfuzz"
echo "    spacy  (optional NER fallback — no model auto-downloaded)"
if [ "$OPT_NO_TORCH" = false ]; then
    echo ""
    echo -e "  ${YELLOW}sentence-transformers  +  transformers  +  PyTorch${NC}"
    echo "  ┌──────────────────────────────────────────────────────────────┐"
    echo "  │  PyTorch (CPU) is a large dependency (~800 MB download).     │"
    echo "  │  It is required for:                                         │"
    echo "  │    • Stage 2c — Semantic TTP detection (all-MiniLM-L6-v2)   │"
    echo "  │    • Stage 2d — CyNER 2.0 cybersecurity NER (DeBERTa-v3)    │"
    echo "  │  These stages significantly improve entity recognition.      │"
    echo "  │  Skip with: bash setup.sh --no-torch                        │"
    echo "  └──────────────────────────────────────────────────────────────┘"
    echo ""
else
    warn "--no-torch: skipping sentence-transformers / transformers / torch."
    warn "  Stage 2c (semantic TTP) and Stage 2d (CyNER) will be disabled."
    echo ""
fi

pip install -r requirements.txt

# Remove spacy-curated-transformers if pulled in (requires torch, avoids errors)
if pip show spacy-curated-transformers &>/dev/null; then
    info "Removing spacy-curated-transformers (unneeded transitive dep)…"
    pip uninstall -y spacy-curated-transformers
fi

if [ "$OPT_NO_TORCH" = true ]; then
    info "Uninstalling sentence-transformers / transformers per --no-torch flag…"
    pip uninstall -y sentence-transformers transformers 2>/dev/null || true
fi

echo ""
info "Installing API packages (requirements-api.txt)…"
echo "  fastapi, uvicorn[standard], python-multipart, aiofiles"
pip install -r requirements-api.txt
echo ""

# re2 backs _compile_pattern in stage2_extraction: it guarantees linear-time
# matching, so a crafted report cannot pin a CPU on catastrophic backtracking.
# The code falls back to the standard `re` module without it, which is why this
# is a soft install — the wheel needs the RE2 C++ library and a toolchain, and a
# failure here must not stop a setup that otherwise works.
info "Installing re2 (ReDoS protection for Stage 2 regexes)…"
if python -c "import re2" 2>/dev/null; then
    ok "re2 already installed"
elif pip install -q "$(grep -E '^re2' requirements-optional.txt || echo re2)" 2>/dev/null \
     && python -c "import re2" 2>/dev/null; then
    ok "re2 installed — Stage 2 regexes run in guaranteed linear time"
else
    warn "re2 not installed — Stage 2 falls back to Python's own re module."
    echo   "       Reports are attacker-influenced text, so this leaves regex"
    echo   "       matching open to catastrophic backtracking. To fix it:"
    echo -e "         ${CYAN}sudo apt-get install -y libre2-dev  # or: sudo dnf install re2-devel${NC}"
    echo -e "         ${CYAN}.venv/bin/pip install -r requirements-optional.txt${NC}"
fi
echo ""
ok "All Python packages installed"

# =============================================================================
# [4/6]  MITRE ATT&CK DATA FILES
# =============================================================================
echo ""
hdr "[4/6]  MITRE ATT&CK DATA FILES"

if [ "$OPT_NO_MITRE" = true ]; then
    warn "--no-mitre: skipping MITRE data download."
    warn "  Stage 2b (gazetteer NER), Stage 2c (semantic TTP), and Stage 3c"
    warn "  (TTP normalization) will run in degraded mode until you run:"
    echo -e "  ${CYAN}python scripts/build_indexes.py${NC}"
else
    # ── Check if indexes are already built ──────────────────────────────────
    INDEXES_OK=true
    [ ! -f "pipeline/data/mitre_index.json"         ] && INDEXES_OK=false
    [ ! -f "pipeline/data/gazetteer.json"            ] && INDEXES_OK=false
    [ ! -f "pipeline/data/mitre_embeddings.npy"      ] && INDEXES_OK=false

    if [ "$INDEXES_OK" = true ]; then
        GAZ_ENTRIES=$(python -c "import json; print(len(json.load(open('pipeline/data/gazetteer.json'))))" 2>/dev/null || echo "?")
        TECH_COUNT=$(python -c "import json; d=json.load(open('pipeline/data/mitre_index.json')); print(len(d['techniques']))" 2>/dev/null || echo "?")
        ok "pipeline/data/mitre_index.json    (${TECH_COUNT} techniques)"
        ok "pipeline/data/gazetteer.json      (${GAZ_ENTRIES} entries)"
        ok "pipeline/data/mitre_embeddings.npy"
        info "Indexes already built. To rebuild from updated bundles:"
        echo -e "     ${CYAN}python scripts/build_indexes.py${NC}"
    else
        # ── Bundle discovery ─────────────────────────────────────────────────
        echo ""
        info "Looking for MITRE ATT&CK bundle files…"
        echo ""

        ENTERPRISE_JSON=""
        MOBILE_JSON=""
        ICS_JSON=""
        CAPEC_JSON=""

        # Search common locations
        for dir in "data" "$HOME/Downloads" "$HOME/Documents"; do
            [ -f "$dir/enterprise-attack.json" ] && [ -z "$ENTERPRISE_JSON" ] && ENTERPRISE_JSON="$dir/enterprise-attack.json"
            [ -f "$dir/mobile-attack.json"     ] && [ -z "$MOBILE_JSON"     ] && MOBILE_JSON="$dir/mobile-attack.json"
            [ -f "$dir/ics-attack.json"        ] && [ -z "$ICS_JSON"        ] && ICS_JSON="$dir/ics-attack.json"
            [ -f "$dir/stix-capec.json"        ] && [ -z "$CAPEC_JSON"      ] && CAPEC_JSON="$dir/stix-capec.json"
        done

        # Show what was found
        if [ -n "$ENTERPRISE_JSON" ]; then
            SIZE_MB=$(du -m "$ENTERPRISE_JSON" | cut -f1)
            ok "enterprise-attack.json  (${SIZE_MB} MB)  →  ${ENTERPRISE_JSON}"
        else
            warn "enterprise-attack.json not found"
        fi
        [ -n "$MOBILE_JSON" ] && ok  "mobile-attack.json found" || warn "mobile-attack.json not found"
        [ -n "$ICS_JSON"    ] && ok  "ics-attack.json found"    || warn "ics-attack.json not found"
        [ -n "$CAPEC_JSON"  ] && ok  "stix-capec.json found"    || warn "stix-capec.json not found"

        echo ""

        # If any bundles are missing, offer to download them
        if [ -z "$ENTERPRISE_JSON" ] || [ -z "$MOBILE_JSON" ] || [ -z "$ICS_JSON" ] || [ -z "$CAPEC_JSON" ]; then
            echo "  Some MITRE bundle files are missing."
            echo "  You can download them automatically (requires internet, ~65 MB total):"
            echo ""
            echo -e "  ${YELLOW}Download all MITRE bundles? [Y/n]${NC} "
            read -r -p "  > " DOWNLOAD_MITRE
            DOWNLOAD_MITRE="${DOWNLOAD_MITRE:-Y}"

            if [[ "$DOWNLOAD_MITRE" =~ ^[Yy] ]]; then
                mkdir -p data
                BASE_URL="https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master"
                CAPEC_URL="https://raw.githubusercontent.com/mitre/cti/master/capec/2.1/stix-capec.json"

                _dl() {
                    local url="$1" dst="$2" label="$3"
                    if [ -f "$dst" ]; then
                        ok "$label already present — skipping download"
                        return
                    fi
                    info "Downloading $label…"
                    if curl -fsSL --retry 3 --retry-delay 2 -o "$dst" "$url"; then
                        SIZE_MB=$(du -m "$dst" | cut -f1)
                        ok "$label downloaded (${SIZE_MB} MB)"
                    else
                        warn "$label download failed — run manually:"
                        echo "       curl -o $dst $url"
                    fi
                }

                [ -z "$ENTERPRISE_JSON" ] && _dl \
                    "$BASE_URL/enterprise-attack/enterprise-attack.json" \
                    "data/enterprise-attack.json" "enterprise-attack.json"
                [ -z "$MOBILE_JSON" ] && _dl \
                    "$BASE_URL/mobile-attack/mobile-attack.json" \
                    "data/mobile-attack.json" "mobile-attack.json"
                [ -z "$ICS_JSON" ] && _dl \
                    "$BASE_URL/ics-attack/ics-attack.json" \
                    "data/ics-attack.json" "ics-attack.json"
                [ -z "$CAPEC_JSON" ] && _dl \
                    "$CAPEC_URL" \
                    "data/stix-capec.json" "stix-capec.json"

                # Re-discover after download
                [ -f "data/enterprise-attack.json" ] && ENTERPRISE_JSON="data/enterprise-attack.json"
                [ -f "data/mobile-attack.json"     ] && MOBILE_JSON="data/mobile-attack.json"
                [ -f "data/ics-attack.json"        ] && ICS_JSON="data/ics-attack.json"
                [ -f "data/stix-capec.json"        ] && CAPEC_JSON="data/stix-capec.json"
            else
                warn "Skipping download. Run later:"
                echo -e "     ${CYAN}python scripts/build_indexes.py --enterprise /path/to/enterprise-attack.json${NC}"
            fi
        fi

        # ── Build indexes ────────────────────────────────────────────────────
        HAVE_AT_LEAST_ONE=false
        [ -n "$ENTERPRISE_JSON" ] && HAVE_AT_LEAST_ONE=true
        [ -n "$MOBILE_JSON"     ] && HAVE_AT_LEAST_ONE=true
        [ -n "$ICS_JSON"        ] && HAVE_AT_LEAST_ONE=true
        [ -n "$CAPEC_JSON"      ] && HAVE_AT_LEAST_ONE=true

        if [ "$HAVE_AT_LEAST_ONE" = true ]; then
            echo ""
            info "Building compact MITRE index, gazetteer, and embeddings…"
            echo "  This runs scripts/build_indexes.py and may take 1–3 minutes"
            echo "  (sentence-transformer encoding of ~1,500 technique descriptions)."
            echo ""

            # Use the venv python so sentence-transformers is available
            CMD="python scripts/build_indexes.py"
            [ -n "$ENTERPRISE_JSON" ] && CMD="$CMD --enterprise '$ENTERPRISE_JSON'"
            [ -n "$MOBILE_JSON"     ] && CMD="$CMD --mobile     '$MOBILE_JSON'"
            [ -n "$ICS_JSON"        ] && CMD="$CMD --ics        '$ICS_JSON'"
            [ -n "$CAPEC_JSON"      ] && CMD="$CMD --capec      '$CAPEC_JSON'"

            if eval "$CMD"; then
                ok "All indexes built successfully"
            else
                warn "Index build encountered errors (see above)."
                info "Retry manually: python scripts/build_indexes.py"
            fi
        else
            warn "No MITRE bundles found — indexes not built."
            info "To build later: python scripts/build_indexes.py"
        fi
    fi
fi

# =============================================================================
# DETECTION-RULE CORPORA  (Sigma / Suricata / YARA — coverage matrix, ADR-0006)
# =============================================================================
echo ""
hdr "DETECTION-RULE CORPORA (Sigma / Suricata / YARA)"

if [ "$OPT_NO_CORPORA" = true ]; then
    warn "--no-corpora: skipping the detection-corpora clone."
    info "  The coverage matrix stays empty until you run:"
    echo -e "     ${CYAN}python scripts/sync_corpora.py && python scripts/build_detection_index.py${NC}"
else
    echo "  Coverage matches each report's MITRE TTPs against public rule corpora"
    echo "  in three formats (Sigma .yml, Suricata .rules, YARA .yar)."
    echo "  This clones the public repos in detection_corpora.yaml into ./corpora/"
    echo "  (~525 MB, shallow) and ingests them into the rule store."
    echo ""
    echo -e "  ${YELLOW}Clone & ingest detection corpora now? [Y/n]${NC}"
    read -r -p "  > " DL_CORPORA
    DL_CORPORA="${DL_CORPORA:-Y}"

    if [[ "$DL_CORPORA" =~ ^[Yy] ]]; then
        info "Cloning corpora (scripts/sync_corpora.py)…"
        if python scripts/sync_corpora.py; then
            info "Ingesting rules (scripts/build_detection_index.py)…"
            if python scripts/build_detection_index.py; then
                ok "Detection corpora cloned & ingested."
            else
                warn "Ingest failed — retry: python scripts/build_detection_index.py"
            fi
        else
            warn "Corpora clone failed — retry: python scripts/sync_corpora.py"
        fi
    else
        info "Skipping. Run later, or use the Settings → Redownload button per corpus:"
        echo -e "     ${CYAN}python scripts/sync_corpora.py && python scripts/build_detection_index.py${NC}"
    fi

    # ---------------------------------------------------------------------
    # Upgrading an existing store.  Schema migrations normally run on API
    # startup, so a store built by an older checkout can sit here with tables
    # the new code expects but has never populated.  A fresh ingest above
    # writes them; an upgrade that skipped the ingest does not, and the
    # symptom is silent (the coverage UI shows every rule size as "0 B"
    # rather than failing).  Apply the migrations and backfill here.
    # ---------------------------------------------------------------------
    if [ -f cti_stix.db ]; then
        info "Applying schema migrations to the existing store…"
        python -c "from api.db import init_db; init_db()" 2>/dev/null \
            && ok "Schema up to date." \
            || warn "Could not apply migrations — start the API once to run them."

        NEEDS_BYTES=$(python - <<'PYEOF' 2>/dev/null
import sqlite3
try:
    c = sqlite3.connect("file:cti_stix.db?mode=ro", uri=True)
    names = {r[0] for r in c.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    if {"detection_rules", "rule_bytes"} <= names:
        print(c.execute(
            "SELECT COUNT(*) FROM detection_rules d WHERE NOT EXISTS "
            "(SELECT 1 FROM rule_bytes b WHERE b.rule_id = d.id)"
        ).fetchone()[0])
    else:
        print(0)
except Exception:
    print(0)
PYEOF
)
        if [ "${NEEDS_BYTES:-0}" -gt 0 ] 2>/dev/null; then
            info "Backfilling rule body sizes for ${NEEDS_BYTES} rules (ADR-0022)…"
            if python -m scripts.backfill_rule_bytes >/dev/null 2>&1; then
                ok "Rule sizes backfilled."
            else
                warn "Backfill failed — retry: python -m scripts.backfill_rule_bytes"
                info "  Until then the coverage page shows every rule size as 0 B."
            fi
        fi
    fi
fi

# =============================================================================
# [5/6]  spaCy MODEL  (optional — CyNER provides better accuracy)
# =============================================================================
echo ""
hdr "[5/6]  spaCy NLP MODEL  (optional)"

if [ "$OPT_NO_SPACY" = true ]; then
    warn "--no-spacy: skipping spaCy model download."
    info "  The pipeline uses CyNER + gazetteer for NER — spaCy is not required."
else
    echo "  spaCy's generic NER is now optional — the pipeline uses:"
    echo "    • Stage 2b  Gazetteer NER  (1,792 known malware/APT/tool names)"
    echo "    • Stage 2d  CyNER 2.0      (DeBERTa-v3 trained on CTI text)"
    echo "  en_core_web_lg (~600 MB) is only useful as a legacy fallback."
    echo ""

    if python -c "import spacy; spacy.load('en_core_web_sm')" 2>/dev/null; then
        ok "spaCy model already installed"
    else
        echo -e "  ${YELLOW}Download en_core_web_sm (small model, ~12 MB)? [y/N]${NC}"
        read -r -p "  > " DL_SPACY
        DL_SPACY="${DL_SPACY:-N}"

        if [[ "$DL_SPACY" =~ ^[Yy] ]]; then
            info "Downloading en_core_web_sm…"
            python -m spacy download en_core_web_sm
            ok "en_core_web_sm installed"
        else
            info "Skipping spaCy model. The pipeline will use CyNER + gazetteer instead."
        fi
    fi
fi

# =============================================================================
# [6/6]  API KEY CONFIGURATION
# =============================================================================
echo ""
hdr "[6/6]  API KEY CONFIGURATION"

if [ ! -f ".env" ]; then
    if [ -f ".env.example" ]; then
        cp .env.example .env
        ok ".env created from .env.example"
    else
        # No inline copy of the template here, deliberately.  The previous
        # fallback duplicated a handful of keys and then drifted: it knew
        # nothing of gemini, lmstudio, vllm, the vision stage or CVE
        # enrichment, and disagreed with the template on OLLAMA_MODEL.  A
        # missing .env.example means a broken checkout, so say that instead of
        # writing a config that looks complete and is not.
        warn ".env.example is missing — this checkout is incomplete."
        echo -e "  ${CYAN}git checkout .env.example${NC}   (or re-clone)"
        cat > .env << 'ENVEOF'
LLM_PROVIDER=anthropic
ANTHROPIC_API_KEY=sk-ant-xxxxxxxxxxxxxxxxxxxx
ENVEOF
        warn ".env created with a minimal starter — restore .env.example for the rest"
    fi
    echo ""
    echo -e "  ${RED}ACTION REQUIRED — set your LLM provider and key in .env:${NC}"
    echo -e "     ${CYAN}nano .env${NC}"
    echo -e "     ${YELLOW}ANTHROPIC_API_KEY=sk-ant-...${NC}   ← Anthropic (default)"
    echo -e "     ${YELLOW}GEMINI_API_KEY=...${NC}             ← or Google Gemini"
    echo -e "     ${YELLOW}MISTRAL_API_KEY=...${NC}            ← or Mistral"
    echo -e "     ${YELLOW}LLM_PROVIDER=ollama${NC}            ← or local Ollama"
    echo -e "     ${YELLOW}LLM_PROVIDER=lmstudio${NC}          ← or local LM Studio"
    echo -e "     ${YELLOW}LLM_PROVIDER=vllm${NC}              ← or local vLLM"
    echo ""
    echo -e "  ${CYAN}Optional, both off by default:${NC}"
    echo -e "     ${YELLOW}VISION_PROVIDER=${NC}               ← read figures (Stage 1f)"
    echo -e "     ${YELLOW}CVE_ENRICHMENT=1${NC}               ← CVSS scores from CIRCL"
else
    ok ".env already present"
    if grep -qE "sk-ant-xxx|xxxx" .env 2>/dev/null; then
        warn "API key looks like the default placeholder!"
        echo -e "  ${RED}  nano .env  →  update ANTHROPIC_API_KEY=sk-ant-...${NC}"
    else
        ok "API key configured"
    fi
fi

# =============================================================================
# CyNER 2.0 MODEL PRE-DOWNLOAD  (Stage 2d — DeBERTa-v3 cybersecurity NER)
# =============================================================================
echo ""
hdr "CyNER 2.0 MODEL PRE-DOWNLOAD"

if [ "$OPT_NO_TORCH" = true ]; then
    warn "--no-torch: skipping CyNER model pre-download (Stage 2d disabled)."
else
    CYNER_MODEL_ID=$(grep -E '^CYNER_MODEL=' .env 2>/dev/null | tail -1 | cut -d'=' -f2-)
    CYNER_ENABLED_VAL=$(grep -E '^CYNER_ENABLED=' .env 2>/dev/null | tail -1 | cut -d'=' -f2-)
    CYNER_MODEL_ID="${CYNER_MODEL_ID:-PranavaKailash/CyNER-2.0-DeBERTa-v3-base}"
    CYNER_ENABLED_VAL="${CYNER_ENABLED_VAL:-true}"

    if [[ "$CYNER_ENABLED_VAL" =~ ^([Ff]alse|0|[Nn]o)$ ]]; then
        info "CYNER_ENABLED=false in .env — skipping CyNER model pre-download."
    else
        echo "  Stage 2d (CyNER 2.0 cybersecurity NER) downloads its model from"
        echo "  HuggingFace on first pipeline run (~0.8 GB). Pre-downloading it now"
        echo "  avoids that delay during the first report processed."
        echo "  (Requires the sentencepiece package — installed above.)"
        echo ""
        echo -e "  Model: ${CYAN}${CYNER_MODEL_ID}${NC}"
        echo -e "  ${YELLOW}Download it now? [Y/n]${NC}"
        read -r -p "  > " DL_CYNER
        DL_CYNER="${DL_CYNER:-Y}"

        if [[ "$DL_CYNER" =~ ^[Yy] ]]; then
            info "Downloading ${CYNER_MODEL_ID} (this may take a few minutes)…"
            if python -c "from transformers import pipeline; pipeline('ner', model='${CYNER_MODEL_ID}', aggregation_strategy='simple', device=-1)" 2>/dev/null; then
                # Clear any stale unavailability sentinel from a previous model.
                rm -f .cyner_model_unavailable
                ok "CyNER model cached: ${CYNER_MODEL_ID}"
            else
                warn "CyNER model pre-download failed — it will be downloaded on first pipeline run instead."
                info "  Retry manually: python -c \"from transformers import pipeline; pipeline('ner', model='${CYNER_MODEL_ID}', aggregation_strategy='simple')\""
            fi
        else
            info "Skipping. The model will download on first pipeline run instead."
        fi
    fi
fi

# =============================================================================
# GLiNER MODEL PRE-DOWNLOAD  (avoids a large download on the first pipeline run)
# =============================================================================
echo ""
hdr "GLiNER MODEL PRE-DOWNLOAD"

if [ "$OPT_NO_TORCH" = true ]; then
    warn "--no-torch: skipping GLiNER model pre-download (Stage 2e disabled)."
else
    GLINER_MODEL_ID=$(grep -E '^GLINER_MODEL=' .env 2>/dev/null | tail -1 | cut -d'=' -f2-)
    GLINER_ENABLED_VAL=$(grep -E '^GLINER_ENABLED=' .env 2>/dev/null | tail -1 | cut -d'=' -f2-)
    GLINER_MODEL_ID="${GLINER_MODEL_ID:-urchade/gliner_large-v2.1}"
    GLINER_ENABLED_VAL="${GLINER_ENABLED_VAL:-true}"

    if [[ "$GLINER_ENABLED_VAL" =~ ^([Ff]alse|0|[Nn]o)$ ]]; then
        info "GLINER_ENABLED=false in .env — skipping GLiNER model pre-download."
    else
        echo "  Stage 2e (GLiNER zero-shot NER) downloads its model from HuggingFace"
        echo "  on first pipeline run (~800 MB for the default model). Pre-downloading"
        echo "  it now avoids that delay during the first report processed."
        echo ""
        echo -e "  Model: ${CYAN}${GLINER_MODEL_ID}${NC}"
        echo -e "  ${YELLOW}Download it now? [Y/n]${NC}"
        read -r -p "  > " DL_GLINER
        DL_GLINER="${DL_GLINER:-Y}"

        if [[ "$DL_GLINER" =~ ^[Yy] ]]; then
            info "Downloading ${GLINER_MODEL_ID} (this may take a few minutes)…"
            if python -c "from gliner import GLiNER; GLiNER.from_pretrained('${GLINER_MODEL_ID}')" 2>/dev/null; then
                ok "GLiNER model cached: ${GLINER_MODEL_ID}"
            else
                warn "GLiNER model pre-download failed — it will be downloaded on first pipeline run instead."
                info "  Retry manually: python -c \"from gliner import GLiNER; GLiNER.from_pretrained('${GLINER_MODEL_ID}')\""
            fi
        else
            info "Skipping. The model will download on first pipeline run instead."
        fi
    fi
fi

# =============================================================================
# FINAL IMPORT VERIFICATION
# =============================================================================
# WEB CAPTURE  (URL → PDF ingestion — optional)
# =============================================================================
echo ""
hdr "WEB CAPTURE  (URL → PDF)"

# Read by the summary block at the end of this script.  Only a real Chromium
# launch sets it: `playwright install chromium` succeeds without the system
# libraries and the browser then dies at runtime, so an import check lies.
CAPTURE_READY=false

if [ "$OPT_NO_CAPTURE" = true ]; then
    warn "--no-capture: skipping Playwright / Chromium install."
    info "  The 'File' and 'Paste' tabs work as usual. Only the 'URL' tab will return a 503."
else
    echo "  The URL tab renders a web page to PDF server-side, then ingests it."
    echo "  It needs Playwright + a Chromium build (~170 MB) and a set of system"
    echo "  libraries. JavaScript stays DISABLED unless the analyst enables it"
    echo "  per capture, and the Chromium sandbox is kept on."
    echo ""

    CAPTURE_WANTED=true

    if python -c "from playwright.sync_api import sync_playwright" 2>/dev/null; then
        ok "Playwright Python package already installed"
    else
        echo -e "  ${YELLOW}Install Playwright and a headless Chromium (~170 MB)? [Y/n]${NC}"
        read -r -p "  > " DL_CAPTURE
        DL_CAPTURE="${DL_CAPTURE:-Y}"

        if [[ "$DL_CAPTURE" =~ ^[Nn] ]]; then
            info "Skipping Playwright install. The URL tab will return a 503."
            CAPTURE_WANTED=false
        else
            info "Installing Playwright…"
            # Version pinned in requirements-optional.txt, not bare, so the
            # constraint that file carries is actually honoured.
            pip install -q "$(grep -E '^playwright' requirements-optional.txt || echo playwright)" \
                || { warn "pip install playwright failed."; CAPTURE_WANTED=false; }
        fi
    fi

    if [ "$CAPTURE_WANTED" = true ]; then
        info "Downloading Chromium for Playwright…"
        python -m playwright install chromium || { warn "Chromium download failed."; }
    fi

    if [ "$CAPTURE_WANTED" = true ]; then
        if sudo -n true 2>/dev/null; then
            info "Installing system dependencies for Chromium…"
            python -m playwright install-deps chromium || { warn "System dependency installation failed."; }
        else
            warn "Passwordless sudo is not available. Please run the following command manually:"
            echo -e "    ${CYAN}sudo .venv/bin/python -m playwright install-deps chromium${NC}"
            info "  Without these libraries, Chromium fails with 'error while loading shared libraries: libasound.so.2'."
        fi
    fi

    if [ "$CAPTURE_WANTED" = true ]; then
        if python - <<'PYEOF' 2>/dev/null
from playwright.sync_api import sync_playwright
with sync_playwright() as p:
    b = p.chromium.launch(headless=True, chromium_sandbox=True)
    b.close()
PYEOF
        then
            CAPTURE_READY=true
            ok "Chromium launches — the URL tab is ready"
        else
            warn "Chromium is installed but does not launch."
            info "  Usually a missing system library (e.g. libasound.so.2)."
            info "  Fix it with:"
            echo -e "    ${CYAN}sudo .venv/bin/python -m playwright install-deps chromium${NC}"
            info "  Until then, the URL tab returns 503 — use the Paste tab."
        fi
    fi
fi

# =============================================================================
echo ""
hdr "IMPORT VERIFICATION"

python - <<'PYEOF'
import sys

checks = [
    # (pip name,             import name,              required)
    # ── Core pipeline ──────────────────────────────────────────
    ("pdfplumber",           "pdfplumber",              True),
    ("python-docx",          "docx",                    True),
    ("beautifulsoup4",       "bs4",                     True),
    ("markitdown",           "markitdown",              True),
    ("pdf2image",            "pdf2image",               True),
    ("pytesseract",          "pytesseract",             True),
    ("iocextract",           "iocextract",              True),
    ("pydantic",             "pydantic",                True),
    ("stix2",                "stix2",                   True),
    ("stix2-validator",      "stix2validator",          True),
    ("python-dotenv",        "dotenv",                  True),
    ("anthropic",            "anthropic",               True),
    ("openai",               "openai",                  True),
    ("rapidfuzz",            "rapidfuzz",               True),
    ("pyahocorasick",        "ahocorasick",             True),
    # ── API ────────────────────────────────────────────────────
    ("fastapi",              "fastapi",                 True),
    ("uvicorn",              "uvicorn",                 True),
    ("aiofiles",             "aiofiles",                True),
    # ── Optional ML stages ─────────────────────────────────────
    ("numpy",                "numpy",                   False),
    ("sentence-transformers","sentence_transformers",   False),
    ("transformers",         "transformers",            False),
    ("sentencepiece",        "sentencepiece",           False),   # CyNER 2.0 tokenizer (Stage 2d)
    ("gliner",               "gliner",                  False),   # Stage 2e — zero-shot NER
    ("spacy",                "spacy",                   False),   # legacy fallback
    # ── Optional ingestion ─────────────────────────────────────
    ("playwright",           "playwright",              False),   # ADR-0029 — URL → PDF capture
]

GREEN = '\033[0;32m'; YELLOW = '\033[1;33m'; RED = '\033[0;31m'; NC = '\033[0m'
missing_required = []

for pip_name, mod_name, required in checks:
    try:
        __import__(mod_name)
        tag = f"{GREEN}✔{NC}"
        status = "OK"
    except ImportError as e:
        tag = f"{RED}✖{NC}" if required else f"{YELLOW}–{NC}"
        status = f"MISSING{'  (required)' if required else '  (optional)'}"
        if required:
            missing_required.append(pip_name)

    print(f"  {tag}  {pip_name:<28}  {status}")

print()
if missing_required:
    print(f"  {RED}Missing required packages:{NC} {', '.join(missing_required)}")
    print(f"  Run: pip install {' '.join(missing_required)}")
    sys.exit(1)
else:
    print(f"  {GREEN}All required packages available.{NC}")
PYEOF

# =============================================================================
# STIX ICONS  (official OASIS STIX 2.1 icon set for the graph view)
# =============================================================================
echo ""
hdr "STIX 2.1 ICONS"

STIX_ICONS_DIR="frontend/public/stix-icons"
STIX_ICON_COUNT=$(ls "${STIX_ICONS_DIR}"/*.svg 2>/dev/null | wc -l)

if [ "${STIX_ICON_COUNT}" -ge 27 ]; then
    ok "STIX icons present (${STIX_ICON_COUNT} SVG files in ${STIX_ICONS_DIR}/)"
else
    warn "STIX icon SVGs not found in ${STIX_ICONS_DIR}/ (found ${STIX_ICON_COUNT}/27)"
    echo ""
    echo "  The graph view uses the official OASIS STIX 2.1 White/normal/SVG icons."
    echo "  They are bundled in the repo — if this is a fresh clone, run:"
    echo -e "     ${CYAN}git lfs pull${NC}   (if the repo uses Git LFS)"
    echo "  Or download and extract manually:"
    echo -e "     ${CYAN}curl -sL https://github.com/oasis-open/cti-stix-visualization/archive/refs/heads/master.tar.gz \\${NC}"
    echo -e "     ${CYAN}  | tar xz --strip=4 -C ${STIX_ICONS_DIR}/ \\${NC}"
    echo -e "     ${CYAN}  'cti-stix-visualization-master/public/stix-icons/White/normal/SVG'${NC}"
    echo ""
    echo -e "  ${YELLOW}Attempt automatic download now? [Y/n]${NC}"
    read -r -p "  > " DOWNLOAD_ICONS
    DOWNLOAD_ICONS="${DOWNLOAD_ICONS:-Y}"

    if [[ "$DOWNLOAD_ICONS" =~ ^[Yy] ]]; then
        mkdir -p "${STIX_ICONS_DIR}"
        TAR_URL="https://github.com/oasis-open/cti-stix-visualization/archive/refs/heads/master.tar.gz"
        info "Downloading STIX icon set from oasis-open/cti-stix-visualization…"
        if curl -fsSL --retry 3 --retry-delay 2 "$TAR_URL" \
             | tar xz --strip=4 -C "${STIX_ICONS_DIR}/" \
               'cti-stix-visualization-master/public/stix-icons/White/normal/SVG' 2>/dev/null; then
            STIX_ICON_COUNT=$(ls "${STIX_ICONS_DIR}"/*.svg 2>/dev/null | wc -l)
            ok "Downloaded ${STIX_ICON_COUNT} STIX icons → ${STIX_ICONS_DIR}/"
        else
            warn "Automatic download failed — graph nodes will show letter glyphs."
            echo "  Extract the White/normal/SVG files manually to ${STIX_ICONS_DIR}/"
        fi
    else
        warn "Skipping icon download — graph nodes will show letter glyphs instead of STIX logos."
    fi
fi

# =============================================================================
# FRONTEND BUILD
# =============================================================================
if [ "$NODE_OK" = true ]; then
    echo ""
    hdr "FRONTEND BUILD"
    info "Installing npm dependencies (including react-markdown for .md preview)…"
    cd frontend && npm install --silent && cd ..
    ok "npm packages installed"
    info "Building frontend…"
    cd frontend && npm run build && cd ..
    ok "Frontend built → dist/"
fi

# =============================================================================
# SUMMARY
# =============================================================================
echo ""
sep
echo -e "${CYAN}   SETUP COMPLETE${NC}"
sep
echo ""

[ "$IS_WSL" = true ] \
    && echo -e "  ${MAGENTA}Environment : ${WSL_VERSION}${DISTRO_NAME:+ — ${DISTRO_NAME}}${NC}" \
    || echo -e "  ${GREEN}Environment : Native Linux${DISTRO_NAME:+ — ${DISTRO_NAME}}${NC}"

echo ""
echo "  Pipeline stages enabled:"
echo ""

_check_file() { [ -f "$1" ] && echo -e "    ${GREEN}✔${NC} $2" || echo -e "    ${YELLOW}–${NC} $2 (needs data files)"; }
_check_mod()  { python -c "import $1" 2>/dev/null \
    && echo -e "    ${GREEN}✔${NC} $2" || echo -e "    ${YELLOW}–${NC} $2 (install: pip install $1)"; }

echo -e "    ${GREEN}✔${NC}  Stage 1   — Document ingestion (PDF, DOCX, HTML, TXT, MD)"
echo -e "    ${GREEN}✔${NC}  Ingest    — File upload + pasted text (ADR-0029)"
if [ "$CAPTURE_READY" = true ]; then
    echo -e "    ${GREEN}✔${NC}  Ingest    — URL capture (Chromium renders the page, sandboxed)"
elif [ "$OPT_NO_CAPTURE" = true ]; then
    echo -e "    ${YELLOW}–${NC}  Ingest    — URL capture skipped (--no-capture); the URL tab returns 503"
else
    echo -e "    ${YELLOW}–${NC}  Ingest    — URL capture NOT ready; the URL tab returns 503 (see step 8)"
fi
echo -e "    ${GREEN}✔${NC}  Stage 2   — Regex IoC extraction (IP, hash, domain, CVE, registry, MAC…)"
_check_file "pipeline/data/gazetteer.json"         "Stage 2b  — Gazetteer NER (1,792 named entities, Aho-Corasick)"
_check_mod  "sentence_transformers"                "Stage 2c  — Semantic TTP detection (all-MiniLM-L6-v2)"
_check_mod  "transformers"                         "Stage 2d  — CyNER 2.0 (DeBERTa-v3 cybersecurity NER)"
_check_mod  "gliner"                               "Stage 2e  — GLiNER zero-shot NER (sectors, campaigns, infra)"
echo -e "    ${GREEN}✔${NC}  Stage 3   — LLM enrichment (relationships, campaign, novel entities)"
echo -e "    ${GREEN}✔${NC}  Stage 3b  — Hallucination filter (fuzzy text verification)"
_check_file "pipeline/data/mitre_index.json"       "Stage 3c  — MITRE TTP normalization (fuzzy ID correction)"
echo -e "    ${GREEN}✔${NC}  Stage 3d  — Self-verification of relationship claims"
echo -e "    ${GREEN}✔${NC}  Stage 4   — STIX 2.1 bundle generation"
echo -e "    ${GREEN}✔${NC}  Stage 5   — STIX validation + export"

# The detection store is optional and built separately, so report what is
# actually in it rather than assuming the corpora step ran.
python - <<'PYEOF' 2>/dev/null || echo -e "    ${YELLOW}–${NC}  Detection coverage — rule store not built yet (see step 6)"
import sqlite3, sys
GREEN, YELLOW, NC = "\033[0;32m", "\033[1;33m", "\033[0m"
try:
    c = sqlite3.connect("file:cti_stix.db?mode=ro", uri=True)
    names = {r[0] for r in c.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    if "detection_rules" not in names:
        raise SystemExit(1)
    n = c.execute("SELECT COUNT(*) FROM detection_rules").fetchone()[0]
    if not n:
        raise SystemExit(1)
    fmts = ", ".join(
        f"{f or 'sigma'} {k}" for f, k in
        c.execute("SELECT format, COUNT(*) FROM detection_rules GROUP BY format ORDER BY 2 DESC")
    )
    atoms = c.execute("SELECT COUNT(DISTINCT rule_id) FROM rule_atoms").fetchone()[0] \
        if "rule_atoms" in names else 0
    print(f"    {GREEN}\u2714{NC}  Detection coverage — {n:,} rules ({fmts})")
    print(f"    {GREEN}\u2714{NC}  Rule proposals    — atoms indexed for {atoms:,} rules")
except SystemExit:
    raise
except Exception:
    raise SystemExit(1)
PYEOF
echo ""

echo "  Next steps:"
echo ""
echo -e "  ${YELLOW}1.${NC}  Set your LLM API key:"
echo      "       nano .env"
echo      "       # ANTHROPIC_API_KEY=sk-ant-..."
echo ""
echo -e "  ${YELLOW}2.${NC}  Activate the venv (every new terminal):"
echo      "       source .venv/bin/activate"
echo ""
echo -e "  ${YELLOW}3.${NC}  Run tests (no API key needed):"
echo      "       pytest tests/ -v -k 'not llm'"
echo ""
echo -e "  ${YELLOW}4.${NC}  Run on a sample report:"
echo      "       python main.py tests/fixtures/sample_report.txt"
echo ""
echo -e "  ${YELLOW}5.${NC}  Launch the web UI  ${YELLOW}(not as root)${NC}:"
echo      "       Chromium will not render URLs as root with its sandbox on,"
echo      "       so /api/ingest/url returns 503. Leave any sudo shell first."
if [ "$NODE_OK" = true ]; then
    echo "       uvicorn api.main:app --reload --app-dir ."
    if [ "$IS_WSL" = true ] && [ "$WSL_VERSION" = "WSL2" ]; then
        echo -e "       ${GREEN}→ http://localhost:8000${NC}  (open in your Windows browser)"
    else
        echo -e "       ${GREEN}→ http://localhost:8000${NC}"
    fi
else
    echo "       Install Node.js first (see step [1b] above), then:"
    echo "       cd frontend && npm install && npm run build && cd .."
    echo "       uvicorn api.main:app --reload --app-dir ."
fi
echo ""
echo -e "  ${YELLOW}6.${NC}  Rebuild MITRE indexes (after updating bundle files):"
echo -e "       ${CYAN}python scripts/build_indexes.py${NC}"
echo ""
echo -e "  ${YELLOW}7.${NC}  Detection coverage (if you skipped the corpora step):"
echo -e "       ${CYAN}python scripts/sync_corpora.py && python scripts/build_detection_index.py${NC}"
echo      "       Then open /coverage/<job-id> to select and export rules."
echo ""
if [ "$CAPTURE_READY" != true ] && [ "$OPT_NO_CAPTURE" != true ]; then
echo -e "  ${YELLOW}8.${NC}  Finish web capture (the URL tab needs root once):"
echo -e "       ${CYAN}sudo .venv/bin/python -m playwright install-deps chromium${NC}"
echo      "       Chromium is installed but cannot start without those libraries;"
echo      "       it fails with 'error while loading shared libraries: libasound.so.2'."
echo      "       Until then use the File or Paste tab — both work."
echo ""
fi
sep
