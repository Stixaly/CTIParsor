#!/usr/bin/env bash
# =============================================================================
# CTIParsor — Environment preparation
#
# Docker is the only supported way to install, develop and run CTIParsor
# (ADR-0054). This script does not build, download or start anything — it
# prepares the files Docker Compose needs (.env, the DB-password secret) and
# checks Docker itself is present, then prints the next commands for you to
# run. Everything else (Python/Node dependencies, NLP models, MITRE data,
# detection corpora, the frontend build) happens inside containers:
#
#   docker compose build                                   # the image
#   docker compose up -d                                   # app + worker + postgres
#   docker compose --profile bootstrap run --rm bootstrap   # models, corpora, rule store
#
# Usage:
#   bash setup.sh                    # prepare .env + secrets, check Docker
#   bash setup.sh --offline=DIR      # air-gapped install from a bundle built
#                                     # by scripts/package_offline_docker.sh
#                                     # (ADR-0054, supersedes ADR-0040)
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

# Ask a yes/no question, falling back to *default* when there is no terminal.
#
# `read` returns non-zero at EOF, and with `set -e` that kills the whole script
# mid-run -- everything after the prompt silently never happens. Worse, when
# setup.sh is itself piped into bash, `read` consumes the script's NEXT LINE as
# the answer, so the reply becomes a stray line of shell and the step is
# skipped. Both failures are silent, which is how a fresh install used to end
# up with no detection corpora.
ask() {
    local __var="$1" __default="$2" __reply=""
    if [ -t 0 ]; then
        read -r -p "  > " __reply || __reply=""
    else
        echo "  >  (no terminal — using the default: ${__default})"
    fi
    printf -v "$__var" '%s' "${__reply:-$__default}"
}

# ── Flags ───────────────────────────────────────────────────────────────────
OFFLINE_DIR=""
for arg in "$@"; do
  case $arg in
    --offline=*)  OFFLINE_DIR="${arg#--offline=}" ;;
    *)
        err "Unknown option: $arg"
        echo "  See the usage comment at the top of this script."
        exit 2
        ;;
  esac
done

echo ""
sep
echo -e "${CYAN}   CTIParsor — Environment Preparation${NC}"
sep
echo ""

# ── Environment detection ───────────────────────────────────────────────────
# Still relevant in a Docker-only world: Docker Desktop's WSL2 backend reads
# the build context (this repo) from wherever it sits, and a repo on the
# Windows-side filesystem pays the same /mnt/ 9p-bridge tax for the build
# context upload that ADR-0037 measured for SQLite page faults — not fatal
# (it's a one-time, cached build), but worth flagging.
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
        echo "     The Docker build context upload is slower from /mnt/. For best"
        echo "     speed (and for 'docker compose run --rm dev ...' live-editing),"
        echo "     copy the repo to the Linux filesystem:"
        echo -e "     ${CYAN}cp -r . ~/ctiparsor && cd ~/ctiparsor${NC}"
    else
        ok "Project on Linux filesystem — optimal performance."
    fi
    [ "$WSL_VERSION" = "WSL1" ] && warn "WSL1 detected — Docker Desktop needs WSL2."
else
    echo -e "  ${GREEN}🐧  Native Linux${NC}${DISTRO_NAME:+ — ${DISTRO_NAME}}"
fi
echo ""

# =============================================================================
# [1/3]  DOCKER
# =============================================================================
hdr "[1/3]  DOCKER"

DOCKER_OK=true
if ! command -v docker >/dev/null 2>&1; then
    err "docker is not on PATH."
    echo "     Install Docker Desktop (Windows/Mac) or docker-ce (Linux):"
    echo -e "     ${CYAN}https://docs.docker.com/engine/install/${NC}"
    DOCKER_OK=false
elif ! docker info >/dev/null 2>&1; then
    err "docker is installed but the daemon is not reachable."
    echo "     Start Docker Desktop, or on Linux: sudo systemctl start docker"
    echo "     (and make sure your user is in the 'docker' group, or run with sudo)"
    DOCKER_OK=false
else
    ok "docker: $(docker --version)"
fi

COMPOSE_CMD=""
if [ "$DOCKER_OK" = true ]; then
    if docker compose version >/dev/null 2>&1; then
        COMPOSE_CMD="docker compose"
        ok "docker compose: $(docker compose version --short 2>/dev/null || echo 'plugin present')"
    elif command -v docker-compose >/dev/null 2>&1; then
        COMPOSE_CMD="docker-compose"
        warn "Using the standalone docker-compose v1 binary — the 'docker compose'"
        echo "     plugin (v2) is what this repo's docs assume; consider upgrading."
    else
        err "Neither 'docker compose' (plugin) nor 'docker-compose' (standalone) found."
        DOCKER_OK=false
    fi
fi

if [ "$DOCKER_OK" != true ]; then
    echo ""
    err "Docker is required — CTIParsor no longer supports a host (venv) install."
    echo "     See docs/docker.md, then re-run this script."
    exit 1
fi

# =============================================================================
# [2/3]  .env
# =============================================================================
echo ""
hdr "[2/3]  .env"

ENV_CREATED=false
if [ ! -f ".env" ]; then
    ENV_CREATED=true
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
    echo -e "     ${YELLOW}LLM_PROVIDER=ollama${NC}            ← or local Ollama (docker compose --profile ollama up -d)"
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

# CTI_DB_PASSWORD, required by compose (compose.yaml's postgres service and
# every service that talks to it). Generate one if .env doesn't have it yet.
if grep -qE '^CTI_DB_PASSWORD=' .env 2>/dev/null && \
   [ -n "$(grep -E '^CTI_DB_PASSWORD=' .env | tail -1 | cut -d'=' -f2-)" ]; then
    ok "CTI_DB_PASSWORD already set in .env"
else
    GENERATED_PW=$(openssl rand -hex 24 2>/dev/null || head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')
    if grep -qE '^CTI_DB_PASSWORD=' .env 2>/dev/null; then
        sed -i "s/^CTI_DB_PASSWORD=.*/CTI_DB_PASSWORD=${GENERATED_PW}/" .env
    else
        printf '\nCTI_DB_PASSWORD=%s\n' "$GENERATED_PW" >> .env
    fi
    ok "CTI_DB_PASSWORD generated and written to .env"
fi

# =============================================================================
# [3/3]  DB PASSWORD SECRET
# =============================================================================
# Materializes CTI_DB_PASSWORD into .secrets/db_password, which compose.yaml
# bind-mounts into every service at /run/secrets/db_password (Docker secrets
# syntax refuses to attach to a read_only:true service via an environment-
# sourced value — see the comment on x-app-image in compose.yaml). Mirrors
# the Makefile's .secrets/db_password target so `make docker-up` and this
# script agree; re-run this script whenever CTI_DB_PASSWORD in .env changes.
echo ""
hdr "[3/3]  DB PASSWORD SECRET"

CTI_DB_PASSWORD_VALUE=$(grep -E '^CTI_DB_PASSWORD=' .env | tail -1 | cut -d'=' -f2-)
mkdir -p .secrets
printf '%s' "$CTI_DB_PASSWORD_VALUE" > .secrets/db_password
chmod 644 .secrets/db_password
ok ".secrets/db_password written"

# =============================================================================
# AIR-GAP RESTORE (--offline=DIR only, ADR-0054)
# =============================================================================
# A bundle built by scripts/package_offline_docker.sh on a connected machine:
# a saved image tarball plus a populated-volume/pg_dump export of everything
# `bootstrap` would otherwise fetch over the network. Loading it here replaces
# the bootstrap step entirely -- see the printed summary at the end.
if [ -n "$OFFLINE_DIR" ]; then
    echo ""
    hdr "AIR-GAP RESTORE — $OFFLINE_DIR"

    # shellcheck source=scripts/offline_lib_docker.sh
    source scripts/offline_lib_docker.sh

    offline_validate_bundle "$OFFLINE_DIR"
    offline_docker_load_images "$OFFLINE_DIR"
    offline_docker_restore_volume "$OFFLINE_DIR" ctiparsor_cti-cache cti-cache.tar.gz
    if [ -n "${BUNDLE_OLLAMA_MODEL:-}" ]; then
        offline_docker_restore_volume "$OFFLINE_DIR" ctiparsor_ollama-models ollama-models.tar.gz
    fi

    info "Starting postgres to restore the database…"
    $COMPOSE_CMD up -d postgres
    offline_wait_postgres_healthy 90 || {
        err "postgres did not become healthy — check: $COMPOSE_CMD logs postgres"
        exit 1
    }
    offline_docker_restore_pg_dump "$OFFLINE_DIR"
    offline_write_env_hints "$ENV_CREATED"

    echo ""
    sep
    echo -e "${CYAN}   AIR-GAP INSTALL READY${NC}"
    sep
    offline_summary
    echo ""
    exit 0
fi

# =============================================================================
# SUMMARY
# =============================================================================
echo ""
sep
echo -e "${CYAN}   ENVIRONMENT READY${NC}"
sep
echo ""
echo "  Next steps:"
echo ""
echo -e "  ${YELLOW}1.${NC}  Build the image (first time, or after a code change):"
echo -e "       ${CYAN}docker compose build${NC}          (or: make docker-build)"
echo ""
echo -e "  ${YELLOW}2.${NC}  Start the stack (API + worker + PostgreSQL):"
echo -e "       ${CYAN}docker compose up -d${NC}          (or: make docker-up)"
echo -e "       → http://127.0.0.1:8000"
echo ""
echo -e "  ${YELLOW}3.${NC}  One-time: NLP models, detection corpora, rule store (10-20 min):"
echo -e "       ${CYAN}docker compose --profile bootstrap run --rm bootstrap${NC}"
echo -e "       (or: make docker-bootstrap)"
echo ""
echo -e "  ${YELLOW}4.${NC}  Run the test suite (no host Python needed):"
echo -e "       ${CYAN}docker compose run --rm dev pytest tests/ -v${NC}"
echo -e "       (or: make docker-test)"
echo ""
echo -e "  ${YELLOW}5.${NC}  Process a report from the CLI (drop files into input/ first):"
echo -e "       ${CYAN}make run-dir${NC}                  (or: make run — the bundled sample report)"
echo ""
echo -e "  ${YELLOW}6.${NC}  Frontend hot-reload (UI development):"
echo -e "       ${CYAN}docker compose --profile dev up frontend-dev${NC}  → http://localhost:5173"
echo ""
echo "  Full guide: docs/docker.md — architecture: docs/architecture.md"
echo ""
