#!/usr/bin/env bash
# =============================================================================
# scripts/check_offline_bundle.sh — replay an air-gap install from a bundle in
# an isolated HOME with no network and no root, then verify it (ADR-0040).
#
# What is real: the venv, every pip install (from the wheelhouse), the model
# loads, build_indexes.py, build_detection_index.py, the Chromium launch, the
# Ollama runtime extraction and model registration.  What is stubbed unless
# --real-root: `sudo` (runs the command as you, with /usr/local redirected to a
# scratch prefix) and `dpkg -i` (logged, not executed).  Network is cut by
# pointing every proxy variable at a closed local port.
# =============================================================================
set -u
GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; CYAN='\033[0;36m'; NC='\033[0m'
pass() { echo -e "  ${GREEN}PASS${NC}  $*"; }
fail() { echo -e "  ${RED}FAIL${NC}  $*"; FAILS=$((FAILS + 1)); }
info() { echo -e "  ${CYAN}→${NC}  $*"; }
FAILS=0

usage() {
    cat >&2 <<EOF
Usage: bash scripts/check_offline_bundle.sh <bundle.tar> [--work DIR] [--real-root] [--no-llm-smoke]
EOF
    exit 2
}

parse_args() {
    TARBALL=""
    WORK="${CHECK_OFFLINE_DIR:-$HOME/.cache/ctiparsor-offline-check}"
    REAL_ROOT=0
    NO_LLM_SMOKE=0
    while [ $# -gt 0 ]; do
        case "$1" in
            --work)
                [ $# -lt 2 ] && usage
                WORK="$2"
                shift 2
                ;;
            --real-root)
                REAL_ROOT=1
                shift
                ;;
            --no-llm-smoke)
                NO_LLM_SMOKE=1
                shift
                ;;
            -h|--help)
                usage
                ;;
            -*)
                usage
                ;;
            *)
                if [ -z "$TARBALL" ]; then
                    TARBALL="$1"
                else
                    usage
                fi
                shift
                ;;
        esac
    done
    if [ -z "$TARBALL" ]; then
        usage
    fi
    if [ ! -f "$TARBALL" ]; then
        echo "error: bundle not found: $TARBALL" >&2
        usage
    fi
}

prepare_work() {
    info "Preparing isolated work dir: $WORK"
    rm -rf "$WORK"
    mkdir -p "$WORK/home" "$WORK/bin" "$WORK/prefix/usr/local"
    if ! tar -xf "$TARBALL" -C "$WORK"; then
        echo "error: failed to extract $TARBALL" >&2
        exit 1
    fi
    SRC="$WORK/cti-parsor"
    if [ ! -f "$SRC/setup.sh" ] || [ ! -f "$SRC/offline/bundle.env" ]; then
        echo "error: bundle is missing setup.sh or offline/bundle.env" >&2
        exit 1
    fi
    # shellcheck disable=SC1091
    source "$SRC/offline/bundle.env"
    BUNDLE_OLLAMA_MODEL="${BUNDLE_OLLAMA_MODEL:-}"
    BUNDLE_OLLAMA_ASSET="${BUNDLE_OLLAMA_ASSET:-}"
    info "Bundle model: ${BUNDLE_OLLAMA_MODEL:-<none>}  asset: ${BUNDLE_OLLAMA_ASSET:-<none>}"
}

install_stubs() {
    if [ "$REAL_ROOT" -eq 1 ]; then
        info "Skipping stubs (--real-root)"
        return 0
    fi
    FAKE_PREFIX="$WORK/prefix"
    CHECK_DPKG_LOG="$WORK/dpkg.log"
    export FAKE_PREFIX CHECK_DPKG_LOG

    cat > "$WORK/bin/sudo" <<'STUB'
#!/usr/bin/env bash
# Stub: run as the current user; -E/-n dropped; `sudo -n true` → 0;
# any argument that is exactly /usr/local is redirected to $FAKE_PREFIX/usr/local.
while [ $# -gt 0 ] && [ "${1#-}" != "$1" ]; do shift; done
[ "${1:-}" = "true" ] && exit 0
args=()
for a in "$@"; do
    [ "$a" = "/usr/local" ] && a="$FAKE_PREFIX/usr/local"
    args+=("$a")
done
exec "${args[@]}"
STUB

    cat > "$WORK/bin/dpkg" <<'STUB'
#!/usr/bin/env bash
# Stub: -i and --configure are logged, everything else goes to the real dpkg.
case "${1:-}" in
    -i) shift; printf '%s\n' "$@" >> "$CHECK_DPKG_LOG"; exit 0 ;;
    --configure) exit 0 ;;
    *) exec /usr/bin/dpkg "$@" ;;
esac
STUB

    chmod +x "$WORK/bin/sudo" "$WORK/bin/dpkg"

    if ! command -v unzstd >/dev/null 2>&1; then
        if python3 -c "import compression.zstd" >/dev/null 2>&1; then
            cat > "$WORK/bin/unzstd" <<'STUB'
#!/usr/bin/env python3
# Shim: decompress stdin -> stdout in 1 MiB blocks, ignoring arguments.
import sys
from compression.zstd import ZstdDecompressor

CHUNK = 1 << 20
d = ZstdDecompressor()
out = sys.stdout.buffer
while True:
    chunk = sys.stdin.buffer.read(CHUNK)
    if not chunk:
        break
    out.write(d.decompress(chunk))
out.flush()
STUB
            chmod +x "$WORK/bin/unzstd"
        else
            info "no zstd available — the Ollama extraction step will be reported by setup.sh as skipped"
        fi
    fi
}

run_install() {
    info "Running setup.sh --offline=offline (no network, HOME=$WORK/home)…"
    START=$(date +%s)
    if [ "$REAL_ROOT" -eq 1 ]; then
        ( cd "$SRC" && env HOME="$WORK/home" PATH="$PATH" \
              http_proxy=http://127.0.0.1:9 https_proxy=http://127.0.0.1:9 \
              HTTP_PROXY=http://127.0.0.1:9 HTTPS_PROXY=http://127.0.0.1:9 \
              no_proxy=localhost,127.0.0.1 NO_PROXY=localhost,127.0.0.1 \
              PIP_NO_INDEX=1 \
              bash setup.sh --offline=offline < /dev/null ) > "$WORK/setup.log" 2>&1
    else
        ( cd "$SRC" && env HOME="$WORK/home" PATH="$WORK/bin:$PATH" \
              http_proxy=http://127.0.0.1:9 https_proxy=http://127.0.0.1:9 \
              HTTP_PROXY=http://127.0.0.1:9 HTTPS_PROXY=http://127.0.0.1:9 \
              no_proxy=localhost,127.0.0.1 NO_PROXY=localhost,127.0.0.1 \
              PIP_NO_INDEX=1 FAKE_PREFIX="$FAKE_PREFIX" CHECK_DPKG_LOG="$CHECK_DPKG_LOG" \
              bash setup.sh --offline=offline < /dev/null ) > "$WORK/setup.log" 2>&1
    fi
    RC=$?
    ELAPSED=$(( $(date +%s) - START ))
}

verify() {
    PY="$SRC/.venv/bin/python"

    # 1. setup.sh exit code
    if [ "$RC" -eq 0 ]; then
        pass "setup.sh exited 0 in ${ELAPSED}s"
    else
        fail "setup.sh exited $RC in ${ELAPSED}s"
        tail -n 40 "$WORK/setup.log" 2>/dev/null || true
    fi

    # 2. bundle checksums
    if grep -q 'bundle .* built ' "$WORK/setup.log" 2>/dev/null; then
        pass "bundle validated (checksums)"
    else
        fail "bundle validated (checksums)"
    fi

    # 3. dpkg -i count (stubs only)
    if [ "$REAL_ROOT" -eq 0 ]; then
        if [ -f "$CHECK_DPKG_LOG" ]; then
            N=$(wc -l < "$CHECK_DPKG_LOG")
            if [ "$N" -ge 400 ]; then
                pass "dpkg -i received $N .deb"
            else
                fail "dpkg -i received $N .deb (expected >= 400)"
            fi
        else
            fail "dpkg -i received 0 .deb (log missing)"
        fi
    fi

    # 4. venv
    if [ -x "$PY" ]; then
        pass "venv created"
    else
        fail "venv created"
    fi

    # 5. core imports
    if "$PY" -c "import torch, transformers, sentence_transformers, gliner, fastapi, uvicorn, playwright, stix2, yaml" 2>/dev/null; then
        pass "core, ML, API and capture packages import"
    else
        fail "core, ML, API and capture packages import"
    fi

    # 6. no wheel downloads
    DL=$(grep -c 'Downloading .*\.whl' "$WORK/setup.log" 2>/dev/null)
    if [ "${DL:-0}" -eq 0 ]; then
        pass "pip never left the wheelhouse"
    else
        fail "pip never left the wheelhouse ($DL downloads)"
    fi

    # 7. no network errors
    if ! grep -qiE 'proxyerror|connection refused|could not fetch|failed to establish|max retries exceeded' "$WORK/setup.log" 2>/dev/null; then
        pass "no network call in the log"
    else
        fail "no network call in the log"
    fi

    # 8. MITRE indexes
    if [ -f "$SRC/pipeline/data/mitre_index.json" ] && [ -f "$SRC/pipeline/data/gazetteer.json" ] && [ -f "$SRC/pipeline/data/mitre_embeddings.npy" ]; then
        pass "MITRE indexes built offline (embeddings from the staged model)"
    else
        fail "MITRE indexes built offline (embeddings from the staged model)"
    fi

    # 9. rule store (the DB path travels as argv: a quoted heredoc does not expand $SRC)
    STORE=$("$PY" - "$SRC/cti_stix.db" <<'PYEOF' 2>&1
import sqlite3, sys
try:
    con = sqlite3.connect(f"file:{sys.argv[1]}?mode=ro", uri=True)
    rows = con.execute("SELECT format, COUNT(*) FROM detection_rules GROUP BY format ORDER BY 2 DESC").fetchall()
    total = sum(r[1] for r in rows)
    detail = ", ".join(f"{f} {n:,}" for f, n in rows)
    ok = total >= 80000 and len(rows) >= 3
    print(f"{total:,} rules ({detail})")
    sys.exit(0 if ok else 1)
except Exception as e:
    print(f"error: {e}")
    sys.exit(1)
PYEOF
    )
    if [ $? -eq 0 ]; then
        pass "rule store built: $STORE"
    else
        fail "rule store built: $STORE"
    fi

    # 10. web UI
    if [ -f "$SRC/frontend/dist/index.html" ]; then
        pass "web UI staged"
    else
        fail "web UI staged"
    fi

    # 11. HF offline
    if grep -q '^HF_HUB_OFFLINE=1' "$SRC/.env" 2>/dev/null; then
        pass ".env has HF_HUB_OFFLINE=1"
    else
        fail ".env has HF_HUB_OFFLINE=1"
    fi

    # 12. LLM provider
    if [ -n "$BUNDLE_OLLAMA_MODEL" ]; then
        if grep -q '^LLM_PROVIDER=ollama' "$SRC/.env" 2>/dev/null; then
            pass ".env points at the bundled LLM"
        else
            fail ".env points at the bundled LLM"
        fi
    fi

    # 13. HF models
    HF_COUNT=$(ls -d "$WORK/home/.cache/huggingface/hub"/models--* 2>/dev/null | wc -l)
    if [ "$HF_COUNT" -ge 3 ]; then
        pass "3 HF models staged ($HF_COUNT)"
    else
        fail "3 HF models staged ($HF_COUNT)"
    fi

    # 14. Chromium
    CH_COUNT=$(ls -d "$WORK/home/.cache/ms-playwright"/chromium* 2>/dev/null | wc -l)
    if [ "$CH_COUNT" -ge 1 ]; then
        pass "Chromium staged"
    else
        fail "Chromium staged"
    fi

    # 15. Chromium launches
    if grep -q 'Chromium launches' "$WORK/setup.log" 2>/dev/null; then
        pass "Chromium launches"
    else
        fail "Chromium launches"
    fi

    # 16. Ollama runtime
    OLLAMA_BIN=""
    if [ -n "$BUNDLE_OLLAMA_ASSET" ] && [ "$REAL_ROOT" -eq 0 ]; then
        OLLAMA_BIN=$(find "$FAKE_PREFIX" -type f -name ollama 2>/dev/null | head -1)
        if [ -n "$OLLAMA_BIN" ]; then
            pass "Ollama runtime extracted"
        else
            fail "Ollama runtime extracted"
        fi
        if [ -d "$WORK/home/.ollama/models/manifests" ]; then
            pass "Ollama model files staged"
        else
            fail "Ollama model files staged"
        fi
    fi

    # 17. LLM smoke
    if [ -n "$OLLAMA_BIN" ] && [ "$NO_LLM_SMOKE" -eq 0 ]; then
        OLLAMA_MODELS="$WORK/home/.ollama/models" OLLAMA_HOST=127.0.0.1:11436 "$OLLAMA_BIN" serve > "$WORK/ollama.log" 2>&1 &
        OLLAMA_PID=$!
        OK=0
        for i in $(seq 1 30); do
            if curl -fs http://127.0.0.1:11436/api/tags 2>/dev/null | grep -q "\"${BUNDLE_OLLAMA_MODEL%%:*}"; then
                OK=1
                break
            fi
            sleep 1
        done
        if [ "$OK" -eq 1 ]; then
            pass "Ollama serves ${BUNDLE_OLLAMA_MODEL} from the staged files"
        else
            fail "Ollama serves ${BUNDLE_OLLAMA_MODEL} from the staged files"
        fi
        kill "$OLLAMA_PID" 2>/dev/null || true
        wait "$OLLAMA_PID" 2>/dev/null || true
    fi
}

main() {
    parse_args "$@"
    prepare_work
    install_stubs
    run_install
    verify
    echo ""
    echo "SUMMARY: $FAILS failures — log: $WORK/setup.log — work dir kept: $WORK (rm -rf it when done)"
    if [ "$FAILS" -gt 0 ]; then
        exit 1
    fi
    exit 0
}

main "$@"
