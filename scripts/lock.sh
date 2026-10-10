#!/bin/sh
# `make lock`: resolve the requirement ranges into five hashed locks (ADR-0080),
# all in requirements/:
#
#   requirements.lock.txt        every package the image installs, from PyPI
#   requirements-torch.lock.txt  torch's CPU build, from the PyTorch index
#   requirements-ci.lock.txt     what CI's fast tests install, same versions
#   requirements-audit.lock.txt  pip-audit, for the dependency-audit job
#   requirements-uv.lock.txt     uv, which this script runs
#
# Installed with `pip install --require-hashes` everywhere: a file whose sha256
# differs from the one recorded here fails the install.  torch is installed
# apart, first, from the PyTorch index only (`--no-deps`), and everything else
# from PyPI only.  The PyTorch index also re-hosts common packages, and its
# copies are not PyPI's files: markupsafe 3.0.3 there has another sha256.  A
# lock that names both indexes let pip take either.
#
# Run inside python:3.14-slim by `make lock`, from the repository root; it
# works in requirements/, where the files are.  UV may point at an existing uv.
# LOCK_FLAGS=--upgrade re-resolves everything to the newest allowed versions,
# uv included: the uv this run installs is the one the previous run locked.
set -eu
cd "$(dirname "$0")/../requirements"
HASHES="python3 ../scripts/lock_pypi_hashes.py"

TORCH_INDEX="https://download.pytorch.org/whl/cpu"
if [ -z "${UV:-}" ]; then
    pip install --quiet --require-hashes --no-deps --target /tmp/uv -r requirements-uv.lock.txt
    UV=/tmp/uv/bin/uv
fi
common() {
    "$UV" pip compile --universal --python-version 3.14 --generate-hashes \
        --annotation-style line --custom-compile-command "make lock" ${LOCK_FLAGS:-} "$@"
}

# diskcache is left out of every lock, and every install is `--no-deps`, so pip
# does not pull it back in.  pySigma declares it, but only its ATT&CK and D3FEND
# data cache imports it (sigma/data/mitre_attack.py, mitre_d3fend.py), which
# CTIParsor never loads; and it has an unfixed pickle-deserialisation CVE
# (PYSEC-2026-2447).  tests/test_pattern_check.py checks the Sigma gate works
# without it and never loads it.
NOT_SHIPPED="--no-emit-package diskcache"

# The resolution needs the PyTorch index to pick torch's +cpu build (no CUDA);
# the lock names no index, so pip installs everything in it from PyPI, and its
# hashes are then rewritten to PyPI's files (scripts/lock_pypi_hashes.py).
common requirements-full.txt \
    --extra-index-url "$TORCH_INDEX" --index-strategy unsafe-best-match \
    $NOT_SHIPPED -o requirements.lock.txt
$HASHES requirements.lock.txt

TORCH="$(sed -n 's/^torch==\([^ ;]*+cpu\).*/\1/p' requirements.lock.txt)"
[ -n "$TORCH" ] || { echo "no torch +cpu pin in requirements.lock.txt" >&2; exit 1; }
printf "torch==%s ; sys_platform != 'darwin'\n" "$TORCH" > /tmp/torch.in
common /tmp/torch.in --index-url "$TORCH_INDEX" --no-deps -o requirements-torch.lock.txt

# CI's fast tests: the light runtime and the dev tools, at the image's versions.
common requirements.txt requirements-dev.txt -c requirements.lock.txt $NOT_SHIPPED -o requirements-ci.lock.txt
common requirements-audit.txt -o requirements-audit.lock.txt
printf "uv\n" > /tmp/uv.in
common /tmp/uv.in -o requirements-uv.lock.txt
$HASHES requirements-ci.lock.txt requirements-audit.lock.txt requirements-uv.lock.txt

for f in requirements.lock.txt requirements-torch.lock.txt requirements-ci.lock.txt requirements-audit.lock.txt requirements-uv.lock.txt; do
    echo "Locked $(grep -c '==' "$f") packages -> $f"
done
