#!/bin/sh
# `make lock`: resolve the requirement ranges into four hashed locks (ADR-0080).
#
#   requirements.lock.txt        every package the image installs, from PyPI
#   requirements-torch.lock.txt  torch's CPU build, from the PyTorch index
#   requirements-ci.lock.txt     what CI's fast tests install, same versions
#   requirements-audit.lock.txt  pip-audit, for the dependency-audit job
#
# Installed with `pip install --require-hashes` everywhere: a file whose sha256
# differs from the one recorded here fails the install.  torch is installed
# apart, first, from the PyTorch index only (`--no-deps`), and everything else
# from PyPI only.  The PyTorch index also re-hosts common packages, and its
# copies are not PyPI's files: markupsafe 3.0.3 there has another sha256.  A
# lock that names both indexes let pip take either.
#
# Run inside python:3.14-slim by `make lock`; UV may point at an existing uv.
# LOCK_FLAGS=--upgrade re-resolves everything to the newest allowed versions.
set -eu

TORCH_INDEX="https://download.pytorch.org/whl/cpu"
if [ -z "${UV:-}" ]; then
    pip install --quiet --target /tmp/uv uv
    UV=/tmp/uv/bin/uv
fi
common() {
    "$UV" pip compile --universal --python-version 3.14 --generate-hashes \
        --annotation-style line --custom-compile-command "make lock" ${LOCK_FLAGS:-} "$@"
}

# The resolution needs the PyTorch index to pick torch's +cpu build (no CUDA);
# the lock names no index, so pip installs everything in it from PyPI, and its
# hashes are then rewritten to PyPI's files (scripts/lock_pypi_hashes.py).
common requirements.txt requirements-api.txt requirements-optional.txt \
    --extra-index-url "$TORCH_INDEX" --index-strategy unsafe-best-match \
    -o requirements.lock.txt
python3 scripts/lock_pypi_hashes.py requirements.lock.txt

TORCH="$(sed -n 's/^torch==\([^ ;]*+cpu\).*/\1/p' requirements.lock.txt)"
[ -n "$TORCH" ] || { echo "no torch +cpu pin in requirements.lock.txt" >&2; exit 1; }
printf "torch==%s ; sys_platform != 'darwin'\n" "$TORCH" > /tmp/torch.in
common /tmp/torch.in --index-url "$TORCH_INDEX" --no-deps -o requirements-torch.lock.txt

common requirements-ci.txt -c requirements.lock.txt -o requirements-ci.lock.txt
common requirements-audit.txt -o requirements-audit.lock.txt
python3 scripts/lock_pypi_hashes.py requirements-ci.lock.txt requirements-audit.lock.txt

for f in requirements.lock.txt requirements-torch.lock.txt requirements-ci.lock.txt requirements-audit.lock.txt; do
    echo "Locked $(grep -c '==' "$f") packages -> $f"
done
