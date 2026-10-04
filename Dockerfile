# syntax=docker/dockerfile:1.7

# Base images are pinned by digest, like compose.yaml's: a tag can be re-pushed,
# a digest cannot. Dependabot (.github/dependabot.yml) proposes new digests.

# ── Stage 1: build the React frontend ─────────────────────────────────────────
FROM node:24-bookworm-slim@sha256:0e0ff40c39bc087845bfb27465a0df4ea419520094bc35842ff83dd8cbe6f9b6 AS ui
WORKDIR /ui
COPY frontend/package.json frontend/package-lock.json ./
RUN --mount=type=cache,target=/root/.npm npm ci --no-audit --no-fund
COPY frontend/ ./
RUN npm run build

# ── Stage 2: build the Python virtualenv ──────────────────────────────────────
FROM python:3.12-slim-bookworm@sha256:54c85f3c47607a77f32adec749d3c81d1348bf25833671f512b26a9b6d778cb3 AS builder
ENV PIP_DISABLE_PIP_VERSION_CHECK=1
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential libxml2-dev libxslt1-dev pkg-config \
    && rm -rf /var/lib/apt/lists/*
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"
WORKDIR /build
# The exact versions CI tested (`make lock`): requirements*.txt hold the ranges,
# requirements.lock.txt the resolution of all three, playwright and google-re2
# included.  It names the PyTorch CPU index itself and pins torch to its +cpu
# build, so no CUDA wheel (about 2.2 GB of nvidia_* packages this CPU image
# would never use) is ever pulled in.
COPY requirements.lock.txt ./
RUN --mount=type=cache,target=/root/.cache/pip \
    pip install --upgrade pip && \
    pip install -r requirements.lock.txt

# ── Stage 3: runtime image ────────────────────────────────────────────────────
FROM python:3.12-slim-bookworm@sha256:54c85f3c47607a77f32adec749d3c81d1348bf25833671f512b26a9b6d778cb3 AS runtime

ARG INSTALL_CAPTURE=true
ARG GIT_REV=""
ARG APP_UID=1001
ARG APP_GID=1001

LABEL org.opencontainers.image.title="CTIParsor" \
      org.opencontainers.image.description="CTI reports to STIX 2.1 - pipeline, web UI and API" \
      org.opencontainers.image.source="https://github.com/Stixaly/CTIParsor" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.revision="${GIT_REV}"

# API_HOST=0.0.0.0 is the container-internal bind; publishing the port to the
# host is the operator's decision in compose (default 127.0.0.1).
# PYTHONDONTWRITEBYTECODE + the compileall step below: the root filesystem is
# read-only at runtime.
# GIT_TERMINAL_PROMPT=0: corpus sync must fail fast instead of waiting for
# credentials.
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PATH="/opt/venv/bin:$PATH" \
    HOME=/home/ctiparsor \
    HF_HOME=/app/cache/hf \
    PLAYWRIGHT_BROWSERS_PATH=/ms-playwright \
    CTIPARSOR_GIT_REV="${GIT_REV}" \
    API_HOST=0.0.0.0 \
    API_PORT=8000 \
    GIT_TERMINAL_PROMPT=0 \
    MPLCONFIGDIR=/tmp/matplotlib \
    XDG_CACHE_HOME=/tmp/cache

# git for the corpus sync (Settings page and bootstrap);
# libmagic1 for python-magic (upload MIME check) — absent from slim images;
# no libre2 package needed: google-re2's wheel statically bundles the RE2
# library — verified via ldd, it links only libstdc++/libgcc_s, both already
# present in this base image (ADR-0049);
# tini reaps the Chromium and pipeline subprocesses.
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates git tini tesseract-ocr poppler-utils \
        libxml2 libxslt1.1 libmagic1 \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd --gid "${APP_GID}" ctiparsor && \
    useradd --uid "${APP_UID}" --gid "${APP_GID}" --create-home \
            --home-dir /home/ctiparsor --shell /usr/sbin/nologin ctiparsor

COPY --from=builder /opt/venv /opt/venv

# Chromium and its system libraries, for the URL tab (ADR-0029).  Installed
# as root at build time; the browser runs as ctiparsor with its sandbox ON,
# which needs the seccomp profile shipped in docker/ (see compose.yaml).
# --build-arg INSTALL_CAPTURE=false gives a smaller image whose URL tab
# answers 503 - the File and Paste tabs are unaffected.
RUN if [ "${INSTALL_CAPTURE}" = "true" ]; then \
        python -m playwright install --with-deps chromium \
        && chmod -R a+rX /ms-playwright \
        && rm -rf /var/lib/apt/lists/*; \
    fi

WORKDIR /app
# root-owned on purpose: the application must not be able to rewrite its own code
COPY . /app/
COPY --from=ui /ui/dist /app/frontend/dist

RUN install -m 0755 /app/docker/entrypoint.sh /usr/local/bin/entrypoint.sh \
    && mkdir -p /app/state /app/cache \
    # a named volume mounted on an empty path copies the owner from the image,
    # so this chown is what makes the volume writable by the app user
    && chown "${APP_UID}:${APP_GID}" /app/state /app/cache \
    && ln -s /app/state/uploads /app/uploads \
    && ln -s /app/state/output /app/output \
    && ln -s /app/state/backups /app/db_backups \
    && ln -s /app/cache/corpora /app/corpora \
    && ln -s /app/state/detection_corpora.local.yaml /app/detection_corpora.local.yaml \
    && python -m compileall -q /app/api /app/pipeline /app/models /app/scripts /app/main.py /app/run_api.py

USER ctiparsor
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=90s --retries=3 \
    CMD ["python", "-c", "import urllib.request, sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/api/health', timeout=4).status == 200 else 1)"]
ENTRYPOINT ["tini", "--", "/usr/local/bin/entrypoint.sh"]
CMD ["serve"]

# ── Stage 4: development image (the compose `dev` service) ────────────────────
# The runtime image plus the lint, type-check and coverage tools CI installs
# (requirements-dev.txt), so every check in CONTRIBUTING.md runs in `dev`.
# Never shipped: built only when asked for by name (`--target dev`).
FROM runtime AS dev
USER root
RUN pip install --no-cache-dir -c /app/requirements.lock.txt -r /app/requirements-dev.txt
USER ctiparsor
# It runs one-shot commands, not the API the inherited check polls.
HEALTHCHECK NONE

# ── Default target: the runtime image ─────────────────────────────────────────
# A build without --target produces the LAST stage.  Ending on `runtime` keeps
# `docker build .`, compose's app/worker and the CI publish job on the image
# without dev tools; BuildKit skips the `dev` stage unless it is the target.
FROM runtime
