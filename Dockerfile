# syntax=docker/dockerfile:1.7

# ── Stage 1: build the React frontend ─────────────────────────────────────────
FROM node:24-bookworm-slim AS ui
WORKDIR /ui
COPY frontend/package.json frontend/package-lock.json ./
RUN --mount=type=cache,target=/root/.npm npm ci --no-audit --no-fund
COPY frontend/ ./
RUN npm run build

# ── Stage 2: build the Python virtualenv ──────────────────────────────────────
FROM python:3.12-slim-bookworm AS builder
ENV PIP_DISABLE_PIP_VERSION_CHECK=1
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential libxml2-dev libxslt1-dev pkg-config \
    && rm -rf /var/lib/apt/lists/*
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"
WORKDIR /build
COPY requirements.txt requirements-api.txt requirements-optional.txt ./
# CPU-only build first, so that sentence-transformers below finds torch already
# satisfied and does not pull the CUDA build (about 2.2 GB of nvidia_* wheels
# that this CPU image would never use).
RUN --mount=type=cache,target=/root/.cache/pip \
    pip install --upgrade pip && \
    pip install --index-url https://download.pytorch.org/whl/cpu torch
RUN --mount=type=cache,target=/root/.cache/pip \
    pip install -r requirements.txt -r requirements-api.txt
# google-re2 (ADR-0049) is optional upstream too (setup.sh treats it the same
# way) — it ships a prebuilt wheel, so this should always succeed, but a
# platform this project hasn't tested still must not fail the build over it.
RUN --mount=type=cache,target=/root/.cache/pip \
    pip install "$(grep -E '^playwright' requirements-optional.txt)" && \
    (pip install "$(grep -E '^google-re2' requirements-optional.txt)" || \
     echo "WARNING: google-re2 did not install; Stage 2 regexes fall back to the stdlib re module")

# ── Stage 3: runtime image ────────────────────────────────────────────────────
FROM python:3.12-slim-bookworm AS runtime

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
    CTIPARSOR_DB_PATH=/app/state/cti_stix.db \
    CTIPARSOR_DB_BACKUP_DIR=/app/state/backups \
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
