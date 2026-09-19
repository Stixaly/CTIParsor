"""Networked fetch of a corpus's local copy: a shallow git clone (ADR-0006) or a
downloaded tarball (ADR-0015 §5).

The ONLY place CTIParsor shells out to `git` or downloads a corpus archive.
Shared by the CLI (scripts/sync_corpora.py, which streams git progress) and the
settings API "redownload" action (which captures output). Uses ambient git
authentication (SSH agent / credential.helper) — no credentials are stored or
handled here, so private corpora are intentionally CLI-only (see
api/routes/settings.py).
"""
from __future__ import annotations

import hashlib
import json
import re
import shutil
import subprocess
import tarfile
import tempfile
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath

from pipeline.security import is_contained
from pipeline.web_capture import CaptureError, validate_url

MANIFEST_NAME = ".sync.json"     # written into `path` after a tarball fetch (ADR-0015 §5)
_USER_AGENT = "cti-to-stix/1.0 (detection corpus sync)"
_CHUNK = 1 << 20
_MD5_RE = re.compile(r"^[0-9a-f]{32}$")


class _SafeRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Re-validates every redirect target through validate_url before
    following it.

    validate_url() only ever sees the URL fetch_tarball was called with;
    urllib's default redirect handling then trusts whatever Location header
    the remote server sends for every hop after that with no further check.
    A server that legitimately passes the scheme/host/public-IP check on the
    first request can still redirect to file://, localhost, or an internal
    address on the next one. This closes that gap by applying the same check
    to every redirect target. DNS rebinding between validation and connection
    (the remaining gap pipeline/web_capture.py closes for its own fetches via
    Chromium's --host-resolver-rules) is not closed here -- it needs control
    of the domain's authoritative DNS, a narrower and higher-effort attack
    than an open redirect.
    """

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        try:
            validate_url(newurl)
        except CaptureError as e:
            raise urllib.error.URLError(f"redirect to an unsafe URL blocked: {e}") from e
        return super().redirect_request(req, fp, code, msg, headers, newurl)


_SAFE_OPENER = urllib.request.build_opener(_SafeRedirectHandler)


def git_command(corpus: dict) -> list[str] | None:
    """The git command to fetch one corpus: `clone --depth 1` when the local
    `path` is missing, else `pull --ff-only`. Returns None when the corpus has no
    `git` remote (its path is managed manually)."""
    remote = corpus.get("git")
    if not remote:
        return None
    path = Path(corpus.get("path", ""))
    if path.exists():
        return ["git", "-C", str(path), "pull", "--ff-only"]
    path.parent.mkdir(parents=True, exist_ok=True)
    return ["git", "clone", "--depth", "1", remote, str(path)]


def _download(url: str, dest: Path, *, timeout: int) -> int:
    """Stream `url` into `dest` in _CHUNK-sized blocks; returns the bytes written.
    Raises URLError/OSError — the caller decides what a failure means."""
    req = urllib.request.Request(url, headers={"User-Agent": _USER_AGENT})
    with _SAFE_OPENER.open(req, timeout=timeout) as resp:
        total = 0
        with open(dest, "wb") as f:
            while True:
                chunk = resp.read(_CHUNK)
                if not chunk:
                    break
                f.write(chunk)
                total += len(chunk)
    return total


def _fetch_text(url: str, *, timeout: int) -> str | None:
    """Fetch a small text sidecar (the .md5 next to a tarball). None on any failure."""
    req = urllib.request.Request(url, headers={"User-Agent": _USER_AGENT})
    try:
        with _SAFE_OPENER.open(req, timeout=timeout) as resp:
            data = resp.read(4096)
        return data.decode("utf-8", errors="replace")
    except (urllib.error.URLError, OSError, TimeoutError, ValueError):
        return None


def _parse_md5(text: str | None) -> str | None:
    """First whitespace-separated token of an .md5 sidecar, lower-cased, when it
    is a 32-hex-digit hash; None otherwise (empty body, HTML error page, ...)."""
    if text is None:
        return None
    text = text.strip()
    if not text:
        return None
    token = text.split()[0].lower()
    if _MD5_RE.match(token):
        return token
    return None


def _safe_members(tar: tarfile.TarFile, dest: Path) -> tuple[list[tarfile.TarInfo], int]:
    """Members safe to extract under `dest`, and how many were rejected: regular
    files and directories only (no links or devices), no absolute names, no `..`,
    and the resolved target must stay inside `dest`."""
    safe: list[tarfile.TarInfo] = []
    skipped = 0
    for member in tar.getmembers():
        if member.name in ("", "."):
            continue
        if not (member.isfile() or member.isdir()):
            skipped += 1
            continue
        p = PurePosixPath(member.name)
        if p.is_absolute() or ".." in p.parts:
            skipped += 1
            continue
        if not is_contained(dest / member.name, dest):
            skipped += 1
            continue
        safe.append(member)
    return safe, skipped


def fetch_tarball(corpus: dict, *, timeout: int = 900) -> tuple[bool, str]:
    """Download `corpus["tarball"]`, verify it against the `<url>.md5` sidecar when
    the server publishes one, extract it into a staging directory next to `path`,
    then swap the staging directory into `path`. The previous copy is removed only
    after a successful extraction, so a failed download never destroys a working
    corpus. Writes `<path>/.sync.json` = {url, sha256, md5, size, fetched_at}
    (ADR-0015 §5: a tarball has no revision to pin, so the fetch records URL +
    content hash instead). Returns (ok, detail)."""
    url = corpus.get("tarball")
    if not isinstance(url, str) or not url.strip():   # YAML can hand us an int/None
        return False, "no tarball URL"
    path = Path(str(corpus.get("path") or ""))
    if str(path) in ("", "."):
        return False, "no path configured"
    # `_validate_remote` in api/routes/settings.py only rejects git-argument-
    # injection shapes (a leading '-', a 'scheme::' transport helper) -- it says
    # nothing about scheme or host, so an operator-supplied tarball URL still
    # needs the same SSRF policy as any other server-side fetch of an
    # attacker-influenced URL. `validate_url` is the one place that policy is
    # defined (see pipeline/web_capture.py): http(s) only, no credentials, no
    # localhost/link-local/metadata hosts, and only publicly-routable resolved
    # IPs. A `file://`/`ftp://` scheme or an internal host is rejected here,
    # before anything is downloaded. The original `url` string (not the
    # normalized return value) is kept, so a `.md5` sidecar built from it below
    # still matches exactly what the registry configured.
    try:
        validate_url(url)
    except CaptureError as e:
        return False, f"invalid tarball URL: {e}"

    path.parent.mkdir(parents=True, exist_ok=True)
    staging = path.parent / f".{path.name}.staging"
    if staging.exists():
        shutil.rmtree(staging)

    tmp = tempfile.NamedTemporaryFile(prefix="corpus-", suffix=".tar", dir=path.parent, delete=False)
    archive: Path = Path(tmp.name)
    tmp.close()

    try:
        try:
            size = _download(url, archive, timeout=timeout)
        except (urllib.error.URLError, OSError, TimeoutError, ValueError) as e:
            return False, f"download failed: {e}"

        sha256_obj = hashlib.sha256()
        md5_obj = hashlib.md5(usedforsecurity=False)   # integrity check; FIPS-safe
        with open(archive, "rb") as f:
            while True:
                chunk = f.read(_CHUNK)
                if not chunk:
                    break
                sha256_obj.update(chunk)
                md5_obj.update(chunk)
        sha256 = sha256_obj.hexdigest()
        md5 = md5_obj.hexdigest()

        expected = _parse_md5(_fetch_text(f"{url}.md5", timeout=timeout))
        if expected is not None and expected != md5:
            return False, f"checksum mismatch: sidecar {expected}, downloaded {md5}"

        staging.mkdir(parents=True)
        try:
            tar = tarfile.open(archive, mode="r:*")
        except (tarfile.TarError, OSError, EOFError) as e:
            return False, f"not a tar archive: {e}"

        with tar:
            members, skipped = _safe_members(tar, staging)
            if not members:
                return False, "archive contains no extractable files"
            kwargs: dict = {"filter": "data"} if hasattr(tarfile, "data_filter") else {}
            tar.extractall(staging, members=members, **kwargs)

        manifest = {
            "url": url,
            "sha256": sha256,
            "md5": md5,
            "sidecar_md5": expected,
            "size": size,
            "files": len(members),
            "fetched_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        }
        (staging / MANIFEST_NAME).write_text(json.dumps(manifest, indent=2), encoding="utf-8")

        try:
            if path.exists():
                shutil.rmtree(path)
            staging.rename(path)
        except OSError as e:
            return False, f"could not replace {path}: {e}"

        detail = f"fetched {size:,} bytes, {len(members)} files"
        if skipped > 0:
            detail += f", {skipped} unsafe members skipped"
        if expected is not None:
            detail += ", verified against sidecar md5"
        else:
            detail += ", no checksum published"
        return True, detail
    finally:
        archive.unlink(missing_ok=True)
        if staging.exists():
            shutil.rmtree(staging, ignore_errors=True)


def sync_corpus(corpus: dict, *, timeout: int = 900) -> tuple[bool, str]:
    """Fetch one corpus (git clone/pull, or tarball download), capturing output."""
    if corpus.get("tarball"):
        return fetch_tarball(corpus, timeout=timeout)
    cmd = git_command(corpus)
    if cmd is None:
        return False, "no git remote or tarball URL — this corpus's path is managed manually"
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except (FileNotFoundError, subprocess.TimeoutExpired) as e:
        return False, str(e)
    if proc.returncode != 0:
        return False, (proc.stderr or proc.stdout or "git failed").strip()[:1000]
    return True, (proc.stdout or proc.stderr or "ok").strip()[:1000]
