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
import lzma
import os
import shutil
import subprocess
import tarfile
import tempfile
import urllib.error
import urllib.request
import zlib
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from urllib.parse import urlsplit, urlunsplit

from api.logging_config import get_logger
from pipeline.regex_safety import compile_pattern
from pipeline.security import is_contained
from pipeline.web_capture import CaptureError, validate_url

logger = get_logger(__name__)

MANIFEST_NAME = ".sync.json"     # written into `path` after a tarball fetch (ADR-0015 §5)
_USER_AGENT = "cti-to-stix/1.0 (detection corpus sync)"
_CHUNK = 1 << 20
_MD5_RE = compile_pattern(r"^[0-9a-f]{32}$")
# What reading a cut-off or damaged archive raises: tarfile's errors, EOFError and
# gzip/bz2's OSError from the stream, zlib's and lzma's errors (#433).
_CORRUPT_ARCHIVE = (tarfile.TarError, EOFError, OSError, zlib.error, lzma.LZMAError)


def _failed(what: str, exc: BaseException) -> tuple[bool, str]:
    """A failed sync as the API returns it to the browser: what failed, not the
    exception's text — server paths, resolver and OS internals go to the log
    (CodeQL py/stack-trace-exposure)."""
    text = str(exc).replace("\r", "\\r").replace("\n", "\\n")   # one log line: the URL is the caller's
    logger.warning(f"[corpora] {what}: {text}")
    return False, f"{what} (details in the server log)"


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


# git is told, on its own command line, which transports a corpus may use:
# https only — `file://` would read the server's filesystem, `ssh://` and
# `git://` reach internal hosts, and a redirect could switch to any of them
# (audit B 8.2.2).  Config given with `-c` applies to the clone and to every
# submodule or redirect that command follows; `GIT_ENV` below says the same
# through the environment for the `pull` of a clone made before this policy.
GIT_HARDENING: tuple[str, ...] = (
    "-c", "protocol.allow=never",
    "-c", "protocol.https.allow=always",
    "-c", "protocol.file.allow=never",
    "-c", "http.followRedirects=false",
)
GIT_ENV: dict[str, str] = {"GIT_ALLOW_PROTOCOL": "https", "GIT_TERMINAL_PROMPT": "0"}


def _is_empty_dir(path: Path) -> bool:
    """An existing folder with nothing in it: what an interrupted clone leaves behind.
    git clones into it, so it is not a checkout to pull (#367)."""
    return path.is_dir() and not any(path.iterdir())


def git_command(corpus: dict) -> list[str] | None:
    """The git command to fetch one corpus: `clone --depth 1` when the local
    `path` is missing or an empty folder, else `pull --ff-only`, both with
    GIT_HARDENING. Returns None when the corpus has no `git` remote (its path is
    managed manually). The pull is only safe once clone_mismatch(corpus) is None:
    callers check it first (#367)."""
    remote = corpus.get("git")
    if not remote:
        return None
    path = Path(str(corpus.get("path") or ""))
    if str(path) in ("", "."):
        raise ValueError("no path configured")
    if path.exists() and not _is_empty_dir(path):
        return ["git", *GIT_HARDENING, "-C", str(path), "pull", "--ff-only"]
    path.parent.mkdir(parents=True, exist_ok=True)
    return ["git", *GIT_HARDENING, "clone", "--depth", "1", remote, str(path)]


def git_remote_refusal(remote: str) -> str | None:
    """Why `remote` is refused, or None when git may fetch it: both the API sync and
    the CLI call it before git runs. The registry can come from a YAML file nobody
    validated over the API (the committed one, or the local overlay), so a remote
    gets here the policy `_validate_git_remote` (api/routes/settings.py) gives one
    created over the API: https only, then `validate_url`'s — no credentials, an
    allowed port, a host that resolves to public addresses only.  Without it,
    `https://169.254.169.254/...` (the cloud metadata service) or an intranet host
    was cloned as is.  A returned reason, not an exception, so the API answers
    with this text and never with an exception's: what `validate_url` objected
    to goes to the log, and the remote is not echoed back, since it may carry a
    token."""
    if not remote.lower().startswith("https://"):
        return f"git remote refused: only https:// remotes are fetched ({remote[:80]!r})"
    try:
        validate_url(remote)
    except CaptureError as e:
        _, reason = _failed("git remote refused: not a safe remote to fetch", e)
        return reason
    return None


# Local git queries (rev-parse, remote get-url) do not touch the network; the timeout
# only guards against a hung filesystem.
_CHECK_TIMEOUT = 30


def _git_query(path: Path, *args: str) -> subprocess.CompletedProcess:
    """A local git query run in `path`, with the fetch's hardening and environment."""
    return subprocess.run(["git", *GIT_HARDENING, "-C", str(path), *args],  # noqa: S603, S607 — local query, git from PATH
                          capture_output=True, text=True, timeout=_CHECK_TIMEOUT,
                          env={**os.environ, **GIT_ENV})


def _without_credentials(remote: str) -> str:
    """`remote` with any `user:pass@` taken out: a token in a remote must not reach
    the browser, and the messages name both remotes."""
    parts = urlsplit(remote.strip())
    return urlunsplit(parts._replace(netloc=parts.netloc.rpartition("@")[2]))


def _remote_key(remote: str) -> str:
    """What two remotes must share to be the same repository: no credentials, scheme
    and host in lower case, no trailing `/` and no `.git`."""
    parts = urlsplit(_without_credentials(remote))
    path = parts.path.rstrip("/")
    if path.endswith(".git"):
        path = path[:-4].rstrip("/")
    return urlunsplit((parts.scheme.lower(), parts.netloc.lower(), path, "", ""))


def clone_mismatch(corpus: dict) -> str | None:
    """Why `git pull` must not run in the existing `path` of a git corpus, or None
    when it may (#367). A folder that is not the root of its own clone is refused:
    `git -C` climbs to the parent checkout and would pull that one instead. A clone
    whose `origin` is not the configured `git` remote is refused too: the pull would
    contact the old repository. A missing `path` is None, since git_command clones
    it, and so is an empty folder (left by an interrupted clone): git clones into it.
    A folder git refuses with "dubious ownership" (owned by another user) gets a
    reason that names `safe.directory`. Nothing is deleted here, the folder is the
    user's to remove. The API answers the reason with a 409, the CLI prints it and
    counts a failure."""
    remote = corpus.get("git")
    if corpus.get("tarball") or not remote:
        return None
    path = Path(str(corpus.get("path") or ""))
    if str(path) in ("", ".") or not path.exists() or _is_empty_dir(path):
        return None
    try:
        top = _git_query(path, "rev-parse", "--show-toplevel")
        if top.returncode != 0 and "dubious ownership" in (top.stderr or ""):
            return (f"{path} belongs to another user, and git refuses to read it "
                    f"(safe.directory) — run `git config --global --add safe.directory {path}` "
                    "or change its owner, then Redownload")
        if top.returncode != 0:
            return (f"{path} exists but is not a git clone of its own (no git repository there) "
                    "— remove it or choose another path, then Redownload")
        if Path(top.stdout.strip()).resolve() != path.resolve():
            # The enclosing checkout's path stays out of the message: it is a
            # server path, and this text reaches the browser. The configured
            # `path`, typed by the user or the default, is in it.
            return (f"{path} exists but is not a git clone of its own "
                    "(it sits inside another checkout) "
                    "— remove it or choose another path, then Redownload")
        origin = _git_query(path, "remote", "get-url", "origin")
    except (OSError, subprocess.TimeoutExpired) as e:
        _, reason = _failed(f"could not check {path} against its git remote", e)
        return reason
    if origin.returncode != 0:
        return (f"{path} is a git clone with no origin remote "
                f"— remove the folder to clone {_without_credentials(remote)}")
    current = origin.stdout.strip()
    try:
        same = _remote_key(current) == _remote_key(remote)
    except ValueError:   # urlsplit refuses e.g. unbalanced IPv6 brackets
        return (f"{path} has an origin remote that cannot be parsed "
                "— remove the folder to clone the configured remote")
    if not same:
        return (f"{path} is a clone of {_without_credentials(current)} but the corpus is "
                f"configured for {_without_credentials(remote)} "
                "— remove the folder to clone the new remote")
    return None


def _download(url: str, dest: Path, *, timeout: int) -> int:
    """Stream `url` into `dest` in _CHUNK-sized blocks; returns the bytes written.
    Raises URLError/OSError — the caller decides what a failure means."""
    # The URL passed validate_url (fetch_tarball), each redirect too (_SAFE_OPENER).
    req = urllib.request.Request(url, headers={"User-Agent": _USER_AGENT})  # noqa: S310 — see above
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
    req = urllib.request.Request(url, headers={"User-Agent": _USER_AGENT})  # noqa: S310 — as _download
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
    content hash instead). A cut-off or damaged archive is a failed sync, not an
    exception (#433). Returns (ok, detail)."""
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
        return _failed("invalid tarball URL", e)

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
            return _failed("download failed", e)

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
        except tarfile.TarError as e:
            return _failed("not a tar archive", e)
        except _CORRUPT_ARCHIVE as e:
            return _failed("archive is truncated or corrupt", e)

        # A cut-off or damaged stream raises from getmembers()/extractall(), not from
        # open(): those calls are in the try too (#433). The finally removes the
        # staging folder, so the previous copy at `path` is never replaced.
        try:
            with tar:
                members, skipped = _safe_members(tar, staging)
                if not members:
                    return False, "archive contains no extractable files"
                kwargs: dict = {"filter": "data"} if hasattr(tarfile, "data_filter") else {}
                tar.extractall(staging, members=members, **kwargs)  # noqa: S202 — _safe_members + data filter
        except _CORRUPT_ARCHIVE as e:
            return _failed("archive is truncated or corrupt", e)

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
            return _failed("could not replace the previous copy", e)

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
    try:
        cmd = git_command(corpus)
    except ValueError:
        # The one ValueError git_command raises; a fixed text, as fetch_tarball gives,
        # never the exception's (it reaches the browser: CodeQL py/stack-trace-exposure).
        return False, "no path configured"
    if cmd is None:
        return False, "no git remote or tarball URL — this corpus's path is managed manually"
    refusal = git_remote_refusal(str(corpus.get("git") or ""))
    if refusal:
        return False, refusal
    mismatch = clone_mismatch(corpus)
    if mismatch:
        return False, mismatch
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,  # noqa: S603 — https remote
                              env={**os.environ, **GIT_ENV})
    except FileNotFoundError as e:
        return _failed("git is not installed", e)
    except subprocess.TimeoutExpired as e:
        return _failed(f"git did not finish within {timeout} s", e)
    if proc.returncode != 0:
        return False, (proc.stderr or proc.stdout or "git failed").strip()[:1000]
    return True, (proc.stdout or proc.stderr or "ok").strip()[:1000]
