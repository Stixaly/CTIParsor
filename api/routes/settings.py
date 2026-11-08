"""Settings API (ADR-0007, ADR-0019) — Slice 1: detection-corpora management.

No secrets here. Adds/removes operate on the gitignored local overlay
(detection_corpora.local.yaml); the committed registry is never edited by the app.
The LLM-keys panel (Slice 2) is intentionally not implemented yet — it needs the
secret-storage + loopback-guard work from ADR-0007.

ADR-0019: Multi-format support (sigma/suricata/yara). Format availability is
derived from the pipeline detection registry adapters (_ADAPTERS).
"""
import itertools
import string
from pathlib import Path
from typing import overload
from urllib.parse import urlsplit, urlunsplit

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from api.db import get_rule_conn
from api.response_models.settings import (
    CorporaOut,
    CorporaResult,
    CorpusCreated,
    FormatsOut,
    RebuildOut,
    SyncOut,
)
from pipeline.detection.builder import rebuild_store
from pipeline.detection.registry import _ADAPTERS, add_corpus, merged_corpora, remove_corpus
from pipeline.detection.store import corpus_counts
from pipeline.detection.sync import clone_mismatch, sync_corpus
from pipeline.regex_safety import compile_pattern
from pipeline.security import is_contained
from pipeline.web_capture import CaptureError, validate_url

router = APIRouter(prefix="/api/settings", tags=["settings"])

_ROOT = Path(__file__).resolve().parents[2]
_CONFIG = _ROOT / "detection_corpora.yaml"
# Every committed and example corpus lives under `./corpora/` (detection_corpora.yaml's
# own header), and `sync_corpus`/`fetch_tarball` (pipeline/detection/sync.py) run
# `git clone`/tarball-extract at whatever `path` a corpus carries with no
# containment check of their own — they trust the registry the way this file
# trusts a human editing YAML by hand. This endpoint accepts `path` over the
# network instead, so it draws the boundary the registry never needed: a corpus
# added here must resolve inside this directory, not wherever the caller says.
_CORPORA_ROOT = (_ROOT / "corpora").resolve()

# Guards against a `git`/`tarball` value shaped to be parsed as something other
# than a location: a leading `-` lets `git clone` read it as an option
# (`--upload-pack=<command>` is the documented argument-injection primitive —
# GitHub Security Lab, "Wagging the Dog"), and a `scheme::` prefix (`ext::`,
# `fd::`) asks git to run an arbitrary local command as the transport itself.
# git blocks `ext::` by default today, but that is git's default to change, not
# a guarantee this app controls — checked here too rather than assumed safe.
# The helper name is what git reads as one (transport.c is_urlschemechar:
# ASCII letters, digits, "+", "-", "."), and what RE2 read as `\w` ("_"): a
# `\w+` let "a-b::" through, and under `re` refused "é::", which git takes for a
# path (ADR-0049, 2026-10-18).
_UNSAFE_REMOTE_RE = compile_pattern(r"^-|^[A-Za-z0-9_][A-Za-z0-9_+.-]*::")

#: Formats this project recognises, independent of whether a parser is compiled in.
#:
#: Configuring and *ingesting* are deliberately separate. `_ADAPTERS` says what can
#: be parsed today; this says what may be written to the registry. Gating creation
#: on `_ADAPTERS` alone would be incoherent — the committed registry already holds
#: seven suricata/yara corpora (ADR-0015), so the API would refuse to create what
#: the config already contains, and a user could never stage a repo ahead of its
#: adapter shipping. A corpus whose adapter is missing is accepted, flagged
#: `adapter_available: false`, and simply contributes no rules until it lands.
KNOWN_FORMATS: frozenset[str] = frozenset({"sigma", "suricata", "yara"})


# A corpus name is a URL path segment of the routes below and the default
# directory under corpora/: no separator, no dot-only name.
_CORPUS_NAME_RE = compile_pattern(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")


class CorpusIn(BaseModel):
    name: str
    adapter: str = "sigma"
    git: str | None = None
    tarball: str | None = None
    path: str | None = None
    subdir: str | None = None
    license: str = "unknown"
    priority: int | None = None
    private: bool = False
    enabled: bool = True


class CorpusPatch(BaseModel):
    enabled: bool


def _validate_corpus_path(raw_path: str, subdir: str | None) -> None:
    """Reject a `path` (or `path` + `subdir`) that would resolve outside `corpora/`.

    `raw_path` reaches `git clone <remote> <path>` / tarball extraction
    (pipeline/detection/sync.py) with no containment check of its own, so
    `../../../etc/cron.d/evil` (or an absolute path) would otherwise let this
    endpoint write files anywhere the API process can — not a secret, but a
    write primitive SECURITY.md's "no endpoint writes a secret" doesn't cover.

    `subdir` is checked too: `corpus_root()` (pipeline/detection/registry.py)
    joins it onto `path` to pick what the adapter parses, so a `subdir` of
    `../../../../etc` would read (and offer up as "detection rules") files
    outside `corpora/` even with `path` itself contained.
    """
    candidate = _ROOT / raw_path
    if not is_contained(candidate, _CORPORA_ROOT):
        raise HTTPException(
            400,
            f"'path' must resolve inside {_CORPORA_ROOT} (got {raw_path!r} -> {candidate.resolve()})",
        )
    # is_relative_to() is reflexive, so "./corpora" resolves to the root itself
    # and passes the check above -- but a later tarball sync rmtree()s the
    # target directory, so the corpora root itself must never be accepted.
    if candidate.resolve() == _CORPORA_ROOT:
        raise HTTPException(400, "'path' must be a strict subdirectory of corpora/")
    if subdir and subdir.strip():
        sub = subdir.strip()
        base = candidate.resolve()
        # The clone is the boundary, not corpora/: another corpus's directory is
        # inside corpora/ too, and `.` is the clone itself.
        if (
            Path(sub).is_absolute()
            or sub.startswith(("/", "\\"))
            or ".." in sub.replace("\\", "/").split("/")
        ):
            raise HTTPException(400, f"'subdir' must be a relative path inside the corpus (got {subdir!r})")
        scoped = base / sub
        if not is_contained(scoped, base) or scoped.resolve() == base:
            raise HTTPException(
                400,
                f"'subdir' must resolve inside {base} (got {subdir!r} -> {scoped.resolve()})",
            )


def _validate_remote(value: str | None, field: str) -> None:
    if value is None:
        return
    if _UNSAFE_REMOTE_RE.match(value):
        raise HTTPException(
            400,
            f"'{field}' must not start with '-' (parsed as a git option, not a URL) "
            "or a 'scheme::' transport helper",
        )
    if field == "git":
        _validate_git_remote(value)


def _validate_git_remote(value: str) -> None:
    """An https:// remote on a public host, and nothing else.

    `git clone <remote>` runs on the server with the container's network: a
    `file://` remote reads the filesystem, `ssh://` and `git://` reach internal
    hosts, `http://169.254.169.254/...` is the cloud metadata service (audit B
    8.2.2).  The tarball path already applied `validate_url`'s policy; the git
    path now does too, and pipeline/detection/sync.py locks git to https as
    well, so a remote that gets past this check still cannot switch protocol.
    A private corpus over SSH is cloned by hand into corpora/ and registered
    with its `path` only (that module's docstring).
    """
    if urlsplit(value).scheme.lower() != "https":
        raise HTTPException(
            400,
            "'git' must be an https:// URL — ssh://, git://, file:// and scp-style "
            "remotes are refused; clone a private corpus by hand and register its path",
        )
    try:
        validate_url(value)
    except CaptureError as e:
        raise HTTPException(400, _mask_text(f"'git' is not a safe remote: {e}")) from e


#: Query parameters whose value is a credential when a corpus URL carries one.
_SECRET_QUERY_PARAMS = frozenset({"token", "access_token", "private_token", "key", "sig"})
_MASK = "***"
#: Prefixes of GitHub and GitLab tokens.
_TOKEN_PREFIXES = ("ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_", "glpat-")
_TOKEN_CHARS = frozenset(string.ascii_letters + string.digits + "_-")
#: Characters of the user in a scp-style `user@host:path` remote.
_SCP_USER_CHARS = frozenset(string.ascii_letters + string.digits + "_.+-")


def _looks_like_token(user: str) -> bool:
    """A lone userinfo name (no password) that looks like a token: a known token
    prefix, or a run of 20 or more token characters. Over-masking a long account
    name is harmless; leaking a token is not.

    Plain string code, no regex: CodeQL ties every pattern compiled through
    `compile_pattern` to every match call, so a new pattern there reopens
    py/polynomial-redos alerts elsewhere in this module.
    """
    if any(c.isspace() for c in user):
        return False
    if any(user.startswith(p) and len(user) > len(p) for p in _TOKEN_PREFIXES):
        return True
    return len(user) >= 20 and all(c in _TOKEN_CHARS for c in user)


def _mask_url(url: str | None) -> str | None:
    """Return `url` with its secret parts replaced by `***`, for responses only.

    Masked: the password of the userinfo (`https://user:***@host`), a lone userinfo
    name shaped like a token, and the value of each query parameter in
    `_SECRET_QUERY_PARAMS`. The rest is kept as written. Storage and the fetch keep
    the real URL. A URL with no secret comes back unchanged.
    """
    if not url:
        return url
    try:
        parts = urlsplit(url)
    except ValueError:   # unbalanced IPv6 brackets: nothing safe to show
        return _MASK
    netloc = parts.netloc
    if "@" in netloc:
        userinfo, _, hostport = netloc.rpartition("@")
        user, colon, password = userinfo.partition(":")
        if colon and password:
            userinfo = f"{user}:{_MASK}"
        elif not colon and _looks_like_token(user):
            userinfo = _MASK
        netloc = f"{userinfo}@{hostport}"
    query = parts.query
    if query:
        pairs = []
        for pair in query.split("&"):
            name, eq, _value = pair.partition("=")
            pairs.append(f"{name}={_MASK}" if eq and name.lower() in _SECRET_QUERY_PARAMS else pair)
        query = "&".join(pairs)
    return urlunsplit((parts.scheme, netloc, parts.path, query, parts.fragment))


def _mask_word(word: str) -> str:
    """Mask a URL, or the token-shaped user of a scp-style remote, in one word."""
    found = [i for i in (word.find("https://"), word.find("http://")) if i != -1]
    if found:
        at = min(found)
        return word[:at] + (_mask_url(word[at:]) or _MASK)
    at = word.find("@")
    if at > 0:
        start = at
        while start > 0 and word[start - 1] in _SCP_USER_CHARS:
            start -= 1
        if _looks_like_token(word[start:at]):
            return word[:start] + _MASK + word[at:]
    return word


@overload
def _mask_text(text: str) -> str: ...
@overload
def _mask_text(text: None) -> None: ...
def _mask_text(text: str | None) -> str | None:
    """Mask every URL in a message (a sync result or an error), with `_mask_url`.

    A git error can echo the remote it failed on, with its token in the userinfo.
    A scp-style `user@host:path` remote has no password, so only a token-shaped
    user is masked; an address such as `ops@example.org` is kept. The text is cut
    into runs of whitespace and of other characters, and each word is masked from
    its URL to the end of the word.
    """
    if not text:
        return text
    return "".join(
        "".join(run) if blank else _mask_word("".join(run))
        for blank, run in itertools.groupby(text, str.isspace)
    )


def _refuse_masked_url(value: str | None, field: str) -> None:
    """A URL that still holds the mask is a masked copy from a response, not a remote."""
    if value and _MASK in value:
        raise HTTPException(
            400,
            f"'{field}' contains '***', the masked form the settings API shows for a secret. "
            "Enter the real URL, or the stored token is lost.",
        )


def _with_counts() -> list[dict]:
    items = merged_corpora(_CONFIG)
    # The rule store is always the SQLite corpus, whatever DATABASE_URL says (ADR-0045).
    with get_rule_conn() as conn:
        counts = {c["corpus"]: c["rules"] for c in corpus_counts(conn)}
    for it in items:
        it["rules"] = counts.get(it.get("name"), 0)
        it["enabled"] = it.get("enabled", True)
        it["adapter"] = it.get("adapter", "sigma")
        it["adapter_available"] = it["adapter"] in _ADAPTERS
        # Responses only: the stored and fetched URLs keep their secrets.
        for field in ("git", "tarball"):
            if it.get(field):
                it[field] = _mask_url(it[field])
    return items


@router.get("/corpora", response_model=CorporaOut, response_model_exclude_unset=True)
def list_corpora():
    """List all configured corpora with their rule counts and adapter availability."""
    return {"corpora": _with_counts()}


@router.get("/formats", response_model=FormatsOut, response_model_exclude_unset=True)
def list_formats():
    """List all known formats (compiled adapters + configured corpora) with stats."""
    items = _with_counts()
    # Union of: what can be parsed, what the project recognises, and what is
    # actually configured — so a corpus for an uncompiled format stays visible
    # instead of silently vanishing from the UI.
    formats = set(_ADAPTERS) | set(KNOWN_FORMATS)
    for it in items:
        if it.get("adapter"):
            formats.add(it["adapter"])

    result = []
    for f in sorted(formats):
        corpus_list = [it for it in items if it.get("adapter") == f]
        result.append({
            "format": f,
            "available": f in _ADAPTERS,
            "corpora": len(corpus_list),
            "rules": sum(it.get("rules", 0) for it in corpus_list),
        })
    return {"formats": result}


@router.post("/corpora", response_model=CorpusCreated, response_model_exclude_unset=True)
def create_corpus(body: CorpusIn):
    """Add a new corpus to the local overlay. Validates adapter against available parsers."""
    name = body.name.strip()
    if not name:
        raise HTTPException(400, "name is required")
    if not _CORPUS_NAME_RE.fullmatch(name):
        # The name is the {name} segment of the PATCH/DELETE/sync routes: one
        # with a "/" (raw or %2F) never reaches them again, so it could be
        # created but neither disabled nor removed (#353).
        raise HTTPException(
            400, "name must be letters, digits, '.', '_' or '-' (no '/'), starting with a letter or digit"
        )

    adapter = (body.adapter or "").strip().lower()
    if adapter not in KNOWN_FORMATS:
        known = ", ".join(sorted(KNOWN_FORMATS))
        raise HTTPException(400, f"unknown format '{adapter}' — known formats: {known}")

    if body.git and body.tarball:
        raise HTTPException(400, "provide either 'git' or 'tarball', not both")

    _refuse_masked_url(body.git, "git")
    _refuse_masked_url(body.tarball, "tarball")
    _validate_remote(body.git, "git")
    _validate_remote(body.tarball, "tarball")
    if body.tarball:
        # `_validate_remote` above only blocks git-argument-injection shapes;
        # `sync_corpus`/`fetch_tarball` fetches this over the network with no
        # scheme/host restriction of its own, so it needs the same SSRF policy
        # web captures use (http/https only, no private/internal hosts).
        # Checked again at fetch time in pipeline/detection/sync.py -- this
        # copy only turns a bad URL into a 400 at creation time instead of a
        # 502 on the first "Redownload" click.
        try:
            validate_url(body.tarball)
        except CaptureError as e:
            raise HTTPException(400, f"'tarball' is not a safe URL to fetch: {e}") from e

    entry = body.model_dump()
    entry["name"] = name
    entry["adapter"] = adapter

    # `path` is always required: it is where the clone/extraction LIVES locally,
    # not an alternative to `git`/`tarball`. Every entry in the committed registry
    # carries both, and `corpus_root()` parses `path`, so defaulting it only for
    # sourceless corpora would leave a git corpus with nowhere to land.
    if not entry.get("path"):
        entry["path"] = f"./corpora/{name}"

    _validate_corpus_path(entry["path"], entry.get("subdir"))

    # Remove None values to avoid writing nulls to YAML
    entry = {k: v for k, v in entry.items() if v is not None}

    add_corpus(_CONFIG, entry)
    # Surface the "configured but not yet ingestible" case explicitly, so the UI
    # never has to infer it and the operator is told at the moment of creation.
    warning = (
        None if adapter in _ADAPTERS else
        f"'{adapter}' has no parser in this build — the repo is saved and will "
        f"ingest once its adapter ships. Available now: "
        f"{', '.join(sorted(_ADAPTERS)) or 'none'}."
    )
    return {"ok": True, "warning": warning, "corpora": _with_counts()}


@router.delete("/corpora/{name}", response_model=CorporaResult, response_model_exclude_unset=True)
def delete_corpus(name: str):
    """Remove a corpus from the local overlay."""
    if not any(c.get("name") == name for c in merged_corpora(_CONFIG)):
        raise HTTPException(404, f"unknown corpus '{name}'")
    remove_corpus(_CONFIG, name)
    return {"ok": True, "corpora": _with_counts()}


@router.patch("/corpora/{name}", response_model=CorporaResult, response_model_exclude_unset=True)
def patch_corpus(name: str, body: CorpusPatch):
    """Enable or disable a corpus without losing its configuration.

    This route exists because `remove_corpus` writes a deactivation override for
    committed registry corpora, but there was no way to re-enable them from the UI
    without manually editing the YAML. ADR-0015 shipped seven corpora disabled,
    making them inaccessible without this endpoint.
    """
    corpus = next((c for c in merged_corpora(_CONFIG) if c.get("name") == name), None)
    if corpus is None:
        raise HTTPException(404, f"unknown corpus '{name}'")

    entry = dict(corpus)
    entry.pop("rules", None)
    entry.pop("adapter_available", None)
    entry["enabled"] = body.enabled

    add_corpus(_CONFIG, entry)
    return {"ok": True, "corpora": _with_counts()}


@router.post("/corpora/{name}/sync", response_model=SyncOut, response_model_exclude_unset=True)
def sync_one_corpus(name: str):
    """Fetch ONE public corpus (git clone/pull, or tarball download — ADR-0015 §5),
    then re-ingest the store.

    This is the same networked step as `scripts/sync_corpora.py`, exposed per-row
    for the Settings "Redownload" button. Restricted to PUBLIC corpora: private
    ones must use the CLI so git credentials never flow through the app (ADR-0006).
    Cloning a large repo can take a while — the request blocks until git finishes.
    A folder that is not the clone of this corpus's remote is a 409, checked before
    any git command runs: the folder is removed by hand, never by this route (#367).
    A download that the rebuild could not re-import (its `subdir` or `path` is
    missing) is a 422 that says why; the rules indexed before are kept (#374).
    """
    corpus = next((c for c in merged_corpora(_CONFIG) if c.get("name") == name), None)
    if corpus is None:
        raise HTTPException(404, f"unknown corpus '{name}'")

    if not corpus.get("git") and not corpus.get("tarball"):
        raise HTTPException(
            400, f"'{name}' has no git remote or tarball URL — its path is managed manually"
        )

    if corpus.get("private"):
        raise HTTPException(
            400,
            f"'{name}' is private — fetch it with `python scripts/sync_corpora.py` "
            "so git credentials stay out of the app",
        )

    mismatch = clone_mismatch(corpus)
    if mismatch:
        raise HTTPException(409, _mask_text(mismatch))

    ok, detail = sync_corpus(corpus)
    detail = _mask_text(detail)
    if not ok:
        raise HTTPException(502, f"sync failed: {detail}")

    with get_rule_conn() as conn:
        summary = rebuild_store(conn, _CONFIG)
    if name in summary["skipped"]:
        # The fetch worked but the rebuild wrote nothing for this corpus, and kept
        # the rules it had: say so instead of reporting a success (#374).
        raise HTTPException(
            422,
            f"downloaded, but not re-imported: {_mask_text(summary['skip_reasons'][name])}. "
            "The rules indexed before are kept.",
        )
    return {
        "ok": True,
        "detail": detail,
        "rules": summary["written"].get(name, 0),
        "file_errors": summary["file_errors"].get(name, []),
        "corpora": _with_counts(),
    }


@router.post("/corpora/rebuild", response_model=RebuildOut, response_model_exclude_unset=True)
def rebuild_corpora():
    """Re-ingest all enabled corpora from their existing local clones into the store.

    Fetching new clones is still the CLI step `python scripts/sync_corpora.py`
    (a background git-sync endpoint is Slice-2 work).
    """
    with get_rule_conn() as conn:
        return rebuild_store(conn, _CONFIG)
