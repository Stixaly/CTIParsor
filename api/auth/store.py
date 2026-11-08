"""Users, sessions, API tokens and the sign-in lockout, in the tables of migration 18.

A session id and an API token are random secrets shown once; the database holds
only their SHA-256 (`hash_secret`), so a copy of it signs nobody in.  Nothing
here logs a password, a token or a session id.
"""
from __future__ import annotations

import hashlib
import hmac
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from uuid import uuid4

from api.auth import passwords
from api.auth.config import DEFAULT_TOKEN_DAYS, ROLE_RANK, ROLES, session_ttl_hours
from api.db import get_conn
from pipeline.regex_safety import compile_pattern

TOKEN_PREFIX = "ctp_"                      # noqa: S105 - the start of every token, not a secret
LOCK_FAILURES = 5                       # failures for one username ...
LOCK_WINDOW = timedelta(minutes=15)     # ... within this window lock it for this long
_TOUCH_EVERY = timedelta(minutes=1)     # a session's or token's last-seen time is written at most this often
_USERNAME_RE = compile_pattern(r"[a-z0-9][a-z0-9._@-]{0,63}")


class AuthError(ValueError):
    """A request to change accounts that is refused; the message is for the operator."""


@dataclass(frozen=True)
class User:
    id: str
    username: str
    display_name: str
    auth_source: str
    role: str
    disabled: bool

    def has_role(self, minimum: str) -> bool:
        return ROLE_RANK[self.role] >= ROLE_RANK[minimum]


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _ts(moment: datetime) -> str:
    # Fixed width, so the text compares as the time does (api.db.now_iso drops zero microseconds).
    return moment.astimezone(timezone.utc).isoformat(timespec="microseconds")


def _parse(value: str) -> datetime:
    return datetime.fromisoformat(value)


def hash_secret(secret: str) -> str:
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()


def normalise_username(username: str) -> str:
    """The stored form of a username (lower case, no surrounding spaces).  Raises
    AuthError for one that is empty, too long or holds a character outside
    letters, digits and `._@-`."""
    name = username.strip().lower()
    if not _USERNAME_RE.fullmatch(name):
        raise AuthError("a username has 1 to 64 characters: letters, digits and . _ @ - (not first)")
    return name


_USER_COLUMNS = "id, username, display_name, auth_source, role, disabled"


def _user(row) -> User:
    return User(row["id"], row["username"], row["display_name"], row["auth_source"], row["role"],
                bool(row["disabled"]))


# ── Accounts ─────────────────────────────────────────────────────────────────

def create_user(username: str, role: str, *, password: str | None = None, display_name: str = "",
                auth_source: str = "local", oidc_subject: str | None = None) -> User:
    """Insert an account.  A local one needs a password; an OIDC one a subject and
    no password.  Raises AuthError for a bad role, a bad username or a password the
    policy refuses, and for a username already taken."""
    if role not in ROLES:
        raise AuthError(f"the role must be one of {', '.join(ROLES)}")
    name = normalise_username(username)
    if auth_source == "local":
        if password is None:
            raise AuthError("a local account needs a password")
        try:
            hashed: str | None = passwords.hash_password(password)
        except ValueError as exc:
            raise AuthError(str(exc)) from None
    elif auth_source == "oidc":
        if not oidc_subject:
            raise AuthError("an OIDC account needs a subject")
        hashed = None
    else:
        raise AuthError("auth_source must be local or oidc")
    conn = get_conn()
    if conn.execute("SELECT 1 FROM users WHERE username=?", (name,)).fetchone():
        raise AuthError(f"the username {name!r} is taken")
    uid = str(uuid4())
    conn.execute(
        "INSERT INTO users (id, username, display_name, auth_source, oidc_subject, password_hash, role, "
        "disabled, created_at) VALUES (?,?,?,?,?,?,?,0,?)",
        (uid, name, display_name.strip() or name, auth_source, oidc_subject, hashed, role, _ts(_now())))
    return User(uid, name, display_name.strip() or name, auth_source, role, False)


def get_user(user_id: str) -> User | None:
    row = get_conn().execute(f"SELECT {_USER_COLUMNS} FROM users WHERE id=?", (user_id,)).fetchone()
    return _user(row) if row else None


def find_user(username: str) -> User | None:
    try:
        name = normalise_username(username)
    except AuthError:
        return None
    row = get_conn().execute(f"SELECT {_USER_COLUMNS} FROM users WHERE username=?", (name,)).fetchone()
    return _user(row) if row else None


def list_users() -> list[dict]:
    rows = get_conn().execute(
        "SELECT username, display_name, auth_source, role, disabled, created_at, last_login_at "
        "FROM users ORDER BY username").fetchall()
    return [dict(zip(r.keys(), r, strict=True)) for r in rows]


def admin_exists() -> bool:
    return get_conn().execute(
        "SELECT 1 FROM users WHERE role='admin' AND disabled=0").fetchone() is not None


def set_password(username: str, password: str) -> None:
    """Replace a local account's password and end its sessions.  Raises AuthError."""
    user = find_user(username)
    if user is None or user.auth_source != "local":
        raise AuthError("no local account with that username")
    try:
        hashed = passwords.hash_password(password)
    except ValueError as exc:
        raise AuthError(str(exc)) from None
    conn = get_conn()
    conn.execute("UPDATE users SET password_hash=? WHERE id=?", (hashed, user.id))
    conn.execute("DELETE FROM sessions WHERE user_id=?", (user.id,))
    clear_failures(user.username)


def set_disabled(username: str, disabled: bool = True) -> None:
    """Disable (or re-enable) an account; disabling ends its sessions and refuses its tokens.
    Raises AuthError for an unknown username."""
    user = find_user(username)
    if user is None:
        raise AuthError("no account with that username")
    conn = get_conn()
    conn.execute("UPDATE users SET disabled=? WHERE id=?", (1 if disabled else 0, user.id))
    if disabled:
        conn.execute("DELETE FROM sessions WHERE user_id=?", (user.id,))


def check_credentials(username: str, password: str) -> User | None:
    """The user a local sign-in names, or None.  The same work for an unknown
    username, a wrong password, an account with no password and a disabled one,
    so the answer tells none of them apart."""
    name = username.strip().lower()[:256]
    row = get_conn().execute(
        "SELECT id, username, display_name, auth_source, role, disabled, password_hash FROM users "
        "WHERE username=? AND auth_source='local'", (name,)).fetchone()
    ok = passwords.verify(password, row["password_hash"] if row else None)
    if not (ok and row and not row["disabled"]):
        return None
    if passwords.needs_rehash(row["password_hash"]):
        get_conn().execute("UPDATE users SET password_hash=? WHERE id=?",
                           (passwords.hash_password(password), row["id"]))
    return _user(row)


def mark_login(user_id: str) -> None:
    get_conn().execute("UPDATE users SET last_login_at=? WHERE id=?", (_ts(_now()), user_id))


# ── Lockout ──────────────────────────────────────────────────────────────────

def _failure_key(username: str) -> str:
    return username.strip().lower()[:256]


def record_failure(username: str) -> None:
    now = _now()
    conn = get_conn()
    conn.execute("DELETE FROM login_failures WHERE attempted_at < ?", (_ts(now - 2 * LOCK_WINDOW),))
    conn.execute("INSERT INTO login_failures (username, attempted_at) VALUES (?,?)",
                 (_failure_key(username), _ts(now)))


def clear_failures(username: str) -> None:
    get_conn().execute("DELETE FROM login_failures WHERE username=?", (_failure_key(username),))


def locked_until(username: str) -> datetime | None:
    """When the lockout of `username` ends, or None if it is not locked: LOCK_FAILURES
    failures within LOCK_WINDOW lock it until LOCK_WINDOW after the last of them.
    Unknown usernames count too, so the lock does not tell which exist."""
    now = _now()
    rows = get_conn().execute(
        "SELECT attempted_at FROM login_failures WHERE username=? AND attempted_at > ? ORDER BY attempted_at",
        (_failure_key(username), _ts(now - 2 * LOCK_WINDOW))).fetchall()
    times = [_parse(r["attempted_at"]) for r in rows]
    until = None
    for i in range(LOCK_FAILURES - 1, len(times)):
        if times[i] - times[i - LOCK_FAILURES + 1] <= LOCK_WINDOW:
            end = times[i] + LOCK_WINDOW
            if until is None or end > until:
                until = end
    return until if until is not None and until > now else None


# ── Sessions ─────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class Session:
    user: User
    csrf_token: str
    expires_at: datetime


def create_session(user_id: str) -> tuple[str, Session]:
    """A new session for `user_id`: (the session id for the cookie, the session).
    The id is returned once; the database keeps its hash."""
    user = get_user(user_id)
    if user is None:
        raise AuthError("no such user")
    session_id = secrets.token_urlsafe(32)
    csrf = secrets.token_urlsafe(32)
    now = _now()
    expires = now + timedelta(hours=session_ttl_hours())
    conn = get_conn()
    conn.execute("DELETE FROM sessions WHERE expires_at < ?", (_ts(now),))
    conn.execute("INSERT INTO sessions (id_hash, user_id, csrf_token, created_at, expires_at, last_seen_at) "
                 "VALUES (?,?,?,?,?,?)", (hash_secret(session_id), user_id, csrf, _ts(now), _ts(expires), _ts(now)))
    return session_id, Session(user, csrf, expires)


def find_session(session_id: str) -> Session | None:
    """The live session for a cookie value, or None (unknown, expired, user disabled).
    A hit slides the expiry by the session lifetime."""
    row = get_conn().execute(
        "SELECT s.id_hash, s.csrf_token, s.expires_at, s.last_seen_at, u.id, u.username, u.display_name, "
        "u.auth_source, u.role, u.disabled FROM sessions s JOIN users u ON u.id = s.user_id "
        "WHERE s.id_hash=?", (hash_secret(session_id),)).fetchone()
    if row is None:
        return None
    now = _now()
    expires = _parse(row["expires_at"])
    if expires <= now or row["disabled"]:
        return None
    if now - _parse(row["last_seen_at"]) >= _TOUCH_EVERY:
        expires = now + timedelta(hours=session_ttl_hours())
        get_conn().execute("UPDATE sessions SET last_seen_at=?, expires_at=? WHERE id_hash=?",
                           (_ts(now), _ts(expires), row["id_hash"]))
    return Session(_user(row), row["csrf_token"], expires)


def delete_session(session_id: str) -> None:
    get_conn().execute("DELETE FROM sessions WHERE id_hash=?", (hash_secret(session_id),))


def csrf_matches(session: Session, sent: str | None) -> bool:
    return bool(sent) and hmac.compare_digest(session.csrf_token.encode(), (sent or "").encode())


# ── API tokens ───────────────────────────────────────────────────────────────

def create_token(user_id: str, name: str, *, days: int = DEFAULT_TOKEN_DAYS) -> tuple[str, str]:
    """A bearer token for `user_id`: (the token, its id).  The token is returned
    once; the database keeps its hash.  Raises AuthError for an unknown user, an
    empty name or a lifetime under one day."""
    if get_user(user_id) is None:
        raise AuthError("no such user")
    name = name.strip()
    if not name or len(name) > 128:
        raise AuthError("a token needs a name of 1 to 128 characters")
    if days < 1:
        raise AuthError("a token lasts at least one day")
    token = TOKEN_PREFIX + secrets.token_urlsafe(32)
    token_id = str(uuid4())
    now = _now()
    get_conn().execute(
        "INSERT INTO api_tokens (id, user_id, name, token_hash, created_at, expires_at) VALUES (?,?,?,?,?,?)",
        (token_id, user_id, name, hash_secret(token), _ts(now), _ts(now + timedelta(days=days))))
    return token, token_id


def find_token_user(token: str) -> User | None:
    """The user a bearer token belongs to, or None (unknown, revoked, expired, user disabled)."""
    if not token.startswith(TOKEN_PREFIX):
        return None
    row = get_conn().execute(
        "SELECT t.id AS token_id, t.expires_at, t.revoked_at, t.last_used_at, u.id, u.username, u.display_name, "
        "u.auth_source, u.role, u.disabled FROM api_tokens t JOIN users u ON u.id = t.user_id "
        "WHERE t.token_hash=?", (hash_secret(token),)).fetchone()
    if row is None or row["revoked_at"] is not None or row["disabled"]:
        return None
    now = _now()
    if _parse(row["expires_at"]) <= now:
        return None
    if row["last_used_at"] is None or now - _parse(row["last_used_at"]) >= _TOUCH_EVERY:
        get_conn().execute("UPDATE api_tokens SET last_used_at=? WHERE id=?", (_ts(now), row["token_id"]))
    return _user(row)


def revoke_token(token_id: str) -> bool:
    cur = get_conn().execute("UPDATE api_tokens SET revoked_at=? WHERE id=? AND revoked_at IS NULL",
                             (_ts(_now()), token_id))
    return cur.rowcount > 0
