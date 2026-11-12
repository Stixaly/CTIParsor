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
from typing import Any
from uuid import uuid4

from api.auth import passwords
from api.auth.config import DEFAULT_TOKEN_DAYS, ROLE_RANK, ROLES, session_ttl_hours
from api.db import get_conn, transaction
from pipeline.regex_safety import compile_pattern

TOKEN_PREFIX = "ctp_"                      # noqa: S105 - the start of every token, not a secret
LOCK_FAILURES = 5                       # failures for one username ...
LOCK_WINDOW = timedelta(minutes=15)     # ... within this window lock it for this long
_TOUCH_EVERY = timedelta(minutes=1)     # a session's or token's last-seen time is written at most this often
_USERNAME_RE = compile_pattern(r"[a-z0-9][a-z0-9._@-]{0,63}")


class AuthError(ValueError):
    """A request to change accounts or tokens that is refused: a bad username, role, password,
    token name or lifetime, or an unknown user.  The message is for the operator.
    The admin routes (api/routes/admin.py) answer 400 with it; the admin CLI (api/admin.py)
    prints `refused: <message>` and exits 1.  The OIDC sign-in catches it to try another
    username (api/auth/oidc.py)."""


class UsernameTakenError(AuthError):
    """The username of a new account is taken.  POST /api/admin/users answers 409 with the message."""


class LastAdminError(AuthError):
    """A role or disabled change that would leave no enabled admin.  PATCH /api/admin/users/{user_id}
    answers 409 with the message; the admin CLI prints it as `refused` (exit 1)."""


@dataclass(frozen=True)
class User:
    id: str
    username: str
    display_name: str
    auth_source: str
    role: str
    disabled: bool

    def has_role(self, minimum: str) -> bool:
        """True when the account's role is at least `minimum`, in the order reader, analyst, admin."""
        return ROLE_RANK[self.role] >= ROLE_RANK[minimum]


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _ts(moment: datetime) -> str:
    # Fixed width, so the text compares as the time does (api.db.now_iso drops zero microseconds).
    return moment.astimezone(timezone.utc).isoformat(timespec="microseconds")


def _parse(value: str) -> datetime:
    return datetime.fromisoformat(value)


def hash_secret(secret: str) -> str:
    """The SHA-256 of a secret, as hex. The database keeps this hash in place of a session id or a token."""
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()


def normalise_username(username: str) -> str:
    """The stored form of a username (lower case, no surrounding spaces).  Raises
    AuthError for one that is empty, too long or holds a character outside
    letters, digits and `._@-`."""
    name = username.strip().lower()
    try:
        matched = _USERNAME_RE.fullmatch(name)
    except UnicodeEncodeError:                  # a lone surrogate: re2 cannot encode it, so it is no name (#616)
        matched = None
    if not matched:
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
        raise UsernameTakenError(f"the username {name!r} is taken")
    uid = str(uuid4())
    conn.execute(
        "INSERT INTO users (id, username, display_name, auth_source, oidc_subject, password_hash, role, "
        "disabled, created_at) VALUES (?,?,?,?,?,?,?,0,?)",
        (uid, name, display_name.strip() or name, auth_source, oidc_subject, hashed, role, _ts(_now())))
    return User(uid, name, display_name.strip() or name, auth_source, role, False)


def get_user(user_id: str) -> User | None:
    """The account with this id, or None."""
    row = get_conn().execute(f"SELECT {_USER_COLUMNS} FROM users WHERE id=?", (user_id,)).fetchone()
    return _user(row) if row else None


def find_user(username: str) -> User | None:
    """The account with this username, or None. A name that is not a valid username matches no account."""
    try:
        name = normalise_username(username)
    except AuthError:
        return None
    row = get_conn().execute(f"SELECT {_USER_COLUMNS} FROM users WHERE username=?", (name,)).fetchone()
    return _user(row) if row else None


def list_users() -> list[dict]:
    """Every account, ordered by username, as dicts that have no password field."""
    rows = get_conn().execute(
        "SELECT id, username, display_name, auth_source, role, disabled, created_at, last_login_at "
        "FROM users ORDER BY username").fetchall()
    return [dict(zip(r.keys(), r, strict=True)) for r in rows]


def user_record(user_id: str) -> dict | None:
    """One row of `list_users`, or None."""
    row = get_conn().execute(
        "SELECT id, username, display_name, auth_source, role, disabled, created_at, last_login_at "
        "FROM users WHERE id=?", (user_id,)).fetchone()
    return dict(zip(row.keys(), row, strict=True)) if row else None


def update_user(user_id: str, *, role: str | None = None, disabled: bool | None = None,
                display_name: str | None = None) -> User:
    """Change an account's role, disabled flag and display name (what is None stays).
    Disabling ends the account's sessions; its tokens stay in the table but are refused
    while it is disabled, and work again when it is enabled.  Raises AuthError for an
    unknown user or role, and LastAdminError when the change would leave no enabled admin."""
    user = get_user(user_id)
    if user is None:
        raise AuthError("no such user")
    if role is not None and role not in ROLES:
        raise AuthError(f"the role must be one of {', '.join(ROLES)}")
    name = user.display_name if display_name is None else display_name.strip() or user.username
    new_role = user.role if role is None else role
    new_disabled = user.disabled if disabled is None else disabled
    conn = get_conn()
    with transaction(conn):
        # One change at a time, so two admins cannot each remove the other.
        conn.execute("SELECT pg_advisory_xact_lock(hashtext('ctiparsor.admins'))")
        if user.role == "admin" and not user.disabled and (new_role != "admin" or new_disabled):
            others = conn.execute("SELECT 1 FROM users WHERE role='admin' AND disabled=0 AND id<>?",
                                  (user_id,)).fetchone()
            if others is None:
                raise LastAdminError("this is the last enabled admin; make another admin first")
        conn.execute("UPDATE users SET role=?, disabled=?, display_name=? WHERE id=?",
                     (new_role, 1 if new_disabled else 0, name, user_id))
        if new_disabled:
            conn.execute("DELETE FROM sessions WHERE user_id=?", (user_id,))
    return User(user.id, user.username, name, user.auth_source, new_role, new_disabled)


def admin_exists() -> bool:
    """True when an enabled admin account exists."""
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
                           (passwords.rehash(password), row["id"]))
    return _user(row)


def mark_login(user_id: str) -> None:
    """Record the time of a successful sign-in on the account."""
    get_conn().execute("UPDATE users SET last_login_at=? WHERE id=?", (_ts(_now()), user_id))


# ── Lockout ──────────────────────────────────────────────────────────────────

def _failure_key(username: str) -> str:
    return username.strip().lower()[:256]


def begin_attempt(username: str) -> datetime | None:
    """Count a sign-in attempt for `username` BEFORE its password is checked.

    Returns when the lockout ends if the username is locked (LOCK_FAILURES attempts
    within LOCK_WINDOW; the attempt is then refused and not counted), else None after
    recording the attempt: the caller checks the password, and `clear_failures` on a
    success.  The count and the insert run in one transaction under a per-username
    lock, so a burst of parallel requests makes at most LOCK_FAILURES password checks.
    Unknown usernames are counted too, so the lock does not tell which exist.
    """
    key = _failure_key(username)
    now = _now()
    conn = get_conn()
    with transaction(conn):
        conn.execute("SELECT pg_advisory_xact_lock(hashtext('ctiparsor.login'), hashtext(?))", (key,))
        conn.execute("DELETE FROM login_failures WHERE attempted_at < ?", (_ts(now - 2 * LOCK_WINDOW),))
        rows = conn.execute("SELECT attempted_at FROM login_failures WHERE username=? ORDER BY attempted_at",
                            (key,)).fetchall()
        until = _lock_end([_parse(r["attempted_at"]) for r in rows], now)
        if until is None:
            conn.execute("INSERT INTO login_failures (username, attempted_at) VALUES (?,?)", (key, _ts(now)))
    return until


def clear_failures(username: str) -> None:
    """Forget the failed sign-in attempts recorded for this username."""
    get_conn().execute("DELETE FROM login_failures WHERE username=?", (_failure_key(username),))


def locked_until(username: str) -> datetime | None:
    """When the lockout of `username` ends, or None if it is not locked: LOCK_FAILURES
    failures within LOCK_WINDOW lock it until LOCK_WINDOW after the last of them.
    Unknown usernames count too, so the lock does not tell which exist."""
    now = _now()
    rows = get_conn().execute(
        "SELECT attempted_at FROM login_failures WHERE username=? AND attempted_at > ? ORDER BY attempted_at",
        (_failure_key(username), _ts(now - 2 * LOCK_WINDOW))).fetchall()
    return _lock_end([_parse(r["attempted_at"]) for r in rows], now)


def _lock_end(times: list[datetime], now: datetime) -> datetime | None:
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
    refreshed: bool = False       # find_session slid the expiry: the browser's cookie needs the new Max-Age


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
    refreshed = now - _parse(row["last_seen_at"]) >= _TOUCH_EVERY
    if refreshed:
        expires = now + timedelta(hours=session_ttl_hours())
        get_conn().execute("UPDATE sessions SET last_seen_at=?, expires_at=? WHERE id_hash=?",
                           (_ts(now), _ts(expires), row["id_hash"]))
    return Session(_user(row), row["csrf_token"], expires, refreshed)


def delete_session(session_id: str) -> None:
    """Delete the session with this id."""
    get_conn().execute("DELETE FROM sessions WHERE id_hash=?", (hash_secret(session_id),))


def csrf_matches(session: Session, sent: str | None) -> bool:
    """True when the sent CSRF token is the session's token, compared in constant time;
    False when no token was sent."""
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


_SELECT_API_TOKENS = ("SELECT t.id, t.name, t.user_id, u.username, t.created_at, t.expires_at, t.revoked_at, "
                 "t.last_used_at FROM api_tokens t JOIN users u ON u.id = t.user_id")


def list_tokens(username: str | None = None, *, user_id: str | None = None) -> list[dict]:
    """The tokens (never the secrets), newest first; those of one user when `username`
    or `user_id` is given."""
    sql = _SELECT_API_TOKENS
    params: tuple[Any, ...] = ()
    if username is not None:
        sql += " WHERE u.username=?"
        params = (normalise_username(username),)
    elif user_id is not None:
        sql += " WHERE t.user_id=?"
        params = (user_id,)
    rows = get_conn().execute(sql + " ORDER BY t.created_at DESC", params).fetchall()
    return [dict(zip(r.keys(), r, strict=True)) for r in rows]


def get_token(token_id: str) -> dict | None:
    """One token's record (never the secret), or None."""
    row = get_conn().execute(_SELECT_API_TOKENS + " WHERE t.id=?", (token_id,)).fetchone()
    return dict(zip(row.keys(), row, strict=True)) if row else None


def revoke_token(token_id: str, *, user_id: str | None = None) -> bool:
    """Revoke a token that is not revoked yet; with `user_id`, only if it is that user's.
    False when there is nothing to revoke."""
    sql = "UPDATE api_tokens SET revoked_at=? WHERE id=? AND revoked_at IS NULL"
    params: tuple[Any, ...] = (_ts(_now()), token_id)
    if user_id is not None:
        sql += " AND user_id=?"
        params += (user_id,)
    return get_conn().execute(sql, params).rowcount > 0


# ── Sign-in with an identity provider (api/auth/oidc.py) ─────────────────────

OIDC_LOGIN_TTL = timedelta(minutes=10)
OIDC_LOGIN_CAP = 2000                       # pending requests at most: the login route is open


def begin_oidc_login(state: str, nonce: str, code_verifier: str, next_path: str, binding: str) -> bool:
    """Remember a pending authorization request for 10 minutes, under the SHA-256 of
    `state`, with the SHA-256 of `binding` (the value of the browser's cookie).  Returns False,
    storing nothing, when OIDC_LOGIN_CAP are already pending."""
    now = _now()
    conn = get_conn()
    conn.execute("DELETE FROM oidc_logins WHERE expires_at < ?", (_ts(now),))
    if conn.execute("SELECT COUNT(*) AS n FROM oidc_logins").fetchone()["n"] >= OIDC_LOGIN_CAP:
        return False
    conn.execute("INSERT INTO oidc_logins (state_hash, nonce, code_verifier, next_path, binding_hash, created_at, "
                 "expires_at) VALUES (?,?,?,?,?,?,?)",
                 (hash_secret(state), nonce, code_verifier, next_path, hash_secret(binding), _ts(now),
                  _ts(now + OIDC_LOGIN_TTL)))
    return True


def consume_oidc_login(state: str, binding: str | None = None) -> dict | None:
    """The pending request for `state` as {nonce, code_verifier, next_path}, deleted in the
    same statement so that it is read once; None when unknown, used, expired, or when
    `binding` (the browser's cookie) is missing or is not the one the request started with.
    A request found with the wrong binding is deleted all the same."""
    row = get_conn().execute(
        "DELETE FROM oidc_logins WHERE state_hash=? "
        "RETURNING nonce, code_verifier, next_path, binding_hash, expires_at", (hash_secret(state),)).fetchone()
    if row is None or _parse(row["expires_at"]) <= _now():
        return None
    if not binding or not hmac.compare_digest(hash_secret(binding).encode(), row["binding_hash"].encode()):
        return None
    return {"nonce": row["nonce"], "code_verifier": row["code_verifier"], "next_path": row["next_path"]}


def find_oidc_user(subject: str) -> User | None:
    """The OIDC account whose subject (the identity provider's id for the user) is this one, or None."""
    row = get_conn().execute(f"SELECT {_USER_COLUMNS} FROM users WHERE auth_source='oidc' AND oidc_subject=?",
                             (subject,)).fetchone()
    return _user(row) if row else None


def set_role(user_id: str, role: str) -> None:
    """Set the role of an account. Raise AuthError when the role is not one of ROLES."""
    if role not in ROLES:
        raise AuthError(f"the role must be one of {', '.join(ROLES)}")
    get_conn().execute("UPDATE users SET role=? WHERE id=?", (role, user_id))


def end_sessions(user_id: str) -> None:
    """End every session of the account."""
    get_conn().execute("DELETE FROM sessions WHERE user_id=?", (user_id,))
