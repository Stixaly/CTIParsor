"""Version 18 — users, sessions, API tokens and who imported a report (ADR-0097 items 14 and 15).

`users` holds the accounts: a local one carries an Argon2id `password_hash`, an
OIDC one an `oidc_subject` and no hash (`auth_source`).  `sessions` holds the
server-side web sessions, keyed by the SHA-256 of the session id — the id itself
is never stored; `api_tokens` holds the bearer tokens the same way
(`token_hash`).  `login_failures` is what the sign-in lockout counts, in the
database so that several processes agree.  `jobs.imported_by` is the id of the
user who imported the report: a row stored before this version stays NULL, and
only an admin deletes it.
Process and access state, not report data: the new tables key to nothing in the
report tables, and the new column is nullable, so a worker of the previous
revision keeps inserting `jobs` rows."""
from api.migrations import Migration, columns_exist, tables_exist

MIGRATION = Migration(
    version=18,
    name="auth",
    store="jobs",
    description="users, sessions, api_tokens, login_failures; jobs.imported_by",
    is_applied=lambda conn: (
        tables_exist(conn, "users", "sessions", "api_tokens", "login_failures")
        and columns_exist(conn, "users", "id", "username", "display_name", "auth_source", "oidc_subject",
                          "password_hash", "role", "disabled", "created_at", "last_login_at")
        and columns_exist(conn, "sessions", "id_hash", "user_id", "csrf_token", "created_at", "expires_at",
                          "last_seen_at")
        and columns_exist(conn, "api_tokens", "id", "user_id", "name", "token_hash", "created_at", "expires_at",
                          "revoked_at", "last_used_at")
        and columns_exist(conn, "login_failures", "username", "attempted_at")
        and columns_exist(conn, "jobs", "imported_by")),
    statements=(
        "CREATE TABLE IF NOT EXISTS users ("
        " id TEXT PRIMARY KEY, username TEXT NOT NULL UNIQUE, display_name TEXT NOT NULL DEFAULT '',"
        " auth_source TEXT NOT NULL CHECK (auth_source IN ('local','oidc')),"
        " oidc_subject TEXT UNIQUE, password_hash TEXT,"
        " role TEXT NOT NULL CHECK (role IN ('reader','analyst','admin')),"
        " disabled INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL, last_login_at TEXT)",
        "CREATE TABLE IF NOT EXISTS sessions ("
        " id_hash TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,"
        " csrf_token TEXT NOT NULL, created_at TEXT NOT NULL, expires_at TEXT NOT NULL,"
        " last_seen_at TEXT NOT NULL)",
        "CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id)",
        "CREATE TABLE IF NOT EXISTS api_tokens ("
        " id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,"
        " name TEXT NOT NULL, token_hash TEXT NOT NULL UNIQUE, created_at TEXT NOT NULL,"
        " expires_at TEXT NOT NULL, revoked_at TEXT, last_used_at TEXT)",
        "CREATE INDEX IF NOT EXISTS idx_api_tokens_user ON api_tokens(user_id)",
        "CREATE TABLE IF NOT EXISTS login_failures ("
        " username TEXT NOT NULL, attempted_at TEXT NOT NULL)",
        "CREATE INDEX IF NOT EXISTS idx_login_failures_username ON login_failures(username, attempted_at)",
        "ALTER TABLE jobs ADD COLUMN IF NOT EXISTS imported_by TEXT",
    ),
)
