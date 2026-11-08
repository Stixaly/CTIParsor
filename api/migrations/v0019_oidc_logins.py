"""Version 19 — the sign-ins with an identity provider that are under way (ADR-0097 item 14, part B).

`oidc_logins` holds what the server must remember between sending the browser to the
identity provider and the browser coming back: the SHA-256 of the `state` (the value
itself travels in the URL), the `nonce`, the PKCE verifier and the page to return to.
A row is read once, then deleted, and lives 10 minutes.
Process state, not report data: the new table keys to nothing, so a worker of the
previous revision is not affected."""
from api.migrations import Migration, columns_exist, tables_exist

MIGRATION = Migration(
    version=19,
    name="oidc_logins",
    store="jobs",
    description="oidc_logins: the pending OIDC authorization requests",
    is_applied=lambda conn: (
        tables_exist(conn, "oidc_logins")
        and columns_exist(conn, "oidc_logins", "state_hash", "nonce", "code_verifier", "next_path",
                          "created_at", "expires_at")),
    statements=(
        "CREATE TABLE IF NOT EXISTS oidc_logins ("
        " state_hash TEXT PRIMARY KEY, nonce TEXT NOT NULL, code_verifier TEXT NOT NULL,"
        " next_path TEXT NOT NULL, created_at TEXT NOT NULL, expires_at TEXT NOT NULL)",
        "CREATE INDEX IF NOT EXISTS idx_oidc_logins_expires ON oidc_logins(expires_at)",
    ),
)
