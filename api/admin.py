"""Manage local accounts and API tokens from the command line (ADR-0097 items 14 and 15).

    python -m api.admin create-admin --username alice            # prompts for the password twice
    python -m api.admin create-admin --username alice --password-file /run/secrets/admin_password
    python -m api.admin set-password --username alice
    python -m api.admin disable --username alice                 # --enable reverses it
    python -m api.admin list-users
    python -m api.admin create-token --user alice --name ci --days 90
    python -m api.admin list-tokens [--user alice]
    python -m api.admin revoke-token --id TOKEN_ID

It uses the database `DATABASE_URL` names and brings its schema to this code's
version first, as the API does.  A password is read from a prompt or a file, never
from an argument (the process list shows arguments) and is never printed; a token
is printed once, on standard output, and cannot be read back.
"""
from __future__ import annotations

import argparse
import getpass
import sys
from pathlib import Path

from api import audit
from api.auth import store
from api.auth.config import DEFAULT_TOKEN_DAYS, ROLES


def _read_password(password_file: str | None) -> str:
    if password_file:
        path = Path(password_file)
        if path.stat().st_mode & 0o077:
            print(f"warning: {path} can be read by other users; keep a password file to its owner (chmod 600)",
                  file=sys.stderr)
        text = path.read_text(encoding="utf-8").removesuffix("\n").removesuffix("\r")
        if not text:
            raise store.AuthError(f"the password file {path} is empty")
        return text
    first = getpass.getpass("Password: ")
    if getpass.getpass("Password (again): ") != first:
        raise store.AuthError("the two passwords differ")
    return first


def _create_admin(args: argparse.Namespace) -> int:
    if store.admin_exists() and not args.force:
        raise store.AuthError("an admin already exists; use --force to create another one")
    user = store.create_user(args.username, "admin", password=_read_password(args.password_file),
                             display_name=args.display_name or "")
    audit.record_cli("create-admin", {"username": user.username})
    print(f"admin {user.username} created")
    return 0


def _create_user(args: argparse.Namespace) -> int:
    user = store.create_user(args.username, args.role, password=_read_password(args.password_file),
                             display_name=args.display_name or "")
    audit.record_cli("create-user", {"username": user.username})
    print(f"{user.role} {user.username} created")
    return 0


def _set_password(args: argparse.Namespace) -> int:
    store.set_password(args.username, _read_password(args.password_file))
    audit.record_cli("set-password", {"username": args.username})
    print(f"password of {args.username} changed; its sessions ended")
    return 0


def _disable(args: argparse.Namespace) -> int:
    store.set_disabled(args.username, disabled=not args.enable)
    audit.record_cli("disable", {"username": args.username, "enabled": args.enable})
    print(f"{args.username} {'enabled' if args.enable else 'disabled'}")
    return 0


def _list_users(_args: argparse.Namespace) -> int:
    users = store.list_users()
    for u in users:
        print(f"{u['username']:<24} {u['role']:<8} {u['auth_source']:<6} "
              f"{'disabled' if u['disabled'] else 'active':<9} last sign-in: {u['last_login_at'] or '-'}")
    if not users:
        print("no users")
    return 0


def _create_token(args: argparse.Namespace) -> int:
    user = store.find_user(args.user)
    if user is None:
        raise store.AuthError(f"no user {args.user!r}")
    token, token_id = store.create_token(user.id, args.name, days=args.days)
    audit.record_cli("create-token", {"username": user.username, "token_id": token_id})
    print("This token is shown once; store it now.", file=sys.stderr)
    print(token)
    return 0


def _list_tokens(args: argparse.Namespace) -> int:
    tokens = store.list_tokens(args.user)
    for t in tokens:
        state = "revoked" if t["revoked_at"] else "active"
        print(f"{t['id']}  {t['username']:<20} {t['name']:<24} {state:<8} expires {t['expires_at']}  "
              f"last used {t['last_used_at'] or '-'}")
    if not tokens:
        print("no tokens")
    return 0


def _revoke_token(args: argparse.Namespace) -> int:
    if not store.revoke_token(args.id):
        raise store.AuthError(f"no active token with the id {args.id!r}")
    audit.record_cli("revoke-token", {"token_id": args.id})
    print(f"token {args.id} revoked")
    return 0


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m api.admin", description=__doc__.split("\n\n")[0])
    sub = parser.add_subparsers(dest="command", required=True)

    def password_args(p: argparse.ArgumentParser) -> None:
        """Add the --password-file option to a sub-command's parser."""
        p.add_argument("--password-file", help="read the password from this file instead of prompting")

    p = sub.add_parser("create-admin", help="create the first admin")
    p.add_argument("--username", required=True)
    p.add_argument("--display-name")
    p.add_argument("--force", action="store_true", help="create another admin when one exists")
    password_args(p)
    p.set_defaults(run=_create_admin)

    p = sub.add_parser("create-user", help="create a local account")
    p.add_argument("--username", required=True)
    p.add_argument("--role", choices=ROLES, default="reader")
    p.add_argument("--display-name")
    password_args(p)
    p.set_defaults(run=_create_user)

    p = sub.add_parser("set-password", help="change a local account's password")
    p.add_argument("--username", required=True)
    password_args(p)
    p.set_defaults(run=_set_password)

    p = sub.add_parser("disable", help="disable an account (ends its sessions, refuses its tokens)")
    p.add_argument("--username", required=True)
    p.add_argument("--enable", action="store_true", help="enable it again")
    p.set_defaults(run=_disable)

    p = sub.add_parser("list-users", help="list the accounts")
    p.set_defaults(run=_list_users)

    p = sub.add_parser("create-token", help="create an API token for a user")
    p.add_argument("--user", required=True)
    p.add_argument("--name", required=True, help="what the token is for")
    p.add_argument("--days", type=int, default=DEFAULT_TOKEN_DAYS, help="lifetime in days (default 90)")
    p.set_defaults(run=_create_token)

    p = sub.add_parser("list-tokens", help="list the tokens (never their secrets)")
    p.add_argument("--user", help="only this user's tokens")
    p.set_defaults(run=_list_tokens)

    p = sub.add_parser("revoke-token", help="revoke a token by its id (see list-tokens)")
    p.add_argument("--id", required=True)
    p.set_defaults(run=_revoke_token)
    return parser


def main(argv: list[str] | None = None) -> int:
    """Entry point of `python -m api.admin`: run the chosen command and return its exit code, 1 when it is refused or
    the database fails."""
    args = _parser().parse_args(argv)
    from api.db import DB_ERRORS, init_db
    from api.logging_config import setup_logging
    from api.migrate import MigrationError

    setup_logging()
    database_errors: tuple[type[BaseException], ...] = (*DB_ERRORS, MigrationError, RuntimeError)
    # The audit lines of a change go to standard error: standard output carries the token of create-token.
    with audit.lines_to(sys.stderr):
        try:
            init_db()
            return args.run(args)
        except (store.AuthError, OSError, UnicodeDecodeError, OverflowError) as exc:
            print(f"refused: {exc}", file=sys.stderr)
        except database_errors as exc:
            print(f"database error: {str(exc).strip().splitlines()[0] if str(exc).strip() else type(exc).__name__}",
                  file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
