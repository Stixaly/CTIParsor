"""Which PostgreSQL cluster each database was on (ADR-0077 part B, 9).

A new PostgreSQL major that starts on an empty data directory gives the app an
empty database, and nothing in the database itself can tell that from a fresh
install.  The state volume can: every start records, for the address the app
connects to, the cluster's `system_identifier` and the schema version, in
`<state>/db-identity.json`.  At the next start, an EMPTY database at the same
address on ANOTHER cluster, where the record says data existed, stops the
start — the data was left behind, not deleted.  A database restored from a
dump (another cluster, tables present) is accepted and recorded; so is any
database at an address with no record.

The record is a convenience for one failure; it never blocks on its own
problems: an unreadable file, a cluster that hides its identifier, a state
directory that cannot be written are logged and ignored.
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from api.logging_config import get_logger
from api.paths import state_dir

logger = get_logger(__name__)

FILE = "db-identity.json"


def _path() -> Path:
    return state_dir() / FILE


def address(conn: Any) -> str:
    """host:port/database/schema — what the app connects to, not the cluster
    behind it (in compose, `postgres:5432/ctiparsor/public` across upgrades)."""
    host = port = ""
    url = getattr(conn, "url", None)
    if url:
        try:
            from psycopg.conninfo import conninfo_to_dict
            info = conninfo_to_dict(url)
            host, port = str(info.get("host") or ""), str(info.get("port") or "5432")
        except Exception as exc:   # an address we cannot parse still has a database and schema
            logger.debug(f"[db] DATABASE_URL not parsed for its host: {exc}")
    row = conn.execute("SELECT current_database() AS db, current_schema() AS schema").fetchone()
    return f"{host}:{port}/{row['db']}/{row['schema']}"


def system_identifier(conn: Any) -> str | None:
    try:
        row = conn.execute("SELECT system_identifier::text AS sid FROM pg_control_system()").fetchone()
        return row["sid"] if row else None
    except Exception as exc:   # a server that does not let this role read it
        logger.debug(f"[db] cluster identifier unavailable: {exc}")
        return None


def _load() -> dict:
    try:
        data = json.loads(_path().read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except FileNotFoundError:
        return {}
    except Exception as exc:
        logger.warning(f"[db] {_path()} unreadable, ignored: {exc}")
        return {}


def refusal(conn: Any, *, empty: bool) -> str | None:
    """Why this start must stop, or None.  `empty`: no CTIParsor table and no
    migration record in the database."""
    if not empty:
        return None
    where = address(conn)
    seen = _load().get(where)
    if not isinstance(seen, dict) or not seen.get("schema_version"):
        return None
    now = system_identifier(conn)
    if now is None or now == seen.get("system_identifier"):
        return None
    return (
        f"the database at {where} is empty, and on another PostgreSQL cluster than the one where it "
        f"had schema version {seen['schema_version']} (cluster {seen.get('system_identifier')}, "
        f"recorded {seen.get('recorded_at', '?')}; now {now}).  PostgreSQL was replaced without moving "
        f"the data: run `make db-upgrade` (docs/upgrading.md).  If an empty database is what you want, "
        f"delete the entry for {where} in {_path()} and start again."
    )


def record(conn: Any, version: int) -> None:
    """Remember this database's cluster and version, for the next start."""
    sid = system_identifier(conn)
    if sid is None:
        return
    where = address(conn)
    data = _load()
    seen = data.get(where)
    if isinstance(seen, dict) and seen.get("system_identifier") not in (None, sid):
        logger.info(f"[db] {where} is now on cluster {sid} (was {seen.get('system_identifier')}), "
                    f"with its data: recorded")
    data[where] = {"system_identifier": sid, "schema_version": version,
                   "recorded_at": datetime.now(timezone.utc).isoformat(timespec="seconds")}
    path = _path()
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_name(f".{FILE}.{os.getpid()}")
        tmp.write_text(json.dumps(data, indent=1, sort_keys=True) + "\n", encoding="utf-8")
        os.replace(tmp, path)     # one writer at a time is the migration lock's job
    except OSError as exc:
        logger.warning(f"[db] could not record the database's cluster in {path}: {exc}")
