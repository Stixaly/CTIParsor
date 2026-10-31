"""A backup of a used install restores into an empty one with every row,
schema object and file it held, and this code reads it back (ADR-0094 item 3).

    python scripts/check_backup_restore.py [--pg-container NAME]

It runs the commands of docs/docker.md ("Data and backups"), with their
flags, on the PostgreSQL server CTIPARSOR_TEST_DATABASE_URL names, in
throwaway databases and directories:

1. the source: a new database and a state directory laid out as the image's
   volume (uploads/, output/); this code's first start (`init_db`: the schema,
   and the database recorded in db-identity.json), then the rows and files of
   a used install (scripts/migration_seed.py), every table covered;
2. the backup: `pg_dump -U <user> -d <source> -Fc`, which `pg_restore -l` must
   list whole, and `tar czf - -C <state> .`.  pg_dump and pg_restore run in
   the server's own container (`docker exec`: --pg-container NAME, or
   CTIPARSOR_TEST_PG_CONTAINER), as in the docs; without one, on this host,
   when its pg_dump and pg_restore are as new as the server.  The dump and the
   archive are readable by their owner only, as the docs' `umask 077` makes
   them;
3. the restore, database first, as the docs order it: into a new, empty
   database, `pg_restore -U <user> -d <target> --single-transaction`, which
   must exit 0 and print nothing; then `tar xzf - --keep-old-files -C <dir>`
   into an empty directory;
4. the target against the source, exactly: every table, row, value and column
   type, and no table, column or row more (scripts/migration_compare.py,
   strict); the state of each sequence; the definition of every table, column,
   constraint, index, trigger, function and sequence; every file and
   directory of the state directory, byte for byte;
5. this code's app starts on the restored database and directory, and its
   routes read the seed back (scripts/migration_readback.py);
6. the target against the source again: the app's start changed nothing in
   the database, and no file but db-identity.json, where the source's entry
   stays as it was and the target's is added, on the same cluster.

Exit 0 when everything came back, 1 on a difference or a command that failed,
2 when the check cannot run: no CTIPARSOR_TEST_DATABASE_URL or no user in it,
a server it cannot reach or create a database on, no pg_dump to run.  The
databases and the directory are removed whatever happens.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlsplit
from uuid import uuid4

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:      # run as a script: the repository root is not on the path
    sys.path.insert(0, str(ROOT))

from scripts import migration_compare, migration_seed
from scripts.check_migration_from import IDENTITY_FILE, Failed, Unusable, environment, identity, run, tail

PREFIX = "ctiparsor_restorecheck_"
CONTAINER_VARIABLE = "CTIPARSOR_TEST_PG_CONTAINER"


@dataclass(frozen=True)
class Tools:
    """Where pg_dump and pg_restore run: the words before theirs (`docker
    exec` into the server's container, or none) and their environment.  The
    password travels in PGPASSWORD, never on a command line."""
    prefix: tuple[str, ...]
    env: dict[str, str]
    version: str

    def command(self, *args: str) -> list[str]:
        return [*self.prefix, *args]


def major(version: str) -> int | None:
    """17 for "pg_dump (PostgreSQL) 17.11", 18 for "... 18.1 (Debian 18.1-1)"."""
    found = re.search(r"\)\s*(\d+)", version)
    return int(found.group(1)) if found else None


def tools(admin_url: str, container: str | None, server_major: int) -> Tools:
    """pg_dump and pg_restore for this server: its container's own, or this
    host's when both are at least as new as the server.  Unusable otherwise."""
    parts = urlsplit(admin_url)
    env = dict(os.environ)
    env.pop("PGPASSWORD", None)
    if parts.password:
        env["PGPASSWORD"] = unquote(parts.password)
    if container:
        prefix: tuple[str, ...] = ("docker", "exec", "-i", "-e", "PGPASSWORD", container)
        where = f"in container {container}"
    else:
        if shutil.which("pg_dump") is None:
            raise Unusable(f"no pg_dump on this host: name the PostgreSQL server's container (--pg-container "
                           f"NAME, or {CONTAINER_VARIABLE}) to run its own, or install pg_dump {server_major} "
                           "or newer")
        env.update(PGHOST=parts.hostname or "localhost", PGPORT=str(parts.port or 5432))
        prefix, where = (), "on this host"
    versions = []
    for program in ("pg_dump", "pg_restore"):
        probe = [*prefix, program, "--version"]
        try:
            done = subprocess.run(probe, env=env, capture_output=True, text=True)
        except OSError as exc:            # no docker on this host
            raise Unusable(f"{' '.join(probe)}: {exc}") from exc
        if done.returncode:
            raise Unusable(f"{' '.join(probe)} exited {done.returncode}: "
                           f"{' '.join((done.stderr or done.stdout).split())}")
        version = done.stdout.strip()
        found = major(version)
        if found is None or found < server_major:
            raise Unusable(f"{program} {where} is {version!r}, older than the server (PostgreSQL {server_major}), "
                           f"which it cannot dump or restore: name the server's container (--pg-container "
                           f"NAME, or {CONTAINER_VARIABLE})")
        versions.append(version)
    return Tools(prefix, env, f"{versions[0]}, {where}")


def tool(cmd: list[str], env: dict[str, str] | None, *, stdin: Path | None = None, stdout: Path | None = None,
         shown: int = 0, silent: bool = False) -> str:
    """Run one of the docs' commands, `< stdin` and `> stdout` as the docs
    write them; a file it writes is readable by its owner only (the docs'
    `umask 077`).  Failed when it exits non-zero or, `silent`, prints anything
    on stderr.  `shown`: the leading words (`docker exec ...`) the report
    leaves out.  Its stdout, when not redirected."""
    def private(path: Path) -> Any:
        return open(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "wb")

    with (stdin.open("rb") if stdin else open(os.devnull, "rb")) as given, \
            (private(stdout) if stdout else tempfile.TemporaryFile()) as taken:
        done = subprocess.run(cmd, stdin=given, stdout=taken, stderr=subprocess.PIPE, env=env)
        taken.seek(0)
        out = "" if stdout else taken.read().decode("utf-8", "replace")
    err = done.stderr.decode("utf-8", "replace")
    what = " ".join(cmd[shown:])
    if done.returncode:
        raise Failed(f"{what} exited {done.returncode}:\n{tail(err)}")
    if silent and err.strip():
        raise Failed(f"{what} exited 0 but printed:\n{tail(err)}")
    return out


def state_tree(state: Path) -> dict[str, str]:
    """{"file <path>": "sha256 <hex>", "directory <path>": "", "link <path>":
    its target} for everything under the state directory."""
    out: dict[str, str] = {}
    for p in sorted(state.rglob("*")):
        rel = p.relative_to(state).as_posix()
        if p.is_symlink():
            out[f"link {rel}"] = os.readlink(p)
        elif p.is_dir():
            out[f"directory {rel}"] = ""
        else:
            out[f"file {rel}"] = "sha256 " + hashlib.sha256(p.read_bytes()).hexdigest()
    return out


@dataclass
class Read:
    """What the comparison reads of a database."""
    content: migration_compare.Snapshot
    sequences: dict[str, str]
    objects: dict[str, str]


def read(url: str, connect: Any) -> Read:
    conn = connect(url)
    try:
        return Read(migration_compare.snapshot(conn), migration_compare.sequence_states(conn),
                    migration_compare.schema_objects(conn))
    finally:
        conn.close()


def differences(source: Read, target: Read, label: str) -> list[str]:
    """The target against the source, exactly; printed under `label`."""
    result = migration_compare.compare(source.content, target.content, strict=True)
    for line in migration_compare.summary(result, label):
        print(line)
    moved = migration_compare.object_differences(source.sequences, target.sequences)
    print(f"{label}, sequences: {len(source.sequences)}; "
          + (f"{len(moved)} difference(s)" if moved else "each one where the source's stood"))
    changed = migration_compare.object_differences(source.objects, target.objects)
    print(f"{label}, schema: {len(source.objects)} objects (tables, columns, constraints, indexes, triggers, "
          "functions, sequences, extensions); "
          + (f"{len(changed)} difference(s)" if changed else "each one defined as in the source"))
    for diff in moved + changed:
        print(f"  DIFF {diff.line()}")
    return [d.line() for d in result.differences + moved + changed]


def identity_differences(restored: Path, recorded: dict[str, Any], target: str, version: int) -> list[str]:
    """db-identity.json after the app's start on the target: the source's
    entries as they were backed up, and one more, the target's, on the
    source's cluster and at this code's schema version."""
    now = identity(restored)
    out = [f"{IDENTITY_FILE}: the entry for {address} changed: {entry!r} -> {now.get(address)!r}"
           for address, entry in recorded.items() if now.get(address) != entry]
    added = {address: entry for address, entry in now.items() if address not in recorded}
    if [f"/{target}/" in address for address in added] != [True]:
        out.append(f"{IDENTITY_FILE}: one entry added, for {target}, expected; got {sorted(added) or 'none'}")
    clusters = {e.get("system_identifier") for e in recorded.values() if isinstance(e, dict)}
    for address, entry in added.items():
        if not isinstance(entry, dict) or entry.get("system_identifier") not in clusters:
            out.append(f"{IDENTITY_FILE}: {address} is not on the source's cluster: {entry!r}")
        elif entry.get("schema_version") != version:
            out.append(f"{IDENTITY_FILE}: {address} records schema version {entry.get('schema_version')}, "
                       f"not {version}")
    return out


def _check(admin_url: str, user: str, source: str, target: str, tmp: Path, pg: Tools, version: int,
           connect: Any) -> list[str]:
    import psycopg

    def url(name: str) -> str:       # the app reads only postgresql:// URLs: the same server, another database
        return urlsplit(admin_url)._replace(path=f"/{name}").geturl()

    state, restored = tmp / "state", tmp / "restored"
    dump, archive = tmp / "ctiparsor.dump", tmp / "cti-state.tgz"
    shown = len(pg.prefix)

    # 1. A used install: this code's first start, then its rows and files.
    run([sys.executable, "-c", "from api.db import init_db; init_db()"], ROOT, environment(url(source), state))
    conn = connect(url(source))
    try:
        seeded = migration_seed.seed(conn, state)
        problems = migration_seed.coverage_errors(conn, seeded)
    finally:
        conn.close()
    before, files, recorded = read(url(source), connect), state_tree(state), identity(state)
    print(f"source: schema version {version}, {len(before.content)} tables, {seeded.row_count()} rows seeded; "
          f"{sum(k.startswith('file ') for k in files)} files in the state directory")
    for gap in problems:
        print(f"  GAP {gap}")

    # 2. The backup, as docs/docker.md takes it.
    tool(pg.command("pg_dump", "-U", user, "-d", source, "-Fc"), pg.env, stdout=dump, shown=shown)
    listed = tool(pg.command("pg_restore", "-l"), pg.env, stdin=dump, shown=shown)
    data = sorted(re.findall(r"^\d+; \d+ \d+ TABLE DATA \S+ (\S+) ", listed, re.MULTILINE))
    tool(["tar", "czf", "-", "-C", str(state), "."], None, stdout=archive)
    print(f"backup: pg_dump -Fc, {dump.stat().st_size} bytes, the data of {len(data)} tables listed by pg_restore -l "
          f"({pg.version}); tar czf, {archive.stat().st_size} bytes")
    if data != sorted(before.content):
        problems.append(f"pg_restore -l lists the data of {data}, not of every table {sorted(before.content)}")

    # 3. The restore into an empty install, the database first.
    with psycopg.connect(admin_url, autocommit=True) as admin:
        admin.execute(f'CREATE DATABASE "{target}"')
    tool(pg.command("pg_restore", "-U", user, "-d", target, "--single-transaction"), pg.env, stdin=dump,
         shown=shown, silent=True)
    restored.mkdir()
    tool(["tar", "xzf", "-", "--keep-old-files", "-C", str(restored)], None, stdin=archive)
    print("restore: pg_restore --single-transaction into an empty database exited 0 and printed nothing; "
          "tar xzf --keep-old-files into an empty directory")

    # 4. Everything the source held, and nothing more.
    problems += differences(before, read(url(target), connect), "restored")
    changed = migration_compare.object_differences(files, state_tree(restored))
    print(f"restored, files: {len(files)} files and directories; "
          + (f"{len(changed)} difference(s)" if changed else "each one as in the source, byte for byte"))
    for diff in changed:
        print(f"  DIFF {diff.line()}")
    problems += [d.line() for d in changed]

    # 5. This code's app starts on them and reads the seed back.  Exit 1 is a
    # mismatch, with a result; without one, the read-back broke: its stderr says why.
    (tmp / "seeded.json").write_text(seeded.to_json(), encoding="utf-8")
    done = run([sys.executable, str(ROOT / "scripts" / "migration_readback.py"), str(tmp / "seeded.json"),
                str(tmp / "readback.json")], ROOT, environment(url(target), restored), ok=(0, 1))
    if not (tmp / "readback.json").is_file():
        raise Failed(f"the read-back exited {done.returncode} without a result:\n{tail(done.stderr)}")
    result = json.loads((tmp / "readback.json").read_text(encoding="utf-8"))
    print(f"read-back: {result['passed']} values read back through the routes; "
          + (f"{len(result['mismatches'])} mismatch(es)" if result["mismatches"] else "every one as seeded"))
    for line in result["mismatches"]:
        print(f"  DIFF {line}")
    for line in result["skipped"]:
        print(f"  skipped {line}")
    problems += result["mismatches"]

    # 6. The app's start changed nothing, but db-identity.json.
    problems += differences(before, read(url(target), connect), "after the app's start")
    kept = {k: v for k, v in files.items() if k != f"file {IDENTITY_FILE}"}
    now = {k: v for k, v in state_tree(restored).items() if k != f"file {IDENTITY_FILE}"}
    changed_lines = [d.line() for d in migration_compare.object_differences(kept, now)]
    if recorded:
        changed_lines += identity_differences(restored, recorded, target, version)
    kept_text = (f"each one unchanged but {IDENTITY_FILE}: the source's entry as backed up, the target's added "
                 "on the same cluster" if recorded
                 else f"each one unchanged (no {IDENTITY_FILE}: the role cannot read the cluster's id)")
    print("after the app's start, files: "
          + (f"{len(changed_lines)} difference(s)" if changed_lines else kept_text))
    for line in changed_lines:
        print(f"  DIFF {line}")
    return problems + changed_lines


def check(admin_url: str, container: str | None) -> bool:
    """One backup and restore, its report printed; True when nothing was lost."""
    import psycopg

    from api import migrations as history
    from api.db_backend import PgConnection

    started = time.monotonic()
    parts = urlsplit(admin_url)
    where = f"{parts.hostname or 'localhost'}:{parts.port or 5432}"
    user = unquote(parts.username or "")
    if not user:
        raise Unusable("CTIPARSOR_TEST_DATABASE_URL names no user: the docs' commands run `pg_dump -U <user>`")
    try:
        with psycopg.connect(admin_url, autocommit=True, connect_timeout=10) as admin:
            server = admin.info.server_version // 10000
    except psycopg.Error as exc:      # unreachable, refused
        raise Unusable(f"cannot reach {where}: {' '.join(str(exc).split())}") from exc
    pg = tools(admin_url, container, server)
    source, target = f"{PREFIX}{uuid4().hex[:10]}", f"{PREFIX}{uuid4().hex[:10]}"
    try:
        with psycopg.connect(admin_url, autocommit=True, connect_timeout=10) as admin:
            admin.execute(f'CREATE DATABASE "{source}"')
    except psycopg.Error as exc:      # a role without CREATEDB
        raise Unusable(f"cannot create a database on {where}: {' '.join(str(exc).split())}") from exc
    print(f"== backup and restore, PostgreSQL {server} at {where}")
    try:
        with tempfile.TemporaryDirectory(prefix="restorecheck-") as tmp:
            problems = _check(admin_url, user, source, target, Path(tmp), pg, history.latest_version(),
                              PgConnection)
    except Exception as exc:          # Failed, or a step that broke
        problems = [str(exc) if isinstance(exc, Failed) else f"{type(exc).__name__}: {exc}"]
        print(f"  {problems[0]}")
    finally:
        with psycopg.connect(admin_url, autocommit=True) as admin:
            for name in (source, target):
                admin.execute(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)')
    seconds = time.monotonic() - started
    if problems:
        print(f"FAIL backup and restore: {len(problems)} problem(s) ({seconds:.0f} s)")
        return False
    print(f"ok   backup and restore: the empty install restored from the backup holds every row, schema object "
          f"and file of the source, and this code reads it back ({seconds:.0f} s)")
    return True


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python scripts/check_backup_restore.py",
                                     description=(__doc__ or "").split("\n\n")[0])
    parser.add_argument("--pg-container", metavar="NAME",
                        help=f"the PostgreSQL server's container, whose pg_dump and pg_restore run (default: "
                             f"{CONTAINER_VARIABLE}; without either, this host's)")
    args = parser.parse_args(argv)
    admin_url = (os.getenv("CTIPARSOR_TEST_DATABASE_URL") or "").strip()
    container = args.pg_container or (os.getenv(CONTAINER_VARIABLE) or "").strip() or None
    try:
        if not admin_url:
            raise Unusable("CTIPARSOR_TEST_DATABASE_URL is required (a PostgreSQL server this role may "
                           "CREATE DATABASE on)")
        ok = check(admin_url, container)
    except Unusable as exc:
        print(f"check_backup_restore: {exc}", file=sys.stderr)
        return 2
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
