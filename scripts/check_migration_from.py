"""A database a release wrote migrates to this code's schema with its content
intact, and this code reads it back (ADR-0077 part B item 7, ADR-0094 item 2).

    python scripts/check_migration_from.py REF [REF ...]
    python scripts/check_migration_from.py --last-release [REF ...]

`--last-release` adds the highest tag vX.Y.Z reachable from HEAD.  CI runs the
check from the last release tag on every push to main, every pull request and
every weekly run — the database an upgrading deployment holds — and, on a pull
request, from its base commit too: what deployments that track main run until
it merges.
For each ref, on the PostgreSQL server CTIPARSOR_TEST_DATABASE_URL names, in a
throwaway database and a throwaway state directory laid out as the image's
volume (uploads/, output/):

1. the ref's own code starts as a deployment's first start does: it builds
   its schema and records the database in the state directory's
   db-identity.json (`api.db.init_db`, run from a `git archive` of the ref);
2. scripts/migration_seed.py writes the rows and files of a deployment that
   has been used into it, adapted to that schema, every table and column
   covered, its bundles and ledgers from the ref's own Stage 4 reference
   builds when its tree has them;
3. every table is read, every row and every column
   (scripts/migration_compare.py);
4. this code migrates the database (`python -m api.migrate up`, then `check`);
5. every table is read again: each row is still there, each column of the
   same type and each value the same, unless EXPECTED_CHANGES declares the
   change for a migration that ran; the sequence of each identity column still
   gives a value above the highest stored;
6. this code's app starts on the database and its routes read the seeded rows
   back (scripts/migration_readback.py);
7. every table is read a third time and compared with step 5 the same way, the
   sequences too: the app's first start and its read routes change nothing;
8. every file of the state directory is as it was, except db-identity.json,
   which every start rewrites (api/db_identity.py): its entry for the
   database must keep its cluster and record this code's schema version.

Exit 0 when every ref passes, 1 on any difference, 2 when the check cannot run
(no CTIPARSOR_TEST_DATABASE_URL, a server it cannot create a database on, a ref
git does not know, an archive that fails, no release tag).  Needs `git` and the
refs in the local repository; a shallow clone has no tags: fetch the tag (CI:
.github/workflows/ci.yml), or name the ref.  The processes of both trees run
with PYTHON_DOTENV_DISABLED=1: a developer's .env reaches neither.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import tarfile
import tempfile
import time
from collections.abc import Iterable
from io import BytesIO
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit
from uuid import uuid4

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:      # run as a script: the repository root is not on the path
    sys.path.insert(0, str(ROOT))

from scripts import migration_compare, migration_seed

# Changes a migration makes to stored values on purpose: {version: {"table.column"
# or "table.*": why}}.  A migration that rewrites values in place, retypes or
# drops a column, or drops rows or a table, declares it here in the pull request
# that adds it; any other change to a row the release wrote fails the check.
EXPECTED_CHANGES: dict[int, dict[str, str]] = {}

RELEASE_TAG = re.compile(r"^v\d+\.\d+\.\d+$")
IDENTITY_FILE = "db-identity.json"


class Unusable(Exception):
    """The check cannot run: exit 2."""


class Failed(Exception):
    """A step failed for one ref: exit 1."""


def git(*args: str) -> str:
    done = subprocess.run(["git", *args], cwd=ROOT, capture_output=True, text=True)
    if done.returncode:
        raise Unusable(f"git {' '.join(args)}: {done.stderr.strip() or f'exit {done.returncode}'}")
    return done.stdout.strip()


def last_release() -> str:
    """The highest tag vX.Y.Z reachable from HEAD, by version."""
    tags = [t for t in git("tag", "--merged", "HEAD", "--list", "v*", "--sort=-v:refname").splitlines()
            if RELEASE_TAG.match(t)]
    if not tags:
        raise Unusable("no tag vX.Y.Z is reachable from HEAD; a shallow clone has none: fetch it "
                       "(git fetch --depth=1 origin refs/tags/vX.Y.Z:refs/tags/vX.Y.Z) and name it")
    return tags[0]


def resolve(refs: list[str]) -> list[tuple[str, str]]:
    """(ref, commit) for each ref; a commit two refs name is checked once."""
    out: list[tuple[str, str]] = []
    seen: dict[str, str] = {}
    for ref in refs:
        done = subprocess.run(["git", "rev-parse", "--verify", "--quiet", f"{ref}^{{commit}}"], cwd=ROOT,
                              capture_output=True, text=True)
        commit = done.stdout.strip()
        if done.returncode or not commit:
            raise Unusable(f"unknown ref: {ref} (not in this repository: fetch it first)")
        if commit in seen:
            print(f"{ref}: the same commit as {seen[commit]}, checked once")
            continue
        seen[commit] = ref
        out.append((ref, commit))
    return out


def environment(url: str, state: Path) -> dict[str, str]:
    """For a process of either tree: the throwaway database, the state
    directory laid out as the image's volume, no queue loop, no model, and no
    .env (api/db.py and Stage 3 call load_dotenv(), which finds the checkout's)."""
    return {**os.environ, "DATABASE_URL": url, "SKIP_HEAVY_MODELS": "1", "CTIPARSOR_ROLE": "api",
            "CTIPARSOR_STATE_DIR": str(state), "CTIPARSOR_UPLOADS_DIR": str(state / "uploads"),
            "CTIPARSOR_OUTPUT_DIR": str(state / "output"), "API_ALLOWED_HOSTS": "testserver",
            "PYTHON_DOTENV_DISABLED": "1"}


def tail(text: str, lines: int = 40) -> str:
    return "\n".join(text.strip().splitlines()[-lines:])


def run(cmd: list[str], cwd: Path, env: dict[str, str],
        ok: tuple[int, ...] = (0,)) -> subprocess.CompletedProcess[str]:
    done = subprocess.run(cmd, cwd=cwd, env=env, capture_output=True, text=True)
    if done.returncode not in ok:
        raise Failed(f"{' '.join(cmd[1:3])} in {cwd} exited {done.returncode}:\n"
                     f"{tail(done.stdout, 10)}\n{tail(done.stderr)}")
    return done


def extract(commit: str, dest: Path) -> None:
    """The tree of `commit`, from `git archive`, under `dest`."""
    archive = subprocess.run(["git", "archive", "--format=tar", commit], cwd=ROOT, capture_output=True)
    if archive.returncode:
        raise Unusable(f"git archive {commit}: {archive.stderr.decode('utf-8', 'replace').strip()}")
    with tarfile.open(fileobj=BytesIO(archive.stdout)) as tar:
        tar.extractall(dest, filter="data")


def state_files(state: Path) -> dict[str, str]:
    """sha256 of every file under the state directory, by its path there."""
    return {p.relative_to(state).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted(state.rglob("*")) if p.is_file()}


def identity(state: Path) -> dict[str, Any]:
    """db-identity.json: {address: {system_identifier, schema_version, recorded_at}}."""
    try:
        return json.loads((state / IDENTITY_FILE).read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {}


def file_differences(state: Path, before: dict[str, str], recorded: dict[str, Any], version: int) -> list[str]:
    """What happened to the state directory's files since `before`; db-identity.json
    by meaning: each address keeps its cluster and records `version`."""
    after = state_files(state)
    out = [f"{rel}: {'deleted' if rel not in after else 'changed'}"
           for rel, digest in before.items() if rel != IDENTITY_FILE and after.get(rel) != digest]
    now = identity(state)
    for address, entry in recorded.items():
        seen = now.get(address)
        if not isinstance(seen, dict):
            out.append(f"{IDENTITY_FILE}: the entry for {address} is gone")
            continue
        if seen.get("system_identifier") != entry.get("system_identifier"):
            out.append(f"{IDENTITY_FILE}: {address} moved to cluster {seen.get('system_identifier')}")
        if seen.get("schema_version") != version:
            out.append(f"{IDENTITY_FILE}: {address} records schema version {seen.get('schema_version')}, "
                       f"not {version}")
    return out


def check(ref: str, commit: str, admin_url: str) -> bool:
    """Steps 1 to 7 for one ref; prints its report."""
    import psycopg

    from api import migrations as history
    from api.db_backend import PgConnection

    started = time.monotonic()
    label = commit[:7] if ref == commit else f"{ref} ({commit[:7]})"
    print(f"== {label}")
    name = f"ctiparsor_migcheck_{uuid4().hex[:10]}"
    # The app reads only postgresql:// URLs: the same server, another database.
    parts = urlsplit(admin_url)
    url = parts._replace(path=f"/{name}").geturl()
    try:
        with psycopg.connect(admin_url, autocommit=True, connect_timeout=10) as admin:
            admin.execute(f'CREATE DATABASE "{name}"')
    except psycopg.Error as exc:      # unreachable, refused, or a role without CREATEDB
        where = f"{parts.hostname or 'localhost'}:{parts.port or 5432}"
        raise Unusable(f"cannot create a database on {where}: {' '.join(str(exc).split())}") from exc
    try:
        with tempfile.TemporaryDirectory(prefix="migcheck-") as tmp:
            problems = _check(commit, url, Path(tmp), history.latest_version(), PgConnection)
    except Unusable:
        raise
    except Exception as exc:          # Failed, or a step that broke: this ref fails, the next one runs
        problems = [str(exc) if isinstance(exc, Failed) else f"{type(exc).__name__}: {exc}"]
        print(f"  {problems[0]}")
    finally:
        with psycopg.connect(admin_url, autocommit=True) as admin:
            admin.execute(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)')
    seconds = time.monotonic() - started
    if problems:
        print(f"FAIL {label}: {len(problems)} problem(s) ({seconds:.0f} s)")
        return False
    print(f"ok   {label}: its database migrates to this code's schema with its content intact, "
          f"and this code reads it back ({seconds:.0f} s)")
    return True


def _content(url: str, connect: Any, before: migration_compare.Snapshot, tables: Iterable[str],
             label: str) -> tuple[migration_compare.Snapshot, list[str]]:
    """Every table read again and compared with `before`, and the sequences of
    `tables`; printed under `label`.  (The snapshot, its differences.)"""
    conn = connect(url)
    try:
        now = migration_compare.snapshot(conn)
        checked, stuck = migration_compare.sequence_differences(conn, tables)
    finally:
        conn.close()
    result = migration_compare.compare(before, now, EXPECTED_CHANGES)
    for line in migration_compare.summary(result, label):
        print(line)
    print(f"{'sequences' if label == 'content' else label + ', sequences'}: {checked} identity column(s); "
          + (f"{len(stuck)} difference(s)" if stuck else "each one's next value above the highest stored"))
    for diff in stuck:
        print(f"  DIFF {diff.line()}")
    return now, [d.line() for d in result.differences + stuck]


def _check(commit: str, url: str, tmp: Path, version: int, connect: Any) -> list[str]:
    old, state = tmp / "old", tmp / "state"
    extract(commit, old)
    env = environment(url, state)
    problems: list[str] = []

    # 1-3. The release's first start, a deployment's rows and files, every table read.
    run([sys.executable, "-c", "from api.db import init_db; init_db()"], old, env)
    stage4 = migration_seed.release_stage4(old)
    conn = connect(url)
    try:
        seeded = migration_seed.seed(conn, state, stage4)
        problems += migration_seed.coverage_errors(conn, seeded)
        before = migration_compare.snapshot(conn)
    except migration_seed.SeedError as exc:
        raise Failed(str(exc)) from exc
    finally:
        conn.close()
    files_before, recorded = state_files(state), identity(state)
    skipped = seeded.skipped_tables + [f"{table}.{column}" for table, columns in sorted(seeded.skipped_columns.items())
                                       for column in columns]
    print(f"seed: schema version {max(migration_compare.versions(before), default=0)}, {len(before)} tables; "
          f"{seeded.row_count()} rows and {len(seeded.files)} files written"
          + (f"; not in this schema, not seeded: {', '.join(skipped)}" if skipped else ""))
    print("payloads: " + ("the release's own Stage 4 reference builds (tests/fixtures/stage4_reference)"
                          if stage4 else "current fixtures, the release has none"))
    for gap in problems:
        print(f"  GAP {gap}")

    # 4. This code migrates it.
    migrated = run([sys.executable, "-m", "api.migrate", "up"], ROOT, env).stdout
    print("migrate: " + migrated.strip().splitlines()[-1])
    run([sys.executable, "-m", "api.migrate", "check"], ROOT, env)

    # 5. Every row, type and value of step 3, after; the sequences.
    after, differences = _content(url, connect, before, before, "content")
    problems += differences

    # 6. This code's routes read it back.  Exit 1 is a mismatch, with a result;
    # without one, the read-back broke: its stderr says why.
    (tmp / "seeded.json").write_text(seeded.to_json(), encoding="utf-8")
    done = run([sys.executable, str(ROOT / "scripts" / "migration_readback.py"), str(tmp / "seeded.json"),
                str(tmp / "readback.json")], ROOT, env, ok=(0, 1))
    if not (tmp / "readback.json").is_file():
        raise Failed(f"the read-back exited {done.returncode} without a result:\n{tail(done.stderr)}")
    read = json.loads((tmp / "readback.json").read_text(encoding="utf-8"))
    print(f"read-back: {read['passed']} values read back through the routes; "
          + (f"{len(read['mismatches'])} mismatch(es)" if read["mismatches"] else "every one as seeded"))
    for line in read["mismatches"]:
        print(f"  DIFF {line}")
    for line in read["skipped"]:
        print(f"  skipped {line}")
    problems += read["mismatches"]

    # 7. The app's first start and its read routes changed nothing.
    _, differences = _content(url, connect, after, before, "after the read-back")
    problems += differences

    # 8. The state directory's files.
    changed = file_differences(state, files_before, recorded, version)
    kept = (f"every one unchanged but {IDENTITY_FILE}, which each start rewrites: same cluster, "
            f"schema version {version}" if recorded
            else f"every one unchanged (no {IDENTITY_FILE}: the role cannot read the cluster's id)")
    print(f"files: {len(files_before)} in the state directory; "
          + (f"{len(changed)} difference(s)" if changed else kept))
    for line in changed:
        print(f"  DIFF {line}")
    return problems + changed


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python scripts/check_migration_from.py",
                                     description=(__doc__ or "").split("\n\n")[0])
    parser.add_argument("refs", nargs="*", metavar="REF", help="a commit, branch or tag whose code wrote the database")
    parser.add_argument("--last-release", action="store_true",
                        help="also from the highest tag vX.Y.Z reachable from HEAD")
    args = parser.parse_args(argv)
    if not args.refs and not args.last_release:
        parser.error("name a REF, or --last-release")
    admin_url = (os.getenv("CTIPARSOR_TEST_DATABASE_URL") or "").strip()
    try:
        if not admin_url:
            raise Unusable("CTIPARSOR_TEST_DATABASE_URL is required (a PostgreSQL server this role may "
                           "CREATE DATABASE on)")
        targets = resolve(([last_release()] if args.last_release else []) + args.refs)
        failed = [ref for ref, commit in targets if not check(ref, commit, admin_url)]
    except Unusable as exc:
        print(f"check_migration_from: {exc}", file=sys.stderr)
        return 2
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
