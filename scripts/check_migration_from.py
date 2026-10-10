"""A database the code at <ref> wrote migrates to this code's schema, its data
intact (ADR-0077 part B, item 7).

    python scripts/check_migration_from.py <git-ref>

CI runs it on every pull request with the PR's base commit — the code running
in deployments the PR will upgrade (there are no release tags).  On the
PostgreSQL server CTIPARSOR_TEST_DATABASE_URL names, in a throwaway database:

1. <ref>'s own code builds its schema (`api.db.init_db`, run from a `git
   archive` of <ref>), and a report's rows are written into it;
2. this code migrates it (`python -m api.migrate up`, then `check`);
3. every table that existed keeps its row count, and this code reads the old
   rows back through the API's own serialisers.

Exit 1 on any difference.  Needs `git`, and <ref> in the local repository.
"""
from __future__ import annotations

import os
import subprocess
import sys
import tarfile
import tempfile
from io import BytesIO
from pathlib import Path
from urllib.parse import urlsplit
from uuid import uuid4

ROOT = Path(__file__).resolve().parent.parent

# Columns every version since the first PostgreSQL job store (v1) has.
_SEED = [
    ("INSERT INTO jobs (id, original_filename, status, report_text, created_at, updated_at) "
     "VALUES ('mig-job', 'r.txt', 'for_review', 'APT29 used WellMess.', '2026-01-01', '2026-01-01')"),
    ("INSERT INTO entities (id, job_id, value, entity_type, confidence, accepted, source) VALUES "
     "('mig-e1', 'mig-job', 'APT29', 'threat_actor', 0.9, 1, 'llm'), "
     "('mig-e2', 'mig-job', 'WellMess', 'malware', 0.5, NULL, 'gliner'), "
     "('mig-e3', 'mig-job', 'T1059', 'ttp', 0.9, 0, 'llm')"),
    ("INSERT INTO relationships (id, job_id, source_value, relationship_type, target_value, accepted, "
     "evidence_text) VALUES ('mig-r1', 'mig-job', 'APT29', 'uses', 'WellMess', 1, 'APT29 used WellMess.')"),
]

_COUNTS = ("SELECT tablename FROM pg_tables WHERE schemaname = 'public' "
           "AND tablename <> 'schema_migrations' ORDER BY tablename")

_READ_BACK = """
from api.db import get_conn
from api.routes.entities import _row_to_dict as entity
from api.routes.relationships import _row_to_dict as relationship
conn = get_conn()
ents = [entity(r) for r in conn.execute("SELECT * FROM entities WHERE job_id='mig-job'").fetchall()]
rels = [relationship(r) for r in conn.execute("SELECT * FROM relationships WHERE job_id='mig-job'").fetchall()]
print(len(ents), len(rels), sorted(str(e["accepted"]) for e in ents))
"""


def _run(cmd: list[str], cwd: Path, url: str) -> str:
    env = {**os.environ, "DATABASE_URL": url, "SKIP_HEAVY_MODELS": "1",
           "CTIPARSOR_STATE_DIR": str(Path(tempfile.gettempdir()) / f"migcheck-state-{os.getpid()}")}
    done = subprocess.run(cmd, cwd=cwd, env=env, capture_output=True, text=True)
    if done.returncode:
        sys.exit(f"FAIL {' '.join(cmd[:3])} in {cwd}:\n{done.stdout[-2000:]}\n{done.stderr[-4000:]}")
    return done.stdout


def _counts(url: str) -> dict[str, int]:
    import psycopg
    with psycopg.connect(url) as conn:
        tables = [r[0] for r in conn.execute(_COUNTS).fetchall()]
        return {t: conn.execute(f'SELECT count(*) FROM "{t}"').fetchone()[0] for t in tables}


def main(ref: str) -> int:
    import psycopg

    admin_url = (os.getenv("CTIPARSOR_TEST_DATABASE_URL") or "").strip()
    if not admin_url:
        sys.exit("CTIPARSOR_TEST_DATABASE_URL is required (a PostgreSQL server this role may CREATE DATABASE on)")
    sha = subprocess.run(["git", "rev-parse", "--short", ref], cwd=ROOT, capture_output=True,
                         text=True, check=True).stdout.strip()
    name = f"ctiparsor_migcheck_{uuid4().hex[:10]}"
    # The app reads only postgresql:// URLs: the same server, another database.
    url = urlsplit(admin_url)._replace(path=f"/{name}").geturl()
    with psycopg.connect(admin_url, autocommit=True) as admin:
        admin.execute(f'CREATE DATABASE "{name}"')
    try:
        with tempfile.TemporaryDirectory(prefix="migcheck-") as tmp:
            old = Path(tmp) / "old"
            archive = subprocess.run(["git", "archive", "--format=tar", ref], cwd=ROOT,
                                     capture_output=True, check=True).stdout
            with tarfile.open(fileobj=BytesIO(archive)) as tar:
                tar.extractall(old, filter="data")

            # 1. <ref>'s schema and a report written into it
            _run([sys.executable, "-c", "from api.db import init_db; init_db()"], old, url)
            with psycopg.connect(url) as conn:
                for statement in _SEED:
                    conn.execute(statement)
            before = _counts(url)
            print(f"{sha}: {len(before)} tables, {sum(before.values())} rows")

            # 2. this code migrates it
            print(_run([sys.executable, "-m", "api.migrate", "up"], ROOT, url).strip()[-400:])
            _run([sys.executable, "-m", "api.migrate", "check"], ROOT, url)

            # 3. the data came through, and this code reads it
            after = _counts(url)
            changed = {t: (n, after.get(t)) for t, n in before.items() if after.get(t) != n}
            if changed:
                print(f"FAIL row counts changed (table: before, after): {changed}")
                return 1
            read = _run([sys.executable, "-c", _READ_BACK], ROOT, url).strip()
            if read != "3 1 ['False', 'None', 'True']":
                print(f"FAIL this code read back: {read}")
                return 1
            print(f"ok   a database written by {sha} migrates to this code's schema, "
                  f"{len(before)} tables and their rows intact, read back by the API")
            return 0
    finally:
        with psycopg.connect(admin_url, autocommit=True) as admin:
            admin.execute(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)')


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    sys.exit(main(sys.argv[1]))
