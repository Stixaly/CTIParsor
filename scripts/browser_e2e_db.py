"""The database of the browser journey (scripts/check_browser_e2e.sh, ADR-0094 item 4).

    python scripts/browser_e2e_db.py create
    python scripts/browser_e2e_db.py seed URL
    python scripts/browser_e2e_db.py stages URL
    python scripts/browser_e2e_db.py drop URL

create  makes a new, empty database on the PostgreSQL server
        CTIPARSOR_TEST_DATABASE_URL names and prints its URL; the API's first
        start builds the schema in it.
seed    writes the one report no upload can make, once the API has built the
        schema: a report whose bundle the STIX 2.1 schemas refused, stored as
        the worker stores one (api.worker._finalize_job, status for_review),
        with the errors Stage 5's own validator gives for it.  The journey finds
        it by its file name, REFUSED_FILENAME, and expects its download refused
        with a 409.
stages  prints, for every report, which stages ran and which were skipped and
        why (the run's stage report, ADR-0059); exit 1 when a stage
        PIPELINE_DISABLED_STAGES turns off ran, or when no report ran at all.
drop    removes the database, connections and all.

seed, stages and drop take only a database create made (its name starts with
PREFIX).  Exit 0 on success, 1 on a failed check, 2 when it cannot run (no
CTIPARSOR_TEST_DATABASE_URL, a server it cannot reach or create a database
on, a database it did not make).
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from collections.abc import Callable, Iterable, Mapping
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit
from uuid import uuid4

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:      # run as a script: the repository root is not on the path
    sys.path.insert(0, str(ROOT))

PREFIX = "ctiparsor_e2e_"
REFUSED_FILENAME = "refused-bundle-e2e.txt"
REFUSED_TEXT = ("A report whose STIX bundle the schemas refused. It was written by "
                "scripts/browser_e2e_db.py for the browser journey.\n")


class Unusable(Exception):
    """The helper cannot run: exit 2."""


def admin_url() -> str:
    url = (os.environ.get("CTIPARSOR_TEST_DATABASE_URL") or "").strip()
    if not url:
        raise Unusable("CTIPARSOR_TEST_DATABASE_URL is not set: the PostgreSQL server to create "
                       "the journey's database on (postgresql://user:password@host:port/db)")
    return url


def database(url: str) -> str:
    """The name of a database `create` made; Unusable for any other."""
    name = urlsplit(url).path.lstrip("/")
    if not name.startswith(PREFIX):
        raise Unusable(f"not a database this helper made (no {PREFIX} prefix): {name!r}")
    return name


def create() -> str:
    """A new, empty database on the server of CTIPARSOR_TEST_DATABASE_URL: its URL."""
    import psycopg

    admin = admin_url()
    name = f"{PREFIX}{uuid4().hex[:10]}"
    parts = urlsplit(admin)
    try:
        with psycopg.connect(admin, autocommit=True, connect_timeout=10) as conn:
            conn.execute(f'CREATE DATABASE "{name}"')
    except psycopg.Error as exc:      # unreachable, refused, or a role without CREATEDB
        where = f"{parts.hostname or 'localhost'}:{parts.port or 5432}"
        raise Unusable(f"cannot create a database on {where}: {' '.join(str(exc).split())}") from exc
    return parts._replace(path=f"/{name}").geturl()


def drop(url: str) -> None:
    import psycopg

    name = database(url)
    with psycopg.connect(admin_url(), autocommit=True, connect_timeout=10) as conn:
        conn.execute(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)')


def refused_bundle() -> str:
    """A bundle Stage 5 refuses: its report's lang is not an RFC 5646 tag."""
    identity = f"identity--{uuid4()}"
    stamp = "2026-10-01T00:00:00.000Z"
    return json.dumps({"type": "bundle", "id": f"bundle--{uuid4()}", "objects": [
        {"type": "identity", "spec_version": "2.1", "id": identity, "created": stamp,
         "modified": stamp, "name": "CTIParsor browser journey", "identity_class": "system"},
        {"type": "report", "spec_version": "2.1", "id": f"report--{uuid4()}", "created": stamp,
         "modified": stamp, "name": "Refused bundle", "published": stamp, "lang": "not a lang!",
         "created_by_ref": identity, "object_refs": [identity]},
    ]})


def write_refused_report() -> str:
    """The refused report, in the database api.db uses, as the worker writes a run
    whose Stage 5 refused the bundle: status for_review, the bundle kept with its
    verdict and its errors.  Its job id."""
    from api.db import get_conn, now_iso
    from api.worker import _finalize_job
    from pipeline.stage5_validation import INVALID, validate_bundle

    bundle = refused_bundle()
    result = validate_bundle(bundle, quiet=True)
    if result.status != INVALID or not result.errors:
        raise RuntimeError(f"Stage 5 did not refuse the seeded bundle: {result.status} {result.errors}")
    job_id = str(uuid4())
    ts = now_iso()
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO jobs (id, original_filename, status, tlp_level, pap_level, pipeline_mode, "
            "report_text, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?)",
            (job_id, REFUSED_FILENAME, "processing", "CLEAR", "WHITE", "full", REFUSED_TEXT, ts, ts),
        )
        conn.commit()
    if not _finalize_job(job_id, "for_review", None, bundle_json=bundle, validation=result.status,
                         validation_errors=result.errors):
        raise RuntimeError("the refused report was not written")
    return job_id


def stage_problems(reports: Iterable[Mapping[str, Any]], disabled: set[str],
                   say: Callable[[str], None] = print) -> list[str]:
    """Says each report's stage report (rows with original_filename, status and
    run_config_json); returns what is wrong: a stage of `disabled` that ran, or
    no report that ran through the pipeline."""
    problems: list[str] = []
    ran_any = False
    for row in reports:
        report = json.loads(row["run_config_json"] or "{}").get("stage_report") or []
        say(f"{row['original_filename']} ({row['status']}):")
        if not report:
            say("  no stage report: the pipeline did not run to its end")
            continue
        ran_any = True
        for stage in report:
            reason = f": {stage['reason']}" if stage.get("reason") else ""
            say(f"  {stage['stage']:<5} {stage['status']}{reason}")
            if stage["stage"] in disabled and stage["status"] == "ran":
                problems.append(f"{row['original_filename']}: stage {stage['stage']} ran, "
                                "but PIPELINE_DISABLED_STAGES turns it off")
    if not ran_any:
        problems.append("no report ran through the pipeline")
    return problems


def _use(url: str) -> None:
    """Points api.db at `url`: before anything imports it."""
    database(url)
    os.environ["DATABASE_URL"] = url


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="The database of the browser journey.")
    parser.add_argument("command", choices=("create", "seed", "stages", "drop"))
    parser.add_argument("url", nargs="?", help="the URL create printed")
    args = parser.parse_args(argv)
    try:
        if args.command == "create":
            print(create())
            return 0
        if not args.url:
            raise Unusable(f"{args.command} needs the URL create printed")
        if args.command == "drop":
            drop(args.url)
            return 0
        _use(args.url)
        if args.command == "seed":
            print(f"seeded {REFUSED_FILENAME}: job {write_refused_report()}")
            return 0
        from api.db import get_conn
        with get_conn() as conn:
            rows = conn.execute("SELECT original_filename, status, run_config_json FROM jobs "
                                "ORDER BY created_at").fetchall()
        disabled = {s.strip() for s in os.environ.get("PIPELINE_DISABLED_STAGES", "").split(",") if s.strip()}
        problems = stage_problems(rows, disabled)
        for problem in problems:
            print(f"FAIL {problem}")
        return 1 if problems else 0
    except Unusable as exc:
        print(f"browser_e2e_db: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
