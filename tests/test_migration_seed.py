"""scripts/migration_seed.py: what scripts/check_migration_from.py writes into
a database an older release created before it migrates it (ADR-0094 item 2) —
written whole into this code's schema, adapted to an older one, and refused
where it would leave a table or a required column out."""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import uuid
from uuid import uuid4

import pytest

from api import migrate
from api import migrations as history
from api.db_backend import PgConnection
from scripts import migration_seed as ms


@pytest.fixture()
def schema():
    """An empty PostgreSQL schema and a connection whose search_path is it."""
    import psycopg

    url = (os.getenv("CTIPARSOR_TEST_DATABASE_URL") or "").strip()
    if not url:
        pytest.fail("CTIPARSOR_TEST_DATABASE_URL is required (ADR-0053)")
    name = "s_" + uuid4().hex[:12]
    with psycopg.connect(url, autocommit=True) as admin:
        admin.execute(f'CREATE SCHEMA "{name}"')
    conn = PgConnection(url, schema=name)
    yield conn
    conn.close()
    with psycopg.connect(url, autocommit=True) as admin:
        admin.execute(f'DROP SCHEMA "{name}" CASCADE')


def schema_at(conn: PgConnection, version: int) -> None:
    """The schema a release at `version` built (tests/test_migrations.py, `_legacy_at`)."""
    for mg in history.load()[:version]:
        for statement in mg.statements:
            conn.execute_script(statement)


def test_this_code_s_schema_is_seeded_whole(schema):
    """The pull request that adds a table or a column teaches the seed about
    it (or says in NOT_SEEDED why not): every column holds a value in at least
    one seeded row."""
    migrate.upgrade(schema)
    seeded = ms.seed(schema)
    # Nothing skipped: a misspelt column would be skipped silently.  A table or
    # column a later migration drops stays in the spec for the releases that
    # have it, and is listed here.
    assert seeded.skipped_tables == [] and seeded.skipped_columns == {}
    assert ms.coverage_errors(schema, seeded) == []


def test_the_rows_are_stored_as_the_spec_says(schema):
    migrate.upgrade(schema)
    seeded = ms.seed(schema)
    for table, rows in ms.spec().items():
        assert schema.execute(f'SELECT count(*) AS n FROM "{table}"').fetchone()["n"] == len(rows), table
    # Version 12's triggers bumped review_revision on every entity written: written back.
    revisions = dict(schema.execute("SELECT id, review_revision FROM jobs").fetchall())
    assert revisions == {r["id"]: r["review_revision"] for r in ms.spec()["jobs"]}
    # The identity values the database chose are known.
    assert all(isinstance(r["id"], int) for r in seeded.rows["review_decisions"])
    assert ms.Seeded.from_json(seeded.to_json()) == seeded


def test_an_older_release_s_schema_gets_the_columns_it_has(schema):
    schema_at(schema, 11)                                   # v0.1.0
    seeded = ms.seed(schema)
    assert seeded.skipped_tables == ["job_baselines", "worker_heartbeats"]
    assert seeded.skipped_columns == {
        "jobs": ["bundle_build_json", "bundle_review_revision", "pipeline_mode", "review_revision"],
        "entities": ["baseline_stix_id", "enrichment_status"],
        "relationships": ["baseline_stix_id", "enrichment_status"],
    }
    assert ms.coverage_errors(schema, seeded) == []
    assert all("pipeline_mode" not in row for row in seeded.rows["jobs"])


def test_a_table_the_seed_leaves_empty_is_named_unless_a_reason_is_given(schema, monkeypatch):
    migrate.upgrade(schema)
    schema.execute("CREATE TABLE analyst_notes (id TEXT PRIMARY KEY, body TEXT)")
    seeded = ms.seed(schema)
    errors = ms.coverage_errors(schema, seeded)
    assert len(errors) == 1 and errors[0].startswith("analyst_notes: ")
    monkeypatch.setitem(ms.NOT_SEEDED, "analyst_notes", "written by nothing yet")
    assert ms.coverage_errors(schema, seeded) == []


def test_a_column_left_null_in_every_row_is_named_unless_a_reason_is_given(schema, monkeypatch):
    """A column NULL in every seeded row is one a migration could wipe unseen."""
    migrate.upgrade(schema)
    schema.execute("ALTER TABLE jobs ADD COLUMN owner TEXT")
    schema.execute("ALTER TABLE cve_cache ADD COLUMN origin TEXT NOT NULL DEFAULT 'circl'")    # its default fills it
    seeded = ms.seed(schema)
    assert ms.coverage_errors(schema, seeded) == [
        "jobs.owner: NULL in every seeded row and NOT_SEEDED gives no reason (scripts/migration_seed.py)"]
    monkeypatch.setitem(ms.NOT_SEEDED, "jobs.owner", "no release writes it yet")
    assert ms.coverage_errors(schema, seeded) == []


def test_a_required_column_the_spec_leaves_out_stops_the_seed_before_any_write(schema):
    migrate.upgrade(schema)
    schema.execute("ALTER TABLE jobs ADD COLUMN owner TEXT NOT NULL")
    schema.execute("ALTER TABLE cve_cache ADD COLUMN origin TEXT NOT NULL DEFAULT 'circl'")    # a default: fine
    with pytest.raises(ms.SeedError, match=r"jobs\.owner \(row 0\), jobs\.owner \(row 1\)") as caught:
        ms.seed(schema)
    assert "cve_cache" not in str(caught.value)
    assert schema.execute("SELECT count(*) AS n FROM jobs").fetchone()["n"] == 0


def test_the_files_land_under_the_state_directory(schema, tmp_path):
    migrate.upgrade(schema)
    seeded = ms.seed(schema, tmp_path / "state")
    assert set(seeded.files) == set(ms.files())
    for rel, digest in seeded.files.items():
        assert hashlib.sha256((tmp_path / "state" / rel).read_bytes()).hexdigest() == digest
    assert set(seeded.sources.values()) <= set(seeded.files)
    assert set(seeded.sources) == {row["id"] for row in seeded.rows["jobs"]}


@pytest.mark.parametrize("name", ["long_distance", "minimal", "policy_pin"])
def test_the_bundles_are_stage4_reference_builds_with_real_ids(name):
    bundle_json, ledger_json = ms.stage4_build(name)
    assert ms.stage4_build(name) == (bundle_json, ledger_json)          # the same at every run
    bundle, ledger = json.loads(bundle_json), json.loads(ledger_json)
    assert bundle["type"] == "bundle" and bundle["objects"]
    for text in (bundle_json, ledger_json):
        assert "<build-time>" not in text and not re.search(r"--R\d+\b", text)
    ids = [o["id"] for o in bundle["objects"]]
    assert len(ids) == len(set(ids))
    assert all(uuid.UUID(i.split("--", 1)[1]) for i in [bundle["id"], *ids])
    assert set(ledger["objects"]) == set(ids)


def _release_tree(tmp_path):
    """A release's tree (its `git archive`) holding a copy of this code's
    Stage 4 reference builds."""
    tree = tmp_path / "old"
    shutil.copytree(ms.STAGE4, tree / "tests" / "fixtures" / "stage4_reference")
    return tree


def test_a_release_s_own_stage4_builds_are_used_when_it_has_them(tmp_path):
    assert ms.release_stage4(tmp_path / "v0.1.0") is None                    # a tree without them
    tree = _release_tree(tmp_path)
    assert ms.release_stage4(tree) == tree / "tests" / "fixtures" / "stage4_reference"
    (tree / "tests" / "fixtures" / "stage4_reference" / "expected" / "minimal.json").write_text(
        '{"objects": []}', encoding="utf-8")                                 # no ledger: not a shape it reads
    assert ms.release_stage4(tree) is None


def test_the_seed_writes_the_bundles_ledgers_and_texts_of_the_builds_it_is_given(schema, tmp_path):
    tree = _release_tree(tmp_path)
    stage4 = tree / "tests" / "fixtures" / "stage4_reference"
    expected, scenario = stage4 / "expected" / "minimal.json", stage4 / "scenarios" / "minimal.json"
    canon, story = json.loads(expected.read_text(encoding="utf-8")), json.loads(scenario.read_text(encoding="utf-8"))
    canon["objects"][0]["x_release"] = "v0.2.0"
    canon["ledger"]["release"] = "v0.2.0"
    story["report_text"] = "The report as the release read it."
    expected.write_text(json.dumps(canon), encoding="utf-8")
    scenario.write_text(json.dumps(story), encoding="utf-8")
    migrate.upgrade(schema)
    seeded = ms.seed(schema, tmp_path / "state", ms.release_stage4(tree))
    jobs = {row["id"]: row for row in seeded.rows["jobs"]}
    assert json.loads(jobs[ms.JOB_B]["bundle_json"])["objects"][0]["x_release"] == "v0.2.0"
    assert json.loads(jobs[ms.JOB_B]["bundle_ledger_json"])["release"] == "v0.2.0"
    assert jobs[ms.JOB_B]["report_text"] == "The report as the release read it."
    assert (tmp_path / "state" / "uploads" / f"{ms.JOB_B}.txt").read_text(encoding="utf-8") == \
        "The report as the release read it."
    assert jobs[ms.JOB_A]["bundle_json"] == ms.stage4_build("long_distance")[0]    # the others: as copied


def test_the_baseline_index_and_intake_were_written_for_the_baseline_file():
    """They are frozen as the intake wrote them: the file they describe must not change."""
    raw = ms._BASELINE_FILE.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == ms._BASELINE_SHA
    assert json.loads(raw)["id"] == ms._BASELINE_INDEX["bundle_id"] == ms._BASELINE_INTAKE["bundle_id"]
