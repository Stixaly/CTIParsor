"""The air-gap bundle carries the schema and the rule store, never the reports
(scripts/package_offline_docker.sh, step 6; ADR-0054).

OFFLINE_RULE_STORE_TABLES, the rule-store list of scripts/offline_lib_docker.sh, must
equal the tables that the migrations with store="rules" create: the first test keeps
the two in step. The others run the helpers of scripts/offline_lib_docker.sh under
bash, on text: no Docker and no database."""
from __future__ import annotations

import re
import shlex
import subprocess
from pathlib import Path

from api import migrations

_ROOT = Path(__file__).resolve().parent.parent
_PACKAGER = _ROOT / "scripts" / "package_offline_docker.sh"
_LIB = "scripts/offline_lib_docker.sh"

_RULE_STORE_LINE = re.compile(r'^OFFLINE_RULE_STORE_TABLES="([^"]*)"$', re.MULTILINE)
_OLD_RULE_STORE_LINE = re.compile(r"^RULE_STORE_TABLES=", re.MULTILINE)
_CREATE_TABLE = re.compile(r"CREATE TABLE (?:IF NOT EXISTS )?(\w+)")

# A `pg_restore -l` listing of a dump that holds the rule store and the schema of
# the job store, but no report data: `jobs` has a TABLE entry and no DATA entry.
_TOC_RULES_ONLY = (
    "; Archive created at 2026-10-30 12:00:00 UTC\n"
    ";     dbname: ctiparsor\n"
    "3456; 1259 16390 TABLE public detection_rules ctiparsor\n"
    "3457; 0 16390 TABLE DATA public detection_rules ctiparsor\n"
    "3458; 0 16391 TABLE DATA public schema_migrations ctiparsor\n"
    "3459; 1259 16392 TABLE public jobs ctiparsor\n"
)

# The same dump as the packager makes it (--schema=public --no-blobs), with the
# entries of a real listing: the public schema, and the counters of two sequences.
_TOC_FULL = _TOC_RULES_ONLY + (
    "4; 2615 2200 SCHEMA - public pg_database_owner\n"
    "3642; 0 0 COMMENT - SCHEMA public pg_database_owner\n"
    "3643; 0 0 SEQUENCE SET public progress_events_id_seq ctiparsor\n"
    "3644; 0 0 SEQUENCE SET public review_decisions_id_seq ctiparsor\n"
)

_CHECK = "offline_check_dump_data $OFFLINE_RULE_STORE_TABLES schema_migrations"


def _run_lib(snippet: str, stdin: str = "") -> subprocess.CompletedProcess[str]:
    """Sources the library in bash, then runs SNIPPET, from the repo root."""
    return subprocess.run(
        ["bash", "-c", f"source {_LIB}\n{snippet}"],
        cwd=_ROOT, input=stdin, capture_output=True, text=True, check=False,
    )


def test_offline_rule_store_tables_are_the_rules_migrations_tables():
    created: set[str] = set()
    for migration in migrations.load():
        if migration.store == "rules":
            for statement in migration.statements:
                created.update(_CREATE_TABLE.findall(statement))
    assert created, 'no migration with store="rules" creates a table'

    match = _RULE_STORE_LINE.search((_ROOT / _LIB).read_text(encoding="utf-8"))
    assert match, 'OFFLINE_RULE_STORE_TABLES="..." must be on one line of scripts/offline_lib_docker.sh'
    assert set(match.group(1).split()) == created

    # The packager reads the library's list: a copy of it there would drift from it.
    assert not _OLD_RULE_STORE_LINE.search(_PACKAGER.read_text(encoding="utf-8"))


def test_sourcing_the_library_prints_nothing():
    """The library is definitions only: sourcing it runs nothing and says nothing."""
    result = _run_lib("")
    assert result.returncode == 0, result.stderr
    assert result.stdout == ""
    assert result.stderr == ""


def test_exclude_data_args_excludes_only_the_tables_outside_keep():
    tables = "jobs\ndetection_rules\n\nschema_migrations\nentities"
    result = _run_lib("offline_exclude_data_args detection_rules rule_text schema_migrations", tables)
    assert result.returncode == 0, result.stderr
    assert result.stdout.splitlines() == [
        "--exclude-table-data=public.jobs",
        "--exclude-table-data=public.entities",
    ]


def test_check_dump_data_passes_a_listing_with_only_kept_data():
    result = _run_lib("offline_check_dump_data detection_rules rule_text schema_migrations", _TOC_RULES_ONLY)
    assert result.returncode == 0, result.stderr
    assert "✔" in result.stdout


def test_check_dump_data_refuses_a_report_table_and_names_it():
    toc = _TOC_RULES_ONLY + "3460; 0 16393 TABLE DATA public jobs ctiparsor\n"
    result = _run_lib("offline_check_dump_data detection_rules rule_text schema_migrations", toc)
    assert result.returncode != 0
    assert "✖" in result.stderr
    assert "jobs" in result.stderr
    assert "detection_rules" not in result.stderr
    assert "✔" not in result.stdout


def test_check_dump_data_passes_the_listing_of_a_packaged_dump():
    result = _run_lib(_CHECK, _TOC_FULL)
    assert result.returncode == 0, result.stderr
    assert "✔" in result.stdout


def test_check_dump_data_accepts_the_sequence_counters():
    toc = _TOC_RULES_ONLY + "3462; 0 0 SEQUENCE SET public review_decisions_id_seq ctiparsor\n"
    result = _run_lib(_CHECK, toc)
    assert result.returncode == 0, result.stderr
    assert "✔" in result.stdout


def test_check_dump_data_refuses_an_empty_listing():
    result = _run_lib(_CHECK, "")
    assert result.returncode != 0
    assert "✖" in result.stderr
    assert "✔" not in result.stdout


def test_check_dump_data_refuses_a_listing_without_the_rule_store_data():
    toc = (
        "3459; 1259 16392 TABLE public jobs ctiparsor\n"
        "3456; 1259 16390 TABLE public detection_rules ctiparsor\n"
    )
    result = _run_lib(_CHECK, toc)
    assert result.returncode != 0
    assert "detection_rules" in result.stderr
    assert "✔" not in result.stdout


def test_check_dump_data_refuses_a_data_entry_outside_public_and_names_it():
    toc = _TOC_RULES_ONLY + "3460; 0 16393 TABLE DATA t_abc jobs ctiparsor\n"
    result = _run_lib(_CHECK, toc)
    assert result.returncode != 0
    assert "t_abc.jobs" in result.stderr
    assert "✔" not in result.stdout


def test_check_dump_data_refuses_large_objects():
    toc = _TOC_RULES_ONLY + "3460; 0 0 BLOBS - 16390 ctiparsor\n"
    result = _run_lib(_CHECK, toc)
    assert result.returncode != 0
    assert "large objects" in result.stderr
    assert "✔" not in result.stdout


def _env_value(tmp_path: Path, text: str, key: str) -> subprocess.CompletedProcess[str]:
    """offline_env_value of KEY in a .env holding TEXT, written as bytes so CRLF stays."""
    env_file = tmp_path / ".env"
    env_file.write_bytes(text.encode("utf-8"))
    return _run_lib(f"offline_env_value {key} {shlex.quote(str(env_file))}")


def test_env_value_strips_one_pair_of_double_quotes(tmp_path):
    result = _env_value(tmp_path, 'LLM_PROVIDER="ollama"\n', "LLM_PROVIDER")
    assert result.returncode == 0, result.stderr
    assert result.stdout == "ollama"


def test_env_value_strips_one_pair_of_single_quotes(tmp_path):
    result = _env_value(tmp_path, "OLLAMA_MODEL='mistral'\n", "OLLAMA_MODEL")
    assert result.returncode == 0, result.stderr
    assert result.stdout == "mistral"


def test_env_value_drops_an_inline_comment(tmp_path):
    result = _env_value(tmp_path, "LLM_PROVIDER=ollama   # the local server\n", "LLM_PROVIDER")
    assert result.returncode == 0, result.stderr
    assert result.stdout == "ollama"
    result = _env_value(tmp_path, 'OLLAMA_MODEL="mistral" # the model\n', "OLLAMA_MODEL")
    assert result.returncode == 0, result.stderr
    assert result.stdout == "mistral"


def test_env_value_keeps_a_hash_inside_quotes(tmp_path):
    result = _env_value(tmp_path, 'OLLAMA_API_KEY="pa #ss"\n', "OLLAMA_API_KEY")
    assert result.returncode == 0, result.stderr
    assert result.stdout == "pa #ss"


def test_env_value_reads_crlf_line_ends(tmp_path):
    result = _env_value(tmp_path, "LLM_PROVIDER=vllm\r\n", "LLM_PROVIDER")
    assert result.returncode == 0, result.stderr
    assert result.stdout == "vllm"


def test_env_value_takes_the_last_line_of_the_key(tmp_path):
    result = _env_value(tmp_path, "LLM_PROVIDER=ollama\nLLM_PROVIDER=vllm\n", "LLM_PROVIDER")
    assert result.returncode == 0, result.stderr
    assert result.stdout == "vllm"


def test_env_value_of_an_absent_key_is_empty_and_succeeds(tmp_path):
    result = _env_value(tmp_path, "OLLAMA_MODEL=mistral\n", "LLM_PROVIDER")
    assert result.returncode == 0, result.stderr
    assert result.stdout == ""
