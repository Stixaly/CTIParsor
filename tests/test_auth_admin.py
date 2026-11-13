"""python -m api.admin: the first admin, passwords, disabling, tokens, the list."""
from __future__ import annotations

import getpass

import pytest

from api import admin
from api.auth import store

GOOD = "correct horse battery staple"


@pytest.fixture()
def cli(temp_db, capsys, monkeypatch):
    """cli(*argv) -> (exit code, stdout, stderr); the schema is the test's own."""
    monkeypatch.setattr("api.db.init_db", lambda: None)

    def run(*argv: str):
        capsys.readouterr()
        code = admin.main(list(argv))
        out = capsys.readouterr()
        return code, out.out, out.err

    return run


@pytest.fixture()
def password_file(tmp_path):
    def make(text: str = GOOD + "\n"):
        path = tmp_path / "password"
        path.write_text(text, encoding="utf-8")
        return str(path)

    return make


def test_create_admin_reads_a_password_file_and_creates_a_working_admin(cli, password_file):
    code, out, err = cli("create-admin", "--username", "Alice", "--password-file", password_file())
    assert code == 0 and "admin alice created" in out
    user = store.check_credentials("alice", GOOD)             # the trailing newline was not part of it
    assert user is not None and user.role == "admin"
    assert GOOD not in out + err


def test_create_admin_prompts_twice(cli, monkeypatch):
    answers = iter([GOOD, GOOD])
    monkeypatch.setattr(getpass, "getpass", lambda prompt="": next(answers))
    assert cli("create-admin", "--username", "alice")[0] == 0
    assert store.check_credentials("alice", GOOD)


def test_create_admin_refuses_when_the_two_passwords_differ(cli, monkeypatch):
    answers = iter([GOOD, GOOD + "x"])
    monkeypatch.setattr(getpass, "getpass", lambda prompt="": next(answers))
    code, _, err = cli("create-admin", "--username", "alice")
    assert code == 1 and "differ" in err and not store.admin_exists()


def test_create_admin_refuses_a_second_admin_unless_forced(cli, password_file):
    assert cli("create-admin", "--username", "alice", "--password-file", password_file())[0] == 0
    code, _, err = cli("create-admin", "--username", "bob", "--password-file", password_file())
    assert code == 1 and "--force" in err and store.find_user("bob") is None
    assert cli("create-admin", "--username", "bob", "--password-file", password_file(), "--force")[0] == 0
    assert store.find_user("bob").role == "admin"


def test_create_admin_refuses_a_weak_password_and_a_missing_file(cli, password_file, tmp_path):
    code, _, err = cli("create-admin", "--username", "alice", "--password-file", password_file("short\n"))
    assert code == 1 and "at least" in err and store.find_user("alice") is None
    code, _, err = cli("create-admin", "--username", "alice", "--password-file", str(tmp_path / "missing"))
    assert code == 1 and "refused" in err


def test_create_user_makes_a_reader_by_default(cli, password_file):
    assert cli("create-user", "--username", "rita", "--password-file", password_file())[0] == 0
    assert store.find_user("rita").role == "reader"
    assert cli("create-user", "--username", "ann", "--role", "analyst", "--password-file", password_file())[0] == 0
    assert store.find_user("ann").role == "analyst"


def test_set_password_changes_it_and_signs_the_user_out(cli, password_file, tmp_path):
    cli("create-admin", "--username", "alice", "--password-file", password_file())
    session_id, _ = store.create_session(store.find_user("alice").id)
    new = tmp_path / "new"
    new.write_text("a different long password", encoding="utf-8")
    assert cli("set-password", "--username", "alice", "--password-file", str(new))[0] == 0
    assert store.find_session(session_id) is None
    assert store.check_credentials("alice", GOOD) is None
    assert store.check_credentials("alice", "a different long password")
    code, _, err = cli("set-password", "--username", "nobody", "--password-file", str(new))
    assert code == 1 and "no local account" in err


def test_disable_and_enable(cli, password_file):
    cli("create-admin", "--username", "alice", "--password-file", password_file())
    cli("create-user", "--username", "bob", "--role", "admin", "--password-file", password_file())
    assert cli("disable", "--username", "alice")[0] == 0
    assert store.check_credentials("alice", GOOD) is None
    assert cli("disable", "--username", "alice", "--enable")[0] == 0
    assert store.check_credentials("alice", GOOD)
    assert cli("disable", "--username", "nobody")[0] == 1


def test_list_users(cli, password_file):
    assert "no users" in cli("list-users")[1]
    cli("create-admin", "--username", "alice", "--password-file", password_file())
    cli("create-user", "--username", "bob", "--password-file", password_file())
    cli("disable", "--username", "bob")
    out = cli("list-users")[1]
    assert "alice" in out and "admin" in out and "active" in out
    assert "bob" in out and "disabled" in out
    assert "$argon2" not in out


def test_create_token_prints_it_once_and_it_works(cli, password_file, temp_db):
    cli("create-admin", "--username", "alice", "--password-file", password_file())
    code, out, err = cli("create-token", "--user", "alice", "--name", "ci", "--days", "30")
    token = out.strip()
    assert code == 0 and token.startswith("ctp_") and "shown once" in err and token not in err
    assert store.find_token_user(token).username == "alice"
    with temp_db.get_conn() as conn:
        assert token not in [r[0] for r in conn.execute("SELECT token_hash FROM api_tokens").fetchall()]


def test_create_token_refuses_an_unknown_user_and_a_bad_lifetime(cli, password_file):
    cli("create-admin", "--username", "alice", "--password-file", password_file())
    assert cli("create-token", "--user", "nobody", "--name", "ci")[0] == 1
    code, _, err = cli("create-token", "--user", "alice", "--name", "ci", "--days", "0")
    assert code == 1 and "one day" in err


def test_a_command_is_required():
    with pytest.raises(SystemExit):
        admin.main([])
