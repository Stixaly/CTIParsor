"""Concurrent changes of an account's role, disabled flag and name (issue #739).

Each change runs in its own thread, which gets its own PostgreSQL connection (api.db keeps one
per thread).  One change is paused at a chosen statement with its transaction still open; the
other runs until it waits on the advisory lock, or finishes; then the paused one is released.
The pauses fix the order of the statements, so the outcome does not depend on timing; the waits
have a 20 s guard so a broken build fails instead of hanging.
"""
from __future__ import annotations

import threading
import time

import pytest

from api import db
from api.auth import store

from .conftest import AUTH_TEST_PASSWORD

GUARD = 20.0
ADVISORY = "SELECT PG_ADVISORY_XACT_LOCK"


class _Pause:
    """Holds thread `name` once, just before or just after the first statement starting with `prefix`."""

    def __init__(self, name: str, prefix: str, when: str):
        self.name, self.prefix, self.when = name, prefix.upper(), when
        self.reached = threading.Event()
        self.go = threading.Event()
        self._spent = False

    def hit(self, sql: str, when: str) -> None:
        if self._spent or when != self.when or threading.current_thread().name != self.name:
            return
        if not sql.lstrip().upper().startswith(self.prefix):
            return
        self._spent = True
        self.reached.set()
        assert self.go.wait(GUARD), "the paused change was never released"


class _Proxy:
    """A connection whose statements pass the pauses first; everything else is the real connection."""

    def __init__(self, conn, pauses: list[_Pause]):
        self._conn = conn
        self._pauses = pauses

    def execute(self, sql, params=None):
        for pause in self._pauses:
            pause.hit(sql, "before")
        result = self._conn.execute(sql, params)
        for pause in self._pauses:
            pause.hit(sql, "after")
        return result

    def __getattr__(self, name):
        return getattr(self._conn, name)


@pytest.fixture()
def pausing(monkeypatch, temp_db):
    """pausing(thread_name, sql_prefix, 'before' | 'after') -> a _Pause for store calls made in that thread."""
    pauses: list[_Pause] = []
    real_get_conn = store.get_conn
    monkeypatch.setattr(store, "get_conn", lambda: _Proxy(real_get_conn(), pauses))

    def pause(name: str, prefix: str, when: str) -> _Pause:
        hold = _Pause(name, prefix, when)
        pauses.append(hold)
        return hold

    return pause


class _Change:
    """A store call run in a thread of its own; `error` and `result` hold what it raised or returned."""

    def __init__(self, name: str, fn, *args, **kwargs):
        self.error: BaseException | None = None
        self.result = None

        def body():
            try:
                self.result = fn(*args, **kwargs)
            except BaseException as exc:             # noqa: BLE001 - reported to the test, not swallowed
                self.error = exc
            finally:
                db.reset_connections()

        self.thread = threading.Thread(target=body, name=name, daemon=True)

    def start(self) -> _Change:
        self.thread.start()
        return self

    def join(self) -> None:
        self.thread.join(GUARD)
        assert not self.thread.is_alive(), "the change is stuck"


def _waiting_for_the_admin_lock() -> int:
    """How many other backends of this database wait for the admins advisory lock."""
    row = store.get_conn().execute(
        "SELECT count(*) AS n FROM pg_stat_activity WHERE wait_event_type = 'Lock' AND wait_event = 'advisory' "
        "AND datname = current_database() AND pid <> pg_backend_pid()").fetchone()
    return row["n"]


def _until(done, what: str) -> None:
    deadline = time.monotonic() + GUARD
    while not done():
        if time.monotonic() > deadline:
            pytest.fail(f"timed out waiting for {what}")
        time.sleep(0.02)


def _blocked_or_finished(change: _Change):
    return lambda: not change.thread.is_alive() or _waiting_for_the_admin_lock() > 0


def _state(user_id: str) -> tuple[str, bool, str]:
    user = store.get_user(user_id)
    return user.role, user.disabled, user.display_name


# ── A rename must not undo a concurrent demotion or disable (#739) ───────────

def test_a_rename_after_a_demotion_and_disable_keeps_both(pausing, make_user):
    make_user("admin", "boss")                                  # another enabled admin: the demotion is allowed
    target = make_user("admin", "target")
    session_id, _ = store.create_session(target.id)
    token, _ = store.create_token(target.id, "ci")
    hold = pausing("writer-a", "UPDATE USERS", "after")          # A holds the lock after its UPDATE
    demote = _Change("writer-a", store.update_user, target.id, role="reader", disabled=True).start()
    assert hold.reached.wait(GUARD)
    rename = _Change("writer-b", store.update_user, target.id, display_name="Target Smith").start()
    _until(_blocked_or_finished(rename), "the rename to wait for the admins lock")
    hold.go.set()
    demote.join()
    rename.join()
    assert demote.error is None and rename.error is None
    assert _state(target.id) == ("reader", True, "Target Smith")
    assert store.find_session(session_id) is None               # ended by the disable, not recreated
    assert store.check_credentials("target", AUTH_TEST_PASSWORD) is None
    assert store.find_token_user(token) is None                 # a disabled account's token is refused
    store.update_user(target.id, disabled=False)                # an explicit re-enable works again ...
    assert store.find_token_user(token) is not None             # ... and its token with it


# ── The other order: the rename read its snapshot first, the demotion commits, then the rename ─────

def test_a_rename_that_read_before_a_demotion_does_not_restore_it(pausing, make_user):
    make_user("admin", "boss")
    target = make_user("admin", "target")
    hold = pausing("writer-a", ADVISORY, "before")               # A has read the account, not yet locked
    rename = _Change("writer-a", store.update_user, target.id, display_name="Target Smith").start()
    assert hold.reached.wait(GUARD)
    demote = _Change("writer-b", store.update_user, target.id, role="reader", disabled=True).start()
    demote.join()
    hold.go.set()
    rename.join()
    assert demote.error is None and rename.error is None
    assert _state(target.id) == ("reader", True, "Target Smith")


# ── The last-admin rule, read under the lock ──────────────────────────────────

def test_two_concurrent_demotions_of_the_last_two_admins_refuse_one(pausing, make_user):
    first = make_user("admin", "first")
    second = make_user("admin", "second")
    hold = pausing("writer-a", "UPDATE USERS", "after")
    a = _Change("writer-a", store.update_user, first.id, role="reader").start()
    assert hold.reached.wait(GUARD)
    b = _Change("writer-b", store.update_user, second.id, role="reader").start()
    _until(_blocked_or_finished(b), "the second demotion to wait for the admins lock")
    hold.go.set()
    a.join()
    b.join()
    assert a.error is None
    assert isinstance(b.error, store.LastAdminError), b.error
    assert _state(first.id)[0] == "reader" and _state(second.id)[0:2] == ("admin", False)


def test_a_concurrent_disable_by_the_cli_cannot_remove_the_last_admin(pausing, make_user):
    first = make_user("admin", "first")
    second = make_user("admin", "second")
    hold = pausing("writer-a", "UPDATE USERS", "after")
    a = _Change("writer-a", store.update_user, first.id, role="reader").start()
    assert hold.reached.wait(GUARD)
    b = _Change("writer-b", store.set_disabled, second.username).start()     # what `python -m api.admin disable` runs
    _until(_blocked_or_finished(b), "the disable to wait for the admins lock")
    hold.go.set()
    a.join()
    b.join()
    assert a.error is None
    assert isinstance(b.error, store.LastAdminError), b.error
    assert _state(second.id)[0:2] == ("admin", False)


def test_a_promotion_and_a_disable_cannot_leave_no_enabled_admin(pausing, make_user):
    # No admin at all at the start. A promotes `account`; B disables it from the state it read before A's
    # promotion committed. Disabling the only enabled admin must be refused.
    account = make_user("reader", "account")
    hold = pausing("writer-a", "UPDATE USERS", "after")
    a = _Change("writer-a", store.update_user, account.id, role="admin").start()
    assert hold.reached.wait(GUARD)
    b = _Change("writer-b", store.update_user, account.id, disabled=True).start()
    _until(_blocked_or_finished(b), "the disable to wait for the admins lock")
    hold.go.set()
    a.join()
    b.join()
    assert a.error is None
    assert isinstance(b.error, store.LastAdminError), b.error
    assert _state(account.id) == ("admin", False, "account")


# ── A user deleted during the change ─────────────────────────────────────────

def test_a_user_deleted_during_a_change_is_refused_not_recreated(pausing, make_user):
    make_user("admin", "boss")
    gone = make_user("reader", "gone")
    hold = pausing("writer-a", ADVISORY, "before")
    change = _Change("writer-a", store.update_user, gone.id, display_name="Renamed").start()
    assert hold.reached.wait(GUARD)
    store.get_conn().execute("DELETE FROM users WHERE id=?", (gone.id,))
    hold.go.set()
    change.join()
    assert isinstance(change.error, store.AuthError) and not isinstance(change.error, store.LastAdminError)
    assert store.get_user(gone.id) is None


# ── The CLI refuses to disable the last enabled admin, as the route does ─────

def test_the_cli_refuses_to_disable_the_last_enabled_admin(temp_db, make_user, capsys, monkeypatch):
    from api import admin

    monkeypatch.setattr("api.db.init_db", lambda: None)
    only = make_user("admin", "only")
    capsys.readouterr()
    code = admin.main(["disable", "--username", only.username])
    err = capsys.readouterr().err
    assert code == 1 and "refused:" in err and "last enabled admin" in err
    assert store.get_user(only.id).disabled is False
