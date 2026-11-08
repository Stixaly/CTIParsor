"""The permission table covers every operation of the app, and the router-level
dependency applies it (ADR-0097 item 14)."""
from __future__ import annotations

import pkgutil
import re

import api.routes
from api.auth.config import ROLES
from api.auth.permissions import OPEN, PERMISSIONS, required_role
from api.main import _ROUTERS, app

_PARAM = re.compile(r"\{[^}]+\}")


def _operations() -> set[tuple[str, str]]:
    return {(method.upper(), path) for path, item in app.openapi()["paths"].items() for method in item}


def test_every_operation_has_a_role_and_every_entry_an_operation():
    operations = _operations()
    assert sorted(operations - set(PERMISSIONS)) == [], "an operation nobody classified"
    assert sorted(set(PERMISSIONS) - operations) == [], "an entry that matches no operation"


def test_the_router_table_and_the_schema_list_the_same_operations():
    """The route files themselves: a route that the schema hides (include_in_schema=False)
    or a router `api/main.py` does not include would escape the first test."""
    in_routers = {(method, route.path) for module in _ROUTERS for route in module.router.routes
                  for method in route.methods - {"HEAD"}}
    assert in_routers | {("GET", "/api/health")} == set(PERMISSIONS)


def test_every_route_file_is_included_with_the_access_check():
    files = {info.name for info in pkgutil.iter_modules(api.routes.__path__) if not info.name.startswith("_")}
    assert files == {module.__name__.rsplit(".", 1)[1] for module in _ROUTERS}


def test_every_role_is_a_known_one_and_only_health_and_login_are_open():
    assert {role for role in PERMISSIONS.values()} <= {OPEN, *ROLES}
    assert sorted(op for op, role in PERMISSIONS.items() if role == OPEN) == [
        ("GET", "/api/health"), ("POST", "/api/auth/login")]


def test_an_operation_that_is_not_listed_has_no_role():
    assert required_role("get", "/api/health") == OPEN
    assert required_role("GET", "/api/nothing") is None


def _call(client, method: str, template: str, **kwargs):
    return client.request(method, _PARAM.sub("x", template), **kwargs)


def test_no_credentials_is_401_on_every_operation_but_the_open_ones(auth_client):
    refused = {}
    for (method, template), role in PERMISSIONS.items():
        if role == OPEN:
            continue
        refused[(method, template)] = _call(auth_client, method, template).status_code
    assert {k: v for k, v in refused.items() if v != 401} == {}


def test_the_open_operations_answer_without_credentials(auth_client):
    assert auth_client.get("/api/health").status_code == 200
    assert auth_client.post("/api/auth/login", json={"username": "nobody", "password": "x"}).status_code == 401


def test_a_role_below_the_minimum_is_403_on_every_operation_above_it(auth_client, make_user, sign_in):
    ranks = {role: i for i, role in enumerate(ROLES)}
    for role in ("reader", "analyst"):
        headers = sign_in(make_user(role))
        wrong = {}
        for (method, template), minimum in PERMISSIONS.items():
            if minimum == OPEN or ranks[minimum] <= ranks[role]:
                continue
            wrong[(method, template)] = _call(auth_client, method, template, headers=headers).status_code
        assert wrong and {k: v for k, v in wrong.items() if v != 403} == {}, role


def test_an_operation_missing_from_the_table_is_refused_not_open(auth_client, make_user, sign_in, monkeypatch):
    sign_in(make_user("admin"))
    monkeypatch.delitem(PERMISSIONS, ("GET", "/api/queue/status"))
    assert auth_client.get("/api/queue/status").status_code == 403


def test_with_authentication_off_every_operation_is_as_before(temp_db_client):
    assert temp_db_client.get("/api/jobs").status_code == 200
    assert temp_db_client.get("/api/settings/formats").status_code == 200
    assert temp_db_client.get("/api/auth/me").json()["auth_mode"] == "off"
